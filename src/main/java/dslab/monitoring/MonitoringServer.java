package dslab.monitoring;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.util.Config;

import java.net.DatagramSocket;
import java.net.SocketException;
import java.io.InputStream;
import java.io.PrintStream;

import java.util.HashMap;
import java.util.Map;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A Monitoring Server receives, stores and (via CLI) displays usage statistics
 * <p>
 * allows CLI-commands:
 * - addresses
 * - servers
 * - shutdown
 */

public class MonitoringServer implements IMonitoringServer {

  private final ExecutorService exec = Executors.newFixedThreadPool(2);
  private AtomicBoolean shutdown_initiated;
  private final Shell shell;
  private DatagramSocket udp_socket;
  private final int port;


  // map from server, as "<IP-text>:<Port-port>"
  //     to   # of messages sent over the server
  private final Map<String, Integer> server_counts = new HashMap<>();
  // map from address, as "<username>:<domain>"
  //     to   # of messages sent from that address
  private final Map<String, Integer> address_counts = new HashMap<>();


  /**
   * Creates a new server instance.
   *
   * @param componentId the id of the component that corresponds to the Config resource
   * @param config      the component config
   * @param in          the input stream to read console input from
   * @param out         the output stream to write console output to
   */
  public MonitoringServer(String componentId, Config config, InputStream in, PrintStream out) {
    this.shutdown_initiated = new AtomicBoolean(false);
    this.port = config.getInt("udp.port");

    shell = new Shell(in, out);
    shell.register(this);

    // (prompt may not work correctly/nicely when application is run via ant)
    shell.setPrompt(componentId + "> ");
  }

  @Override
  public void run() {
    // setup UDP socket
    try {
      udp_socket = new DatagramSocket(port);
    } catch (SocketException e) {
      e.printStackTrace();
      shutdown();
    }

    exec.execute(new ListenThread(shutdown_initiated, udp_socket, shell, server_counts, address_counts));

    exec.execute(shell);

    exec.shutdown();
  }

  /**
   * Lists all addresses and the number of messages they have sent (aggregated over all servers)
   * Example output:
   * zaphod@univer.ze 12
   * trillian@earth.planet 4
   */
  @Override
  @Command
  public void addresses() {
    for (Map.Entry<String, Integer> e : address_counts.entrySet()) {
      shell.out().println(e.getKey() + " " + e.getValue());
    }
    shell.out().flush();
  }

  /**
   * Lists all servers and the number of messages sent over these servers.
   * Example output:
   * 10.0.0.1:1337 321
   * 10.0.0.2:1338 512
   */
  @Override
  @Command
  public void servers() {
    for (Map.Entry<String, Integer> e : server_counts.entrySet()) {
      shell.out().println(e.getKey() + " " + e.getValue());
    }
    shell.out().flush();
  }

  @Override
  @Command
  public void shutdown() {
    shell.out().println("shutdown initiated! Please give it a couple of seconds");

    shutdown_initiated.set(true);
    if (udp_socket != null) {
      udp_socket.close();
    }

    throw new StopShellException(); // This will break the shell's read loop and make Shell.run() return gracefully.
  }

  @Command
  public void debug() {
    shell.out().println(port);
    shell.out().println(server_counts.isEmpty());
    shell.out().println(address_counts.isEmpty());
  }

  public static void main(String[] args) throws Exception {
    IMonitoringServer server =
        ComponentFactory.createMonitoringServer(args[0], System.in, System.out);
    server.run();
  }
}
