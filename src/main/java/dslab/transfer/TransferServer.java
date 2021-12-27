package dslab.transfer;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.shared_models.Addr_Info;
import dslab.shared_models.ConfigException;
import dslab.shared_models.DMTP_Message;
import dslab.transfer.sub_thread.AcceptThread;
import dslab.transfer.sub_thread.TransferThread;
import dslab.transfer.models.*;
import dslab.util.Config;

import java.io.InputStream;
import java.io.PrintStream;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class TransferServer implements ITransferServer, Runnable {

  private final Config maildomains_config;
  // Executor for spawning arbitrary distinct tasks.
  private final ExecutorService exec = Executors.newCachedThreadPool();
  private final AtomicBoolean shutdown_initiated = new AtomicBoolean(false);
  private final Shell shell;
  private final Map<String, Addr_Info> mailbox_domains;
  private final Addr_Info monitor_info;
  private final Self_Info self_info;


  // sizing config
  private final int base_msg_queue_length = 10;
  private final int base_n_of_TransferThreads = 2;
  private final int scale_factor = 1;

  /**
   * Creates a new server instance.
   * <p>
   * On running, sets up a (concurrently available) queue of received, correct messages (waitingMessages).
   * Then starts 1 AcceptThread
   * -   which in turn starts an ConnectionHandler for each incoming connection on the socket
   * -   ConnectionHandlers (may) write to waitingMessages
   * Also starts k (== 2?) TransferThreads
   *
   * @param componentId the id of the component that corresponds to the Config resource
   * @param self_config the component config
   * @param in          the input stream to read console input from
   * @param out         the output stream to write console output to
   */
  public TransferServer(String componentId, Config self_config, Config maildomains_config, InputStream in, PrintStream out) {
    this.maildomains_config = maildomains_config;


    mailbox_domains = domain_lookup();

    // find out own IP address
    try {
      self_info = new Self_Info(self_config.getInt("tcp.port"));
    } catch (UnknownHostException e) {
      throw new ConfigException("Could not figure out own IP address", e);
    }

    // Read MonitorServer Info from Config
    Addr_Info monitor_info1;
    try {
      monitor_info1 = new Addr_Info(self_config.getString("monitoring.host"), self_config.getInt("monitoring.port"));
    } catch (UnknownHostException e) {
      // A bad IP (or "Monitoring Server being down", ...) should not stop the Transfer Server
      // a (admittedly brittle) check is done before sending monitoring msg (see TransferThread)
      monitor_info1 = null;
    }
    monitor_info = monitor_info1;

    shell = new Shell(in, out);
    shell.register(this);

    // (prompt may not work correctly/nicely when application is run via ant)
    shell.setPrompt(componentId + "> ");
  }


  @Override
  public void run() {

    //create a blocking queue for the messages to be forwarded
    BlockingQueue<DMTP_Message> waitingMessages =
        new ArrayBlockingQueue<>(scale_factor * base_msg_queue_length);

    // start the message-forwarding TransferThreads
    int n_of_TransferThreads = scale_factor * base_n_of_TransferThreads;
    for (int i = 0; i < n_of_TransferThreads; i++) {
      exec.execute(new TransferThread(shutdown_initiated, waitingMessages, mailbox_domains, self_info, monitor_info));
    }

    // spawns/manages new ConnectionHandler-Threads on it's own, in it's own Pool:
    exec.execute(new AcceptThread(self_info.port(), shutdown_initiated, scale_factor, waitingMessages));

    exec.execute(shell); // pdf mentions shell blocking may not be bad...

    // stop accepting new threads, but let the previously started ones terminate in their own time.
    exec.shutdown();
  }

  // should be invoked when "shutdown" is typed in the console window of the running application.
  @Override
  @Command
  public void shutdown() {
    shell.out().println("shutdown initiated! Please give it a couple of seconds");
    shell.out().flush();

    // My way of sending Threads the signal to shut down:
    // A concern: does it "penetrate" blocking methods (like accept())?
    // prev doc says "serverSocket.setSoTimeout + a loop" may be the answer
    shutdown_initiated.set(true);

    /*
    When your application shuts down, you should properly close all resources.
    Do not simply force end via System.exit (this is also why you should not use the exit shell command).
    Closing the ServerSocket(s) is a good place to start. (-> stop accepting new connections)
    You should then proceed to terminate all open Socket connections.

    Close any other I/O resources you may be using
    shut down all your thread pools.
    */

    throw new StopShellException(); // This will break the shell's read loop and make Shell.run() return gracefully.

    //If your application does not terminate after exiting the main method, you may still have some threads running which did not properly terminate.
  }

  public static void main(String[] args) throws Exception {
    ITransferServer server = ComponentFactory.createTransferServer(args[0], System.in, System.out);
    server.run();
  }

  /**
   * Reads all domains and their associated mailbox-server-IPs
   * from the maildomains_config (<-> domains.properties file).
   * parse the socket addresses.
   *
   * @return a domain-name -> Addr_Info Map
   *
   */
  private Map<String, Addr_Info> domain_lookup(){
    Set<String> keys = this.maildomains_config.listKeys();
    Map<String, Addr_Info> res = new HashMap<>();

    for (String k : keys) {
      String   temp1 = this.maildomains_config.getString(k);
      String[] temp2 = temp1.split(":", 2);

      Addr_Info addr = null;
      try {
        addr = new Addr_Info(temp2[0], Integer.parseInt(temp2[1]));
      } catch (UnknownHostException e) {
        throw new ConfigException("The domains.properties file seems to be faulty.", e);
      }

      res.put(k, addr);
    }
    return res;
  }
}
