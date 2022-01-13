package dslab.mailbox;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.mailbox.sub_threads.AcceptThread;
import dslab.mailbox.models.DMAP_ThreadFactory;
import dslab.mailbox.models.DMTP_ThreadFactory;
import dslab.nameserver.AlreadyRegisteredException;
import dslab.nameserver.INameserverRemote;
import dslab.nameserver.InvalidDomainException;
import dslab.util.Config;
import dslab.util.Pair;

import java.io.InputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Receives mails via DMTP
 * and makes mails available via DMAP
 * for each connection, creates either
 *  a "DMTP ConnectionHandler" which
      vets recepients and mails (rejecting those the server is not responsible for)
      assigns the mail an (at least user-unique) id
      and 'permanently' stores the mail + id for the user to access via DMAP
 *  a "DMAP ConnectionHandler" which allows
      a) logging in as a particular user
      b) listing, accessing, and deleting the logged-in user's mails
      NB: mby better to split logging in and accessing 
 * 
 */
public class MailboxServer implements IMailboxServer, Runnable {

  private final ExecutorService exec = Executors.newCachedThreadPool();
  private final AtomicBoolean shutdown_initiated = new AtomicBoolean(false);
  private final Map<String, Pair<String, Inbox>> user_db = new ConcurrentHashMap<>();
  private final Shell shell;
  private final int DMTP_port;
  private final int DMAP_port;
  private final String domain;
  private final String componentId;
  private final Config config;

  /**
   * Creates a new server instance.
   *
   * @param componentId      the id of the component that corresponds to the Config resource
   * @param component_config the component config
   * @param in               the input stream to read console input from
   * @param out              the output stream to write console output to
   */
  public MailboxServer(String componentId, Config component_config, Config user_cred_config, InputStream in, PrintStream out) {

    this.componentId = componentId;
    this.config = component_config;
    DMTP_port = component_config.getInt("dmtp.tcp.port");
    DMAP_port = component_config.getInt("dmap.tcp.port");

    domain = component_config.getString("domain");

    // read usernames and passwords from users file, feed into user_db
    for (String s : user_cred_config.listKeys()) {
      user_db.put(s, new Pair<>(user_cred_config.getString(s), new Inbox()));
    }

    this.registerAtNS();

    shell = new Shell(in, out);
    shell.register(this);

    // (prompt may not work correctly/nicely when application is run via ant)
    shell.setPrompt(componentId + "> ");
  }

  @Override
  public void run() {
    // Spawning the 2 AcceptThreads
    exec.execute(new AcceptThread(componentId, domain, DMTP_port, shutdown_initiated, user_db, new DMTP_ThreadFactory()));
    exec.execute(new AcceptThread(componentId, domain, DMAP_port, shutdown_initiated, user_db, new DMAP_ThreadFactory()));
    // ... and the Shell
    exec.execute(shell); // pdf mentions shell blocking may not be bad...

    // stop accepting new threads, but let the previously started ones terminate in their own time.
    exec.shutdown();
  }

  @Override
  @Command
  public void shutdown() {
    shell.out().println("shutdown initiated! Please give it a couple of seconds");
    shell.out().flush();

    // doc for shutdown strat / logic @ TransferServer
    shutdown_initiated.set(true);

    throw new StopShellException(); // This will break the shell's read loop and make Shell.run() return gracefully.
  }

  private void registerAtNS(){
    try {
      Registry registry = LocateRegistry.getRegistry(this.config.getString("registry.host"), this.config.getInt("registry.port"));
      INameserverRemote rootNameserver = (INameserverRemote) registry.lookup(this.config.getString("root_id"));
      rootNameserver.registerMailboxServer(this.domain, InetAddress.getLocalHost()+":"+this.DMTP_port);
    } catch (NotBoundException | RemoteException | AlreadyRegisteredException | InvalidDomainException | UnknownHostException e) {
      e.printStackTrace();
    }
  }

  public static void main(String[] args) throws Exception {
    IMailboxServer server = ComponentFactory.createMailboxServer(args[0], System.in, System.out);
    server.run();
  }
}
