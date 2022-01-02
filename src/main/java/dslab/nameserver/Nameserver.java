package dslab.nameserver;

import java.io.InputStream;
import java.io.PrintStream;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.util.Config;

public class Nameserver implements INameserver, INameserverRemote {

  private final Shell shell;
  final Config config;
  final Map<String, String> entries = new ConcurrentHashMap<>();
  final Map<String, INameserverRemote> nameservers = new ConcurrentHashMap<>();

  /**
   * Creates a new server instance.
   *
   * @param componentId the id of the component that corresponds to the Config resource
   * @param config      the component config
   * @param in          the input stream to read console input from
   * @param out         the output stream to write console output to
   */
  public Nameserver(String componentId, Config config, InputStream in, PrintStream out) {
    // TODO

    this.config = config;

    shell = new Shell(in, out);
    shell.register(this);

    // (prompt may not work correctly/nicely when application is run via ant)
    shell.setPrompt(componentId + "> ");
  }

  @Override
  public void run() {
    // TODO
  }

  @Override
  @Command
  public void nameservers() {
    // TODO
  }

  @Override
  @Command
  public void addresses() {
    // TODO
  }

  @Override
  @Command
  public void shutdown() {
    // TODO
  }

  public static void main(String[] args) throws Exception {
    INameserver component = ComponentFactory.createNameserver(args[0], System.in, System.out);
    component.run();
  }

  @Override
  public void registerNameserver(String domain, INameserverRemote nameserver) throws RemoteException, AlreadyRegisteredException, InvalidDomainException {
    if (!domain.endsWith(config.getString("domain"))) {
      throw new InvalidDomainException("Domain " + domain + " is not a valid domain for this nameserver");
    }
    // TODO forward to next nameserver
    if (nameservers.containsKey(domain)) {
      throw new AlreadyRegisteredException("Nameserver already registered for domain " + domain);
    }
    nameservers.put(domain, nameserver);
  }

  @Override
  public void registerMailboxServer(String domain, String address) throws RemoteException, AlreadyRegisteredException, InvalidDomainException {
    entries.put(domain, address);
  }

  @Override
  public INameserverRemote getNameserver(String zone) throws RemoteException {
    return nameservers.get(zone);
  }

  @Override
  public String lookup(String username) throws RemoteException {
    return entries.get(username);
  }
}
