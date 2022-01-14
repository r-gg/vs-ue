package dslab.nameserver;

import java.io.InputStream;
import java.io.PrintStream;
import java.rmi.NoSuchObjectException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.util.Config;

public class Nameserver implements INameserver, INameserverRemote {

  private final Shell shell;
  final Config config;
  final Map<String, String> entries = new ConcurrentHashMap<>();
  final Map<String, INameserverRemote> nameservers = new ConcurrentHashMap<>();
  final String[] domain;

  /**
   * Creates a new server instance.
   * @param componentId the id of the component that corresponds to the Config resource
   * @param config      the component config
   * @param in          the input stream to read console input from
   * @param out         the output stream to write console output to
   */
  public Nameserver(String componentId, Config config, InputStream in, PrintStream out) {
    this.config = config;

    if(config.containsKey("domain")){
      this.domain = config.getString("domain").split("\\.");
    } else {
      this.domain = new String[0];
    }



    shell = new Shell(in, out);
    this.registerSelf();

    shell.register(this);

    // (prompt may not work correctly/nicely when application is run via ant)
    shell.setPrompt(componentId + "> ");
  }

  @Override
  public void run() {
    // TODO
    shell.run();
    this.shutdown();
  }

  @Override
  @Command
  public void nameservers() {
    int i = 1;
    for (Map.Entry<String, INameserverRemote> entry : nameservers.entrySet()) {
      shell.out().println(i + ". " + entry.getKey());
      i++;
    }
  }

  @Override
  @Command
  public void addresses() {
    int i = 1;
    for (Map.Entry<String, String> entry : entries.entrySet()) {
      shell.out().println(i + ". " + entry.getKey() + " " + entry.getValue());
      i++;
    }
  }

  @Override
  @Command
  public void shutdown() {
    try {
      UnicastRemoteObject.unexportObject(this, true);
    } catch (NoSuchObjectException ignored) {
    }

    shell.out().println("shutdown initiated! Please give it a couple of seconds");
    shell.out().flush();

    throw new StopShellException(); // This will break the shell's read loop and make Shell.run() return gracefully.
  }

  public static void main(String[] args) throws Exception {
    INameserver component = ComponentFactory.createNameserver(args[0], System.in, System.out);
    component.run();
  }

  public void registerSelf() {
    try {
      Registry registry = LocateRegistry.getRegistry(this.config.getString("registry.host"), this.config.getInt("registry.port"));
      INameserverRemote rootNameserver = (INameserverRemote) registry.lookup(this.config.getString("root_id"));
      INameserverRemote remoteobject = (INameserverRemote) UnicastRemoteObject.exportObject(this, 0);
      rootNameserver.registerNameserver(this.config.getString("domain"), remoteobject);
      this.shell.out().println("Registered at parent nameserver");
    } catch (NotBoundException | RemoteException | AlreadyRegisteredException | InvalidDomainException e) {
      this.shell.out().println("Could not register at parent nameserver");
      e.printStackTrace();
    }
  }

  @Override
  public void registerNameserver(String domain, INameserverRemote nameserver) throws RemoteException, AlreadyRegisteredException, InvalidDomainException {
    String[] subdomain = stripDomainPart(domain);
    if (subdomain == null || subdomain.length == 0) {
      throw new InvalidDomainException("Domain " + domain + " is not a valid domain for this nameserver");
    }
    if (subdomain.length == 1) {
      if (nameservers.containsKey(subdomain[0])) {
        throw new AlreadyRegisteredException("Nameserver already registered for domain " + domain);
      }
      nameservers.put(subdomain[0], nameserver);
      this.shell.out().println("Registered sub nameserver "+subdomain[0]);
    } else {
      INameserverRemote nextNameserver = nameservers.get(subdomain[subdomain.length-1]);
      if (nextNameserver == null) {
        throw new InvalidDomainException("Zone for " + domain + " is not existent on this nameserver");
      }
      nextNameserver.registerNameserver(String.join(".", subdomain), nameserver);
      this.shell.out().println("Forwarded nameserver registration for "+String.join(".", subdomain));
    }
  }

  @Override
  public void registerMailboxServer(String domain, String address) throws RemoteException, AlreadyRegisteredException, InvalidDomainException {
    String[] subdomain = stripDomainPart(domain);
    if (subdomain == null || subdomain.length == 0) {
      throw new InvalidDomainException("Domain " + domain + " is not a valid domain for this nameserver");
    }
    if (subdomain.length == 1) {
      if (entries.containsKey(subdomain[0])) {
        throw new AlreadyRegisteredException("Hostname already registered for domain " + domain);
      }
      entries.put(subdomain[0], address);
      this.shell.out().println("Registered mailbox server "+subdomain[0]);
    } else {
      INameserverRemote nextNameserver = nameservers.get(subdomain[subdomain.length-1]);
      if (nextNameserver == null) {
        throw new InvalidDomainException("Zone for " + domain + " is not existent on this nameserver");
      }
      nextNameserver.registerMailboxServer(String.join(".", subdomain), address);
      this.shell.out().println("Forwarded mailbox registration for "+String.join(".", subdomain));
    }
  }

  @Override
  public INameserverRemote getNameserver(String zone) throws RemoteException {
    this.shell.out().println("Nameserver requested for "+zone);
    return nameservers.get(zone);
  }

  @Override
  public String lookup(String username) throws RemoteException {
    this.shell.out().println("Mailbox requested: "+username);
    return entries.get(username);
  }

  private String[] stripDomainPart(String domain){
    if (!checkDomain(domain)) {
      return null;
    }
    String[] domainParts = domain.split("\\.");
    String[] newDomainParts = new String[domainParts.length-this.domain.length];
    System.arraycopy(domainParts, 0, newDomainParts, 0, newDomainParts.length);
    return newDomainParts;
  }

  private boolean checkDomain(String domain) {
    String[] domainParts = domain.split("\\.");
    for (int i = 1; i <= this.domain.length; i++) {
      if (!this.domain[this.domain.length-i].equalsIgnoreCase(domainParts[domainParts.length-i])) {
        return false;
      }
    }
    return true;
  }
}
