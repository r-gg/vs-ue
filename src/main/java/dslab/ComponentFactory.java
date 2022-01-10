package dslab;

import dslab.client.IMessageClient;
import dslab.client.MessageClient;
import dslab.mailbox.IMailboxServer;
import dslab.mailbox.MailboxServer;
import dslab.monitoring.IMonitoringServer;
import dslab.monitoring.MonitoringServer;
import dslab.nameserver.INameserver;
import dslab.nameserver.Nameserver;
import dslab.nameserver.RootNameserver;
import dslab.transfer.ITransferServer;
import dslab.transfer.TransferServer;
import dslab.util.Config;

import java.io.InputStream;
import java.io.PrintStream;

/**
 * The component factory provides methods to create the core components of the application. You can
 * edit the method body if the component instantiation requires additional logic.
 *
 * <p>Do not change the existing method signatures!
 */
public final class ComponentFactory {

  private ComponentFactory() {
    // static utility class
  }

  /**
   * Creates a new {@link IMonitoringServer} instance.
   *
   * @param componentId the component id
   * @param in          the input stream used for accepting cli commands
   * @param out         the output stream to print to
   * @return a new MonitoringServer instance
   */
  public static IMonitoringServer createMonitoringServer(
      String componentId, InputStream in, PrintStream out) throws Exception {
    /*
     * TODO: Here you can modify the code (if necessary) to instantiate your components
     */

    Config config = new Config(componentId);
    return new MonitoringServer(componentId, config, in, out);
  }

  /**
   * Creates a new {@link IMailboxServer} instance.
   *
   * @param componentId the component id
   * @param in          the input stream used for accepting cli commands
   * @param out         the output stream to print to
   * @return a new MailboxServer instance
   */
  public static IMailboxServer createMailboxServer(
      String componentId, InputStream in, PrintStream out) throws Exception {
    /*
     * TODO: Here you can modify the code (if necessary) to instantiate your components
     */

    Config component_config = new Config(componentId);
    Config user_credentials_config = new Config(component_config.getString("users.config"));
    return new MailboxServer(componentId, component_config, user_credentials_config, in, out);
  }

  /**
   * Creates a new {@link ITransferServer} instance.
   *
   * @param componentId the component id
   * @param in          the input stream used for accepting cli commands
   * @param out         the output stream to print to
   * @return a new TransferServer instance
   */
  public static ITransferServer createTransferServer(
      String componentId, InputStream in, PrintStream out) throws Exception {
    /*
     * TODO: Here you can modify the code (if necessary) to instantiate your components
     */
    Config self_config = new Config(componentId);
    Config maildomains_config = new Config("domains.properties");
    return new TransferServer(componentId, self_config, maildomains_config, in, out);
  }

  /**
   * Creates a new {@link INameserver} instance.
   *
   * @param componentId the component id
   * @param in          the input stream used for accepting cli commands
   * @param out         the output stream to print to
   * @return a new Nameserver instance
   */
  public static INameserver createNameserver(String componentId, InputStream in, PrintStream out)
      throws Exception {
    /*
     * TODO: Here you can modify the code (if necessary) to instantiate your components
     */

    Config config = new Config(componentId);
    if (componentId.equals("ns-root")){
      return new RootNameserver(componentId, config, in, out);
    }
    return new Nameserver(componentId, config, in, out);
  }

  /**
   * Creates a new {@link IMessageClient} instance.
   *
   * @param componentId the component id
   * @param in          the input stream used for accepting cli commands
   * @param out         the output stream to print to
   * @return a new MessageClient instance
   */
  public static IMessageClient createMessageClient(String componentId, InputStream in, PrintStream out)
      throws Exception {
    Config config = new Config(componentId);
    return new MessageClient(componentId, config, in, out);
  }
}
