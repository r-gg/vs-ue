package dslab.transfer.models;

import dslab.shared_models.Addr_InfoI;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * encapsulates the running server's own IP+port
 */
public class Self_Info implements Addr_InfoI {
  /**
   * tries to find out own IP address upon construction
   *
   * @param port passed on
   * @throws UnknownHostException if own IP address couldn't be determined
   */
  public Self_Info(int port) throws UnknownHostException {
    this.port = port;
    this.ip = InetAddress.getLocalHost();
  }

  private final InetAddress ip;
  private final int port;

  public InetAddress ip() {
    return this.ip;
  }

  public int port() {
    return this.port;
  }

  @Override
  public String toString() {
    return "Self_Info{" +
        "ip=" + ip.getHostAddress() +
        ", port=" + port +
        '}';
  }
}
