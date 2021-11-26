package dslab.transfer.models;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Addr_Info implements Addr_InfoI {
  /**
   * @param ip_or_url
   * @param port
   * @throws UnknownHostException if ip_or_url is an ill-formed IP "literal"
   *                              or if the URL (DNS request?) doesn't come back with an IP
   */
  public Addr_Info(String ip_or_url, int port) throws UnknownHostException {
    this.port = port;
    this.ip = InetAddress.getByName(ip_or_url);
  }

  private final InetAddress ip;
  private final int port;

  @Override
  public String toString() {
    return "Addr_Info{" +
        "ip=" + ip.getHostAddress() +
        ", port=" + port +
        '}';
  }

  public InetAddress ip() {
    return this.ip;
  }

  public int port() {
    return this.port;
  }
}
