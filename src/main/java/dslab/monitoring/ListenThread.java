package dslab.monitoring;

import at.ac.tuwien.dsg.orvell.Shell;
import dslab.util.InputChecker;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class ListenThread implements Runnable {

  private final AtomicBoolean shutdown_initiated;
  private final Shell shell;
  private final DatagramSocket udp_socket;

  private final Map<String, Integer> server_counts;
  private final Map<String, Integer> address_counts;

  ListenThread(AtomicBoolean shutdown_initiated, DatagramSocket udp_socket, Shell shell,
               Map<String, Integer> server_counts, Map<String, Integer> address_counts) {
    this.shutdown_initiated = shutdown_initiated;
    this.shell = shell;
    this.udp_socket = udp_socket;

    this.server_counts = server_counts;
    this.address_counts = address_counts;
  }


  @Override
  public void run() {
    // receive loop
    while (!shutdown_initiated.get()) {
      // based on https://stackoverflow.com/a/35697810/4602253, a size of up to 508 should work:
      byte[] inc_buf = new byte[256];
      DatagramPacket inc_packet = new DatagramPacket(inc_buf, inc_buf.length);
      try {
        udp_socket.receive(inc_packet);
      } catch (IOException e) {
        // "probably" a SocketException thrown by .close() on udp_socket, indicating shutdown
        // I (re)set shutdown initiated, and break out of the loop.
        shutdown_initiated.set(true);
        break;
      }
      // this is a critical section
      var received = new String(inc_packet.getData(), 0, inc_packet.getLength());
      var split = received.trim().split("\\s");
      // NB: this checking is _known_ to be spotty
      if (split.length == 2
          && InputChecker.is_server_addr_string(split[0])
          && InputChecker.is_mail_address(split[1])
      ){
        var host = split[0];
        var user = split[1];

        if(server_counts.containsKey(host)){
          server_counts.replace(host, server_counts.get(host) + 1);
        } else {
          server_counts.put(host, 1);
        }

        if(address_counts.containsKey(user)){
          address_counts.replace(user, address_counts.get(user) + 1);
        } else {
          address_counts.put(user, 1);
        }
      }

    }
  }
}
