package dslab.transfer.sub_thread;

import dslab.nameserver.INameserverRemote;
import dslab.shared_models.Addr_Info;
import dslab.shared_models.DMTP_Message;
import dslab.shared_models.ImplError;
import dslab.transfer.models.Self_Info;
import dslab.util.Config;
import dslab.util.Pair;
import dslab.util.Tripple;

import java.io.*;
import java.net.*;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * TransferThread.java
 * responsible for
 * a) taking 1 message at a time out of waitingMessages (until shutdown)
 * b) doing domain-lookup for each recepient('s after-@-section?)
 * c) connecting to the found mailbox servers
 * d) passing the mail via DMTP to the server
 * e) In case of any error (lookup, non-existant pre-@-part):
 * sending an error message to mail's origin ("from")
 * f) sending a UDP package to a monitoring server
 */
public class TransferThread implements Runnable {
  static final String connection_ended_string = "server ended connection prematurely";
  static final String server_protocol_error_string = "server committed a DMTP protocol error";

  private final AtomicBoolean shutdown_initiated;
  private final BlockingQueue<DMTP_Message> waiting_messages;
  private DatagramSocket udp_socket;
  private final Addr_Info monitor_info;
  private final Self_Info self_info;
  private final Map<String, Addr_Info> mailbox_addrss;
  private final Config config;

  public TransferThread(AtomicBoolean shutdown_initiated, BlockingQueue<DMTP_Message> waiting_messages, Map<String, Addr_Info> mailbox_addrss, Self_Info self_info, Addr_Info monitor_addr, Config config) {
    this.shutdown_initiated = shutdown_initiated;
    this.waiting_messages = waiting_messages;
    this.monitor_info = monitor_addr;
    this.self_info = self_info;
    this.mailbox_addrss = mailbox_addrss;
    this.config = config;

    // StackOverflow is conflicted on whether UDP-socket.send() is thread-safe
    // So I'll opt for potential duplication (a socket per thread) over possible erroneous behavior
    // Also, I "handle" the case where "new DatagramSocket()" fails via a "rudimentary check" before send_monitor_msg
    try {
      udp_socket = new DatagramSocket();
    } catch (SocketException soc_except) {
      System.err.println("UDP socket could not be opened, or could not bind to specified local port.");
      soc_except.printStackTrace();
    } catch (SecurityException sec_except) {
      System.err.println("A SecurityException occured when creating a UDP socket");
    }
  }

  @Override
  public void run() {
    // a)
    while (!shutdown_initiated.get()) {
      DMTP_Message cur_msg = null;
      try {
        cur_msg = waiting_messages.poll(500, TimeUnit.MILLISECONDS);
      } catch (InterruptedException e) {
        System.err.println("TransferThread got interrupted waiting while polling a message from the queue");
        e.printStackTrace();
        // I believe "just try again" is reasonable here.
        continue;
      }
      if (cur_msg == null) {
        // cur_msg set to null 2x/s, to allow shutdown_initiated-check
        // construct chosen over "Poison"/End-Of-Stream msgs for a sort of congruency with AcceptThread
        // and to keep DMTP_Message Model simple.
        continue;
      }

      // b)
      // pre: recipients only contains values of format <blah>@<blub>
      var temp = server_selection(cur_msg.recipients);
      Set<Addr_Info> destinations = temp.e1;
      boolean some_delivery_failed = temp.e2;
      String err_msg = temp.e3;

      // c) + d) + f)
      for (Addr_Info dest : destinations) {
        var problem = send_mail(cur_msg, dest);
        if (problem.isPresent()) {
          some_delivery_failed = true;
          err_msg = "".equals(err_msg) ? problem.get() : (err_msg + " And " + problem.get());
        }
      }

      // e)
      if (some_delivery_failed) {
        send_error_mail(cur_msg, err_msg);
      }
    }


    System.out.println("TransferThread seems to have finished");
  }

  /**
   * connects to a DMTP server (@param to) and passes on the message.
   * also sends a monitioring message via send_monitor_msg()
   *
   * @return empty, if everthing went well, or an error message if delivery failed in an expected way.
   */
  private Optional<String> send_mail(DMTP_Message msg, Addr_Info to) {
    // c)
    try (
        Socket conn = new Socket(to.ip(), to.port());
        PrintWriter out = new PrintWriter(conn.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))
    ) {
      // DMTP server?
      String server_line = in.readLine();
      if (server_line == null) {
        return Optional.of(connection_ended_string);
      }
      if (!"ok DMTP2.0".equals(server_line)) {
        return Optional.of(server_protocol_error_string);
      }

      // y -> begin
      out.println("begin");
      server_line = in.readLine();
      if (server_line == null) {
        return Optional.of(connection_ended_string);
      }
      if (!"ok".equals(server_line)) {
        return Optional.of(server_protocol_error_string);
      }

      // pass through recipients
      out.println("to " + String.join(",", msg.recipients));
      server_line = in.readLine();
      if (server_line == null) {
        return Optional.of(connection_ended_string);
      }
      if (server_line.matches("^error.*")) { // test if regex ok
        return Optional.of("mailbox server said: " + server_line);
      }
      if (!server_line.matches("^ok \\d*")) { // test if regex ok
        return Optional.of(server_protocol_error_string);
      }

      // set sender
      out.println("from " + msg.sender);
      server_line = in.readLine();
      if (server_line == null) {
        return Optional.of(connection_ended_string);
      }
      if (!"ok".equals(server_line)) {
        return Optional.of(server_protocol_error_string);
      }

      // set subject
      out.println("subject " + msg.subject);
      server_line = in.readLine();
      if (server_line == null) {
        return Optional.of(connection_ended_string);
      }
      if (!"ok".equals(server_line)) {
        return Optional.of(server_protocol_error_string);
      }

      // set mail's text body
      out.println("data " + msg.text_body);
      server_line = in.readLine();
      if (server_line == null) {
        return Optional.of(connection_ended_string);
      }
      if (!"ok".equals(server_line)) {
        return Optional.of(server_protocol_error_string);
      }

      // set mail's hash if hash is present
      if (msg.hash != null) {
        out.println("hash " + msg.hash);
        server_line = in.readLine();
        if (server_line == null) {
          return Optional.of(connection_ended_string);
        }
        if (!"ok".equals(server_line)) {
          return Optional.of(server_protocol_error_string);
        }
      }


      // finalizes mail and send it off
      out.println("send");
      server_line = in.readLine();
      if (server_line == null) {
        return Optional.of(connection_ended_string);
      }
      if (!"ok".equals(server_line)) {
        return Optional.of(server_protocol_error_string);
      }

      // quit the socket/DMTP connection
      out.println("quit");
      server_line = in.readLine();
      if (server_line == null) {
        return Optional.of(connection_ended_string);
      }
      if (!"ok bye".equals(server_line)) {
        return Optional.of(server_protocol_error_string);
      }

      // sending finished
      // assert (in.readLine() == null) - if the other server does DMTP correctly.
      // I let try-with-resources close all the resources.
    } catch (UnknownHostException e) {
      System.err.println("UnknownHostException while trying to connect to " + to.ip());
    } catch (IOException e) {
      System.err.println("I/O exception while creating Socket or while getting OutputStream stream");
      System.err.println("While trying to connect to " + to.ip());
    }

    // f)
    // rudimentary check, see doc @ udp_socket initalization
    if (udp_socket != null && monitor_info != null && msg != null) {
      send_monitor_msg(msg);
    }

    return Optional.empty();
  }

  /**
   * @param original_msg pre: sender has format <blah>@<blub>
   * @param error
   */
  private void send_error_mail(DMTP_Message original_msg, String error) {
    var error_mail = new DMTP_Message();
    error_mail.recipients = List.of(original_msg.sender);
    error_mail.sender = "mailer@" + self_info.ip().getHostAddress();
    error_mail.subject = "Delivering your mail failed (at least partially)";
    error_mail.text_body = error;

    var sender_domain = original_msg.sender.split("@")[1];
    if (mailbox_addrss.containsKey(sender_domain)) {
      send_mail(error_mail, mailbox_addrss.get(sender_domain));
    }
    // else: give up
  }

  /**
   * pre: monitor_info is init'd
   * pre: udp_socket is init'd
   *
   * @param msg
   */
  private void send_monitor_msg(DMTP_Message msg) {
    String monitoring_msg = self_info.ip().getHostAddress() + ":" + self_info.port() + " " + msg.sender;
    byte[] buf = monitoring_msg.getBytes();
    DatagramPacket udp_packet = new DatagramPacket(buf, buf.length, monitor_info.ip(), monitor_info.port());
    try {
      udp_socket.send(udp_packet);
    } catch (IOException e) {
      // I'm unsure if/how one can react to this...
      // but a failing to send a monitoring packet def _should not_ cause a shutdown.
      System.err.println("IO exception when sending Monitoring msg");
      e.printStackTrace();
    }
  }

  /**
   * uses the local mailbox_addrss map to construct the Set of servers (Addr_Infos) to connect to
   * (Set.size() is <= recipients.length)
   *
   * @param recipients email addresses (each satisfying InputChecker.is_mail_address)
   * @return Set<Addr_Info>, the server addresses encompassing the recipients - only the _known_ ones tho
   *         Boolean delivery_failure, whether any recipient's domain could not be resolved
   *         String err_msg, is "" if delivery_failure == false,
   *                         otherwise gives some human-readable info about which domains were unknown
   */
  private Tripple<Set<Addr_Info>, Boolean, String> server_selection(List<String> recipients) {
    Set<Addr_Info> res = new HashSet<>();
    boolean delivery_failure = false;
    StringBuilder err_msg = new StringBuilder();
    for (String recp : recipients) {
      var split = recp.split("@", 2);
      var mb_domain = split[1];
      var addr = domainLookup(mb_domain);

      if (addr == null) {
        // no server-address was found by the domain-lookup
        delivery_failure = true;
        err_msg.append(mb_domain).append(" is not a known domain. ");
      } else {
        res.add(addr);
      }
    }
    return new Tripple<>(res, delivery_failure, err_msg.toString());
  }

  /**
   *
   * @param domain
   * @return something, or null if ...
   */
  private Addr_Info domainLookup(String domain) {
    var addr_str = domainLookupRec(domain, null);
    if (addr_str == null){
      return null;
    }
    var splitted = addr_str.split(":", 2);
    String hostname = splitted[0];
    int port;
    try {
      port = Integer.parseInt(splitted[1]);
    } catch (NumberFormatException nfe) {
      throw new ImplError("lookup didn't yield a valid port after ':'");
    }

    Addr_Info addr = null;
    try {
      addr = new Addr_Info(hostname, port);
    } catch (UnknownHostException e) {
      // this case is at least sort of handled by the null check in server_selection()
    }
    return addr;
  }

  private String domainLookupRec(String domain, INameserverRemote ns) {
    if (ns == null) {
      try {
        Registry registry = LocateRegistry.getRegistry(this.config.getString("registry.host"), this.config.getInt("registry.port"));
        ns = (INameserverRemote) registry.lookup(this.config.getString("root_id"));
      } catch (RemoteException | NotBoundException e) {
        e.printStackTrace();
        return null;
      }
    }
    String[] domainparts = domain.split("\\.");
    if (domainparts.length <= 1) {
      try {
        return ns.lookup(domain);
      } catch (RemoteException e) {
        e.printStackTrace();
      }
    } else {
      try {
        INameserverRemote next_ns = ns.getNameserver(domainparts[domainparts.length - 1]);
        if (next_ns != null) {
          return domainLookupRec(String.join(".", Arrays.copyOfRange(domainparts, 0, domainparts.length - 1)), next_ns);
        }
      } catch (RemoteException e) {
        e.printStackTrace();
      }
    }
    return null;
  }

}
