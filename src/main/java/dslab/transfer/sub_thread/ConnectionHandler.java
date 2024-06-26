package dslab.transfer.sub_thread;

import dslab.mailbox.sub_threads.DMTP_Thread;
import dslab.shared_models.ConnectionEnd;
import dslab.shared_models.DMTP_Message;
import dslab.shared_models.FormatException;
import dslab.util.InputChecker;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static dslab.util.DMTP_Utils.*;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;


/**
 * Thread to handle 1 incoming connection,
 * 'parse' any Mail-Sending-Requests
 * then place the received message (if any) in the queue
 */
public class ConnectionHandler extends Thread {

  private final AtomicBoolean shutdown_initiated;
  private final Socket socket;
  private final BlockingQueue<DMTP_Message> waiting_messages;

  private static final Log LOG = LogFactory.getLog(ConnectionHandler.class);

  public ConnectionHandler(
      AtomicBoolean shutdown_initiated,
      Socket socket,
      BlockingQueue<DMTP_Message> waiting_messages) {
    this.shutdown_initiated = shutdown_initiated;
    this.socket = socket;
    this.waiting_messages = waiting_messages;
  }

  /**
   * @param them
   * @param msg     pre: null exactly if no "begin" encountered yet, or if a message was just sent off
   * @param command
   * @param content
   * @return adapted msg - reset to null after successful "send"
   */
  // mby make content an Optional?
  //
  private DMTP_Message handle_line(PrintWriter them, DMTP_Message msg, String command, Optional<String> content) throws ConnectionEnd {
    if (msg == null) {
      if (content.isPresent()) {
        protocol_error(them);
        throw new ConnectionEnd();
      }
      switch (command) {
        case "begin":
          msg = new DMTP_Message();
          ok(them);
          return msg;
        case "quit":
          ok(them, "bye");
          throw new ConnectionEnd();
        default:
          protocol_error(them);
          throw new ConnectionEnd();
      }
    }

    // assert: msg != null
    switch (command) {
      case "to":
        if (content.isPresent()) {
          int n_recipients;
          try {
            n_recipients = msg.set_recips_by_string(content.get());
          } catch (FormatException fe) {
            error(them, fe.getMessage());
            break;
          }
          ok(them, String.valueOf(n_recipients));
        } else {
          error(them, "no recipients specified");
        }
        break;
      case "from":
        if (content.isEmpty()) {
          error(them, "no sender specified");
          break;
        }
        var sender = content.get();
        if (InputChecker.is_mail_address(sender)) {
          msg.sender = sender;
          ok(them);
        } else {
          error(them, "not an email address");
        }
        break;
      case "subject":
        msg.subject = content.orElse("");
        ok(them);
        break;
      case "data":
        msg.text_body = content.orElse("");
        ok(them);
        break;
      case "hash":
        msg.hash = content.orElse("");
        ok(them);
        break;
      case "send":
        List<String> probs = DMTP_Message.collectProblems(msg);
        if (probs.size() == 0) {
          waiting_messages.add(msg);
          ok(them);
          msg = null;
        } else {
          error(them, String.join(", ", DMTP_Message.collectProblems(msg)));
        }
        break;
      case "quit":
        ok(them, "bye");
        throw new ConnectionEnd();
      default:
        protocol_error(them);
        throw new ConnectionEnd();
    }

    return msg;
  }

  public void run() {
    try ( // prepare the input reader for the socket
          BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
          // prepare the writer for responding to clients requests
          PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {
      DMTP_Message message = null;
      String inc_line;

      if (shutdown_initiated.get()) {
        return;
      }

      ok(writer, "DMTP2.0");

      // read client requests
      while (!shutdown_initiated.get() && (inc_line = reader.readLine()) != null) {
        System.out.println("Client sent the following request: " + inc_line);

        var parsed = split_cmd_cntnt(inc_line);
        if (parsed.isEmpty()) {
          protocol_error(writer);
          break;
        }

        try {
          message = handle_line(writer, message, parsed.get().left, parsed.get().right);
        } catch (ConnectionEnd e) {
          // the connection ended according to the protocol.
          // therefore, break out of the read-loop
          break;
        }
      }
    } catch (SocketException e) {
      // see documentation at DMAP_Thread
    } catch (IOException e) {
      // you should properly handle all other exceptions
      // idk what could be wrong / how it would be handled...
      // ... but creating reader + writer may have something to do with it.
      throw new UncheckedIOException(e);
    } finally {
      if (socket != null && !socket.isClosed()) {
        try {
          socket.close();
        } catch (IOException e) {
          // LVA-sanctioned "Ignore unhandle-able case"
          e.printStackTrace();
        }
      }
    }
  }
}
