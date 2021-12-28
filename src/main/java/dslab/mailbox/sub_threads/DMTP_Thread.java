package dslab.mailbox.sub_threads;

import dslab.mailbox.Inbox;
import dslab.mailbox.models.MB_Thread;
import dslab.shared_models.ConnectionEnd;
import dslab.shared_models.DMTP_Message;
import dslab.util.InputChecker;
import dslab.util.Pair;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static dslab.util.DMTP_Utils.*;

public class DMTP_Thread extends MB_Thread {

  public DMTP_Thread(String componentId, String domain, AtomicBoolean shutdown_initiated, Socket incomingConn, Map<String, Pair<String, Inbox>> user_db) {
    super(componentId, domain, shutdown_initiated, incomingConn, user_db);
  }

  @Override
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
      // when the socket is closed, the I/O methods of the Socket will throw a SocketException
      // almost all SocketException cases indicate that the socket was closed
      System.out.println("SocketException while handling socket:\n" + e.getMessage());
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


  /**
   * @param them
   * @param msg     pre: null exactly if no "begin" encountered yet, or if a message was just sent off
   * @param command DMTP command as String. Anything apart from {begin, to, from, subject, data, send} leads to connection end, as does "quit"
   * @param content
   * @return adapted msg - reset to null after successful "send"
   */
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
        // (could be extracted w/ "msg <- some_fun(msg, content, them, (domain, user_db)"

        // mailbox servers only accept messages with >= 1 _known, own_ recipients.
        // recipients that do not have "@<this.domain>" are ignored.
        // if any recipients that _do_ belong to "this.domain", but don't correspond to a user in the user_db
        // -> "error unknown recipient <pre @ part>"
        if (content.isPresent()) {
          String[] recipients_parsed = content.get().split(",", 0);
          int accepted_recips = 0;
          boolean any_problems = false;
          for (String r : recipients_parsed) {
            if (!InputChecker.is_mail_address(r)) {
              error(them, "at least one recipient address is malformed");
              any_problems = true;
              break;  // break _the for loop_
            }
            // InputChecker call above guarantees |addr_split| = 2
            var addr_split = r.split("@", 0);
            if (!domain.equals(addr_split[1])) {
              continue; // to the next elem of recipients_parsed
            }
            if (!user_db.containsKey(addr_split[0])) {
              error(them, "unknown recipient " + addr_split[0]);
              any_problems = true;
              break;
            }
            // r is a valid address, belonging to "this" domain, and belonging to a known user.
            accepted_recips++;
          }
          if (accepted_recips == 0
              && !any_problems) { // "&& !any_problems" to not print multiple errors in response
            error(them, "none of the recipients are known");
            any_problems = true;
          }
          // finally, if all recipient checks passed, add recipients to msg and "ok" them
          if (!any_problems) {
            msg.recipients = new LinkedList<>();
            Collections.addAll(msg.recipients, recipients_parsed);
            ok(them, String.valueOf(accepted_recips));
          }
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
          for (String r : msg.recipients) {
            mby_add_mail_to_mailbox(r, msg);
          }
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

  /**
   * if input corresponds to a locally known user, add msg to that users mailbox
   *
   * @param recep_address pre: mail-address-shaped.
   */
  private void mby_add_mail_to_mailbox(String recep_address, DMTP_Message msg) {
    var addr_split = recep_address.split("@", 0);
    if (domain.equals(addr_split[1]) && user_db.containsKey(addr_split[0])) {
      user_db.get(addr_split[0]).right.add(msg);
    }
  }
}
