package dslab.mailbox.sub_threads;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import dslab.mailbox.Inbox;
import dslab.mailbox.models.MB_Thread;
import dslab.shared_models.ConnectionEnd;
import dslab.shared_models.DMTP_Message;
import dslab.util.InputChecker;
import dslab.util.Keys;
import dslab.util.Pair;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static dslab.util.DMTP_Utils.*;

public class DMAP_Thread extends MB_Thread {
  public DMAP_Thread(String componentId, String domain, AtomicBoolean shutdown_initiated, Socket incomingConn, Map<String, Pair<String, Inbox>> user_db) {
    super(componentId,domain, shutdown_initiated, incomingConn, user_db);
  }

  private enum HandshakeState{
    DEACTIVATED, INITIALIZED, GOT_CHALLENGE, CONFIRMED
  };

  private HandshakeState state = HandshakeState.DEACTIVATED;
  private static final Log LOG = LogFactory.getLog(DMAP_Thread.class);

  private boolean secure_started = false;
  private final String ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";
  private final String ALGORITHM_AES = "AES/CTR/NoPadding";
  PrivateKey pk;
  Cipher rsa_dec_cipher;
  Cipher aes_enc_cipher;
  Cipher aes_dec_cipher;

  @Override
  public void run() {


    try ( // prepare the input reader for the socket
          BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
          // prepare the writer for responding to clients requests
          PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {
      Inbox logged_in_inbox = null;
      String inc_line;

      // Initialize the private key and the cipher
      pk = Keys.readPrivateKey(new File("keys/server/mailbox-earth-planet.der"));
      try{
        rsa_dec_cipher = Cipher.getInstance(ALGORITHM_RSA);
        rsa_dec_cipher.init(Cipher.DECRYPT_MODE, pk);
      }catch(NoSuchAlgorithmException | NoSuchPaddingException e){
        System.err.println("No Such Algorithm or padding in DMAP, failed to create the cipher");
      } catch (InvalidKeyException e){
        System.err.println("Sorry the key is invalid, could not initialize the cipher");
      }



      if (shutdown_initiated.get()) {
        return;
      }

      ok(writer, "DMAP2.0");

      // read client requests
      while (!shutdown_initiated.get() && (inc_line = reader.readLine()) != null) {

        // TODO: if secure is off, continue
        // TODO: if secure, decode first then decrypt, only then continue

        var parsed = split_cmd_cntnt(inc_line);
        if (parsed.isEmpty()) {
          protocol_error(writer);
          break;
        }

        try {
          logged_in_inbox = handle_line(writer, logged_in_inbox, parsed.get().left, parsed.get().right, reader);
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

  private void handshake(PrintWriter writer, BufferedReader reader) throws IOException, ConnectionEnd{
    ok(writer, componentId);

    String inc_line;

    try {
      while(!shutdown_initiated.get() && (inc_line = reader.readLine()) != null && state != HandshakeState.CONFIRMED) {
        switch (state){
          case DEACTIVATED:
            error(writer, "Got into handshake when secure deactivated");
            throw new ConnectionEnd();
          case INITIALIZED:
            byte[] decoded = Base64.getDecoder().decode(inc_line);
            String decrypted = new String(rsa_dec_cipher.doFinal(decoded));
            String[] splitted_arr = decrypted.trim().split(" ");
            if(splitted_arr.length != 4) {
              LOG.error("Invalid syntax in third message of the secure handshake");
              throw new ConnectionEnd();
            }
            String challenge_enc = splitted_arr[1];

            // AES Key
            String secretAesKey_enc = splitted_arr[2];
            byte[] secret_AES_key = Base64.getDecoder().decode(secretAesKey_enc);
            SecretKey aes_key = new SecretKeySpec(secret_AES_key, "AES");

            // IV
            String init_vector_enc = splitted_arr[3];
            byte[] init_vector = Base64.getDecoder().decode(init_vector_enc);
            IvParameterSpec iv = new IvParameterSpec(init_vector);

            // AES Ciphers
            //  Encrypt
            aes_enc_cipher = Cipher.getInstance("AES/CTR/NoPadding");
            aes_enc_cipher.init(Cipher.ENCRYPT_MODE, aes_key, iv);
            //  Decrypt
            aes_dec_cipher = Cipher.getInstance("AES/CTR/NoPadding");
            aes_dec_cipher.init(Cipher.DECRYPT_MODE, aes_key, iv);

            // RESPONSE
            String response_plain = "ok "+ challenge_enc;
            byte[] response_encrypted = aes_enc_cipher.doFinal(response_plain.getBytes());
            String response_encoded = Base64.getEncoder().encodeToString(response_encrypted);

            writer.println(response_encoded);
            writer.flush();

            state = HandshakeState.GOT_CHALLENGE;
            break;
          case GOT_CHALLENGE:
            byte[] decoded_aes = Base64.getDecoder().decode(inc_line);
            String decrypted_aes = new String(aes_dec_cipher.doFinal(decoded_aes));
            if(decrypted_aes.trim().equals("ok") ){
              state = HandshakeState.CONFIRMED;
              return;
            }
            else{
              LOG.error("Client failed to confirm the correctness of the challenge");
              throw new ConnectionEnd();
            }
          case CONFIRMED:
            error(writer, "Got into handshake when secure already confirmed");
            break;
          default:
            error(writer, "Got into handshake when secure deactivated");
            throw new ConnectionEnd();
        }

      }

    } catch (BadPaddingException | IllegalBlockSizeException e){
      LOG.error("Bad padding or illegal block size in decrpytion");
      throw new ConnectionEnd();
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e){
      LOG.error("Invalid key or invalid algorithm for the AES cypher");
      throw new ConnectionEnd();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e){
      LOG.error("The algorithm or padding used for initializing the AES cypher was not found");
      throw new ConnectionEnd();
    }


  }

  /**
   *
   * @param them the handle (PrintWriter) via which msgs shall be sent
   * @param inbox pre: null exactly if no successful "login" yet, or if the user has logged out again.
   * @param command DMAP command as String. Anything apart from {login, list, show, delete, logout} leads to connection end, as does "quit"
   * @param content
   * @param reader the handle (BufferedReader) where we receive messages
   * @return  null if no successful login yet, after logouts or bad initial logins
   *          new inbox after a good login
   *          passed-through inbox for "normal" commands when logged in already
   * @throws ConnectionEnd in all cases where the protocol demands it
   */
  private Inbox handle_line(PrintWriter them, Inbox inbox, String command,
                            Optional<String> content, BufferedReader reader) throws ConnectionEnd, IOException {
    if (inbox == null) {
      switch (command) {
        case "login":
          if (content.isEmpty()) {
            error(them, "credentials required");
          } else {
            String[] credentials = content.get().split("\\s", 2);
            var username = credentials[0];
            var password = credentials[1]; // may be null
            if (user_db.containsKey(username) && user_db.get(username).left.equals(password)){
              // successful login!
              inbox = user_db.get(username).right;
              ok(them);
              return inbox;
            } else {
              error(them, "bad credentials");
              return null;
            }
          }
          break;
        case "startsecure":
          if(state == HandshakeState.CONFIRMED){
            error(them, "secure channel already running");
          }else {
            state = HandshakeState.INITIALIZED;
            handshake(them, reader);
          }
          // TODO: initiate the handshake
          return null;
        case "quit":
          ok(them, "bye");
          throw new ConnectionEnd();
        case "list":
        case "show":
        case "delete":
        case "logout":
          error(them, "not logged in");
          return null;
        default:
          protocol_error(them);
          throw new ConnectionEnd();
      }
    }

    // assert: inbox != null
    switch (command) {
      case "login":
        error(them, "already logged in, 'logout' to switch accounts");
        return inbox;
      case "list":
        var mail_sigs = inbox.list_mails_sigs();
        for(String sig : mail_sigs){
          printMsg(them, sig);
        }
        return inbox;
      case "show":
        var id = try_parse_int(content);
        if(id.isPresent()){
          var mby_msg = inbox.get(id.getAsInt());
          if(mby_msg.isPresent()){
            var msg = mby_msg.get();
            them.println("from " + msg.sender);
            them.println("to " + String.join(",", msg.recipients));
            them.println("subject " + msg.subject);
            them.println("data " + msg.text_body);
            them.flush();
          } else {
            error(them, "unknown message id");
          }
        } else {
          error(them, "missing or invalid message id");
        }
        return inbox;
      case "delete":
        id = try_parse_int(content); // test whether that doesn't crash ("var" keyword from other branch super dodgy)
        if(id.isPresent()){
          if(inbox.delete(id.getAsInt())){
            ok(them);
          } else {
            error(them, "unknown message id");
          }
        } else {
          error(them, "missing or invalid message id");
        }
        return inbox;
      case "startsecure":
        if(state==HandshakeState.CONFIRMED){
          error(them, "secure channel already running");
        }else {
          state = HandshakeState.INITIALIZED;
          handshake(them, reader);
        }
        // TODO: initiate the handshake
        return inbox;
      case "logout":
        ok(them);
        return null;
      case "quit":
        ok(them, "bye");
        throw new ConnectionEnd();
      default:
        protocol_error(them);
        throw new ConnectionEnd();
    }
  }

  private static OptionalInt try_parse_int(Optional<String> content){
    if(content.isPresent()){
      int id;
      try {
        id = Integer.parseInt(content.get());
      } catch (NumberFormatException e) {
        // actually more "malformed message id" than "unknown message id"
        return OptionalInt.empty();
      }
      return OptionalInt.of(id);
    } else {
      return OptionalInt.empty();
    }
  }
}
