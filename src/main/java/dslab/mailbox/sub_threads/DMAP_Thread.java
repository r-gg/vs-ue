package dslab.mailbox.sub_threads;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
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
    DEACTIVATED, // Default state, no secure communication, all messages in plaintext
    INITIALIZED, // Handshake initialized with startsecure
    GOT_CHALLENGE,  // Decrypted the challenge message
    CONFIRMED // Secure channel activated, all messages encrypted and encoded
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
      // TODO: read in the appropriate key based on the Mailbox-Server's component-id
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

        if(state == HandshakeState.CONFIRMED && aes_dec_cipher != null){
          inc_line = decipher(inc_line);
        }

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
    } catch (IllegalBlockSizeException | BadPaddingException e){
      LOG.error("Illegal block size or bad padding while enciphering or deciphering");

    }
    finally {
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
    } catch (IllegalArgumentException e){
      LOG.error("Invalid agrument when decoding b64");
      throw new ConnectionEnd();
    }


  }

  /**
   * If secure channel has been confirmed, the method encrypts and encodes the message with the shared secret key and base64 encoding.
   * The result of the method is the encrypted and encoded message which can be sent via the socket.
   * @param message to be encryped and encoded
   * @returns string with the encryped and then encoded message if the secure channel was started, otherwise null
   */
  private String encipher(String message) throws IllegalBlockSizeException, BadPaddingException{
    if(state != HandshakeState.CONFIRMED || aes_enc_cipher == null){
      LOG.error("Encrypt called without initiating secure channel or one of the ciphers is null");
      return null;
    }else {
      byte[] encrypted = aes_enc_cipher.doFinal(message.getBytes());
      return Base64.getEncoder().encodeToString(encrypted);
    }
  }

  /**
   * If secure channel has been confirmed, the method decodes and decrypts the message with the shared secret key and base64 encoding.
   * The result of the method is the decoded and decrypted message which can be further interpreted by the server side protocol resolver.
   * @param encoded message which is also encrypted
   * @returns string with the plain text message if the secure channel was started, otherwise null
   */
  private String decipher(String encoded) throws IllegalBlockSizeException, BadPaddingException{
    if(state != HandshakeState.CONFIRMED || aes_dec_cipher == null){
      LOG.error("Encrypt called without initiating secure channel or one of the ciphers is null");
      return null;
    }else {
      byte[] decoded = Base64.getDecoder().decode(encoded);
      return new String(aes_dec_cipher.doFinal(decoded));
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
                            Optional<String> content, BufferedReader reader) throws ConnectionEnd, IOException, IllegalBlockSizeException, BadPaddingException{
    if (inbox == null) {
      switch (command) {
        case "login":
          if (content.isEmpty()) {
            printMsg(them, encipher_mby("error credentials required"));
          } else {
            String[] credentials = content.get().split("\\s", 2);
            var username = credentials[0];
            var password = credentials[1]; // may be null
            if (user_db.containsKey(username) && user_db.get(username).left.equals(password)){
              // successful login!
              inbox = user_db.get(username).right;
              //ok(them);
              printMsg(them, encipher_mby("ok"));
              return inbox;
            } else {
              printMsg(them, encipher_mby("error bad credentials"));
              return null;
            }
          }
          break;
        case "startsecure":
          if(state == HandshakeState.CONFIRMED){
            printMsg(them, encipher("secure channel already running"));
          }else {
            state = HandshakeState.INITIALIZED;
            handshake(them, reader);
          }
          return null;
        case "quit":
          printMsg(them, encipher("ok bye"));
          throw new ConnectionEnd();
        case "list":
        case "show":
        case "delete":
        case "logout":
          printMsg(them, encipher_mby("error not logged in"));
          return null;
        default:
          protocol_error(them); // TODO: encrypt as well?
          throw new ConnectionEnd();
      }
    }

    // assert: inbox != null
    switch (command) {
      case "login":
        printMsg(them, encipher_mby("error already logged in, 'logout' to switch accounts"));
        return inbox;
      case "list":
        var mail_sigs = inbox.list_mails_sigs();
        StringBuilder list = new StringBuilder();
        for(String sig : mail_sigs){
          list.append(sig).append("\n");
        }
        list.append("ok"); // DMAP2.0 change
        // Encrypting the whole message
        printMsg(them, encipher_mby(list.toString()));
        return inbox;
      case "show":
        var id = try_parse_int(content);
        if(id.isPresent()){
          var mby_msg = inbox.get(id.getAsInt());
          if(mby_msg.isPresent()){
            var msg = mby_msg.get();
            String details = "from " + msg.sender + "\n"
                    + "to " + String.join(",", msg.recipients) + "\n"
                    + "subject " + msg.subject + "\n"
                    + "data " + msg.text_body + "\n"
                    + "hash " + ((msg.hash != null)? msg.hash : "");
            printMsg(them, encipher_mby(details));
//            them.println("from " + msg.sender);
//            them.println("to " + String.join(",", msg.recipients));
//            them.println("subject " + msg.subject);
//            them.println("data " + msg.text_body);
            //them.flush();
          } else {
            printMsg(them, encipher_mby("error unknown message id"));
          }
        } else {
          printMsg(them, encipher_mby("error missing or invalid message id"));
        }
        return inbox;
      case "delete":
        id = try_parse_int(content); // test whether that doesn't crash ("var" keyword from other branch super dodgy)
        if(id.isPresent()){
          if(inbox.delete(id.getAsInt())){
            printMsg(them, encipher_mby("ok"));
          } else {
            printMsg(them, encipher_mby("error unknown message id");
          }
        } else {
          printMsg(them, encipher_mby("error missing or invalid message id");
        }
        return inbox;
      case "startsecure":
        if(state==HandshakeState.CONFIRMED){
          printMsg(them, encipher("error secure channel already running"));
        }else {
          state = HandshakeState.INITIALIZED;
          handshake(them, reader);
        }
        return inbox;
      case "logout":
        printMsg(them, encipher_mby("ok"));
        return null;
      case "quit":
        printMsg(them, encipher_mby("ok bye");
        throw new ConnectionEnd();
      default:
        protocol_error(them); // TODO: Also encrypt?
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

  /**
   * depending on the HandshakeState, simply returns the string as is or encrypts it
   * @param str which may get encrypted
   * @return either
   */
  private String encipher_mby(String str) throws IllegalBlockSizeException, BadPaddingException {
    return (state == HandshakeState.CONFIRMED) ? encipher(str) : str;
    }
  }
}
