package dslab.client;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.util.*;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.shared_models.*;
import dslab.util.Config;
import dslab.util.InputChecker;
import dslab.util.Keys;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import static dslab.util.DMTP_Utils.*;

public class MessageClient implements IMessageClient, Runnable {

  private static final Log LOG = LogFactory.getLog(MessageClient.class);

  private final Shell shell;
  private final String HASH_ALGORITHM = "HmacSHA256";
  private Mac hMac; // gets initiated with the secret key in constructor.
  //  that (single) key is a stand-in for all shared secrets between any sender+recipient pair

  // Secure channel stuff
  private static final String ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";
  private static final String ALGORITHM_AES = "AES/CTR/NoPadding";
  SecretKey custom_aes_key;
  Cipher aes_enc_cipher, aes_dec_cipher;
  private boolean secure_channel_activated = false;

  // IP + Port for default servers
  private final Addr_Info transfer_addr;
  private final Addr_Info mailbox_addr;
  // the user mail address
  private final String own_mail_addr;
  // the login credentials for the mailbox server
  private final String mailbox_username;
  private final String mailbox_password;

  // The reader/writer objects are initialized in "connect_to_mailbox"
  // and are reused for all later communication with the mailbox server
  private BufferedReader mb_reader;
  private PrintWriter mb_writer;
  // TODO: properly end mailbox-connection
  // on shutdown (+ when aborting?): send "quit" (+ read "ok bye")
  // close the mb-socket. I _think_ mb_reader.close() does the trick.


  // LIFECYCLE START
  public static void main(String[] args) throws Exception {
    IMessageClient client = ComponentFactory.createMessageClient(args[0], System.in, System.out);
    client.run();
  }

  /**
   * Creates a new client instance,
   * reads in config infos from the client-*.properties file
   * and the "shared secret" from keys/hmac.key
   *
   * @param componentId the id of the component that corresponds to the Config resource
   * @param config      the component config
   * @param in          the input stream to read console input from
   * @param out         the output stream to write console output to
   */
  public MessageClient(String componentId, Config config, InputStream in, PrintStream out) {
    // read in from property file
    try {
      transfer_addr = new Addr_Info(config.getString("transfer.host"), config.getInt("transfer.port"));
      mailbox_addr = new Addr_Info(config.getString("mailbox.host"), config.getInt("mailbox.port"));
    } catch (UnknownHostException e) {
      throw new ConfigError("The address information for either transfer or mailbox server seems to be misconfigured");
    }
    own_mail_addr = config.getString("transfer.email");
    mailbox_username = config.getString("mailbox.user");
    mailbox_password = config.getString("mailbox.password");

    // read in "hmac.key" (the shared secret) from /keys/
    try {
      Key secretKey = Keys.readSecretKey(new File("keys/hmac.key"));
      hMac = Mac.getInstance(HASH_ALGORITHM);
      hMac.init(secretKey);
    } catch (IOException e) {
      throw new ConfigError("The shared secret key could not be read");
    } catch (NoSuchAlgorithmException e) {
      throw new ImplError("HASH_ALGORITHM doesn't resolve to an available Algo");
    } catch (InvalidKeyException e) {
      throw new ConfigError("the shared secret (HMAC key) seems to be misconfigured");
    }

    // configure the shell
    shell = new Shell(in, out);
    shell.register(this);
    shell.setPrompt(componentId + "> ");
  }

  @Override
  public void run() {
    try {
      connect_to_mailbox();
    } catch (ServerException e) {
      shell.out().println("mailbox server misbehaved while connecting: " + e.getMessage());
    } catch (IOException e) {
      shell.out().println("IO exception while connecting to the mailbox server");
      // todo: shutdown...
      // but probably not via "shutdown()", because that assumes we were connected in the first place
    }

    try {
      client_handshake();
    } catch (IOException | HandshakeException | ServerException e){
      shell.out().println("could not establish a secure connection to the mailbox server: " + e.getMessage());
      // see comment above
    }

    try {
      login();
    } catch (ServerException | IOException e) {
      // notify user
    }

    // NB: once shell runs, it masks (certain?) Errors thrown by the MessageClient thread
    shell.run();
  }

  @Override
  @Command
  public void shutdown() {
    try {
      disconnect_from_mailbox();
    } catch (IOException e) {
      shell.out().println("IOException while ending connection to mailbox server:\n" + e.getMessage());
    } catch (ServerException e) {
      shell.out().println("mailbox server misbehaved while disconnecting:\n" + e.getMessage());
    }
    // This will break the shell's read loop and make Shell.run() return gracefully.
    throw new StopShellException();
  }
  // LIFECYCLE END


  // tries to set up a connection to mb,
  // initializes reader + writer
  // checks for proper DMAP2.0 protocol start
  void connect_to_mailbox() throws IOException, ServerException {
    Socket conn = new Socket(mailbox_addr.ip(), mailbox_addr.port());
    mb_writer = new PrintWriter(conn.getOutputStream(), true);
    mb_reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));

    String server_line = mb_reader.readLine();

    // Am I talking to a DMAP server?
    if (server_line == null) {
      throw new ServerException("mailbox server didn't send an initial message");
    }
    if (!"ok DMAP2.0".equals(server_line)) {
      throw new ServerException("mailbox server's initial message was off");
    }
  }

  /**
   * precondition: the secure channel has been activated
   * ends the mailbox connection (as per DMAP) and closes the connection
   */
  void disconnect_from_mailbox() throws IOException, ServerException {
    if (!secure_channel_activated) {
      throw new ImplError("precondition breached");
    }

    printMsg(mb_writer, encipher("quit"));

    String server_line = mb_reader.readLine();
    if (server_line == null || !"ok bye".equals(decipher(server_line))){
      throw new ServerException("The mailbox server did not end the connection according to protocol");
    }
    mb_reader.close(); // This also closes the underlying socket (see e.g. https://stackoverflow.com/q/484925/)
  }

  /**
   * wip
   */
  void client_handshake() throws IOException, HandshakeException, ServerException {
    printMsg(mb_writer, "startsecure");

    // comp_id <- parse "ok <component-id>"
    String server_line = mb_reader.readLine();
    if(!server_line.matches("^ok .+"))  // regex =^= "ok " + <something, at least one character>
      throw new ServerException("Server did not answer with 'ok <component-id>' after 'startsecure' was sent");
    String mailbox_component_id = server_line.split(" ")[1];

    try {
      // pubkey <- get_pubkey(comp_id)
      Cipher rsa_cipher = Cipher.getInstance(ALGORITHM_RSA);
      PublicKey publicKey = Keys.readPublicKey(new File("keys/client/"+ mailbox_component_id +"_pub.der"));
      rsa_cipher.init(Cipher.ENCRYPT_MODE, publicKey);

      // new iv
      SecureRandom secureRandom = new SecureRandom();
      final byte[] iv_bytes = new byte[16];
      secureRandom.nextBytes(iv_bytes);
      IvParameterSpec iv = new IvParameterSpec(iv_bytes);

      // generate new secret key
      KeyGenerator generator = KeyGenerator.getInstance("AES");
      generator.init(256);
      custom_aes_key = generator.generateKey();

      // initialize an AES cipher
      aes_enc_cipher = Cipher.getInstance(ALGORITHM_AES);
      aes_enc_cipher.init(Cipher.ENCRYPT_MODE, custom_aes_key, iv);

      aes_dec_cipher = Cipher.getInstance(ALGORITHM_AES);
      aes_dec_cipher.init(Cipher.DECRYPT_MODE, custom_aes_key, iv);

      // challenge <- 32 random bytes
      // TODO: make random
      String challenge = "challenge";

      // printMsg(encode(pubkey, "ok <challenge> <secret-key> <iv>"))
      String req_plain = String.join(" ", "ok", challenge, Base64.getEncoder().encodeToString(custom_aes_key.getEncoded()),
              Base64.getEncoder().encodeToString(iv_bytes));
      byte[] challenge_encrypted = rsa_cipher.doFinal(req_plain.getBytes());
      String challenge_encoded = Base64.getEncoder().encodeToString(challenge_encrypted);

      mb_writer.println(challenge_encoded);
      mb_writer.flush();

      server_line = mb_reader.readLine();
      not_null_guard(server_line);

      // decode
      byte[] decoded_server_challenge = Base64.getDecoder().decode(server_line);
      // decrypt
      String decrypted_server_challenge = new String(aes_dec_cipher.doFinal(decoded_server_challenge));

      if(!"ok ".equals(decrypted_server_challenge.substring(0, 3))){
        throw new ServerException("Server did not return a valid response after sending the challenge");
      }

      if(!challenge.equals(decrypted_server_challenge.split(" ")[1]))
        throw new ServerException("challenges do not match");

      byte[] ok_encrypted = aes_enc_cipher.doFinal("ok".getBytes());
      String ok_encoded = Base64.getEncoder().encodeToString(ok_encrypted);

      mb_writer.println(ok_encoded);
      mb_writer.flush();

      secure_channel_activated = true;
    } catch (BadPaddingException | IllegalBlockSizeException e) {
      throw new HandshakeException("Bad padding or illegal block size in decryption",e);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new HandshakeException("Invalid key or invalid algorithm for the AES cypher",e);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new HandshakeException("The algorithm or padding used for initializing the AES cypher was not found",e);
    } catch (IllegalArgumentException e) {
      throw new HandshakeException("Invalid argument when decoding b64",e);
    }
  }

  /**
   * precondition: secure channel has been confirmed
   * The method encrypts and encodes the message with the shared secret key and base64 encoding.
   *
   * @param message to be encrypted and encoded
   * @return the resulting string which can be sent via the socket.
   */
  private String encipher(String message) {
    if (!secure_channel_activated || aes_enc_cipher == null) {
      throw new ImplError("encipher called without initiating secure channel or one of the ciphers is null");
    }

    byte[] encrypted = new byte[0];
    try {
      encrypted = aes_enc_cipher.doFinal(message.getBytes());
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new ImplError("in encipher: " + e.getMessage());
    }
    return Base64.getEncoder().encodeToString(encrypted);
  }

  /**
   * precondition: secure channel has been confirmed
   * The method decodes and decrypts the message with base64 decoding and the shared secret key.
   *
   * @param encoded message which is also encrypted
   * @return plaintext string which can be further interpreted by the server side protocol resolver.
   * @throws ServerException if the input was not encoded in a valid way ("bad block size" or "bad padding")
   */
  private String decipher(String encoded) throws ServerException {
    if (!secure_channel_activated || aes_enc_cipher == null) {
      throw new ImplError("decipher called without initiating secure channel or one of the ciphers is null");
    }

    byte[] decoded = Base64.getDecoder().decode(encoded);
    try {
      return new String(aes_dec_cipher.doFinal(decoded));
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new ServerException("error could not decipher \"" + encoded + "\": " + e.getMessage());
      // logging/bubbling up the incoming data could actually be a security risk.
      // at least if Log4j were involved https://de.wikipedia.org/wiki/Log4j#Bekanntwerden_einer_Sicherheitsl%C3%BCcke_im_Dezember_2021.
    }
  }

  void login () throws IOException, ServerException {
    printMsg(mb_writer, encipher("login " + mailbox_username + " " + mailbox_password));
    String server_line = decipher(mb_reader.readLine());
    if (!"ok".equals(server_line)){
      throw new ServerException("login failed, server said: " + server_line);
    }
  }

  @Override
  @Command
  public void inbox() {
    // "list" inbox content, decipher response
    printMsg(mb_writer, encipher("list"));
    String plaintext;
    try {
      String list_response = mb_reader.readLine();
      not_null_guard(list_response);
      plaintext = decipher(list_response);
    } catch (IOException e) {
      shell.out().println("error with the mailbox-connection:\n" + e.getMessage());
      return;
    } catch (ServerException e) {
      shell.out().println(e.getMessage());
      return;
    }
    // parse "list" response
    // parse result: a map with all message-ids as keys, nulls as values
    HashMap<Integer, DMTP_Message> inbox = new HashMap<>();

    String[] lines = plaintext.split("\\n");
    for (String l : lines){
      if ("ok".equals(l)) {
        // end of list reached / nop
        break;
      }

      // pick first part from "<message-id> <sender> <subject>"
      String[] l_parts = l.split("\\s");
      if (l_parts.length < 3) {
        shell.out().println(protocol_error_str + " in it's response to the 'list' command");
        return;
      }
      int msg_id;
      try { msg_id = Integer.parseInt(l_parts[0]); }
      catch (NumberFormatException nfe) {
        shell.out().println(protocol_error_str + " (a non-number as message-id)");
        return;
      }
      inbox.put(msg_id, null);
    }

    // for each msg_id
    for (Integer msg_id: inbox.keySet()) {
      // "show <msg_id>"
      printMsg(mb_writer, encipher("show " + msg_id));

      // read + decipher response
      String show_resp_plain;
      try {
        String show_response = mb_reader.readLine();
        not_null_guard(show_response);
        show_resp_plain = decipher(show_response);
      } catch (IOException e) {
        shell.out().println("error with the mailbox-connection:\n" + e.getMessage());
        return;
      } catch (ServerException e) {
        shell.out().println(e.getMessage());
        return;
      }

      // parse plaintext
      DMTP_Message new_msg = new DMTP_Message();
      String[] show_lines = show_resp_plain.split("\\n");
      for (String l : show_lines) {
        var cmd_cntnt = split_cmd_cntnt(l);
        if (cmd_cntnt.isEmpty()) {
          shell.out().println(protocol_error_str);
          return;
        }
        String command = cmd_cntnt.get().left;
        Optional<String> content = cmd_cntnt.get().right;
        switch (command) {
          case "to":
            if (content.isEmpty()) {
              shell.out().println(protocol_error_str + " (empty 'to' on a msg)");
              return;
            } else {
              try {
                new_msg.set_recips_by_string(content.get());
              } catch (FormatException e) {
                shell.out().println(protocol_error_str + " (invalid 'to' field on a msg)");
                return;
              }
            }
            break;
          case "from":
            if (content.isEmpty() || !InputChecker.is_mail_address(content.get())) {
              shell.out().println(protocol_error_str + " (invalid 'from' on a msg)");
              return;
            } else {
              new_msg.sender = content.get();
            }
            break;
          case "subject":
            new_msg.subject = content.orElse("");
            break;
          case "data":
            new_msg.text_body = content.orElse("");
            break;
          case "hash":
              new_msg.hash = content.orElse("");
          break;
        }
      }

      if (DMTP_Message.collectProblems(new_msg).size() == 0) {
        inbox.put(msg_id, new_msg);
      } else {
        shell.out().println("msg " + msg_id + " had problems" );
      }
    }

    // pretty print each message inbox (format not specified)
    for (var mapping: inbox.entrySet()) {
      shell.out().println("message #" + mapping.getKey() + ":");
      shell.out().println(mapping.getValue().toString());
    }
  }

  @Override
  @Command
  public void delete(String id) {
    printMsg(mb_writer, "delete " + id);
    String response_plain;
    try {
      String response = mb_reader.readLine();
      not_null_guard(response);
      response_plain = decipher(response);
    } catch (IOException e) {
      shell.out().println("error - IO exception occurred while communicating with the mailbox server");
      return;
    } catch (ServerException e) {
      shell.out().println(e.getMessage());
      return;
    }
    shell.out().println(response_plain);
  }

  @Override
  @Command
  public void verify(String id) {
        /*
        TODO
        Check Handbook/Tips & Tricks chapter for useful code snippets.
        Create a javax.crypto.Mac instance using the HmacSHA256 algorithm,
        initialize it with the shared secret key.
        
        prepare message-string for hashing (bytes_to_hash)
        DMTP_to_bytes()

            convert to bytes
        
        using Mac instance, calc 32-byte hash of bytes_to_hash

        use Base64 binary-to-text to get plaintext hash
        attach to 'hash' field
        */
  }


  final String connection_ended_str = "error server ended connection prematurely";
  final String protocol_error_str = "error server committed a protocol error";

  /**
   * Parse a mail and try to send it to the configured transfer server.
   * The Orvell shell parses the different arguments by interpreting space as delimiters,
   * except in "quoted strings" (which get unquoted by Orvell)
   *
   * Prints "ok" if the mail was successfully parsed and sent
   * Prints "error <something>" if it wasn't
   *
   * @param to      comma separated list of recipients
   * @param subject the message subject
   * @param data    the message data
   */
  @Override
  @Command
  public void msg(String to, String subject, String data) {
    // craft the DMTP2.0 message, including hash.
    DMTP_Message msg = new DMTP_Message();
    msg.sender = own_mail_addr;
    try {
      msg.set_recips_by_string(to);
    } catch (FormatException fe) {
      shell.out().println("error" + fe.getMessage());
      return;
    }
    msg.subject = subject;
    msg.text_body = data;
    msg.hash = calculateHash(msg);

    // connect to Transfer Server
    String result = "error in the program flow, this should never be printed";
    try (Socket conn = new Socket(transfer_addr.ip(), transfer_addr.port());
         PrintWriter transfer_writer = new PrintWriter(conn.getOutputStream(), true);
         BufferedReader transfer_reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
      try {
        // and try to send the mail
        result = play_DMTP2(transfer_writer, transfer_reader, msg);
      } catch (ServerException se) {
        shell.out().println(se.getMessage());
        return;
      } catch (IOException e) {
        shell.out().println("error - IO exception occurred while communicating with the transfer server");
      }
    } catch (IOException e) {
      shell.out().println("error - IO exception while connecting to the transfer server");
    }
    // I let try-with-resources close all the resources.

    shell.out().println(result);
  }

  /**
   * go through DMTP2.0, i.e. send off the DMTP_Message if everything goes right.
   *
   * @return "ok" if everything goes right, "error <something>" if the server sent a protocol-conforming error
   * @throws ServerException if the server violated the DMTP2.0 protocol or ended the connection
   * @throws IOException if any of the read/write socket operations failed
   */
  private String play_DMTP2(PrintWriter out, BufferedReader in, DMTP_Message msg) throws ServerException, IOException {

    // Am I talking to a DMTP server?
    String server_line = in.readLine();
    not_null_guard(server_line);
    if (!"ok DMTP2.0".equals(server_line)) {
      throw new ServerException("transfer server's initial message was off");
    }

    out.println("begin");
    server_line = in.readLine();
    ok_guard(server_line);

    // pass through recipients
    out.println("to " + String.join(",", msg.recipients));
    server_line = in.readLine();
    not_null_guard(server_line);
    if (server_line.matches("^error.*")) { // regex =^= "error" + whatever
      return "error on recipients field. Server said: " + server_line;
    }
    if (!server_line.matches("^ok \\d*")) { // regex =^= "ok <integer"
      return protocol_error_str;
    }

    // set sender
    out.println("from " + msg.sender);
    server_line = in.readLine();
    ok_guard(server_line);

    // set subject
    out.println("subject " + msg.subject);
    server_line = in.readLine();
    ok_guard(server_line);

    // set mail's text body
    out.println("data " + msg.text_body);
    server_line = in.readLine();
    ok_guard(server_line);

    // set mail's hash (should always be present when sending from the client)
    out.println("hash " + msg.hash);
    server_line = in.readLine();
    ok_guard(server_line);

    // finalize mail and send it off
    out.println("send");
    server_line = in.readLine();
    ok_guard(server_line);

    // quit the socket/DMTP connection
    out.println("quit");
    server_line = in.readLine();
    not_null_guard(server_line);
    if (!"ok bye".equals(server_line)) {
      throw new ServerException(protocol_error_str);
    }

    // sending finished
    // assert (in.readLine() == null) - if the other server does DMTP correctly.

    return "ok";
  }

  // I use these guard-functions instead of several if-statements above.
  // I am aware that using exceptions for program flow is kind of an anti-pattern,
  // but here it allows avoiding a good bit of code duplication + repetitive if-statements
  // (which non-exception-throwing functions could not avoid)
  /**
   * @param server_line is checked for being exactly "ok" (and not null)
   * @throws ServerException with a meaningful (for DMTP/DMAP) details-message
   */
  private void ok_guard(String server_line) throws ServerException {
    not_null_guard(server_line);
    if (!"ok".equals(server_line)) {
      throw new ServerException(protocol_error_str);
    }
  }
  private void not_null_guard(String server_line) throws ServerException {
    if (server_line == null) {
      throw new ServerException(connection_ended_str);
    }
  }

  /**
   * Returns the base64 encoded hash of the message
   *
   * @param message to be hashed
   * @return b64 encoded hash of the message
   */
  private String calculateHash(DMTP_Message message) {
    hMac.update(message.getJoined().getBytes());
    byte[] hash = hMac.doFinal();
    return Base64.getEncoder().encodeToString(hash);
  }

  /**
   * Returns the base64 encoded hash of the message
   *
   * @param message to be hashed, formatted as described in assignment sheet (Fields joined with '\n')
   * @return b64 encoded hash of the message
   */
  private String calculateHash(String message) {
    hMac.update(message.getBytes());
    byte[] hash = hMac.doFinal();
    return Base64.getEncoder().encodeToString(hash);
  }

  /**
   * Checks if the value of the hash matches the actual hash of the message
   *
   * @param message received message, to be checked
   * @param hash    received hash (b64 encoded), to be checked
   * @return true if hash is correct, false otherwise
   */
  private boolean isHashCorrect(DMTP_Message message, String hash) {
    return Arrays.equals(Base64.getDecoder().decode(hash), Base64.getDecoder().decode(calculateHash(message)));
  }

  /**
   * Checks if the value of the hash matches the actual hash of the message
   *
   * @param message received message, to be checked (fields joined with '\n')
   * @param hash    received hash (b64 encoded), to be checked
   * @return true if hash is correct, false otherwise
   */
  private boolean isHashCorrect(String message, String hash) {
    return Arrays.equals(Base64.getDecoder().decode(hash), Base64.getDecoder().decode(calculateHash(message)));
  }
}
