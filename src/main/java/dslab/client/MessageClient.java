package dslab.client;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.shared_models.Addr_Info;
import dslab.shared_models.ConfigException;
import dslab.shared_models.DMTP_Message;
import dslab.shared_models.FormatException;
import dslab.util.Config;
import dslab.util.Keys;

import javax.crypto.Mac;

import static dslab.util.DMTP_Utils.printMsg;

public class MessageClient implements IMessageClient, Runnable {

  private final Shell shell;
  private final String HASH_ALGORITHM = "HmacSHA256";
  private Mac hMac; // gets initiated with the secret key in constructor.
  //  that (single) key is a stand-in for all shared secrets between any sender+recipient pair

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
      throw new ConfigException("The address information for either transfer or mailbox server seems to be misconfigured", e);
    }
    own_mail_addr = config.getString("transfer.email");
    mailbox_username = config.getString("mailbox.user");
    mailbox_password = config.getString("mailbox.password");

    // read in "hmac.key" (the shared secret) from /keys/
    try {
      // Creating the hash:
      Key secretKey = Keys.readSecretKey(new File("keys/hmac.key"));
      hMac = Mac.getInstance(HASH_ALGORITHM);
      hMac.init(secretKey);
    } catch (NoSuchAlgorithmException | InvalidKeyException | IOException e) {
      System.err.println("HMAC init failed");
      // TODO: Gracefully shutdown
    }

    // configure the shell
    shell = new Shell(in, out);
    shell.register(this);
    shell.setPrompt(componentId + "> ");
  }

  @Override
  public void run() {
    connect_to_mailbox();
    client_handshake();

    // TODO:
    // "login"

    // NB: once shell runs, it masks (certain?) Errors thrown by the MessageClient thread
    shell.run();
  }

  @Override
  @Command
  public void shutdown() {
    // This will break the shell's read loop and make Shell.run() return gracefully.
    throw new StopShellException();
  }
  // LIFECYCLE END


  // tries to set up a connection to mb,
  // initializes reader + writer
  // checks for proper DMAP2.0 protocol start
  void connect_to_mailbox() {
    Socket conn = null;
    try {
      conn = new Socket(mailbox_addr.ip(), mailbox_addr.port());
    } catch (IOException e) {
      throw new UncheckedIOException("could not connect to configured Mailbox server", e);
    }
    try {
      mb_writer = new PrintWriter(conn.getOutputStream(), true);
      mb_reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));

      String server_line = mb_reader.readLine();

      // Am I talking to a DMAP server?
      if (server_line == null) {
        throw new ServerError("mailbox server didn't send an initial message");
      }
      if (!"ok DMAP2.0".equals(server_line)) {
        throw new ServerError("mailbox server's initial message was off");
      }
    } catch (IOException e) {
      throw new UncheckedIOException("IO exception during initial mailbox-server communication", e);
    }
  }

  /**
   * wip
   */
  void client_handshake() {
    printMsg(mb_writer, "startsecure");
    // TODO:
    // comp_id <- parse "ok <component-id>"
    // pubkey <- get_pubkey(comp_id)
    // challenge <- 32 random bytes
    // "initialize an AES cipher, by"
    // new secret key
    // new iv
    // printMsg(encode(pubkey, "ok <challenge> <secret-key> <iv>"))
  }

  @Override
  @Command
  public void inbox() {
    // TODO
    // 1) "list" inbox content
    // 2) parse -> List<DMTP_Msg> w/ many holes
    // 3) for each msg: "show" -> parse -> fill holes
    // 4) pretty print each message inbox (format not specified)
  }

  @Override
  @Command
  public void delete(String id) {
    // TODO
    shell.out().println(id);
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
  final String protocol_error_str = "error server committed a DMTP protocol error";

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
      } catch (ServerError se) {
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
   * @throws ServerError if the server violated the DMTP2.0 protocol or ended the connection
   * @throws IOException if any of the read/write socket operations failed
   */
  private String play_DMTP2(PrintWriter out, BufferedReader in, DMTP_Message msg) throws ServerError, IOException {

    // Am I talking to a DMTP server?
    String server_line = in.readLine();
    not_null_guard(server_line);
    if (!"ok DMTP2.0".equals(server_line)) {
      throw new ServerError("transfer server's initial message was off");
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
      throw new ServerError(protocol_error_str);
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
   * @throws ServerError with a meaningful (for DMTP) details-message
   */
  private void ok_guard(String server_line) throws ServerError {
    not_null_guard(server_line);
    if (!"ok".equals(server_line)) {
      throw new ServerError(protocol_error_str);
    }
  }
  private void not_null_guard(String server_line) throws ServerError {
    if (server_line == null) {
      throw new ServerError(connection_ended_str);
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
