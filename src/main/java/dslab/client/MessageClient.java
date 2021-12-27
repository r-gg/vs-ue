package dslab.client;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
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
import dslab.shared_models.DMTP_Message;
import dslab.util.Config;
import dslab.util.Keys;

import javax.crypto.Mac;

// TODO:
// check if commands work
// check how command-arguments work (/are seperated)

public class MessageClient implements IMessageClient, Runnable {

    private final Shell shell;
    private String HASH_ALGORITHM = "HmacSHA256";
    private Mac hMac;
    /**
     * Creates a new client instance.
     *
     * @param componentId the id of the component that corresponds to the Config resource
     * @param config the component config
     * @param in the input stream to read console input from
     * @param out the output stream to write console output to
     */
    public MessageClient(String componentId, Config config, InputStream in, PrintStream out) {
        /*
        TODO: init client. In particular, read in from property file:
        transfer.host: the address of the default transfer server
        transfer.port: the port of the default transfer server
        transfer.email: the email address to use as from field when sending messages
        mailbox.host: the address of the default mailbox server
        mailbox.port: the port of the default mailbox server
        mailbox.user: the mailbox server login username
        mailbox.password: the mailbox server login password
        */

        // read in "hmac.key" (the shared secret) from /keys/
        // this (single) hmac.key is a stand-in for all shared secrets between any sender+recipient pair
        try {
            // Creating the hash:
            Key secretKey = Keys.readSecretKey(new File("keys/hmac.key"));
            hMac = Mac.getInstance(HASH_ALGORITHM);
            hMac.init(secretKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException e){
            System.err.println("HMAC init failed");
            // TODO: Gracefully shutdown
        }

        // start the shell
        shell = new Shell(in, out);
        shell.register(this);

        // (prompt may not work correctly/nicely when application is run via ant)
        shell.setPrompt(componentId + "> ");
    }

    /**
     * Returns the base64 encoded hash of the message
     * @param message to be hashed
     * @return b64 encoded hash of the message
     */
    private String calculateHash(DMTP_Message message){
        hMac.update(message.getJoined().getBytes());
        byte[] hash = hMac.doFinal();
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Returns the base64 encoded hash of the message
     * @param message to be hashed, formatted as described in assignment sheet (Fields joined with '\n')
     * @return b64 encoded hash of the message
     */
    private String calculateHash(String message){
        hMac.update(message.getBytes());
        byte[] hash = hMac.doFinal();
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Checks if the value of the hash matches the actual hash of the message
     * @param message received message, to be checked
     * @param hash received hash (b64 encoded), to be checked
     * @return true if hash is correct, false otherwise
     */
    private boolean isHashCorrect(DMTP_Message message, String hash){
        return Arrays.equals(Base64.getDecoder().decode(hash), Base64.getDecoder().decode(calculateHash(message)));
    }

    /**
     * Checks if the value of the hash matches the actual hash of the message
     * @param message received message, to be checked (fields joined with '\n')
     * @param hash received hash (b64 encoded), to be checked
     * @return true if hash is correct, false otherwise
     */
    private boolean isHashCorrect(String message, String hash){
        return Arrays.equals(Base64.getDecoder().decode(hash), Base64.getDecoder().decode(calculateHash(message)));
    }

    @Override
    public void run() {
        // TODO: start the shell
        shell.run();

        // TODO: connect to MB server (for reading own mailbox via DMAP),
        // "startsecure"
        // "login"


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

    @Override
    @Command
    public void msg(String to, String subject, String data) {
        // TODO
        // parse
        // ? is a separate @Command method needed?
        // connect to Transfer Server
        // play DMTP2.0
    }

    @Override
    @Command
    public void shutdown() {
        // This will break the shell's read loop and make Shell.run() return gracefully.
        throw new StopShellException();
    }



    public static void main(String[] args) throws Exception {
        IMessageClient client = ComponentFactory.createMessageClient(args[0], System.in, System.out);
        client.run();
    }
}
