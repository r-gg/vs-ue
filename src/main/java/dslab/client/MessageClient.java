package dslab.client;

import java.io.InputStream;
import java.io.PrintStream;

import dslab.ComponentFactory;
import dslab.util.Config;

// TODO:
// check if compile-/runnable
// check if commands work
// check how command-arguments work (/are seperated)

public class MessageClient implements IMessageClient, Runnable {

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

        aaand

        read in "hmac.key" (the shared secret) from /keys/
        using the Keys class
        ? where tf are the supposed shared keys of "friends" for verifying ?
        */
    }

    @Override
    public void run() {
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
        // TODO
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
        // TODO
    }

    public static void main(String[] args) throws Exception {
        IMessageClient client = ComponentFactory.createMessageClient(args[0], System.in, System.out);
        client.run();
    }
}
