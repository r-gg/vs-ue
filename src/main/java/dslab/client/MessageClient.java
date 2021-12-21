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
        TODO: init client, in particular:
        read username, password, email address,
        transfer server + mailbox server details from properties file(s?)

        ? init inbox / login state
        */
    }

    @Override
    public void run() {
    }

    @Override
    @Command
    public void inbox() {
        // TODO
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
