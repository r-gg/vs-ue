package dslab.client;

import static org.hamcrest.CoreMatchers.is;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;

import dslab.secureDMAP.SecureDMAPTest;
import dslab.shared_models.ConnectionEnd;
import dslab.util.Keys;
import jdk.jfr.Description;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ErrorCollector;

import dslab.ComponentFactory;
import dslab.Constants;
import dslab.JunitSocketClient;
import dslab.SimpleTcpServer;
import dslab.Sockets;
import dslab.TestInputStream;
import dslab.TestOutputStream;
import dslab.util.Config;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.*;


/**
 * Tests that the message client connects to the configured DMAP server at startup and sends the startsecure command.
 */
public class MessageClientStartupTest {

    private static final Log LOG = LogFactory.getLog(MessageClientStartupTest.class);

    @Rule
    public ErrorCollector err = new ErrorCollector();

    private static final String ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";
    private static final String ALGORITHM_AES = "AES/CTR/NoPadding";


    private SimpleTcpServer dmapServer;
    private Thread serverThread;
    private String clientId = "client-arthur";
    private String mailboxId = "mailbox-earth-planet";

    @Before
    public void setUp() throws Exception {
        Config clientConfig = new Config(clientId);
        int port = clientConfig.getInt("mailbox.port");
        dmapServer = new SimpleTcpServer(port);

        serverThread = new Thread(dmapServer);
        serverThread.start();

        Sockets.waitForSocket("localhost", port, Constants.COMPONENT_STARTUP_WAIT);
        Thread.sleep(100);
    }

    @After
    public void tearDown() throws Exception {
        dmapServer.close();
        serverThread.join(Constants.COMPONENT_TEARDOWN_WAIT);
    }

    @Test(timeout = 15000)
    public void startClient_shouldConnectToMailboxServerAndSendStartsecure() throws Exception {
        final CountDownLatch connected = new CountDownLatch(1);

        // setup mock server
        dmapServer.setSocketAcceptor(socket -> {
            try (JunitSocketClient client = new JunitSocketClient(socket)) {
                client.send("ok DMAP2.0");
                err.checkThat("expected first command from client to be startsecure", client.read(), is("startsecure"));

                connected.countDown();
                // the server unexpectedly terminates the connection here. make sure your client can handle it!
            } finally {
                dmapServer.close();
            }
        });

        // setup message client
        TestInputStream messageClientIn = new TestInputStream();
        TestOutputStream messageClientOut = new TestOutputStream();

        Runnable messageClient = ComponentFactory.createMessageClient(clientId, messageClientIn, messageClientOut);
        Thread messClientThread = new Thread(messageClient);
        messClientThread.start();

        // shutdown message client once the connection has been made
        connected.await();
        messageClientIn.addLine("shutdown");

        try {
            messClientThread.join(Constants.COMPONENT_TEARDOWN_WAIT);
        } catch (InterruptedException e) {
            // ignore
        }
    }

    @Test(timeout = 15000)
    @Description("The secure handshake should work as described in assignment")
    public void clientSideSuccessfulHandshakeOnStartup() throws Exception {
        final CountDownLatch connected = new CountDownLatch(1);

        // setup mock server
        dmapServer.setSocketAcceptor(socket -> {
            try (JunitSocketClient client = new JunitSocketClient(socket)) {
                client.send("ok DMAP2.0");
                err.checkThat("expected first command from client to be startsecure", client.read(), is("startsecure"));
                client.send("ok "+ mailboxId);

                Cipher rsa_dec_cipher = Cipher.getInstance(ALGORITHM_RSA);
                PrivateKey privateKey = Keys.readPrivateKey(new File("keys/server/"+mailboxId+".der"));
                rsa_dec_cipher.init(Cipher.DECRYPT_MODE, privateKey);

                String response = client.read();
                byte[] decoded = Base64.getDecoder().decode(response);
                String decrypted = new String(rsa_dec_cipher.doFinal(decoded));
                String[] splitted_arr = decrypted.trim().split(" ");
                if (splitted_arr.length != 4) {
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
                Cipher aes_enc_cipher, aes_dec_cipher;
                //  Encrypt
                aes_enc_cipher = Cipher.getInstance(ALGORITHM_AES);
                aes_enc_cipher.init(Cipher.ENCRYPT_MODE, aes_key, iv);
                //  Decrypt
                aes_dec_cipher = Cipher.getInstance(ALGORITHM_AES);
                aes_dec_cipher.init(Cipher.DECRYPT_MODE, aes_key, iv);

                // RESPONSE
                String response_plain = "ok " + challenge_enc;
                byte[] response_encrypted = aes_enc_cipher.doFinal(response_plain.getBytes());
                String response_encoded = Base64.getEncoder().encodeToString(response_encrypted);

                client.send(response_encoded);

                byte[] client_ok_decoded = Base64.getDecoder().decode(client.read());
                String client_ok_decryped = new String(aes_dec_cipher.doFinal(client_ok_decoded));

                assertEquals("ok", client_ok_decryped);

                connected.countDown();
                // the server unexpectedly terminates the connection here. make sure your client can handle it!
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (ConnectionEnd connectionEnd) {
                connectionEnd.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } finally {
                dmapServer.close();
            }
        });

        // setup message client
        TestInputStream messageClientIn = new TestInputStream();
        TestOutputStream messageClientOut = new TestOutputStream();

        Runnable messageClient = ComponentFactory.createMessageClient(clientId, messageClientIn, messageClientOut);
        Thread messClientThread = new Thread(messageClient);
        messClientThread.start();

        // shutdown message client once the connection has been made
        connected.await();
        messageClientIn.addLine("shutdown");

        try {
            messClientThread.join(Constants.COMPONENT_TEARDOWN_WAIT);
        } catch (InterruptedException e) {
            // ignore
        }

    }

}
