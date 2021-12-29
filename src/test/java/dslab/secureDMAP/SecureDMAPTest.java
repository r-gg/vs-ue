package dslab.secureDMAP;

import dslab.*;
import dslab.client.IMessageClient;
import dslab.mailbox.IMailboxServer;
import dslab.mailbox.MailboxServerProtocolTest;
import dslab.util.Config;
import dslab.util.Keys;
import jdk.jfr.Description;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import static dslab.StringMatches.matchesPattern;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class SecureDMAPTest extends TestBase {
    private static final Log LOG = LogFactory.getLog(SecureDMAPTest.class);

    private static final String ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";

    private int dmapServerPort;
    private int dmtpServerPort;

    @Before
    public void setUp() throws Exception {
        String componentId = "mailbox-earth-planet";

        IMailboxServer component = ComponentFactory.createMailboxServer(componentId, in, out);
        dmapServerPort = new Config(componentId).getInt("dmap.tcp.port");
        dmtpServerPort = new Config(componentId).getInt("dmtp.tcp.port");

        new Thread(component).start();

        LOG.info("Waiting for server sockets to appear");
        Sockets.waitForSocket("localhost", dmapServerPort, Constants.COMPONENT_STARTUP_WAIT);
        Sockets.waitForSocket("localhost", dmtpServerPort, Constants.COMPONENT_STARTUP_WAIT);
    }

    @After
    public void tearDown() throws Exception {
        in.addLine("shutdown"); // send "shutdown" command to command line
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT);
    }

    @Test(timeout = 15000)
    public void serverSideSecureTest() throws Exception {

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey custom_aes_key = generator.generateKey();

        SecureRandom secureRandom = new SecureRandom();
        final byte[] custom_iv_bytes = new byte[16];
        secureRandom.nextBytes(custom_iv_bytes);

        IvParameterSpec custom_iv = new IvParameterSpec(custom_iv_bytes);

        Cipher custom_rsa_cipher = Cipher.getInstance(ALGORITHM_RSA);
        PublicKey publicKey = Keys.readPublicKey(new File("keys/client/mailbox-earth-planet_pub.der"));
        custom_rsa_cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        Cipher custom_aes_enc = Cipher.getInstance("AES/CTR/NoPadding");
        custom_aes_enc.init(Cipher.ENCRYPT_MODE, custom_aes_key, custom_iv);

        Cipher custom_aes_dec = Cipher.getInstance("AES/CTR/NoPadding");
        custom_aes_dec.init(Cipher.DECRYPT_MODE, custom_aes_key, custom_iv);

        String req_plain = "ok " + "challlenge " + Base64.getEncoder().encodeToString(custom_aes_key.getEncoded()) + " "+
                Base64.getEncoder().encodeToString(custom_iv_bytes);

        byte[] encrypted = custom_rsa_cipher.doFinal(req_plain.getBytes());
        String encoded = Base64.getEncoder().encodeToString(encrypted);
        String testChallenge = encoded;


        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            // protocol check
            client.verify("ok DMAP2.0");

            // ---------------------------  PERFORM HANDSHAKE

            // check that mailbox returns its component id
            client.sendAndVerify("startsecure", "ok mailbox-earth-planet");


            // send the challenge + aes init
            client.send(testChallenge);

            String response = client.listen();
            byte[] response_with_challenge_decoded = Base64.getDecoder().decode(response);
            String response_with_challenge_decrypted = new String(custom_aes_dec.doFinal(response_with_challenge_decoded));
            String[] splitted = response_with_challenge_decrypted.trim().split(" ");
            assertEquals(2, splitted.length);

            String received_challenge = splitted[1];

            // response should be "ok <challenge>" (which is AES encrypted and base64 encoded)
            // specifically it should be y8pi/vUC7xzEoFsV8FXoKMB/0WfeD+k3zEBJsJ0wHwTVfJaKG7iexa565iZVMag=
            err.checkThat("Expected server response to be Base64 encoded", response,
                    matchesPattern("^(?:[a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?$"));
            assertEquals("challlenge", received_challenge );

            // send encrypted "ok" (with the aes cipher) in
            client.send(Base64.getEncoder().encodeToString(custom_aes_enc.doFinal("ok".getBytes())));

            // ----------------------------  HANDSHAKE COMPLETE

            // Not logged in
            client.send(Base64.getEncoder().encodeToString(custom_aes_enc.doFinal("list".getBytes())));
            String cl_resp = client.listen();
            assertEquals("error not logged in",new String(custom_aes_dec.doFinal(Base64.getDecoder().decode(cl_resp))));

            // Login
            client.send(Base64.getEncoder().encodeToString(custom_aes_enc.doFinal("login trillian 12345".getBytes())));
            cl_resp = client.listen();
            assertEquals("ok",new String(custom_aes_dec.doFinal(Base64.getDecoder().decode(cl_resp))));

            // Logout
            client.send(Base64.getEncoder().encodeToString(custom_aes_enc.doFinal("logout".getBytes())));
            cl_resp = client.listen();
            assertEquals("ok",new String(custom_aes_dec.doFinal(Base64.getDecoder().decode(cl_resp))));

            // Quit
            client.send(Base64.getEncoder().encodeToString(custom_aes_enc.doFinal("quit".getBytes())));
            cl_resp = client.listen();
            assertEquals("ok bye",new String(custom_aes_dec.doFinal(Base64.getDecoder().decode(cl_resp))));
        }
    }


    @Test(timeout = 15000)
    public void loginAndLogout_withValidLogin() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey custom_aes_key = generator.generateKey();
        SecureRandom secureRandom = new SecureRandom();
        final byte[] custom_iv_bytes = new byte[16];
        secureRandom.nextBytes(custom_iv_bytes);
        IvParameterSpec custom_iv = new IvParameterSpec(custom_iv_bytes);
        Cipher custom_rsa_cipher = Cipher.getInstance(ALGORITHM_RSA);
        PublicKey publicKey = Keys.readPublicKey(new File("keys/client/mailbox-earth-planet_pub.der"));
        custom_rsa_cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        Cipher custom_aes_enc = Cipher.getInstance("AES/CTR/NoPadding");
        custom_aes_enc.init(Cipher.ENCRYPT_MODE, custom_aes_key, custom_iv);
        Cipher custom_aes_dec = Cipher.getInstance("AES/CTR/NoPadding");
        custom_aes_dec.init(Cipher.DECRYPT_MODE, custom_aes_key, custom_iv);
        String req_plain = "ok " + "challlenge " + Base64.getEncoder().encodeToString(custom_aes_key.getEncoded()) + " "+
                Base64.getEncoder().encodeToString(custom_iv_bytes);
        byte[] encrypted = custom_rsa_cipher.doFinal(req_plain.getBytes());
        String encoded = Base64.getEncoder().encodeToString(encrypted);
        String testChallenge = encoded;

        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            client.verify("ok DMAP2.0");
            // HANDSHAKE
            client.sendAndVerify("startsecure", "ok mailbox-earth-planet");
            client.send(testChallenge);
            String response = client.listen();
            byte[] response_with_challenge_decoded = Base64.getDecoder().decode(response);
            String response_with_challenge_decrypted = new String(custom_aes_dec.doFinal(response_with_challenge_decoded));
            String[] splitted = response_with_challenge_decrypted.trim().split(" ");
            assertEquals(2, splitted.length);
            String received_challenge = splitted[1];
            assertEquals("challlenge", received_challenge );
            client.send(Base64.getEncoder().encodeToString(custom_aes_enc.doFinal("ok".getBytes())));
            // HANDSHAKE Done

            client.sendAndVerify(encipher("login trillian 12345",custom_aes_enc), encipher("ok", custom_aes_enc));
            client.sendAndVerify(encipher("logout",custom_aes_enc), encipher("ok", custom_aes_enc));
            client.sendAndVerify(encipher("quit",custom_aes_enc), encipher("ok bye", custom_aes_enc));
        }
    }

    private String encipher(String message, Cipher enc_cipher) throws IllegalBlockSizeException, BadPaddingException {
        return Base64.getEncoder().encodeToString(enc_cipher.doFinal(message.getBytes()));
    }

    private String decipher(String message, Cipher dec_cipher)throws IllegalBlockSizeException, BadPaddingException{
        return new String(dec_cipher.doFinal(Base64.getDecoder().decode(message)));
    }

    @Test(timeout = 15000)
    public void login_withInvalidLogin_returnsError() throws Exception {
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            client.verify("ok DMAP2.0");
            client.sendAndVerify("login trillian WRONGPW", "error");
            client.sendAndVerify("quit", "ok bye");
        }
    }

    @Test(timeout = 15000)
    public void acceptDmtpMessage_listDmapMessage() throws Exception {

        // accept a message via DMTP (to trillian)
        try (JunitSocketClient client = new JunitSocketClient(dmtpServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from arthur@earth.planet", "ok");
            client.sendAndVerify("to trillian@earth.planet", "ok 1");
            client.sendAndVerify("subject hello", "ok");
            client.sendAndVerify("data hello from junit", "ok");
            client.sendAndVerify("send", "ok");

            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from me@earth.planet", "ok");
            client.sendAndVerify("to trillian@earth.planet", "ok 1");
            client.sendAndVerify("subject hello2", "ok");
            client.sendAndVerify("data hello2 from junit", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey custom_aes_key = generator.generateKey();
        SecureRandom secureRandom = new SecureRandom();
        final byte[] custom_iv_bytes = new byte[16];
        secureRandom.nextBytes(custom_iv_bytes);
        IvParameterSpec custom_iv = new IvParameterSpec(custom_iv_bytes);
        Cipher custom_rsa_cipher = Cipher.getInstance(ALGORITHM_RSA);
        PublicKey publicKey = Keys.readPublicKey(new File("keys/client/mailbox-earth-planet_pub.der"));
        custom_rsa_cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        Cipher custom_aes_enc = Cipher.getInstance("AES/CTR/NoPadding");
        custom_aes_enc.init(Cipher.ENCRYPT_MODE, custom_aes_key, custom_iv);
        Cipher custom_aes_dec = Cipher.getInstance("AES/CTR/NoPadding");
        custom_aes_dec.init(Cipher.DECRYPT_MODE, custom_aes_key, custom_iv);
        String req_plain = "ok " + "challlenge " + Base64.getEncoder().encodeToString(custom_aes_key.getEncoded()) + " "+
                Base64.getEncoder().encodeToString(custom_iv_bytes);
        byte[] encrypted = custom_rsa_cipher.doFinal(req_plain.getBytes());
        String encoded = Base64.getEncoder().encodeToString(encrypted);
        String testChallenge = encoded;

        // list the message via DMAP list
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            client.verify("ok DMAP2.0");

            // HANDSHAKE
            client.sendAndVerify("startsecure", "ok mailbox-earth-planet");
            client.send(testChallenge);
            String response = client.listen();
            byte[] response_with_challenge_decoded = Base64.getDecoder().decode(response);
            String response_with_challenge_decrypted = new String(custom_aes_dec.doFinal(response_with_challenge_decoded));
            String[] splitted = response_with_challenge_decrypted.trim().split(" ");
            assertEquals(2, splitted.length);
            String received_challenge = splitted[1];
            assertEquals("challlenge", received_challenge );
            client.send(Base64.getEncoder().encodeToString(custom_aes_enc.doFinal("ok".getBytes())));
            // HANDSHAKE Done

            client.sendAndVerify(encipher("login trillian 12345",custom_aes_enc), encipher("ok",custom_aes_enc));

            client.send(encipher("list",custom_aes_enc));
            String listResult = decipher(client.listen() , custom_aes_dec);
            err.checkThat(listResult, containsString("arthur@earth.planet hello"));
            err.checkThat(listResult, containsString("me@earth.planet hello2"));
            LOG.info("\n-------------------------------- LIST RESULT -----------------------------------------\n"+listResult+
                    "\n--------------------------------------------------------------------------------------");

            client.send(encipher("show 0", custom_aes_enc));
            String showResult = decipher(client.listen(), custom_aes_dec);
            err.checkThat(showResult, containsString("hello from junit"));
            LOG.info("\n-------------------------------- SHOW RESULT -----------------------------------------\n"+showResult+
                    "\n--------------------------------------------------------------------------------------");

            client.sendAndVerify(encipher("delete 0", custom_aes_enc), encipher("ok", custom_aes_enc));

            client.send(encipher("list",custom_aes_enc));
            listResult = decipher(client.listen() , custom_aes_dec);
            assertFalse(listResult.contains("arthur@earth.planet hello"));
            err.checkThat(listResult, containsString("me@earth.planet hello2"));

            client.sendAndVerify(encipher("logout",custom_aes_enc), encipher("ok",custom_aes_enc));
            client.sendAndVerify(encipher("quit",custom_aes_enc), encipher("ok bye",custom_aes_enc));
        }
    }

    @Test(timeout = 15000)
    public void dmtpMessage_withUnknownRecipient_returnsError() throws Exception {

        // accept a message via DMTP (to trillian)
        try (JunitSocketClient client = new JunitSocketClient(dmtpServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from arthur@earth.planet", "ok");
            client.sendAndVerify("to unknown@earth.planet", "error unknown");
            client.sendAndVerify("quit", "ok bye");
        }
    }

    @Test(timeout = 15000)
    public void serverSideInvalidKeyOrEncryption() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey custom_aes_key = generator.generateKey();
        SecureRandom secureRandom = new SecureRandom();
        final byte[] custom_iv_bytes = new byte[16];
        secureRandom.nextBytes(custom_iv_bytes);
        IvParameterSpec custom_iv = new IvParameterSpec(custom_iv_bytes);
        Cipher custom_rsa_cipher = Cipher.getInstance(ALGORITHM_RSA);
        PublicKey publicKey = Keys.readPublicKey(new File("keys/client/mailbox-earth-planet_pub.der"));
        custom_rsa_cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        Cipher custom_aes_enc = Cipher.getInstance("AES/CTR/NoPadding");
        custom_aes_enc.init(Cipher.ENCRYPT_MODE, custom_aes_key, custom_iv);
        Cipher custom_aes_dec = Cipher.getInstance("AES/CTR/NoPadding");
        custom_aes_dec.init(Cipher.DECRYPT_MODE, custom_aes_key, custom_iv);
        String req_plain = "ok " + "challlenge " + "gibberish" + " "+
                "trash";
        byte[] encrypted = custom_rsa_cipher.doFinal(req_plain.getBytes());
        String encoded = Base64.getEncoder().encodeToString(encrypted);
        String testChallenge = encoded;

        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            client.verify("ok DMAP2.0");
            // HANDSHAKE
            client.sendAndVerify("startsecure", "ok mailbox-earth-planet");
            client.send(testChallenge);
            Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT);

            assertEquals("",client.listen(1500, TimeUnit.MILLISECONDS));
            // TODO: Maybe add other incorrect handshake messages, like just invalid key, incorrectly encrypted "ok" at the end...
        }
    }



}
