package dslab.mailbox;

import static dslab.StringMatches.matchesPattern;

import dslab.util.Keys;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import dslab.ComponentFactory;
import dslab.Constants;
import dslab.JunitSocketClient;
import dslab.Sockets;
import dslab.TestBase;
import dslab.util.Config;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;
import static org.junit.Assert.*;

public class MailboxStartsecureTest extends TestBase {

    private static final Log LOG = LogFactory.getLog(MailboxServerProtocolTest.class);

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
    public void sendStartsecure() throws Exception {

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
        //String testChallenge = encoded;
        // a challenge, aes secret and iv param encrypted with the server's RSA key
        String testChallenge = "wTZqUdwD6RIWtgTrvoYecJgulKRQVActTzbaW7u4i0puTak8ymlUHmvVQGT6wCUVoByDaF3dEhRFku5uC4kap" +
                "9yd2FntrtIcuftaf36WSU/Qg2ue254TiEVmCLILd2eef8SxHh6U0hyWwXPdD+BHBplzrBeIIiTPqLteKKHl6veEzuEh+s/u66hcy" +
                "PG+3t18C4ZR1jo50VZhAa9Kfqeuj787llQTZMMv+2gEIRciKPu8pF5/57+hmOmcp+mAoBaK0XdjTZ1Win4bF1CP44sdHLgKy2Bfv" +
                "Gn69RN7ThWBEu8fXuBsxcflhLDus1OIlDv8YgoLVGiOCamtZf0TtqcErg==";

        byte[] dec = Base64.getDecoder().decode(testChallenge);
        PrivateKey pk = Keys.readPrivateKey(new File("keys/server/mailbox-earth-planet.der"));
        Cipher cipher = Cipher.getInstance(ALGORITHM_RSA);
        cipher.init(Cipher.DECRYPT_MODE, pk);

        String decr = new String(cipher.doFinal(dec));
        String[] splitted_arr = decr.trim().split(" ");
        assertEquals(4, splitted_arr.length);

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
        Cipher cipher_aes_encrypt = Cipher.getInstance("AES/CTR/NoPadding");
        cipher_aes_encrypt.init(Cipher.ENCRYPT_MODE, aes_key, iv);
        //  Decrypt
        Cipher cipher_aes_decrypt = Cipher.getInstance("AES/CTR/NoPadding");
        cipher_aes_decrypt.init(Cipher.DECRYPT_MODE, aes_key, iv);

        // RESPONSE
        String response_plain = "ok "+ challenge_enc;
        byte[] response_encrypted = cipher_aes_encrypt.doFinal(response_plain.getBytes());
        String response_encoded = Base64.getEncoder().encodeToString(response_encrypted);

        assertEquals("g9UJxNFULO+H0otZoH5AVXoHv9TxJUEcbY/ScWoWMvcJYLz2lYBaZ16OtqEKtVk=", response_encoded);

        //String response_decrypted = new String(custom_aes_dec.doFinal(response_encrypted));
        //assertEquals("ok challlenge", response_decrypted);



        byte[] decoded_ok = Base64.getDecoder().decode("g9U=");
        byte[] decryptedOk = cipher_aes_decrypt.doFinal(decoded_ok);

        String ok_str = new String(decryptedOk);
        assertEquals("ok",ok_str);

        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            // protocol check
            client.verify("ok DMAP2.0");

            // check that mailbox returns its component id
            client.sendAndVerify("startsecure", "ok mailbox-earth-planet");


            // send the challenge + aes init
            client.send(testChallenge);

            // response should be "ok <challenge>" (which is AES encrypted and base64 encoded)
            // specifically it should be g9UJxNFULO+H0otZoH5AVXoHv9TxJUEcbY/ScWoWMvcJYLz2lYBaZ16OtqEKtVk=
            err.checkThat("Expected server response to be Base64 encoded", client.listen(),
                    matchesPattern("^(?:[a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?$"));

            // send encrypted "ok" (with the aes cipher) in
            client.send("g9U=");
        }
    }


}
