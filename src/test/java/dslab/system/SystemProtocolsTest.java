package dslab.system;

import dslab.*;
import dslab.mailbox.IMailboxServer;
import dslab.monitoring.IMonitoringServer;
import dslab.nameserver.INameserver;
import dslab.transfer.ITransferServer;
import dslab.transfer.TransferServerProtocolTest;
import dslab.util.Config;
import jdk.jfr.Description;
import jdk.jfr.Name;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.Theories;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class SystemProtocolsTest extends TestBase {
    private static final Log LOG = LogFactory.getLog(SystemProtocolsTest.class);

    private String transferComponentId = "transfer-1";
    private String transferComponentId2 = "transfer-2";

    private ITransferServer transferServer;
    private ITransferServer transferServer2;

    private int transferServerPort;
    private String transferServerAddress;

    private int transferServerPort2;
    private String transferServerAddress2;

    private String earthMailboxComponentId = "mailbox-earth-planet";
    private String univerMailboxComponentId2 = "mailbox-univer-ze";

    private IMailboxServer earthMailboxServer;
    private int dmapServerPort;
    private int dmtpServerPort;

    private IMailboxServer univerMailboxServer;
    private int dmapServerPort2;
    private int dmtpServerPort2;

    private String monitoringComponentId = "monitoring";

    private IMonitoringServer monitoringServer;
    private InetSocketAddress addr;

    private TestInputStream nsRootIn;
    private TestOutputStream nsRootOut;

    private String nsPlanetComponentId = "ns-planet";
    private String nsZeComponentId = "ns-ze";
    private String nsRootComponentId = "ns-root";
    private TestInputStream nsPlanetIn;
    private TestOutputStream nsPlanetOut;

    private TestInputStream nsZeIn;
    private TestOutputStream nsZeOut;

    private INameserver planet_nameserver;
    private INameserver root_nameserver;
    private INameserver ze_nameserver;

    @Before
    public void setUp() throws Exception {

        this.nsRootIn = new TestInputStream();
        this.nsPlanetIn = new TestInputStream();
        this.nsRootOut = new TestOutputStream();
        this.nsPlanetOut = new TestOutputStream();
        this.nsZeIn = new TestInputStream();
        this.nsZeOut = new TestOutputStream();

        root_nameserver = ComponentFactory.createNameserver(nsRootComponentId, nsRootIn, nsRootOut);
        planet_nameserver = ComponentFactory.createNameserver(nsPlanetComponentId, nsPlanetIn, nsPlanetOut);
        ze_nameserver = ComponentFactory.createNameserver(nsZeComponentId, nsZeIn, nsZeOut);

        transferServer = ComponentFactory.createTransferServer(transferComponentId, transferIn, transferOut);
        transferServer2 = ComponentFactory.createTransferServer(transferComponentId2, transferIn2, transferOut2);
        earthMailboxServer = ComponentFactory.createMailboxServer(earthMailboxComponentId, mailboxIn1, mailboxOut1);
        monitoringServer = ComponentFactory.createMonitoringServer(monitoringComponentId, monitorIn, monitorOut);
        univerMailboxServer = ComponentFactory.createMailboxServer(univerMailboxComponentId2,mailboxIn2,mailboxOut2);





        transferServerPort = new Config(transferComponentId).getInt("tcp.port");
        transferServerPort2 = new Config(transferComponentId2).getInt("tcp.port");

        this.transferServerAddress = "127.0.0.1";
        this.transferServerAddress2 = "127.0.0.1";
        InetAddress localhost = null;

        boolean isKnownHost = true;
        try {
            localhost= InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            isKnownHost = false;
        }
        if(isKnownHost && localhost != null){
            this.transferServerAddress = localhost.getHostAddress();
            this.transferServerAddress2 = localhost.getHostAddress();
        }

        dmapServerPort = new Config(earthMailboxComponentId).getInt("dmap.tcp.port");
        dmtpServerPort = new Config(earthMailboxComponentId).getInt("dmtp.tcp.port");

        dmapServerPort2 = new Config(univerMailboxComponentId2).getInt("dmap.tcp.port");
        dmtpServerPort2 = new Config(univerMailboxComponentId2).getInt("dmtp.tcp.port");

        addr = new InetSocketAddress("127.0.0.1", new Config(monitoringComponentId).getInt("udp.port"));

        new Thread(root_nameserver).start();
        Thread.sleep(100);
        new Thread(planet_nameserver).start();
        Thread.sleep(100);
        new Thread(ze_nameserver).start();
        Thread.sleep(100);

        new Thread(transferServer).start();
        new Thread(transferServer2).start();
        new Thread(earthMailboxServer).start();
        new Thread(monitoringServer).start();
        new Thread(univerMailboxServer).start();



        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT);

        LOG.info("Waiting for server sockets to appear");
        Sockets.waitForSocket("localhost", dmapServerPort, Constants.COMPONENT_STARTUP_WAIT);
        Sockets.waitForSocket("localhost", dmtpServerPort, Constants.COMPONENT_STARTUP_WAIT);
        Sockets.waitForSocket("localhost", dmapServerPort2, Constants.COMPONENT_STARTUP_WAIT);
        Sockets.waitForSocket("localhost", dmtpServerPort2, Constants.COMPONENT_STARTUP_WAIT);
        Sockets.waitForSocket("localhost", transferServerPort, Constants.COMPONENT_STARTUP_WAIT);
        Sockets.waitForSocket("localhost", transferServerPort2, Constants.COMPONENT_STARTUP_WAIT);

    }

    @After
    public void tearDown() throws Exception {
        transferIn.addLine("shutdown"); // transfer server shutdown
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/3);
        transferIn2.addLine("shutdown"); // transfer server shutdown
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/3);
        mailboxIn1.addLine("shutdown"); // mailbox1 server shutdown
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/3);
        mailboxIn2.addLine("shutdown"); // mailbox2 server shutdown
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/3);
        monitorIn.addLine("shutdown"); // monitor server shutdown
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/3);
        nsPlanetIn.addLine("shutdown");
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/3);
        nsRootIn.addLine("shutdown");
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/6);
        nsZeIn.addLine("shutdown");
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/6);

        // Transfer
        err.checkThat("Expected tcp socket on port " + transferServerPort + " to be closed after shutdown",
                Sockets.isServerSocketOpen(transferServerPort), is(false));
        // Transfer
        err.checkThat("Expected tcp socket on port " + transferServerPort2 + " to be closed after shutdown",
                Sockets.isServerSocketOpen(transferServerPort2), is(false));
        // Mailbox 1
        err.checkThat("Expected tcp socket on port " + dmtpServerPort + " to be closed after shutdown",
                Sockets.isServerSocketOpen(dmtpServerPort), is(false));

        err.checkThat("Expected tcp socket on port " + dmapServerPort + " to be closed after shutdown",
                Sockets.isServerSocketOpen(dmapServerPort), is(false));
        // Mailbox 2
        err.checkThat("Expected tcp socket on port " + dmtpServerPort2 + " to be closed after shutdown",
                Sockets.isServerSocketOpen(dmtpServerPort2), is(false));

        err.checkThat("Expected tcp socket on port " + dmapServerPort2 + " to be closed after shutdown",
                Sockets.isServerSocketOpen(dmapServerPort2), is(false));

        // Monitor
        err.checkThat("Expected datagram socket on port " + addr.getPort() + " to be closed after shutdown",
                Sockets.isDatagramSocketOpen(addr.getPort()), is(false));
    }

    @Test(timeout = 10000)
    public void defaultDmtpInteractionTest() throws Exception {
        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("to arthur@earth.planet", "ok 1");
            client.sendAndVerify("subject hello", "ok");
            client.sendAndVerify("data hello from junit", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }
    }

    @Test(timeout = 10000)
    public void sendWithoutRecipient_returnsErrorOnSend() throws Exception {
        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("subject hello", "ok");
            client.sendAndVerify("data hello from junit", "ok");
            client.sendAndVerify("send", "error");
            client.sendAndVerify("quit", "ok bye");
        }
    }

    @Test(timeout = 200000000)
    @Name("Transferring the message to the mailbox server (one recipient)")
    @Description("Positive test: Message is visible in the mailbox of the recipient and the monitoring server sees the increase in traffic for the server and the sender.")
    public void onePositiveTransfer() throws Exception{
        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("to arthur@earth.planet", "ok 1");
            client.sendAndVerify("subject hello", "ok");
            client.sendAndVerify("data hello from junit", "ok");
            client.sendAndVerify("hash 111111111111","ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT); // Waiting for the message to be transferred

        // list the message via DMAP list
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            client.verify("ok DMAP2.0");
            client.sendAndVerify("login arthur 23456", "ok");

            client.send("list");
            String listResult = client.listen();
            err.checkThat(listResult, containsString("trillian@earth.planet hello"));

            client.send("show 0");
            String showResult = client.listen();
            err.checkThat(showResult, containsString("hash 111111111111"));

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }
        monitorIn.addLine("addresses"); // send "addresses" command to command line
        Thread.sleep(2500);
        String output = String.join(",", monitorOut.getLines());
        assertThat(output, containsString("trillian@earth.planet 1"));

        monitorIn.addLine("servers");
        Thread.sleep(2500);
        output = String.join(",", monitorOut.getLines());
        assertThat(output, containsString(transferServerAddress+":"+transferServerPort+" 1"));

    }

    @Test(timeout = 17000)
    @Name("Transferring the message to the mailbox server (three recipients)")
    @Description("Positive test: Each recipient gets the message and monitor gets trafic info as well")
    public void threePositiveTransfers() throws Exception{
        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("to arthur@earth.planet,zaphod@univer.ze,trillian@earth.planet", "ok 3");
            client.sendAndVerify("subject hello3", "ok");
            client.sendAndVerify("data hello you three from junit", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT); // Waiting for the message to be transferred

        // list the message for arthur via DMAP list
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            client.verify("ok DMAP");
            client.sendAndVerify("login arthur 23456", "ok");

            client.send("list");
            String listResult = client.listen();
            err.checkThat(listResult, containsString("trillian@earth.planet hello3"));

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        // list the message for trillian via DMAP list
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            client.verify("ok DMAP");
            client.sendAndVerify("login trillian 12345", "ok");

            client.send("list");
            String listResult = client.listen();
            err.checkThat(listResult, containsString("trillian@earth.planet hello3"));

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        // list the message for zaphod via DMAP list
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort2, err)) { // NOTE: different dmap port
            client.verify("ok DMAP");
            client.sendAndVerify("login zaphod 12345", "ok");

            client.send("list");
            String listResult = client.listen();
            err.checkThat(listResult, containsString("trillian@earth.planet hello3"));

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        monitorIn.addLine("addresses"); // send "addresses" command to command line
        Thread.sleep(2500);
        String output = String.join(",", monitorOut.getLines());
        assertThat(output, containsString("trillian@earth.planet 3"));

        monitorIn.addLine("servers");
        Thread.sleep(2500);
        output = String.join(",", monitorOut.getLines());
        assertThat(output, containsString(transferServerAddress+":"+transferServerPort+" 3"));

    }


    @Test
    @Name("Negative test: Sending a message with invalid recipient")
    @Description("Sending a message to a recipient whose E-Mail address is not in the domains list, should " +
            "not throw an Exception. (Usually Missing ressource exception.) Further, the sender should see " +
            "an error message in his/her mailbox.")
    public void transferToInvalidDomain() throws Exception{

        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from zaphod@univer.ze", "ok");
            client.sendAndVerify("to arthur@email.com", "ok 1");
            client.sendAndVerify("subject hello3", "ok");
            client.sendAndVerify("data hello you three from junit", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        // list the message for zaphod via DMAP list
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort2, err)) { // NOTE: different dmap port
            client.verify("ok DMAP");
            client.sendAndVerify("login zaphod 12345", "ok");

            Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT); // waiting for the message to be sent
            client.send("list");
            String listResult = client.listen();
            err.checkThat(listResult, containsString("Delivering your mail failed"));


            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }
    }

    @Test
    @Name("Deleting only from one mailbox test")
    public void deletingAMessageDeletesItOnlyForOneUser() throws Exception{
        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("to arthur@earth.planet,zaphod@univer.ze", "ok 2");
            client.sendAndVerify("subject hello", "ok");
            client.sendAndVerify("data hello from junit", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT); // Waiting for the message to be transferred

        // list the message via DMAP list
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) {
            client.verify("ok DMAP");
            client.sendAndVerify("login arthur 23456", "ok");

            client.send("list");
            String listResult = client.listen();
            err.checkThat(listResult, containsString("trillian@earth.planet hello"));
            String index = listResult.replaceAll("[^0-9]",""); // removing all non numerical characters

            client.send("show "+index);
            String showResult = client.listen();
            err.checkThat(showResult, containsString("hello from junit"));

            client.sendAndVerify("delete "+index, "ok");

            client.send("list");
            listResult = client.listen();

            // Assert that it is indeed deleted
            assertFalse(listResult.contains("trillian@earth.planet hello"));

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        // The message should be in zaphods mailbox
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort2, err)) {
            client.verify("ok DMAP");
            client.sendAndVerify("login zaphod 12345", "ok");

            client.send("list");
            String listResult = client.listen();
            err.checkThat(listResult, containsString("trillian@earth.planet hello"));

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }
    }

    @Test
    @Name("Error message received upon sending a message to a domain whose server is not running")
    public void sendingToANonRunningMailboxShouldSendAnErrorMessage() throws Exception{

        // Shutting down the mailbox univer.ze server
        mailboxIn2.addLine("shutdown"); // mailbox2 server shutdown
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT);
        // Mailbox 2
        err.checkThat("Expected tcp socket on port " + dmtpServerPort2 + " to be closed after shutdown",
                Sockets.isServerSocketOpen(dmtpServerPort2), is(false));

        err.checkThat("Expected tcp socket on port " + dmapServerPort2 + " to be closed after shutdown",
                Sockets.isServerSocketOpen(dmapServerPort2), is(false));

        // Sending a message to the user at univer.ze
        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("to arthur@earth.planet,zaphod@univer.ze", "ok 2");
            client.sendAndVerify("subject hello", "ok");
            client.sendAndVerify("data hello from junit", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) { // NOTE: different dmap port
            client.verify("ok DMAP");
            client.sendAndVerify("login trillian 12345", "ok");

            Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT); // waiting for the message to be sent
            client.send("list");
            String listResult = client.listen();

            // err.checkThat(listResult, containsString("Error Message"));


            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }


    }

    @Test
    @Name("Positive: Sending a message with empty subject should be possible")
    public void sendingAMessageWithEmptySubjectAndDataShouldBePossible() throws Exception{
        // Sending a message to the user at univer.ze
        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("to arthur@earth.planet,zaphod@univer.ze", "ok 2");
            client.sendAndVerify("subject", "ok");
            client.sendAndVerify("data", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

    }

    @Test
    @Name("Negative: Deleting or showing a message with unknown id should return an error")
    public void deletingOrShowingAMessageWithUnknownId() throws Exception{
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) { // NOTE: different dmap port
            client.verify("ok DMAP");
            client.sendAndVerify("login trillian 12345", "ok");

            Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT); // waiting for the message to be sent
            client.send("delete 999");
            String delResult = client.listen();
            err.checkThat(delResult, containsString("error"));

            client.send("show 999");
            String showResult = client.listen();
            err.checkThat(showResult, containsString("error"));

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }
    }

    @Test
    @Name("Positive: Showing a message should show it in a DMAP conforming syntax")
    public void showingAMessage() throws Exception{
        // Sending a message
        try (JunitSocketClient client = new JunitSocketClient(transferServerPort, err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("to arthur@earth.planet,zaphod@univer.ze", "ok 2");
            client.sendAndVerify("subject my answer", "ok");
            client.sendAndVerify("data i have thought about it and the answer is clearly 42 ", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

        String expectedFormat = "from trillian@earth.planet\n" +
                "to arthur@earth.planet,zaphod@univer.ze\n" +
                "subject my answer\n" +
                "data i have thought about it and the answer is clearly 42";

        // Viewing the message as arthur
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) { // NOTE: different dmap port
            client.verify("ok DMAP");
            client.sendAndVerify("login arthur 23456", "ok");

            Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT); // waiting for the message to be sent
            client.send("list");
            String listResult = client.listen();
            err.checkThat(listResult, containsString("trillian@earth.planet my answer"));
            String index = listResult.replaceAll("[^0-9]",""); // removing all non numerical characters

            client.send("show "+index);
            String showResult = client.listen();

            LOG.info("\n-------------------------------- SHOW RESULT -----------------------------------------\n"+showResult+
                    "\n--------------------------------------------------------------------------------------");

            err.checkThat(showResult, containsString(expectedFormat));

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }
    }


    @Test
    @Name("Two transfer servers should be able to transfer messages simultaneously")
    @Description("Also tests the concurrency properties of the servers, 16 messages should be sent concurrently," +
            "with one of the two transfer servers chosen randomly")
    public void twoTransferServers() throws Exception{
        int numberOfThreads = 16;
        ExecutorService service = Executors.newFixedThreadPool(numberOfThreads);
        CountDownLatch latch = new CountDownLatch(numberOfThreads);
        int[] transferPorts = {transferServerPort, transferServerPort2};

        for (int i = 0; i < numberOfThreads; i++) {
            service.submit(() -> {
                try {
                    this.transferMessage(transferPorts);
                } catch (Exception e) {
                    // Handle exception
                }
                latch.countDown();
            });
        }
        latch.await();

        // Assert that there were 8 messages received
        try (JunitSocketClient client = new JunitSocketClient(dmapServerPort, err)) { // NOTE: different dmap port
            client.verify("ok DMAP");
            client.sendAndVerify("login arthur 23456", "ok");

            Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT); // waiting for the message to be sent
            client.send("list");
            String listResult = client.listen();
            LOG.info("\n-------------------------------- SHOW RESULT -----------------------------------------\n"+listResult+
                "\n--------------------------------------------------------------------------------------");

            assertEquals(numberOfThreads, listResult.lines().count()-1);

            client.sendAndVerify("logout", "ok");
            client.sendAndVerify("quit", "ok bye");
        }

    }

    private void transferMessage(int[] transferServerPortt) throws Exception{
        int which = (int) Math.round(Math.random()) * (transferServerPortt.length-1);
        LOG.info("SELECTED TRANSFER SERVER: "+which);
        try (JunitSocketClient client = new JunitSocketClient(transferServerPortt[which], err)) {
            client.verify("ok DMTP");
            client.sendAndVerify("begin", "ok");
            client.sendAndVerify("from trillian@earth.planet", "ok");
            client.sendAndVerify("to arthur@earth.planet,zaphod@univer.ze", "ok 2");
            client.sendAndVerify("subject message through "+transferServerPortt[which], "ok");
            client.sendAndVerify("data i have thought about it and the answer is clearly 42 ", "ok");
            client.sendAndVerify("send", "ok");
            client.sendAndVerify("quit", "ok bye");
        }
    }


}
