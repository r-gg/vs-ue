package dslab.system;

import dslab.ComponentFactory;
import dslab.Constants;
import dslab.Sockets;
import dslab.TestBase;
import dslab.mailbox.IMailboxServer;
import dslab.monitoring.IMonitoringServer;
import dslab.transfer.ITransferServer;
import dslab.util.Config;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import java.net.SocketTimeoutException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

public class SystemTest extends TestBase {
    private static final Log LOG = LogFactory.getLog(SystemTest.class);

    @Test
    public void runAndShutdownTransferServer_createsAndStopsTcpSocketCorrectly() throws Exception {
        ITransferServer transferServer = ComponentFactory.createTransferServer("transfer-1", transferIn, transferOut);
        int port = new Config("transfer-1").getInt("tcp.port");

        String componentId = "mailbox-earth-planet";
        Config config = new Config(componentId);
        IMailboxServer mailboxServer = ComponentFactory.createMailboxServer(componentId, mailboxIn1, mailboxOut1);
        int dmtpPort = config.getInt("dmtp.tcp.port");
        int dmapPort = config.getInt("dmap.tcp.port");

        IMonitoringServer monitoringServer = ComponentFactory.createMonitoringServer("monitoring", monitorIn, monitorOut);
        int monitoringPort = new Config("monitoring").getInt("udp.port");

        assertThat(transferServer, is(notNullValue()));
        assertThat(mailboxServer, is(notNullValue()));
        assertThat(monitoringServer, is(notNullValue()));

        Thread transferThread = new Thread(transferServer);
        LOG.info("Starting thread with transferServer " + transferServer);
        transferThread.start();



        Thread monitoringThread = new Thread(monitoringServer);
        LOG.info("Starting thread with monitoringServer " + monitoringServer);
        monitoringThread.start();

        Thread.sleep(Constants.COMPONENT_STARTUP_WAIT); // wait a bit for resources to be initialized


        Thread mailboxThread = new Thread(mailboxServer);
        LOG.info("Starting thread with mailboxServer " + mailboxServer);
        mailboxThread.start();

        // transfer
        try {
            LOG.info("Waiting for socket to open on port " + port);
            Sockets.waitForSocket("localhost", port, Constants.COMPONENT_STARTUP_WAIT);
        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + port, e));
        }

        // Mailbox
        try {
            LOG.info("Waiting for DMTP socket to open on port " + dmtpPort);
            Sockets.waitForSocket("localhost", dmtpPort, Constants.COMPONENT_STARTUP_WAIT);
        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + dmtpPort, e));
        }

        try {
            LOG.info("Waiting for DMAP socket to open on port " + dmapPort);
            Sockets.waitForSocket("localhost", dmapPort, Constants.COMPONENT_STARTUP_WAIT);
        } catch (SocketTimeoutException e) {
            err.addError(new AssertionError("Expected a TCP server socket on port " + dmapPort, e));
        }

        // Monitoring
        try {
            LOG.info("Trying to create socket on port " + monitoringPort);
            err.checkThat("Expected an open UDP socket on port " + monitoringPort, Sockets.isDatagramSocketOpen(monitoringPort), is(true));
        } catch (Exception e) {
            // a different unexpected error occurred (unlikely)
            err.addError(e);
        }

        // Shutdown
        LOG.info("Shutting down servers");
        transferIn.addLine("shutdown"); // send "shutdown" command to transfer servers command line
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/2);
        mailboxIn1.addLine("shutdown"); // second command to shut down the mailbox server
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/2);
        monitorIn.addLine("shutdown"); // third command to shut down the monitor server
        Thread.sleep(Constants.COMPONENT_TEARDOWN_WAIT/2);
        try {
            LOG.info("Waiting for thread to stop for transferServer " + transferServer);
            transferThread.join();
        } catch (InterruptedException e) {
            err.addError(new AssertionError("Monitoring server was not terminated correctly"));
        }

        try {
            LOG.info("Waiting for thread to stop for mailboxServer " + mailboxServer);
            mailboxThread.join();
        } catch (InterruptedException e) {
            err.addError(new AssertionError("Monitoring server was not terminated correctly"));
        }

        // Monitor
        try {
            LOG.info("Waiting for thread to stop for monitoringServer " + monitoringServer);
            monitoringThread.join();
        } catch (InterruptedException e) {
            err.addError(new AssertionError("Monitoring server was not terminated correctly"));
        }

        // Transfer
        err.checkThat("Expected tcp socket on port " + port + " to be closed after shutdown",
                Sockets.isServerSocketOpen(port), is(false));
        // Mailbox
        err.checkThat("Expected tcp socket on port " + dmtpPort + " to be closed after shutdown",
                Sockets.isServerSocketOpen(dmtpPort), is(false));

        err.checkThat("Expected tcp socket on port " + dmapPort + " to be closed after shutdown",
                Sockets.isServerSocketOpen(dmapPort), is(false));

        // Monitor
        err.checkThat("Expected datagram socket on port " + monitoringPort + " to be closed after shutdown",
                Sockets.isDatagramSocketOpen(monitoringPort), is(false));
    }

}
