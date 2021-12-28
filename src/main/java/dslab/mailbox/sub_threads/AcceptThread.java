package dslab.mailbox.sub_threads;

import dslab.mailbox.Inbox;
import dslab.util.Pair;
import dslab.mailbox.models.ThreadFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class AcceptThread implements Runnable {

  private final AtomicBoolean shutdown_initiated;
  private final ServerSocket serverSocket;
  private final ExecutorService thread_pool;
  private final Map<String, Pair<String, Inbox>> user_db;
  private final ThreadFactory thread_maker;
  private final String domain;
  private final String componentId;

  public AcceptThread(
      String componentId,
      String domain,
      int port,
      AtomicBoolean si,
      Map<String, Pair<String, Inbox>> user_db,
      ThreadFactory thread_maker) {
    this.componentId = componentId;
    this.domain = domain;
    this.shutdown_initiated = si;
    this.user_db = user_db;
    this.thread_maker = thread_maker;

    try {
      serverSocket = new ServerSocket(port);
    } catch (IOException e) {
      shutdown_initiated.set(true);
      throw new UncheckedIOException("Error while creating server socket\n" + e.getMessage(), e);
    }

    try {
      this.serverSocket.setSoTimeout(1500);
    } catch (SocketException e) {
      shutdown_initiated.set(true);
      throw new UncheckedIOException(
          "Error while setting accept-blocking-timeout\n" + e.getMessage(), e);
    }

    thread_pool = Executors.newCachedThreadPool();
  }

  @Override
  public void run() {
    // wait for Client to connect
    while (!shutdown_initiated.get()) {
      Socket incomingConn;
      try {
        incomingConn = serverSocket.accept();
      } catch (SocketTimeoutException timeout) {
        // all ok, happens every 1500ms to allow shutdown_initiated-check
        // (construct chosen over shutting down via socket-closing)
        continue;
      } catch (IOException e) {
        throw new UncheckedIOException(
            "Error during serverSocket.accept()-call\n" + e.getMessage(), e);
      }
      thread_pool.execute(thread_maker.newThread(componentId, domain, shutdown_initiated, incomingConn, user_db));
    }

    // shutdown_initiated -> shutdown everything down!
    try {
      serverSocket.close();
    } catch (IOException e) {
      // LVA-sanctioned "Ignore unhandle-able case"
      e.printStackTrace();
    }
    thread_pool.shutdown();
    System.out.println("AcceptThread seems to have finished");
  }
}
