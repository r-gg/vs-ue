package dslab.transfer.sub_thread;

import dslab.shared_models.DMTP_Message;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class AcceptThread implements Runnable {

  private AtomicBoolean shutdown_initiated;
  private ServerSocket serverSocket;
  private ExecutorService thread_pool;
  private BlockingQueue<DMTP_Message> waiting_messages;

  public AcceptThread(
      int port,
      AtomicBoolean si,
      int scale_factor,
      BlockingQueue<DMTP_Message> waiting_messages) {
    this.shutdown_initiated = si;
    this.waiting_messages = waiting_messages;

    // test - does this work when in the constructor (as opposed to in run())?
    try {
      serverSocket = new ServerSocket(port);
    } catch (IOException e) {
      shutdown_initiated.set(true);
      throw new UncheckedIOException("Error while creating server socket\n" + e.getMessage(), e);
    }

    try {
      this.serverSocket.setSoTimeout(500);
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
        // all ok, happens 2x/s to allow shutdown_initiated-check
        // (construct chosen over shutting down via socket-closing)
        continue;
      } catch (IOException e) {
        throw new UncheckedIOException(
            "Error during serverSocket.accept()-call\n" + e.getMessage(), e);
      }
      thread_pool.execute(new ConnectionHandler(shutdown_initiated, incomingConn, waiting_messages));
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
