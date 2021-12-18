package dslab.mailbox.models;

import dslab.mailbox.Inbox;
import dslab.util.Pair;

import java.net.Socket;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public abstract class MB_Thread implements Runnable {

  protected final String componentId;
  protected final String domain;
  protected final AtomicBoolean shutdown_initiated;
  protected final Socket socket;
  protected final Map<String, Pair<String, Inbox>> user_db;

  public MB_Thread( String componentId, String domain, AtomicBoolean shutdown_initiated, Socket incomingConn, Map<String, Pair<String, Inbox>> user_db) {
    this.componentId = componentId;
    this.domain = domain;
    this.shutdown_initiated = shutdown_initiated;
    this.socket = incomingConn;
    this.user_db = user_db;
  }
}
