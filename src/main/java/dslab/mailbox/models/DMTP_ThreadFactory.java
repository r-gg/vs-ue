package dslab.mailbox.models;

import dslab.mailbox.Inbox;
import dslab.mailbox.sub_threads.DMTP_Thread;
import dslab.util.Pair;

import java.net.Socket;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class DMTP_ThreadFactory implements ThreadFactory {
  @Override
  public MB_Thread newThread(String componentId, String domain, AtomicBoolean shutdown_initiated, Socket incomingConn, Map<String, Pair<String, Inbox>> user_db) {
    return new DMTP_Thread(componentId, domain, shutdown_initiated, incomingConn, user_db);
  }
}
