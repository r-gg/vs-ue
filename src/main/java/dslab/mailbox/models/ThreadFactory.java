package dslab.mailbox.models;

import dslab.mailbox.Inbox;
import dslab.util.Pair;

import java.net.Socket;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public interface ThreadFactory {
  MB_Thread newThread(String componentId, String domain, AtomicBoolean shutdown_initiated, Socket incomingConn, Map<String, Pair<String, Inbox>> user_db);
}
