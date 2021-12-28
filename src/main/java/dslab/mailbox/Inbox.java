package dslab.mailbox;

import dslab.shared_models.DMTP_Message;

import java.io.UncheckedIOException;
import java.util.*;

public class Inbox {

  private int index = 0;
  private HashMap<Integer, DMTP_Message> internalMap = new HashMap<>();
  // Inspiration for this solution (internal HashMap + index) taken from:
  // https://stackoverflow.com/questions/16069636/collection-with-automatic-indexing-in-java

  /**
   * adds the message, incrementing the internal index
   *
   * @param msg the mail to add to the inbox
   */
  public synchronized void add(DMTP_Message msg) {
    if (index == Integer.MAX_VALUE) {
      System.err.println("A message was lost because an Mailbox overflowed. That's a lot of ~damage~ spam!");
    } else {
      int temp = index++;
      internalMap.put(temp, msg);
    }
  }

  /**
   * pre: internalMap never holds null-values
   *
   * @param id the ID of the message to delete
   * @return true if message was deleted, false if the message didn't exist in the first place
   */
  public synchronized boolean delete(int id) {
    return internalMap.remove(id) != null;
  }

  /**
   * @param id the ID of the message to retrieve
   * @return of(msg) if a msg was found, empty if the message didn't exist
   */
  public synchronized Optional<DMTP_Message> get(int id) {
    return internalMap.containsKey(id) ? Optional.of(internalMap.get(id)) : Optional.empty();
  }

  public synchronized List<String> list_mails_sigs() {
    List<String> res = new LinkedList<>();
    for (Map.Entry<Integer, DMTP_Message> entry : internalMap.entrySet()) {
      var ind = entry.getKey();
      var mail = entry.getValue();
      res.add(ind + " " + mail.sender + " " + mail.subject);
    }
    return res;
  }
}
