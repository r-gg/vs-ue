package dslab.shared_models;

import java.util.LinkedList;
import java.util.List;

public class DMTP_Message {
  public List<String> recipients;
  public String sender;
  public String subject;
  public String text_body;

  /**
   *  simple DMTP_Message validation
   *  only checks whether all fields are set (to something non-"empty" or "blank")
   *  doesn't check validity of sender / recipient mail addresses
   *  returns list of problems (as List<String>)
  */
  public static List<String> collectProblems(DMTP_Message msg) {
    List<String> probs = new LinkedList<>();
    if (msg.recipients == null || msg.recipients.isEmpty()) {
      probs.add("no recipients");
    }
    if (msg.sender == null) {
      probs.add("no sender");
    }
    if (msg.subject == null) {
      probs.add("no subject");
    }
    if (msg.text_body == null) {
      probs.add("no data");
    }
    return probs;
  }
}
