package dslab.shared_models;

import dslab.util.InputChecker;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class DMTP_Message {
  public List<String> recipients;
  public String sender;
  public String subject;
  public String text_body;
  public String hash;

  /**
   * sets (or overwrites) the recipients field with a list of recipients parsed from...
   *
   * @param recip_str, a comma-separated list of one or more email addresses. e.g.: "someone@example.com,superman@cos.arctic"
   * @return how many recipients were detected/added
   * @throws FormatException if the recip_str is null, empty, or if for any of the substrings InputChecker.is_mail_address() is false
   *                         in this case, the message remains unchanged.
   */
  public int set_recips_by_string(String recip_str) throws FormatException {
    if (recip_str == null) {
      throw new FormatException("no recipient string was provided");
    }
    String[] split_recips = recip_str.split(",", 0);
    int n_recipients = split_recips.length;
    if (n_recipients < 1) {
      throw new FormatException("a string with no recipient was provided");
    }
    for (String r : split_recips) {
      if (!InputChecker.is_mail_address(r)) {
        throw new FormatException("at least one recipient address is malformed");
      }
    }
    this.recipients = new LinkedList<>();
    Collections.addAll(this.recipients, split_recips);
    return n_recipients;
  }

  /**
   * simple DMTP_Message validation
   * only checks whether all fields are set (to something non-"empty" or "blank")
   * except with hash, where just "not null" is checked
   * doesn't check validity of sender / recipient mail addresses
   * returns list of problems (as List<String>)
   */
  public static List<String> collectProblems(DMTP_Message msg) {
    List<String> probs = new LinkedList<>();
    if (msg.recipients == null || msg.recipients.isEmpty()) {
      probs.add("no recipients");
    }
    if (InputChecker.null_or_blank(msg.sender)) {
      probs.add("no sender");
    }
    if (InputChecker.null_or_blank(msg.subject)) {
      probs.add("no subject");
    }
    if (InputChecker.null_or_blank(msg.text_body)) {
      probs.add("no data");
    }
    if (msg.hash == null) {
      probs.add("no hash");
    }
    return probs;
  }

  /**
   * @return a String representation of the Message as DMAP's "show" would print it
   * (and as DMTP would set the message, if every line is read as a command)
   */
  @Override
  public String toString() {
    return "from " + this.sender + "\n"
        + "to " + String.join(",", this.recipients) + "\n"
        + "subject " + this.subject + "\n"
        + "data " + this.text_body + "\n"
        + "hash " + ((this.hash == null) ? "" : this.hash);
  }

  /**
   * @return a "canonical" string representation of the Message (for Hashing purposes):
   * The _contents_ of the fields
   * in the order: from, to, subject, data
   * separated by newlines
   */
  public String getJoined() {
    String recipients_str = this.recipients.toString().replace("[", "").replace("]", "");
    return String.join("\n", this.sender, recipients_str, this.subject, this.text_body);
  }
}
