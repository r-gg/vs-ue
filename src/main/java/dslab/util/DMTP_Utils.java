package dslab.util;

import java.io.PrintWriter;
import java.util.Optional;

public class DMTP_Utils {
  static public void ok(PrintWriter writer) {
    ok(writer, "");
  }

  static public void ok(PrintWriter writer, String msg) {
    printMsg(writer, "ok" + ("".equals(msg) ? "" : " " + msg));
  }

  static public void protocol_error(PrintWriter writer) {
    error(writer, "protocol error");
  }

  static public void error(PrintWriter writer, String msg) {
    printMsg(writer, "error " + msg);
  }

  static public void printMsg(PrintWriter writer, String msg) {
    writer.println(msg);
    writer.flush();
  }

  /**
   * removes leading or trailing whitespace,
   * checks if the line has the form of "<command>[ <content>]"
   * splits the given string at the first whitespace, if any
   *
   * @param line
   * @return "empty" if String is empty, otherwise the 1-2 processed (see above) segments of the string
   */
  static public Optional<Pair<String, Optional<String>>> split_cmd_cntnt(String line) {
    String[] words = line.trim().split("\\s", 2);
    switch (words.length) {
      case 0: return Optional.empty();
      case 1: return Optional.of(new Pair<>(words[0], Optional.empty()));
      case 2: return Optional.of(new Pair<>(words[0], Optional.of(words[1])));
      default: assert (false); return Optional.empty();
    }
  }
}
