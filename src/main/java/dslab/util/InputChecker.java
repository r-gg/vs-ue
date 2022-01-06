package dslab.util;

import java.util.Arrays;

public class InputChecker {

  public static boolean null_or_blank(String test) {
    return test == null || test.isBlank();
  }

  /**
   * @param str
   * @return whether str has the form of an email address: "<non-blank, no space>@<non-blank, no space>"
   */
  public static boolean is_mail_address(String str) {
    if (str == null) {
      return false;
    }
    if (str.contains(" ")) {
      return false;
    }

    var splits = str.split("@", 0);
    return splits.length == 2 &&
        !"".equals(splits[0]) &&
        !"".equals(splits[1]);
  }


  public static boolean is_server_addr_string(String str) {
    if (str == null) {
      return false;
    }
    if (str.contains(" ")) {
      return false;
    }

    // <bla>:<blub>
    var splits = str.split(":");
    if (splits.length != 2) {
      return false;
    }
    var bla = splits[0];
    var blub = splits[1];

    // bla ist 4 zahlen, interspersed mit 3 punkten (etwa 123.1234.1346346.12356)
    var bla_splits = bla.split("\\.");
    if (bla_splits.length != 4) {
      return false;
    }
    if (!Arrays.stream(bla_splits).allMatch(InputChecker::is_int_parsable)) {
      return false;
    }

    // blub is int-parsable
    if (!is_int_parsable(blub)) {
      return false;
    }

    return true;
  }

  private static boolean is_int_parsable(String int_str) {
    try {
      var parse_res = Integer.parseInt(int_str);
    } catch (NumberFormatException e) {
      // actually more "malformed message id" than "unknown message id"
      return false;
    }
    return true;
  }

}
