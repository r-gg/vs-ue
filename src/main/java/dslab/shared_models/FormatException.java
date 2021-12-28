package dslab.shared_models;

/**
 * An exception indicating that an argument (probably a String) did not conform to the expected Format.
 * Can/Should probably be handled.
 */
public class FormatException extends Exception {
  FormatException (String details_on_problem) {
    super(details_on_problem);
  }
}
