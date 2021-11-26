package dslab.shared_models;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * for now my way of aborting the program in "untenable" situations
 */
public class ConfigOrImplException extends UncheckedIOException {
  public ConfigOrImplException(String msg, IOException cause) {
    super(msg, cause);
  }
}
