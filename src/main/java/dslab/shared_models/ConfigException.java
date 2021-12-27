package dslab.shared_models;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * An exception indicating problems with (reading in) the configuration file
 * Will usually not get handled, but lead to shutdown.
 */
public class ConfigException extends UncheckedIOException {
  public ConfigException(String msg, IOException cause) {
    super(msg, cause);
  }
}
