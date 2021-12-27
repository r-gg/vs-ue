package dslab.client;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * An exception indicating that a server "misbehaved".
 * IDK yet whether/how to handle them - maybe do print something to the shell before aborting...
 */
public class ServerError extends Error {
  public ServerError(String detail_msg) {
    super(detail_msg);
  }
}
