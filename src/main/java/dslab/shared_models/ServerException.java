package dslab.shared_models;

/**
 * An exception indicating that, while communicating with an external server,
 * that server "misbehaved" (i.e. committed a protocol-breach or aborted the connection early).
 * I think this should get handled without aborting the application,
 * or by at least printing a meaningful message before aborting
 */
public class ServerException extends Exception {
  public ServerException(String detail_msg) {
    super(detail_msg);
  }
}
