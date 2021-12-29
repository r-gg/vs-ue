package dslab.shared_models;

// Exception which is thrown if one of the steps in the handshake fails
public class HandshakeException extends Exception{
    public HandshakeException() {
    }

    public HandshakeException(String message) {
        super(message);
    }

    public HandshakeException(String message, Throwable cause) {
        super(message, cause);
    }

    public HandshakeException(Throwable cause) {
        super(cause);
    }

    public HandshakeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
