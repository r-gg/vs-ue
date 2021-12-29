package dslab;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * CheckedConsumer.
 */
@FunctionalInterface
public interface CheckedConsumer<T, E extends Exception> {
    void accept(T socket) throws E, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException;
}
