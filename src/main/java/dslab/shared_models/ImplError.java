package dslab.shared_models;

/**
 * An error showing that some unexpected/"illegal" program state occurred
 * If this gets thrown, it does not need to get handled by the calling code
 * (see the customary difference between "Error" and "Exception" in Java)
 * Instead, if it ever shows up at runtime, it means that some bug needs to be squashed.
 */
public class ImplError extends Error {
  public ImplError(String detail_msg) {
    super(detail_msg);
  }
}
