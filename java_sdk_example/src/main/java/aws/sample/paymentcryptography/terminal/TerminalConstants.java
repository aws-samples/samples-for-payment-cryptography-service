package aws.sample.paymentcryptography.terminal;

import aws.sample.paymentcryptography.CommonConstants;

public interface TerminalConstants extends CommonConstants{
    
    public final String PIN_MASK = "00000000000000FF00000000000000FF";

    /* Clear text key */
    public final String MAC_KEY_PLAIN_TEXT = "75BDAEF54587CAE6563A5CE57B4B9F9F";

    // Clear text PEK key.
    public final String PEK = "545e2aadfd5ec42f2f5be5e3adc75e9b290252a1a219b380";

    public final String ALGORITHM = "DESede"; // Same as TripleDES
    public final String NO_PADDING = "NoPadding";
    public final String PKCS_PADDING = "PKCS5Padding";
    public final String TRANSFORMATION = ALGORITHM + "/" + MODE + "/" + NO_PADDING;

    public final String TRANSFORMATION_WITH_PKCS5_PADDING = ALGORITHM + "/" + MODE + "/" + PKCS_PADDING;
}
