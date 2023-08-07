package aws.sample.paymentcryptography;

public interface ServiceConstants extends CommonConstants {
    
    public final String ISO_0_PIN_BLOCK_FORMAT = "ISO_FORMAT_0";
    public final String ISO_3_PIN_BLOCK_FORMAT = "ISO_FORMAT_3";

    public final String BDK_ARN = "arn:aws:payment-cryptography:us-east-1:886958290065:key/xe5wa7q2xcke6g7j";
    
    public final String ACQUIRER_WORKING_KEY_ALIAS = "alias/atmPek";

    public final String BDK_ALGORITHM = "TDES_2KEY"; // BDK for DUKPT
    public final String PEK_ALGORITHM = "TDES_3KEY"; // Pin Encryption Key
    public final String PGK_ALGORITHM = "TDES_3KEY"; // Pin Generation Key

    public final int PIN_VERIFICATION_KEY_INDEX = 1;

}
