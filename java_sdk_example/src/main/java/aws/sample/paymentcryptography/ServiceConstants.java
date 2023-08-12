package aws.sample.paymentcryptography;

public interface ServiceConstants extends CommonConstants {
    
    public final String ISO_0_PIN_BLOCK_FORMAT = "ISO_FORMAT_0";
    public final String ISO_3_PIN_BLOCK_FORMAT = "ISO_FORMAT_3";

    public final String BDK_ALIAS = "alias/MerchantTerminal_BDK";
    public final String PIN_TRANSLATION_KEY_ALIAS = "alias/pinTranslateServicePek";
    public final String ISSUER_PEK_ALIAS = "alias/issuerPek";
    public final String PIN_VALIDATION_KEY_ALIAS = "alias/issuerPinValidationKey";
    public final String HMAC_KEY_ALIAS = "alias/tr31_macValidationKey";

    public final String BDK_ALGORITHM = "TDES_2KEY";
    public final String PEK_ALGORITHM = "TDES_3KEY";
    public final String PGK_ALGORITHM = "TDES_3KEY";

    public final int PIN_VERIFICATION_KEY_INDEX = 1;

}
