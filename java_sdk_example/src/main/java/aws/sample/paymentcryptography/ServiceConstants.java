package aws.sample.paymentcryptography;

public interface ServiceConstants extends CommonConstants {
    
    public final String ISO_0_PIN_BLOCK_FORMAT = "ISO_FORMAT_0";
    public final String ISO_4_PIN_BLOCK_FORMAT = "ISO_FORMAT_4";

    public final String BDK_ALIAS_AES_128 = "alias/MerchantTerminal_BDK_AES_128";
    public final String BDK_ALIAS_TDES_2KEY = "alias/MerchantTerminal_TDES_BDK";
    public final String PIN_TRANSLATION_KEY_ALIAS = "alias/pinTranslateServicePek";
    public final String ISSUER_PEK_ALIAS = "alias/issuerPek";
    public final String PIN_VALIDATION_KEY_ALIAS = "alias/issuerPinValidationKey";
    public final String ARQC_Retail_9797_3_KEY_ALIAS = "alias/arqcValidationKey";
    public final String ISO_9797_3_MAC_KEY_ALIAS = "alias/macValidationKey";

    public final String BDK_ALGORITHM_AES_128 = "AES_128";//"TDES_2KEY";
    public final String BDK_ALGORITHM_TDES_2KEY = "TDES_2KEY";//"TDES_2KEY";
    public final String PEK_ALGORITHM = "TDES_3KEY";
    public final String PGK_ALGORITHM = "TDES_3KEY";

    public final int PIN_VERIFICATION_KEY_INDEX = 1;

}
