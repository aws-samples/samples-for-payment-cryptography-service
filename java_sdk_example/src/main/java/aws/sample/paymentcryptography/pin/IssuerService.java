package aws.sample.paymentcryptography.pin;

import com.amazonaws.services.paymentcryptography.model.Alias;
import com.amazonaws.services.paymentcryptography.model.Key;
import com.amazonaws.services.paymentcryptographydata.AWSPaymentCryptographyData;
import com.amazonaws.services.paymentcryptographydata.model.PinVerificationAttributes;
import com.amazonaws.services.paymentcryptographydata.model.VerifyPinDataRequest;
import com.amazonaws.services.paymentcryptographydata.model.VerifyPinDataResult;
import com.amazonaws.services.paymentcryptographydata.model.VisaPinVerification;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;

public class IssuerService {

    private static String encryptedPinBlock = "5748C8FC6EF3DB52"; //"A2725B9007D341AE";
    private static String PAN = "9123412341234";
    private static final String ISSUER_PEK_ALIAS = "alias/acquirer-working-key"; // key used by
                                                                                 // PaymentProcessorPinTranslate to
                                                                                 // encrypt the PIN

    private static final String INPUT_PIN_BLOCK_FORMAT = "ISO_FORMAT_0";
    private static final String OUTPUT_PIN_BLOCK_FORMAT = "ISO_FORMAT_3";
    private static final String OUTPUT_DUKPT_TYPE = "TDES_2KEY";
    private static final String OUTPUT_DUKPT_KSN = "FFFF9876543210E00001"; 
    private static final int VERIFICATION_KEY_INDEX = 0;

    private static final String PEK_ALGO = "TDES_3KEY";
    private static final String BDK_ALGO = "TDES_2KEY"; //"AES_128";
    private static final String PGK_ALGO = "TDES_3KEY";

    private static final String pekAliasName = String.format("alias/demo-pek");
    private static final String bdkAliasName = String.format("alias/demo-bdk");
    private static final String pgkAliasName = String.format("alias/demo-pgk");
    private static Alias pekAlias = ControlPlaneUtils.getOrCreateAlias(pekAliasName);
    private static Alias bdkAlias = ControlPlaneUtils.getOrCreateAlias(bdkAliasName);
    private static Alias pgkAlias = ControlPlaneUtils.getOrCreateAlias(pgkAliasName);

    //private static final String TEST_DATA_FROM_BANK = "6D064DD821983A3D";
    private static final String pinVerificationValue = "1571";
    //private static final String encryptionArn = "arn:aws:payment-cryptography:us-east-1:886958290065:key/7f5sirc2frutlpfo";
    //private static final String generationArn = "arn:aws:payment-cryptography:us-east-1:886958290065:key/sxcbkkd7fxptczvh";

    private static AWSPaymentCryptographyData client = DataPlaneUtils.getDataPlaneClient();

    public static void main(String[] args) {
        //generatePinData();
        VerifyPinDataResult verifyPinDataResult = verifyPinData(encryptedPinBlock, pekAlias.getKeyArn(), pgkAlias.getKeyArn(),
                pinVerificationValue, OUTPUT_PIN_BLOCK_FORMAT, PAN);
        System.out.println(verifyPinDataResult);

    }

    private static VerifyPinDataResult verifyPinData(String encryptedPinBlock, String encryptionKeyIdentifier,
            String verificationKeyIdentifer, String pinVerificationValue, String pinBlockFormat,
            String primaryAccountNumber) {

        VisaPinVerification visaPinVerification = new VisaPinVerification();
        visaPinVerification.withPinVerificationKeyIndex(1)
                .withVerificationValue(pinVerificationValue); // TODO where is the verification value coming from?,
                                                              // where is the genration
        // key identifier created, why pin for visa only
        PinVerificationAttributes pinVerificationAttributes = new PinVerificationAttributes();
        pinVerificationAttributes.withVisaPin(visaPinVerification);

        VerifyPinDataRequest verifyPinDataRequest = new VerifyPinDataRequest();
        verifyPinDataRequest.withEncryptedPinBlock(encryptedPinBlock)
                .withVerificationKeyIdentifier(verificationKeyIdentifer)
                .withEncryptionKeyIdentifier(encryptionKeyIdentifier)
                .withPrimaryAccountNumber(primaryAccountNumber)
                .withPinBlockFormat(pinBlockFormat)
                .withVerificationAttributes(pinVerificationAttributes);

        VerifyPinDataResult verifyPinDataResult = client.verifyPinData(verifyPinDataRequest);
        return verifyPinDataResult;
        // verifyPinDataResult.getVerificationKeyCheckValue();

    }

    private static void generatePinData() {
        // finds or generates a Pin Generation Key (used for generating random PINs)
        if (null == pgkAlias.getKeyArn()) {
            System.out.println("No PGK found, creating a new one.");
            Key pgkKey = ControlPlaneUtils.createVisaPGK(PGK_ALGO);
            pgkAlias = ControlPlaneUtils.upsertAlias(pgkAliasName, pgkKey.getKeyArn());
            System.out.println(String.format("PGK created: %s", pgkAlias.getKeyArn()));
        } else {
            System.out.println(String.format("PGK already exists: %s", pgkAlias.getKeyArn()));
        }

        // finds existing or generates a Pin Encryption Key (used for encryption pin
        // payloads)
        if (null == pekAlias.getKeyArn()) {
            System.out.println("No PEK found, creating a new one.");
            Key pekKey = ControlPlaneUtils.createPEK(PEK_ALGO);
            pekAlias = ControlPlaneUtils.upsertAlias(pekAliasName, pekKey.getKeyArn());
            System.out.println(String.format("PEK created: %s", pekAlias.getKeyArn()));
        } else {
            System.out.println(String.format("PEK already exists: %s", pekAlias.getKeyArn()));
        }

        // Generate a BDK used as the base deriviation key typically for DUKPT
        if (null == bdkAlias.getKeyArn()) {
            System.out.println("No BDK found, creating a new one.");
            Key bdkKey = ControlPlaneUtils.createBDK(BDK_ALGO);
            bdkAlias = ControlPlaneUtils.upsertAlias(bdkAliasName, bdkKey.getKeyArn());
            System.out.println(String.format("BDK created: %s", bdkAlias.getKeyArn()));
        } else {
            System.out.println(String.format("BDK already exists: %s", bdkAlias.getKeyArn()));
        }
        System.out.println("Creating a random pin and returns back the encrypted pin and visa/ABA PVV");
        String pinBlockUnderPEK = DataPlaneUtils.generateVisaPinBlock(
                pekAliasName,
                pgkAliasName,
                INPUT_PIN_BLOCK_FORMAT,
                PAN,
                VERIFICATION_KEY_INDEX);
        System.out.println(String.format("PIN block: %s", pinBlockUnderPEK));

        System.out.println("Translating encrypted PIN under PEK to encrypted under DUKPT");
        String pinBlockUnderBDK = DataPlaneUtils.translateVisaPinBlockPekToBdk(
                pekAliasName,
                INPUT_PIN_BLOCK_FORMAT,
                pinBlockUnderPEK,
                bdkAliasName,
                OUTPUT_PIN_BLOCK_FORMAT,
                OUTPUT_DUKPT_TYPE,
                OUTPUT_DUKPT_KSN,
                PAN);

        System.out.println(String.format("Translated PIN block: %s", pinBlockUnderBDK));
    }
}
