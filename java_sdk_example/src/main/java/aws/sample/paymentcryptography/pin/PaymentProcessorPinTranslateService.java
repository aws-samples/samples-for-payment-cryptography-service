package aws.sample.paymentcryptography.pin;

import java.util.logging.Logger;

import com.amazonaws.services.paymentcryptography.model.Alias;
import com.amazonaws.services.paymentcryptography.model.Key;
import com.amazonaws.util.StringUtils;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;

public class PaymentProcessorPinTranslateService {

    private static final String INPUT_PIN_BLOCK_FORMAT = "ISO_FORMAT_0";
    private static final String OUTPUT_PIN_BLOCK_FORMAT = "ISO_FORMAT_3";

    private static final String ENCRYPTED_PIN_TEST_DATA = "5C69805208ECBD7B";
    private static final String PAN = "9123412341234";
    private static final String OUTPUT_DUKPT_KSN = "FFFF9876543210E00001";

    private static final String OUTPUT_DUKPT_TYPE = "TDES_2KEY";
    private static final String PEK_ALGO = "TDES_3KEY";

    private static final String BDK_ARN = "arn:aws:payment-cryptography:us-east-1:886958290065:key/xe5wa7q2xcke6g7j";

    //private static final String ACQUIRER_WORKING_KEY_ALIAS = "alias/acquirer-working-key";
    private static final String ACQUIRER_WORKING_KEY_ALIAS = "alias/demo-pek";

    public static void main(String[] args) {
        /* Acquirer Key */
        String acquirerWorkingKeyArn = getAcquirerWorkingKeyArn();

        String pinBlockUnderPEK = DataPlaneUtils.translateVisaPinBlockBdkToPek(BDK_ARN, 
                                                                    INPUT_PIN_BLOCK_FORMAT, 
                                                                    ENCRYPTED_PIN_TEST_DATA, 
                                                                    acquirerWorkingKeyArn, 
                                                                    OUTPUT_PIN_BLOCK_FORMAT, 
                                                                    OUTPUT_DUKPT_TYPE, 
                                                                    OUTPUT_DUKPT_KSN, 
                                                                    PAN);
         

        Logger.getGlobal().info("PIN Block under DUKPT - " + ENCRYPTED_PIN_TEST_DATA + " PIN Block under PEK - " + pinBlockUnderPEK);

    }

    /*  
     * Creating/Retrieving the Acquirer Working Key (AWK) alias. The underlying key is the same as the DEMO_PIN_PEK_ALIAS.
     * In real scenario, the payment gateway and acquirer would have the same PEK through a key exchange process.
    */
    private static String getAcquirerWorkingKeyArn(){
        Alias acquirerWorkingKeyAlias = ControlPlaneUtils.getOrCreateAlias(ACQUIRER_WORKING_KEY_ALIAS);
        if (StringUtils.isNullOrEmpty(acquirerWorkingKeyAlias.getKeyArn())) {
            Logger.getGlobal().info("No AWS PEK found, creating a new one.");
            //Alias demoPekAlias = ControlPlaneUtils.getControlPlaneClient().getAlias(new GetAliasRequest().withAliasName(DEMO_PIN_PEK_ALIAS_NAME)).getAlias();
            Key acquirerWorkingKey = ControlPlaneUtils.createPEK(PEK_ALGO);
            acquirerWorkingKeyAlias = ControlPlaneUtils.upsertAlias(acquirerWorkingKeyAlias.getAliasName(), acquirerWorkingKey.getKeyArn());
            Logger.getGlobal().info(String.format("PEK created: %s", acquirerWorkingKeyAlias.getKeyArn()));
            return acquirerWorkingKeyAlias.getKeyArn();
        } else {
            Logger.getGlobal().info(String.format("PEK already exists: %s", acquirerWorkingKeyAlias.getKeyArn()));
        }
        return acquirerWorkingKeyAlias.getKeyArn();
    }

}
