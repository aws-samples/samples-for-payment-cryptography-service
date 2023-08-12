package aws.sample.paymentcryptography.pin;

import org.json.JSONObject;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.services.paymentcryptography.model.Alias;
import com.amazonaws.services.paymentcryptographydata.AWSPaymentCryptographyData;
import com.amazonaws.services.paymentcryptographydata.model.GeneratePinDataRequest;
import com.amazonaws.services.paymentcryptographydata.model.GeneratePinDataResult;
import com.amazonaws.services.paymentcryptographydata.model.PinGenerationAttributes;
import com.amazonaws.services.paymentcryptographydata.model.PinVerificationAttributes;
import com.amazonaws.services.paymentcryptographydata.model.VerifyPinDataRequest;
import com.amazonaws.services.paymentcryptographydata.model.VerifyPinDataResult;
import com.amazonaws.services.paymentcryptographydata.model.VisaPinVerification;
import com.amazonaws.services.paymentcryptographydata.model.VisaPinVerificationValue;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;
import aws.sample.paymentcryptography.ServiceConstants;

@RestController
public class IssuerService {

    /* private static final String pekAliasName = String.format("alias/demo-pek");
    private static final String bdkAliasName = String.format("alias/demo-bdk");
    private static Alias pekAlias = ControlPlaneUtils.getOrCreateAlias(pekAliasName);
    private static Alias bdkAlias = ControlPlaneUtils.getOrCreateAlias(bdkAliasName); */

    private static final String issuerPekAliasName = ServiceConstants.ISSUER_PEK_ALIAS;
    private static final String pinValidationKeyAliasName = ServiceConstants.PIN_VALIDATION_KEY_ALIAS;
    private static Alias issuerPekAlias = ControlPlaneUtils.getOrCreateAlias(issuerPekAliasName);    
    private static Alias pinValidationKeyAlias = ControlPlaneUtils.getOrCreateAlias(pinValidationKeyAliasName);

    private static AWSPaymentCryptographyData client = DataPlaneUtils.getDataPlaneClient();

    private String pinVerificationValue = null;
    
    @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_SET_API)
    @ResponseBody
    public String setPinData(@RequestParam String encryptedPinBLock, @RequestParam String pan) {
        JSONObject response = new JSONObject();

        try {
            VisaPinVerificationValue pinVerificationValue = new VisaPinVerificationValue()
                .withEncryptedPinBlock(encryptedPinBLock)
                .withPinVerificationKeyIndex(ServiceConstants.PIN_VERIFICATION_KEY_INDEX);
        PinGenerationAttributes attributes = new PinGenerationAttributes()
                .withVisaPinVerificationValue(pinVerificationValue);
        GeneratePinDataRequest request = new GeneratePinDataRequest()
                .withGenerationKeyIdentifier(pinValidationKeyAlias.getKeyArn())
                .withEncryptionKeyIdentifier(issuerPekAlias.getKeyArn())
                .withPrimaryAccountNumber(pan)
                .withPinBlockFormat(ServiceConstants.ISO_0_PIN_BLOCK_FORMAT)
                .withGenerationAttributes(attributes);

        GeneratePinDataResult result = client.generatePinData(request);
        response.put("pvv", result.getPinData().getVerificationValue());
        setPinVerificationValue(result.getPinData().getVerificationValue());
        } catch(Exception exception) {
            response.put("error", exception.getMessage());
        }
        return response.toString();
    }

    @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API)
    @ResponseBody
    public String verifyPinData(@RequestParam String encryptedPin, @RequestParam String pan, @RequestParam String pinVerificationValue){
        JSONObject response = new JSONObject();
        try {
            VerifyPinDataResult verifyPinDataResult = verifyPinData(encryptedPin, issuerPekAlias.getKeyArn(), 
            pinValidationKeyAlias.getKeyArn(), pinVerificationValue, ServiceConstants.ISO_0_PIN_BLOCK_FORMAT, pan);
            if(verifyPinDataResult!=null) {
                response.put("status", "pass");
            }else {
                response.put("status", "fail");    
            }
        return response.toString();
        } catch(Exception exception) {
            exception.printStackTrace();
            response.put("status", "fail");
        }
        return response.toString();
        
    }

    private VerifyPinDataResult verifyPinData(String encryptedPinBlock, String encryptionKeyIdentifier,
            String verificationKeyIdentifer, String pinVerificationValue, String pinBlockFormat,
            String primaryAccountNumber) {

        VisaPinVerification visaPinVerification = new VisaPinVerification();
        visaPinVerification.withPinVerificationKeyIndex(ServiceConstants.PIN_VERIFICATION_KEY_INDEX)
                .withVerificationValue(pinVerificationValue); 
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
    }

    /*
     * Sample code to show how new pin genration can be done in the Payment Cryptography Service. This flow is currently not used in the samples.
    */
    /* private GeneratePinDataResult generatePinData() {
        // finds or generates a Pin Generation Key (used for generating random PINs)
        if (null == pgkAlias.getKeyArn()) {
            System.out.println("No PGK found, creating a new one.");
            Key pgkKey = ControlPlaneUtils.createVisaPGK(ServiceConstants.PGK_ALGORITHM);
            pgkAlias = ControlPlaneUtils.upsertAlias(pgkAliasName, pgkKey.getKeyArn());
            System.out.println(String.format("PGK created: %s", pgkAlias.getKeyArn()));
        } else {
            System.out.println(String.format("PGK already exists: %s", pgkAlias.getKeyArn()));
        }

        // finds existing or generates a Pin Encryption Key (used for encryption pin
        // payloads)
        if (null == pekAlias.getKeyArn()) {
            System.out.println("No PEK found, creating a new one.");
            Key pekKey = ControlPlaneUtils.createPEK(ServiceConstants.PEK_ALGORITHM);
            pekAlias = ControlPlaneUtils.upsertAlias(pekAliasName, pekKey.getKeyArn());
            System.out.println(String.format("PEK created: %s", pekAlias.getKeyArn()));
        } else {
            System.out.println(String.format("PEK already exists: %s", pekAlias.getKeyArn()));
        }

        // Generate a BDK used as the base deriviation key typically for DUKPT
        if (null == bdkAlias.getKeyArn()) {
            System.out.println("No BDK found, creating a new one.");
            Key bdkKey = ControlPlaneUtils.createBDK(ServiceConstants.BDK_ALGORITHM);
            bdkAlias = ControlPlaneUtils.upsertAlias(bdkAliasName, bdkKey.getKeyArn());
            System.out.println(String.format("BDK created: %s", bdkAlias.getKeyArn()));
        } else {
            System.out.println(String.format("BDK already exists: %s", bdkAlias.getKeyArn()));
        }
        System.out.println("Creating a random pin and returns back the encrypted pin and visa/ABA PVV");
        GeneratePinDataResult pinDataGenerationResult = DataPlaneUtils.generateVisaPinBlock(
                pekAliasName,
                pgkAliasName,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                ServiceConstants.PAN,
                ServiceConstants.PIN_VERIFICATION_KEY_INDEX);
        System.out.println(String.format("PIN block: %s", pinDataGenerationResult.getEncryptedPinBlock()));

        System.out.println("Translating encrypted PIN under PEK to encrypted under DUKPT");
        String pinBlockUnderBDK = DataPlaneUtils.translateVisaPinBlockPekToBdk(
                pekAliasName,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                pinDataGenerationResult.getEncryptedPinBlock(),
                bdkAliasName,
                ServiceConstants.ISO_3_PIN_BLOCK_FORMAT,
                ServiceConstants.BDK_ALGORITHM,
                ServiceConstants.KSN,
                ServiceConstants.PAN);

        System.out.println(String.format("Translated PIN block: %s", pinBlockUnderBDK));
        return pinDataGenerationResult;
    } */

    public String getPinVerificationValue() {
        return pinVerificationValue;
    }

    public void setPinVerificationValue(String pinVerificationValue) {
        this.pinVerificationValue = pinVerificationValue;
    }


}
