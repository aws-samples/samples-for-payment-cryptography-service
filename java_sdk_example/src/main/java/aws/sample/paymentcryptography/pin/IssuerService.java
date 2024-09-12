package aws.sample.paymentcryptography.pin;

import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;
import aws.sample.paymentcryptography.ServiceConstants;
import software.amazon.awssdk.services.paymentcryptography.model.Alias;
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataClient;
import software.amazon.awssdk.services.paymentcryptographydata.model.GeneratePinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.GeneratePinDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.PinGenerationAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.PinVerificationAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyPinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyPinDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.VisaPinVerification;
import software.amazon.awssdk.services.paymentcryptographydata.model.VisaPinVerificationValue;

@RestController
public class IssuerService {

    /* private static final String pekAliasName = String.format("alias/demo-pek");
    private static final String bdkAliasName = String.format("alias/demo-bdk");
    private Alias pekAlias = null;
    private Alias bdkAlias = null; */

    private Alias issuerPekAlias = null;
    private Alias pinValidationKeyAlias = null;

    private static PaymentCryptographyDataClient client = DataPlaneUtils.getDataPlaneClient();

    public IssuerService() throws InterruptedException, ExecutionException {
        //pekAlias = ControlPlaneUtils.getOrCreateAlias(pekAliasName);
        //bdkAlias = ControlPlaneUtils.getOrCreateAlias(bdkAliasName);
        issuerPekAlias = ControlPlaneUtils.getOrCreateAlias(ServiceConstants.ISSUER_PEK_ALIAS);    
        pinValidationKeyAlias = ControlPlaneUtils.getOrCreateAlias(ServiceConstants.PIN_VALIDATION_KEY_ALIAS);
    }
    /* File based repository where the pin verification values (PVV) are store against the PAN.
     * The PVV is needed for PIN verification with the AWS Cryptography Service. In real scenario,
     * the PVV would be stored in a database.
    */
    @Autowired
    private Repository repository;

    @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_SET_API)
    @ResponseBody
    public String setPinData(@RequestParam String encryptedPinBLock, @RequestParam String pan) {
        JSONObject response = new JSONObject();

        try {
            VisaPinVerificationValue pinVerificationValue = VisaPinVerificationValue
                    .builder()
                    .encryptedPinBlock(encryptedPinBLock)
                    .pinVerificationKeyIndex(ServiceConstants.PIN_VERIFICATION_KEY_INDEX)
                    .build();
            PinGenerationAttributes attributes = PinGenerationAttributes
                    .builder()
                    .visaPinVerificationValue(pinVerificationValue)
                    .build();
            GeneratePinDataRequest request = GeneratePinDataRequest
                    .builder()
                    .generationKeyIdentifier(pinValidationKeyAlias.keyArn())
                    .encryptionKeyIdentifier(issuerPekAlias.keyArn())
                    .primaryAccountNumber(pan)
                    .pinBlockFormat(ServiceConstants.ISO_0_PIN_BLOCK_FORMAT)
                    .generationAttributes(attributes)
                    .build();

            Logger.getGlobal().info(
                    "IssuerService:setPinData Attempting to set PIN thru AWS Cryptography Service via encrypted PIN Block - "
                            + encryptedPinBLock);
            GeneratePinDataResponse generatePinDataResponse = client.generatePinData(request);
            response.put("status", "ok");
            Logger.getGlobal().info(
                    "IssuerService:setPinData Set PIN Data successful for encrypted PIN Block " + encryptedPinBLock);
            getRepository().addEntry(pan, generatePinDataResponse.pinData().verificationValue());
        } catch (Exception exception) {
            response.put("error", exception.getMessage());
            exception.printStackTrace();
        }
        return response.toString();
    }

    @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API)
    @ResponseBody
    public String verifyPinData(@RequestParam String encryptedPin, @RequestParam String pan) {
        JSONObject response = new JSONObject();
        try {
            VerifyPinDataResponse verifyPinDataResponse = verifyPinData(encryptedPin, issuerPekAlias.keyArn(),
                    pinValidationKeyAlias.keyArn(), getRepository().getEntry(pan),
                    ServiceConstants.ISO_0_PIN_BLOCK_FORMAT, pan);
            if (verifyPinDataResponse != null) {
                response.put("status", "valid");
            } else {
                response.put("status", "fail");
            }
            return response.toString();
        } catch (Exception exception) {
            exception.printStackTrace();
            response.put("status", "fail");
        }
        return response.toString();
    }

    private VerifyPinDataResponse verifyPinData(String encryptedPinBlock, String encryptionKeyIdentifier,
            String verificationKeyIdentifer, String pinVerificationValue, String pinBlockFormat,
            String primaryAccountNumber) {

        VisaPinVerification visaPinVerification = VisaPinVerification
                                                    .builder()
                                                    .pinVerificationKeyIndex(ServiceConstants.PIN_VERIFICATION_KEY_INDEX)
                                                    .verificationValue(pinVerificationValue)
                                                    .build();
        PinVerificationAttributes pinVerificationAttributes = PinVerificationAttributes
                                                                .builder()
                                                                .visaPin(visaPinVerification)
                                                                .build();

        VerifyPinDataRequest verifyPinDataRequest = VerifyPinDataRequest
                                                    .builder().
                                                    encryptedPinBlock(encryptedPinBlock)
                                                    .verificationKeyIdentifier(verificationKeyIdentifer)
                                                    .encryptionKeyIdentifier(encryptionKeyIdentifier)
                                                    .primaryAccountNumber(primaryAccountNumber)
                                                    .pinBlockFormat(pinBlockFormat)
                                                    .verificationAttributes(pinVerificationAttributes)
                                                    .build();

        Logger.getGlobal().info(
                "IssuerService:verifyPinData Attempting to verify PIN data through AWS Cryptography Service for encrypted PIN block "
                        + encryptedPinBlock);
        VerifyPinDataResponse verifyPinDataResponse = client.verifyPinData(verifyPinDataRequest);
        Logger.getGlobal().info("IssuerService:verifyPinData Verification of encrypted PIN block " + encryptedPinBlock
                + " through AWS Cryptography Service is successful");
        return verifyPinDataResponse;
    }

    /*
     * Sample code to show how new pin genration can be done in the Payment Cryptography Service. This flow is currently not used in the samples.
    */
    /* private GeneratePinDataResponse generatePinData() {
        // finds or generates a Pin Generation Key (used for generating random PINs)
        if (null == pgkAlias.keyArn()) {
            System.out.println("No PGK found, creating a new one.");
            Key pgkKey = ControlPlaneUtils.createVisaPGK(ServiceConstants.PGK_ALGORITHM);
            pgkAlias = ControlPlaneUtils.upsertAlias(pgkAliasName, pgkKey.keyArn());
            System.out.println(String.format("PGK created: %s", pgkAlias.keyArn()));
        } else {
            System.out.println(String.format("PGK already exists: %s", pgkAlias.keyArn()));
        }

        // finds existing or generates a Pin Encryption Key (used for encryption pin
        // payloads)
        if (null == pekAlias.keyArn()) {
            System.out.println("No PEK found, creating a new one.");
            Key pekKey = ControlPlaneUtils.createPEK(ServiceConstants.PEK_ALGORITHM);
            pekAlias = ControlPlaneUtils.upsertAlias(pekAliasName, pekKey.keyArn());
            System.out.println(String.format("PEK created: %s", pekAlias.keyArn()));
        } else {
            System.out.println(String.format("PEK already exists: %s", pekAlias.keyArn()));
        }

        // Generate a BDK used as the base deriviation key typically for DUKPT
        if (null == bdkAlias.keyArn()) {
            System.out.println("No BDK found, creating a new one.");
            Key bdkKey = ControlPlaneUtils.createBDK(ServiceConstants.BDK_ALGORITHM);
            bdkAlias = ControlPlaneUtils.upsertAlias(bdkAliasName, bdkKey.keyArn());
            System.out.println(String.format("BDK created: %s", bdkAlias.keyArn()));
        } else {
            System.out.println(String.format("BDK already exists: %s", bdkAlias.keyArn()));
        }
        System.out.println("Creating a random pin and returns back the encrypted pin and visa/ABA PVV");
        GeneratePinDataResponse pinDataGenerationResponse = DataPlaneUtils.generateVisaPinBlock(
                pekAliasName,
                pgkAliasName,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                ServiceConstants.PAN,
                ServiceConstants.PIN_VERIFICATION_KEY_INDEX);
        System.out.println(String.format("PIN block: %s", pinDataGenerationResponse.encryptedPinBlock()));

        System.out.println("Translating encrypted PIN under PEK to encrypted under DUKPT");
        String pinBlockUnderBDK = DataPlaneUtils.translateVisaPinBlockPekToBdk(
                pekAliasName,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                pinDataGenerationResponse.encryptedPinBlock(),
                bdkAliasName,
                ServiceConstants.ISO_3_PIN_BLOCK_FORMAT,
                ServiceConstants.BDK_ALGORITHM,
                ServiceConstants.KSN,
                ServiceConstants.PAN);

        System.out.println(String.format("Translated PIN block: %s", pinBlockUnderBDK));
        return pinDataGenerationResponse;
    } */

    public Repository getRepository() {
        return repository;
    }

    public void setRepository(Repository repository) {
        this.repository = repository;
    }
}
