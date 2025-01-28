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
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataClient;
import software.amazon.awssdk.services.paymentcryptographydata.model.GeneratePinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.GeneratePinDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.PinGenerationAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyAuthRequestCryptogramRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyAuthRequestCryptogramResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyPinDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.VerifyPinDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.VisaPinVerificationValue;

@RestController
public class IssuerService extends AbstractIssuerService {

        protected PaymentCryptographyDataClient client = null;

        /*
         * File based repository where the pin verification values (PVV) are store
         * against the PAN.
         * The PVV is needed for PIN verification with the AWS Cryptography Service. In
         * real scenario,
         * the PVV would be stored in a database.
         */
        @Autowired
        private Repository repository;

        public IssuerService() throws InterruptedException, ExecutionException {
                client = DataPlaneUtils.getDataPlaneClient();
                issuerPekAlias = ControlPlaneUtils.getOrCreateAlias(ServiceConstants.ISSUER_PEK_ALIAS);
                pinValidationKeyAlias = ControlPlaneUtils.getOrCreateAlias(ServiceConstants.PIN_VALIDATION_KEY_ALIAS);
                arqcValidationKeyAlias = ControlPlaneUtils.getOrCreateAlias(
                                ServiceConstants.ARQC_Retail_9797_3_KEY_ALIAS,
                                null);
        }

        @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_SET_API)
        @ResponseBody
        public String setPinData(@RequestParam String encryptedPinBLock, @RequestParam String pan) {
                JSONObject response = new JSONObject();
                Logger.getGlobal().info(
                                "IssuerService:setPinData Attempting to set PIN thru AWS Cryptography Service via encrypted PIN Block - "
                                                + encryptedPinBLock);
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

                        GeneratePinDataResponse generatePinDataResponse = client.generatePinData(request);
                        response.put("status", "ok");
                        Logger.getGlobal().info(
                                        "IssuerService:setPinData Set PIN Data successful for encrypted PIN Block "
                                                        + encryptedPinBLock);
                        getRepository().addEntry(pan, generatePinDataResponse.pinData().verificationValue());
                } catch (Exception exception) {
                        response.put("error", exception.getMessage());
                        exception.printStackTrace();
                }
                return response.toString();
        }

        @GetMapping(ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API)
        @ResponseBody
        public String pinAuthorizationFlow(@RequestParam String encryptedPin, @RequestParam String pan,
                        @RequestParam String transactionData, @RequestParam String arqcCryptogram) {
                JSONObject response = new JSONObject();
                try {
                        Logger.getGlobal().info("Sync IssuerService:pinAuthorizationFlow PIN and ARQC, PIN Block - " + encryptedPin
                                        + " with PAN " + pan + " ARQC " + arqcCryptogram);

                        Logger.getGlobal().info("Step A - verifyARQCCryptogram start");
                        VerifyAuthRequestCryptogramResponse verifyAuthRequestCryptogramResponse = verifyARQCCryptogram(
                                        arqcCryptogram, transactionData, pan);
                        Logger.getGlobal().info("Step A - verifyARQCCryptogram complete");                                        
                        Logger.getGlobal().info("Step B - verifyPinData start");
                        VerifyPinDataResponse verifyPinDataResponse = verifyPinData(encryptedPin,
                                        issuerPekAlias.keyArn(),
                                        pinValidationKeyAlias.keyArn(), getRepository().getEntry(pan),
                                        ServiceConstants.ISO_0_PIN_BLOCK_FORMAT, pan);
                                        Logger.getGlobal().info("Step B - verifyPinData complete");
                        Logger.getGlobal().info("Step C - verifyBalance");
                        boolean verifyBalance = validateTransaction(transactionData);
                        Logger.getGlobal().info("Step C - verifyBalance complete");

                        if (verifyPinDataResponse != null && verifyAuthRequestCryptogramResponse != null
                                        && verifyBalance) {
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

        protected VerifyPinDataResponse verifyPinData(String encryptedPinBlock, String encryptionKeyIdentifier,
                        String verificationKeyIdentifer, String pinVerificationValue, String pinBlockFormat,
                        String primaryAccountNumber) {
                VerifyPinDataRequest verifyPinDataRequest = getVerifyPinDataRequest(encryptedPinBlock,
                                encryptionKeyIdentifier,
                                verificationKeyIdentifer, pinVerificationValue, pinBlockFormat, primaryAccountNumber);
                Logger.getGlobal().info(
                                "IssuerService:verifyPinData Attempting to verify PIN data through AWS Cryptography Service for encrypted PIN block "
                                                + encryptedPinBlock);
                VerifyPinDataResponse verifyPinDataResponse = client.verifyPinData(verifyPinDataRequest);
                Logger.getGlobal()
                                .info("IssuerService:verifyPinData Verification of encrypted PIN block "
                                                + encryptedPinBlock
                                                + " through AWS Cryptography Service is successful");
                return verifyPinDataResponse;
        }

        protected VerifyAuthRequestCryptogramResponse verifyARQCCryptogram(String arqcCryptogram,
                        String transactionData, String pan) {
                Logger.getGlobal().info("IssuerService:verifyARQCCryptogram " + arqcCryptogram + " pan " + pan);
                VerifyAuthRequestCryptogramRequest request = getVerifyARQCCryptogramRequest(arqcCryptogram,
                                transactionData,
                                pan);
                return client.verifyAuthRequestCryptogram(request);
        }

        public Repository getRepository() {
                return repository;
        }

        public void setRepository(Repository repository) {
                this.repository = repository;
        }
}
