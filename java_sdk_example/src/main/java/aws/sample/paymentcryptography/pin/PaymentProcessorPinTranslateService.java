package aws.sample.paymentcryptography.pin;

import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;
import aws.sample.paymentcryptography.ServiceConstants;
import software.amazon.awssdk.services.paymentcryptography.model.Alias;
import software.amazon.awssdk.services.paymentcryptography.model.Key;
import software.amazon.awssdk.services.paymentcryptographydata.model.TranslatePinDataResponse;
import software.amazon.awssdk.utils.StringUtils;

@RestController
public class PaymentProcessorPinTranslateService {

    @GetMapping(ServiceConstants.PIN_PROCESSOR_SERVICE_ISO_0_FORMAT_PIN_VERIFY_API)
    @ResponseBody
    public String verifyPinData_ISO_0_Format(@RequestParam String encryptedPin, @RequestParam String pan, @RequestParam String ksn,  @RequestParam String transactionData, @RequestParam String arqcCryptogram) throws InterruptedException, ExecutionException {

        Logger.getGlobal().info("PaymentProcessorPinTranslateService:verifyPinData_ISO_0_Format Attempting to translate TDES BDK encrypted PIN block " + encryptedPin + " to PEK encrypted PIN Block thru AWS Cryptography Service");
        String acquirerWorkingKeyArn = getAcquirerWorkingKeyArn();
        TranslatePinDataResponse translatePinDataResponse = DataPlaneUtils.translateVisaPinBlockBdkToPek(
                ServiceConstants.BDK_ALIAS_TDES_2KEY,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                encryptedPin,
                acquirerWorkingKeyArn,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                ServiceConstants.BDK_ALGORITHM_TDES_2KEY,
                ksn,
                pan);

        Logger.getGlobal().info("PaymentProcessorPinTranslateService:verifyPinData_ISO_0_Format BDK PIN " + encryptedPin + " to PEK encrypted PIN Block " + translatePinDataResponse.pinBlock() + " translation is successful");
        RestTemplate restTemplate = new RestTemplate();
        String verifyPinUrl = ServiceConstants.HOST
                    + ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API_ASYNC;
        String finalVerifyPinlUrl = new StringBuilder(verifyPinUrl)
                .append("?encryptedPin=")
                .append(translatePinDataResponse.pinBlock())
                .append("&pan=")
                .append(pan)
                .append("&transactionData=")
                .append(transactionData)
                .append("&arqcCryptogram=")
                .append(arqcCryptogram)
                .toString();

        ResponseEntity<String> verifyPinResponse = restTemplate.getForEntity(finalVerifyPinlUrl, String.class);
        Logger.getGlobal().info("Issuer service response for PEK Pin verify is " + verifyPinResponse.getBody());
        return verifyPinResponse.getBody();
    }

    @GetMapping(ServiceConstants.PIN_PROCESSOR_SERVICE_ISO_4_FORMAT_PIN_VERIFY_API)
    @ResponseBody
    public String verifyPinData_ISO_4_Format(@RequestParam String encryptedPin, @RequestParam String pan, @RequestParam String ksn,  @RequestParam String transactionData, @RequestParam String arqcCryptogram) throws InterruptedException, ExecutionException {

        Logger.getGlobal().info("PaymentProcessorPinTranslateService:verifyPinData_ISO_4_Format Attempting to translate BDK encrypted PIN block " + encryptedPin + " to PEK encrypted PIN Block thru AWS Cryptography Service");
        String acquirerWorkingKeyArn = getAcquirerWorkingKeyArn();
        TranslatePinDataResponse translatePinDataResponse = DataPlaneUtils.translateVisaPinBlockBdkToPek(
                ServiceConstants.BDK_ALIAS_AES_128,
                ServiceConstants.ISO_4_PIN_BLOCK_FORMAT,
                encryptedPin,
                acquirerWorkingKeyArn,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                ServiceConstants.BDK_ALGORITHM_AES_128,
                ksn,
                pan);

        Logger.getGlobal().info("PaymentProcessorPinTranslateService:verifyPinData_ISO_4_Format BDK PIN " + encryptedPin + " to PEK encrypted PIN Block " + translatePinDataResponse.pinBlock() + " translation is successful");
        RestTemplate restTemplate = new RestTemplate();
        String verifyPinUrl = ServiceConstants.HOST
                    + ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API_ASYNC;
                    String finalVerifyPinlUrl = new StringBuilder(verifyPinUrl)
                    .append("?encryptedPin=")
                    .append(translatePinDataResponse.pinBlock())
                    .append("&pan=")
                    .append(pan)
                    .append("&transactionData=")
                    .append(transactionData)
                    .append("&arqcCryptogram=")
                    .append(arqcCryptogram)
                    .toString();

        ResponseEntity<String> verifyPinResponse = restTemplate.getForEntity(finalVerifyPinlUrl, String.class);
        Logger.getGlobal().info("Issuer service response for PEK Pin verify is " + verifyPinResponse.getBody());
        return verifyPinResponse.getBody();
    }

    /*
     * Creating/Retrieving the Acquirer Working Key (AWK) alias. The underlying key
     * is the same as the DEMO_PIN_PEK_ALIAS.
     * In real scenario, the payment gateway and acquirer would have the same PEK
     * through a key exchange process.
     */
    private static String getAcquirerWorkingKeyArn() throws InterruptedException, ExecutionException {
        Alias acquirerWorkingKeyAlias = ControlPlaneUtils.getOrCreateAlias(ServiceConstants.PIN_TRANSLATION_KEY_ALIAS);
        if (StringUtils.isBlank(acquirerWorkingKeyAlias.keyArn())) {
            Logger.getGlobal().info("No AWS PEK found, creating a new one.");
            Key acquirerWorkingKey = ControlPlaneUtils.createPEK(ServiceConstants.PEK_ALGORITHM);
            acquirerWorkingKeyAlias = ControlPlaneUtils.upsertAlias(acquirerWorkingKeyAlias.aliasName(),
                    acquirerWorkingKey.keyArn());
            Logger.getGlobal().info(String.format("PEK created: %s", acquirerWorkingKeyAlias.keyArn()));
            return acquirerWorkingKeyAlias.keyArn();
        }
        return acquirerWorkingKeyAlias.keyArn();
    }

}
