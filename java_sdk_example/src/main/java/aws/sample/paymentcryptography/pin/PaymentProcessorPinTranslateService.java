package aws.sample.paymentcryptography.pin;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.amazonaws.services.paymentcryptography.model.Alias;
import com.amazonaws.services.paymentcryptography.model.Key;
import com.amazonaws.services.paymentcryptographydata.model.TranslatePinDataResult;
import com.amazonaws.util.StringUtils;

import aws.sample.paymentcryptography.ControlPlaneUtils;
import aws.sample.paymentcryptography.DataPlaneUtils;
import aws.sample.paymentcryptography.ServiceConstants;

@RestController
public class PaymentProcessorPinTranslateService {

   /*  @GetMapping(ServiceConstants.PIN_PROCESSOR_SERVICE_PIN_SET_API)
    @ResponseBody
    public String setPinData(@RequestParam String encryptedPinBLock, @RequestParam String pan) {

        String acquirerWorkingKeyArn = getAcquirerWorkingKeyArn();
        TranslatePinDataResult translatePinDataResult = DataPlaneUtils.translateVisaPinBlockBdkToPek(
                ServiceConstants.BDK_ALIAS,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                encryptedPinBLock,
                acquirerWorkingKeyArn,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                ServiceConstants.BDK_ALGORITHM,
                ServiceConstants.KSN,
                pan);

        RestTemplate restTemplate = new RestTemplate();

        String setPinUrl = ServiceConstants.HOST
                + ServiceConstants.ISSUER_SERVICE_PIN_SET_API;

        String finaSetPinlUrl = new StringBuilder(setPinUrl)
                .append("?encryptedPinBLock=")
                .append(translatePinDataResult.getPinBlock()) // setting BDK -> PEK translated PIN data
                .append("&pan=")
                .append(pan).toString();

        ResponseEntity<String> setPinResponse = restTemplate.getForEntity(finaSetPinlUrl, String.class);
        System.out.println("PaymentProcessorPinTranslateService: Issuer service response for PEK Pin set is "
                + setPinResponse.getBody());
        return setPinResponse.getBody();
    } */

    @GetMapping(ServiceConstants.PIN_PROCESSOR_SERVICE_PIN_VERIFY_API)
    @ResponseBody
    public String verifyPinData(@RequestParam String encryptedPin, @RequestParam String pan, @RequestParam String ksn) {

        System.out.println("Translated PIN block - " + encryptedPin);
        String acquirerWorkingKeyArn = getAcquirerWorkingKeyArn();
        TranslatePinDataResult translatePinDataResult = DataPlaneUtils.translateVisaPinBlockBdkToPek(
                ServiceConstants.BDK_ALIAS,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                encryptedPin,
                acquirerWorkingKeyArn,
                ServiceConstants.ISO_0_PIN_BLOCK_FORMAT,
                ServiceConstants.BDK_ALGORITHM,
                ksn,
                pan);

        RestTemplate restTemplate = new RestTemplate();
        String verifyPinUrl = ServiceConstants.HOST
                    + ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API;
        String finalVerifyPinlUrl = new StringBuilder(verifyPinUrl)
                .append("?encryptedPin=")
                .append(translatePinDataResult.getPinBlock())
                .append("&pan=")
                .append(pan)
                .toString();

        ResponseEntity<String> verifyPinResponse = restTemplate.getForEntity(finalVerifyPinlUrl, String.class);
        System.out.println("Issuer service response for PEK Pin verify is " + verifyPinResponse.getBody());
        return verifyPinResponse.getBody();
    }

    /*
     * Creating/Retrieving the Acquirer Working Key (AWK) alias. The underlying key
     * is the same as the DEMO_PIN_PEK_ALIAS.
     * In real scenario, the payment gateway and acquirer would have the same PEK
     * through a key exchange process.
     */
    private static String getAcquirerWorkingKeyArn() {
        Alias acquirerWorkingKeyAlias = ControlPlaneUtils.getOrCreateAlias(ServiceConstants.PIN_TRANSLATION_KEY_ALIAS);
        if (StringUtils.isNullOrEmpty(acquirerWorkingKeyAlias.getKeyArn())) {
            System.out.println("No AWS PEK found, creating a new one.");
            Key acquirerWorkingKey = ControlPlaneUtils.createPEK(ServiceConstants.PEK_ALGORITHM);
            acquirerWorkingKeyAlias = ControlPlaneUtils.upsertAlias(acquirerWorkingKeyAlias.getAliasName(),
                    acquirerWorkingKey.getKeyArn());
            System.out.println(String.format("PEK created: %s", acquirerWorkingKeyAlias.getKeyArn()));
            return acquirerWorkingKeyAlias.getKeyArn();
        }
        return acquirerWorkingKeyAlias.getKeyArn();
    }

}
