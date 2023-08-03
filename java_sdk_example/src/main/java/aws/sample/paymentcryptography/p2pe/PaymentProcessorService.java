package aws.sample.paymentcryptography.p2pe;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.amazonaws.services.paymentcryptographydata.AWSPaymentCryptographyData;
import com.amazonaws.services.paymentcryptographydata.model.DecryptDataRequest;
import com.amazonaws.services.paymentcryptographydata.model.DecryptDataResult;
import com.amazonaws.services.paymentcryptographydata.model.DukptEncryptionAttributes;
import com.amazonaws.services.paymentcryptographydata.model.EncryptionDecryptionAttributes;

import aws.sample.paymentcryptography.DataPlaneUtils;
import aws.sample.paymentcryptography.hmac.HMACService;

//@SpringBootApplication
@RestController
public class PaymentProcessorService {

    private static final String TEST_DATA = "2e59a0c2c2d8c4930117cb0b02466d719517dae177888646ddcad82dc94b402e";
    private static final String KEY_ARN = "arn:aws:payment-cryptography:us-east-1:886958290065:key/xe5wa7q2xcke6g7j";

    @Autowired
    private HMACService hmacService;

    public static void main(String[] args) {
        DecryptDataResult decryptedDataResult = decryptData(KEY_ARN, TEST_DATA);
        try {
            System.out.println("Decrypted data result - " + decryptedDataResult.getPlainText() + " -- decoded text:  "
                    + new String(Hex.decodeHex(decryptedDataResult.getPlainText())));
        } catch (DecoderException e) {
            e.printStackTrace();
        }
    }

    /*
     * public static void main(String[] args) {
     * SpringApplication.run(PaymentProcessorService.class, args);kj
     * }
     * 
     * @Bean
     * public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
     * return args -> {
     * 
     * System.out.println("Let's inspect the beans provided by Spring Boot:");
     * 
     * String[] beanNames = ctx.getBeanDefinitionNames();
     * Arrays.sort(beanNames);
     * for (String beanName : beanNames) {
     * System.out.println(beanName);
     * }
     * 
     * };
     * }
     */

    @GetMapping("/authorizePayment/")
    @ResponseBody
    public String authorizePayment(@RequestParam String encryptedData, @RequestParam String ksn)
            throws DecoderException {
        AWSPaymentCryptographyData dataPlaneClient = DataPlaneUtils.getDataPlaneClient();

        DukptEncryptionAttributes dukptEncryptionAttributes = new DukptEncryptionAttributes()
                // .withKeySerialNumber("629949012C0000000001")
                .withKeySerialNumber(ksn)
                .withMode("CBC");

        EncryptionDecryptionAttributes decryptionAttributes = new EncryptionDecryptionAttributes();
        decryptionAttributes.setDukpt(dukptEncryptionAttributes);

        DecryptDataRequest decryptDataRequest = new DecryptDataRequest();
        decryptDataRequest.setCipherText(encryptedData);
        decryptDataRequest.setKeyIdentifier(KEY_ARN);
        decryptDataRequest.setDecryptionAttributes(decryptionAttributes);

        DecryptDataResult decryptDataResult = dataPlaneClient.decryptData(decryptDataRequest);
        String macData = getHmacService().generateMac();
        JSONObject respJsonObject = new JSONObject()
                .put("mac", macData)
                .put("decryptedData", new String(Hex.decodeHex(decryptDataResult.getPlainText())));
        return respJsonObject.toString();
        // return macData + " --- " + new
        // String(Hex.decodeHex(decryptDataResult.getPlainText()));
    }

    public static DecryptDataResult decryptData(String keyArn, String encryptedData) {
        AWSPaymentCryptographyData dataPlaneClient = DataPlaneUtils.getDataPlaneClient();

        DukptEncryptionAttributes dukptEncryptionAttributes = new DukptEncryptionAttributes()
                // .withKeySerialNumber("629949012C0000000001")
                .withKeySerialNumber("FFFF9876543210E00010")
                .withMode("CBC");

        EncryptionDecryptionAttributes decryptionAttributes = new EncryptionDecryptionAttributes();
        decryptionAttributes.setDukpt(dukptEncryptionAttributes);

        DecryptDataRequest decryptDataRequest = new DecryptDataRequest();
        decryptDataRequest.setCipherText(encryptedData);
        decryptDataRequest.setKeyIdentifier(keyArn);
        decryptDataRequest.setDecryptionAttributes(decryptionAttributes);

        DecryptDataResult decryptDataResult = dataPlaneClient.decryptData(decryptDataRequest);
        return decryptDataResult;

    }

    public HMACService getHmacService() {
        return hmacService;
    }

    public void setHmacService(HMACService hmacService) {
        this.hmacService = hmacService;
    }
}
