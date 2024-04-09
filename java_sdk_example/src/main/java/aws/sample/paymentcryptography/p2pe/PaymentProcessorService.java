package aws.sample.paymentcryptography.p2pe;

import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
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
import aws.sample.paymentcryptography.ServiceConstants;
import aws.sample.paymentcryptography.hmac.HMACService;

@RestController
public class PaymentProcessorService {

    @Autowired
    private HMACService hmacService;

    @GetMapping(ServiceConstants.PAYMENT_PROCESSOR_SERVICE_AUTHORIZE_PAYMENT_API)
    @ResponseBody
    public String authorizePayment(@RequestParam String encryptedData, @RequestParam String ksn) {
        try {
            AWSPaymentCryptographyData dataPlaneClient = DataPlaneUtils.getDataPlaneClient();

            DukptEncryptionAttributes dukptEncryptionAttributes = new DukptEncryptionAttributes()
                    .withKeySerialNumber(ksn)
                    .withMode(ServiceConstants.MODE);

            EncryptionDecryptionAttributes decryptionAttributes = new EncryptionDecryptionAttributes();
            decryptionAttributes.setDukpt(dukptEncryptionAttributes);

            DecryptDataRequest decryptDataRequest = new DecryptDataRequest();
            decryptDataRequest.setCipherText(encryptedData);
            decryptDataRequest.setKeyIdentifier(ServiceConstants.BDK_ALIAS_TDES_2KEY);
            decryptDataRequest.setDecryptionAttributes(decryptionAttributes);

            Logger.getGlobal()
                    .info("PaymentProcessorService:authorizePayment Attempting to decrypt data " + encryptedData
                            + " by AWS Cryptography Service");
            DecryptDataResult decryptDataResult = dataPlaneClient.decryptData(decryptDataRequest);

            PKCS7Padding padder = new PKCS7Padding();
            int padCount = padder.padCount(Hex.decodeHex(decryptDataResult.getPlainText()));
            String decryptedText = decryptDataResult.getPlainText().substring(0,
                    decryptDataResult.getPlainText().length() - padCount * 2);
            String textWithPaddingRemoved = new String(Hex.decodeHex(decryptedText));
            JSONObject responseJsonObject = new JSONObject()
                    .put("response", textWithPaddingRemoved)
                    .put("authCode", getApprovalCode())
                    .put("response_code", getResponseCode());

            String macData = getHmacService().generateMac(responseJsonObject.toString());

            JSONObject returnJsonObject = new JSONObject()
                    .put("mac", macData)
                    .put("response", responseJsonObject.toString());
            Logger.getGlobal().info(
                    "PaymentProcessorService:authorizePayment Finished decrypting from AWS Cryptography Service. Returning to caller - "
                            + responseJsonObject.toString());
            return returnJsonObject.toString();
        } catch (Exception exception) {
            Logger.getGlobal().info(
                    "PaymentProcessorService:authorizePayment Error occurred when decrypting from AWS Cryptography Service.");
            JSONObject returnJsonObject = new JSONObject()
                    .put("response", exception.getMessage())
                    .put("mac", "");
            exception.printStackTrace();
            return returnJsonObject.toString();
        }
    }

    public HMACService getHmacService() {
        return hmacService;
    }

    public void setHmacService(HMACService hmacService) {
        this.hmacService = hmacService;
    }

    /* 
     * Returns a random 3-byte hex string for the approval code.
     */
    private String getApprovalCode() {
        byte[] approvalCode = RandomUtils.nextBytes(3);

        String hexApprovalCode = "";

        // Iterating through each byte in the array
        for (byte i : approvalCode) {
            hexApprovalCode += String.format("%02X", i);
        }
        return hexApprovalCode;
    }

    /* 
     * Returns a random 2-byte hex string for the response code.
     */
    private String getResponseCode() {
        return RandomUtils.nextInt(0, 9) + "" + RandomUtils.nextInt(0, 9);
    }
}
