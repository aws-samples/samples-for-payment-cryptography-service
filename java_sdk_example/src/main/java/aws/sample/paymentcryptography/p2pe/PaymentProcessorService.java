package aws.sample.paymentcryptography.p2pe;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.RandomUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import aws.sample.paymentcryptography.DataPlaneUtils;
import aws.sample.paymentcryptography.ServiceConstants;
import aws.sample.paymentcryptography.mac.MACService;
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataClient;
import software.amazon.awssdk.services.paymentcryptographydata.model.DecryptDataRequest;
import software.amazon.awssdk.services.paymentcryptographydata.model.DecryptDataResponse;
import software.amazon.awssdk.services.paymentcryptographydata.model.DukptEncryptionAttributes;
import software.amazon.awssdk.services.paymentcryptographydata.model.EncryptionDecryptionAttributes;

@RestController
public class PaymentProcessorService {

    @Autowired
    private MACService macService;

    // GET API for simplicity. In production scenarios, this would typically be a POST API
    @GetMapping(ServiceConstants.PAYMENT_PROCESSOR_SERVICE_AUTHORIZE_PAYMENT_API)
    @ResponseBody
    public String authorizePayment(@RequestParam String encryptedData, @RequestParam String ksn) {
        try {
            PaymentCryptographyDataClient dataPlaneClient = DataPlaneUtils.getDataPlaneClient();

            DukptEncryptionAttributes dukptEncryptionAttributes = DukptEncryptionAttributes
                    .builder()
                    .keySerialNumber(ksn)
                    .mode(ServiceConstants.MODE)
                    .build();

            EncryptionDecryptionAttributes decryptionAttributes = EncryptionDecryptionAttributes
                    .builder()
                    .dukpt(dukptEncryptionAttributes)
                    .build();

            DecryptDataRequest decryptDataRequest = DecryptDataRequest
                    .builder()
                    .cipherText(encryptedData)
                    .keyIdentifier(ServiceConstants.BDK_ALIAS_TDES_2KEY)
                    .decryptionAttributes(decryptionAttributes)
                    .build();

            Logger.getGlobal()
                    .log(Level.INFO,"PaymentProcessorService:authorizePayment Attempting to decrypt data {0}" ,encryptedData);
            DecryptDataResponse decryptDataResponse = dataPlaneClient.decryptData(decryptDataRequest);

            int padCount = getPADCount(decryptDataResponse.plainText());
            String decryptedText = decryptDataResponse.plainText().substring(0,
                    decryptDataResponse.plainText().length() - padCount * 2);
            String textWithPaddingRemoved = new String(Hex.decodeHex(decryptedText));
            JSONObject responseJsonObject = new JSONObject()
                    .put("response", textWithPaddingRemoved)
                    .put("authCode", getApprovalCode())
                    .put("response_code", getResponseCode());

            String macData = getMACService().generateMac(responseJsonObject.toString());

            JSONObject returnJsonObject = new JSONObject()
                    .put("mac", macData)
                    .put("response", responseJsonObject.toString());
            Logger.getGlobal().log(Level.INFO,
                    "PaymentProcessorService:authorizePayment Decryption completed -  {0}"
                            ,responseJsonObject.toString());
            return returnJsonObject.toString();
        } catch (Exception exception) {
            Logger.getGlobal().log(Level.INFO,
                    "PaymentProcessorService:authorizePayment Error occurred when decrypting");
            JSONObject returnJsonObject = new JSONObject()
                    .put("response", exception.getMessage())
                    .put("mac", "");
            exception.printStackTrace();
            return returnJsonObject.toString();
        }
    }

    public MACService getMACService() {
        return macService;
    }

    public void setmacService(MACService macService) {
        this.macService = macService;
    }

    private int getPADCount(String data) throws InvalidCipherTextException, DecoderException {
        PKCS7Padding padder = new PKCS7Padding();
        int padCount = padder.padCount(Hex.decodeHex(data));
        return padCount;
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
