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
import aws.sample.paymentcryptography.ServiceConstants;
import aws.sample.paymentcryptography.hmac.HMACService;

@RestController
public class PaymentProcessorService {

    @Autowired
    private HMACService hmacService;

    @GetMapping(ServiceConstants.PAYMENT_PROCESSOR_SERVICE_AUTHORIZE_PAYMENT_API)
    @ResponseBody
    public String authorizePayment(@RequestParam String encryptedData, @RequestParam String ksn)
            throws DecoderException {
        AWSPaymentCryptographyData dataPlaneClient = DataPlaneUtils.getDataPlaneClient();

        DukptEncryptionAttributes dukptEncryptionAttributes = new DukptEncryptionAttributes()
                .withKeySerialNumber(ksn)
                .withMode(ServiceConstants.MODE);

        EncryptionDecryptionAttributes decryptionAttributes = new EncryptionDecryptionAttributes();
        decryptionAttributes.setDukpt(dukptEncryptionAttributes);

        DecryptDataRequest decryptDataRequest = new DecryptDataRequest();
        decryptDataRequest.setCipherText(encryptedData);
        decryptDataRequest.setKeyIdentifier(ServiceConstants.BDK_ARN);
        decryptDataRequest.setDecryptionAttributes(decryptionAttributes);

        DecryptDataResult decryptDataResult = dataPlaneClient.decryptData(decryptDataRequest);
        String macData = getHmacService().generateMac();
        JSONObject respJsonObject = new JSONObject()
                .put("mac", macData)
                .put("decryptedData", new String(Hex.decodeHex(decryptDataResult.getPlainText())));
        return respJsonObject.toString();
    }

    public HMACService getHmacService() {
        return hmacService;
    }

    public void setHmacService(HMACService hmacService) {
        this.hmacService = hmacService;
    }
}
