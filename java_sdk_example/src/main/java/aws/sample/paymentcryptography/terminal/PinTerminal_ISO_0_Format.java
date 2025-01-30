package aws.sample.paymentcryptography.terminal;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import aws.sample.paymentcryptography.ServiceConstants;

public class PinTerminal_ISO_0_Format extends AbstractTerminal {

    protected static String KEYS_KSN_DATA_FILE = "/test-data/sample-pek-ksn-data-iso-0-format.json";

    public static void main(String[] args) throws Exception {
        testISOFormat0Block();
    }

    public static void testISOFormat0Block() throws Exception {
        JSONObject pinData = loadData(System.getProperty("user.dir") + PINS_DATA_FILE);
        JSONArray pinDataList = pinData.getJSONArray("pins");

        JSONObject keyKsnData = loadData(System.getProperty("user.dir") + KEYS_KSN_DATA_FILE);
        JSONArray keyKsnDList = keyKsnData.getJSONArray("data");

        JSONObject panArqcData = loadData(System.getProperty("user.dir") + ARQC_DATA_FILE);
        JSONArray panArqcDList = panArqcData.getJSONArray("arqcData");

        for (int i = 0; i < pinDataList.length(); i++) {
            JSONObject panPinOBject = pinDataList.getJSONObject(i);

            try {
                Logger.getGlobal().log(Level.INFO,"---------testDUKPTPinValidation ---------");
                String pan = (panPinOBject).getString("pan");
                String pin = (panPinOBject).getString("pin");

                String encodedPin = encodeForISO0Format(pin, pan);

                String dukptVariantKey = keyKsnDList.getJSONObject(i).getString("pek");
                String ksn = keyKsnDList.getJSONObject(i).getString("ksn");
                String dukptEncryptedBlock = encryptPINWithDukpt(dukptVariantKey, encodedPin);

                String arqcKey = panArqcDList.getJSONObject(i).getString("udk");
                String arqcTransactionData = panArqcDList.getJSONObject(i).getString("transactionData");
                String arqcCryptogram = Utils.generateIso9797Alg3Mac(arqcKey, arqcTransactionData);
                
                Logger.getGlobal().log(Level.INFO, "PAN -> {0}, PIN {1}, key {2}, ksn {3}, ARQC {4}",  new Object[] {pan,pin,dukptVariantKey,ksn,arqcCryptogram});
                
                RestTemplate restTemplate = new RestTemplate();

                String verifyPinUrl = ServiceConstants.HOST
                        + ServiceConstants.PIN_PROCESSOR_SERVICE_ISO_0_FORMAT_PIN_VERIFY_API;

                // Making GET calls for simplicity. In produciton scenarios these would typically be POST calls with appropriate payload.        
                String finalVerifyPinlUrl = new StringBuilder(verifyPinUrl)
                        .append("?encryptedPin=")
                        .append(dukptEncryptedBlock)
                        .append("&transactionData=")
                        .append(arqcTransactionData)
                        .append("&arqcCryptogram=")
                        .append(arqcCryptogram)
                        .append("&pan=")
                        .append(pan)
                        .append("&ksn=")
                        .append(ksn)
                        .toString();

                ResponseEntity<String> verifyPinResponse = restTemplate.getForEntity(finalVerifyPinlUrl,
                        String.class);
                Logger.getGlobal().log(Level.INFO,"Response from PinTranslate service for (DUKPT encrypted) pin verify operation is {0} "
                        , verifyPinResponse.getBody());
                // Adding sleep so there's time between each request - making it easy to look at requsts on the console
                Thread.sleep(sleepTimeInMs);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static String encryptPINWithDukpt(String dukpt, String encodedPinBlock) throws Exception {
        byte[] maskedKey = xorBytes(Hex.decodeHex(dukpt), Hex.decodeHex(TerminalConstants.PIN_MASK));

        byte[] key = new byte[24];

        System.arraycopy(maskedKey, 0, key, 0, 16);
        System.arraycopy(maskedKey, 0, key, 16, 8);

        Cipher cipher = Cipher.getInstance(TerminalConstants.TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, TerminalConstants.ALGORITHM),
                new IvParameterSpec(new byte[8]));

        byte[] encVal = cipher.doFinal(Hex.decodeHex(encodedPinBlock));
        String encryptedValue = Hex.encodeHexString(encVal);
        return encryptedValue;
    }

    
}
