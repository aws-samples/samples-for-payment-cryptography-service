package aws.sample.paymentcryptography.terminal;

import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import aws.sample.paymentcryptography.ServiceConstants;

public class PinTerminal extends AbstractTerminal {

    private static final String KEYS_KSN_DATA_FILE = "/test-data/sample-pek-ksn-data.json";
    private static final String PINS_DATA_FILE = "/test-data/sample-pin-pan.json";

    public static void main(String[] args) throws Exception {
        testDukptPinValidation();
    }

    public static void testDukptPinValidation() throws Exception {
        JSONObject pinData = loadPinAndPanData();
        JSONArray pinDataList = pinData.getJSONArray("pins");

        JSONObject keyKsnData = loadPEKAndKSNData();
        JSONArray keyKsnDList = keyKsnData.getJSONArray("data");

        for (int i = 0; i < pinDataList.length(); i++) {
            JSONObject panPinOBject = pinDataList.getJSONObject(i);

            try {
                System.out.println("---------testDUKPTPinValidation ---------");
                String pan = (panPinOBject).getString("pan");
                String pin = (panPinOBject).getString("pin");

                String encodedPin = encodeForISO0Format(pin, pan);

                String dukptVariantKey = keyKsnDList.getJSONObject(i).getString("pek");
                String ksn = keyKsnDList.getJSONObject(i).getString("ksn");
                String dukptEncryptedBlock = encryptPINWithDukpt(dukptVariantKey, encodedPin);

                System.out.println(
                        "PAN -> " + pan + ", PIN -> " + pin + ", key -> " + dukptVariantKey + ", ksn -> " + ksn);
                System.out.println("EncodedPin block is " + encodedPin);
                System.out.println(("DUKPT encrypted block - " + dukptEncryptedBlock));

                RestTemplate restTemplate = new RestTemplate();

                String verifyPinUrl = ServiceConstants.HOST
                        + ServiceConstants.PIN_PROCESSOR_SERVICE_PIN_VERIFY_API;

                String finalVerifyPinlUrl = new StringBuilder(verifyPinUrl)
                        .append("?encryptedPin=")
                        .append(dukptEncryptedBlock)
                        .append("&pan=")
                        .append(pan)
                        .append("&ksn=")
                        .append(ksn)
                        .toString();

                ResponseEntity<String> verifyPinResponse = restTemplate.getForEntity(finalVerifyPinlUrl,
                        String.class);
                System.out.println("Response from PinTranslate service for (DUKPT encrypted) pin set operation is "
                        + verifyPinResponse.getBody());

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

        Cipher chiper = Cipher.getInstance(TerminalConstants.TRANSFORMATION);
        chiper.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, TerminalConstants.ALGORITHM),
                new IvParameterSpec(new byte[8]));

        byte[] encVal = chiper.doFinal(Hex.decodeHex(encodedPinBlock));
        String encryptedValue = Hex.encodeHexString(encVal);
        return encryptedValue;
    }

    private static JSONObject loadPinAndPanData() throws IOException {
        return loadData(System.getProperty("user.dir") + PINS_DATA_FILE);
    }

    private static JSONObject loadPEKAndKSNData() throws IOException {
        return loadData(System.getProperty("user.dir") + KEYS_KSN_DATA_FILE);
    }
}
