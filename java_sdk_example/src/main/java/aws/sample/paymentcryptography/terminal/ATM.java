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

public class ATM extends AbstractTerminal {

    private static final String PINS_DATA_FILE = "/test-data/sample-pin-pan.json";

    public static void main(String[] args) throws Exception {
        testPinSet();
    }

    public static void testPinSet() throws Exception {
        JSONObject data = loadPinAndPanData();
        JSONArray dataList = data.getJSONArray("pins");

        dataList.forEach(panPinOBject -> {
            try {
                System.out.println("---------testPinSet ---------");
                String pan = ((JSONObject) panPinOBject).getString("pan");
                String pin = ((JSONObject) panPinOBject).getString("pin");
                System.out.println("PAN -> " + pan + ", PIN -> " + pin);
                String encodedPin = encodeForISO0Format(pin, pan);
                System.out.println("ISO_0_Format Encoded Pin block is " + encodedPin);
                String pekEncryptedBlock = encryptPINWithPEK(TerminalConstants.PEK, encodedPin);
                System.out.println(("PEK encrypted block - " + pekEncryptedBlock));
                Thread.sleep(2000);
                RestTemplate restTemplate = new RestTemplate();

                String setPinUrl = ServiceConstants.HOST
                        + ServiceConstants.ISSUER_SERVICE_PIN_SET_API;

                String finaSetPinlUrl = new StringBuilder(setPinUrl)
                        .append("?encryptedPinBLock=")
                        .append(pekEncryptedBlock)
                        .append("&pan=")
                        .append(pan).toString();

                ResponseEntity<String> setPinResponse = restTemplate.getForEntity(finaSetPinlUrl, String.class);
                System.out.println("Response from issuer service for (PEK encrypted) pin set operation is "
                        + setPinResponse.getBody());
                Thread.sleep(3500);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    public static String encryptPINWithPEK(String pek, String encodedPinBlock) throws Exception {
        Cipher chiper = Cipher.getInstance(TerminalConstants.TRANSFORMATION);
        chiper.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Hex.decodeHex(pek), TerminalConstants.ALGORITHM),
                new IvParameterSpec(new byte[8]));

        byte[] encVal = chiper.doFinal(Hex.decodeHex(encodedPinBlock));
        String encryptedValue = Hex.encodeHexString(encVal);
        return encryptedValue;
    }

    private static JSONObject loadPinAndPanData() throws IOException {
        return loadData(System.getProperty("user.dir") + PINS_DATA_FILE);
    }

}
