package aws.sample.paymentcryptography.p2pe;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import aws.sample.paymentcryptography.hmac.TerminalHMACService;

/* 
 * Sample class to simulate merchant's payment terminal. This data defined in the DATA_FILE contains DUKTPT keys that are 
 * pre generated from BDK and KSN.
 * This class sends the payment authorization request (similar to what termial does) to the payment service and processes
 * the HMAC response.
 */
public class PaymentTerminal {
    private static final String ALGORITHM = "DESede";
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS5Padding";
    private static final String DATA_FILE = "/java_sdk_example/src/main/java/aws/sample/paymentcryptography/p2pe/key-ksn-data.json";
    public static final String HMAC_DATA_PLAIN_TEXT = "4123412341234123";

    private static final String TRANSFORMATION = ALGORITHM + "/" + MODE + "/" + PADDING;

    public static void main(String[] args) throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        String paymentAuthorizationUrl = "http://localhost:8080/authorizePayment/";

        System.out.println("curr dir is " + System.getProperty("user.dir"));
        JSONObject data = getData(System.getProperty("user.dir") + DATA_FILE);
        JSONArray dataList = data.getJSONArray("data");

        dataList.forEach(dataObject -> {
            try {
                String encryptedData = encryptData(
                        ((JSONObject) dataObject).get("dataKey").toString(),
                        ((JSONObject) dataObject).get("track2Data").toString(),
                        ((JSONObject) dataObject).get("ksn").toString());
                StringBuilder builder = new StringBuilder()
                        .append("?encryptedData=")
                        .append(encryptedData)
                        .append("&")
                        .append("ksn=")
                        .append(((JSONObject) dataObject).get("ksn").toString());
                String finalUrl = new StringBuilder(paymentAuthorizationUrl).append(builder).toString();
                ResponseEntity<String> response = restTemplate.getForEntity(finalUrl, String.class);
                System.out.println("response is " + response.getBody());

                JSONObject responseObject = new JSONObject(response.getBody());
                System.out.println("HMAC Validated = " + validateHMAC(responseObject.getString("mac").toLowerCase()));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private static boolean validateHMAC(String dataFromPaymentService) throws Exception {
        String hmacOnTerminal = TerminalHMACService.getMac(HMAC_DATA_PLAIN_TEXT);
        return hmacOnTerminal.trim().toLowerCase().startsWith(dataFromPaymentService);
    }

    private static JSONObject getData(String filePath) throws IOException {
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();

        String paymentData = new String(data, "UTF-8");
        JSONObject json = new JSONObject(paymentData);
        return json;
    }

    public static String encryptData(String key, String track2Data, String ksn) throws Exception {
        byte[] keyByteArray = Hex.decodeHex(key);
        byte[] key24byte = new byte[24];

        System.arraycopy(keyByteArray, 0, key24byte, 0, 16);
        System.arraycopy(keyByteArray, 0, key24byte, 16, 8);

        Cipher chiper = Cipher.getInstance(TRANSFORMATION);
        chiper.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key24byte, ALGORITHM), new IvParameterSpec(new byte[8]));

        String hexEncocedData = Hex.encodeHexString(track2Data.getBytes("UTF-8"));
        byte[] encVal = chiper.doFinal(Hex.decodeHex(hexEncocedData));
        String encryptedValue = Hex.encodeHexString(encVal);
        return encryptedValue;
    }

}
