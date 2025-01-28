package aws.sample.paymentcryptography.terminal;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import aws.sample.paymentcryptography.ServiceConstants;

public class PinTerminal_ISO_4_Format extends AbstractTerminal {

    private static final String KEYS_KSN_DATA_FILE = "/test-data/sample-pek-ksn-data-iso-4-format.json";
    private static final String PINS_DATA_FILE = "/test-data/sample-pin-pan.json";

    public static void main(String[] args) throws Exception {
        testISOFormat4Block();
    }

    public static String aesEncryptPINWithDukpt(String dukpt, String encodedPinBlock) throws Exception {
        //byte[] maskedKey = xorBytes(Hex.decodeHex(dukpt), Hex.decodeHex(TerminalConstants.PIN_MASK));

        byte[] key = Hex.decodeHex(dukpt);
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

        byte[] encVal = cipher.doFinal(Hex.decodeHex(encodedPinBlock));
        String encryptedValue = Hex.encodeHexString(encVal);
        return encryptedValue;
    }

    /*
        Reference - https://listings.pcisecuritystandards.org/documents/Implementing_ISO_Format_4_PIN_Blocks_Information_Supplement.pdf

         1. Prepare PIN Block PinTerminal_ISO_4_Format#getISO4FormatPINBlock
         2. Prepare PAN BLOCK PinTerminal_ISO_4_Format#getISO4FormatPANBlock
         
         3. PIN block is encrypted with AES key
         
         4. The resulting Intermediate Block A is then XOR’ed with PAN Block
         
         5. The resulting Intermediate Block B is enciphered with the AES key again so
         we get the Enciphered PIN Block
    */
    public static void testISOFormat4Block() throws Exception {

        JSONObject pinData = loadData(System.getProperty("user.dir") + PINS_DATA_FILE);
        JSONArray pinDataList = pinData.getJSONArray("pins");

        JSONObject keyKsnData = loadData(System.getProperty("user.dir") + KEYS_KSN_DATA_FILE);
        JSONArray keyKsnDList = keyKsnData.getJSONArray("data");

        JSONObject panArqcData = loadData(System.getProperty("user.dir") + ARQC_DATA_FILE);
        JSONArray panArqcDList = panArqcData.getJSONArray("arqcData");
        
        for (int i = 0; i < pinDataList.length(); i++) {
            JSONObject panPinOBject = pinDataList.getJSONObject(i);
            try {
                System.out.println("---------testDUKPTPinValidation with ISO 4 FORMAT Pin Block---------");
                String pan = (panPinOBject).getString("pan");
                String pin = (panPinOBject).getString("pin");

                //pan = pan.substring(0, 12); // READ FROM END INSTEAD OF BEGINNING

                System.out.println("plain text pin is " + pin + " and pan is " + pan);

                String pinBlock = getISO4FormatPINBlock(pin);
                String panBlock = getISO4FormatPANBlock(pan);

                String dukptVariantKey = keyKsnDList.getJSONObject(i).getString("pek");
                String ksn = keyKsnDList.getJSONObject(i).getString("ksn");

                System.out.println("pin block is " + pinBlock.toString());
                System.out.println("pan block is " + panBlock.toString());
                System.out.println("DUKPT is " + dukptVariantKey);
                System.out.println("KSN is  " + ksn);
                String encryptedPinBlock = aesEncryptPINWithDukpt(dukptVariantKey, pinBlock.toString());
                System.out.println("ISO_4_FORMAT Encrypted Intermeidiate pinblock A = " + encryptedPinBlock);

                byte[] encodedPinAndPanXorBytes = xorBytes(Hex.decodeHex(encryptedPinBlock),
                        Hex.decodeHex(panBlock));

                String encodedPinPanBlock = Hex.encodeHexString(encodedPinAndPanXorBytes);
                System.out.println("ISO_4_FORMAT Encrypted Intermeidiate pinblock B = " + encodedPinPanBlock);
                String encryptedPinPanBlock = aesEncryptPINWithDukpt(dukptVariantKey, encodedPinPanBlock.toString());
                System.out.println("ISO_4_FORMAT Final encrypted pin pan block = " + encryptedPinPanBlock);
                
                
                String arqcKey = panArqcDList.getJSONObject(i).getString("udk");
                String arqcTransactionData = panArqcDList.getJSONObject(i).getString("transactionData");
                
                String arqcCryptogram = Utils.generateIso9797Alg3Mac(arqcKey, arqcTransactionData);
                System.out.println("ARQC payload is " + arqcCryptogram);

                //Thread.sleep(2000);
                RestTemplate restTemplate = new RestTemplate();
                String verifyPinUrl = ServiceConstants.HOST
                        + ServiceConstants.PIN_PROCESSOR_SERVICE_ISO_4_FORMAT_PIN_VERIFY_API;

                String finalVerifyPinlUrl = new StringBuilder(verifyPinUrl)
                        .append("?encryptedPin=")
                        .append(encryptedPinPanBlock)
                        .append("&transactionData=")
                        .append(arqcTransactionData)
                        .append("&arqcCryptogram=")
                        .append(arqcCryptogram)
                        .append("&pan=")
                        .append(pan)
                        .append("&ksn=")
                        .append(ksn)
                        .toString();
                System.out.println("pin verification endpoint url -> " + finalVerifyPinlUrl);
                ResponseEntity<String> setPinResponse = restTemplate.getForEntity(finalVerifyPinlUrl, String.class);
                System.out.println("Pin Verify operation response from issuer service for ISO_4_FORMAT encrypted pin is "
                        + setPinResponse.getBody());
                        Thread.sleep(3500);
                // final byte[] pinblock = xorBytes(pinToByteArray, panToByteArray);
                
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }

    }

    /* 
        Prepare PIN block – L is length of the PIN, P is PIN digit, F is fill digit
         ‘A’. R is random value from X’0′ to X’F’
            Example pin - 1234   
            Clear PIN block:441234AAAAAAAAAAB038B55E0E09E98F

        Reference - https://listings.pcisecuritystandards.org/documents/Implementing_ISO_Format_4_PIN_Blocks_Information_Supplement.pdf
     */
    private static String getISO4FormatPINBlock(String pin) {
        int PIN_OR_FILL_DIGIT_COUNT = 14;
        StringBuilder pinBlock = new StringBuilder()
                        .append(4)
                        .append(pin.length())
                        .append(pin);
                        
        int fillLength = PIN_OR_FILL_DIGIT_COUNT - pin.length();
        String paddedData = StringUtils.rightPad("", fillLength, 'A');
        pinBlock.append(paddedData);
        pinBlock.append(getRandomHexValues(8));
        return pinBlock.toString();
    }

   /* 
      Prepare PAN – take the primary account number – M is PAN length indicating PAN length of 12 plus the value of the 
      field ‘0’-‘7’ (ranging then from 12 to 19). If the PAN is less than 12 digits, the digits are right justified and 
      padded to the left with zeros and M is set to ‘0’. A is PAN digit, 0 is PAD digit ‘0’

        Example pan - 9123412341231
        Clear PAN block:09123412341230000000000000000000

    Reference - https://listings.pcisecuritystandards.org/documents/Implementing_ISO_Format_4_PIN_Blocks_Information_Supplement.pdf
    */
    private static String getISO4FormatPANBlock(String pan) {
        int panFillLength = pan.length() - 12;
        String panToEncrypt = pan.substring(0, pan.length());
        StringBuilder buffer = new StringBuilder()
                .append(panFillLength)
                .append(panToEncrypt);
        String panBlock = StringUtils.rightPad(buffer.toString(), 32, '0');
        return panBlock;
    }

    private static String getRandomHexValues(int count) {
        byte[] randomBytes = RandomUtils.nextBytes(count);

        StringBuilder hexValue = new StringBuilder();

        // Iterating through each byte in the array
        for (byte i : randomBytes) {
            hexValue.append(String.format("%02X", i));
        }
        return hexValue.toString();
    }

}
