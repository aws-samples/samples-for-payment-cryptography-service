package aws.sample.paymentcryptography.terminal;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import aws.sample.paymentcryptography.ServiceConstants;
import aws.sample.paymentcryptography.TerminalConstants;

public class PinTerminal {

    private static final String PIN = "9271";

    public static void main(String[] args) throws Exception {
        testPEKPinEncryptionAndValidation();
        testDukptPinEncryptionAndValidation();
    }

    public static void testPEKPinEncryptionAndValidation() throws Exception {
        String encodedPin = encodeForISO0Format(PIN, TerminalConstants.PAN);
        System.out.println("---------\ntestPEKPinEncryptionAndValidation Pin block is " + encodedPin);
        String pekEncryptedBlock = encryptPINWithPEK(TerminalConstants.PEK, encodedPin);
        System.out.println(("PEK encrypted block - " + pekEncryptedBlock));

        RestTemplate restTemplate = new RestTemplate();

        String setPinUrl = ServiceConstants.HOST
                + ServiceConstants.ISSUER_SERVICE_PIN_SET_API;

        String finaSetPinlUrl = new StringBuilder(setPinUrl)
                .append("?encryptedPinBLock=")
                .append(pekEncryptedBlock)
                .append("&pan=")
                .append(TerminalConstants.PAN).toString();

        ResponseEntity<String> setPinResponse = restTemplate.getForEntity(finaSetPinlUrl, String.class);
        System.out.println("Response from issuer service for (PEK encrypted) pin set operation is " + setPinResponse.getBody());
        JSONObject setPinResponseObject = new JSONObject(setPinResponse.getBody());

        if (setPinResponseObject.has("pvv")) {
            String verifyPinUrl = ServiceConstants.HOST
                    + ServiceConstants.ISSUER_SERVICE_PIN_VERIFY_API;

            String finalVerifyPinlUrl = new StringBuilder(verifyPinUrl)
                    .append("?encryptedPin=")
                    .append(pekEncryptedBlock)
                    .append("&pan=")
                    .append(TerminalConstants.PAN)
                    .append("&pinVerificationValue=")
                    .append(setPinResponseObject.getString("pvv")).toString();

            ResponseEntity<String> verifyPinResponse = restTemplate.getForEntity(finalVerifyPinlUrl, String.class);
            System.out.println("Response from issuer service for (PEK encrypted) pin verify operation is " + verifyPinResponse.getBody());
        }

    }

    public static void testDukptPinEncryptionAndValidation() throws Exception {
        String encodedPin = encodeForISO0Format(PIN, TerminalConstants.PAN);
        System.out.println("---------\ntestDukptPinEncryptionAndValidation: Pin block is " + encodedPin);
        String dukptEncryptedBlock = encryptPINWithDukpt(TerminalConstants.DUKPT_CURRENT_KEY, encodedPin);
        System.out.println(("DUKPT encrypted block - " + dukptEncryptedBlock));

        RestTemplate restTemplate = new RestTemplate();

        String setPinUrl = ServiceConstants.HOST
        + ServiceConstants.PIN_PROCESSOR_SERVICE_PIN_SET_API;

        String finaSetPinlUrl = new StringBuilder(setPinUrl)
                .append("?encryptedPinBLock=")
                .append(dukptEncryptedBlock)
                .append("&pan=")
                .append(TerminalConstants.PAN).toString();

        ResponseEntity<String> setPinResponse = restTemplate.getForEntity(finaSetPinlUrl, String.class);
        System.out.println("Response from PinTranslate service for (DUKPT encrypted) pin set operation is " + setPinResponse.getBody());
        JSONObject setPinResponseObject = new JSONObject(setPinResponse.getBody());

        if (setPinResponseObject.has("pvv")) {
            String verifyPinUrl = ServiceConstants.HOST
            + ServiceConstants.PIN_PROCESSOR_SERVICE_PIN_VERIFY_API;

            String finalVerifyPinlUrl = new StringBuilder(verifyPinUrl)
                    .append("?encryptedPin=")
                    .append(dukptEncryptedBlock)
                    .append("&pan=")
                    .append(TerminalConstants.PAN)
                    .append("&pinVerificationValue=")
                    .append(setPinResponseObject.getString("pvv")).toString();

            ResponseEntity<String> verifyPinResponse = restTemplate.getForEntity(finalVerifyPinlUrl, String.class);
            System.out.println("Response from PinTranslate service for (DUKPT encrypted) pin set operation is " + verifyPinResponse.getBody());
        }
    }

    public static String encryptPINWithPEK(String pek, String encodedPinBlock) throws Exception {
        Cipher chiper = Cipher.getInstance(TerminalConstants.TRANSFORMATION);
        chiper.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Hex.decodeHex(pek), TerminalConstants.ALGORITHM),
                new IvParameterSpec(new byte[8]));

        byte[] encVal = chiper.doFinal(Hex.decodeHex(encodedPinBlock));
        String encryptedValue = Hex.encodeHexString(encVal);
        return encryptedValue;
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

    /**
     * The PIN block is constructed by XOR-ing two 64-bit fields: the plain text PIN
     * field and the account number field, both of which comprise 16 four-bit
     * nibbles.
     * 
     * The plain text PIN field is:
     * 
     * one nibble with the value of 0, which identifies this as a format 0 block
     * one nibble encoding the length N of the PIN
     * N nibbles, each encoding one PIN digit
     * 14−N nibbles, each holding the "fill" value 15 (i.e. 11112)
     * The account number field is:
     * 
     * four nibbles with the value of zero
     * 12 nibbles containing the right-most 12 digits of the primary account number
     * (PAN), excluding the check digit
     * 
     * Decode pinblock format 0 (ISO 9564)
     * 
     * @param pin pin
     * @param pan primary account number (PAN/CLN/CardNumber)
     * @return pinblock in HEX format
     * @throws Exception
     */
    public static String encodeForISO0Format(String pin, String pan) throws Exception {
        try {
            final String pinLenHead = StringUtils.leftPad(Integer.toString(pin.length()), 2, '0') + pin;
            final String pinData = StringUtils.rightPad(pinLenHead, 16, 'F');
            final byte[] pinToByteArray = Hex.decodeHex(pinData.toCharArray());
            String pan12digits = pan.substring(pan.length() - 13, pan.length() - 1);
            final String panData = StringUtils.leftPad(pan12digits, 16, '0');
            final byte[] panToByteArray = Hex.decodeHex(panData.toCharArray());

            final byte[] pinblock = xorBytes(pinToByteArray, panToByteArray);
            return Hex.encodeHexString(pinblock).toUpperCase();
        } catch (DecoderException e) {
            throw new RuntimeException("Hex decoder failed!", e);
        }
    }

    public static byte[] xorBytes(byte[] byteArray1, byte[] byteArray2) throws Exception {
        if (byteArray1.length != byteArray2.length) {
            throw new Exception("Two arrays are not of the same length");
        }
        byte[] output = new byte[byteArray1.length];
        for (int i = 0; i < byteArray1.length; i++) {
            output[i] = (byte) ((byteArray1[i] ^ byteArray2[i]) & 0xFF);
        }

        return output;

    }

}
