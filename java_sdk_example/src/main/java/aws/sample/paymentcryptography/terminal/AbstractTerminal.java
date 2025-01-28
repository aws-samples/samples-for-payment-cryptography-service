package aws.sample.paymentcryptography.terminal;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Random;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;

public abstract class AbstractTerminal {

    protected static String PINS_DATA_FILE = "/test-data/sample-pin-pan.json";
    protected static String ARQC_DATA_FILE = "/test-data/sample-pan-arqc-key.json";

    private static Random rnd = new Random();

    protected static JSONObject loadData(String filePath) throws IOException {
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();

        String paymentData = new String(data, "UTF-8");
        JSONObject json = new JSONObject(paymentData);
        return json;
    }

    protected static String getRandomNumber(int digCount) {
        StringBuilder sb = new StringBuilder(digCount);
        for (int i = 0; i < digCount; i++)
            sb.append((char) ('0' + rnd.nextInt(10)));
        return sb.toString();
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

    /* // Utility method to convert hex string to byte array
    public static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // Utility method to convert byte array to hex string
    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }

    public static byte[] applyISO9797Method1Padding(byte[] input, int blockSize) {
        // Calculate padding length
        int paddingLength = blockSize - (input.length % blockSize);
        if (paddingLength == blockSize) {
            // If data is already aligned with block size, no padding needed
            return input;
        }
        
        // Create new array with room for padding
        byte[] paddedData = new byte[input.length + paddingLength];
        
        // Copy original data
        System.arraycopy(input, 0, paddedData, 0, input.length);
        
        // Fill remaining bytes with zeros (M1 padding)
        for (int i = input.length; i < paddedData.length; i++) {
            paddedData[i] = 0x00;
        }
        
        return paddedData;
    } */
    
    
}
