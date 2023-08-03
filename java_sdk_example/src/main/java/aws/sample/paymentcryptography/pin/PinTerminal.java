package aws.sample.paymentcryptography.pin;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;

public class PinTerminal {

    private static final String CARD_NUMBER = "9123412341234";
    private static final String PIN = "1234";
    private static final String PIN_MASK = "00000000000000FF00000000000000FF";
    
    // pre-calculated this outside the code for brevity
    private final static String CURRENT_KEY = "91E7A69D04B61A30AE4965847D94A2E2";
    
    // KSN for reference only. This was used to derive the CURRENT_KEY and needs to be passed for Pin Translate
    private static final String KSN = "FFFF9876543210E00001"; 
 
    private static final String ALGORITHM = "TripleDES";
    private static final String MODE = "CBC";
    private static final String PADDING = "NoPadding";

    private static final String TRANSFORMATION = ALGORITHM + "/" + MODE + "/" + PADDING;

    public static void main(String[] args) throws Exception {
        String encryptedData = encrypt(CURRENT_KEY, CARD_NUMBER, PIN);
        System.out.println("Encrypted data: " + encryptedData);
        //String decryptedData = decrypt(CURRENT_KEY, CARD_NUMBER, encryptedData);
        //System.out.println("Decrypted data: " + decryptedData);
    }

    public static String encrypt(String dukpt_key, String pan, String pin) throws Exception {
        String pinEncoded = encodeForISO0Format(pin, pan);
        System.out.println("Pin block is " + pinEncoded);
        
        byte[] maskedKey = xorBytes(Hex.decodeHex(dukpt_key), Hex.decodeHex(PIN_MASK));

        byte[] key = new byte[24];
        
        System.arraycopy(maskedKey, 0, key, 0, 16);
        System.arraycopy(maskedKey, 0, key, 16, 8);

        Cipher chiper = Cipher.getInstance(TRANSFORMATION);
        chiper.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGORITHM), new IvParameterSpec(new byte[8]));

        byte[] encVal = chiper.doFinal(Hex.decodeHex(pinEncoded));
        String encryptedValue = Hex.encodeHexString(encVal);
        return encryptedValue;
        
    }

    /* public static String decrypt(String dukpt_key, String pan, String encryptedPin) throws Exception {
        byte[] tmp = Hex.decodeHex(dukpt_key);
        byte[] key = new byte[24];
        System.arraycopy(tmp, 0, key, 0, 16);
        System.arraycopy(tmp, 0, key, 16, 8);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        //cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGORITHM), new IvParameterSpec(new byte[8]));
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGORITHM), iv);
        byte[] plaintext = cipher.doFinal(Hex.decodeHex(encryptedPin));
        String pinEncoded = Hex.encodeHexString(plaintext);//Utils.b2h(plaintext);
        //return decodePinBlock(pan, pinEncoded);
        return format0decode(pinEncoded, pan);
    } */

    /**
        The PIN block is constructed by XOR-ing two 64-bit fields: the plain text PIN field and the account number field, both of which comprise 16 four-bit nibbles.

        The plain text PIN field is:

        one nibble with the value of 0, which identifies this as a format 0 block
        one nibble encoding the length N of the PIN
        N nibbles, each encoding one PIN digit
        14−N nibbles, each holding the "fill" value 15 (i.e. 11112)
        The account number field is:

        four nibbles with the value of zero
        12 nibbles containing the right-most 12 digits of the primary account number (PAN), excluding the check digit

	 * Decode pinblock format 0 (ISO 9564)
	 * @param pin pin 
	 * @param pan primary account number (PAN/CLN/CardNumber)
	 * @return pinblock in HEX format
     * @throws Exception
	 */
	public static String encodeForISO0Format(String pin, String pan) throws Exception {
		try {
			final String pinLenHead = StringUtils.leftPad(Integer.toString(pin.length()), 2, '0')+pin;
			final String pinData = StringUtils.rightPad(pinLenHead, 16,'F');
			final byte[] pinToByteArray = Hex.decodeHex(pinData.toCharArray());
            String pan12digits = pan.substring(pan.length() - 13, pan.length() - 1);
			final String panData = StringUtils.leftPad(pan12digits, 16, '0');
			final byte[] panToByteArray = Hex.decodeHex(panData.toCharArray());

            final byte[] pinblock = xorBytes(pinToByteArray, panToByteArray);
			/* final byte[] pinblock = new byte[8];
			for (int i = 0; i < 8; i++)
				pinblock[i] = (byte) (bPin[i] ^ bPan[i]);
 */
			return Hex.encodeHexString(pinblock).toUpperCase();
		} catch (DecoderException e) {
			throw new RuntimeException("Hex decoder failed!",e);
		}
	}
	
	/**
	 * @param accountNumber PAN - primary account number
	 * @return extract right-most 12 digits of the primary account number (PAN)
	 */
	/* public static String extractPanAccountNumberPart(String accountNumber) {
		String accountNumberPart = null;
		if (accountNumber.length() > 12)
			accountNumberPart = accountNumber.substring(accountNumber.length() - 13, accountNumber.length() - 1);
		else
			accountNumberPart = accountNumber;
		return accountNumberPart;
	} */
	
	/**
	 * decode pinblock format 0 - ISO 9564
	 * @param pinblock pinblock in format 0 - ISO 9564 in HEX format 
	 * @param pan primary account number (PAN/CLN/CardNumber)
	 * @return clean PIN
	 * @throws Exception
	 */
	/* public static String format0decode(String pinblock, String pan) throws Exception {
		try {
			final String panPart = pan; //extractPanAccountNumberPart(pan);
			final String panData = StringUtils.leftPad(panPart, 16, '0');
			final byte[] bPan = Hex.decodeHex(panData);
			
			final byte[] bPinBlock = Hex.decodeHex(pinblock.toCharArray());
			
            final byte[] bPin = xorBytes(bPinBlock, bPan);			
			final String pinData = Hex.encodeHexString(bPin);
			//final int pinLen = Integer.parseInt(pinData.substring(0, 2));
			return pinData.substring(2,2+PIN.length());
            
		} catch (NumberFormatException e) {
			throw new RuntimeException("Invalid pinblock format!");
		} catch (DecoderException e) {
			throw new RuntimeException("Hex decoder failed!",e);
		}
	} */

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
