package aws.sample.paymentcryptography.hmac;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.KeyParameter;

public class TerminalHMACService {

    public static final String HMAC_DATA_PLAIN_TEXT = "4123412341234123";
    public static final String key = "8A8349794C9EE9A4C2927098F249FED6";

    public static void main(String[] args) throws DecoderException {

        // String hmacMD5Value = "B0E3F0C0";

        /*
         * HmacUtils hmacUtils = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, key);
         * String result = hmacUtils.hmacHex(data);
         */
        final BlockCipher cipher = new DESEngine();
        final KeyParameter keyParameter = createKey(Hex.decodeHex(key.toCharArray()));
        final byte[] dataToMac = Hex.decodeHex(HMAC_DATA_PLAIN_TEXT.toCharArray());
        final byte[] genMac = generateIso9797Alg3Mac(keyParameter, cipher, dataToMac);

        // String retailMac = getRetailMAC()
        System.out.println("hmac is " + Hex.encodeHexString(genMac));
        /*
         * System.out.println(("old hmac is " + result));
         * 
         * System.out.println("Generated MAC 2 : " + hmacWithBouncyCastle("", data,
         * key));
         */

        // assertEquals(hmacMD5Value, result);
    }

    private static byte[] generateIso9797Alg3Mac(KeyParameter key, BlockCipher cipher, byte[] data) {
        final Mac mac = new ISO9797Alg3Mac(cipher);
        mac.init(key);
        mac.update(data, 0, data.length);
        final byte[] out = new byte[8];
        mac.doFinal(out, 0);
        // System.out.println("Generated MAC : " + Hex.encodeHexString(out));

        return out;
    }

    /*
     * public byte[] getRetailMAC(byte[] key, byte[] data) {
     * BlockCipher cipher = new DESEngine();
     * Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());
     * 
     * KeyParameter keyP = new KeyParameter(key);
     * mac.init(keyP);
     * mac.update(data, 0, data.length);
     * 
     * byte[] out = new byte[8];
     * 
     * mac.doFinal(out, 0);
     * 
     * return out;
     * }
     */

    private static KeyParameter createKey(byte[] key) {
        if (key.length != 16) {
            throw new RuntimeException("Unsupported key len " + key.length + " B for ISO9797Alg3Mac");
        }
        return new KeyParameter(key);
    }

    public static String getMac(String data) throws Exception {
        final BlockCipher cipher = new DESEngine();
        final KeyParameter keyParameter = createKey(Hex.decodeHex(key.toCharArray()));
        final byte[] dataToMac = Hex.decodeHex(data.toCharArray());
        final byte[] genMac = generateIso9797Alg3Mac(keyParameter, cipher, dataToMac);

        System.out.println("hmac is " + Hex.encodeHexString(genMac));
        return Hex.encodeHexString(genMac);
    }
    /*
     * public static String hmacWithBouncyCastle(String algorithm, String data,
     * String key) {
     * Digest digest = new SHA256Digest();
     * 
     * HMac hMac = new HMac(digest);
     * hMac.init(new KeyParameter(key.getBytes()));
     * 
     * byte[] hmacIn = data.getBytes();
     * hMac.update(hmacIn, 0, hmacIn.length);
     * byte[] hmacOut = new byte[hMac.getMacSize()];
     * 
     * hMac.doFinal(hmacOut, 0);
     * return Hex.encodeHexString(hmacOut);
     * }
     */
}