package aws.sample.paymentcryptography.terminal;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.KeyParameter;

import aws.sample.paymentcryptography.TerminalConstants;

public class HMACTerminalTester {

    public static final String HMAC_DATA_PLAIN_TEXT = "4123412341234123";

    public static void main(String[] args) throws DecoderException {

        final BlockCipher cipher = new DESEngine();
        final KeyParameter keyParameter = new KeyParameter(Hex.decodeHex(TerminalConstants.MAC_KEY_PLAIN_TEXT.toCharArray()));
        final byte[] dataToMac = Hex.decodeHex(HMAC_DATA_PLAIN_TEXT.toCharArray());
        final byte[] genMac = generateIso9797Alg3Mac(keyParameter, cipher, dataToMac);

        System.out.println("hmac is " + Hex.encodeHexString(genMac));
    }

    private static byte[] generateIso9797Alg3Mac(KeyParameter key, BlockCipher cipher, byte[] data) {
        final Mac mac = new ISO9797Alg3Mac(cipher);
        mac.init(key);
        mac.update(data, 0, data.length);
        final byte[] out = new byte[8];
        mac.doFinal(out, 0);
        return out;
    }

    public static String getMac(String data) throws Exception {
        final BlockCipher cipher = new DESEngine();
        final KeyParameter keyParameter = new KeyParameter(Hex.decodeHex(TerminalConstants.MAC_KEY_PLAIN_TEXT.toCharArray()));
        final byte[] dataToMac = Hex.decodeHex(data.toCharArray());
        final byte[] genMac = generateIso9797Alg3Mac(keyParameter, cipher, dataToMac);

        System.out.println("hmac is " + Hex.encodeHexString(genMac));
        return Hex.encodeHexString(genMac);
    }
}