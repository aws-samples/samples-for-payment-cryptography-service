package aws.sample.paymentcryptography.terminal;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.KeyParameter;

public class Utils {

     /* public static byte[] generateIso9797Alg3Mac(KeyParameter key, byte[] data) {
        final BlockCipher cipher = new DESEngine();
        final Mac mac = new ISO9797Alg3Mac(cipher);
        mac.init(key);
        mac.update(data, 0, data.length);
        final byte[] out = new byte[8];
        mac.doFinal(out, 0);
        return out;
    } */

    public static String generateIso9797Alg3Mac(String key, String data) throws DecoderException {
        final BlockCipher cipher = new DESEngine();
        final Mac mac = new ISO9797Alg3Mac(cipher);

        final KeyParameter keyParameter = new KeyParameter(Hex.decodeHex(key.toCharArray()));
        final byte[] dataArray = Hex.decodeHex(data.toCharArray());

        mac.init(keyParameter);
        mac.update(dataArray, 0, dataArray.length);
        final byte[] out = new byte[8];
        mac.doFinal(out, 0);
        return Hex.encodeHexString(out);
    }

    /* public static String getMac(String data) throws Exception {
        final KeyParameter keyParameter = new KeyParameter(Hex.decodeHex(TerminalConstants.MAC_KEY_PLAIN_TEXT.toCharArray()));
        final byte[] dataToMac = Hex.decodeHex(data.toCharArray());
        final byte[] genMac = Utils.generateIso9797Alg3Mac(keyParameter, dataToMac);
        return Hex.encodeHexString(genMac);
    } */
}
