package aws.sample.paymentcryptography.utils;

public class Utils {
    
    public static byte[] xorBytes(byte[] byteArray1, byte[] byteArray2) throws Exception {
        if (byteArray1.length != byteArray2.length) {
            throw new Exception("Two arrays are not of the same length");
        }
        byte[] output = new byte[byteArray1.length];
        for (int i = 0; i < byteArray1.length; i++) {
            output[i] = (byte) ((byteArray1[i] ^ byteArray2[i]) & 0xFF);
            //output[i] &= 0xFF;
        }

        return output;
        
    }

    /* public static byte[] xorBytes(byte[] a, byte[] b) throws Exception {
        if (a.length != b.length) {
            throw new Exception();
        }
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            int r = 0;
            r = a[i] ^ b[i];
            r &= 0xFF;
            result[i] = (byte) r;
        }
        return result;
    } */

    public static byte[] h2b(String hex) {
        if ((hex.length() & 0x01) == 0x01)
            throw new IllegalArgumentException();
        byte[] bytes = new byte[hex.length() / 2];
        for (int idx = 0; idx < bytes.length; ++idx) {
            int hi = Character.digit((int) hex.charAt(idx * 2), 16);
            int lo = Character.digit((int) hex.charAt(idx * 2 + 1), 16);
            if ((hi < 0) || (lo < 0))
                throw new IllegalArgumentException();
            bytes[idx] = (byte) ((hi << 4) | lo);
        }
        return bytes;
    }

    public static String b2h(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int idx = 0; idx < bytes.length; ++idx) {
            int hi = (bytes[idx] & 0xF0) >>> 4;
            int lo = (bytes[idx] & 0x0F);
            hex[idx * 2] = (char) (hi < 10 ? '0' + hi : 'A' - 10 + hi);
            hex[idx * 2 + 1] = (char) (lo < 10 ? '0' + lo : 'A' - 10 + lo);
        }
        return new String(hex);
    }

}
