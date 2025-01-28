package aws.sample.paymentcryptography.terminal;

public class TerminalMAC {

    public static String getMac(String data) throws Exception {
        return Utils.generateIso9797Alg3Mac(TerminalConstants.MAC_KEY_PLAIN_TEXT, data);
    }

}