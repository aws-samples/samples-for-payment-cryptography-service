package aws.sample.paymentcryptography.ecdh;

import org.json.JSONObject;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * Integration tests for ECDH PIN flows (ISO Format 0 and ISO Format 4).
 */
public class ECDHFlowTest {
    
    private static final String SERVICE_URL = "http://localhost:8080";
    private static final String TEST_PAN = "4111111111111111";
    private static final String TEST_PIN = "1234";
    
    @Test
    public void testISOFormat4SetAndRevealPin() throws Exception {
        System.out.println("\n=== Testing ISO Format 4 - Set and Reveal PIN ===");
        
        // Step 1: Set PIN using ISO Format 4
        String pekEncryptedPinBlock = setPinFormat4(TEST_PAN, TEST_PIN);
        assertNotNull("PEK encrypted PIN block should not be null", pekEncryptedPinBlock);
        System.out.println("✓ PIN set successfully (Format 4)");
        System.out.println("  PEK Encrypted PIN Block: " + pekEncryptedPinBlock);
        
        // Step 2: Reveal PIN using ISO Format 4
        String revealedPin = revealPinFormat4(TEST_PAN, pekEncryptedPinBlock);
        assertEquals("Revealed PIN should match original PIN", TEST_PIN, revealedPin);
        System.out.println("✓ PIN revealed successfully (Format 4): " + revealedPin);
    }
    
    @Test
    public void testResetPin() throws Exception {
        System.out.println("\n=== Testing Reset PIN ===");
        
        // Reset PIN generates a random PIN
        String newPin = resetPin(TEST_PAN);
        assertNotNull("Reset PIN should not be null", newPin);
        assertTrue("PIN should be 4-6 digits", newPin.length() >= 4 && newPin.length() <= 6);
        assertTrue("PIN should contain only digits", newPin.matches("\\d+"));
        System.out.println("✓ PIN reset successfully: " + newPin);
    }
    
    private String setPinFormat4(String pan, String pin) throws Exception {
        // Generate ECDH key pair
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        String sharedInfo = ECDHCryptoUtils.generateSharedInfo();
        
        // Get certificates
        JSONObject certificates = getCertificates();
        String apcCertificateBase64 = certificates.getString("certificate");
        String apcCertificateChainBase64 = certificates.getString("certificateChain");
        String apcCertificate = new String(java.util.Base64.getDecoder().decode(apcCertificateBase64), StandardCharsets.UTF_8);
        String apcCertificateChain = new String(java.util.Base64.getDecoder().decode(apcCertificateChainBase64), StandardCharsets.UTF_8);
        
        // Derive symmetric key
        X509Certificate peerCert = ECDHCryptoUtils.parseCertificate(apcCertificate);
        SecretKeySpec derivedKey = ECDHCryptoUtils.deriveSymmetricKey(keyPair.getPrivate(), peerCert, sharedInfo);
        
        // Encode PIN block (ISO Format 4 - double encryption)
        String clearPinBlock = getISO4FormatClearPINBlock(pin);
        String intermediateBlockA = ECDHCryptoUtils.encrypt(clearPinBlock, derivedKey);
        String panBlock = getISO4FormatPANBlock(pan);
        byte[] intermediateABytes = hexToBytes(intermediateBlockA);
        byte[] panBytes = hexToBytes(panBlock);
        byte[] intermediateBBytes = new byte[intermediateABytes.length];
        for (int i = 0; i < intermediateABytes.length; i++) {
            intermediateBBytes[i] = (byte) (intermediateABytes[i] ^ panBytes[i]);
        }
        String intermediateBlockB = bytesToHex(intermediateBBytes);
        String encryptedPinBlock = ECDHCryptoUtils.encrypt(intermediateBlockB, derivedKey);
        
        // Generate CSR and call service
        String csr = ECDHCryptoUtils.generateCSR(keyPair);
        JSONObject response = callSetPinService(encryptedPinBlock, pan, csr, sharedInfo, apcCertificate, apcCertificateChain);
        
        assertEquals("Set PIN should succeed", "success", response.getString("status"));
        return response.getString("pekEncryptedPinBlock");
    }
    
    private String revealPinFormat4(String pan, String pekEncryptedPinBlock) throws Exception {
        // Generate ECDH key pair
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        String sharedInfo = ECDHCryptoUtils.generateSharedInfo();
        
        // Get certificates
        JSONObject certificates = getCertificates();
        String apcCertificateBase64 = certificates.getString("certificate");
        String apcCertificateChainBase64 = certificates.getString("certificateChain");
        String apcCertificate = new String(java.util.Base64.getDecoder().decode(apcCertificateBase64), StandardCharsets.UTF_8);
        String apcCertificateChain = new String(java.util.Base64.getDecoder().decode(apcCertificateChainBase64), StandardCharsets.UTF_8);
        
        // Derive symmetric key
        X509Certificate peerCert = ECDHCryptoUtils.parseCertificate(apcCertificate);
        SecretKeySpec derivedKey = ECDHCryptoUtils.deriveSymmetricKey(keyPair.getPrivate(), peerCert, sharedInfo);
        
        // Generate CSR and call service
        String csr = ECDHCryptoUtils.generateCSR(keyPair);
        JSONObject response = callRevealPinService(pekEncryptedPinBlock, pan, csr, sharedInfo, apcCertificate, apcCertificateChain);
        
        assertEquals("Reveal PIN should succeed", "success", response.getString("status"));
        String ecdhEncryptedPinBlock = response.getString("ecdhEncryptedPinBlock");
        
        // Decrypt PIN block (ISO Format 4 - double decryption)
        String intermediateBlockB = ECDHCryptoUtils.decrypt(ecdhEncryptedPinBlock, derivedKey);
        String panBlock = getISO4FormatPANBlock(pan);
        byte[] intermediateBBytes = hexToBytes(intermediateBlockB);
        byte[] panBytes = hexToBytes(panBlock);
        byte[] intermediateABytes = new byte[intermediateBBytes.length];
        for (int i = 0; i < intermediateBBytes.length; i++) {
            intermediateABytes[i] = (byte) (intermediateBBytes[i] ^ panBytes[i]);
        }
        String intermediateBlockA = bytesToHex(intermediateABytes);
        String clearPinBlock = ECDHCryptoUtils.decrypt(intermediateBlockA, derivedKey);
        
        return extractPinFromClearBlock(clearPinBlock);
    }
    
    private String resetPin(String pan) throws Exception {
        // Generate ECDH key pair
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        String sharedInfo = ECDHCryptoUtils.generateSharedInfo();
        
        // Get certificates
        JSONObject certificates = getCertificates();
        String apcCertificateBase64 = certificates.getString("certificate");
        String apcCertificateChainBase64 = certificates.getString("certificateChain");
        String apcCertificate = new String(java.util.Base64.getDecoder().decode(apcCertificateBase64), StandardCharsets.UTF_8);
        String apcCertificateChain = new String(java.util.Base64.getDecoder().decode(apcCertificateChainBase64), StandardCharsets.UTF_8);
        
        // Derive symmetric key
        X509Certificate peerCert = ECDHCryptoUtils.parseCertificate(apcCertificate);
        SecretKeySpec derivedKey = ECDHCryptoUtils.deriveSymmetricKey(keyPair.getPrivate(), peerCert, sharedInfo);
        
        // Generate CSR and call service
        String csr = ECDHCryptoUtils.generateCSR(keyPair);
        JSONObject response = callResetPinService(pan, csr, sharedInfo, apcCertificate, apcCertificateChain);
        
        assertEquals("Reset PIN should succeed", "success", response.getString("status"));
        String ecdhEncryptedPinBlock = response.getString("ecdhEncryptedPinBlock");
        
        // Decrypt PIN block (ISO Format 4 double decryption)
        String intermediateBlockB = ECDHCryptoUtils.decrypt(ecdhEncryptedPinBlock, derivedKey);
        String panBlock = getISO4FormatPANBlock(pan);
        byte[] intermediateBBytes = hexToBytes(intermediateBlockB);
        byte[] panBytes = hexToBytes(panBlock);
        byte[] intermediateABytes = new byte[intermediateBBytes.length];
        for (int i = 0; i < intermediateBBytes.length; i++) {
            intermediateABytes[i] = (byte) (intermediateBBytes[i] ^ panBytes[i]);
        }
        String intermediateBlockA = bytesToHex(intermediateABytes);
        String clearPinBlock = ECDHCryptoUtils.decrypt(intermediateBlockA, derivedKey);
        
        return extractPinFromClearBlock(clearPinBlock);
    }
    
    // Helper methods
    
    private JSONObject getCertificates() throws Exception {
        URL url = new URL(SERVICE_URL + "/ecdh-service/certificates");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        
        return new JSONObject(response.toString());
    }
    
    private JSONObject callSetPinService(String encryptedPinBlock, String pan, String csr, String sharedInfo,
                                         String signedCertificate, String certificateChain) throws Exception {
        String urlParameters = 
            "encryptedPinBlock=" + URLEncoder.encode(encryptedPinBlock, StandardCharsets.UTF_8) +
            "&pan=" + URLEncoder.encode(pan, StandardCharsets.UTF_8) +
            "&csr=" + URLEncoder.encode(csr, StandardCharsets.UTF_8) +
            "&sharedInfo=" + URLEncoder.encode(sharedInfo, StandardCharsets.UTF_8) +
            "&signedCertificate=" + URLEncoder.encode(signedCertificate, StandardCharsets.UTF_8) +
            "&certificateChain=" + URLEncoder.encode(certificateChain, StandardCharsets.UTF_8);
        
        return callService(SERVICE_URL + "/ecdh-service/setPin", urlParameters);
    }
    
    private JSONObject callRevealPinService(String pekEncryptedPinBlock, String pan, String csr, String sharedInfo,
                                            String signedCertificate, String certificateChain) throws Exception {
        String urlParameters = 
            "pekEncryptedPinBlock=" + URLEncoder.encode(pekEncryptedPinBlock, StandardCharsets.UTF_8) +
            "&pan=" + URLEncoder.encode(pan, StandardCharsets.UTF_8) +
            "&csr=" + URLEncoder.encode(csr, StandardCharsets.UTF_8) +
            "&sharedInfo=" + URLEncoder.encode(sharedInfo, StandardCharsets.UTF_8) +
            "&signedCertificate=" + URLEncoder.encode(signedCertificate, StandardCharsets.UTF_8) +
            "&certificateChain=" + URLEncoder.encode(certificateChain, StandardCharsets.UTF_8);
        
        return callService(SERVICE_URL + "/ecdh-service/revealPin", urlParameters);
    }
    
    private JSONObject callResetPinService(String pan, String csr, String sharedInfo,
                                           String signedCertificate, String certificateChain) throws Exception {
        String urlParameters = 
            "pan=" + URLEncoder.encode(pan, StandardCharsets.UTF_8) +
            "&csr=" + URLEncoder.encode(csr, StandardCharsets.UTF_8) +
            "&sharedInfo=" + URLEncoder.encode(sharedInfo, StandardCharsets.UTF_8) +
            "&signedCertificate=" + URLEncoder.encode(signedCertificate, StandardCharsets.UTF_8) +
            "&certificateChain=" + URLEncoder.encode(certificateChain, StandardCharsets.UTF_8);
        
        return callService(SERVICE_URL + "/ecdh-service/resetPin", urlParameters);
    }
    
    private JSONObject callService(String serviceUrl, String urlParameters) throws Exception {
        URL url = new URL(serviceUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        
        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = urlParameters.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }
        
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        
        return new JSONObject(response.toString());
    }
    
    private String getISO4FormatClearPINBlock(String pin) {
        int PIN_OR_FILL_DIGIT_COUNT = 14;
        StringBuilder pinBlock = new StringBuilder()
            .append(4)
            .append(pin.length())
            .append(pin);
        
        int fillLength = PIN_OR_FILL_DIGIT_COUNT - pin.length();
        String paddedData = org.apache.commons.lang3.StringUtils.rightPad("", fillLength, 'A');
        pinBlock.append(paddedData);
        pinBlock.append(getRandomHexValues(8));
        
        return pinBlock.toString();
    }
    
    private String getISO4FormatPANBlock(String pan) {
        int panFillLength = pan.length() - 12;
        String panToEncrypt = pan.substring(0, pan.length());
        StringBuilder buffer = new StringBuilder()
            .append(panFillLength)
            .append(panToEncrypt);
        String panBlock = org.apache.commons.lang3.StringUtils.rightPad(buffer.toString(), 32, '0');
        return panBlock;
    }
    
    private String getRandomHexValues(int count) {
        byte[] randomBytes = new byte[count];
        new java.security.SecureRandom().nextBytes(randomBytes);
        
        StringBuilder hexValue = new StringBuilder();
        for (byte b : randomBytes) {
            hexValue.append(String.format("%02X", b));
        }
        return hexValue.toString();
    }
    
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
    
    private String extractPinFromClearBlock(String clearPinBlock) {
        if (clearPinBlock.length() < 2) {
            throw new IllegalArgumentException("Invalid PIN block length");
        }
        
        int pinLength = Character.getNumericValue(clearPinBlock.charAt(1));
        if (pinLength < 4 || pinLength > 12) {
            throw new IllegalArgumentException("Invalid PIN length: " + pinLength);
        }
        
        if (clearPinBlock.length() < 2 + pinLength) {
            throw new IllegalArgumentException("PIN block too short for specified PIN length");
        }
        
        String pin = clearPinBlock.substring(2, 2 + pinLength);
        
        if (!pin.matches("\\d+")) {
            throw new IllegalArgumentException("PIN contains non-digit characters: " + pin);
        }
        
        return pin;
    }
}
