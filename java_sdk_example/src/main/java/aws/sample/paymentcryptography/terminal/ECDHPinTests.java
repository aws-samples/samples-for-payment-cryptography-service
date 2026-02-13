package aws.sample.paymentcryptography.terminal;

import aws.sample.paymentcryptography.CommonConstants;
import aws.sample.paymentcryptography.ecdh.ECDHCryptoUtils;
import org.json.JSONObject;

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
import java.util.Scanner;

/**
 * Simulated terminal for ECDH PIN operations.
 * Demonstrates PIN set, reveal, and reset flows using ECDH key exchange.
 */
public class ECDHPinTests extends AbstractTerminal {
    
    private static final String SERVICE_URL = CommonConstants.HOST;
    
    public static void main(String[] args) {
        try {
            System.out.println("=== ECDH Terminal Simulation ===\n");
            
            Scanner scanner = new Scanner(System.in);
            
            while (true) {
                System.out.println("\nSelect operation:");
                System.out.println("1. Set PIN");
                System.out.println("2. Reveal PIN");
                System.out.println("3. Reset PIN");
                System.out.println("4. Exit");
                System.out.println("Choice: ");
                
                int choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline
                
                if (choice == 4) {
                    System.out.println("Exiting...");
                    break;
                }
                
                System.out.print("Enter PAN (Primary Account Number): ");
                String pan = scanner.nextLine().trim();
                
                // Validate PAN format
                if (!pan.matches("^[0-9]+$")) {
                    System.out.println("✗ Error: Invalid PAN format. PAN must contain only digits.");
                    continue;
                }
                
                switch (choice) {
                    case 1:
                        System.out.print("Enter PIN (4-6 digits): ");
                        String pin = scanner.nextLine().trim();
                        if (!pin.matches("^[0-9]{4,6}$")) {
                            System.out.println("✗ Error: Invalid PIN format. PIN must be 4-6 digits.");
                            break;
                        }
                        setPinFlowFormat4(pan, pin);
                        break;
                    case 2:
                        System.out.print("Enter PEK-encrypted PIN block: ");
                        String pekPinBlock = scanner.nextLine().trim();
                        if (pekPinBlock.isEmpty()) {
                            System.out.println("✗ Error: PIN block cannot be empty.");
                            break;
                        }
                        revealPinFlowFormat4(pan, pekPinBlock);
                        break;
                    case 3:
                        resetPinFlow(pan);
                        break;
                    default:
                        System.out.println("Invalid choice");
                }
                
                Thread.sleep(sleepTimeInMs);
            }
            
            scanner.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * PIN Set Flow using ECDH with ISO Format 4.
     */
    private static void setPinFlowFormat4(String pan, String pin) throws Exception {
        System.out.println("\n--- PIN Set Flow (ECDH - ISO Format 4) ---");
        
        // Step 1: Generate ECDH key pair
        System.out.println("1. Generating ECDH key pair...");
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        
        // Step 2: Generate shared info
        System.out.println("2. Generating shared info...");
        String sharedInfo = ECDHCryptoUtils.generateSharedInfo();
        
        // Step 3: Get AWS Payment Cryptography certificates
        System.out.println("3. Fetching AWS Payment Cryptography certificates...");
        JSONObject certificates = getCertificates();
        
        // Debug: Check response
        if (!certificates.has("status") || !certificates.getString("status").equals("success")) {
            System.out.println("\n✗ Error: Failed to get certificates");
            System.out.println("Response: " + certificates.toString());
            return;
        }
        
        if (!certificates.has("certificate") || certificates.getString("certificate").isEmpty()) {
            System.out.println("\n✗ Error: Certificate not found in response");
            System.out.println("Response: " + certificates.toString());
            return;
        }
        
        // Decode base64-encoded certificates
        String apcCertificateBase64 = certificates.getString("certificate");
        String apcCertificateChainBase64 = certificates.getString("certificateChain");
        
        String apcCertificate = new String(java.util.Base64.getDecoder().decode(apcCertificateBase64), StandardCharsets.UTF_8);
        String apcCertificateChain = new String(java.util.Base64.getDecoder().decode(apcCertificateChainBase64), StandardCharsets.UTF_8);
        
        System.out.println("   Certificate length: " + apcCertificate.length() + " characters");
        
        // Step 4: Derive symmetric key using ECDH
        System.out.println("4. Deriving symmetric key using ECDH...");
        X509Certificate peerCert = ECDHCryptoUtils.parseCertificate(apcCertificate);
        SecretKeySpec derivedKey = ECDHCryptoUtils.deriveSymmetricKey(
            keyPair.getPrivate(), 
            peerCert, 
            sharedInfo
        );
        
        // Step 5: Encode PIN block (ISO Format 4) - requires double encryption
        System.out.println("5. Encoding PIN block (ISO Format 4)...");
        
        // 5a. Prepare clear PIN block (without PAN XOR yet)
        String clearPinBlock = getISO4FormatClearPINBlock(pin);
        System.out.println("   Clear PIN block (hex): " + clearPinBlock);
        
        // 5b. First encryption: Encrypt PIN block → Intermediate Block A
        String intermediateBlockA = ECDHCryptoUtils.encrypt(clearPinBlock, derivedKey);
        System.out.println("   Intermediate Block A (encrypted): " + intermediateBlockA);
        
        // 5c. XOR with PAN block → Intermediate Block B
        String panBlock = getISO4FormatPANBlock(pan);
        byte[] intermediateABytes = hexToBytes(intermediateBlockA);
        byte[] panBytes = hexToBytes(panBlock);
        byte[] intermediateBBytes = new byte[intermediateABytes.length];
        for (int i = 0; i < intermediateABytes.length; i++) {
            intermediateBBytes[i] = (byte) (intermediateABytes[i] ^ panBytes[i]);
        }
        String intermediateBlockB = bytesToHex(intermediateBBytes);
        System.out.println("   Intermediate Block B (XOR with PAN): " + intermediateBlockB);
        
        // 5d. Second encryption: Encrypt Intermediate Block B → Final encrypted PIN block
        String encryptedPinBlock = ECDHCryptoUtils.encrypt(intermediateBlockB, derivedKey);
        System.out.println("   Final encrypted PIN block: " + encryptedPinBlock);
        System.out.println("   Encrypted length: " + encryptedPinBlock.length() + " characters (" + (encryptedPinBlock.length()/2) + " bytes)");
        
        // Step 6: Generate CSR
        System.out.println("6. Generating Certificate Signing Request...");
        String csr = ECDHCryptoUtils.generateCSR(keyPair);
        
        // Step 7: Send to ECDH service
        System.out.println("7. Sending PIN to ECDH service...");
        System.out.println("   Sending encrypted PIN block: " + encryptedPinBlock);
        System.out.println("   PAN: " + pan);
        
        // For this simulation, we'll use the APC certificate as signed certificate
        // In production, the CSR would be sent to CA for signing
        JSONObject response = callSetPinService(
            encryptedPinBlock, 
            pan, 
            csr, 
            sharedInfo,
            apcCertificate,
            apcCertificateChain
        );
        
        System.out.println("\n✓ PIN Set Response:");
        System.out.println("  Status: " + response.getString("status"));
        if (response.getString("status").equals("success")) {
            System.out.println("  Message: " + response.getString("message"));
            System.out.println("  PVV: " + response.getString("pvv"));
            if (response.has("pekEncryptedPinBlock")) {
                System.out.println("  PEK Encrypted PIN Block: " + response.getString("pekEncryptedPinBlock"));
            }
        } else {
            System.out.println("  Message: " + response.getString("message"));
            if (response.has("workaround")) {
                System.out.println("  Workaround: " + response.getString("workaround"));
            }
        }
    }
    
    /**
     * PIN Reveal Flow using ECDH with ISO Format 4.
     */
    private static void revealPinFlowFormat4(String pan, String pekEncryptedPinBlock) throws Exception {
        System.out.println("\n--- PIN Reveal Flow (ECDH - ISO Format 4) ---");
        
        // Step 1: Generate ECDH key pair
        System.out.println("1. Generating ECDH key pair...");
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        
        // Step 2: Generate shared info
        System.out.println("2. Generating shared info...");
        String sharedInfo = ECDHCryptoUtils.generateSharedInfo();
        
        // Step 3: Get AWS Payment Cryptography certificates
        System.out.println("3. Fetching AWS Payment Cryptography certificates...");
        JSONObject certificates = getCertificates();
        
        // Decode base64-encoded certificates
        String apcCertificateBase64 = certificates.getString("certificate");
        String apcCertificateChainBase64 = certificates.getString("certificateChain");
        
        String apcCertificate = new String(java.util.Base64.getDecoder().decode(apcCertificateBase64), StandardCharsets.UTF_8);
        String apcCertificateChain = new String(java.util.Base64.getDecoder().decode(apcCertificateChainBase64), StandardCharsets.UTF_8);
        
        // Step 4: Derive symmetric key using ECDH
        System.out.println("4. Deriving symmetric key using ECDH...");
        X509Certificate peerCert = ECDHCryptoUtils.parseCertificate(apcCertificate);
        SecretKeySpec derivedKey = ECDHCryptoUtils.deriveSymmetricKey(
            keyPair.getPrivate(), 
            peerCert, 
            sharedInfo
        );
        
        // Step 5: Generate CSR
        System.out.println("5. Generating Certificate Signing Request...");
        String csr = ECDHCryptoUtils.generateCSR(keyPair);
        
        // Step 6: Call reveal PIN service
        System.out.println("6. Requesting PIN reveal from ECDH service...");
        JSONObject response = callRevealPinService(
            pekEncryptedPinBlock,
            pan,
            csr,
            sharedInfo,
            apcCertificate,
            apcCertificateChain
        );
        
        if (response.getString("status").equals("success")) {
            String ecdhEncryptedPinBlock = response.getString("ecdhEncryptedPinBlock");
            
            // Step 7: Decrypt PIN block with derived key (ISO Format 4 double decryption)
            System.out.println("7. Decrypting PIN block with derived key (ISO Format 4)...");
            
            // 7a. First decryption: Decrypt encrypted PIN block → Intermediate Block B
            String intermediateBlockB = ECDHCryptoUtils.decrypt(ecdhEncryptedPinBlock, derivedKey);
            System.out.println("   Intermediate Block B (after first decrypt): " + intermediateBlockB);
            
            // 7b. XOR with PAN block → Intermediate Block A
            String panBlock = getISO4FormatPANBlock(pan);
            byte[] intermediateBBytes = hexToBytes(intermediateBlockB);
            byte[] panBytes = hexToBytes(panBlock);
            byte[] intermediateABytes = new byte[intermediateBBytes.length];
            for (int i = 0; i < intermediateBBytes.length; i++) {
                intermediateABytes[i] = (byte) (intermediateBBytes[i] ^ panBytes[i]);
            }
            String intermediateBlockA = bytesToHex(intermediateABytes);
            System.out.println("   Intermediate Block A (after XOR with PAN): " + intermediateBlockA);
            
            // 7c. Second decryption: Decrypt Intermediate Block A → Clear PIN block
            String clearPinBlock = ECDHCryptoUtils.decrypt(intermediateBlockA, derivedKey);
            System.out.println("   Clear PIN block: " + clearPinBlock);
            
            // 7d. Extract PIN from clear PIN block
            // ISO Format 4 clear PIN block format: 0L[PIN][F padding]
            // where L is the PIN length (1 digit), PIN is the actual PIN digits
            String pin = extractPinFromClearBlock(clearPinBlock);
            
            System.out.println("\n✓ PIN Revealed:");
            System.out.println("  Clear PIN Block: " + clearPinBlock);
            System.out.println("  Actual PIN: " + pin);
        } else {
            System.out.println("\n✗ Error: " + response.getString("message"));
        }
    }
    
    /**
     * PIN Reset Flow using ECDH.
     */
    private static void resetPinFlow(String pan) throws Exception {
        System.out.println("\n--- PIN Reset Flow (ECDH) ---");
        
        // Step 1: Generate ECDH key pair
        System.out.println("1. Generating ECDH key pair...");
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        
        // Step 2: Generate shared info
        System.out.println("2. Generating shared info...");
        String sharedInfo = ECDHCryptoUtils.generateSharedInfo();
        
        // Step 3: Get AWS Payment Cryptography certificates
        System.out.println("3. Fetching AWS Payment Cryptography certificates...");
        JSONObject certificates = getCertificates();
        
        // Decode base64-encoded certificates
        String apcCertificateBase64 = certificates.getString("certificate");
        String apcCertificateChainBase64 = certificates.getString("certificateChain");
        
        String apcCertificate = new String(java.util.Base64.getDecoder().decode(apcCertificateBase64), StandardCharsets.UTF_8);
        String apcCertificateChain = new String(java.util.Base64.getDecoder().decode(apcCertificateChainBase64), StandardCharsets.UTF_8);
        
        // Step 4: Derive symmetric key using ECDH
        System.out.println("4. Deriving symmetric key using ECDH...");
        X509Certificate peerCert = ECDHCryptoUtils.parseCertificate(apcCertificate);
        SecretKeySpec derivedKey = ECDHCryptoUtils.deriveSymmetricKey(
            keyPair.getPrivate(), 
            peerCert, 
            sharedInfo
        );
        
        // Step 5: Generate CSR
        System.out.println("5. Generating Certificate Signing Request...");
        String csr = ECDHCryptoUtils.generateCSR(keyPair);
        
        // Step 6: Call reset PIN service
        System.out.println("6. Requesting PIN reset from ECDH service...");
        JSONObject response = callResetPinService(
            pan,
            csr,
            sharedInfo,
            apcCertificate,
            apcCertificateChain
        );
        
        if (response.getString("status").equals("success")) {
            String ecdhEncryptedPinBlock = response.getString("ecdhEncryptedPinBlock");
            String pekEncryptedPinBlock = response.getString("pekEncryptedPinBlock");
            String pvv = response.getString("pvv");
            
            System.out.println("\n--- Received from Backend ---");
            System.out.println("  ECDH Encrypted PIN Block: " + ecdhEncryptedPinBlock);
            System.out.println("  PEK Encrypted PIN Block: " + pekEncryptedPinBlock);
            System.out.println("  PVV: " + pvv);
            System.out.println("  Note: This PIN was generated by AWS Payment Cryptography Service");
            System.out.println("  Note: Save the PEK Encrypted PIN Block for future reveal operations");
            
            // Step 7: Decrypt PIN block with derived key (ISO Format 4 double decryption)
            System.out.println("\n7. Decrypting PIN block with derived key (ISO Format 4)...");
            
            // 7a. First decryption: Decrypt encrypted PIN block → Intermediate Block B
            String intermediateBlockB = ECDHCryptoUtils.decrypt(ecdhEncryptedPinBlock, derivedKey);
            System.out.println("   Intermediate Block B (after first decrypt): " + intermediateBlockB);
            
            // 7b. XOR with PAN block → Intermediate Block A
            String panBlock = getISO4FormatPANBlock(pan);
            byte[] intermediateBBytes = hexToBytes(intermediateBlockB);
            byte[] panBytes = hexToBytes(panBlock);
            byte[] intermediateABytes = new byte[intermediateBBytes.length];
            for (int i = 0; i < intermediateBBytes.length; i++) {
                intermediateABytes[i] = (byte) (intermediateBBytes[i] ^ panBytes[i]);
            }
            String intermediateBlockA = bytesToHex(intermediateABytes);
            System.out.println("   Intermediate Block A (after XOR with PAN): " + intermediateBlockA);
            
            // 7c. Second decryption: Decrypt Intermediate Block A → Clear PIN block
            String clearPinBlock = ECDHCryptoUtils.decrypt(intermediateBlockA, derivedKey);
            System.out.println("   Clear PIN block: " + clearPinBlock);
            
            // 7d. Extract PIN from clear PIN block
            String pin = extractPinFromClearBlock(clearPinBlock);
            
            System.out.println("\n✓ PIN Reset Successfully:");
            System.out.println("  New PIN: " + pin);
            System.out.println("  PVV: " + pvv);
            System.out.println("  PEK Encrypted PIN Block (for storage): " + pekEncryptedPinBlock);
        } else {
            System.out.println("\n✗ Error: " + response.getString("message"));
        }
    }
    
    /**
    
    /**
    
    /**
     * Get certificates from ECDH service.
     */
    private static JSONObject getCertificates() throws Exception {
        URL url = new URL(SERVICE_URL + "/ecdh-service/certificates");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();
        
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        
        return new JSONObject(response.toString());
    }
    
    /**
     * Call set PIN service.
     */
    private static JSONObject callSetPinService(
            String encryptedPinBlock,
            String pan,
            String csr,
            String sharedInfo,
            String signedCertificate,
            String certificateChain) throws Exception {
        
        String urlParameters = 
            "encryptedPinBlock=" + URLEncoder.encode(encryptedPinBlock, StandardCharsets.UTF_8) +
            "&pan=" + URLEncoder.encode(pan, StandardCharsets.UTF_8) +
            "&csr=" + URLEncoder.encode(csr, StandardCharsets.UTF_8) +
            "&sharedInfo=" + URLEncoder.encode(sharedInfo, StandardCharsets.UTF_8) +
            "&signedCertificate=" + URLEncoder.encode(signedCertificate, StandardCharsets.UTF_8) +
            "&certificateChain=" + URLEncoder.encode(certificateChain, StandardCharsets.UTF_8);
        
        return callService(SERVICE_URL + "/ecdh-service/setPin", urlParameters);
    }
    
    /**
     * Call reveal PIN service.
     */
    private static JSONObject callRevealPinService(
            String pekEncryptedPinBlock,
            String pan,
            String csr,
            String sharedInfo,
            String signedCertificate,
            String certificateChain) throws Exception {
        
        String urlParameters = 
            "pekEncryptedPinBlock=" + URLEncoder.encode(pekEncryptedPinBlock, StandardCharsets.UTF_8) +
            "&pan=" + URLEncoder.encode(pan, StandardCharsets.UTF_8) +
            "&csr=" + URLEncoder.encode(csr, StandardCharsets.UTF_8) +
            "&sharedInfo=" + URLEncoder.encode(sharedInfo, StandardCharsets.UTF_8) +
            "&signedCertificate=" + URLEncoder.encode(signedCertificate, StandardCharsets.UTF_8) +
            "&certificateChain=" + URLEncoder.encode(certificateChain, StandardCharsets.UTF_8);
        
        return callService(SERVICE_URL + "/ecdh-service/revealPin", urlParameters);
    }
    
    /**
     * Call reset PIN service.
     */
    private static JSONObject callResetPinService(
            String pan,
            String csr,
            String sharedInfo,
            String signedCertificate,
            String certificateChain) throws Exception {
        
        String urlParameters = 
            "pan=" + URLEncoder.encode(pan, StandardCharsets.UTF_8) +
            "&csr=" + URLEncoder.encode(csr, StandardCharsets.UTF_8) +
            "&sharedInfo=" + URLEncoder.encode(sharedInfo, StandardCharsets.UTF_8) +
            "&signedCertificate=" + URLEncoder.encode(signedCertificate, StandardCharsets.UTF_8) +
            "&certificateChain=" + URLEncoder.encode(certificateChain, StandardCharsets.UTF_8);
        
        return callService(SERVICE_URL + "/ecdh-service/resetPin", urlParameters);
    }
    
    /**
     * Generic service call helper.
     */
    private static JSONObject callService(String serviceUrl, String urlParameters) throws Exception {
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
        String inputLine;
        StringBuilder response = new StringBuilder();
        
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        
        return new JSONObject(response.toString());
    }
    
    /**
     * Get clear PIN block for ISO Format 4 (without PAN XOR).
     * Format: 4L[PIN][FILL][RANDOM]
     * - 4: Format identifier
     * - L: PIN length (1 digit)
     * - PIN: PIN digits
     * - FILL: 'A' padding to make 14 digits total (PIN + FILL)
     * - RANDOM: 16 random hex digits
     */
    private static String getISO4FormatClearPINBlock(String pin) {
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
    
    /**
    
    /**
     * Prepare PAN block for ISO Format 4.
     * Format: M[PAN][PAD]
     * - M: PAN length - 12 (0-7, representing 12-19 digits)
     * - PAN: Primary Account Number
     * - PAD: Right-padded with '0' to 32 characters
     */
    private static String getISO4FormatPANBlock(String pan) {
        int panFillLength = pan.length() - 12;
        String panToEncrypt = pan.substring(0, pan.length());
        StringBuilder buffer = new StringBuilder()
            .append(panFillLength)
            .append(panToEncrypt);
        String panBlock = org.apache.commons.lang3.StringUtils.rightPad(buffer.toString(), 32, '0');
        return panBlock;
    }
    
    /**
    
    /**
     * Generate random hex values.
     */
    private static String getRandomHexValues(int count) {
        byte[] randomBytes = new byte[count];
        new java.security.SecureRandom().nextBytes(randomBytes);
        
        StringBuilder hexValue = new StringBuilder();
        for (byte b : randomBytes) {
            hexValue.append(String.format("%02X", b));
        }
        return hexValue.toString();
    }
    
    /**
     * Convert hex string to bytes.
     */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    /**
     * Convert bytes to hex string.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
    
    /**
     * Extract PIN from clear PIN block (ISO Format 0 or 4).
     * 
     * ISO Format 0: 0L[PIN][F padding]
     * ISO Format 4: 4L[PIN][A padding][RANDOM]
     * 
     * - Format ID: '0' or '4' (1 digit)
     * - L: PIN length (1 digit)
     * - PIN: PIN digits (L digits)
     * - Padding: 'F' for Format 0, 'A' for Format 4
     */
    private static String extractPinFromClearBlock(String clearPinBlock) {
        if (clearPinBlock.length() < 2) {
            throw new IllegalArgumentException("Invalid PIN block length");
        }
        
        // Extract format identifier
        char formatId = clearPinBlock.charAt(0);
        if (formatId != '0' && formatId != '4') {
            System.out.println("Warning: Expected format '0' or '4', got '" + formatId + "'");
        }
        
        // Extract PIN length
        int pinLength = Character.getNumericValue(clearPinBlock.charAt(1));
        if (pinLength < 4 || pinLength > 12) {
            throw new IllegalArgumentException("Invalid PIN length: " + pinLength);
        }
        
        // Extract PIN digits
        if (clearPinBlock.length() < 2 + pinLength) {
            throw new IllegalArgumentException("PIN block too short for specified PIN length");
        }
        
        String pin = clearPinBlock.substring(2, 2 + pinLength);
        
        // Validate PIN contains only digits
        if (!pin.matches("\\d+")) {
            throw new IllegalArgumentException("PIN contains non-digit characters: " + pin);
        }
        
        return pin;
    }
}
