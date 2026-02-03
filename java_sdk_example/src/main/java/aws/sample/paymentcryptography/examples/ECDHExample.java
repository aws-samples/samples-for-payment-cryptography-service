package aws.sample.paymentcryptography.examples;

import aws.sample.paymentcryptography.ecdh.ECDHCryptoUtils;

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;

/**
 * Standalone example demonstrating ECDH cryptographic operations.
 * 
 * This example shows the client-side cryptographic operations without
 * requiring AWS Payment Cryptography Service to be running.
 * 
 * Purpose:
 * - Educational: Learn how ECDH cryptographic operations work
 * - Testing: Test crypto utilities independently
 * - Understanding: See key generation, CSR creation, encryption/decryption in action
 * 
 * Note: For actual ECDH PIN flows with AWS Payment Cryptography, use:
 * - ECDHTerminal.java - Interactive terminal for PIN operations
 * - ECDHFlowTest.java - Integration tests
 * - ECDHService.java - Backend service
 * 
 * Run: ./run_example.sh aws.sample.paymentcryptography.examples.ECDHExample
 */
public class ECDHExample {
    
    public static void main(String[] args) {
        try {
            System.out.println("=== ECDH Cryptographic Operations Example ===\n");
            
            // Example 1: Key Pair Generation
            demonstrateKeyPairGeneration();
            
            // Example 2: CSR Generation
            demonstrateCSRGeneration();
            
            // Example 3: Shared Info Generation
            demonstrateSharedInfoGeneration();
            
            // Example 4: Encryption/Decryption
            demonstrateEncryptionDecryption();
            
            // Example 5: Hex Conversion
            demonstrateHexConversion();
            
            System.out.println("\n=== All Examples Completed Successfully ===");
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void demonstrateKeyPairGeneration() throws Exception {
        System.out.println("--- Example 1: ECDH Key Pair Generation ---");
        
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        
        System.out.println("Generated ECDH Key Pair:");
        System.out.println("  Algorithm: " + keyPair.getPrivate().getAlgorithm());
        System.out.println("  Private Key Format: " + keyPair.getPrivate().getFormat());
        System.out.println("  Public Key Format: " + keyPair.getPublic().getFormat());
        System.out.println("  Private Key Length: " + keyPair.getPrivate().getEncoded().length + " bytes");
        System.out.println("  Public Key Length: " + keyPair.getPublic().getEncoded().length + " bytes");
        System.out.println();
    }
    
    private static void demonstrateCSRGeneration() throws Exception {
        System.out.println("--- Example 2: Certificate Signing Request (CSR) Generation ---");
        
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        String csr = ECDHCryptoUtils.generateCSR(keyPair);
        
        System.out.println("Generated CSR:");
        System.out.println(csr);
        System.out.println("CSR Length: " + csr.length() + " characters");
        System.out.println();
    }
    
    private static void demonstrateSharedInfoGeneration() throws Exception {
        System.out.println("--- Example 3: Shared Info Generation ---");
        
        String sharedInfo1 = ECDHCryptoUtils.generateSharedInfo();
        String sharedInfo2 = ECDHCryptoUtils.generateSharedInfo();
        String sharedInfo3 = ECDHCryptoUtils.generateSharedInfo();
        
        System.out.println("Generated Shared Info (Random):");
        System.out.println("  Sample 1: " + sharedInfo1);
        System.out.println("  Sample 2: " + sharedInfo2);
        System.out.println("  Sample 3: " + sharedInfo3);
        System.out.println("  All Different: " + 
            (!sharedInfo1.equals(sharedInfo2) && !sharedInfo2.equals(sharedInfo3)));
        System.out.println();
    }
    
    private static void demonstrateEncryptionDecryption() throws Exception {
        System.out.println("--- Example 4: AES-256-CBC Encryption/Decryption ---");
        
        // Generate a sample AES-256 key
        byte[] keyBytes = new byte[32]; // 256 bits
        for (int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) (i % 256);
        }
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        // Sample PIN block (ISO Format 0)
        String pinBlock = "041234FFFFFFFFFF";
        
        System.out.println("Original PIN Block: " + pinBlock);
        
        // Encrypt
        String encrypted = ECDHCryptoUtils.encrypt(pinBlock, key);
        System.out.println("Encrypted (Base64): " + encrypted);
        System.out.println("Encrypted Length: " + encrypted.length() + " characters");
        
        // Decrypt
        String decrypted = ECDHCryptoUtils.decrypt(encrypted, key);
        System.out.println("Decrypted PIN Block: " + decrypted);
        System.out.println("Match: " + pinBlock.equals(decrypted));
        
        // Demonstrate random IV
        String encrypted2 = ECDHCryptoUtils.encrypt(pinBlock, key);
        System.out.println("\nSecond Encryption (Different IV): " + encrypted2);
        System.out.println("Ciphertexts Different: " + !encrypted.equals(encrypted2));
        System.out.println("Both Decrypt Correctly: " + 
            pinBlock.equals(ECDHCryptoUtils.decrypt(encrypted2, key)));
        System.out.println();
    }
    
    private static void demonstrateHexConversion() throws Exception {
        System.out.println("--- Example 5: Hex Conversion ---");
        
        // Sample data
        String originalHex = "041234FFFFFFFFFF";
        System.out.println("Original Hex: " + originalHex);
        
        // Convert to bytes
        byte[] bytes = ECDHCryptoUtils.hexToBytes(originalHex);
        System.out.println("Byte Array Length: " + bytes.length);
        System.out.print("Byte Values: ");
        for (byte b : bytes) {
            System.out.print(String.format("%02X ", b));
        }
        System.out.println();
        
        // Convert back to hex
        String resultHex = ECDHCryptoUtils.bytesToHex(bytes);
        System.out.println("Result Hex: " + resultHex);
        System.out.println("Match: " + originalHex.equalsIgnoreCase(resultHex));
        System.out.println();
    }
}
