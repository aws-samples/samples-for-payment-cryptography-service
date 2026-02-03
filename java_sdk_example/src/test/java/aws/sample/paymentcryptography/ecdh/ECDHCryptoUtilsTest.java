package aws.sample.paymentcryptography.ecdh;

import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;

/**
 * Unit tests for ECDH cryptographic utilities.
 */
public class ECDHCryptoUtilsTest {
    
    @Test
    public void testGenerateECDHKeyPair() throws Exception {
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        
        assertNotNull("Key pair should not be null", keyPair);
        assertNotNull("Private key should not be null", keyPair.getPrivate());
        assertNotNull("Public key should not be null", keyPair.getPublic());
        assertEquals("Algorithm should be EC", "EC", keyPair.getPrivate().getAlgorithm());
        assertEquals("Algorithm should be EC", "EC", keyPair.getPublic().getAlgorithm());
    }
    
    @Test
    public void testGenerateCSR() throws Exception {
        KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
        String csr = ECDHCryptoUtils.generateCSR(keyPair);
        
        assertNotNull("CSR should not be null", csr);
        assertTrue("CSR should contain BEGIN CERTIFICATE REQUEST", 
            csr.contains("BEGIN CERTIFICATE REQUEST"));
        assertTrue("CSR should contain END CERTIFICATE REQUEST", 
            csr.contains("END CERTIFICATE REQUEST"));
    }
    
    @Test
    public void testGenerateSharedInfo() {
        String sharedInfo1 = ECDHCryptoUtils.generateSharedInfo();
        String sharedInfo2 = ECDHCryptoUtils.generateSharedInfo();
        
        assertNotNull("Shared info should not be null", sharedInfo1);
        assertNotNull("Shared info should not be null", sharedInfo2);
        assertNotEquals("Shared info should be random", sharedInfo1, sharedInfo2);
        assertTrue("Shared info should be base64 encoded", 
            sharedInfo1.matches("^[A-Za-z0-9+/]+=*$"));
    }
    
    @Test
    public void testEncryptDecrypt() throws Exception {
        // Generate a test key
        byte[] keyBytes = new byte[32]; // 256 bits
        for (int i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) i;
        }
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        String plaintext = "Test PIN Block 1234";
        
        // Encrypt
        String ciphertext = ECDHCryptoUtils.encrypt(plaintext, key);
        assertNotNull("Ciphertext should not be null", ciphertext);
        assertNotEquals("Ciphertext should differ from plaintext", plaintext, ciphertext);
        
        // Decrypt
        String decrypted = ECDHCryptoUtils.decrypt(ciphertext, key);
        assertEquals("Decrypted text should match original", plaintext, decrypted);
    }
    
    @Test
    public void testEncryptWithRandomIV() throws Exception {
        byte[] keyBytes = new byte[32];
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        
        String plaintext = "Test";
        
        // Encrypt twice with same key and plaintext
        String ciphertext1 = ECDHCryptoUtils.encrypt(plaintext, key);
        String ciphertext2 = ECDHCryptoUtils.encrypt(plaintext, key);
        
        // Ciphertexts should differ due to random IV
        assertNotEquals("Ciphertexts should differ with random IV", ciphertext1, ciphertext2);
        
        // Both should decrypt to same plaintext
        assertEquals("First decryption should match", plaintext, 
            ECDHCryptoUtils.decrypt(ciphertext1, key));
        assertEquals("Second decryption should match", plaintext, 
            ECDHCryptoUtils.decrypt(ciphertext2, key));
    }
    
    @Test
    public void testHexConversion() {
        String hex = "48656C6C6F"; // "Hello" in hex
        byte[] bytes = ECDHCryptoUtils.hexToBytes(hex);
        String hexResult = ECDHCryptoUtils.bytesToHex(bytes);
        
        assertEquals("Hex conversion should be reversible", 
            hex.toUpperCase(), hexResult);
    }
    
    @Test
    public void testHexToBytesLowerCase() {
        String hexLower = "48656c6c6f";
        String hexUpper = "48656C6C6F";
        
        byte[] bytesLower = ECDHCryptoUtils.hexToBytes(hexLower);
        byte[] bytesUpper = ECDHCryptoUtils.hexToBytes(hexUpper);
        
        assertArrayEquals("Hex conversion should be case-insensitive", 
            bytesLower, bytesUpper);
    }
    
    @Test
    public void testBytesToHex() {
        byte[] bytes = {0x00, 0x0F, (byte) 0xFF, 0x12, 0x34};
        String hex = ECDHCryptoUtils.bytesToHex(bytes);
        
        assertEquals("Hex string should be correct", "000FFF1234", hex);
    }
    
    @Test(expected = Exception.class)
    public void testDecryptWithWrongKey() throws Exception {
        byte[] keyBytes1 = new byte[32];
        byte[] keyBytes2 = new byte[32];
        keyBytes2[0] = 1; // Different key
        
        SecretKeySpec key1 = new SecretKeySpec(keyBytes1, "AES");
        SecretKeySpec key2 = new SecretKeySpec(keyBytes2, "AES");
        
        String plaintext = "Test";
        String ciphertext = ECDHCryptoUtils.encrypt(plaintext, key1);
        
        // Should throw exception when decrypting with wrong key
        ECDHCryptoUtils.decrypt(ciphertext, key2);
    }
    
    @Test
    public void testKeyPairUniqueness() throws Exception {
        KeyPair keyPair1 = ECDHCryptoUtils.generateECDHKeyPair();
        KeyPair keyPair2 = ECDHCryptoUtils.generateECDHKeyPair();
        
        assertNotEquals("Key pairs should be unique", 
            keyPair1.getPrivate(), keyPair2.getPrivate());
        assertNotEquals("Public keys should be unique", 
            keyPair1.getPublic(), keyPair2.getPublic());
    }
    
    @Test
    public void testCSRUniqueness() throws Exception {
        KeyPair keyPair1 = ECDHCryptoUtils.generateECDHKeyPair();
        KeyPair keyPair2 = ECDHCryptoUtils.generateECDHKeyPair();
        
        String csr1 = ECDHCryptoUtils.generateCSR(keyPair1);
        String csr2 = ECDHCryptoUtils.generateCSR(keyPair2);
        
        assertNotEquals("CSRs should be unique for different key pairs", csr1, csr2);
    }
}
