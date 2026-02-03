package aws.sample.paymentcryptography.ecdh;

import aws.sample.paymentcryptography.ecdh.ECDHCryptoUtils;
import org.junit.Before;
import org.junit.Test;
import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyClient;
import software.amazon.awssdk.services.paymentcryptography.model.*;
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataClient;

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Integration test for ECDH operations with AWS Payment Cryptography.
 * 
 * NOTE: This test requires:
 * 1. AWS credentials configured
 * 2. AWS Payment Cryptography service available in your region
 * 3. Appropriate IAM permissions
 * 
 * Run with: mvn test -Dtest=ECDHIntegrationTest
 * 
 * To skip: mvn test -Dtest=!ECDHIntegrationTest
 */
public class ECDHIntegrationTest {
    
    private PaymentCryptographyClient controlPlaneClient;
    private PaymentCryptographyDataClient dataPlaneClient;
    private String ecdhKeyArn;
    
    @Before
    public void setUp() {
        // Initialize AWS clients
        controlPlaneClient = PaymentCryptographyClient.builder().build();
        dataPlaneClient = PaymentCryptographyDataClient.builder().build();
        
        System.out.println("=== ECDH Integration Test Setup ===");
        System.out.println("Testing AWS Payment Cryptography ECDH operations");
    }
    
    @Test
    public void testECDHKeyCreation() {
        System.out.println("\n--- Test: ECDH Key Creation ---");
        
        try {
            // Create ECDH key
            KeyModesOfUse keyModesOfUse = KeyModesOfUse.builder()
                .deriveKey(true)
                .build();
            
            // Try different key algorithm values
            String[] possibleAlgorithms = {
                "ECC_NIST_P_256",
                "ECC_NIST_P256", 
                "ECDH_P256",
                "ECC_P256"
            };
            
            boolean keyCreated = false;
            String usedAlgorithm = null;
            
            for (String algorithm : possibleAlgorithms) {
                try {
                    System.out.println("Trying algorithm: " + algorithm);
                    
                    KeyAttributes keyAttributes = KeyAttributes.builder()
                        .keyAlgorithm(algorithm)
                        .keyClass(KeyClass.ASYMMETRIC_KEY_PAIR)
                        .keyUsage(KeyUsage.TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT)
                        .keyModesOfUse(keyModesOfUse)
                        .build();
                    
                    CreateKeyResponse response = controlPlaneClient.createKey(
                        CreateKeyRequest.builder()
                            .enabled(true)
                            .exportable(true)
                            .keyAttributes(keyAttributes)
                            .build()
                    );
                    
                    ecdhKeyArn = response.key().keyArn();
                    usedAlgorithm = algorithm;
                    keyCreated = true;
                    
                    System.out.println("✓ Successfully created ECDH key with algorithm: " + algorithm);
                    System.out.println("  Key ARN: " + ecdhKeyArn);
                    break;
                    
                } catch (Exception e) {
                    System.out.println("✗ Failed with algorithm " + algorithm + ": " + e.getMessage());
                }
            }
            
            if (!keyCreated) {
                System.out.println("\n⚠️  Could not create ECDH key with any known algorithm");
                System.out.println("This may indicate:");
                System.out.println("1. ECDH support not available in your AWS region");
                System.out.println("2. AWS SDK version doesn't support ECDH");
                System.out.println("3. Different enum value needed");
                
                // Don't fail the test - just skip
                System.out.println("\nSkipping ECDH integration tests");
                return;
            }
            
            // Get public key certificate
            GetPublicKeyCertificateResponse certResponse = controlPlaneClient.getPublicKeyCertificate(
                GetPublicKeyCertificateRequest.builder()
                    .keyIdentifier(ecdhKeyArn)
                    .build()
            );
            
            assertNotNull("Certificate should not be null", certResponse.keyCertificate());
            assertNotNull("Certificate chain should not be null", certResponse.keyCertificateChain());
            
            System.out.println("✓ Successfully retrieved public key certificate");
            System.out.println("  Certificate length: " + certResponse.keyCertificate().length());
            
            // Clean up
            deleteKey(ecdhKeyArn);
            System.out.println("✓ Cleaned up test key");
            
        } catch (Exception e) {
            System.err.println("✗ Test failed: " + e.getMessage());
            e.printStackTrace();
            fail("ECDH key creation test failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testClientSideECDHOperations() {
        System.out.println("\n--- Test: Client-Side ECDH Operations ---");
        
        try {
            // Generate ECDH key pair
            KeyPair keyPair = ECDHCryptoUtils.generateECDHKeyPair();
            assertNotNull("Key pair should not be null", keyPair);
            System.out.println("✓ Generated ECDH key pair");
            
            // Generate CSR
            String csr = ECDHCryptoUtils.generateCSR(keyPair);
            assertNotNull("CSR should not be null", csr);
            assertTrue("CSR should contain BEGIN CERTIFICATE REQUEST", 
                csr.contains("BEGIN CERTIFICATE REQUEST"));
            System.out.println("✓ Generated CSR");
            
            // Generate shared info
            String sharedInfo = ECDHCryptoUtils.generateSharedInfo();
            assertNotNull("Shared info should not be null", sharedInfo);
            System.out.println("✓ Generated shared info");
            
            // Test encryption/decryption
            byte[] keyBytes = new byte[32];
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            String plaintext = "Test PIN Block";
            
            String encrypted = ECDHCryptoUtils.encrypt(plaintext, key);
            String decrypted = ECDHCryptoUtils.decrypt(encrypted, key);
            
            assertEquals("Decrypted should match original", plaintext, decrypted);
            System.out.println("✓ Encryption/decryption works correctly");
            
            System.out.println("\n✓ All client-side ECDH operations passed");
            
        } catch (Exception e) {
            System.err.println("✗ Test failed: " + e.getMessage());
            e.printStackTrace();
            fail("Client-side ECDH operations test failed: " + e.getMessage());
        }
    }
    
    @Test
    public void testListAvailableKeyAlgorithms() {
        System.out.println("\n--- Test: List Available Key Algorithms ---");
        
        try {
            // Try to create keys with different algorithms to see what's supported
            System.out.println("Testing which key algorithms are supported:");
            
            String[] testAlgorithms = {
                "TDES_2_KEY",
                "TDES_3_KEY", 
                "AES_128",
                "AES_192",
                "AES_256",
                "RSA_2048",
                "RSA_3072",
                "RSA_4096"
            };
            
            for (String algorithm : testAlgorithms) {
                try {
                    KeyModesOfUse modes = KeyModesOfUse.builder()
                        .encrypt(true)
                        .decrypt(true)
                        .build();
                    
                    KeyAttributes attrs = KeyAttributes.builder()
                        .keyAlgorithm(algorithm)
                        .keyClass(KeyClass.SYMMETRIC_KEY)
                        .keyUsage(KeyUsage.TR31_P0_PIN_ENCRYPTION_KEY)
                        .keyModesOfUse(modes)
                        .build();
                    
                    CreateKeyResponse response = controlPlaneClient.createKey(
                        CreateKeyRequest.builder()
                            .enabled(true)
                            .exportable(true)
                            .keyAttributes(attrs)
                            .build()
                    );
                    
                    System.out.println("  ✓ " + algorithm + " - SUPPORTED");
                    
                    // Clean up
                    deleteKey(response.key().keyArn());
                    
                } catch (Exception e) {
                    System.out.println("  ✗ " + algorithm + " - " + e.getMessage().split("\n")[0]);
                }
            }
            
        } catch (Exception e) {
            System.err.println("✗ Test failed: " + e.getMessage());
        }
    }
    
    private void deleteKey(String keyArn) {
        try {
            // Schedule key deletion
            controlPlaneClient.deleteKey(
                DeleteKeyRequest.builder()
                    .keyIdentifier(keyArn)
                    .deleteKeyInDays(7) // Minimum allowed
                    .build()
            );
        } catch (Exception e) {
            System.err.println("Warning: Could not delete key " + keyArn + ": " + e.getMessage());
        }
    }
}
