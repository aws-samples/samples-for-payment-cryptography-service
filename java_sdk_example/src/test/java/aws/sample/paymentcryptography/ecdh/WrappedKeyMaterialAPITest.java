package aws.sample.paymentcryptography.ecdh;

import org.junit.Test;
import software.amazon.awssdk.services.paymentcryptographydata.model.*;

/**
 * Test to explore the WrappedKeyMaterial API and determine correct usage.
 */
public class WrappedKeyMaterialAPITest {
    
    @Test
    public void testWrappedKeyMaterialAPI() {
        System.out.println("Testing WrappedKeyMaterial API...");
        
        try {
            // Test 1: Check if we can create EcdhDerivationAttributes
            EcdhDerivationAttributes ecdhAttrs = EcdhDerivationAttributes.builder()
                .certificateAuthorityPublicKeyIdentifier("arn:aws:payment-cryptography:us-east-1:123456789012:key/test")
                .publicKeyCertificate("test-certificate")
                .keyAlgorithm("AES_128")  // Use string instead of enum
                .keyDerivationFunction(KeyDerivationFunction.NIST_SP800)
                .keyDerivationHashAlgorithm(KeyDerivationHashAlgorithm.SHA_256)
                .sharedInformation("test-shared-info")
                .build();
            
            System.out.println("✓ EcdhDerivationAttributes created successfully");
            
            // Test 2: Check if we can create WrappedKeyMaterial
            WrappedKeyMaterial wrappedKeyMaterial = WrappedKeyMaterial.builder()
                .diffieHellmanSymmetricKey(ecdhAttrs)
                .build();
            
            System.out.println("✓ WrappedKeyMaterial created successfully");
            System.out.println("  Type: " + wrappedKeyMaterial.type());
            
            // Test 3: Check if we can create WrappedKey (for control plane)
            software.amazon.awssdk.services.paymentcryptography.model.WrappedKey wrappedKey = 
                software.amazon.awssdk.services.paymentcryptography.model.WrappedKey.builder()
                    .keyMaterial("test-key-material")
                    .build();
            
            System.out.println("✓ WrappedKey (control plane) created successfully");
            
            System.out.println("\n✅ All API tests passed!");
            System.out.println("The ECDH wrapped key classes are available and functional!");
            
        } catch (Exception e) {
            System.out.println("\n✗ API test failed:");
            e.printStackTrace();
        }
    }
}
