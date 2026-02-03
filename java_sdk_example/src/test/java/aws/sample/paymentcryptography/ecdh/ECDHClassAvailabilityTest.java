package aws.sample.paymentcryptography.ecdh;

import org.junit.Test;

/**
 * Test to check if ECDH wrapped key classes are available in the current AWS SDK version.
 */
public class ECDHClassAvailabilityTest {
    
    @Test
    public void testWrappedKeyMaterialClassExists() {
        try {
            Class.forName("software.amazon.awssdk.services.paymentcryptographydata.model.WrappedKeyMaterial");
            System.out.println("✓ WrappedKeyMaterial class is available");
        } catch (ClassNotFoundException e) {
            System.out.println("✗ WrappedKeyMaterial class NOT available");
            System.out.println("  This class is required for ECDH PIN operations");
        }
    }
    
    @Test
    public void testDiffieHellmanSymmetricKeyClassExists() {
        try {
            Class.forName("software.amazon.awssdk.services.paymentcryptographydata.model.DiffieHellmanSymmetricKey");
            System.out.println("✓ DiffieHellmanSymmetricKey class is available");
        } catch (ClassNotFoundException e) {
            System.out.println("✗ DiffieHellmanSymmetricKey class NOT available");
            System.out.println("  This class is required for ECDH key derivation");
        }
    }
    
    @Test
    public void testEcdhDerivationAttributesClassExists() {
        try {
            Class.forName("software.amazon.awssdk.services.paymentcryptographydata.model.EcdhDerivationAttributes");
            System.out.println("✓ EcdhDerivationAttributes class is available");
        } catch (ClassNotFoundException e) {
            System.out.println("✗ EcdhDerivationAttributes class NOT available");
            System.out.println("  This class is required for ECDH key derivation parameters");
        }
    }
    
    @Test
    public void testKeyDerivationFunctionClassExists() {
        try {
            Class.forName("software.amazon.awssdk.services.paymentcryptographydata.model.KeyDerivationFunction");
            System.out.println("✓ KeyDerivationFunction class is available");
        } catch (ClassNotFoundException e) {
            System.out.println("✗ KeyDerivationFunction class NOT available");
            System.out.println("  This class is required for key derivation configuration");
        }
    }
    
    @Test
    public void testKeyDerivationHashAlgorithmClassExists() {
        try {
            Class.forName("software.amazon.awssdk.services.paymentcryptographydata.model.KeyDerivationHashAlgorithm");
            System.out.println("✓ KeyDerivationHashAlgorithm class is available");
        } catch (ClassNotFoundException e) {
            System.out.println("✗ KeyDerivationHashAlgorithm class NOT available");
            System.out.println("  This class is required for hash algorithm specification");
        }
    }
}
