package aws.sample.paymentcryptography.ecdh;

/**
 * Constants for ECDH (Elliptic Curve Diffie-Hellman) key exchange operations.
 */
public interface ECDHConstants {
    
    // Key aliases for ECDH operations
    String ECDH_KEY_ALIAS = "alias/ecdh_key";
    String CA_KEY_ALIAS = "alias/ecdh_ca_key";
    String CA_PUBLIC_KEY_ALIAS = "alias/ca_public_key";
    String PEK_ALIAS = "alias/ecdh_pek";
    String PGK_ALIAS = "alias/ecdh_pgk";
    
    // Key algorithms
    String ECDH_KEY_ALGORITHM = "ECC_NIST_P256";
    String SYMMETRIC_KEY_ALGORITHM = "AES_256";
    
    // Certificate validity
    int CERTIFICATE_VALIDITY_DAYS = 365;
    
    // Shared info for key derivation
    String DEFAULT_SHARED_INFO_PREFIX = "ECDH_PIN_";
    
    // API endpoints
    String ECDH_SERVICE_SET_PIN_API = "/ecdh-service/setPin/";
    String ECDH_SERVICE_REVEAL_PIN_API = "/ecdh-service/revealPin/";
    String ECDH_SERVICE_RESET_PIN_API = "/ecdh-service/resetPin/";
    
    // Encryption parameters
    String AES_CIPHER_MODE = "AES/CBC/PKCS5Padding";
    int AES_KEY_SIZE = 256;
    int IV_SIZE = 16;
}
