package aws.sample.paymentcryptography.ecdh;

import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyClient;
import software.amazon.awssdk.services.paymentcryptography.model.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Manages ECDH keys in AWS Payment Cryptography Service.
 * Creates and retrieves keys needed for ECDH operations.
 */
public class ECDHKeyManager {
    
    private final PaymentCryptographyClient controlPlaneClient;
    
    public ECDHKeyManager(PaymentCryptographyClient controlPlaneClient) {
        this.controlPlaneClient = controlPlaneClient;
    }
    
    /**
     * Create or retrieve ECDH key for key agreement operations.
     */
    public String createOrGetECDHKey() {
        try {
            // Try to get existing key by alias
            String keyArn = getKeyByAlias(ECDHConstants.ECDH_KEY_ALIAS);
            if (keyArn != null) {
                Logger.getGlobal().info("Using existing ECDH key: " + keyArn);
                return keyArn;
            }
            
            // Create new ECDH key
            Logger.getGlobal().info("Creating new ECDH key...");
            
            KeyModesOfUse keyModesOfUse = KeyModesOfUse.builder()
                .deriveKey(true)
                .build();
            
            KeyAttributes keyAttributes = KeyAttributes.builder()
                .keyAlgorithm(KeyAlgorithm.ECC_NIST_P256)
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
            
            keyArn = response.key().keyArn();
            
            // Create alias
            createAlias(ECDHConstants.ECDH_KEY_ALIAS, keyArn);
            
            Logger.getGlobal().info("Created ECDH key: " + keyArn);
            return keyArn;
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to create/get ECDH key", e);
        }
    }
    
    /**
     * Create or retrieve PEK (PIN Encryption Key) for ECDH operations.
     */
    public String createOrGetPEK() {
        try {
            String keyArn = getKeyByAlias(ECDHConstants.PEK_ALIAS);
            if (keyArn != null) {
                Logger.getGlobal().info("Using existing PEK: " + keyArn);
                return keyArn;
            }
            
            Logger.getGlobal().info("Creating new PEK...");
            
            KeyModesOfUse keyModesOfUse = KeyModesOfUse.builder()
                .encrypt(true)
                .decrypt(true)
                .wrap(true)
                .unwrap(true)
                .build();
            
            KeyAttributes keyAttributes = KeyAttributes.builder()
                .keyAlgorithm("TDES_2KEY")
                .keyClass(KeyClass.SYMMETRIC_KEY)
                .keyUsage(KeyUsage.TR31_P0_PIN_ENCRYPTION_KEY)
                .keyModesOfUse(keyModesOfUse)
                .build();
            
            CreateKeyResponse response = controlPlaneClient.createKey(
                CreateKeyRequest.builder()
                    .enabled(true)
                    .exportable(true)
                    .keyAttributes(keyAttributes)
                    .build()
            );
            
            keyArn = response.key().keyArn();
            createAlias(ECDHConstants.PEK_ALIAS, keyArn);
            
            Logger.getGlobal().info("Created PEK: " + keyArn);
            return keyArn;
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to create/get PEK", e);
        }
    }
    
    /**
     * Create or retrieve PGK (PIN Generation/Verification Key).
     * Uses TR31_V2_VISA_PIN_VERIFICATION_KEY for PVV generation operations.
     */
    public String createOrGetPGK() {
        try {
            String keyArn = getKeyByAlias(ECDHConstants.PGK_ALIAS);
            if (keyArn != null) {
                Logger.getGlobal().info("Using existing PGK: " + keyArn);
                return keyArn;
            }
            
            Logger.getGlobal().info("Creating new PGK...");
            
            KeyModesOfUse keyModesOfUse = KeyModesOfUse.builder()
                .generate(true)
                .verify(true)
                .build();
            
            KeyAttributes keyAttributes = KeyAttributes.builder()
                .keyAlgorithm("TDES_2KEY")
                .keyClass(KeyClass.SYMMETRIC_KEY)
                .keyUsage(KeyUsage.TR31_V2_VISA_PIN_VERIFICATION_KEY)
                .keyModesOfUse(keyModesOfUse)
                .build();
            
            CreateKeyResponse response = controlPlaneClient.createKey(
                CreateKeyRequest.builder()
                    .enabled(true)
                    .exportable(true)
                    .keyAttributes(keyAttributes)
                    .build()
            );
            
            keyArn = response.key().keyArn();
            updateAlias(ECDHConstants.PGK_ALIAS, keyArn);
            
            Logger.getGlobal().info("Created PGK: " + keyArn);
            return keyArn;
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to create/get PGK", e);
        }
    }
    
    /**
     * Get public key certificate for ECDH key.
     */
    public Map<String, String> getPublicKeyCertificate(String keyArn) {
        try {
            GetPublicKeyCertificateResponse response = controlPlaneClient.getPublicKeyCertificate(
                GetPublicKeyCertificateRequest.builder()
                    .keyIdentifier(keyArn)
                    .build()
            );
            
            Map<String, String> certificates = new HashMap<>();
            certificates.put("certificate", response.keyCertificate());
            certificates.put("certificateChain", response.keyCertificateChain());
            
            return certificates;
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to get public key certificate", e);
        }
    }
    
    /**
     * Import CA public key certificate to AWS Payment Cryptography.
     * If a CA key already exists, it will be deleted and re-imported to ensure consistency.
     */
    public String importCAPublicKey(String caCertificatePEM) {
        try {
            // Check if CA key already exists
            String existingKeyArn = getKeyByAlias(ECDHConstants.CA_KEY_ALIAS);
            if (existingKeyArn != null) {
                Logger.getGlobal().info("Found existing CA public key: " + existingKeyArn);
                Logger.getGlobal().info("Deleting old CA key to ensure consistency with local CA...");
                
                try {
                    // Delete the alias first
                    controlPlaneClient.deleteAlias(
                        DeleteAliasRequest.builder()
                            .aliasName(ECDHConstants.CA_KEY_ALIAS)
                            .build()
                    );
                    
                    // Schedule key deletion (minimum 7 days)
                    controlPlaneClient.deleteKey(
                        DeleteKeyRequest.builder()
                            .keyIdentifier(existingKeyArn)
                            .deleteKeyInDays(7)
                            .build()
                    );
                    
                    Logger.getGlobal().info("Old CA key scheduled for deletion");
                } catch (Exception e) {
                    Logger.getGlobal().warning("Could not delete old CA key: " + e.getMessage());
                }
            }
            
            Logger.getGlobal().info("Importing CA public key to AWS Payment Cryptography...");
            
            // Base64 encode the PEM certificate
            String base64Cert = Base64.getEncoder().encodeToString(
                caCertificatePEM.getBytes(StandardCharsets.UTF_8)
            );
            
            // Create key attributes for CA public key
            KeyAttributes keyAttributes = KeyAttributes.builder()
                .keyAlgorithm(KeyAlgorithm.ECC_NIST_P256)
                .keyClass(KeyClass.PUBLIC_KEY)
                .keyUsage(KeyUsage.TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE)
                .keyModesOfUse(KeyModesOfUse.builder()
                    .verify(true)
                    .build())
                .build();
            
            // Import the CA public key
            ImportKeyResponse response = controlPlaneClient.importKey(
                ImportKeyRequest.builder()
                    .enabled(true)
                    .keyMaterial(
                        ImportKeyMaterial.builder()
                            .rootCertificatePublicKey(
                                RootCertificatePublicKey.builder()
                                    .keyAttributes(keyAttributes)
                                    .publicKeyCertificate(base64Cert)
                                    .build()
                            )
                            .build()
                    )
                    .build()
            );
            
            String keyArn = response.key().keyArn();
            createAlias(ECDHConstants.CA_KEY_ALIAS, keyArn);
            
            Logger.getGlobal().info("Imported CA public key: " + keyArn);
            return keyArn;
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to import CA public key", e);
        }
    }
    
    /**
     * Get key ARN by alias.
     * Returns null if the key is in DELETE_PENDING state.
     */
    private String getKeyByAlias(String alias) {
        try {
            GetAliasResponse response = controlPlaneClient.getAlias(
                GetAliasRequest.builder()
                    .aliasName(alias)
                    .build()
            );
            String keyArn = response.alias().keyArn();
            
            // Check if key is in DELETE_PENDING state
            GetKeyResponse keyResponse = controlPlaneClient.getKey(
                GetKeyRequest.builder()
                    .keyIdentifier(keyArn)
                    .build()
            );
            
            if (keyResponse.key().keyState() == KeyState.DELETE_PENDING) {
                Logger.getGlobal().info("Key " + keyArn + " is in DELETE_PENDING state, will create new key");
                return null;
            }
            
            return keyArn;
        } catch (ResourceNotFoundException e) {
            return null;
        }
    }
    
    /**
     * Create alias for a key.
     */
    private void createAlias(String aliasName, String keyArn) {
        try {
            controlPlaneClient.createAlias(
                CreateAliasRequest.builder()
                    .aliasName(aliasName)
                    .keyArn(keyArn)
                    .build()
            );
        } catch (Exception e) {
            Logger.getGlobal().warning("Could not create alias " + aliasName + ": " + e.getMessage());
        }
    }
    
    /**
     * Update alias to point to a new key, or create it if it doesn't exist.
     */
    private void updateAlias(String aliasName, String keyArn) {
        try {
            controlPlaneClient.updateAlias(
                UpdateAliasRequest.builder()
                    .aliasName(aliasName)
                    .keyArn(keyArn)
                    .build()
            );
            Logger.getGlobal().info("Updated alias " + aliasName + " to point to " + keyArn);
        } catch (ResourceNotFoundException e) {
            // Alias doesn't exist, create it
            createAlias(aliasName, keyArn);
        } catch (Exception e) {
            Logger.getGlobal().warning("Could not update alias " + aliasName + ": " + e.getMessage());
        }
    }
}
