package aws.sample.paymentcryptography.ecdh;

import org.json.JSONObject;
import org.springframework.web.bind.annotation.*;
import software.amazon.awssdk.services.paymentcryptography.PaymentCryptographyClient;
import software.amazon.awssdk.services.paymentcryptographydata.PaymentCryptographyDataClient;
import software.amazon.awssdk.services.paymentcryptographydata.model.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Logger;

/**
 * ECDH Service for PIN operations using AWS Payment Cryptography.
 * Handles PIN set, reveal, and reset operations using ECDH key exchange.
 */
@RestController
@RequestMapping("/ecdh-service")
public class ECDHService {
    
    private final PaymentCryptographyClient controlPlaneClient;
    private final PaymentCryptographyDataClient dataPlaneClient;
    private final ECDHKeyManager keyManager;
    private final LocalCAManager caManager;
    
    private String ecdhKeyArn;
    private String pekKeyArn;
    private String pgkKeyArn;
    private String caPublicKeyArn;
    
    public ECDHService() {
        this.controlPlaneClient = PaymentCryptographyClient.builder().build();
        this.dataPlaneClient = PaymentCryptographyDataClient.builder().build();
        this.keyManager = new ECDHKeyManager(controlPlaneClient);
        
        try {
            // Initialize local CA
            this.caManager = new LocalCAManager();
            
            // Initialize keys
            initializeKeys();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize ECDH service", e);
        }
    }
    
    private void initializeKeys() {
        Logger.getGlobal().info("Initializing ECDH keys...");
        this.ecdhKeyArn = keyManager.createOrGetECDHKey();
        this.pekKeyArn = keyManager.createOrGetPEK();
        this.pgkKeyArn = keyManager.createOrGetPGK();
        
        // Import local CA public key to AWS Payment Cryptography
        try {
            String caCertPEM = caManager.getCACertificatePEM();
            this.caPublicKeyArn = keyManager.importCAPublicKey(caCertPEM);
        } catch (Exception e) {
            throw new RuntimeException("Failed to import CA public key", e);
        }
        
        Logger.getGlobal().info("ECDH keys initialized successfully");
        Logger.getGlobal().info("  ECDH Key: " + ecdhKeyArn);
        Logger.getGlobal().info("  PEK Key: " + pekKeyArn);
        Logger.getGlobal().info("  PGK Key: " + pgkKeyArn);
        Logger.getGlobal().info("  CA Public Key: " + caPublicKeyArn);
    }
    
    /**
     * Get AWS Payment Cryptography certificates for ECDH operations.
     */
    @GetMapping("/certificates")
    public String getCertificates() {
        try {
            Map<String, String> certificates = keyManager.getPublicKeyCertificate(ecdhKeyArn);
            
            JSONObject response = new JSONObject();
            response.put("certificate", certificates.get("certificate"));
            response.put("certificateChain", certificates.get("certificateChain"));
            response.put("status", "success");
            
            return response.toString();
            
        } catch (Exception e) {
            e.printStackTrace();
            JSONObject error = new JSONObject();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return error.toString();
        }
    }
    
    /**
     * Set PIN using ECDH encrypted PIN block.
     * 
     * @param encryptedPinBlock PIN block encrypted with ECDH-derived key
     * @param pan Primary Account Number
     * @param csr Certificate Signing Request from client
     * @param sharedInfo Shared information for key derivation
     * @param signedCertificate Client certificate signed by CA
     * @param certificateChain Certificate chain
     */
    @PostMapping("/setPin")
    public String setPin(
            @RequestParam String encryptedPinBlock,
            @RequestParam String pan,
            @RequestParam String csr,
            @RequestParam String sharedInfo,
            @RequestParam String signedCertificate,
            @RequestParam String certificateChain) {
        
        try {
            Logger.getGlobal().info("\n=== SET PIN REQUEST ===");
            
            // Sanitize inputs - remove any whitespace
            pan = pan.trim();
            encryptedPinBlock = encryptedPinBlock.trim();
            
            Logger.getGlobal().info("Setting PIN for PAN: " + pan);
            Logger.getGlobal().info("Received ECDH encrypted PIN block: " + encryptedPinBlock);
            
            // Validate PAN format
            if (!pan.matches("^[0-9]+$")) {
                throw new IllegalArgumentException("Invalid PAN format. PAN must contain only digits. Received: '" + pan + "'");
            }
            
            // Sign the client's CSR with local CA
            String actualSignedCertificate = caManager.signCSR(csr);
            Logger.getGlobal().info("Signed client certificate with local CA");
            
            // Build wrapped key for ECDH
            WrappedKeyMaterial wrappedKeyMaterial = buildWrappedKeyMaterial(actualSignedCertificate, sharedInfo);
            
            // Translate PIN from ECDH encryption to PEK encryption
            Logger.getGlobal().info("Translating PIN: ECDH (ISO Format 4) → PEK (ISO Format 0)...");
            TranslatePinDataResponse translateResponse = dataPlaneClient.translatePinData(
                TranslatePinDataRequest.builder()
                    .encryptedPinBlock(encryptedPinBlock)
                    .incomingKeyIdentifier(ecdhKeyArn)
                    .incomingWrappedKey(
                        WrappedKey.builder()
                            .wrappedKeyMaterial(wrappedKeyMaterial)
                            .build()
                    )
                    .incomingTranslationAttributes(
                        TranslationIsoFormats.builder()
                            .isoFormat4(
                                TranslationPinDataIsoFormat034.builder()
                                    .primaryAccountNumber(pan)
                                    .build()
                            )
                            .build()
                    )
                    .outgoingKeyIdentifier(pekKeyArn)
                    .outgoingTranslationAttributes(
                        TranslationIsoFormats.builder()
                            .isoFormat0(
                                TranslationPinDataIsoFormat034.builder()
                                    .primaryAccountNumber(pan)
                                    .build()
                            )
                            .build()
                    )
                    .build()
            );
            
            String pekEncryptedPinBlock = translateResponse.pinBlock();
            Logger.getGlobal().info("PEK encrypted PIN block: " + pekEncryptedPinBlock);
            
            // Generate PIN verification value for the translated PIN
            Logger.getGlobal().info("Generating PVV for the PIN...");
            GeneratePinDataResponse pinDataResponse = dataPlaneClient.generatePinData(
                GeneratePinDataRequest.builder()
                    .generationKeyIdentifier(pgkKeyArn)
                    .encryptionKeyIdentifier(pekKeyArn)
                    .primaryAccountNumber(pan)
                    .pinBlockFormat(PinBlockFormatForPinData.ISO_FORMAT_0)
                    .generationAttributes(
                        PinGenerationAttributes.builder()
                            .visaPinVerificationValue(
                                VisaPinVerificationValue.builder()
                                    .encryptedPinBlock(pekEncryptedPinBlock)
                                    .pinVerificationKeyIndex(1)
                                    .build()
                            )
                            .build()
                    )
                    .build()
            );
            
            String pvv = pinDataResponse.pinData().verificationValue();
            Logger.getGlobal().info("Generated PVV: " + pvv);
            
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("message", "PIN set successfully");
            response.put("pvv", pvv);
            response.put("pekEncryptedPinBlock", pekEncryptedPinBlock);
            
            Logger.getGlobal().info("✓ PIN set successfully for PAN: " + pan);
            Logger.getGlobal().info("=== SET PIN COMPLETE ===\n");
            return response.toString();
            
        } catch (Exception e) {
            e.printStackTrace();
            JSONObject error = new JSONObject();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return error.toString();
        }
    }
    
    /**
     * Reveal PIN by translating from PEK encryption to ECDH encryption.
     * 
     * Note: ISO Format 0 (used for PEK storage) only uses the rightmost 12 digits
     * of the PAN (excluding the check digit). This means:
     * - The first few digits (BIN/IIN) are not cryptographically bound
     * - The last digit (check digit) is not used
     * - Only positions 4-15 of a 16-digit PAN provide cryptographic binding
     * 
     * Example: For PAN 4111111111111111
     * - Used: 111111111111 (positions 4-15)
     * - Not used: 4 (position 1-3) and 1 (position 16, check digit)
     * 
     * This is a known limitation of ISO Format 0. ISO Format 4 uses the full PAN
     * for better security.
     */
    @PostMapping("/revealPin")
    public String revealPin(
            @RequestParam String pekEncryptedPinBlock,
            @RequestParam String pan,
            @RequestParam String csr,
            @RequestParam String sharedInfo,
            @RequestParam String signedCertificate,
            @RequestParam String certificateChain) {
        
        try {
            Logger.getGlobal().info("\n=== REVEAL PIN REQUEST ===");
            
            // Sanitize inputs - remove any whitespace
            pan = pan.trim();
            pekEncryptedPinBlock = pekEncryptedPinBlock.trim();
            
            Logger.getGlobal().info("Revealing PIN for PAN: " + pan);
            Logger.getGlobal().info("Received PEK encrypted PIN block: " + pekEncryptedPinBlock);
            
            // Validate PAN format
            if (!pan.matches("^[0-9]+$")) {
                throw new IllegalArgumentException("Invalid PAN format. PAN must contain only digits. Received: '" + pan + "'");
            }
            
            // Sign the client's CSR with local CA
            String actualSignedCertificate = caManager.signCSR(csr);
            Logger.getGlobal().info("Signed client certificate with local CA");
            
            // Build wrapped key for ECDH
            WrappedKeyMaterial wrappedKeyMaterial = buildWrappedKeyMaterial(actualSignedCertificate, sharedInfo);
            
            // Translate PIN from PEK encryption to ECDH encryption
            Logger.getGlobal().info("Translating PIN: PEK (ISO Format 0) → ECDH (ISO Format 4)...");
            TranslatePinDataResponse translateResponse = dataPlaneClient.translatePinData(
                TranslatePinDataRequest.builder()
                    .encryptedPinBlock(pekEncryptedPinBlock)
                    .incomingKeyIdentifier(pekKeyArn)
                    .incomingTranslationAttributes(
                        TranslationIsoFormats.builder()
                            .isoFormat0(
                                TranslationPinDataIsoFormat034.builder()
                                    .primaryAccountNumber(pan)
                                    .build()
                            )
                            .build()
                    )
                    .outgoingKeyIdentifier(ecdhKeyArn)
                    .outgoingWrappedKey(
                        WrappedKey.builder()
                            .wrappedKeyMaterial(wrappedKeyMaterial)
                            .build()
                    )
                    .outgoingTranslationAttributes(
                        TranslationIsoFormats.builder()
                            .isoFormat4(
                                TranslationPinDataIsoFormat034.builder()
                                    .primaryAccountNumber(pan)
                                    .build()
                            )
                            .build()
                    )
                    .build()
            );
            
            String ecdhEncryptedPinBlock = translateResponse.pinBlock();
            Logger.getGlobal().info("ECDH encrypted PIN block: " + ecdhEncryptedPinBlock);
            
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("ecdhEncryptedPinBlock", ecdhEncryptedPinBlock);
            
            Logger.getGlobal().info("✓ PIN revealed successfully for PAN: " + pan);
            Logger.getGlobal().info("=== REVEAL PIN COMPLETE ===\n");
            return response.toString();
            
        } catch (Exception e) {
            e.printStackTrace();
            JSONObject error = new JSONObject();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return error.toString();
        }
    }
    
    /**
     * Reset PIN by generating a new random PIN.
     */
    @PostMapping("/resetPin")
    public String resetPin(
            @RequestParam String pan,
            @RequestParam String csr,
            @RequestParam String sharedInfo,
            @RequestParam String signedCertificate,
            @RequestParam String certificateChain) {
        
        try {
            Logger.getGlobal().info("\n=== RESET PIN REQUEST ===");
            
            // Sanitize inputs - remove any whitespace
            pan = pan.trim();
            
            Logger.getGlobal().info("Resetting PIN for PAN: " + pan);
            Logger.getGlobal().info("Note: New PIN will be generated by AWS Payment Cryptography Service");
            
            // Validate PAN format
            if (!pan.matches("^[0-9]+$")) {
                throw new IllegalArgumentException("Invalid PAN format. PAN must contain only digits. Received: '" + pan + "'");
            }
            
            // Generate new random PIN with PVV encrypted with PEK
            Logger.getGlobal().info("Requesting AWS Payment Cryptography to generate random 4-digit PIN...");
            GeneratePinDataResponse pinDataResponse = dataPlaneClient.generatePinData(
                GeneratePinDataRequest.builder()
                    .generationKeyIdentifier(pgkKeyArn)
                    .encryptionKeyIdentifier(pekKeyArn)
                    .primaryAccountNumber(pan)
                    .pinBlockFormat(PinBlockFormatForPinData.ISO_FORMAT_0)
                    .pinDataLength(4)
                    .generationAttributes(
                        PinGenerationAttributes.builder()
                            .visaPin(
                                VisaPin.builder()
                                    .pinVerificationKeyIndex(1)
                                    .build()
                            )
                            .build()
                    )
                    .build()
            );
            
            String pekEncryptedPinBlock = pinDataResponse.encryptedPinBlock();
            String pvv = pinDataResponse.pinData().verificationValue();
            Logger.getGlobal().info("AWS Payment Cryptography generated random PIN");
            Logger.getGlobal().info("PEK encrypted PIN block: " + pekEncryptedPinBlock);
            Logger.getGlobal().info("Generated PVV: " + pvv);
            
            // Sign the client's CSR with local CA
            String actualSignedCertificate = caManager.signCSR(csr);
            Logger.getGlobal().info("Signed client certificate with local CA");
            
            // Build wrapped key for ECDH
            WrappedKeyMaterial wrappedKeyMaterial = buildWrappedKeyMaterial(actualSignedCertificate, sharedInfo);
            
            // Translate PIN from PEK encryption to ECDH encryption
            Logger.getGlobal().info("Translating PIN: PEK (ISO Format 0) → ECDH (ISO Format 4)...");
            TranslatePinDataResponse translateResponse = dataPlaneClient.translatePinData(
                TranslatePinDataRequest.builder()
                    .encryptedPinBlock(pekEncryptedPinBlock)
                    .incomingKeyIdentifier(pekKeyArn)
                    .incomingTranslationAttributes(
                        TranslationIsoFormats.builder()
                            .isoFormat0(
                                TranslationPinDataIsoFormat034.builder()
                                    .primaryAccountNumber(pan)
                                    .build()
                            )
                            .build()
                    )
                    .outgoingKeyIdentifier(ecdhKeyArn)
                    .outgoingWrappedKey(
                        WrappedKey.builder()
                            .wrappedKeyMaterial(wrappedKeyMaterial)
                            .build()
                    )
                    .outgoingTranslationAttributes(
                        TranslationIsoFormats.builder()
                            .isoFormat4(
                                TranslationPinDataIsoFormat034.builder()
                                    .primaryAccountNumber(pan)
                                    .build()
                            )
                            .build()
                    )
                    .build()
            );
            
            String ecdhEncryptedPinBlock = translateResponse.pinBlock();
            Logger.getGlobal().info("ECDH encrypted PIN block: " + ecdhEncryptedPinBlock);
            
            JSONObject response = new JSONObject();
            response.put("status", "success");
            response.put("ecdhEncryptedPinBlock", ecdhEncryptedPinBlock);
            response.put("pekEncryptedPinBlock", pekEncryptedPinBlock);
            response.put("pvv", pvv);
            
            Logger.getGlobal().info("✓ PIN reset successfully for PAN: " + pan);
            Logger.getGlobal().info("=== RESET PIN COMPLETE ===\n");
            return response.toString();
            
        } catch (Exception e) {
            e.printStackTrace();
            JSONObject error = new JSONObject();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return error.toString();
        }
    }
    
    /**
     * Build WrappedKeyMaterial for ECDH operations.
     */
    private WrappedKeyMaterial buildWrappedKeyMaterial(String signedCertificate, String sharedInfo) {
        // Base64 encode the PEM certificate (AWS expects double encoding)
        String base64Cert = Base64.getEncoder().encodeToString(
            signedCertificate.getBytes(StandardCharsets.UTF_8)
        );
        
        return WrappedKeyMaterial.builder()
            .diffieHellmanSymmetricKey(
                EcdhDerivationAttributes.builder()
                    .certificateAuthorityPublicKeyIdentifier(caPublicKeyArn)
                    .keyAlgorithm("AES_128")
                    .keyDerivationFunction(KeyDerivationFunction.NIST_SP800)
                    .keyDerivationHashAlgorithm(KeyDerivationHashAlgorithm.SHA_256)
                    .publicKeyCertificate(base64Cert)
                    .sharedInformation(sharedInfo)
                    .build()
            )
            .build();
    }
}
