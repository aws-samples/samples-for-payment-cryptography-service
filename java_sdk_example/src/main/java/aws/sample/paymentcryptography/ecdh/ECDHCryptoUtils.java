package aws.sample.paymentcryptography.ecdh;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * Utility class for ECDH cryptographic operations including key generation,
 * key derivation, encryption/decryption, and certificate handling.
 */
public class ECDHCryptoUtils {
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * Generate an EC key pair using SECP256R1 curve (NIST P-256).
     */
    public static KeyPair generateECDHKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }
    
    /**
     * Generate a Certificate Signing Request (CSR) for the client's public key.
     */
    public static String generateCSR(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=ECDH Client");
        
        PKCS10CertificationRequestBuilder csrBuilder = 
            new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC")
            .build(keyPair.getPrivate());
        
        PKCS10CertificationRequest csr = csrBuilder.build(signer);
        
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(csr);
        }
        
        return writer.toString();
    }
    
    /**
     * Generate random shared info for key derivation.
     * Returns hex-encoded string as required by AWS Payment Cryptography.
     */
    public static String generateSharedInfo() {
        SecureRandom random = new SecureRandom();
        byte[] sharedInfo = new byte[32]; // 32 bytes = 256 bits (matching Python implementation)
        random.nextBytes(sharedInfo);
        return bytesToHex(sharedInfo); // Return hex-encoded, not base64
    }
    
    /**
     * Derive a symmetric key using ECDH and Concat KDF (NIST SP 800-56A).
     * 
     * @param privateKey Client's private key
     * @param peerCertificate Peer's certificate containing public key
     * @param sharedInfoHex Additional shared information for key derivation (hex-encoded)
     * @return Derived AES-128 key (16 bytes)
     */
    public static SecretKeySpec deriveSymmetricKey(
            PrivateKey privateKey, 
            X509Certificate peerCertificate,
            String sharedInfoHex) throws Exception {
        
        // Perform ECDH key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(peerCertificate.getPublicKey(), true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        
        // Convert hex-encoded shared info to bytes
        byte[] sharedInfo = hexToBytes(sharedInfoHex);
        
        // Perform Concat KDF (NIST SP 800-56Ar3)
        // Note: AWS uses AES-128 (16 bytes), matching Python implementation
        byte[] derivedKey = concatKDF(
            sharedSecret,
            16, // 128 bits for AES-128
            sharedInfo
        );
        
        return new SecretKeySpec(derivedKey, "AES");
    }
    
    /**
     * Concat KDF implementation (NIST SP 800-56A Rev. 3).
     */
    private static byte[] concatKDF(byte[] sharedSecret, int keyDataLen, byte[] otherInfo) 
            throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        int reps = (keyDataLen + 31) / 32; // Ceiling division for SHA-256 (32 bytes)
        
        for (int counter = 1; counter <= reps; counter++) {
            digest.reset();
            digest.update(ByteBuffer.allocate(4).putInt(counter).array());
            digest.update(sharedSecret);
            digest.update(otherInfo);
            baos.write(digest.digest());
        }
        
        byte[] derivedKeyMaterial = baos.toByteArray();
        byte[] result = new byte[keyDataLen];
        System.arraycopy(derivedKeyMaterial, 0, result, 0, keyDataLen);
        
        return result;
    }
    
    /**
     * Encrypt PIN block using AES-128-ECB for ECDH (ISO Format 4).
     * PIN block should be hex string (32 characters = 16 bytes), will be converted to bytes before encryption.
     * 
     * Note: Supports both ISO Format 0 (8 bytes) and ISO Format 4 (16 bytes).
     * Uses ECB mode with no padding.
     */
    public static String encrypt(String pinBlockHex, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        
        // Convert hex PIN block to bytes
        byte[] pinBlockBytes = hexToBytes(pinBlockHex);
        
        // Support both ISO Format 0 (8 bytes) and ISO Format 4 (16 bytes)
        if (pinBlockBytes.length != 8 && pinBlockBytes.length != 16) {
            throw new IllegalArgumentException("PIN block must be exactly 8 bytes (ISO Format 0) or 16 bytes (ISO Format 4)");
        }
        
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(pinBlockBytes);
        
        // Return encrypted data as hex
        return bytesToHex(encrypted);
    }
    
    /**
     * Decrypt PIN block using AES-128-ECB for ECDH.
     * Supports both ISO Format 0 (8 bytes) and ISO Format 4 (16 bytes).
     * 
     * Note: Uses ECB mode with no padding.
     */
    public static String decrypt(String ciphertextHex, SecretKeySpec key) throws Exception {
        byte[] encrypted = hexToBytes(ciphertextHex);
        
        // Support both ISO Format 0 (8 bytes) and ISO Format 4 (16 bytes)
        if (encrypted.length != 8 && encrypted.length != 16) {
            throw new IllegalArgumentException("Ciphertext must be exactly 8 bytes (ISO Format 0) or 16 bytes (ISO Format 4)");
        }
        
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        byte[] decrypted = cipher.doFinal(encrypted);
        return bytesToHex(decrypted);
    }
    
    /**
     * Parse PEM-encoded certificate to X509Certificate.
     */
    public static X509Certificate parseCertificate(String pemCertificate) throws Exception {
        pemCertificate = pemCertificate.replace("\\n", "\n");
        
        try (StringReader reader = new StringReader(pemCertificate);
             PEMParser pemParser = new PEMParser(reader)) {
            
            Object object = pemParser.readObject();
            
            if (object instanceof X509CertificateHolder) {
                X509CertificateHolder certHolder = (X509CertificateHolder) object;
                return new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certHolder);
            } else {
                // Try standard certificate factory
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(pemCertificate.getBytes())
                );
            }
        }
    }
    
    /**
     * Convert hex string to byte array.
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    /**
     * Convert byte array to hex string.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}
