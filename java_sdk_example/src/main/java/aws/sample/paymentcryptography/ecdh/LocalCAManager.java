package aws.sample.paymentcryptography.ecdh;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.logging.Logger;

/**
 * Local Certificate Authority Manager for ECDH demo.
 * Creates a self-signed CA and signs client certificates.
 */
public class LocalCAManager {
    
    private static final String CA_KEY_FILE = "ca-private-key.pem";
    private static final String CA_CERT_FILE = "ca-certificate.pem";
    private static final long CERT_VALIDITY_DAYS = 365;
    
    private KeyPair caKeyPair;
    private X509Certificate caCertificate;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    /**
     * Initialize CA - load existing or create new.
     */
    public LocalCAManager() throws Exception {
        File caKeyFile = new File(CA_KEY_FILE);
        File caCertFile = new File(CA_CERT_FILE);
        
        if (caKeyFile.exists() && caCertFile.exists()) {
            Logger.getGlobal().info("Loading existing local CA...");
            loadCA();
        } else {
            Logger.getGlobal().info("Creating new local CA...");
            createCA();
            saveCA();
        }
        
        Logger.getGlobal().info("Local CA initialized successfully");
        Logger.getGlobal().info("  CA Subject: " + caCertificate.getSubjectX500Principal());
    }
    
    /**
     * Create a new self-signed CA certificate.
     */
    private void createCA() throws Exception {
        // Generate EC key pair for CA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        caKeyPair = keyPairGenerator.generateKeyPair();
        
        // Create self-signed CA certificate
        X500Name issuer = new X500Name("CN=ECDH Demo CA, O=AWS Payment Cryptography Demo, C=US");
        X500Name subject = issuer; // Self-signed
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (CERT_VALIDITY_DAYS * 24 * 60 * 60 * 1000L));
        
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer,
            serial,
            notBefore,
            notAfter,
            subject,
            caKeyPair.getPublic()
        );
        
        // Add CA extensions
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(Extension.keyUsage, true, 
            new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        
        // Sign the certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC")
            .build(caKeyPair.getPrivate());
        
        X509CertificateHolder certHolder = certBuilder.build(signer);
        caCertificate = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certHolder);
    }
    
    /**
     * Sign a client CSR with the CA.
     */
    public String signCSR(String csrPem) throws Exception {
        // Parse the CSR - use PEMParser for proper PEM handling
        org.bouncycastle.openssl.PEMParser pemParser = new org.bouncycastle.openssl.PEMParser(
            new java.io.StringReader(csrPem)
        );
        
        Object parsedObject = pemParser.readObject();
        pemParser.close();
        
        if (!(parsedObject instanceof PKCS10CertificationRequest)) {
            throw new IllegalArgumentException("Invalid CSR format");
        }
        
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parsedObject;
        
        // Extract subject and public key from CSR
        X500Name subject = csr.getSubject();
        PublicKey publicKey = new JcaPKCS10CertificationRequest(csr).getPublicKey();
        
        // Create certificate
        X500Name issuer = new X500Name(caCertificate.getSubjectX500Principal().getName());
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (1 * 24 * 60 * 60 * 1000L)); // 1 day validity
        
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer,
            serial,
            notBefore,
            notAfter,
            subject,
            publicKey
        );
        
        // Add extensions for end-entity certificate
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true, 
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement));
        
        // Sign with CA private key
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC")
            .build(caKeyPair.getPrivate());
        
        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate signedCert = new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certHolder);
        
        // Convert to PEM
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(signedCert);
        }
        
        return writer.toString();
    }
    
    /**
     * Get CA certificate in PEM format.
     */
    public String getCACertificatePEM() throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(caCertificate);
        }
        return writer.toString();
    }
    
    /**
     * Get CA certificate.
     */
    public X509Certificate getCACertificate() {
        return caCertificate;
    }
    
    /**
     * Save CA to files.
     */
    private void saveCA() throws Exception {
        // Save private key
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(CA_KEY_FILE))) {
            pemWriter.writeObject(caKeyPair.getPrivate());
        }
        
        // Save certificate
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(CA_CERT_FILE))) {
            pemWriter.writeObject(caCertificate);
        }
        
        Logger.getGlobal().info("CA saved to files:");
        Logger.getGlobal().info("  Private key: " + CA_KEY_FILE);
        Logger.getGlobal().info("  Certificate: " + CA_CERT_FILE);
    }
    
    /**
     * Load CA from files.
     */
    private void loadCA() throws Exception {
        // Load private key from PEM file
        try (PEMParser pemParser = new PEMParser(new FileReader(CA_KEY_FILE))) {
            Object object = pemParser.readObject();
            
            if (object instanceof PEMKeyPair) {
                // Handle PEM key pair format
                PEMKeyPair pemKeyPair = (PEMKeyPair) object;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                caKeyPair = converter.getKeyPair(pemKeyPair);
            } else if (object instanceof PrivateKeyInfo) {
                // Handle PKCS#8 format
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
                
                // We need to reconstruct the public key from the certificate
                // Load certificate first to get public key
                try (FileInputStream fis = new FileInputStream(CA_CERT_FILE)) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate tempCert = (X509Certificate) cf.generateCertificate(fis);
                    caKeyPair = new KeyPair(tempCert.getPublicKey(), privateKey);
                }
            } else {
                throw new IllegalStateException("Unexpected key format: " + object.getClass().getName());
            }
        }
        
        // Load certificate from PEM file
        try (FileInputStream fis = new FileInputStream(CA_CERT_FILE)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            caCertificate = (X509Certificate) cf.generateCertificate(fis);
        }
        
        Logger.getGlobal().info("CA loaded from files:");
        Logger.getGlobal().info("  Private key: " + CA_KEY_FILE);
        Logger.getGlobal().info("  Certificate: " + CA_CERT_FILE);
    }
}
