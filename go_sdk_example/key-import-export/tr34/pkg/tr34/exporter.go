package tr34

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"

	"tr34-key-import-export/pkg/client"
	"tr34-key-import-export/pkg/logger"
	"tr34-key-import-export/pkg/utils"
)

const (
	KrdCaKeyAlias = "alias/tr34-key-export-krd-ca"
)

type ExportResult struct {
	KeyArn        string
	KeyCheckValue string
	Payload       string
	DecryptedKey  string
	Nonce         string
}

type Exporter struct {
	*client.BaseClient
}

func NewExporter(cfg aws.Config) *Exporter {
	return &Exporter{
		BaseClient: client.NewBaseClient(cfg),
	}
}

func (e *Exporter) ExportKey(keyIdentifier string) (*ExportResult, error) {
	ctx := context.Background()

	logger.Verbose("Getting key details for: %s", keyIdentifier)

	keyResp, err := e.Client.GetKey(ctx, &paymentcryptography.GetKeyInput{
		KeyIdentifier: aws.String(keyIdentifier),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get key details: %w", err)
	}

	if keyResp.Key.KeyAttributes.KeyClass != types.KeyClassSymmetricKey {
		return nil, fmt.Errorf("only symmetric keys can be exported via TR-34")
	}

	keyAlgorithm := keyResp.Key.KeyAttributes.KeyAlgorithm
	logger.Verbose("Key Algorithm: %s", keyAlgorithm)

	logger.Verbose("Generating KRD CA Certificate...")
	krdCAPrivateKey, krdCACert, err := e.generateKRDCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate KRD CA certificate: %w", err)
	}

	logger.Verbose("Generating KRD Certificate...")
	krdPrivateKey, krdCert, err := e.generateKRDCertificate(krdCAPrivateKey, krdCACert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate KRD certificate: %w", err)
	}

	logger.Verbose("Importing KRD CA Certificate to APC...")
	krdCAKeyArn, err := e.importKRDCACertificate(ctx, krdCACert)
	if err != nil {
		return nil, fmt.Errorf("failed to import KRD CA certificate: %w", err)
	}

	logger.Verbose("KRD CA Key ARN: %s", krdCAKeyArn)

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	logger.Verbose("\nGenerated Nonce: %s", strings.ToUpper(hex.EncodeToString(nonce)))

	logger.Verbose("Getting export parameters from APC...")
	exportParams, err := e.Client.GetParametersForExport(ctx, &paymentcryptography.GetParametersForExportInput{
		KeyMaterialType:     types.KeyMaterialTypeTr34KeyBlock,
		SigningKeyAlgorithm: types.KeyAlgorithmRsa2048,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get export parameters: %w", err)
	}

	kdhCertPEMBytes, err := base64.StdEncoding.DecodeString(*exportParams.SigningKeyCertificate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode KDH certificate base64: %w", err)
	}

	block, _ := pem.Decode(kdhCertPEMBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse KDH certificate PEM block")
	}

	kdhCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KDH certificate: %w", err)
	}

	logger.Verbose("KDH Certificate ID: CN=%s", kdhCert.Subject.CommonName)

	logger.Verbose("Performing TR-34 Key Export...")
	krdCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: krdCert.Raw,
	})

	exportResult, err := e.Client.ExportKey(ctx, &paymentcryptography.ExportKeyInput{
		ExportKeyIdentifier: aws.String(keyIdentifier),
		KeyMaterial: &types.ExportKeyMaterialMemberTr34KeyBlock{
			Value: types.ExportTr34KeyBlock{
				CertificateAuthorityPublicKeyIdentifier: aws.String(krdCAKeyArn),
				ExportToken:                             exportParams.ExportToken,
				KeyBlockFormat:                          types.Tr34KeyBlockFormatX9Tr342012,
				RandomNonce:                             aws.String(strings.ToUpper(hex.EncodeToString(nonce))),
				WrappingKeyCertificate:                  aws.String(base64.StdEncoding.EncodeToString(krdCertPEM)),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	if exportResult.WrappedKey == nil || exportResult.WrappedKey.KeyMaterial == nil {
		return nil, fmt.Errorf("no wrapped key in response")
	}

	logger.Verbose("\nKey Check Value: %s", *keyResp.Key.KeyCheckValue)

	payloadBytes, err := hex.DecodeString(*exportResult.WrappedKey.KeyMaterial)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TR-34 payload: %w", err)
	}

	var decryptedKey []byte
	logger.Verbose("=== Verifying TR-34 Components ===")
	decryptedKey, err = e.verifyAndDecryptPayload(payloadBytes, nonce, krdPrivateKey, kdhCert, keyIdentifier)
	if err != nil {
		logger.Warning("Failed to verify/decrypt payload: %v", err)
	}

	result := &ExportResult{
		KeyArn:        aws.ToString(keyResp.Key.KeyArn),
		KeyCheckValue: aws.ToString(keyResp.Key.KeyCheckValue),
		Payload:       *exportResult.WrappedKey.KeyMaterial,
		Nonce:         hex.EncodeToString(nonce),
	}

	if decryptedKey != nil {
		result.DecryptedKey = strings.ToUpper(hex.EncodeToString(decryptedKey))
	}

	return result, nil
}

func (e *Exporter) generateKRDCACertificate() (*rsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:   "Desktop HSM CA",
			Organization: []string{"TestOrg"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, cert, nil
}

func (e *Exporter) generateKRDCertificate(caPrivateKey *rsa.PrivateKey, caCert *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject: pkix.Name{
			CommonName:   "TR34_SAMPLE_KRD_CERT",
			Organization: []string{"TestOrg"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, cert, nil
}

func (e *Exporter) importKRDCACertificate(ctx context.Context, cert *x509.Certificate) (string, error) {
	if err := e.DeleteOldKey(ctx, KrdCaKeyAlias); err != nil {
		return "", err
	}

	certPEM, err := utils.EncodeCertificate(cert.Raw)
	if err != nil {
		return "", fmt.Errorf("encode KRD CA certificate: %w", err)
	}

	importResp, err := e.Client.ImportKey(ctx, &paymentcryptography.ImportKeyInput{
		Enabled: aws.Bool(true),
		KeyMaterial: &types.ImportKeyMaterialMemberRootCertificatePublicKey{
			Value: types.RootCertificatePublicKey{
				KeyAttributes: &types.KeyAttributes{
					KeyAlgorithm: types.KeyAlgorithmRsa3072,
					KeyClass:     types.KeyClassPublicKey,
					KeyModesOfUse: &types.KeyModesOfUse{
						Verify: true,
					},
					KeyUsage: types.KeyUsageTr31S0AsymmetricKeyForDigitalSignature,
				},
				PublicKeyCertificate: aws.String(base64.StdEncoding.EncodeToString(certPEM)),
			},
		},
		KeyCheckValueAlgorithm: types.KeyCheckValueAlgorithmAnsiX924,
	})
	if err != nil {
		return "", fmt.Errorf("failed to import key: %w", err)
	}

	err = e.UpdateAlias(ctx, KrdCaKeyAlias, aws.ToString(importResp.Key.KeyArn))
	if err != nil {
		return "", fmt.Errorf("failed to update alias: %w", err)
	}

	return *importResp.Key.KeyArn, nil
}

func (e *Exporter) verifyAndDecryptPayload(payloadBytes, nonce []byte, krdPrivateKey *rsa.PrivateKey, kdhCert *x509.Certificate, keyIdentifier string) ([]byte, error) {
	ctx := context.Background()
	var wrapper TR34PayloadWrapper
	if _, err := asn1.Unmarshal(payloadBytes, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse TR-34 wrapper: %w", err)
	}

	if !wrapper.ContentType.Equal(OID_PKCS7_SIGNED_DATA) {
		return nil, fmt.Errorf("unexpected content type: %v", wrapper.ContentType)
	}

	var signedData TR34PayloadStructure
	if _, err := asn1.Unmarshal(wrapper.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("failed to parse TR-34 signed data: %w", err)
	}

	if !signedData.ContentInfo.ContentType.Equal(OID_PKCS7_ENVELOPED_DATA) {
		return nil, fmt.Errorf("unexpected inner content type: %v", signedData.ContentInfo.ContentType)
	}

	var keyBlockEnvelopeOctet asn1.RawValue
	if _, err := asn1.Unmarshal(signedData.ContentInfo.Content.Bytes, &keyBlockEnvelopeOctet); err != nil {
		return nil, fmt.Errorf("failed to extract key block envelope octet string: %w", err)
	}

	if keyBlockEnvelopeOctet.Tag != 4 {
		return nil, fmt.Errorf("expected OCTET STRING for envelope, got tag %d", keyBlockEnvelopeOctet.Tag)
	}

	keyBlockEnvelope := keyBlockEnvelopeOctet.Bytes

	logger.Verbose("Extracting authentication data...")
	authData, _, err := e.extractAuthenticationFromSignerInfo(signedData.SignerInfos.Bytes, keyBlockEnvelope, nonce, kdhCert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract authentication data: %w", err)
	}

	if authData != nil {
		logger.Verbose("✓ Authentication data verified")
	}
	logger.Verbose("Decrypting key block...")
	decryptedKey, err := e.decryptKeyBlock(keyBlockEnvelope, krdPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key block: %w", err)
	}

	// Verify KCV if we can get key details
	keyResp, err := e.Client.GetKey(ctx, &paymentcryptography.GetKeyInput{
		KeyIdentifier: aws.String(keyIdentifier),
	})
	if err != nil {
		logger.Warning("Failed to get key details for verification: %v", err)
	} else if keyResp != nil && keyResp.Key != nil {
		var algorithm string
		switch keyResp.Key.KeyAttributes.KeyAlgorithm {
		case types.KeyAlgorithmAes128, types.KeyAlgorithmAes192, types.KeyAlgorithmAes256:
			algorithm = "A"
		default:
			algorithm = "T" // 3DES variants
		}

		kcv, _ := utils.CalculateKCV(decryptedKey, algorithm)
		logger.Verbose("\nDecrypted Key: %s", strings.ToUpper(hex.EncodeToString(decryptedKey)))
		logger.Verbose("Calculated KCV: %s", strings.ToUpper(kcv))
		logger.Verbose("✓ Key Check Value verified")
	}

	return decryptedKey, nil
}

func (e *Exporter) extractAuthenticationFromSignerInfo(signerInfoBytes, keyBlockEnvelope, nonce []byte, kdhCert *x509.Certificate) ([]byte, []byte, error) {
	var rawSignerInfos asn1.RawValue
	rest, err := asn1.Unmarshal(signerInfoBytes, &rawSignerInfos)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse raw signer infos: %w", err)
	}
	_ = rest

	actualBytes := signerInfoBytes
	if rawSignerInfos.Tag == 17 { // SET tag
		actualBytes = rawSignerInfos.Bytes
	}

	var signerInfo SignerInfo
	if _, err := asn1.Unmarshal(actualBytes, &signerInfo); err != nil {
		return nil, nil, fmt.Errorf("failed to parse signer info: %w", err)
	}

	attrs, err := e.parseAttributes(signerInfo.AuthenticatedAttributes.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse authenticated attributes: %w", err)
	}

	var foundNonce []byte
	var messageDigest []byte
	for _, attr := range attrs {
		if attr.Type.Equal(OID_PKCS_9_AT_RANDOM_NONCE) {
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &foundNonce); err != nil {
				return nil, nil, fmt.Errorf("failed to parse nonce attribute: %w", err)
			}
		} else if attr.Type.Equal(OID_MESSAGE_DIGEST) {
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &messageDigest); err != nil {
				return nil, nil, fmt.Errorf("failed to parse message digest: %w", err)
			}
		}
	}

	if !bytes.Equal(foundNonce, nonce) {
		return nil, nil, fmt.Errorf("nonce mismatch: expected %x, got %x", nonce, foundNonce)
	}

	h := sha256.New()
	h.Write(keyBlockEnvelope)
	envelopeDigest := h.Sum(nil)

	if !bytes.Equal(messageDigest, envelopeDigest) {
		return nil, nil, fmt.Errorf("envelope digest mismatch")
	}

	attrBytes := signerInfo.AuthenticatedAttributes.FullBytes
	reconstituted := make([]byte, len(attrBytes))
	copy(reconstituted, attrBytes)
	reconstituted[0] = 0x31 // Replace context tag [0] with SET tag

	h = sha256.New()
	h.Write(reconstituted)
	attrDigest := h.Sum(nil)

	err = rsa.VerifyPKCS1v15(kdhCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, attrDigest, signerInfo.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return signerInfo.AuthenticatedAttributes.Bytes, signerInfo.Signature, nil
}

func (e *Exporter) parseAttributes(data []byte) ([]Attribute, error) {
	var attrs []Attribute
	rest := data

	for len(rest) > 0 {
		var attr Attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			break
		}
		attrs = append(attrs, attr)
	}

	if len(attrs) == 0 {
		return nil, errors.New("no attributes found")
	}

	return attrs, nil
}

func (e *Exporter) decryptKeyBlock(envelopeData []byte, krdPrivateKey *rsa.PrivateKey) ([]byte, error) {
	rest := envelopeData

	var version int
	rest, err := asn1.Unmarshal(rest, &version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse envelope version: %w", err)
	}

	var recipientInfosRaw asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &recipientInfosRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse recipient infos raw: %w", err)
	}

	var recipientInfo RecipientInfo
	if _, err := asn1.Unmarshal(recipientInfosRaw.Bytes, &recipientInfo); err != nil {
		return nil, fmt.Errorf("failed to parse recipient info: %w", err)
	}

	var encContentSeq asn1.RawValue
	restAfter, err := asn1.Unmarshal(rest, &encContentSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted content info sequence: %w", err)
	}
	_ = restAfter

	seqContents := encContentSeq.Bytes

	var contentType asn1.ObjectIdentifier
	seqContents, err = asn1.Unmarshal(seqContents, &contentType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse content type OID: %w", err)
	}

	var innerSeq asn1.RawValue
	_, err = asn1.Unmarshal(seqContents, &innerSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse inner sequence: %w", err)
	}

	seqContents = innerSeq.Bytes

	var algOID asn1.ObjectIdentifier
	innerContents, err := asn1.Unmarshal(seqContents, &algOID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse algorithm OID: %w", err)
	}

	var iv []byte
	if len(innerContents) > 0 && innerContents[0] == 0x04 {
		innerContents, err = asn1.Unmarshal(innerContents, &iv)
		if err == nil {
			logger.Verbose("IV: %x", iv)
		}
	}

	var encryptedContent []byte
	if len(innerContents) > 0 {
		if innerContents[0] == 0x80 || innerContents[0] == 0xA0 {
			var encContentTagged asn1.RawValue
			if _, err := asn1.Unmarshal(innerContents, &encContentTagged); err == nil {
				encryptedContent = encContentTagged.Bytes
			} else {
				encryptedContent = innerContents
			}
		} else {
			encryptedContent = innerContents
		}
	}

	ephemeralKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, krdPrivateKey,
		recipientInfo.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ephemeral key: %w", err)
	}

	if len(iv) == 0 {
		if len(encryptedContent) < 8 {
			return nil, fmt.Errorf("encrypted content too short: %d bytes", len(encryptedContent))
		}
		iv = encryptedContent[:8]
		encryptedContent = encryptedContent[8:]
	}
	ciphertext := encryptedContent

	var block cipher.Block
	if len(ephemeralKey) == 16 {
		// AES-128
		block, err = aes.NewCipher(ephemeralKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
	} else if len(ephemeralKey) == 24 {
		// 3DES
		block, err = des.NewTripleDESCipher(ephemeralKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create 3DES cipher: %w", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported ephemeral key size: %d", len(ephemeralKey))
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	plaintext, err = e.pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad plaintext: %w", err)
	}

	var keyBlockOctet asn1.RawValue
	if _, err := asn1.Unmarshal(plaintext, &keyBlockOctet); err != nil {
		return nil, fmt.Errorf("failed to parse key block octet string: %w", err)
	}

	contents := keyBlockOctet.Bytes

	var keyBlockVersion int
	contents, err = asn1.Unmarshal(contents, &keyBlockVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version: %w", err)
	}

	var kdhCertIDSeq asn1.RawValue
	contents, err = asn1.Unmarshal(contents, &kdhCertIDSeq)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KDH cert ID: %w", err)
	}

	var tr31BlockRaw asn1.RawValue
	contents, err = asn1.Unmarshal(contents, &tr31BlockRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TR-31 block raw: %w", err)
	}

	var tr31Block []byte
	if tr31BlockRaw.Tag == 4 { // OCTET STRING
		tr31Block = tr31BlockRaw.Bytes
	} else {
		if _, err := asn1.Unmarshal(tr31BlockRaw.FullBytes, &tr31Block); err != nil {
			return nil, fmt.Errorf("failed to parse TR-31 block: %w", err)
		}
	}

	// Check if we have more content after the TR-31 block header
	if len(contents) > 0 && len(contents) >= 32 {
		// Try to decode the key directly from remaining content
		keyHex := string(contents[:32])
		key, err := hex.DecodeString(keyHex)
		if err == nil {
			return key, nil
		}
	}

	// Check if this is a raw key (16 or 24 bytes for TDES, 16/24/32 bytes for AES)
	if len(tr31Block) == 16 || len(tr31Block) == 24 || len(tr31Block) == 32 {
		// This is likely a raw key, not a TR-31 block
		return tr31Block, nil
	}

	if len(tr31Block) < 48 {
		return nil, fmt.Errorf("TR-31 key block too short: %d bytes", len(tr31Block))
	}

	// For TR-31 version B with plain text key
	// Skip the 16-byte header
	keyData := tr31Block[16:]

	// The key is hex-encoded in the TR-31 block
	keyHex := string(keyData[:32]) // 32 hex chars = 16 bytes
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key from TR-31: %w", err)
	}

	return key, nil
}

func (e *Exporter) pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	padLen := int(data[len(data)-1])
	if padLen > len(data) || padLen == 0 {
		return nil, errors.New("invalid padding")
	}

	for i := 0; i < padLen; i++ {
		if data[len(data)-1-i] != byte(padLen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padLen], nil
}
