package tr34

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
)

// OIDs used in TR-34 (raw bytes for building ASN.1 structures)
var (
	OID_MGF1, _         = hex.DecodeString("2A864886F70D010108")
	OID_SHA256, _       = hex.DecodeString("608648016503040201")
	OID_DES_EDE3_CBC, _ = hex.DecodeString("2A864886F70D0307")
	OID_AES128_CBC, _   = hex.DecodeString("608648016503040102")
	OID_RSAES_OEAP, _   = hex.DecodeString("2A864886F70D010107")
	OID_P_SPECIFIED, _  = hex.DecodeString("2A864886F70D010109")
	OID_CONTENT_TYPE, _ = hex.DecodeString("2A864886F70D010903")
)

// PayloadBuilder builds TR-34 payloads
type PayloadBuilder struct {
	KrdCert       *x509.Certificate
	KdhCertResult *CertificateResult
	ClearKey      []byte
	Header        []byte
	Nonce         []byte
}

func (b *PayloadBuilder) Build() ([]byte, error) {
	krdCertID := b.extractCertificateID(b.KrdCert)
	kdhCertID := b.extractCertificateID(b.KdhCertResult.Cert)

	keyBlock := b.buildKeyBlock(kdhCertID)

	// Determine block size and ephemeral key size based on algorithm
	// Default values for 3DES
	blockSize := 8
	ephemeralKeySize := 24

	if len(b.Header) >= 8 && b.Header[7] == 'A' {
		blockSize = 16
		ephemeralKeySize = 16
	}

	if len(keyBlock)%blockSize != 0 {
		paddingLength := blockSize - (len(keyBlock) % blockSize)
		padding := bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)
		keyBlock = append(keyBlock, padding...)
	}

	ephemeralKey := make([]byte, ephemeralKeySize)
	if _, err := rand.Read(ephemeralKey); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	encryptedKeyBlock, err := b.encryptKeyBlock(keyBlock, ephemeralKey, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key block: %w", err)
	}

	encryptedEphemeralKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		b.KrdCert.PublicKey.(*rsa.PublicKey),
		ephemeralKey,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt ephemeral key: %w", err)
	}

	envelope := b.buildEnvelope(krdCertID, encryptedEphemeralKey, encryptedKeyBlock, iv)

	envelopeDigest := sha256.Sum256(envelope)

	authData := b.buildAuthenticationData(envelopeDigest[:])

	authDataForSigning := b.wrapAuthDataForSigning(authData)
	authDataHash := sha256.Sum256(authDataForSigning)
	signature, err := rsa.SignPKCS1v15(rand.Reader, b.KdhCertResult.PrivKey, crypto.SHA256, authDataHash[:])
	if err != nil {
		return nil, fmt.Errorf("sign authentication data: %w", err)
	}

	payload := b.buildFinalPayload(envelope, kdhCertID, authData, signature)

	return payload, nil
}

func (b *PayloadBuilder) extractCertificateID(cert *x509.Certificate) []byte {
	var certStruct struct {
		TBSCertificate struct {
			Version      int `asn1:"optional,explicit,default:0,tag:0"`
			SerialNumber *big.Int
			SignatureAlg asn1.RawValue
			Issuer       asn1.RawValue
			Validity     asn1.RawValue
			Subject      asn1.RawValue
			PublicKey    asn1.RawValue
			Extensions   asn1.RawValue `asn1:"optional,explicit,tag:3"`
		}
		SignatureAlgorithm asn1.RawValue
		Signature          asn1.BitString
	}

	asn1.Unmarshal(cert.Raw, &certStruct)

	serialBytes, _ := asn1.Marshal(certStruct.TBSCertificate.SerialNumber)
	issuerBytes := certStruct.TBSCertificate.Issuer.FullBytes

	certID, _ := asn1.Marshal(asn1.RawValue{
		Tag:        16, // SEQUENCE
		Class:      0,
		IsCompound: true,
		Bytes:      append(issuerBytes, serialBytes...),
	})

	return certID
}

func (b *PayloadBuilder) buildKeyBlock(recipientID []byte) []byte {
	// Version
	versionBytes, _ := asn1.Marshal(1)

	// Key data (OCTET STRING)
	keyDataBytes, _ := asn1.Marshal(asn1.RawValue{
		Tag:   4,
		Class: 0,
		Bytes: b.ClearKey,
	})

	// Key attributes
	oidBytes, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
	headerOctetBytes, _ := asn1.Marshal(asn1.RawValue{
		Tag:   4,
		Class: 0,
		Bytes: b.Header,
	})
	setBytes, _ := asn1.Marshal(asn1.RawValue{
		Tag:        17, // SET
		Class:      0,
		IsCompound: true,
		Bytes:      headerOctetBytes,
	})
	keyAttrBytes, _ := asn1.Marshal(asn1.RawValue{
		Tag:        16, // SEQUENCE
		Class:      0,
		IsCompound: true,
		Bytes:      append(oidBytes, setBytes...),
	})

	// Combine all
	allBytes := append(versionBytes, recipientID...)
	allBytes = append(allBytes, keyDataBytes...)
	allBytes = append(allBytes, keyAttrBytes...)

	keyBlock, _ := asn1.Marshal(asn1.RawValue{
		Tag:        16, // SEQUENCE
		Class:      0,
		IsCompound: true,
		Bytes:      allBytes,
	})

	return keyBlock
}

func (b *PayloadBuilder) encryptKeyBlock(keyBlock, key, iv []byte) ([]byte, error) {
	var block cipher.Block
	var err error

	// Determine cipher based on key length
	if len(key) == 16 {
		// AES-128
		block, err = aes.NewCipher(key)
	} else if len(key) == 24 {
		// 3DES
		block, err = des.NewTripleDESCipher(key)
	} else {
		return nil, fmt.Errorf("unsupported key length: %d", len(key))
	}

	if err != nil {
		return nil, err
	}

	if len(keyBlock)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("key block size must be multiple of block size")
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(keyBlock))
	mode.CryptBlocks(encrypted, keyBlock)

	return encrypted, nil
}

func (b *PayloadBuilder) buildEnvelope(recipientID, encryptedEphemeralKey, encryptedKeyBlock, iv []byte) []byte {
	// Version
	envVersionBytes, _ := asn1.Marshal(0)
	recipVersion, _ := asn1.Marshal(0)

	// Build RSAES-OAEP parameters
	rsaesOaepOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7})
	sha256Oid1, _ := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	nullBytes, _ := asn1.Marshal(asn1.RawValue{Tag: 5, Class: 0, Bytes: []byte{}})
	hashFuncSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(sha256Oid1, nullBytes...),
	})

	mgf1Oid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8})
	sha256Oid2, _ := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	mgfParamSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: sha256Oid2,
	})
	maskGenSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(mgf1Oid, mgfParamSeq...),
	})

	pSpecOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9})
	emptyOctet, _ := asn1.Marshal(asn1.RawValue{Tag: 4, Class: 0, Bytes: []byte{}})
	pSourceSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(pSpecOid, emptyOctet...),
	})

	oaepParams, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(append(hashFuncSeq, maskGenSeq...), pSourceSeq...),
	})

	keyEncAlgSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(rsaesOaepOid, oaepParams...),
	})

	encKeyOctet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 4, Class: 0,
		Bytes: encryptedEphemeralKey,
	})

	recipInfoSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(append(append(recipVersion, recipientID...), keyEncAlgSeq...), encKeyOctet...),
	})

	recipInfosSet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 17, Class: 0, IsCompound: true,
		Bytes: recipInfoSeq,
	})

	// Encrypted content info
	pkcs7DataOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})

	// Select encryption OID based on algorithm
	var encryptionOid []byte
	if len(b.Header) >= 8 && b.Header[7] == 'A' {
		// AES-128-CBC
		encryptionOid = append([]byte{0x06, 0x09}, OID_AES128_CBC...)
	} else {
		// 3DES-CBC
		encryptionOid = append([]byte{0x06, 0x08}, OID_DES_EDE3_CBC...)
	}

	ivOctet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 4, Class: 0,
		Bytes: iv,
	})
	encContent, _ := asn1.Marshal(asn1.RawValue{
		Tag: 0, Class: 2,
		Bytes: encryptedKeyBlock,
	})

	contentEncAlgBytes := append(encryptionOid, ivOctet...)
	innerSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(contentEncAlgBytes, encContent...),
	})

	encContentInfo, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(pkcs7DataOid, innerSeq...),
	})

	// Combine envelope
	envelope := append(append(envVersionBytes, recipInfosSet...), encContentInfo...)

	return envelope
}

func (b *PayloadBuilder) buildAuthenticationData(envelopeDigest []byte) []byte {
	// Content Type attribute
	contentTypeOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3})
	envelopedDataOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3})
	contentTypeSet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 17, Class: 0, IsCompound: true,
		Bytes: envelopedDataOid,
	})
	attr1, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(contentTypeOid, contentTypeSet...),
	})

	// Random Nonce attribute
	randomNonceOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 25, 3})
	nonceOctet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 4, Class: 0,
		Bytes: b.Nonce,
	})
	nonceSet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 17, Class: 0, IsCompound: true,
		Bytes: nonceOctet,
	})
	attr2, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(randomNonceOid, nonceSet...),
	})

	// Header attribute
	pkcs7DataOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
	headerOctet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 4, Class: 0,
		Bytes: b.Header,
	})
	headerSet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 17, Class: 0, IsCompound: true,
		Bytes: headerOctet,
	})
	attr3, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(pkcs7DataOid, headerSet...),
	})

	// Message Digest attribute
	messageDigestOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4})
	digestOctet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 4, Class: 0,
		Bytes: envelopeDigest,
	})
	digestSet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 17, Class: 0, IsCompound: true,
		Bytes: digestOctet,
	})
	attr4, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(messageDigestOid, digestSet...),
	})

	// Concatenate all attributes
	authData := append(append(append(attr1, attr2...), attr3...), attr4...)

	return authData
}

func (b *PayloadBuilder) wrapAuthDataForSigning(authData []byte) []byte {
	wrapped, _ := asn1.Marshal(asn1.RawValue{
		Tag: 17, Class: 0, IsCompound: true,
		Bytes: authData,
	})
	return wrapped
}

func (b *PayloadBuilder) buildFinalPayload(envelope []byte, signerID []byte, authData []byte, signature []byte) []byte {
	// SignedData OID
	signedDataOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})

	// Version
	signedVersion, _ := asn1.Marshal(1)

	// Digest algorithms
	sha256OidForDigest, _ := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	digestAlgSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: sha256OidForDigest,
	})
	digestAlgsSet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 17, Class: 0, IsCompound: true,
		Bytes: digestAlgSeq,
	})

	// Content info
	envelopedDataOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3})
	envelopedDataOctet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 4, Class: 0,
		Bytes: envelope,
	})
	envelopedDataContext, _ := asn1.Marshal(asn1.RawValue{
		Tag: 0, Class: 2, IsCompound: true,
		Bytes: envelopedDataOctet,
	})
	contentInfo, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(envelopedDataOid, envelopedDataContext...),
	})

	// Signer info
	signerVersion, _ := asn1.Marshal(1)
	sha256OidForSigner, _ := asn1.Marshal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	digestAlgForSigner, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: sha256OidForSigner,
	})

	authenticatedAttrs, _ := asn1.Marshal(asn1.RawValue{
		Tag: 0, Class: 2, IsCompound: true,
		Bytes: authData,
	})

	rsaEncryptionOid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1})
	rsaNull, _ := asn1.Marshal(asn1.RawValue{Tag: 5, Class: 0, Bytes: []byte{}})
	digestEncAlg, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(rsaEncryptionOid, rsaNull...),
	})

	encryptedDigest, _ := asn1.Marshal(asn1.RawValue{
		Tag: 4, Class: 0,
		Bytes: signature,
	})

	// Build signer info
	signerInfoBytes := signerVersion
	signerInfoBytes = append(signerInfoBytes, signerID...)
	signerInfoBytes = append(signerInfoBytes, digestAlgForSigner...)
	signerInfoBytes = append(signerInfoBytes, authenticatedAttrs...)
	signerInfoBytes = append(signerInfoBytes, digestEncAlg...)
	signerInfoBytes = append(signerInfoBytes, encryptedDigest...)

	signerInfoSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: signerInfoBytes,
	})

	signerInfosSet, _ := asn1.Marshal(asn1.RawValue{
		Tag: 17, Class: 0, IsCompound: true,
		Bytes: signerInfoSeq,
	})

	// Build SignedData
	signedDataBytes := signedVersion
	signedDataBytes = append(signedDataBytes, digestAlgsSet...)
	signedDataBytes = append(signedDataBytes, contentInfo...)
	signedDataBytes = append(signedDataBytes, signerInfosSet...)

	signedDataSeq, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: signedDataBytes,
	})

	signedDataContext, _ := asn1.Marshal(asn1.RawValue{
		Tag: 0, Class: 2, IsCompound: true,
		Bytes: signedDataSeq,
	})

	// Final ContentInfo
	payload, _ := asn1.Marshal(asn1.RawValue{
		Tag: 16, Class: 0, IsCompound: true,
		Bytes: append(signedDataOid, signedDataContext...),
	})

	return payload
}
