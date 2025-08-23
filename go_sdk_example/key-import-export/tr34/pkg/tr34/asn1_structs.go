package tr34

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// ASN.1 Object Identifiers for export
var (
	OID_PKCS7_SIGNED_DATA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OID_PKCS7_ENVELOPED_DATA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OID_PKCS7_DATA             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OID_MESSAGE_DIGEST         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OID_PKCS_9_AT_RANDOM_NONCE = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 25, 3}
)

// TR34 ASN.1 Structures for export functionality
type TR34PayloadWrapper struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit"`
}

type TR34PayloadStructure struct {
	Version          int           `asn1:"default:1"`
	DigestAlgorithms asn1.RawValue // Set of digest algorithms
	ContentInfo      TR34ContentInfo
	SignerInfos      asn1.RawValue // Set of signer infos
}

type TR34ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit"`
}

type SignerInfo struct {
	Version                   int
	IssuerAndSerialNumber     IssuerAndSerialNumber
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"tag:0,implicit,optional"`
	SignatureAlgorithm        pkix.AlgorithmIdentifier
	Signature                 []byte
	UnauthenticatedAttributes asn1.RawValue `asn1:"tag:1,implicit,optional"`
}

type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type RecipientInfo struct {
	Version                int
	IssuerAndSerialNumber  IssuerAndSerialNumber
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}
