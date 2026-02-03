package utils

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func EncodeCertificate(certDER []byte) ([]byte, error) {
	buf := &bytes.Buffer{}
	err := pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err != nil {
		return nil, fmt.Errorf("encode certificate: %w", err)
	}
	return buf.Bytes(), nil
}

func LoadPEMCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: not PEM or base64 format")
	}

	block, _ = pem.Decode(decoded)
	if block != nil {
		return x509.ParseCertificate(block.Bytes)
	}

	return x509.ParseCertificate(decoded)
}
