package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func CertificateFromPEM(pemBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}
