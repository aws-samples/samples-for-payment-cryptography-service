package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"
)

// GenerateECDHKeys build an ECC key set for ECDH.
func GenerateECDHKeys(curve elliptic.Curve) (privKey *ecdsa.PrivateKey, certPEM, caCertPEM []byte, err error) {
	caPrivKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	caCertTmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "Desktop HSM CA",
			Organization:       []string{"Asaptech"},
			OrganizationalUnit: []string{"Asapcard"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCertTmpl, caCertTmpl, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	caCertPEM = buf.Bytes()

	privKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	certTmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "Desktop HSM",
			Organization:       []string{"Asaptech"},
			OrganizationalUnit: []string{"Asapcard"},
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(30 * 24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTmpl, caCert, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	buf = new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM = buf.Bytes()

	return
}
