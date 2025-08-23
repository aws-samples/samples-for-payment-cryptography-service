package tr34

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
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
	KdhCaKeyAlias  = "alias/tr34-key-import-kdh-ca"
	ImportKeyAlias = "alias/tr34-key-import"
)

type ImportOptions struct {
	ExportMode string
	KeyType    string
	ModeOfUse  string
	Algorithm  string
	AliasName  string
}

type ImportResult struct {
	KeyArn        string
	KeyCheckValue string
	Payload       string
	Nonce         string
	SigningCert   string
}

type CertificateResult struct {
	Template *x509.Certificate
	CertDER  []byte
	CertPEM  []byte
	Cert     *x509.Certificate
	PrivKey  *rsa.PrivateKey
}

type Importer struct {
	*client.BaseClient
}

func NewImporter(cfg aws.Config) *Importer {
	return &Importer{
		BaseClient: client.NewBaseClient(cfg),
	}
}

func (i *Importer) ImportKey(clearKeyHex string, options ImportOptions) (*ImportResult, error) {
	ctx := context.Background()

	clearKey, err := utils.ParseHexString(clearKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid clear key: %w", err)
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	kdhCaResult, err := i.generateKdhCaCertificate()
	if err != nil {
		return nil, fmt.Errorf("generate KDH CA certificate: %w", err)
	}

	kdhCertResult, err := i.generateKdhCertificate(kdhCaResult)
	if err != nil {
		return nil, fmt.Errorf("generate KDH certificate: %w", err)
	}

	kdhCaKeyArn, err := i.setupKdhCa(ctx, kdhCaResult)
	if err != nil {
		return nil, fmt.Errorf("setup KDH CA: %w", err)
	}

	krdCert, importToken, err := i.getKrdCertificate(ctx)
	if err != nil {
		return nil, fmt.Errorf("get KRD certificate: %w", err)
	}

	header := ConstructHeader(options.Algorithm, options.KeyType, options.ModeOfUse, options.ExportMode)
	logger.Verbose("TR-34 Header: %s", string(header))

	builder := &PayloadBuilder{
		KrdCert:       krdCert,
		KdhCertResult: kdhCertResult,
		ClearKey:      clearKey,
		Header:        header,
		Nonce:         nonce,
	}

	payload, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build TR-34 payload: %w", err)
	}

	result := &ImportResult{
		Payload:     strings.ToUpper(hex.EncodeToString(payload)),
		Nonce:       strings.ToUpper(hex.EncodeToString(nonce)),
		SigningCert: base64.StdEncoding.EncodeToString(kdhCertResult.CertPEM),
	}

	keyArn, keyCheckValue, err := i.importToAWS(ctx, kdhCaKeyArn, importToken, result, options)
	if err != nil {
		return nil, fmt.Errorf("import key to AWS: %w", err)
	}

	result.KeyArn = keyArn
	result.KeyCheckValue = keyCheckValue

	return result, nil
}

func (i *Importer) generateKdhCaCertificate() (*CertificateResult, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName:   "Desktop HSM CA",
			Organization: []string{"TestOrg"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	certPEM, err := utils.EncodeCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("encode KDH CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse KDH CA certificate: %w", err)
	}

	return &CertificateResult{
		Template: template,
		CertDER:  certDER,
		CertPEM:  certPEM,
		Cert:     cert,
		PrivKey:  privKey,
	}, nil
}

func (i *Importer) generateKdhCertificate(kdhCaResult *CertificateResult) (*CertificateResult, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject: pkix.Name{
			CommonName:   "Desktop HSM",
			Organization: []string{"TestOrg"},
		},
		IsCA:                  false,
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, kdhCaResult.Template, &privKey.PublicKey, kdhCaResult.PrivKey)
	if err != nil {
		return nil, err
	}

	certPEM, err := utils.EncodeCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("encode KDH certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse KDH certificate: %w", err)
	}

	return &CertificateResult{
		Template: template,
		CertDER:  certDER,
		CertPEM:  certPEM,
		Cert:     cert,
		PrivKey:  privKey,
	}, nil
}

func (i *Importer) setupKdhCa(ctx context.Context, kdhCaResult *CertificateResult) (*string, error) {
	if err := i.DeleteOldKey(ctx, KdhCaKeyAlias); err != nil {
		return nil, err
	}

	importResp, err := i.Client.ImportKey(ctx, &paymentcryptography.ImportKeyInput{
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
				PublicKeyCertificate: aws.String(base64.StdEncoding.EncodeToString(kdhCaResult.CertPEM)),
			},
		},
		KeyCheckValueAlgorithm: types.KeyCheckValueAlgorithmAnsiX924,
	})
	if err != nil {
		return nil, err
	}

	if err := i.UpdateAlias(ctx, KdhCaKeyAlias, aws.ToString(importResp.Key.KeyArn)); err != nil {
		return nil, err
	}

	return importResp.Key.KeyArn, nil
}

func (i *Importer) getKrdCertificate(ctx context.Context) (*x509.Certificate, *string, error) {

	// RSA_3072 allows for an AES-128 ephemeral key to be used, extending TR-34 wrapped key support up to AES-128
	params, err := i.Client.GetParametersForImport(ctx, &paymentcryptography.GetParametersForImportInput{
		KeyMaterialType:      types.KeyMaterialTypeTr34KeyBlock,
		WrappingKeyAlgorithm: types.KeyAlgorithmRsa3072,
	})
	if err != nil {
		return nil, nil, err
	}

	certData, err := base64.StdEncoding.DecodeString(*params.WrappingKeyCertificate)
	if err != nil {
		return nil, nil, err
	}

	cert, err := utils.LoadPEMCertificate(certData)
	if err != nil {
		return nil, nil, err
	}

	return cert, params.ImportToken, nil
}

func (i *Importer) importToAWS(ctx context.Context, kdhCaKeyArn, importToken *string, result *ImportResult, options ImportOptions) (string, string, error) {
	if options.AliasName != "" {
		if err := i.DeleteOldKey(ctx, options.AliasName); err != nil {
			return "", "", err
		}
	}

	// Determine KCV algorithm based on key type
	var kcvAlgorithm types.KeyCheckValueAlgorithm
	if len(result.Payload) > 15 && result.Payload[7] == 'A' {
		// AES uses CMAC
		kcvAlgorithm = types.KeyCheckValueAlgorithmCmac
	} else {
		// 3DES uses ANSI X9.24
		kcvAlgorithm = types.KeyCheckValueAlgorithmAnsiX924
	}

	resp, err := i.Client.ImportKey(ctx, &paymentcryptography.ImportKeyInput{
		Enabled: aws.Bool(true),
		KeyMaterial: &types.ImportKeyMaterialMemberTr34KeyBlock{
			Value: types.ImportTr34KeyBlock{
				CertificateAuthorityPublicKeyIdentifier: kdhCaKeyArn,
				ImportToken:                             importToken,
				KeyBlockFormat:                          types.Tr34KeyBlockFormatX9Tr342012,
				SigningKeyCertificate:                   aws.String(result.SigningCert),
				WrappedKeyBlock:                         aws.String(result.Payload),
				RandomNonce:                             aws.String(result.Nonce),
			},
		},
		KeyCheckValueAlgorithm: kcvAlgorithm,
	})
	if err != nil {
		return "", "", err
	}

	if options.AliasName != "" {
		if err := i.UpdateAlias(ctx, options.AliasName, aws.ToString(resp.Key.KeyArn)); err != nil {
			return "", "", err
		}
	}

	return aws.ToString(resp.Key.KeyArn), aws.ToString(resp.Key.KeyCheckValue), nil
}

func ConstructHeader(algo, keyType, modeOfUse, exportMode string) []byte {
	versionID := "D" // ignored in tr-34
	length := "9999" // ignored in tr-34

	header := versionID + length + keyType + algo + modeOfUse + "00" + exportMode + "0000"
	return []byte(header)
}
