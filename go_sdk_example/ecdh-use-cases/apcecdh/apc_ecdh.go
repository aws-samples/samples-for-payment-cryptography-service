package apcecdh

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"ecdh-use-cases/usecases"
	"ecdh-use-cases/utils"
	"encoding/base64"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
)

type AWSPaymentCryptographyECDH struct {
	keyArns    []*string
	ecdhPacket *usecases.ECDHPacket
	apcClient  *paymentcryptography.Client
}

// Setup performs all APC ECDH base steps, returning a condensed packet with
// useful information for more specialized operations.
func (apcECDH *AWSPaymentCryptographyECDH) Setup(ctx context.Context, curve elliptic.Curve, derivedKeyUsage types.DeriveKeyUsage) (packet *usecases.ECDHPacket, err error) {
	if apcECDH.ecdhPacket != nil {
		return apcECDH.ecdhPacket, nil
	}

	apcCurveAlgorithm, ok := map[elliptic.Curve]types.KeyAlgorithm{
		elliptic.P256(): types.KeyAlgorithmEccNistP256,
		elliptic.P384(): types.KeyAlgorithmEccNistP384,
		elliptic.P521(): types.KeyAlgorithmEccNistP521,
	}[curve]
	if !ok {
		return nil, errors.New("elliptic curve algorithm not supported by APC")
	}

	// Party U Setup
	partyUKey, partyUCertPEM, partyUCAPEM, err := utils.GenerateECDHKeys(curve)
	if err != nil {
		return nil, err
	}

	partyUCAImportResp, err := apcECDH.apcClient.ImportKey(ctx, &paymentcryptography.ImportKeyInput{
		KeyMaterial: &types.ImportKeyMaterialMemberRootCertificatePublicKey{
			Value: types.RootCertificatePublicKey{
				KeyAttributes: &types.KeyAttributes{
					KeyAlgorithm:  apcCurveAlgorithm,
					KeyClass:      types.KeyClassPublicKey,
					KeyModesOfUse: &types.KeyModesOfUse{Verify: true},
					KeyUsage:      types.KeyUsageTr31S0AsymmetricKeyForDigitalSignature,
				},
				PublicKeyCertificate: aws.String(base64.StdEncoding.EncodeToString(partyUCAPEM)),
			},
		},
	})
	if err != nil {
		return nil, err
	}
	apcECDH.keyArns = append(apcECDH.keyArns, partyUCAImportResp.Key.KeyArn)
	// End Party U Setup

	// Party V Setup
	partyVECCPairResp, err := apcECDH.apcClient.CreateKey(ctx, &paymentcryptography.CreateKeyInput{
		Exportable: aws.Bool(true),
		KeyAttributes: &types.KeyAttributes{
			KeyAlgorithm: apcCurveAlgorithm,
			KeyUsage:     types.KeyUsageTr31K3AsymmetricKeyForKeyAgreement,
			KeyClass:     types.KeyClassAsymmetricKeyPair,
			KeyModesOfUse: &types.KeyModesOfUse{
				DeriveKey: true,
			},
		},
		DeriveKeyUsage: derivedKeyUsage,
	})
	if err != nil {
		return nil, err
	}
	apcECDH.keyArns = append(apcECDH.keyArns, partyVECCPairResp.Key.KeyArn)

	partyVCertResp, err := apcECDH.apcClient.GetPublicKeyCertificate(ctx, &paymentcryptography.GetPublicKeyCertificateInput{
		KeyIdentifier: partyVECCPairResp.Key.KeyArn,
	})
	if err != nil {
		return nil, err
	}

	partyVCertPEM, err := base64.StdEncoding.DecodeString(aws.ToString(partyVCertResp.KeyCertificate))
	if err != nil {
		return nil, err
	}

	partyVCert, err := utils.CertificateFromPEM(partyVCertPEM)
	if err != nil {
		return nil, err
	}

	partyVPubKey, ok := partyVCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, err
	}
	// End Party V Setup

	// ECDH Secret Exchange
	partyUECDHKey, err := partyUKey.ECDH()
	if err != nil {
		return nil, err
	}

	partyVECDHPubKey, err := partyVPubKey.ECDH()
	if err != nil {
		return nil, err
	}

	secret, err := partyUECDHKey.ECDH(partyVECDHPubKey)
	if err != nil {
		return nil, err
	}
	// End ECDH Secret Exchange

	apcECDH.ecdhPacket = &usecases.ECDHPacket{
		SharedSecret:        secret,
		PartyUCAArn:         aws.ToString(partyUCAImportResp.Key.KeyArn),
		PartyUCertPEM:       partyUCertPEM,
		PartyVECCKeyPairArn: aws.ToString(partyVECCPairResp.Key.KeyArn),
	}

	return apcECDH.ecdhPacket, nil
}

// Cleanup performs any needed post execution cleanup, e.g. deleting generated keys
// from APC. This function should be deferred as soon as possible in the majority of
// cases.
func (apcECDH *AWSPaymentCryptographyECDH) Cleanup(ctx context.Context) {
	// Delete all ECDH-related keys
	for _, keyArn := range apcECDH.keyArns {
		apcECDH.apcClient.DeleteKey(ctx, &paymentcryptography.DeleteKeyInput{
			KeyIdentifier:   keyArn,
			DeleteKeyInDays: aws.Int32(3),
		})
	}

	apcECDH.ecdhPacket = nil
}

func New(awsConf aws.Config) *AWSPaymentCryptographyECDH {
	return &AWSPaymentCryptographyECDH{
		keyArns:    make([]*string, 0),
		ecdhPacket: nil,
		apcClient:  paymentcryptography.NewFromConfig(awsConf),
	}
}
