package usecases

import (
	"context"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	apctypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata"
	apcdtypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptographydata/types"
	"github.com/golang-crypto/concatkdf"
)

type pinSelect struct {
	pin          string
	pan          string
	apcClient    *paymentcryptography.Client
	apcdClient   *paymentcryptographydata.Client
	storagePEKID string
	pvkID        string
	keyArns      []*string
}

func (uc *pinSelect) Execute(ctx context.Context, ecdhPacket *ECDHPacket) error {
	pek, contextInfo, err := uc.derivePEK(ecdhPacket.SharedSecret)
	if err != nil {
		return errors.Join(errors.New("failed to derive PEK from shared secret"), err)
	}

	// Since uc.derivePEK derives a TDES2key PEK.
	pekTDESBlock, err := des.NewTripleDESCipher(append(pek, pek[:8]...))
	if err != nil {
		return errors.Join(errors.New("failed to create PEK TDES cipher block"), err)
	}

	encryptedPinBlock, err := uc.genPinBlockIsoFormat0(pekTDESBlock)
	if err != nil {
		return errors.Join(errors.New("failed to build ISO format 0 PIN Block"), err)
	}

	storagePEKID, err := uc.getStoragePEK(ctx)
	if err != nil {
		return errors.Join(errors.New("faile to retrieve storage PEK"), err)
	}

	translatePINBlockResp, err := uc.apcdClient.TranslatePinData(ctx, &paymentcryptographydata.TranslatePinDataInput{
		EncryptedPinBlock: aws.String(strings.ToUpper(hex.EncodeToString(encryptedPinBlock))),
		IncomingTranslationAttributes: &apcdtypes.TranslationIsoFormatsMemberIsoFormat0{
			Value: apcdtypes.TranslationPinDataIsoFormat034{
				PrimaryAccountNumber: aws.String(uc.pan),
			},
		},
		IncomingKeyIdentifier: aws.String(ecdhPacket.PartyVECCKeyPairArn),
		IncomingWrappedKey: &apcdtypes.WrappedKey{
			WrappedKeyMaterial: &apcdtypes.WrappedKeyMaterialMemberDiffieHellmanSymmetricKey{
				Value: apcdtypes.EcdhDerivationAttributes{
					CertificateAuthorityPublicKeyIdentifier: aws.String(ecdhPacket.PartyUCAArn),
					// Since uc.derivePEK derives a TDES2key PEK.
					KeyAlgorithm: apcdtypes.SymmetricKeyAlgorithmTdes2key,
					// Since uc.derivePEK uses ConcatKDF
					KeyDerivationFunction: apcdtypes.KeyDerivationFunctionNistSp800,
					// Since uc.derivePEK uses SHA-512 for ConcatKDF
					KeyDerivationHashAlgorithm: apcdtypes.KeyDerivationHashAlgorithmSha512,
					PublicKeyCertificate:       aws.String(base64.StdEncoding.EncodeToString(ecdhPacket.PartyUCertPEM)),
					SharedInformation:          aws.String(hex.EncodeToString(contextInfo)),
				},
			},
		},
		OutgoingTranslationAttributes: &apcdtypes.TranslationIsoFormatsMemberIsoFormat0{
			Value: apcdtypes.TranslationPinDataIsoFormat034{
				PrimaryAccountNumber: aws.String(uc.pan),
			},
		},
		OutgoingKeyIdentifier: aws.String(storagePEKID),
	})
	if err != nil {
		return errors.Join(errors.New("failed to translate PIN block"), err)
	}
	slog.Info("PIN block translated to storage PEK.", slog.String("storagePINBlock", aws.ToString(translatePINBlockResp.PinBlock)))

	pvkID, err := uc.getPVK(ctx)
	if err != nil {
		return errors.Join(errors.New("faile to retrieve PVK"), err)
	}

	genPVVResp, err := uc.apcdClient.GeneratePinData(ctx, &paymentcryptographydata.GeneratePinDataInput{
		EncryptionKeyIdentifier: aws.String(storagePEKID),
		GenerationKeyIdentifier: aws.String(pvkID),
		PinBlockFormat:          apcdtypes.PinBlockFormatForPinDataIsoFormat0,
		PrimaryAccountNumber:    aws.String(uc.pan),
		GenerationAttributes: &apcdtypes.PinGenerationAttributesMemberVisaPinVerificationValue{
			Value: apcdtypes.VisaPinVerificationValue{
				EncryptedPinBlock:       translatePINBlockResp.PinBlock,
				PinVerificationKeyIndex: aws.Int32(1),
			},
		},
	})
	if err != nil {
		return errors.Join(errors.New("failed to generate PVV"), err)
	}
	pvv, ok := genPVVResp.PinData.(*apcdtypes.PinDataMemberVerificationValue)
	if !ok {
		return errors.New("unexpected pin generation response; PVV not generated")
	}
	slog.Info("PVV generated successfully.", slog.String("pvv", pvv.Value))

	return nil
}

func (uc *pinSelect) Cleanup(ctx context.Context) {
	for _, keyArn := range uc.keyArns {
		uc.apcClient.DeleteKey(ctx, &paymentcryptography.DeleteKeyInput{
			KeyIdentifier:   keyArn,
			DeleteKeyInDays: aws.Int32(3),
		})
	}
}

// derivePEK derives a one-time use PEK from the ECDH shared
// secret, using ConcatKDF with SHA512 and requesting 16 bytes
// for a TDES double length PEK.
func (uc *pinSelect) derivePEK(sharedSecret []byte) (pek []byte, contextInfo []byte, err error) {
	otherInfo := make([]byte, 32)
	_, err = rand.Read(contextInfo)
	if err != nil {
		return nil, nil, err
	}

	pinEncKey, err := concatkdf.Key(sha512.New, sharedSecret, string(otherInfo), 16)
	if err != nil {
		return nil, nil, err
	}

	return pinEncKey, otherInfo, nil
}

// genPinBlockIsoFormat0 constructs an encrypted PIN block in
// ISO 9564 Format 0, using the PIN and PAN passed to the use
// case.
func (uc *pinSelect) genPinBlockIsoFormat0(pekTDESBlock cipher.Block) ([]byte, error) {
	paddedPIN := fmt.Sprintf("0%x%s", len(uc.pin), uc.pin)
	paddedPIN += strings.Repeat("F", 16-len(paddedPIN))
	slog.Info("Padded PIN generated.", slog.String("paddedPIN", paddedPIN))

	paddedPAN := fmt.Sprintf("0000%s", uc.pan[len(uc.pan)-13:len(uc.pan)-1])
	slog.Info("Padded PAN generated.", slog.String("paddedPAN", paddedPAN))

	paddedPINBytes, err := hex.DecodeString(paddedPIN)
	if err != nil {
		return nil, err
	}

	paddedPANBytes, err := hex.DecodeString(paddedPAN)
	if err != nil {
		return nil, err
	}

	pinBlock := make([]byte, 8)
	subtle.XORBytes(pinBlock, paddedPINBytes, paddedPANBytes)
	slog.Info("PIN block generated.", slog.String("pinBlock", strings.ToUpper(hex.EncodeToString(pinBlock))))

	encryptedPinBlock := make([]byte, des.BlockSize)
	pekTDESBlock.Encrypt(encryptedPinBlock, pinBlock)
	slog.Info("Encrypted PIN Block generated.", slog.String("encryptedPINBlock", strings.ToUpper(hex.EncodeToString(encryptedPinBlock))))

	return encryptedPinBlock, nil
}

// getStoragePEK returns the identifier of a PEK at APC, either validating the pre-existing
// one passed to the use case or creating a new temporary one.
func (uc *pinSelect) getStoragePEK(ctx context.Context) (string, error) {
	getStoragePEKResp, err := uc.apcClient.GetKey(ctx, &paymentcryptography.GetKeyInput{
		KeyIdentifier: aws.String(uc.storagePEKID),
	})
	if err == nil {
		return aws.ToString(getStoragePEKResp.Key.KeyArn), nil
	}

	createStoragePEKResp, err := uc.apcClient.CreateKey(context.Background(), &paymentcryptography.CreateKeyInput{
		Exportable: aws.Bool(true),
		KeyAttributes: &apctypes.KeyAttributes{
			KeyAlgorithm: apctypes.KeyAlgorithmTdes3key,
			KeyClass:     apctypes.KeyClassSymmetricKey,
			KeyModesOfUse: &apctypes.KeyModesOfUse{
				Encrypt: true,
				Decrypt: true,
				Wrap:    true,
				Unwrap:  true,
			},
			KeyUsage: apctypes.KeyUsageTr31P0PinEncryptionKey,
		},
	})
	if err != nil {
		return "", err
	}
	uc.keyArns = append(uc.keyArns, createStoragePEKResp.Key.KeyArn)
	slog.Info("Temporary PEK created.", slog.String("arn", aws.ToString(createStoragePEKResp.Key.KeyArn)), slog.String("kcv", aws.ToString(createStoragePEKResp.Key.KeyCheckValue)))

	return aws.ToString(createStoragePEKResp.Key.KeyArn), nil
}

// getPVK returns the identifier of a PVK at APC, either validating the pre-existing
// one passed to the use case or creating a new temporary one.
func (uc *pinSelect) getPVK(ctx context.Context) (string, error) {
	getPVKResp, err := uc.apcClient.GetKey(ctx, &paymentcryptography.GetKeyInput{
		KeyIdentifier: aws.String(uc.pvkID),
	})
	if err == nil {
		return aws.ToString(getPVKResp.Key.KeyArn), nil
	}

	createPVKResp, err := uc.apcClient.CreateKey(context.Background(), &paymentcryptography.CreateKeyInput{
		Exportable: aws.Bool(true),
		KeyAttributes: &apctypes.KeyAttributes{
			KeyAlgorithm: apctypes.KeyAlgorithmTdes3key,
			KeyClass:     apctypes.KeyClassSymmetricKey,
			KeyModesOfUse: &apctypes.KeyModesOfUse{
				Generate: true,
				Verify:   true,
			},
			KeyUsage: apctypes.KeyUsageTr31V2VisaPinVerificationKey,
		},
	})
	if err != nil {
		return "", err
	}
	uc.keyArns = append(uc.keyArns, createPVKResp.Key.KeyArn)
	slog.Info("Temporary PVK created.", slog.String("arn", aws.ToString(createPVKResp.Key.KeyArn)), slog.String("kcv", aws.ToString(createPVKResp.Key.KeyCheckValue)))

	return aws.ToString(createPVKResp.Key.KeyArn), nil
}

type PINSelectParams struct {
	// AWSConfig provides the information to initialize
	// any AWS SDK needed clients.
	AWSConfig aws.Config

	// PIN is a 4 to 12 digit Personal Identification Number.
	PIN string

	// PAN is a 12 to 19 digit Primary Account Number.
	PAN string

	// StoragePEKIdentifier is the identifier of a pre-existing PEK which should
	// be used as the target PEK for a PIN Select operation. If not provided, a
	// temporary one will be created during execution.
	//
	// Default: ""
	StoragePEKIdentifier string

	// PVKIdentifier is the identifier of a pre-existing PVK which should
	// be used to calculate the PIN Verification Value during a PIN Select
	// operation. If not provided, a temporary one will be created during
	// execution.
	//
	// Default: ""
	PVKIdentifier string
}

func (p *PINSelectParams) Validate() error {
	if len(p.PIN) < 4 || len(p.PIN) > 12 {
		return fmt.Errorf("invalid pin length: %d", len(p.PIN))
	}

	if len(p.PAN) < 12 || len(p.PAN) > 19 {
		return fmt.Errorf("invalid pan length: %d", len(p.PAN))
	}

	return nil
}

// PINSelect returns a use case that calculates validation
// information for the provided PIN.
func PINSelect(params PINSelectParams) (UseCase, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}

	return &pinSelect{
		keyArns:      make([]*string, 0),
		pin:          params.PIN,
		pan:          params.PAN,
		apcClient:    paymentcryptography.NewFromConfig(params.AWSConfig),
		apcdClient:   paymentcryptographydata.NewFromConfig(params.AWSConfig),
		storagePEKID: params.StoragePEKIdentifier,
		pvkID:        params.PVKIdentifier,
	}, nil
}
