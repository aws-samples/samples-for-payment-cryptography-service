package usecases

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"ecdh-use-cases/enums"
	"ecdh-use-cases/utils"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
	"github.com/golang-crypto/concatkdf"
	"github.com/moov-io/tr31/pkg/tr31"
)

type importClearTransportKey struct {
	targetKeyAlgorithm enums.KeyAlgorithm
	targetKey          []byte
	apcClient          *paymentcryptography.Client
	keyArns            []*string

	executed bool
}

func (uc *importClearTransportKey) Execute(ctx context.Context, ecdhPacket *ECDHPacket) error {
	wrappingKey, contextInfo, err := uc.deriveWrappingKey(ecdhPacket.SharedSecret)
	if err != nil {
		return errors.Join(errors.New("failed to derive wrapping key from shared secret"), err)
	}

	targetKCV := uc.calcTargetKeyKCV()
	slog.Info("Target key KCV generated.", slog.String("kcv", targetKCV))

	// Since uc.deriveWrappingKey derives an AES-256 KBPK.
	wrappedTargetKey, err := uc.genTR31KeyBlock(wrappingKey, enums.KeyAlgorithmAES256)
	if err != nil {
		return errors.Join(errors.New("failed to generate target key"), err)
	}
	slog.Info("Wrapped target key generated.", slog.String("tr31KeyBlock", wrappedTargetKey))

	keyImportResp, err := uc.apcClient.ImportKey(ctx, &paymentcryptography.ImportKeyInput{
		KeyMaterial: &types.ImportKeyMaterialMemberDiffieHellmanTr31KeyBlock{
			Value: types.ImportDiffieHellmanTr31KeyBlock{
				CertificateAuthorityPublicKeyIdentifier: aws.String(ecdhPacket.PartyUCAArn),
				DerivationData: &types.DiffieHellmanDerivationDataMemberSharedInformation{
					Value: hex.EncodeToString(contextInfo),
				},
				// Since uc.deriveWrappingKey derives an AES-256 KBPK.
				DeriveKeyAlgorithm: types.SymmetricKeyAlgorithmAes256,
				// Since uc.deriveWrappingKey uses ConcatKDF
				KeyDerivationFunction: types.KeyDerivationFunctionNistSp800,
				// Since uc.deriveWrappingKey uses SHA-512 for ConcatKDF
				KeyDerivationHashAlgorithm: types.KeyDerivationHashAlgorithmSha512,
				PrivateKeyIdentifier:       aws.String(ecdhPacket.PartyVECCKeyPairArn),
				PublicKeyCertificate:       aws.String(base64.StdEncoding.EncodeToString(ecdhPacket.PartyUCertPEM)),
				WrappedKeyBlock:            aws.String(wrappedTargetKey),
			},
		},
	})
	if err != nil {
		return errors.Join(errors.New("failed to import target key"), err)
	}
	uc.keyArns = append(uc.keyArns, keyImportResp.Key.KeyArn)
	slog.Info("Target key imported.", slog.String("keyArn", aws.ToString(keyImportResp.Key.KeyArn)))

	if aws.ToString(keyImportResp.Key.KeyCheckValue) != targetKCV {
		slog.Warn("KCV from APC does not match locally calculated KCV.", slog.String("apcKCV", aws.ToString(keyImportResp.Key.KeyCheckValue)), slog.String("localKCV", targetKCV))
	}

	return nil
}

// Cleanup performs any needed post execution cleanup, e.g. deleting generated keys
// from APC. This function should be deferred as soon as possible in the majority of
// cases.
func (uc *importClearTransportKey) Cleanup(ctx context.Context) {
	// Delete all ECDH-related keys
	for _, keyArn := range uc.keyArns {
		uc.apcClient.DeleteKey(ctx, &paymentcryptography.DeleteKeyInput{
			KeyIdentifier:   keyArn,
			DeleteKeyInDays: aws.Int32(3),
		})
	}
}

// deriveWrappingKey derives a one-time use KBPK from the ECDH
// shared secret, using ConcatKDF with SHA512 and requesting 32
// bytes for an AES-256 KBPK.
func (uc *importClearTransportKey) deriveWrappingKey(sharedSecret []byte) (kbpk []byte, contextInfo []byte, err error) {
	otherInfo := make([]byte, 32)
	_, err = rand.Read(contextInfo)
	if err != nil {
		return nil, nil, err
	}

	wrappingKey, err := concatkdf.Key(sha512.New, sharedSecret, string(otherInfo), 32)
	if err != nil {
		return nil, nil, err
	}

	return wrappingKey, otherInfo, nil
}

// calcTargetKeyKCV returns the KCV for the target key. Returns
// an empty string if no calculator is implemented for the target
// key algorithm.
func (uc *importClearTransportKey) calcTargetKeyKCV() string {
	switch uc.targetKeyAlgorithm {
	case enums.KeyAlgorithmTDES2Key:
		return utils.CalculateTDESKCV(append(uc.targetKey, uc.targetKey[:8]...))
	case enums.KeyAlgorithmTDES3Key:
		return utils.CalculateTDESKCV(uc.targetKey)
	case enums.KeyAlgorithmAES128, enums.KeyAlgorithmAES192, enums.KeyAlgorithmAES256:
		return utils.CalculateAESKCV(uc.targetKey)
	default:
		slog.Warn("No KCV calculator implemented for target key algorithm.", slog.String("targetKeyAlgorithm", string(uc.targetKeyAlgorithm)))
		return ""
	}
}

var keyBlockVersionMapping = map[enums.KeyAlgorithm]string{
	enums.KeyAlgorithmTDES2Key: tr31.TR31_VERSION_B,
	enums.KeyAlgorithmTDES3Key: tr31.TR31_VERSION_B,
	enums.KeyAlgorithmAES128:   tr31.TR31_VERSION_D,
	enums.KeyAlgorithmAES192:   tr31.TR31_VERSION_D,
	enums.KeyAlgorithmAES256:   tr31.TR31_VERSION_D,
}

var keyBlockAlgorithmMapping = map[enums.KeyAlgorithm]string{
	enums.KeyAlgorithmTDES2Key: tr31.ENC_ALGORITHM_TRIPLE_DES,
	enums.KeyAlgorithmTDES3Key: tr31.ENC_ALGORITHM_TRIPLE_DES,
	enums.KeyAlgorithmAES128:   tr31.ENC_ALGORITHM_AES,
	enums.KeyAlgorithmAES192:   tr31.ENC_ALGORITHM_AES,
	enums.KeyAlgorithmAES256:   tr31.ENC_ALGORITHM_AES,
}

// genTR31KeyBlock generates a TR-31 key block for a reusable KBPK.
func (uc *importClearTransportKey) genTR31KeyBlock(wrappingKey []byte, wrappingKeyAlgorithm enums.KeyAlgorithm) (string, error) {
	kbVersion := keyBlockVersionMapping[wrappingKeyAlgorithm]
	kbTargetAlgo := keyBlockAlgorithmMapping[uc.targetKeyAlgorithm]

	kbHeader, err := tr31.NewHeader(kbVersion, "K1", kbTargetAlgo, "B", "00", "E")
	if err != nil {
		return "", err
	}

	keyBlock, err := tr31.NewKeyBlock(wrappingKey, kbHeader)
	if err != nil {
		return "", err
	}

	wrappedTargetKey, err := keyBlock.Wrap(uc.targetKey, nil)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(wrappedTargetKey), nil
}

type ImportClearTransportKeyParams struct {
	// AWSConfig provides the information to initialize
	// any AWS SDK needed clients.
	AWSConfig aws.Config

	// TargetKeyAlgorithm is the algorithm for which the target key material shall be used.
	TargetKeyAlgorithm enums.KeyAlgorithm

	// TargetKey is a the target clear key to be imported. Must match the amount of bytes
	// required by the algorithm provided in TargetKeyAlgorithm.
	//
	// Required byte length:
	// 	- enums.KeyAlgorithmTDES2Key: 16
	// 	- enums.KeyAlgorithmTDES3Key: 24
	// 	- enums.KeyAlgorithmAES128:   16
	// 	- enums.KeyAlgorithmAES192:   24
	// 	- enums.KeyAlgorithmAES256:   32
	TargetKey []byte
}

var keyAlgorithmSizeMapping = map[enums.KeyAlgorithm]int{
	enums.KeyAlgorithmTDES2Key: 16,
	enums.KeyAlgorithmTDES3Key: 24,
	enums.KeyAlgorithmAES128:   16,
	enums.KeyAlgorithmAES192:   24,
	enums.KeyAlgorithmAES256:   32,
}

func (p *ImportClearTransportKeyParams) Validate() error {
	if p.TargetKey == nil {
		return errors.New("a target key must be provided")
	}

	if !p.TargetKeyAlgorithm.Valid() {
		return errors.New("invalid target key algorithm provided")
	}

	if len(p.TargetKey) != keyAlgorithmSizeMapping[p.TargetKeyAlgorithm] {
		return fmt.Errorf(
			"target key with %d bytes does not match the required byte size for provided %s algorithm",
			len(p.TargetKey), p.TargetKeyAlgorithm,
		)
	}

	return nil
}

// ImportClearTransportKey returns a usecase that imports the
// provided clear key as a KBPK (base transport key) for future
// TR-31 imports.
func ImportClearTransportKey(params ImportClearTransportKeyParams) (UseCase, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}

	return &importClearTransportKey{
		keyArns:            make([]*string, 0),
		apcClient:          paymentcryptography.NewFromConfig(params.AWSConfig),
		targetKey:          params.TargetKey,
		targetKeyAlgorithm: params.TargetKeyAlgorithm,
	}, nil
}
