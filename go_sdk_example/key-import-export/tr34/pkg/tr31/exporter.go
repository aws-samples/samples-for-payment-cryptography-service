package tr31

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
	moovtr31 "github.com/moov-io/tr31/pkg/tr31"

	"tr34-key-import-export/pkg/client"
	"tr34-key-import-export/pkg/logger"
)

type ExportResult struct {
	KeyArn        string
	KeyCheckValue string
	WrappedKey    string
	KeyType       string
	Algorithm     string
	Header        *moovtr31.Header
}

type Exporter struct {
	*client.BaseClient
}

func NewExporter(cfg aws.Config) *Exporter {
	return &Exporter{
		BaseClient: client.NewBaseClient(cfg),
	}
}

func (e *Exporter) ExportKey(keyIdentifier, kekIdentifier string) (*ExportResult, error) {
	ctx := context.Background()

	keyResp, err := e.Client.GetKey(ctx, &paymentcryptography.GetKeyInput{
		KeyIdentifier: aws.String(keyIdentifier),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get key details: %w", err)
	}

	kekResp, err := e.Client.GetKey(ctx, &paymentcryptography.GetKeyInput{
		KeyIdentifier: aws.String(kekIdentifier),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get KEK details: %w", err)
	}

	logger.Verbose("Exporting key: %s", aws.ToString(keyResp.Key.KeyArn))
	logger.Verbose("Using KEK: %s", aws.ToString(kekResp.Key.KeyArn))

	tr31Params := e.determineTR31Parameters(keyResp.Key.KeyAttributes)

	exportResp, err := e.Client.ExportKey(ctx, &paymentcryptography.ExportKeyInput{
		KeyMaterial: &types.ExportKeyMaterialMemberTr31KeyBlock{
			Value: types.ExportTr31KeyBlock{
				WrappingKeyIdentifier: aws.String(kekIdentifier),
			},
		},
		ExportKeyIdentifier: aws.String(keyIdentifier),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to export key from AWS: %w", err)
	}

	var wrappedKey string
	if exportResp.WrappedKey != nil && exportResp.WrappedKey.KeyMaterial != nil {
		wrappedKey = aws.ToString(exportResp.WrappedKey.KeyMaterial)
	} else {
		return nil, fmt.Errorf("no wrapped key material in response")
	}

	wrapper := NewWrapper([]byte{}) // Empty KEK for parsing only
	header, err := wrapper.GetHeader(wrappedKey)
	if err != nil {
		logger.Warning("Failed to parse TR-31 header: %v", err)
	}

	result := &ExportResult{
		KeyArn:        aws.ToString(keyResp.Key.KeyArn),
		KeyCheckValue: aws.ToString(keyResp.Key.KeyCheckValue),
		WrappedKey:    wrappedKey,
		KeyType:       tr31Params.keyUsage,
		Algorithm:     tr31Params.algorithm,
		Header:        header,
	}

	logger.Verbose("Export successful")
	logger.Verbose("Key ARN: %s", result.KeyArn)
	logger.Verbose("KCV: %s", result.KeyCheckValue)
	logger.Verbose("TR-31 Block: %s...", result.WrappedKey[:32])
	if header != nil {
		logger.Verbose("TR-31 Version: %s", header.VersionID)
		logger.Verbose("Key Usage: %s", header.KeyUsage)
		logger.Verbose("Algorithm: %s", header.Algorithm)
		logger.Verbose("Mode of Use: %s", header.ModeOfUse)
		logger.Verbose("Exportability: %s", header.Exportability)
	}

	return result, nil
}

type tr31Parameters struct {
	keyUsage      string
	algorithm     string
	modeOfUse     string
	exportability string
}

func (e *Exporter) determineTR31Parameters(attrs *types.KeyAttributes) tr31Parameters {
	params := tr31Parameters{
		keyUsage:      "00",
		algorithm:     "T",
		modeOfUse:     "B",
		exportability: "E",
	}

	if attrs == nil {
		return params
	}

	switch attrs.KeyAlgorithm {
	case types.KeyAlgorithmAes128, types.KeyAlgorithmAes192, types.KeyAlgorithmAes256:
		params.algorithm = "A"
	case types.KeyAlgorithmTdes2key, types.KeyAlgorithmTdes3key:
		params.algorithm = "T"
	}

	switch attrs.KeyClass {
	case types.KeyClassSymmetricKey:
		switch string(attrs.KeyUsage) {
		case "TR31_B0_BASE_DERIVATION_KEY":
			params.keyUsage = "B0"
			params.modeOfUse = "X"
		case "TR31_K0_KEY_ENCRYPTION_KEY":
			params.keyUsage = "K0"
			params.modeOfUse = "B"
		case "TR31_P0_PIN_ENCRYPTION_KEY":
			params.keyUsage = "P0"
			params.modeOfUse = "B"
		case "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS":
			params.keyUsage = "E0"
			params.modeOfUse = "X"
		case "TR31_M3_ISO_9797_3_MAC_KEY":
			params.keyUsage = "M3"
			params.modeOfUse = "C"
		case "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY":
			params.keyUsage = "D0"
			params.modeOfUse = "B"
		case "TR31_V2_VISA_PIN_VERIFICATION_KEY":
			params.keyUsage = "V2"
			params.modeOfUse = "V"
		default:
			params.keyUsage = "00"
		}
	}

	if attrs.KeyModesOfUse != nil {
		if attrs.KeyModesOfUse.NoRestrictions {
			params.exportability = "E"
		} else {
			params.exportability = "S"
		}
	} else {
		params.exportability = "E" // Default to exportable
	}

	return params
}
