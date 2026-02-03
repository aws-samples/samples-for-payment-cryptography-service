package tr31

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"

	"tr34-key-import-export/pkg/client"
	"tr34-key-import-export/pkg/logger"
	"tr34-key-import-export/pkg/utils"
)

type ImportOptions struct {
	ExportMode string
	KeyType    string
	ModeOfUse  string
	Algorithm  string
	VersionID  string
	AliasName  string
	KEK        []byte
}

type ImportResult struct {
	KeyArn        string
	KeyCheckValue string
	WrappedKey    string
	AliasName     string
	KeyType       string
}

type Importer struct {
	*client.BaseClient
}

func NewImporter(cfg aws.Config) *Importer {
	return &Importer{
		BaseClient: client.NewBaseClient(cfg),
	}
}

func (i *Importer) ImportKey(kekIdentifier, clearKeyHex, kekCleartext string, options ImportOptions) (*ImportResult, error) {
	ctx := context.Background()

	clearKey, err := utils.ParseHexString(clearKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid clear key: %w", err)
	}

	kekBytes, err := utils.ParseHexString(kekCleartext)
	if err != nil {
		return nil, fmt.Errorf("invalid KEK: %w", err)
	}

	_, err = i.Client.GetKey(ctx, &paymentcryptography.GetKeyInput{
		KeyIdentifier: aws.String(kekIdentifier),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get KEK details: %w", err)
	}

	wrapper := NewWrapper(kekBytes)
	wrappedKey, err := wrapper.Wrap(clearKey, options)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	logger.Verbose("WRAPPED KEY IN TR-31: %s", wrappedKey)
	logger.Verbose("Imported Key: %s", clearKeyHex)

	importResp, err := i.Client.ImportKey(ctx, &paymentcryptography.ImportKeyInput{
		Enabled: aws.Bool(true),
		KeyMaterial: &types.ImportKeyMaterialMemberTr31KeyBlock{
			Value: types.ImportTr31KeyBlock{
				WrappedKeyBlock:       aws.String(wrappedKey),
				WrappingKeyIdentifier: aws.String(kekIdentifier),
			},
		},
		KeyCheckValueAlgorithm: types.KeyCheckValueAlgorithmAnsiX924,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to import key to AWS: %w", err)
	}

	result := &ImportResult{
		KeyArn:        aws.ToString(importResp.Key.KeyArn),
		KeyCheckValue: aws.ToString(importResp.Key.KeyCheckValue),
		WrappedKey:    wrappedKey,
		KeyType:       utils.DetermineKeyTypeString(importResp.Key.KeyAttributes),
	}

	if options.AliasName != "" {
		err = i.CreateOrUpdateAlias(ctx, options.AliasName, result.KeyArn)
		if err != nil {
			logger.Warning("Failed to create/update alias: %v", err)
		} else {
			result.AliasName = options.AliasName
		}
	}

	logger.Verbose("Key Arn: %s", result.KeyArn)
	logger.Verbose("Reported KCV: %s", result.KeyCheckValue)
	logger.Verbose("Reported Type: %s", result.KeyType)
	if result.AliasName != "" {
		logger.Verbose("Alias: %s", result.AliasName)
	}

	return result, nil
}
