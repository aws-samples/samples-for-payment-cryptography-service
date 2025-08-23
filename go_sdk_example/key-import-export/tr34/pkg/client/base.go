package client

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"

	"tr34-key-import-export/pkg/logger"
)

type BaseClient struct {
	Client    *paymentcryptography.Client
	AwsConfig aws.Config
}

func NewBaseClient(cfg aws.Config) *BaseClient {
	return &BaseClient{
		Client:    paymentcryptography.NewFromConfig(cfg),
		AwsConfig: cfg,
	}
}

func (bc *BaseClient) CreateOrUpdateAlias(ctx context.Context, aliasName, keyArn string) error {
	if !strings.HasPrefix(aliasName, "alias/") {
		aliasName = "alias/" + aliasName
	}

	aliasResp, err := bc.Client.GetAlias(ctx, &paymentcryptography.GetAliasInput{
		AliasName: aws.String(aliasName),
	})

	if err != nil {
		var notFoundErr *types.ResourceNotFoundException
		if !errors.As(err, &notFoundErr) {
			return fmt.Errorf("failed to get alias: %w", err)
		}

		_, err = bc.Client.CreateAlias(ctx, &paymentcryptography.CreateAliasInput{
			AliasName: aws.String(aliasName),
			KeyArn:    aws.String(keyArn),
		})
		if err != nil {
			return fmt.Errorf("failed to create alias: %w", err)
		}
		return nil
	}

	if aliasResp != nil && aliasResp.Alias != nil && aliasResp.Alias.KeyArn != nil {
		oldKeyArn := aws.ToString(aliasResp.Alias.KeyArn)
		if oldKeyArn != keyArn {
			keyResp, err := bc.Client.GetKey(ctx, &paymentcryptography.GetKeyInput{
				KeyIdentifier: aws.String(oldKeyArn),
			})
			if err == nil && keyResp.Key != nil {
				if keyResp.Key.KeyState == types.KeyStateCreateComplete {
					_, err = bc.Client.DeleteKey(ctx, &paymentcryptography.DeleteKeyInput{
						KeyIdentifier:   aws.String(oldKeyArn),
						DeleteKeyInDays: aws.Int32(3),
					})
					if err != nil {
						logger.Warning("Failed to delete old key: %v", err)
					}
				}
			}
		}
	}

	_, err = bc.Client.UpdateAlias(ctx, &paymentcryptography.UpdateAliasInput{
		AliasName: aws.String(aliasName),
		KeyArn:    aws.String(keyArn),
	})
	if err != nil {
		return fmt.Errorf("failed to update alias: %w", err)
	}

	return nil
}

func (bc *BaseClient) DeleteOldKey(ctx context.Context, aliasName string) error {
	if !strings.HasPrefix(aliasName, "alias/") {
		aliasName = "alias/" + aliasName
	}

	aliasResp, err := bc.Client.GetAlias(ctx, &paymentcryptography.GetAliasInput{
		AliasName: aws.String(aliasName),
	})
	if err != nil {
		if _, err := bc.Client.CreateAlias(ctx, &paymentcryptography.CreateAliasInput{
			AliasName: aws.String(aliasName),
		}); err != nil {
			return err
		}
		return nil
	}

	if aliasResp.Alias.KeyArn != nil {
		if _, err := bc.Client.UpdateAlias(ctx, &paymentcryptography.UpdateAliasInput{
			AliasName: aliasResp.Alias.AliasName,
		}); err != nil {
			return err
		}

		keyResp, err := bc.Client.GetKey(ctx, &paymentcryptography.GetKeyInput{
			KeyIdentifier: aliasResp.Alias.KeyArn,
		})
		if err != nil {
			return err
		}

		if keyResp.Key.KeyState == types.KeyStateCreateComplete {
			if _, err := bc.Client.DeleteKey(ctx, &paymentcryptography.DeleteKeyInput{
				KeyIdentifier:   keyResp.Key.KeyArn,
				DeleteKeyInDays: aws.Int32(3),
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bc *BaseClient) EnsureAlias(ctx context.Context, aliasName string) error {
	if !strings.HasPrefix(aliasName, "alias/") {
		aliasName = "alias/" + aliasName
	}

	_, err := bc.Client.GetAlias(ctx, &paymentcryptography.GetAliasInput{
		AliasName: aws.String(aliasName),
	})

	if err != nil {
		var notFoundErr *types.ResourceNotFoundException
		if errors.As(err, &notFoundErr) {
			_, err = bc.Client.CreateAlias(ctx, &paymentcryptography.CreateAliasInput{
				AliasName: aws.String(aliasName),
			})
			if err != nil {
				return fmt.Errorf("failed to create alias: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get alias: %w", err)
		}
	}

	return nil
}

func (bc *BaseClient) UpdateAlias(ctx context.Context, aliasName, keyArn string) error {
	if !strings.HasPrefix(aliasName, "alias/") {
		aliasName = "alias/" + aliasName
	}

	_, err := bc.Client.UpdateAlias(ctx, &paymentcryptography.UpdateAliasInput{
		AliasName: aws.String(aliasName),
		KeyArn:    aws.String(keyArn),
	})
	if err != nil {
		return fmt.Errorf("failed to update alias: %w", err)
	}

	return nil
}
