package config

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

type Config struct {
	Region  string
	Profile string
}

func (c *Config) LoadAWSConfig() (aws.Config, error) {
	ctx := context.Background()

	var opts []func(*config.LoadOptions) error

	if c.Region != "" {
		opts = append(opts, config.WithRegion(c.Region))
	}

	if c.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(c.Profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return cfg, nil
}
