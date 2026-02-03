package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"

	"tr34-key-import-export/pkg/logger"
	"tr34-key-import-export/pkg/tr31"
)

func main() {
	var (
		keyIdentifier = flag.String("key", "", "Key identifier or ARN to export (required)")
		kekIdentifier = flag.String("kek", "", "KEK identifier or ARN for wrapping (required)")

		region  = flag.String("region", "us-east-1", "AWS region")
		profile = flag.String("profile", "default", "AWS profile to use")

		verbose  = flag.Bool("verbose", false, "Enable verbose output")
		showHelp = flag.Bool("help", false, "Show help message")
	)

	flag.Parse()

	if *showHelp || *keyIdentifier == "" || *kekIdentifier == "" {
		fmt.Fprintf(os.Stderr, "TR-31 Key Export Tool for AWS Payment Cryptography Service\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Required:\n")
		fmt.Fprintf(os.Stderr, "  -key string       Key identifier or ARN to export\n")
		fmt.Fprintf(os.Stderr, "  -kek string       KEK identifier or ARN for wrapping\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -exportmode string  Export mode (default: E)\n")
		fmt.Fprintf(os.Stderr, "                      E = Exportable\n")
		fmt.Fprintf(os.Stderr, "                      S = Sensitive\n")
		fmt.Fprintf(os.Stderr, "                      N = Non-exportable\n")
		fmt.Fprintf(os.Stderr, "  -region string      AWS region (default: us-east-1)\n")
		fmt.Fprintf(os.Stderr, "  -profile string     AWS profile to use\n")
		fmt.Fprintf(os.Stderr, "  -verbose           Enable verbose output\n")
		fmt.Fprintf(os.Stderr, "  -help              Show this help message\n\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  %s -key arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \\\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    -kek arn:aws:payment-cryptography:us-east-1:123456789012:key/def456 \\\n")
		fmt.Fprintf(os.Stderr, "    -verbose\n")

		if *keyIdentifier == "" || *kekIdentifier == "" {
			os.Exit(1)
		}
		os.Exit(0)
	}

	ctx := context.Background()
	var cfgOpts []func(*config.LoadOptions) error
	cfgOpts = append(cfgOpts, config.WithRegion(*region))
	if *profile != "" {
		cfgOpts = append(cfgOpts, config.WithSharedConfigProfile(*profile))
	}

	logger.SetVerbose(*verbose)

	cfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		logger.Fatal("Failed to load AWS config: %v", err)
	}

	exporter := tr31.NewExporter(cfg)

	logger.Verbose("Exporting key using TR-31...")
	logger.Verbose("Key: %s", *keyIdentifier)
	logger.Verbose("KEK: %s", *kekIdentifier)
	logger.Verbose("Region: %s", *region)
	if *profile != "" {
		logger.Verbose("Profile: %s", *profile)
	}

	result, err := exporter.ExportKey(*keyIdentifier, *kekIdentifier)
	if err != nil {
		logger.Fatal("Failed to export key: %v", err)
	}

	// Display results
	logger.Info("Key ARN: %s", result.KeyArn)
	logger.Info("Key Check Value: %s", result.KeyCheckValue)
	logger.Info("TR-31 Block: %s", result.WrappedKey)

	if result.Header != nil {
		logger.Verbose("\nTR-31 Header Details:")
		logger.Verbose("  Version: %s", result.Header.VersionID)
		logger.Verbose("  Key Usage: %s", result.Header.KeyUsage)
		logger.Verbose("  Algorithm: %s", result.Header.Algorithm)
		logger.Verbose("  Mode of Use: %s", result.Header.ModeOfUse)
		logger.Verbose("  Exportability: %s", result.Header.Exportability)
	}
}
