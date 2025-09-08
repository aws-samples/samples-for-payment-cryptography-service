package main

import (
	"flag"
	"fmt"
	"os"

	"tr34-key-import-export/internal/config"
	"tr34-key-import-export/pkg/logger"
	"tr34-key-import-export/pkg/tr34"
	"tr34-key-import-export/pkg/utils"
)

func main() {
	keyArn := flag.String("keyarn", "", "ARN of the key to export")
	keyAlias := flag.String("keyalias", "", "Alias of the key to export")
	exportMode := flag.String("exportmode", "E", "Export mode - E (exportable), S (sensitive), or N (non-exportable)")
	components := flag.Bool("components", false, "Generate XOR components for manual key entry")

	region := flag.String("region", "us-east-1", "AWS region")
	profile := flag.String("profile", "", "AWS profile to use")

	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	help := flag.Bool("help", false, "Show help message")

	flag.StringVar(exportMode, "e", "E", "Export mode (short)")
	flag.StringVar(region, "r", "us-east-1", "AWS region (short)")
	flag.StringVar(profile, "p", "", "AWS profile (short)")
	flag.BoolVar(verbose, "v", false, "Verbose (short)")
	flag.BoolVar(components, "c", false, "Components (short)")
	flag.BoolVar(help, "h", false, "Help (short)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "TR-34 Key Export for AWS Payment Cryptography\n\n")
		fmt.Fprintf(os.Stderr, "Export symmetric keys from AWS Payment Cryptography Service using TR-34 protocol.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Export a key by ARN\n")
		fmt.Fprintf(os.Stderr, "  %s --keyarn arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Export a key by alias\n")
		fmt.Fprintf(os.Stderr, "  %s --keyalias alias/my-key\n", os.Args[0])
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *keyArn != "" && *keyAlias != "" {
		fmt.Fprintf(os.Stderr, "Error: specify either --keyarn or --keyalias, not both\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *exportMode != "E" && *exportMode != "S" && *exportMode != "N" {
		logger.Fatal("Invalid export mode: %s (must be E, S, or N)", *exportMode)
	}

	logger.SetVerbose(*verbose)

	cfg := config.Config{
		Region:  *region,
		Profile: *profile,
	}

	logger.Verbose("Verbose mode enabled")
	logger.Verbose("Configuration: Region=%s, Profile=%s", cfg.Region, cfg.Profile)

	awsConfig, err := cfg.LoadAWSConfig()
	if err != nil {
		logger.Fatal("Failed to load AWS config: %v", err)
	}

	exporter := tr34.NewExporter(awsConfig)

	keyIdentifier := *keyArn
	if *keyAlias != "" {
		keyIdentifier = *keyAlias
	}
	if keyIdentifier == "" {
		logger.Verbose("No key specified, will create or use existing default key")
	}

	result, err := exporter.ExportKey(keyIdentifier)
	if err != nil {
		logger.Fatal("Export failed: %v", err)
	}

	logger.Info("Successfully exported key:")
	logger.Info("  Key ARN: %s", result.KeyArn)
	logger.Info("  Key Check Value: %s", result.KeyCheckValue)

	logger.Verbose("  Nonce: %s", result.Nonce)
	logger.Verbose("  TR-34 Payload (hex): %s", result.Payload)

	if result.DecryptedKey != "" {
		logger.Verbose("  Decrypted Key (verification): %s", result.DecryptedKey)
	}

	if result.DecryptedKey != "" {
		logger.Info("*************************************************")
		logger.Info("Clear Key: %s", result.DecryptedKey)
		logger.Info("KCV: %s", result.KeyCheckValue)

		keyComponents, err := utils.GenerateKeyComponents(result.DecryptedKey, result.KeyCheckValue)
		if err != nil {
			logger.Error("Failed to generate key components: %v", err)
		} else {
			logger.Info("Components:")
			logger.Info("  Component One: %X", keyComponents.ComponentOne)
			logger.Info("  Component Two: %X", keyComponents.ComponentTwo)
		}
	}
}
