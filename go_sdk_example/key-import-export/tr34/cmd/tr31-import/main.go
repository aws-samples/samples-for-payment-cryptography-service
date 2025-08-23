package main

import (
	"flag"
	"fmt"
	"os"

	"tr34-key-import-export/internal/config"
	"tr34-key-import-export/pkg/logger"
	"tr34-key-import-export/pkg/tr31"
)

func main() {
	clearKey := flag.String("clearkey", "BA6DCE7F5E54F2A7CE45C41A64838C70", "Clear text key to import using TR-31")
	kbpkClearKey := flag.String("kbpk_clearkey", "", "Clear text version of KBPK (KEK/ZMK/ZMCK) [REQUIRED]")
	kbpkIdentifier := flag.String("kbpkkey_apcIdentifier", "", "Key identifier for KEK in AWS (ARN or alias) [REQUIRED]")
	kekAlgorithm := flag.String("kek_algorithm", "", "KEK algorithm - T (3DES) or A (AES) [REQUIRED]")
	exportMode := flag.String("exportmode", "E", "Export mode - E (exportable), S (sensitive), or N (non-exportable)")
	algorithm := flag.String("algorithm", "T", "Algorithm of key - T (3DES) or A (AES)")
	keyType := flag.String("keytype", "B0", "Key type according to TR-31 (K0, B0, D0, P0, D1)")
	modeOfUse := flag.String("modeofuse", "X", "Mode of use according to TR-31 (B, X, N, E, D, G, C, V)")
	aliasName := flag.String("alias", "", "Alias name for the imported key")

	region := flag.String("region", "us-east-1", "AWS region")
	profile := flag.String("profile", "default", "AWS profile to use")

	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	help := flag.Bool("help", false, "Show help message")

	flag.StringVar(exportMode, "e", "E", "Export mode (short)")
	flag.StringVar(algorithm, "a", "T", "Algorithm (short)")
	flag.StringVar(keyType, "t", "B0", "Key type (short)")
	flag.StringVar(modeOfUse, "m", "X", "Mode of use (short)")
	flag.StringVar(kbpkIdentifier, "z", "", "KEK identifier (short)")
	flag.StringVar(region, "r", "", "AWS region (short)")
	flag.StringVar(profile, "p", "", "AWS profile (short)")
	flag.BoolVar(verbose, "v", false, "Verbose (short)")
	flag.BoolVar(help, "h", false, "Help (short)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "TR-31 Key Import for AWS Payment Cryptography\n\n")
		fmt.Fprintf(os.Stderr, "Import symmetric keys using TR-31 protocol.\n")
		fmt.Fprintf(os.Stderr, "This requires a cleartext KBPK (KEK) and its identifier in AWS.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s --kbpkkey_apcIdentifier <ARN/alias> [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Import with AWS KEK identifier\n")
		fmt.Fprintf(os.Stderr, "  %s --kbpkkey_apcIdentifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \\\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    --kbpk_clearkey 79ADAEF3212AADCE312ACE422ACCFEFB \\\n")
		fmt.Fprintf(os.Stderr, "    --kek_algorithm T \\\n")
		fmt.Fprintf(os.Stderr, "    --clearkey 8A8349794C9EE9A4C2927098F249FED6\n")
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *kbpkIdentifier == "" || *kekAlgorithm == "" || *kbpkClearKey == "" {
		if *kbpkIdentifier == "" {
			fmt.Fprintf(os.Stderr, "Error: --kbpkkey_apcIdentifier is required\n")
		}
		if *kbpkClearKey == "" {
			fmt.Fprintf(os.Stderr, "Error: --kbpk_clearkey is required\n")
		}
		if *kekAlgorithm == "" {
			fmt.Fprintf(os.Stderr, "Error: --kek_algorithm is required\n")
		}
		fmt.Fprintf(os.Stderr, "\n")
		flag.Usage()
		os.Exit(1)
	}

	if *kekAlgorithm != "T" && *kekAlgorithm != "A" {
		fmt.Fprintf(os.Stderr, "Error: --kek_algorithm must be T (3DES) or A (AES)\n\n")
		flag.Usage()
		os.Exit(1)
	}

	logger.SetVerbose(*verbose)

	logger.Info("Key to import: %s", *clearKey)
	logger.Info("Key Encryption Key (in cleartext): %s", *kbpkClearKey)
	logger.Info("Key Encryption Key identifier on the service: %s", *kbpkIdentifier)
	logger.Info("KEK Algorithm: %s", *kekAlgorithm)
	logger.Info("Export Mode: %s", *exportMode)
	logger.Info("Key Type: %s", *keyType)
	logger.Info("Key Mode of use: %s", *modeOfUse)
	logger.Info("Key Algorithm: %s", *algorithm)

	cfg := config.Config{
		Region:  *region,
		Profile: *profile,
	}

	logger.Verbose("Verbose mode enabled")
	logger.Verbose("Configuration: Region=%s, Profile=%s", cfg.Region, cfg.Profile)

	// Version ID is determined by the KEK algorithm, not the imported key algorithm
	// B = TDES KEK, D = AES KEK
	versionID := "B"
	if *kekAlgorithm == "A" {
		versionID = "D"
	}

	options := tr31.ImportOptions{
		KeyType:    *keyType,
		Algorithm:  *algorithm,
		ModeOfUse:  *modeOfUse,
		ExportMode: *exportMode,
		VersionID:  versionID,
		AliasName:  *aliasName,
	}

	awsConfig, err := cfg.LoadAWSConfig()
	if err != nil {
		logger.Fatal("Failed to load AWS config: %v", err)
	}

	importer := tr31.NewImporter(awsConfig)

	result, err := importer.ImportKey(*kbpkIdentifier, *clearKey, *kbpkClearKey, options)
	if err != nil {
		logger.Fatal("Import failed: %v", err)
	}

	logger.Info("************************ DONE *****************")
	logger.Info("Imported Key: %s", *clearKey)
	logger.Info("Key Arn: %s", result.KeyArn)
	logger.Info("Reported KCV: %s", result.KeyCheckValue)
	logger.Info("Reported Type: %s", result.KeyType)

	if result.AliasName != "" {
		logger.Info("Alias: %s", result.AliasName)
	}

	logger.Info("If this key was a key encryption key (K0), use TR-31 to import subsequent keys.")
}
