package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"tr34-key-import-export/internal/config"
	"tr34-key-import-export/pkg/logger"
	"tr34-key-import-export/pkg/tr34"
	"tr34-key-import-export/pkg/utils"
)

func main() {
	clearKey := flag.String("clearkey", "8A8349794C9EE9A4C2927098F249FED6", "Clear text key to import (hex format)")
	exportMode := flag.String("exportmode", "E", "Export mode - E (exportable), S (sensitive), or N (non-exportable)")
	algorithm := flag.String("algorithm", "T", "Algorithm of key - T (3DES) or A (AES)")
	keyType := flag.String("keytype", "K0", "Key type according to TR-31 (K0, K1, B0, D0, P0, E0, E1, E2, E3, E6, C0)")
	modeOfUse := flag.String("modeofuse", "B", "Mode of use according to TR-31 (B, X, N, E, D, C, G, V)")
	aliasName := flag.String("alias", "", "Alias name for the imported key")

	region := flag.String("region", "us-east-1", "AWS region")
	profile := flag.String("profile", "default", "AWS profile to use")

	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	help := flag.Bool("help", false, "Show help message")

	flag.StringVar(exportMode, "e", "E", "Export mode (short)")
	flag.StringVar(algorithm, "a", "T", "Algorithm (short)")
	flag.StringVar(keyType, "t", "K0", "Key type (short)")
	flag.StringVar(modeOfUse, "m", "B", "Mode of use (short)")
	flag.StringVar(region, "r", "us-east-1", "AWS region (short)")
	flag.StringVar(profile, "p", "", "AWS profile (short)")
	flag.BoolVar(verbose, "v", false, "Verbose (short)")
	flag.BoolVar(help, "h", false, "Help (short)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "TR-34 Key Import for AWS Payment Cryptography\n")
		fmt.Fprintf(os.Stderr, "Import symmetric keys into AWS Payment Cryptography Service using TR-34 protocol.\n")
		fmt.Fprintf(os.Stderr, "Usage:")
		fmt.Fprintf(os.Stderr, "  %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:")
		fmt.Fprintf(os.Stderr, "  # Import a 3DES key")
		fmt.Fprintf(os.Stderr, "  %s --clearkey 79ADAEF3212AADCE312ACE422ACCFEFB\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  # Import an AES key with specific options")
		fmt.Fprintf(os.Stderr, "  %s --clearkey 0123456789ABCDEF0123456789ABCDEF -a A -t B0 -m X\n", os.Args[0])
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *clearKey == "" {
		fmt.Fprintf(os.Stderr, "Error: --clearkey cannot be empty\n")
		flag.Usage()
		os.Exit(1)
	}

	if err := validateInputs(*exportMode, *algorithm, *keyType, *modeOfUse, *clearKey); err != nil {
		logger.Fatal("Invalid input: %v", err)
	}

	logger.SetVerbose(*verbose)

	cfg := config.Config{
		Region:  *region,
		Profile: *profile,
	}

	logger.Verbose("Verbose mode enabled")
	logger.Verbose("Configuration: Region=%s, Profile=%s", cfg.Region, cfg.Profile)

	options := tr34.ImportOptions{
		KeyType:    *keyType,
		Algorithm:  *algorithm,
		ModeOfUse:  *modeOfUse,
		ExportMode: *exportMode,
		AliasName:  *aliasName,
	}

	awsConfig, err := cfg.LoadAWSConfig()
	if err != nil {
		logger.Fatal("Failed to load AWS config: %v", err)
	}

	importer := tr34.NewImporter(awsConfig)

	result, err := importer.ImportKey(*clearKey, options)
	if err != nil {
		logger.Fatal("Import failed: %v", err)
	}

	logger.Info("Successfully imported key:")
	logger.Info("  Key ARN: %s", result.KeyArn)
	logger.Info("  Key Check Value: %s", result.KeyCheckValue)
	if *aliasName != "" {
		logger.Info("  Alias: %s", *aliasName)
	}
	if *verbose {
		clearKeyBytes, _ := hex.DecodeString(strings.ReplaceAll(*clearKey, " ", ""))
		calculatedKCV, err := utils.CalculateKCV(clearKeyBytes, *algorithm)
		if err != nil {
			logger.Error("Failed to calculate KCV: %v", err)
		} else {
			logger.Info("  Calculated KCV: %s", strings.ToUpper(calculatedKCV))
			if strings.ToUpper(calculatedKCV) == strings.ToUpper(result.KeyCheckValue) {
				logger.Info("  KCV Verification: PASS")
			} else {
				logger.Info("  KCV Verification: FAIL (mismatch)")
			}
		}
		logger.Info("  Nonce: %s", result.Nonce)
	}
}

func validateInputs(exportMode, algorithm, keyType, modeOfUse, clearKey string) error {
	validExportModes := map[string]bool{"E": true, "S": true, "N": true}
	if !validExportModes[exportMode] {
		return fmt.Errorf("invalid export mode: %s (must be E, S, or N)", exportMode)
	}

	validAlgorithms := map[string]bool{"T": true, "A": true}
	if !validAlgorithms[algorithm] {
		return fmt.Errorf("invalid algorithm: %s (must be T for 3DES or A for AES)", algorithm)
	}

	validKeyTypes := map[string]bool{
		"K0": true, "K1": true, "B0": true, "D0": true,
		"P0": true, "E0": true, "E1": true, "E2": true,
		"E3": true, "E6": true, "C0": true,
	}
	if !validKeyTypes[keyType] {
		return fmt.Errorf("invalid key type: %s", keyType)
	}

	validModes := map[string]bool{
		"B": true, "X": true, "N": true, "E": true,
		"D": true, "C": true, "G": true, "V": true,
	}
	if !validModes[modeOfUse] {
		return fmt.Errorf("invalid mode of use: %s", modeOfUse)
	}

	if len(clearKey) == 0 || len(clearKey)%2 != 0 {
		return fmt.Errorf("clear key must be a valid hex string")
	}

	return nil
}
