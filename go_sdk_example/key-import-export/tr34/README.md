# TR-34 Key Import/Export for AWS Payment Cryptography Service

This Go implementation provides TR-34 protocol support for importing and exporting symmetric keys to/from AWS Payment Cryptography Service.

## Overview

This implementation provides complete support for both TR-34 and TR-31 protocols:

- **TR-34**: An asymmetric key exchange protocol for initial key bootstrapping to establish a Key Encryption Key (KEK)
- **TR-31**: A symmetric key exchange protocol for importing/exporting working keys using an established KEK

This implementation allows you to:

- Import 3DES and AES keys into AWS Payment Cryptography Service using TR-34
- Export keys from AWS Payment Cryptography Service using TR-34
- Import working keys using TR-31 format with full standard compliance
- Export keys in TR-31 format for distribution to other systems
- Set up complete demonstration keys for testing payment cryptography workflows

## Project Structure

```
.
├── cmd/
│   ├── import/         # TR-34 import command
│   ├── export/         # TR-34 export command
│   ├── tr31-import/    # TR-31 import command
│   └── tr31-export/    # TR-31 export command
├── internal/
│   └── config/        # Configuration handling
├── pkg/
│   ├── client/        # AWS Payment Cryptography client wrapper
│   ├── logger/        # Logging utilities
│   ├── tr34/          # TR-34 protocol implementation
│   ├── tr31/          # TR-31 protocol implementation (with moov-io/tr31)
│   └── utils/         # Utility functions
├── cleanup.sh         # Cleanup demo resources
├── demo-export.sh     # Export keys created by demo setup
├── demo-setup.sh      # Basic demo setup
└── go.mod
```

## Building

```bash
# Build all commands at once
make build

# Or build individually
go build -o tr34-import ./cmd/import
go build -o tr34-export ./cmd/export
go build -o tr31-import ./cmd/tr31-import
go build -o tr31-export ./cmd/tr31-export
```

## Usage

### TR-34 Key Import

```bash
# Import a 3DES KEK
./build/tr34-import --clearkey 79ADAEF3212AADCE312ACE422ACCFEFB

# Import an AES key with specific options
./build/tr34-import --clearkey 0123456789ABCDEF0123456789ABCDEF -a A -t B0 -m X
```

### TR-34 Key Export

```bash
# Export a key from AWS
./build/tr34-export --keyalias alias/my-key --verbose
```

### TR-31 Key Import

```bash
# Import a working key using TR-31
./build/tr31-import \
  --kbpkkey_apcIdentifier arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
  --kbpk_clearkey 79ADAEF3212AADCE312ACE422ACCFEFB \
  --kek_algorithm T \
  --clearkey 8A8349794C9EE9A4C2927098F249FED6 \
  --keytype B0 \
  --modeofuse X \
  --algorithm T \
  --alias alias/my-bdk
```

### TR-31 Key Export

```bash
# Export a key in TR-31 format
./build/tr31-export \
  --key arn:aws:payment-cryptography:us-east-1:123456789012:key/def456 \
  --kek arn:aws:payment-cryptography:us-east-1:123456789012:key/abc123 \
  --verbose
```

### Command Line Options

#### Import Command

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--clearkey` | | Clear text key to import (hex format) | Required |
| `--exportmode` | `-e` | Export mode - E (exportable), S (sensitive), or N (non-exportable) | E |
| `--algorithm` | `-a` | Algorithm of key - T (3DES) or A (AES) | T |
| `--keytype` | `-t` | Key type according to TR-31 | K0 |
| `--modeofuse` | `-m` | Mode of use according to TR-31 | B |
| `--alias` | | Alias name for the imported key | |
| `--region` | `-r` | AWS region | us-east-1 |
| `--profile` | `-p` | AWS profile to use | |
| `--verbose` | `-v` | Enable verbose logging | false |

### TR-31 Key Types

| Type | Description |
|------|-------------|
| K0 | Key encryption or wrapping |
| K1 | TR-31 key block protection key |
| B0 | Base derivation key (BDK) |
| D0 | Data encryption - symmetric and asymmetric |
| P0 | PIN encryption |
| E0 | EMV/chip issuer master key |
| E1 | EMV/chip ICC master key |
| E2 | EMV/chip ICC application cryptogram key |
| E3 | EMV/chip issuer script key |
| E6 | EMV/chip ARPC generation and ARQC verification |
| C0 | Card verification key |

### TR-31 Modes of Use

| Mode | Description |
|------|-------------|
| B | Both encrypt and decrypt |
| X | Key derivation |
| N | No special restrictions |
| E | Encrypt only |
| D | Decrypt only |
| C | Calculate MAC (generate and verify) |
| G | Generate MAC only |
| V | Verify MAC only |

## AWS Configuration

The tool uses standard AWS SDK configuration. You can configure credentials using:

1. Environment variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
```

2. AWS credentials file (`~/.aws/credentials`)
```ini
[default]
aws_access_key_id = your_access_key
aws_secret_access_key = your_secret_key

[dev]
aws_access_key_id = dev_access_key
aws_secret_access_key = dev_secret_key
```

3. IAM role (when running on EC2/ECS/Lambda)

## Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "payment-cryptography:CreateAlias",
                "payment-cryptography:CreateKey",
                "payment-cryptography:DeleteAlias",
                "payment-cryptography:DeleteKey",
                "payment-cryptography:ExportKey",
                "payment-cryptography:GetAlias",
                "payment-cryptography:GetKey",
                "payment-cryptography:GetParametersForExport",
                "payment-cryptography:GetParametersForImport",
                "payment-cryptography:ImportKey",
                "payment-cryptography:ListKeys",
                "payment-cryptography:UpdateAlias"
            ],
            "Resource": "*"
        }
    ]
}
```

## Demo Setup Scripts

### Complete Demo Setup (TR-34 + TR-31)
```bash
# Import KEK and all working keys
./demo-setup.sh --region us-east-1 --profile default
```

The demo setup imports:
- **KEK (Key Encryption Key)**: Imported via TR-34 for subsequent key wrapping
- **BDK (Base Derivation Key)**: For DUKPT key derivation (both TDES and AES)
- **PEK (PIN Encryption Key)**: For PIN block encryption/decryption
- **MAC Key**: For message authentication
- **ARQC Key**: For cryptogram validation
- **PVK (PIN Verification Key)**: Generated directly in AWS for PIN verification

### Export Demo
```bash
# Export keys from AWS Payment Cryptography Service
./demo-export.sh --region us-east-1 --profile default
```

### Cleanup Demo Resources
```bash
# Preview what will be deleted (dry run)
./cleanup.sh --dry-run

# Delete all demo keys with confirmation
./cleanup.sh --region us-east-1 --profile dev

# Delete without confirmation prompts
./cleanup.sh --force
```

## Development

### Building with Make

```bash
# Build all binaries
make build

# Build specific binaries
make build-import       # Build TR-34 import tool
make build-export       # Build TR-34 export tool
make build-tr31         # Build TR-31 import tool
make build-tr31-export  # Build TR-31 export tool

# Clean build artifacts
make clean

# Format code
make fmt

# Run go vet
make vet

# Download dependencies
make deps

# Install binaries to GOPATH/bin
make install

# Complete build pipeline (clean, deps, fmt, vet, test, build)
make all

# Show help with all available targets
make help
```
