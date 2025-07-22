# AWS Payment Cryptography ECDH-TR31 Key Exchange

This application demonstrates the integration between AWS Payment Cryptography and a local CA
for secure key management and cryptographic operations using ECDH key exchange with TR31 format.

## Features

- Create and manage a local Certificate Authority (CA)
- Generate ECDH key pairs locally and in AWS Payment Cryptography
- Perform secure key exchange using ECDH and TR31 format
- Support for both key import and export operations
- Support for multiple key types:
  - AES-256 (32 bytes / 256 bits)
  - Triple DES 2-Key (16 bytes / 128 bits)
  - Triple DES 3-Key (24 bytes / 192 bits)
- Interactive CLI for operation selection

## Prerequisites

- Python 3.8+
- AWS account with Payment Cryptography service enabled
- AWS credentials configured locally

## Installation

1. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # On macOS/Linux
.venv\Scripts\activate     # On Windows
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode

Run the application without arguments for interactive mode:

```bash
python main.py
```

#### Interactive Operation Selection

The application will present an interactive menu to select between:
- `Import a key from a raw plaintext key into AWS Payment Cryptography`: Import a key into AWS Payment Cryptography
- `Export a key from AWS Payment Cryptography to plaintext`: Export an existing key from AWS Payment Cryptography

Use the up/down arrow keys to navigate and Enter to select an option.

#### Key Type Selection

You'll be prompted to select the key type:
- **AES-256 (32 bytes / 256 bits)**: Advanced Encryption Standard with 256-bit key length
- **Triple DES 2-Key (16 bytes / 128 bits)**: Triple DES with two distinct key components
- **Triple DES 3-Key (24 bytes / 192 bits)**: Triple DES with three distinct key components

#### Import Key Options

If you select the import operation, you'll be presented with another menu to choose how to provide the key:

1. **Generate a random key**: The application will automatically generate a secure random key of the selected type
2. **Enter a custom hexadecimal key**: You can manually enter a key in hexadecimal format

For custom key entry, the application will validate that:
- The key has the correct length for the selected key type:
  - AES-256: 64 hexadecimal characters (32 bytes)
  - TDES_2KEY: 32 hexadecimal characters (16 bytes)
  - TDES_3KEY: 48 hexadecimal characters (24 bytes)
- All characters are valid hexadecimal digits (0-9, A-F, a-f)

### Command-Line Arguments

You can also run the application with command-line arguments to bypass the interactive prompts:

```bash
# Export operation with AES-256 key
python main.py --operation export --key-type AES_256

# Export operation with TDES_2KEY
python main.py --operation export --key-type TDES_2KEY

# Import operation with random AES-256 key
python main.py --operation import --import-method random --key-type AES_256

# Import operation with custom AES-256 key
python main.py --operation import --import-method custom --key-type AES_256 --key 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F

# Import operation with custom TDES_2KEY
python main.py --operation import --import-method custom --key-type TDES_2KEY --key 0123456789ABCDEF0123456789ABCDEF

# Import operation with custom TDES_3KEY
python main.py --operation import --import-method custom --key-type TDES_3KEY --key 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
```

#### Available Arguments

| Argument | Description | Values |
|----------|-------------|--------|
| `--operation` | Operation mode | `import`, `export` |
| `--key-type` | Type of key | `AES_256`, `TDES_2KEY`, `TDES_3KEY` |
| `--import-method` | Key import method | `random`, `custom` |
| `--key` | Custom key in hex format | Hex characters (length depends on key type) |

You can mix command-line arguments with interactive prompts. For example, specifying just the operation will still prompt for the import method and key if needed.

## Application Flow

### Input Collection Phase
- The application first collects all necessary inputs:
  - Operation mode (import or export)
  - For import operations: import method (random or custom key)
  - For custom key imports: the key value in hexadecimal format

### Execution Phase

#### Common Steps (1-7)
1. Create Local CA and import public CA key
2. Locally create an ECDH KeyPair
3. Sign the local KeyPair with Local CA
4. Create an ECDH KeyPair in AWS Payment Cryptography
5. Get the server's public key certificate
6. Generate shared information for key derivation
7. Derive shared secret for key wrapping

#### Export Operation (Steps 8-10)
8. Create a data encryption key of the selected type (AES_256, TDES_2KEY, or TDES_3KEY) in AWS Payment Cryptography
9. Export the key wrapped under ECDH key using TR31
10. Unwrap the exported key locally

#### Import Operation (Steps 8-10)
8. Get key to import (random generation or use provided custom key) of the selected type
9. Wrap key using TR31 format with the appropriate algorithm identifier (A for AES, T for TDES)
10. Import the wrapped key into AWS Payment Cryptography

#### Verification (Step 11)
11. Calculate and verify Key Check Value (KCV)

## Directory Structure

- `main.py`: Main application script
- `crypto_utils.py`: Cryptographic utility functions
- `tr31.py`: TR31 key block operations
