# AWS Payment Cryptography ECDH-TR31 Key Exchange

This application demonstrates the integration between AWS Payment Cryptography and a local CA
for secure key management and cryptographic operations using ECDH key exchange with TR31 format.

## Features

- Create and manage a local Certificate Authority (CA)
- Generate ECDH key pairs locally and in AWS Payment Cryptography
- Perform secure key exchange using ECDH and TR31 format
- Support for both key import and export operations
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

#### Import Key Options

If you select the import operation, you'll be presented with another menu to choose how to provide the key:

1. **Generate a random AES-256 key**: The application will automatically generate a secure random 256-bit key
2. **Enter a custom hexadecimal key**: You can manually enter a 32-byte (64 hex characters) key in hexadecimal format

For custom key entry, the application will validate that:
- The key is exactly 64 hexadecimal characters (32 bytes)
- All characters are valid hexadecimal digits (0-9, A-F, a-f)

### Command-Line Arguments

You can also run the application with command-line arguments to bypass the interactive prompts:

```bash
# Export operation
python main.py --operation export

# Import operation with random key
python main.py --operation import --import-method random

# Import operation with custom key
python main.py --operation import --import-method custom --key 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
```

#### Available Arguments

| Argument | Description | Values |
|----------|-------------|--------|
| `--operation` | Operation mode | `import`, `export` |
| `--import-method` | Key import method | `random`, `custom` |
| `--key` | Custom key in hex format | 64 hex characters |

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
8. Create an AES-256 data encryption key in AWS Payment Cryptography
9. Export the AES-256 key wrapped under ECDH key using TR31
10. Unwrap the exported key locally

#### Import Operation (Steps 8-10)
8. Get key to import (random generation or use provided custom key)
9. Wrap key using TR31 format
10. Import the wrapped key into AWS Payment Cryptography

#### Verification (Step 11)
11. Calculate and verify Key Check Value (KCV)

## Directory Structure

- `main.py`: Main application script
- `crypto_utils.py`: Cryptographic utility functions
- `tr31.py`: TR31 key block operations
- `ca_storage/`: Local storage for CA certificates and keys