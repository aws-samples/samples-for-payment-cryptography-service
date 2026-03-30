# RSA Key Import/Export for AWS Payment Cryptography

This folder contains sample scripts for importing and exporting clear text symmetric keys to/from AWS Payment Cryptography using RSA wrapping (OAEP with SHA-256).

RSA wrap is suitable for importing TDES (2-key or 3-key) and AES-128 keys. For AES-192 or higher keys, or HMAC keys, use the [ECDH method](../ecdh/) instead. For X9.24-compliant formatted key blocks, use [TR-34](../tr34/).

## Folder Structure

```
rsa/
├── import_app/
│   └── import_raw_key_rsa.py       # Import a clear text key using RSA wrap
├── export_app/
│   └── export_raw_key_from_apc_with_rsa_wrap.py  # Export a key using RSA wrap
├── export_app_with_signature/       # Export with signature verification (Lambda-based)
├── requirements.txt
└── README.md
```

## Prerequisites

- Python 3.8+
- AWS credentials configured (via environment variables, AWS CLI profile, or IAM role)
- Permissions to call AWS Payment Cryptography APIs

### Install Dependencies

```bash
cd samples-for-payment-cryptography-service/key-import-export/rsa

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Import a Key

The import script supports several modes:

### Import a Clear Text Key

Provide the key directly as a hex string:

```bash
python3 import_app/import_raw_key_rsa.py \
  --action importclearkey \
  --clearkey 6E46FE409DF704BCA75E7FF270B65E73 \
  --clearkey_algorithm A \
  --keytype K0 \
  --modeofuse B
```

### Import Using Three Key Components

For split-knowledge key ceremonies, provide three hex components that are XORed together:

```bash
python3 import_app/import_raw_key_rsa.py \
  --action importclearkey \
  --component1 "AAAABBBBCCCCDDDD1111222233334444" \
  --component2 "1111222233334444AAAABBBBCCCCDDDD" \
  --component3 "FFFF0000FFFF00000000FFFF0000FFFF" \
  --clearkey_algorithm A \
  --keytype B0 \
  --modeofuse X
```

### Demo Mode (Random Key)

Generates a random key, wraps it, and imports it — useful for testing:

```bash
python3 import_app/import_raw_key_rsa.py --action demo --keytype K0 --modeofuse B
```

### Import Parameters

| Parameter | Description | Default | Choices |
|-----------|-------------|---------|---------|
| `--action` | Action to perform | `demo` | `demo`, `importclearkey`, `generateWrappingKey`, `importKey` |
| `--clearkey` | Clear text key in hex | | |
| `--component1/2/3` | Key components in hex (XORed together) | | |
| `--clearkey_algorithm` | Key algorithm | `T` | `T` (TDES), `A` (AES) |
| `--keytype` | TR-31 key type | `K0` | `K0`, `K1`, `B0`, `D0`, `P0`, `E0`, `E1`, `E2`, `E3`, `E6`, `C0` |
| `--modeofuse` | TR-31 mode of use | `B` | `B`, `X`, `N`, `E`, `D`, `C`, `G`, `V` |

### Common Key Type / Mode of Use Combinations

| Key Type | Mode of Use | Description |
|----------|-------------|-------------|
| `K0` + `B` | KEK — encrypt and decrypt |
| `B0` + `X` | BDK — derive keys |
| `P0` + `B` | PIN encryption key — encrypt and decrypt |
| `D0` + `B` | Data encryption key — encrypt and decrypt |
| `C0` + `G` | Card verification key — generate |

## Export a Key

```bash
python3 export_app/export_raw_key_from_apc_with_rsa_wrap.py
```

This script generates a local RSA key pair, registers the public key with the service, and exports the target key wrapped under that public key. The clear text key is then recovered locally using the private key.

## How RSA Wrap Works

1. The service generates an RSA key pair and returns the public key certificate
2. The client encrypts the symmetric key using RSA-OAEP (SHA-256) with the service's public key
3. The encrypted key cryptogram is sent to the service via `ImportKey`
4. The service decrypts the key using its private key and stores it

This method is recommended for establishing an initial KEK. Subsequent keys should be imported using TR-31 key blocks wrapped by that KEK.

## Security Note

This sample code uses clear text keys for demonstration purposes. In production, keys should never be handled in clear text outside of a secure cryptographic device. Use key components with split knowledge and dual control procedures.
