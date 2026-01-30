# Import AES-256 KEK using ECDH and TR-31

This sample script demonstrates how to securely import a symmetric AES-256 Key Encryption Key (KEK) into **AWS Payment Cryptography** using Asymmetric Key Exchange (ECDH) and TR-31 key blocks.

This script demonstrates the import of a cleartext AES-256 Key Encryption Key (KEK), establishing a secure channel for transporting subsequent keys between AWS Payment Cryptography and your local environment. With AES-256, this KEK provides sufficient strength to wrap and transport the majority of key types supported by APC.

Note: As this script handles cleartext key material via CLI arguments, it is intended strictly for testing environments and proof-of-concept purposes.

## Prerequisities

### Python Dependencies
Ensure you have the following Python libraries installed. This script relies heavily on the `cryptography` library for low-level cryptographic operations, `psec` for TR-31 related operations and `boto3` for AWS interactions.

```bash
pip install boto3 cryptography argparse psec
```

### AWS Permissions
The AWS credentials used to run this script must have permissions for the following actions in AWS Payment Cryptography:
*   `payment-cryptography:CreateKey`
*   `payment-cryptography:ImportKey`
*   `payment-cryptography:GetPublicKeyCertificate`
*   `payment-cryptography:CreateAlias`
*   `payment-cryptography:UpdateAlias`
*   `payment-cryptography:GetAlias`

## How It Works

The script automates a complex manual key ceremony. Here is the step-by-step workflow:

1.  **Receiver Key Creation (AWS):** Creates an ECC NIST P-521 Key Pair in AWS. This key is used for Key Agreement (ECDH).
2.  **Get Receiver Certificate:** Retrieves the public key certificate of the AWS-hosted receiver key.
3.  **Sender Credentials (Local):** Generates a local ECC P-521 key pair and a self-signed Root CA certificate. These are saved locally to a `certs/` directory.
4.  **Import Root CA:** Imports the local Sender's Root Certificate into AWS (as a `TR31_S0` Public Key) to establish trust.
5.  **Key Derivation (ECDH):**
    *   Performs an Elliptic Curve Diffie-Hellman exchange between the Local Sender Private Key and the AWS Receiver Public Key.
    *   Derives a shared secret.
    *   Uses **NIST SP 800-56A Concatenation KDF** (with SHA-256) to derive a temporary **AES-256 Wrapping Key**.
6.  **TR-31 Wrapping:** Wraps the cleartext AES-256 KEK (provided via CLI) into a TR-31 Key Block using the derived wrapping key.
7.  **Final Import:** Calls `ImportKey` on AWS Payment Cryptography, passing the TR-31 block, the sender's leaf certificate, and key exchange parameters.

## Usage

Run the script from the command line passing the AWS Region, AWS CLI Profile, and the cleartext key you wish to import (in Hexadecimal format).

```bash
python import_kek_ecdh.py --region <region> --profile <profile_name> --kek <32_byte_hex_key>
```

### Example

To import a dummy AES-256 key (`0000...`):

```bash
python import_kek_ecdh.py \
    --region us-east-1 \
    --profile default \
    --kek 1111222233334444555566667777888811112222333344445555666677778888
```

## Resources Created

### Local Files
The script creates a `certs/` directory in the execution path containing:
*   `sender_key.pem`: The local private key used for the exchange.
*   `sender_cert.pem`: The local public certificate imported into AWS.

### AWS Resources
The script creates (or updates) the following Aliases and underlying Keys:

| Alias | Type | Description |
| :--- | :--- | :--- |
| `alias/import-kek-ecdh-receiver` | ECC_NIST_P521 | The AWS-side key used for Key Agreement. |
| `alias/import-kek-ecdh-sender-root` | ECC_NIST_P521 | The imported public key of your local Sender CA. |
| `alias/import-kek-ecdh-result` | AES-256 | **The final imported KEK.** |

## Technical Details

### TR-31 Header
The script hardcodes the TR-31 header to **`D0000K0AB00E0000`**. This signifies:
*   **D:** Version D (AES Key Derivation Binding Method).
*   **K0:** Key Usage is Key Encryption or Wrapping.
*   **A:** Algorithm is AES.
*   **B:** Mode of Use is Both (Encrypt and Decrypt).
*   **E:** Exportable.

### Shared Information
The Key Derivation Function (KDF) uses a static shared info string `0123456789` (hex). This matches the `SharedInformation` parameter sent to the AWS `ImportKey` API to ensure the cloud service derives the exact same wrapping key.

## Cleanup

To clean up resources created by this script, you can run:

```bash
aws payment-cryptography delete-alias --alias-name alias/import-kek-ecdh-receiver
aws payment-cryptography delete-alias --alias-name alias/import-kek-ecdh-sender-root
aws payment-cryptography delete-alias --alias-name alias/import-kek-ecdh-result
# You will also need to schedule key deletion for the specific Key ARNs printed in the script output.
```