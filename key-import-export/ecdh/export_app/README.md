# Export a Symmetric Key using ECDH and TR-31

> **⚠️ WARNING: DEVELOPMENT / TESTING USE ONLY**
>
> This script handles cleartext key material and uses a locally-generated, self-signed
> certificate for its Certificate Authority trust chain. This approach is **not compliant**
> with PCI PIN Security, PCI DSS, or similar payment industry key-management requirements
> for production use. Do not run it against production AWS accounts or production key
> material.
>
> On every run, the script prints this warning and requires you to interactively type
> `yes` at a confirmation prompt before it will proceed. This cannot be bypassed with an
> environment variable or command-line flag -- it must be a deliberate action taken by
> whoever is running the script, so it can't be silently baked into a scheduled job or
> CI/CD pipeline.

This sample script is the mirror image of [`../import_app/import_raw_key_ecdh.py`](../import_app/import_raw_key_ecdh.py). Instead of importing a cleartext key *into* **AWS Payment Cryptography**, it **exports** an existing exportable key *out* of AWS Payment Cryptography (APC) to cleartext, using Asymmetric Key Exchange (ECDH) and TR-31 key blocks so the key material is never sent unprotected over the network.

Note: As this script handles cleartext key material, it is intended strictly for testing environments and proof-of-concept purposes.

## Prerequisites

### Python Dependencies
This script relies on the `cryptography` library for low-level cryptographic operations, `psec` for TR-31 related operations, `pycryptodome` for KCV calculation, and `boto3` for AWS interactions.

```bash
pip install boto3 cryptography pycryptodome psec
```

### AWS Permissions
The AWS credentials used to run this script must have permissions for the following actions in AWS Payment Cryptography:
*   `payment-cryptography:GetKey`
*   `payment-cryptography:CreateKey`
*   `payment-cryptography:ExportKey`
*   `payment-cryptography:ImportKey`
*   `payment-cryptography:GetPublicKeyCertificate`
*   `payment-cryptography:CreateAlias`
*   `payment-cryptography:UpdateAlias`
*   `payment-cryptography:GetAlias`

The target key you wish to export must have `Exportable=True`. For IPEK export (see [`--ksn`](#exporting-an-ipek)), the target key must additionally have `KeyUsage=TR31_B0_BASE_DERIVATION_KEY`.

## How It Works

The script automates the reverse of the import key ceremony:

1.  **Key Lookup:** Calls `GetKey` on the target `--key-arn` to confirm it exists, is `Exportable`, and to learn its `KeyAlgorithm` (needed for KCV calculation).
2.  **APC-side ECDH Key:** Creates (or reuses) an ECC NIST P-521 Key Pair in AWS. This key plays the "sender" role in the ECDH exchange; its private key never leaves AWS Payment Cryptography.
3.  **Get APC Certificate:** Retrieves the public key certificate of the AWS-hosted ECDH key.
4.  **Receiver Credentials (Local):** Generates a local ECC P-521 key pair and a self-signed Root CA certificate ("receiver", since we are receiving the exported key material). These are saved locally to a `certs/` directory.
5.  **Import Receiver Root CA:** Imports the local Receiver's Root Certificate into AWS (as a `TR31_S0` Public Key) so APC will trust our receiving certificate for this exchange.
6.  **Key Derivation (ECDH), performed locally:**
    *   Performs an Elliptic Curve Diffie-Hellman exchange between the Local Receiver Private Key and the AWS ECDH Public Key.
    *   Derives a shared secret.
    *   Uses **NIST SP 800-56A Concatenation KDF** (with SHA-256) to derive a temporary **AES-256 Unwrapping Key**. This exactly mirrors the derivation APC performs internally with the same `SharedInformation`.
7.  **ExportKey:** Calls `ExportKey` on AWS Payment Cryptography, passing the same ECDH derivation parameters. APC wraps the target key in a TR-31 Key Block using its own derived AES-256 key and returns the wrapped block.
8.  **TR-31 Unwrapping (local):** Unwraps the returned TR-31 Key Block locally using the independently-derived AES-256 unwrapping key, recovering the cleartext key. The locally-calculated KCV is compared against APC's reported KCV as an integrity check.
9.  **Output:** Prints the cleartext key in the form requested via `--output` (see below).

## Usage

```bash
python export_raw_key_ecdh.py --region <region> --profile <profile_name> --key-arn <key_arn_or_alias> \
                         [--ksn <hex>] \
                         [--output <full|2-component|3-component>] \
                         [--suppress-key-output] \
                         [--shared-info <hex>]
```

Every run first prints the development-use-only warning and requires you to type `yes` at the confirmation prompt shown above before continuing.

### `--output` options

| Value | Description |
| :--- | :--- |
| `full` (default) | Prints the entire cleartext key as a single hex string, plus its KCV. |
| `2-component` | Splits the key into 2 randomly-generated components that XOR back to the original key (standard manual key-component scheme), printing each component and its KCV. |
| `3-component` | Same as above, but with 3 components. |

Use `--suppress-key-output` to print only KCVs (no key/component values) -- useful when running the script in the presence of others, e.g. during a dual-control key ceremony where each custodian should see only their own component out-of-band.

### Examples

#### Example 1: Export as a single full key

```bash
python export_raw_key_ecdh.py \
    --region us-east-1 \
    --profile default \
    --key-arn arn:aws:payment-cryptography:us-east-1:111122223333:key/abcd1234efgh5678 \
    --output full
```

#### Example 2: Export as 2 key components

```bash
python export_raw_key_ecdh.py \
    --region us-east-1 \
    --profile default \
    --key-arn alias/my-kek \
    --output 2-component
```

#### Example 3: Export as 3 key components, suppressing key values on screen

```bash
python export_raw_key_ecdh.py \
    --region us-east-1 \
    --profile default \
    --key-arn alias/my-kek \
    --output 3-component \
    --suppress-key-output
```

### Exporting an IPEK

Provide `--ksn` to export an **IPEK (Initial PIN Encryption Key)** for DUKPT, derived on the fly by AWS Payment Cryptography from a BDK (Base Derivation Key) plus the supplied Key Serial Number, instead of exporting `--key-arn`'s own key material directly.

Requirements:
*   `--key-arn` must identify a key with `KeyUsage=TR31_B0_BASE_DERIVATION_KEY` (checked before any export call is attempted; the script fails fast with a clear error otherwise).
*   `--ksn` must already be padded per the AWS Payment Cryptography `ExportKey` API: **20 hex characters** for a `TDES_2KEY` BDK, or **24 hex characters** for an AES BDK. The script validates this length against the BDK's actual algorithm before calling AWS.
*   The derived IPEK does **not** persist within AWS Payment Cryptography -- it's recomputed by APC on every export call that supplies a KSN, so exporting the same BDK+KSN combination again always yields the same IPEK.

The TR-31 header returned for an IPEK export will show `key_usage: B1` (Initial Key), not `B0` -- this confirms APC exported the derived IPEK rather than the BDK itself.

#### Example 4: Export an IPEK from a BDK

```bash
python export_raw_key_ecdh.py \
    --region us-east-1 \
    --profile default \
    --key-arn alias/my-bdk \
    --ksn FFFF9876543210E00000 \
    --output full
```

## Resources Created

### Local Files
The script creates a `certs/` directory in the execution path containing:
*   `receiver_key.pem`: The local private key used for the exchange.
*   `receiver_cert.pem`: The local public certificate imported into AWS as a trusted Root CA.

### AWS Resources
The script creates (or reuses) the following Aliases and underlying Keys:

| Alias | Type | Description |
| :--- | :--- | :--- |
| `alias/export-ecdh-sender` | ECC_NIST_P521 | The AWS-side key used for Key Agreement (APC's "sender" role for this exchange). |
| `alias/export-ecdh-receiver-root` | ECC_NIST_P521 | The imported public key of your local Receiver CA. |

Unlike the import script, no new symmetric key is created in APC -- the target key specified by `--key-arn` is exported (read), not modified.

## Technical Details

### TR-31 Header
The TR-31 header returned by APC in the wrapped key block reflects the target key's actual `KeyUsage`, `KeyAlgorithm`, `KeyModesOfUse`, and exportability, as originally configured when the key was created/imported into APC (or, for IPEK export, the derived IPEK's `B1` usage). The script reads this header back after unwrapping and prints it for reference.

### Shared Information
The Key Derivation Function (KDF) uses a randomly-generated `SharedInformation` hex string by default (override with `--shared-info` if you need a specific value). This is passed to the AWS `ExportKey` API's `DerivationData.SharedInformation` field to ensure APC derives the exact same wrapping key that this script derives locally.

## Cleanup

To clean up resources created by this script, you can run:

```bash
aws payment-cryptography delete-alias --alias-name alias/export-ecdh-sender
aws payment-cryptography delete-alias --alias-name alias/export-ecdh-receiver-root
# You will also need to schedule key deletion for the specific Key ARNs printed in the script output.
# The originally exported key (--key-arn) is NOT deleted by this script or this cleanup step.
```
