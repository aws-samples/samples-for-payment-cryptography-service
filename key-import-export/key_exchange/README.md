# Import Export Migration Scripts
**Note**: Currently supports payShield and Futurex HSMs.  Running TR-34, ECDH and RSA wrap commands relies on access to host (not admin) modules of HSM.  HSM admin consoles do not typically expose this functionality.


## Assumptions
* KDH : Key Distribution Host
* KRD : Key Receiving Device
* Futurex : HSM is configured using PMK. Tested using firmware versions [7.4, 7.6].
* payShield: Tested using firmware versions [1.14].

## Key Exchange using TR34

The script will establish a KEK (Key Encryption Key) between the chosen KDH and KRD. A set of options are supported for KDH and KRD type.
Update the input_config.json file with details on the host connection.
If KDH or KRD is AWS Payment Cryptography, update the region and/or endpoint you would like to connect to.
If KDH or KRD is Futurex or payShield HSM, update the host ip address and port that you would like to stablish the connection to.

As part of the key exchange, if you would like to generate a new symmetric KEK, leave 'transport_key' and 'transport_key_kcv' in the config file for KDH as blank.
If you already have a key created, update the key and kcv in the config file for KDH.

### Commands used when transferring with a payShield
* payShield - EI (create RSA key), B8(export key using TR-34), A0 (create symmetric key, optional only if key to export isn't specified)
* Payment Cryptography - Get Parameters for import, Import Key (KeyMaterial=Tr34KeyBlock), Import Key (type=RootCertificatePublicKey), Import Key (type=TrustedPublicKey, optional only for intermediate CA)
* NOTE: This sample code uses a certificate authority (CA) within the sample code. For production use, we recommend using your own CA or AWS Private Certificate Authority (PCA).
* 
### Usage

* Establish the connection to your chosen Payment HSM and update input config file with host and port info to connect.
* Set AWS credentials for the account you want to use for the service resources. Set the region you want to execute the scripts in input config.

```
python3 import_export_tr34.py --kdh <Options: "futurex | payshield"> --krd <Options: "apc">
```

### Running the phases in separate environments (split HSM / APC)

`import_export_tr34.py` also supports `--mode` to split the exchange so the HSM and AWS Payment Cryptography (APC) can run in separate environments, exchanging a JSON state file. TR-34 touches APC at both ends (each side generates its own certificate and trusts the other's CA), so it splits into the same three phases as RSA:

| Mode | Runs in | Reads | Writes | What it does |
|---|---|---|---|---|
| `get-params` | APC environment | — | params file | Generates the KRD's TR-34 import certificate + chain and import token (`GetParametersForImport`). |
| `export` | HSM environment | params file | export file | Generates the KDH's signing certificate + chain, trusts the KRD CA locally, and builds the TR-34 2-pass payload (wrapped key + nonce). |
| `import` | APC environment | export file | — | Trusts the KDH CA locally, then imports the TR-34 payload using the import token from `get-params`. |
| `full` (default) | both | — | — | Runs all three phases in one process (original behavior). |

File paths follow `--output-file`/`--input-file`, defaulting to `tr34_import_params.json` and `tr34_export_output.json`.

```
# 1) APC environment — get import parameters
python3 import_export_tr34.py --kdh payshield --krd apc --mode get-params --output-file tr34_params.json

# 2) HSM environment — build the TR-34 payload
python3 import_export_tr34.py --kdh payshield --krd apc --mode export --input-file tr34_params.json --output-file tr34_export.json

# 3) APC environment — import the TR-34 payload
python3 import_export_tr34.py --kdh payshield --krd apc --mode import --input-file tr34_export.json

# Or run all three phases in one process (single environment)
python3 import_export_tr34.py --kdh payshield --krd apc --mode full
```

Notes:
* On payShield, the KDH's private key from certificate generation is a live key object, not a serializable token, so KDH key generation and the TR-34 payload build must happen in the same `export` phase (they already do). Futurex uses a key handle string instead, which is JSON-safe either way.
* The import token from `get-params` is time-limited by APC. Run `export` and `import` before it expires.
* Treat the interim files as sensitive: they contain the import token and the TR-34 wrapped key payload.

## Key Exchange using TR31
The script will exchange working keys between KDH and KRD once a KEK is established between KDH and KRD.
Establish a KEK using the Tr34 script and update the kek in the input_config file for both KDH and KRD.

As part of the key exchange, if you would like to generate a new symmetric KEK, leave 'transport_key' and 'transport_key_kcv' in the config file for KDH as blank.
If you already have a key created, update the key and kcv in the config file for KDH.


  
### Usage

* Establish the connection to your chosen Payment HSM and update input config file with host and port info to connect.
* Set AWS credentials for the account you want to use for the service resources. Set the region you want to execute the scripts in input config.

```
python3 import_export_tr31.py --kdh <Options: "futurex | payshield"> --krd <Options: "apc">
```

### Running the phases in separate environments (split HSM / APC)

`import_export_tr31.py` also supports `--mode` to split the exchange. TR-31 uses a KEK that must already be established on both sides (via TR-34 or ECDH), so APC does not need to be contacted before the HSM wraps the key — there is no `get-params` phase, just two:

| Mode | Runs in | Reads | Writes | What it does |
|---|---|---|---|---|
| `export` | HSM environment | — | export file | Wraps the transport key under the KDH's KEK (`kdh_config["tr31"]["kek"]`) using TR-31. |
| `import` | APC environment | export file | — | Imports the wrapped key under the KRD's KEK (`krd_config["tr31"]["kek"]`). |
| `full` (default) | both | — | — | Runs both phases in one process (original behavior). |

File paths follow `--output-file`/`--input-file`, defaulting to `tr31_export_output.json`. No certificates cross the seam for TR-31 — only the TR-31 wrapped key block string.

```
# 1) HSM environment — wrap the transport key under the KEK
python3 import_export_tr31.py --kdh payshield --krd apc --mode export --output-file tr31_export.json

# 2) APC environment — import the wrapped key
python3 import_export_tr31.py --kdh payshield --krd apc --mode import --input-file tr31_export.json

# Or run both phases in one process (single environment)
python3 import_export_tr31.py --kdh payshield --krd apc --mode full
```

Note: both `kdh_config["tr31"]["kek"]` and `krd_config["tr31"]["kek"]` must already be populated (e.g. from a prior TR-34 or ECDH exchange) before running either phase.

## Key Exchange using ECDH
The script will perform key agreement using ECDH between KDH and KRD, derive a shared key which will be the KEK to wrap the transport key.
Using this path, you can import/export upto AES-256 keys.

### Commands used when transferring with a payShield
* Ensure that all commands/APIs are enabled on both HSM and Payment Cryptography side.
* payShield - FY (create ECC key), IG(derive key using ECDH), A8 (export key using TR-31), A0 (create symmetric key, optional only if key to export isn't specified), authorized activty = eckai.K1.host (enable using ECDH to generate Key Block Protection Keys)
* Payment Cryptography - Create Key (ECC type), Get Public Key Certificate, Import Key (KeyMaterial=DiffieHellmanTr31KeyBlock), Import Key (type=RootCertificatePublicKey), Import Key (type=TrustedPublicKey, optional only for intermediate CA)
* NOTE: This sample code uses a certificate authority (CA) within the sample code. For production use, we recommend using your own CA or AWS Private Certificate Authority (PCA).

### Usage

```
python3 import_export_ecdh.py --kdh <Options: "futurex | payshield | apc"> --krd <Options: "apc">
```

### Running the phases in separate environments (split HSM / APC)

`import_export_ecdh.py` also supports `--mode` to split the exchange. ECDH is a mutual key agreement: both sides generate an ECC key pair + certificate and independently derive the same shared KEK, so it splits into the same three phases as RSA/TR-34, but each side's cert is only usable by the other after the handshake completes:

| Mode | Runs in | Reads | Writes | What it does |
|---|---|---|---|---|
| `get-params` | APC environment | — | params file | Generates the KRD's ECC key pair + certificate chain for the key agreement. |
| `export` | HSM environment | params file | export file | Generates the KDH's ECC key pair + certificate chain, trusts the KRD CA locally, derives the shared KEK via ECDH, and TR-31-wraps the transport key under it. |
| `import` | APC environment | export file | — | Trusts the KDH CA locally, independently derives the same KEK via ECDH, and unwraps the transport key. |
| `full` (default) | both | — | — | Runs all three phases in one process (original behavior). |

File paths follow `--output-file`/`--input-file`, defaulting to `ecdh_import_params.json` and `ecdh_export_output.json`.

```
# 1) APC environment — get the KRD key agreement certificate
python3 import_export_ecdh.py --kdh payshield --krd apc --mode get-params --output-file ecdh_params.json

# 2) HSM environment — derive the KEK and wrap the transport key
python3 import_export_ecdh.py --kdh payshield --krd apc --mode export --input-file ecdh_params.json --output-file ecdh_export.json

# 3) APC environment — derive the same KEK and unwrap the transport key
python3 import_export_ecdh.py --kdh payshield --krd apc --mode import --input-file ecdh_export.json

# Or run all three phases in one process (single environment)
python3 import_export_ecdh.py --kdh payshield --krd apc --mode full
```

Notes:
* The derivation parameters (`shared_info`, key derivation function, hash algorithm, derived key algorithm) are carried in the interim JSON so both sides derive the identical KEK; do not edit these files by hand.
* `--kdh apc` is supported (APC acting as its own KDH); in that case both the `get-params`/`export` phases and the `import` phase run against APC, but the split still works the same way.
* payShield with `variant_lmk: true` does not support ECDH; the script exits with an error in that case regardless of mode.

## Key Exchange using RSA (Key Cryptogram)

**Note**: RSA key cryptogram export/import is currently supported only for key block LMKs on payShield. It is not supported when the payShield is configured with a variant LMK (`variant_lmk: true`).

The script exports a symmetric transport key from the KDH as an RSA key cryptogram, wrapped under an RSA public key provided by the KRD, and imports it into the KRD.
AWS Payment Cryptography returns the RSA wrapping public key certificate (and chain) via GetParametersForImport (KeyMaterialType = KEY_CRYPTOGRAM). The KDH wraps the key under that public key using RSA-OAEP (SHA-512 by default) and the KRD imports it using the matching import token.

As part of the key exchange, if you would like to generate a new symmetric key, leave 'transport_key' and 'transport_key_kcv' in the config file for KDH as blank.
If you already have a key created, update the key and kcv in the config file for KDH.

### Commands used when transferring with a payShield
* Ensure that all commands/APIs are enabled on both HSM and Payment Cryptography side.
* payShield - EO (import KRD public key under LMK), BU (calculate KCV), GK (RSA wrap key using OAEP), A0 (create symmetric key, optional only if key to export isn't specified), authorized activity required for import of a key under an RSA key.
* Payment Cryptography - Get Parameters for import (KeyMaterialType=KEY_CRYPTOGRAM), Import Key (KeyMaterial=KeyCryptogram).
* NOTE: This sample code uses a certificate authority (CA) within the sample code. For production use, we recommend using your own CA or AWS Private Certificate Authority (PCA).

### Commands used when transferring with a Futurex
* Ensure that all commands/APIs are enabled on both HSM and Payment Cryptography side.
* Futurex - GPGS (create symmetric key, optional only if key to export isn't specified), AVPC (trust KRD certificate chain and certificate), GPRW (RSA wrap key using OAEP).
* Payment Cryptography - Get Parameters for import (KeyMaterialType=KEY_CRYPTOGRAM), Import Key (KeyMaterial=KeyCryptogram).
* NOTE: This sample code uses a certificate authority (CA) within the sample code. For production use, we recommend using your own CA or AWS Private Certificate Authority (PCA).

### Usage

* Establish the connection to your chosen Payment HSM and update input config file with host and port info to connect.
* Set AWS credentials for the account you want to use for the service resources. Set the region you want to execute the scripts in input config.

```
python3 import_export_rsa.py --kdh <Options: "futurex | payshield"> --krd <Options: "apc">
```

### Configurable key metadata (RSA)

The metadata describing the transport key is read from the KDH `rsa` block in `input_config.json`, so it can match the actual key being exported without editing code. AWS Payment Cryptography validates these attributes against the wrapped key material during import; a mismatch (for example declaring `TDES_3KEY` for a `TDES_2KEY` key) raises `ValidationException: Actual KeyAlgorithm of the WrappedKey is mismatching ...`.

| Field | Purpose | Example | Default |
|---|---|---|---|
| `key_algorithm` | Algorithm of the transport key. Must match the real key. | `TDES_2KEY` | `TDES_3KEY` |
| `apc_key_usage` | APC `KeyUsage` (`TR31_*`) applied on import into APC. | `TR31_K0_KEY_ENCRYPTION_KEY` | `TR31_K0_KEY_ENCRYPTION_KEY` |
| `apc_key_modes_of_use` | APC `KeyModesOfUse` object applied on import into APC. | `{ "Decrypt": true, "Unwrap": true }` | `{ "Encrypt": true, "Decrypt": true, "Wrap": true, "Unwrap": true }` |

* Valid `key_algorithm` values: `TDES_2KEY`, `TDES_3KEY`, `AES_128`, `AES_192`, `AES_256`.
* `apc_key_usage` accepts any `TR31_*` KeyUsage supported by APC, and `apc_key_modes_of_use` any combination of `Encrypt`, `Decrypt`, `Wrap`, `Unwrap`, `Generate`, `Verify`, `DeriveKey`, `NoRestrictions`. For the allowed usage/algorithm/mode combinations, see [Valid keys for cryptographic operations](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/crypto-ops-validkeys-ops.html).
* `apc_key_usage` and `apc_key_modes_of_use` are optional. When omitted, they default to a key-encryption key with full modes of use.

Example `rsa` block:

```json
"rsa": {
    "transport_key": "S10096V0TC00...",
    "transport_key_kcv": "5F30B6",
    "key_algorithm": "TDES_2KEY",
    "apc_key_usage": "TR31_K0_KEY_ENCRYPTION_KEY",
    "apc_key_modes_of_use": {
        "Encrypt": true,
        "Decrypt": true,
        "Wrap": true,
        "Unwrap": true
    }
}
```

### Running the phases in separate environments (split HSM / APC)

By default `import_export_rsa.py` runs the whole exchange end to end, which requires the environment running the script to reach **both** the HSM and AWS Payment Cryptography (APC). Some environments cannot reach both at once. For those cases the flow can be split into three phases with the `--mode` flag, exchanging a small JSON state file between environments.

The RSA key-cryptogram exchange is ordered `APC -> HSM -> APC`, so it splits into:

| Mode | Runs in | Reads | Writes | What it does |
|---|---|---|---|---|
| `get-params` | APC environment | — | params file | Calls `GetParametersForImport`; captures the import token and the RSA wrapping certificate + chain. |
| `export` | HSM environment | params file | export file | RSA-wraps the transport key under the wrapping certificate; produces the key cryptogram. |
| `import` | APC environment | export file | — | Imports the key cryptogram into APC using the import token. |
| `full` (default) | both | — | — | Runs all three phases in one process (original behavior). |

File paths are controlled with `--output-file` (written by `get-params` and `export`) and `--input-file` (read by `export` and `import`). When omitted they default to `rsa_import_params.json` (params) and `rsa_export_output.json` (export).

#### Split usage

```
# 1) APC environment — get import parameters
python3 import_export_rsa.py --kdh payshield --krd apc --mode get-params --output-file rsa_params.json
#    Copy rsa_params.json to the HSM environment.

# 2) HSM environment — wrap the transport key
python3 import_export_rsa.py --kdh payshield --krd apc --mode export --input-file rsa_params.json --output-file rsa_export.json
#    Copy rsa_export.json back to the APC environment.

# 3) APC environment — import the key cryptogram
python3 import_export_rsa.py --kdh payshield --krd apc --mode import --input-file rsa_export.json

# Or run all three phases in one process (single environment)
python3 import_export_rsa.py --kdh payshield --krd apc --mode full
```

Notes:
* The `input_config.json` still supplies the HSM connection and transport key details on the HSM side, and the APC region on the APC side. Populate each environment's config with the parts it needs.
* The interim JSON files carry the `key_algorithm`, `apc_key_usage`, and `apc_key_modes_of_use` metadata forward, so those only need to be set once (before the `get-params` phase). x509 certificates are carried as PEM text inside the JSON.
* The import token from `get-params` is time-limited by APC. Run the `export` and `import` phases before it expires (otherwise re-run `get-params`).
* Treat the interim files as sensitive: they contain the import token and the wrapped key cryptogram. Transfer them over a secure channel and delete them once the import succeeds.

#### Interim JSON schema

`get-params` output (params file):

```json
{
    "krd": "apc",
    "krd_wrapping_key_algorithm": "RSA_4096",
    "key_algorithm": "TDES_2KEY",
    "apc_key_usage": "TR31_K0_KEY_ENCRYPTION_KEY",
    "apc_key_modes_of_use": { "Encrypt": true, "Decrypt": true, "Wrap": true, "Unwrap": true },
    "import_token": "import-token-...",
    "krd_certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "krd_ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

`export` output (export file) adds the wrapping result to the above:

```json
{
    "kdh": "payshield",
    "rsa_cryptogram": "....",
    "transport_key_kcv": "5F30B6",
    "wrapping_spec": "RSA_OAEP_SHA_512"
}
```

## Key check value (KCV) algorithm

When a key is imported into AWS Payment Cryptography, APC returns a key check value (KCV) that you can compare against the source KCV to confirm the key material transferred intact. The KCV algorithm must match the type of key being imported, otherwise the returned KCV will not match the value your HSM computed:

* **TDES keys** use `ANSI_X9_24` (the legacy KCV: encrypt an all-zero block with the key, keep the 3 highest-order bytes).
* **AES keys** use `CMAC` (CMAC over 16 zero bytes, keep the 3 highest-order bytes).

All four scripts select the KCV algorithm automatically for the key being transferred, following the same convention as `key-import-export/rsa/import_app/import_raw_key_rsa.py` (`TDES -> ANSI_X9_24`, `AES -> CMAC`):

* **RSA, TR-31, TR-34** derive the KCV algorithm from the transport key's declared algorithm (`key_algorithm` in the RSA config block, or the default TDES/AES for the flow).
* **ECDH** derives the KCV algorithm from the transport key's own TR-31 key block header (the algorithm indicator character), **not** from the AES key derived via ECDH that is used to wrap it. This keeps the KCV correct for a TDES transport key while leaving the ECDH wrapping untouched. Because ECDH is only supported under a key block LMK (payShield variant LMK is rejected up front), the transport key always carries a parseable key block header, so no additional configuration is required.
