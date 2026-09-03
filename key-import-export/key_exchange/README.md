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

## Key Exchange using RSA (Key Cryptogram)
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
python3 import_export_rsa.py --kdh payshield --mode get-params --output-file params.json
#    Copy params.json to the HSM environment.

# 2) HSM environment — wrap the transport key
python3 import_export_rsa.py --kdh payshield --mode export --input-file params.json --output-file export.json
#    Copy export.json back to the APC environment.

# 3) APC environment — import the key cryptogram
python3 import_export_rsa.py --kdh payshield --mode import --input-file export.json
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
