# Import Keys

Importing keys is a prerequisite to run the JAVA samples.

The Python samples are used to import clear text keys. The key import app already has sample clear text keys defined and can be run as is. The same keys and aliases defined in the Python app here are used in the JAVA samples app. Look under `java_sdk_example/src/main/java/aws/sample/paymentcryptography/ServiceConstants.java`.

You can change the clear text Hex keys in order to import your own key. If you do change the PEK or MAC keys in the import app you will need to set the same values in `java_sdk_example/src/main/java/aws/sample/paymentcryptography/TerminalConstants.java` under "PEK" and "MAC_KEY_PLAIN_TEXT" variables.

If you change the BDK key, you will need to generate corresponding DUKPT variants along with KSN using the BDK key and set those variants in `java_sdk_example/src/main/java/aws/sample/paymentcryptography/p2pe/key-ksn-data.json` with the corresponding KSN. Refer to https://github.com/SoftwareVerde/java-dukpt for information on DUKPT keys and variants.

---

## import_raw_key_tr34.py

This script imports a clear text symmetric key into AWS Payment Cryptography using a TR-34 2012 key block. It supports three ways to provide the key:

| Mode | Description |
|------|-------------|
| `--clearkey` | Provide the key directly as a hex string |
| `--component1/2/3` | Provide 2 or 3 hex components via flags — XORed together to form the key |
| `--prompt-components` | Interactive ceremony mode — components are entered at the terminal with masked input and KCV verification |

### Setup

```bash
cd samples-for-payment-cryptography-service/key-import-export/tr34/import_app

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install boto3 pycryptodome cryptography
```

### Usage

#### Single clear key

```bash
python3 import_raw_key_tr34.py \
  --clearkey 8A8349794C9EE9A4C2927098F249FED6 \
  --algorithm T --keytype K0 --modeofuse B
```

#### Key components via flags

```bash
python3 import_raw_key_tr34.py \
  --component1 AAAABBBBCCCCDDDD1111222233334444 \
  --component2 1111222233334444AAAABBBBCCCCDDDD \
  --component3 FFFF0000FFFF00000000FFFF0000FFFF \
  --algorithm T --keytype K0 --modeofuse B
```

Two-component entry is also supported — simply omit `--component3`.

#### Interactive key ceremony (--prompt-components)

This mode is designed for split-knowledge key loading ceremonies where no single person should see the full key. Each component is entered interactively with characters masked as `*`. A KCV is displayed after each component so custodians can verify their component without revealing it.

```bash
python3 import_raw_key_tr34.py \
  --prompt-components \
  --algorithm T --keytype K0 --modeofuse B --region us-east-1
```

The flow proceeds as follows:

```
--- Key Import Summary ---
  Algorithm  : TDES
  Key Type   : K0
  Mode of Use: B
  Export Mode: E
  AWS Region : us-east-1
--------------------------

--- Key Component Entry ---
  Enter Component 1 (hex): ********************************
  Component 1 KCV: 3C0A31

  Enter Component 2 (hex): ********************************
  Component 2 KCV: A1B2C3

  Enter Component 3 (press Enter to skip for 2-component entry): 
  (skipped — 2-component mode)

  Combined key KCV: 9F4D22
---------------------------

  Confirm import of key with KCV [9F4D22]? (yes/no): yes
```

**Input validation:**
- Only valid hex characters are accepted (0–9, a–f, A–F)
- Input must be an even number of characters
- Key length must match a valid size for the chosen algorithm:
  - TDES: 32 hex chars (2KEY) or 48 hex chars (3KEY)
  - AES: 32 hex chars (AES-128), 48 hex chars (AES-192), or 64 hex chars (AES-256)
- Single-DES (8-byte) keys are not permitted
- All components must be the same length
- A confirmation prompt showing the combined KCV is displayed before the key is imported
- The combined key value is never printed to the terminal

### Parameters

| Parameter | Description | Default | Choices |
|-----------|-------------|---------|---------|
| `--clearkey` | Clear text key in hex | | |
| `--component1` | First key component (hex) | | |
| `--component2` | Second key component (hex) | | |
| `--component3` | Third key component (hex, optional) | | |
| `--prompt-components` | Interactive masked component entry | | |
| `--algorithm` / `-a` | Key algorithm | `T` | `T` (TDES), `A` (AES) |
| `--keytype` / `-t` | TR-31 key type | `K0` | `K0`, `K1`, `B0`, `D0`, `P0`, `E0`, `E1`, `E2`, `E3`, `E6`, `C0` |
| `--modeofuse` / `-m` | TR-31 mode of use | `B` | `B`, `X`, `N`, `E`, `D`, `C`, `G`, `V` |
| `--exportmode` / `-e` | TR-31 export mode | `E` | `E`, `S`, `N` |
| `--runmode` | `APC` imports directly; `OFFLINE` produces payload only | `APC` | `APC`, `OFFLINE` |
| `--krdcert` | KRD certificate (base64) — required for `OFFLINE` mode | | |
| `--region` / `-r` | AWS region | `us-east-1` | `us-east-1`, `us-west-2` |
| `--deleteoldkeys` | Delete previously imported key at the alias | `False` | |

---

## Running the demo key setup (for JAVA samples)

Either of the approaches below can be used to import the demo keys. You will need AWS credentials configured.

#### Using [Docker](https://docs.docker.com/get-docker/)

```bash
cd samples-for-payment-cryptography-service/key-import-export

docker build -t key-import-app .

docker run -e AWS_ACCESS_KEY_ID=<Access Key> \
           -e AWS_SECRET_ACCESS_KEY=<Secret Key> \
           -e AWS_DEFAULT_REGION=us-east-1 \
           -it --rm key-import-app
```

#### Using [Finch](https://github.com/runfinch/finch)

```bash
cd samples-for-payment-cryptography-service/key-import-export

finch build -t key-import-app .

finch run -e AWS_ACCESS_KEY_ID=<Access Key> \
          -e AWS_SECRET_ACCESS_KEY=<Secret Key> \
          -e AWS_DEFAULT_REGION=us-east-1 \
          -it --rm key-import-app
```

#### Using local Python

```bash
cd samples-for-payment-cryptography-service/key-import-export/tr34/import_app

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install psec boto3 pycryptodome
python3 apc_demo_keysetup.py
```
