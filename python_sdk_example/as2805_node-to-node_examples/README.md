# AWS Payment Cryptography Samples for AS2805

This sub-section of the repo includes examples for node-to-node communications using the Australian Standard AS2805, Section 6 methods available in AWS Payment Cryptography. One HSM is implemented in code, where we show manual construction of the keys, MACs and data protection measures used in this standard. The other HSM is AWS Payment Cryptography. These scripts are designed to be run sequentially to complete the entire node-to-node flow. Currently, at Steps 3 and 4, we only handle PINs in the example. We might expand that in the future. So currently, we implement the PIN encryption (with a zone pin key, or ZPK) and message authentication (with a zone authentication key, or ZAK), but don't provide an example protecting a primary account number (PAN) with a zone encryption key, or ZEK.

Note that these scripts should be taken collectively as enabling a basic working examples of:
1. Key Encipherment Key (KEK) creation
2. KEK exchange
3. KEK validation
4. Working key creation:
    a. Zone Encryption Key (ZEK),
    b. Zone PIN Key (ZPK),
    c. Zone Authentication Key (ZAK)
5. Working key exchange
6. PIN block calculation and encryption
7. PIN translation
8. MAC derivation and integrity check for the encrypted PIN block

## Instructions

### Install Prerequisites

#### Virtual Environments
If you want to run these scripts (and install the dependencies) in a virtual environment, you can do so with:

```bash
python -m venv .venv
source .venv/bin/activate
```

#### Requirements
These scripts are written in Python, and have the minimum following prerequisites (additional Python modules may be needed, depending on your current configuration).
1. Python (3.1x or later)
2. pip
3. boto3
4. botocore
5. cryptography (41 or later)
6. keyring

All are available via pip, and we've created a `requirements.txt` file containing all dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The scripts are executed using the Python runtime, simply like so:

```
python ~/path_to_files/samples-for-aws-payment-cryptography-service/python-sdk-example/as2805_node-to-node_examples/as2805_1_1_KEK_and_keystore_setup_both_nodes.py
```

### Set up credentials
As the scripts call AWS APIs (the AWS Payment Cryptography [data plane](https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/Welcome.html) and [control plane](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/Welcome.html) APIs), ensure you have an IAM entity set up with permissions to use the service. At a minimum, your IAM entity will need permission to call the following APIs:

1. [CreateKey](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_CreateKey.html)
2. [GetParametersForImport](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_GetParametersForImport.html)
3. [ImportKey](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_ImportKey.html)
4. [ExportKey](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_ExportKey.html)
5. [GetKey](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_GetKey.html)
6. [GenerateAs2805KekValidation](https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/API_GenerateAs2805KekValidation.html)
7. [TranslatePinData](https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/API_TranslatePinData.html)
8. [GenerateMac](https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/API_GenerateMac.html)
9. [VerifyMac](https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/API_VerifyMac.html)

Each script that requires AWS credentials will do a check to confirm it has credentials, if it does not, you'll receive a message to set them up. The script uses the [boto3.sesssion() credential helper](https://docs.aws.amazon.com/boto3/latest/reference/core/session.html) at the [standard locations](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html).

## Samples

### as2805_1_1 — KEK and Keystore Setup (Both Nodes)
Creates a 2-key TDES KEK on Node 2 (software HSM) with an encrypted local keystore, and a matching KEK in AWS Payment Cryptography. Exchanges KEKs between nodes using RSA key wrapping.
- **AWS Payment Cryptography**: `CreateKey`, `ImportKey` (RootCertificatePublicKey), `ExportKey` (KeyCryptogram)
- **AS2805**: KEK establishment per Part 6

### as2805_1_2 — Prepare for KEK Import
Calls AWS Payment Cryptography to obtain a wrapping certificate and import token, used to securely import Node 2's KEK into the service.
- **AWS Payment Cryptography**: `GetParametersForImport`

### as2805_1_3 — Export Node 2 KEK for Import into APC
Wraps Node 2's KEK using the AWS wrapping certificate (RSA-OAEP) and creates an import package for AWS Payment Cryptography.
- **AS2805**: KEK export using RSA key wrapping

### as2805_1_4 — Import Node 2 KEK into APC
Imports the wrapped Node 2 KEK into AWS Payment Cryptography and validates the imported key.
- **AWS Payment Cryptography**: `ImportKey` (KeyCryptogram), `GetKey`

### as2805_1_5 — KEK Validation
Performs bidirectional KEK validation between both nodes per AS2805 Section 6.3, using variant masks (0x82/0x84) and random key exchange to prove each node holds the correct KEK.
- **AWS Payment Cryptography**: `GenerateAs2805KekValidation`
- **AS2805**: KEK validation with request/response variant masks, 3DES-CBC, bitwise NOT with parity adjustment

### as2805_2_1 — Working Key Exchange (Bidirectional)
Creates ZPK, ZEK, and ZAK working keys in AWS Payment Cryptography, exports them to Node 2 using AS2805 variant-based wrapping, then generates working keys on Node 2 and imports them into APC. Validates all keys via KCV.
- **AWS Payment Cryptography**: `CreateKey`, `ExportKey` (As2805KeyCryptogram), `ImportKey` (As2805KeyCryptogram)
- **AS2805**: Variant masks for key separation (PIN: 28C0, Data: 22C0, MAC: 24C0), KCV validation (ANSI X9.24)

### as2805_3_1 — PIN Translation with Session Key Derivation
Derives a session PIN key (KPE) from the ZPK using STAN and transaction amount per AS2805 Section 6.6, encrypts a PIN block under the derived KPE, and translates it via AWS Payment Cryptography. Also generates a MAC over the encrypted PIN block using the ZAK.
- **AWS Payment Cryptography**: `TranslatePinData` (with `IncomingAs2805Attributes`)
- **AS2805**: KPE derivation (OWF per AS2805.5.4), ISO Format 0 PIN block, MAC generation (Retail MAC / ISO 9797-1 Algorithm 3)

### as2805_4_1 — MAC Validation
Verifies the MAC generated by Node 2 using the imported ZAK in AWS Payment Cryptography, then generates a new MAC for the outgoing message using Node 1's ZAK.
- **AWS Payment Cryptography**: `GenerateMac` (AS2805_4_1), `VerifyMac` (AS2805_4_1)
- **AS2805**: MAC per AS2805.4.1 (Retail MAC / ISO 9797-1 Algorithm 3, Method 2)

### keystore_helper - Gracefully handle credentials required to interact with a software keystore. Useful if running these scripts on an operating system that doesn't implement its own keystore. You don't need to run this module, the as2805_* modules will import and use this module as necessary.

## Authors and acknowledgment
Frank Phillis
Mark Cline

## License
This library is licensed under the MIT-0 License. See the [LICENSE](https://github.com/aws-samples/samples-for-payment-cryptography-service/blob/main/LICENSE) file.

## Project status
V1 complete and up-to-date.
