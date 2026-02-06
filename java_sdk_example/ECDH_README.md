# ECDH PIN Exchange Implementation

## Overview

This implementation demonstrates PIN exchange using ECDH (Elliptic Curve Diffie-Hellman) key agreement with AWS Payment Cryptography Service. The solution provides secure PIN operations (set, reveal, reset) using ephemeral key pairs and cryptographic key derivation.

## Architecture

```
┌─────────────────┐         ┌─────────────────┐         ┌──────────────────────┐
│  ECDH Terminal  │         │  ECDH Service   │         │  AWS Payment Crypto  │
│  (Client)       │         │  (Server)       │         │  Service             │
└─────────────────┘         └─────────────────┘         └──────────────────────┘
        │                            │                            │
        │ 1. Get Certificates        │                            │
        │───────────────────────────>│                            │
        │                            │ Get Public Key Cert        │
        │                            │───────────────────────────>│
        │<───────────────────────────│<───────────────────────────│
        │                            │                            │
        │ 2. Generate ECDH Key Pair  │                            │
        │ 3. Derive Shared Secret    │                            │
        │ 4. Encrypt PIN Block       │                            │
        │                            │                            │
        │ 5. Send Encrypted PIN      │                            │
        │───────────────────────────>│                            │
        │                            │ 6. Translate PIN (ECDH→PEK)│
        │                            │───────────────────────────>│
        │                            │ 7. Generate PVV            │
        │                            │───────────────────────────>│
        │<───────────────────────────│<───────────────────────────│
```

## Components

### Client-Side (Terminal Package)

#### ECDHTerminal.java
Simulated terminal that performs ECDH PIN operations:
- **PIN Set**: Encrypts user-entered PIN using ECDH-derived key
- **PIN Reveal**: Decrypts PEK-encrypted PIN using ECDH
- **PIN Reset**: Generates new random PIN encrypted with ECDH

### Server-Side (ECDH Package)

#### ECDHService.java
Spring Boot REST service handling ECDH operations:
- Manages ECDH keys in AWS Payment Cryptography
- Translates PIN blocks between ECDH and PEK encryption
- Generates PIN verification values (PVV)

#### ECDHKeyManager.java
Manages cryptographic keys:
- Creates/retrieves ECDH key pairs (ECC_NIST_P256)
- Creates/retrieves PEK (PIN Encryption Key)
- Creates/retrieves PGK (PIN Generation Key)
- Manages key aliases and ARNs

#### ECDHCryptoUtils.java
Cryptographic utility functions:
- ECDH key pair generation (SECP256R1 curve)
- Certificate Signing Request (CSR) generation
- Symmetric key derivation using Concat KDF (NIST SP 800-56A)
- AES-256-CBC encryption/decryption
- Certificate parsing and handling

#### ECDHConstants.java
Configuration constants for ECDH operations

## Prerequisites

1. **AWS Credentials**: Configure AWS credentials with access to Payment Cryptography
2. **Java 17+**: Required for running the application
3. **Maven**: For building the project
4. **AWS Payment Cryptography**: Service must be available in your region

## Setup

### 1. Build the Project

```bash
cd java_sdk_example
mvn clean install
```

### 2. Start the ECDH Service

```bash
./run_example.sh aws.sample.paymentcryptography.Application
```

The service will:
- Start on port 8080
- Automatically create required keys in AWS Payment Cryptography
- Register ECDH service endpoints

### 3. Run the ECDH Terminal

In a separate terminal:

```bash
./run_example.sh aws.sample.paymentcryptography.terminal.ECDHTerminal
```

## Usage Examples

### PIN Set Operation

```
Select operation:
1. Set PIN
2. Reveal PIN
3. Reset PIN
4. Exit
Choice: 1

Enter PAN (Primary Account Number): 4111111111111111
Enter PIN (4-6 digits): 1234

--- PIN Set Flow (ECDH) ---
1. Generating ECDH key pair...
2. Generating shared info...
3. Fetching AWS Payment Cryptography certificates...
4. Deriving symmetric key using ECDH...
5. Encoding PIN block (ISO Format 0)...
6. Encrypting PIN block with derived key...
7. Generating Certificate Signing Request...
8. Sending PIN to ECDH service...

✓ PIN Set Response:
  Status: success
  Message: PIN set successfully
  PVV: 1234
```

### PIN Reveal Operation

```
Choice: 2
Enter PAN (Primary Account Number): 4111111111111111
Enter PEK-encrypted PIN block: <hex_encoded_pin_block>

--- PIN Reveal Flow (ECDH) ---
1. Generating ECDH key pair...
2. Generating shared info...
3. Fetching AWS Payment Cryptography certificates...
4. Deriving symmetric key using ECDH...
5. Generating Certificate Signing Request...
6. Requesting PIN reveal from ECDH service...
7. Decrypting PIN block with derived key...

✓ PIN Revealed:
  Decrypted PIN Block: 041234FFFFFFFFFF
  (Note: PIN block is in ISO Format 0, decode to get actual PIN)
```

### PIN Reset Operation

```
Choice: 3
Enter PAN (Primary Account Number): 4111111111111111

--- PIN Reset Flow (ECDH) ---
1. Generating ECDH key pair...
2. Generating shared info...
3. Fetching AWS Payment Cryptography certificates...
4. Deriving symmetric key using ECDH...
5. Generating Certificate Signing Request...
6. Requesting PIN reset from ECDH service...
7. Decrypting PIN block with derived key...

✓ PIN Reset Successfully:
  New PIN Block: 045678FFFFFFFFFF
  PVV: 5678
  (Note: PIN block is in ISO Format 0, decode to get actual PIN)
```

## API Endpoints

### GET /ecdh-service/certificates
Get AWS Payment Cryptography public key certificates for ECDH operations.

**Response:**
```json
{
  "status": "success",
  "certificate": "<PEM_CERTIFICATE>",
  "certificateChain": "<PEM_CERTIFICATE_CHAIN>"
}
```

### POST /ecdh-service/setPin
Set PIN using ECDH-encrypted PIN block.

**Parameters:**
- `encryptedPinBlock`: PIN block encrypted with ECDH-derived key
- `pan`: Primary Account Number
- `csr`: Certificate Signing Request
- `sharedInfo`: Shared information for key derivation
- `signedCertificate`: Client certificate signed by CA
- `certificateChain`: Certificate chain

**Response:**
```json
{
  "status": "success",
  "message": "PIN set successfully",
  "pvv": "1234",
  "pekEncryptedPinBlock": "<hex_encoded>"
}
```

### POST /ecdh-service/revealPin
Reveal PIN by translating from PEK to ECDH encryption.

**Parameters:**
- `pekEncryptedPinBlock`: PIN block encrypted with PEK
- `pan`: Primary Account Number
- `csr`: Certificate Signing Request
- `sharedInfo`: Shared information for key derivation
- `signedCertificate`: Client certificate signed by CA
- `certificateChain`: Certificate chain

**Response:**
```json
{
  "status": "success",
  "ecdhEncryptedPinBlock": "<base64_encoded>"
}
```

### POST /ecdh-service/resetPin
Generate new random PIN encrypted with ECDH.

**Parameters:**
- `pan`: Primary Account Number
- `csr`: Certificate Signing Request
- `sharedInfo`: Shared information for key derivation
- `signedCertificate`: Client certificate signed by CA
- `certificateChain`: Certificate chain

**Response:**
```json
{
  "status": "success",
  "ecdhEncryptedPinBlock": "<base64_encoded>",
  "pvv": "5678"
}
```

## Security Features

### Cryptographic Standards
- **ECDH**: Elliptic Curve Diffie-Hellman key agreement
- **Curve**: SECP256R1 (NIST P-256)
- **KDF**: Concat KDF (NIST SP 800-56A Rev. 3)
- **Hash**: SHA-256
- **Encryption**: AES-256-CBC with random IV
- **PIN Block**: ISO Format 0

### Key Management
- **Ephemeral Keys**: New ECDH key pair generated for each operation
- **Key Derivation**: Unique symmetric key derived per transaction
- **Secure Storage**: Keys managed by AWS Payment Cryptography
- **Key Rotation**: Supported through key aliases

### Best Practices
- Random IV for each encryption operation
- Secure random number generation
- Certificate-based authentication
- No plaintext PIN transmission
- PVV generation for PIN verification

## Troubleshooting

### Service Won't Start
- Verify AWS credentials are configured
- Check AWS Payment Cryptography is available in your region
- Ensure port 8080 is not in use

### Key Creation Fails
- Verify IAM permissions for Payment Cryptography
- Check service quotas and limits
- Review CloudWatch logs for detailed errors

### Certificate Parsing Errors
- Ensure BouncyCastle provider is loaded
- Verify certificate format (PEM)
- Check certificate validity

### Connection Refused
- Ensure ECDH service is running
- Verify service URL in CommonConstants.HOST
- Check firewall settings

## Comparison with Python Implementation

This Java implementation mirrors the Python ECDH flows in `python_sdk_example/ecdh_flows/`:

| Feature | Python | Java |
|---------|--------|------|
| ECDH Key Generation | ✓ | ✓ |
| Concat KDF | ✓ | ✓ |
| PIN Set | ✓ | ✓ |
| PIN Reveal | ✓ | ✓ |
| PIN Reset | ✓ | ✓ |
| CSR Generation | ✓ | ✓ |
| Certificate Handling | ✓ | ✓ |
| AES Encryption | ✓ | ✓ |

## References

- [AWS Payment Cryptography Documentation](https://docs.aws.amazon.com/payment-cryptography/)
- [NIST SP 800-56A Rev. 3](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
- [ISO 9564 PIN Block Formats](https://en.wikipedia.org/wiki/ISO_9564)
- [Python ECDH Implementation](../python_sdk_example/ecdh_flows/)

## License

This sample code is licensed under the MIT-0 License. See the LICENSE file.
