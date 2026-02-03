# ECDH Quick Start Guide

## What is ECDH PIN Exchange?

ECDH (Elliptic Curve Diffie-Hellman) PIN exchange provides a secure method for transmitting PINs between a terminal and AWS Payment Cryptography Service. Instead of using pre-shared keys, ECDH uses ephemeral key pairs to establish a shared secret for each transaction.

## Quick Start (5 Minutes)

### 1. Build the Project

```bash
cd java_sdk_example
mvn clean install
```

### 2. Start the ECDH Service

```bash
./run_example.sh aws.sample.paymentcryptography.Application
```

Wait for the message: "ECDH keys initialized successfully"

### 3. Run the Terminal (New Terminal Window)

```bash
./run_example.sh aws.sample.paymentcryptography.terminal.ECDHTerminal
```

### 4. Try PIN Set

```
Select operation: 1
Enter PAN: 4111111111111111
Enter PIN: 1234
```

You should see the PIN set successfully with a PVV (PIN Verification Value).

## Architecture Overview

```
Terminal                    ECDH Service              AWS Payment Crypto
   │                             │                            │
   │ Generate ECDH Key Pair      │                            │
   │────────────────────────────>│                            │
   │                             │                            │
   │ Get Certificates            │                            │
   │────────────────────────────>│ Get Public Key Cert       │
   │                             │───────────────────────────>│
   │<────────────────────────────│<───────────────────────────│
   │                             │                            │
   │ Derive Shared Secret        │                            │
   │ Encrypt PIN                 │                            │
   │                             │                            │
   │ Send Encrypted PIN          │                            │
   │────────────────────────────>│ Translate PIN (ECDH→PEK)  │
   │                             │───────────────────────────>│
   │<────────────────────────────│<───────────────────────────│
```

## Key Components

### Client Side (Terminal)
- **ECDHTerminal.java** - Interactive terminal simulation
- **ECDHCryptoUtils.java** - Cryptographic operations

### Server Side (Service)
- **ECDHService.java** - REST API for PIN operations
- **ECDHKeyManager.java** - AWS key management

## Operations

### 1. PIN Set
User enters PIN → Terminal encrypts with ECDH → Service stores with PEK

### 2. PIN Reveal
Service translates PEK-encrypted PIN → ECDH-encrypted → Terminal decrypts

### 3. PIN Reset
Service generates random PIN → ECDH-encrypted → Terminal decrypts

## Example Without Service

To see ECDH cryptographic operations without running the full service:

```bash
./run_example.sh aws.sample.paymentcryptography.examples.ECDHExample
```

This demonstrates:
- ECDH key pair generation
- CSR generation
- Shared info generation
- AES-256-CBC encryption/decryption
- Hex conversion utilities

## Testing

Run unit tests:

```bash
mvn test -Dtest=ECDHCryptoUtilsTest
```

## Security Features

✓ **Ephemeral Keys** - New key pair for each transaction  
✓ **Forward Secrecy** - Compromise of one session doesn't affect others  
✓ **NIST Standards** - SECP256R1 curve, Concat KDF (SP 800-56A)  
✓ **Strong Encryption** - AES-256-CBC with random IV  
✓ **No Pre-shared Keys** - Keys established dynamically  

## Troubleshooting

**Service won't start:**
- Check AWS credentials: `aws sts get-caller-identity`
- Verify Payment Cryptography is available in your region

**Key creation fails:**
- Check IAM permissions for `payment-cryptography:CreateKey`
- Review service quotas

**Connection refused:**
- Ensure service is running on port 8080
- Check `CommonConstants.HOST` setting

## Next Steps

1. Review [ECDH_README.md](ECDH_README.md) for detailed documentation
2. Explore the Python implementation in `python_sdk_example/ecdh_flows/`
3. Integrate ECDH with your payment application
4. Add AWS Private CA for production certificate signing

## Comparison: ECDH vs Traditional PIN Encryption

| Feature | Traditional (DUKPT/PEK) | ECDH |
|---------|------------------------|------|
| Key Distribution | Pre-shared keys | Dynamic key agreement |
| Key Management | Complex key hierarchy | Ephemeral keys |
| Forward Secrecy | No | Yes |
| Setup Complexity | High | Medium |
| Transaction Security | Good | Excellent |

## Resources

- [Full Documentation](ECDH_README.md)
- [Python ECDH Implementation](../python_sdk_example/ecdh_flows/)
- [AWS Payment Cryptography Docs](https://docs.aws.amazon.com/payment-cryptography/)
- [NIST SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
