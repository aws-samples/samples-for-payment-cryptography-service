# AWS Payment Crypto ECDH Pin Set/Reveal flows

This repository contains a sample for three specific AWS Payment Cryptography Use Cases:
1. RESET PIN: When a user forgets it's PIN and you want to randomly generate a new one and show it to them, storing the PVV on the backend. 
2. SET PIN: When a user wants to set an arbitrary PIN, and the backend stores the PVV.
3. REVEAL PIN: When you want to obtain the pinblock from an encrypted pinblock for some very niche and specific use-cases

These use cases are implemented using ECDH Key Agreement to derive a symmetric key which is used to encrypt the pinblock between the device and AWS Payment Cryptography using ISO_FORMAT_4. As part of the implementation a Certificate Authority is needed, this demo implements it using AWS Private CA with short-lived certificates. 

## Flows
### Reset PIN
![PIN Reset](images/PIN-Reset.png?raw=true "PIN Reset")

### Select PIN
![PIN Select](images/PIN-Select.png?raw=true "PIN Select")

### Reveal PIN
![PIN Reveal](images/PIN-Reveal.png?raw=true "PIN Reveal")

## Cost
The following costs represent the us-east-1 (North Virginia) AWS Region, prices may vary across regions.

1. AWS Private CA for short-lived certificates has a pricing of US$ 50 (hourly prorated) per month.
2. AWS Private CA charges 0.058 for each short-lived certificate (This demo issues 4 certificates: 1 for CA setup, 1 for each flow)
3. Each AWS Payment Cryptography key is charged US$ 1 per key (hourly prorated) per month, and this demo uses 4 keys
4. Each AWS Payment Cryptography API is charged at US$ 2 per 10,000 API Calls, this demo does less than 50

You can stop the costs by calling the tear_down.py script included, which deletes all created assets.

If you execute this demo and immediately call tear_down.py, it will have an overall cost of 0.24 USD approximated.

## Setup

Generate a Python Virtual Environment and install required libraries
```
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```
You also need local AWS Credentials that have access to AWS Payment Cryptography and AWS Private CA

## Permissions - IAM Policy
To execute this demo you need the following permissions
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "acm-pca:ListCertificateAuthorities",
                "acm-pca:CreateCertificateAuthority",
                "acm-pca:DescribeCertificateAuthority",
                "acm-pca:TagCertificateAuthority",
                "acm-pca:GetCertificateAuthorityCsr",
                "acm-pca:IssueCertificate",
                "acm-pca:GetCertificate",
                "acm-pca:ImportCertificateAuthorityCertificate",
                "acm-pca:GetCertificateAuthorityCertificate",
                "payment-cryptography:GetAlias",
                "payment-cryptography:ImportKey",
                "payment-cryptography:CreateAlias",
                "payment-cryptography:CreateKey",
                "kms:GenerateRandom",
                "payment-cryptography:GetPublicKeyCertificate",
                "payment-cryptography:GeneratePinData",
                "payment-cryptography:TranslatePinData",
                "acm-pca:ListTags",
                "acm-pca:UpdateCertificateAuthority",
                "acm-pca:DeleteCertificateAuthority",
                "payment-cryptography:ListKeys",
                "payment-cryptography:ListTagsForResource",
                "payment-cryptography:DeleteKey",
                "payment-cryptography:ListAliases",
                "payment-cryptography:TagResource",
                "payment-cryptography:DeleteAlias"
            ],
            "Resource": "*"
        }
    ]
}

```

## Execute
Simulate the three flows of this Demo. This will create a Private CA and the needed AWS Payment Cryptography cryptographic key the first time is ran.
These keys and CA will stay created until you call the tear_down.py script.

```
python3 payment_crypto/main.py
```

## Browser-based Select PIN demo

In addition to the CLI-only demo above, this sample includes a browser UX for the **Select PIN**
flow where **ECDH key agreement and ISO 9564 Format 4 PIN block encryption happen entirely in the
browser**, using the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
The plaintext PIN never leaves the browser tab.

What happens where:

| Step | Where | Notes |
|---|---|---|
| Generate ephemeral ECDH key pair (P-256) | Browser | `window.crypto.subtle.generateKey` |
| Fetch AWS Payment Cryptography's ECDH public key certificate | Server → Browser | Server just proxies `GetPublicKeyCertificate` |
| ECDH key agreement | Browser | `window.crypto.subtle.deriveBits` |
| Key derivation (NIST SP 800-56A Concatenation KDF, SHA-512) | Browser | No native WebCrypto API for this; implemented directly on `subtle.digest` |
| ISO Format 4 PIN block encryption | Browser | AES-ECB has no native WebCrypto mode; implemented via the AES-CBC-with-zero-IV single-block trick |
| PKCS#10 CSR generation + signing | Browser | Via [pkijs](https://github.com/PeculiarVentures/PKI.js) + [asn1js](https://github.com/PeculiarVentures/ASN1.js), loaded from esm.sh (no build step) |
| Sign browser's CSR with the demo AWS Private CA | Server | So AWS Payment Cryptography trusts the browser's ephemeral public key |
| Translate PIN block to PEK + generate PVV | Server | Calls `TranslatePinData` / `GeneratePinData` |

Only the browser-encrypted PIN block (never the plaintext PIN) is ever sent over the network, to the
Flask server in this demo.

### Run it

```
python3 payment_crypto/webapp.py
```

Then open http://127.0.0.1:5000 in a browser, enter a PAN and a PIN, and submit. The "Client-side
crypto log" panel on the page shows each step happening in the browser.

**Security note:** `webapp.py` is a local development demo server (Flask's built-in dev server, no
authentication, single process). It is not intended to be exposed beyond localhost or used as-is in
production. The AWS Private CA in this demo is a self-signed root created solely to satisfy AWS
Payment Cryptography's requirement for a trust anchor on the browser's ephemeral key; it has no
bearing on the security of the PIN block encryption itself, which relies on the ECDH-derived key.

## Clean Up
Clean up resources (including CA)
```
python3 payment_crypto/tear_down.py
```

