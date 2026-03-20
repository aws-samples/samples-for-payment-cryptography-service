# PayShield to AWS Payment Cryptography Command Mapping

This document maps Thales payShield HSM commands to their equivalent AWS Payment Cryptography service API calls.

**Legend:**
- **Y** — Supported
- **N/A** — Not applicable (managed by the service or not needed)

---

## Key Management

### Key Generation (A0)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|-------------|----------------|-----------------|-------|------|
| Y | Create 3DES key | Generate 3DES Key | Create key | KeyAlgorithm=TDES_2KEY (most common) or KeyAlgorithm=TDES_3KEY | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/create-keys.html#3des-deriv-mrr-example) |
| Y | Create AES key | Generate AES key | Create key | KeyAlgorithm=AES_128, AES_192, AES_256 | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/create-keys.html#aes-example) |
| Y | Generate DUKPT derived key and export | Generate DUKPT IPEK/IK and export | Export Key | ExportDukptInitialKey | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keys-export.html#keys-export-ipek) |
| Y | Create and export key | Generate key and immediately export | Create key | | The service expects you to create the key first and then export it as a separate command. The key can then be deleted if it's not needed. | |
| Y | Create Key — General Listing | | Create Key | | | |

### Key Import (A6)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|-------------|----------------|-----------------|-------|------|
| Y | Import a key protected using TR-31/X9.143 wrapping scheme | Keytype S (TR-31/X9.143) | Import Key | KeyMaterial=Tr31KeyBlock | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keys-import.html#keys-import-tr31) |
| Y | Import a key wrapped by symmetric key | | | | | |

### Key Export (A8)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|-------------|----------------|-----------------|-------|------|
| Y | Export a key protected using TR-31/X9.143 wrapping scheme | Keytype S (TR-31/X9.143) | Export Key | KeyMaterial=Tr31KeyBlock | | |
| Y | Export a key wrapped by symmetric key | | | | | |

### Unsupported Key Commands (AE, AG, AK, AM)

| Supported | Command | Notes |
|-----------|---------|-------|
| N/A | AE | |
| N/A | AG | |
| N/A | AK | |
| N/A | AM | |

### CVK Management (AS, AU, AW)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Create CVK for CVV, CVV2 or similar purposes | AS | Create key | |
| Y | Export CVK | AU | Export Key | |
| N/A | Import CVK | AW | Import Key | |


### Key Translation and Heartbeat (B0, B2)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | Translate key from variant to key block format | B0 | N/A | The service stores all keys in key block format adhering to X9.24. |
| N/A | Echo/heartbeat | B2 | N/A | The service manages all HSM and heartbeat commands are not needed. The service automatically load balances within a given AWS Region. |

### TR-34 Key Export (B8)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Export a key using TR-34 2012 version | Option 0 — TR-34 2012 edition | Export Key | KeyMaterial=Tr34KeyBlock | |
| Y | Export a key using TR-34 (General command) | | Export Key | | |

### PIN Encryption and BDK (BA, BG, BI, BK)

| Supported | Description | Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|---------|----------------|-----------------|-------|------|
| Y | Encrypt a clear pin | BA | Translate Pin | WrappedKeyMaterial=DiffieHellmanSymmetricKey | To maintain PCI compliance, the service does not take in clear pins. End-to-end protection can be achieved using ECDH. | [ECDH Flows](https://github.com/aws-samples/samples-for-payment-cryptography-service/tree/main/python_sdk_example/ecdh_flows) |
| N/A | Rewrap pin under a new main key | BG | Translate Pin | | The service does not use main keys for pin protection. PEK are used and can be rotated using translate pin. | |
| Y | Generate a BDK | BI | Create Key | | | |
| Y | Generate IBM3624 pin offset | BK | Generate Pin Data | | | |

### Temporary Keys and Main Key Rotation (BS, BW)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | Clear temporary keys | BS | N/A | The service manages any temporary key material used for main key rotation. |
| N/A | Translate key to new main key | BW | N/A | The service manages main key rotation automatically. |

### Key Check Value (BU)

| Supported | Description | Sub-Command | APC Equivalent | Notes |
|-----------|-------------|-------------|----------------|-------|
| Y | Generate key check value using CMAC method | CMAC (AES method) | GetKey | CMAC method uses CMAC over zeros and then selects first 3 bytes. |
| Y | Generate key check value | X9.24 (3DES method) | GetKey | X9.24 method consists of encrypting 16 zeros and then selecting the first 3 bytes. In case where output from HSM is padded with zero or contains 16 hex characters, only select first 6 characters (3 bytes). |
| Y | Generate key check value (General Command) | | GetKey | |

### ZMK Import (BY)

| Supported | Description | Sub-Command | APC Equivalent | Notes |
|-----------|-------------|-------------|----------------|-------|
| Y | Import zone main key (ZMK) using key blocks | Keytype S (TR-31/X9.143) | Import Key | |
| Y | Import ZMK (General Command) | | Import Key | |

---

## MAC Operations

### Generate MAC (C2)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Generate ISO9797-1 Algo 1 — X9.9 (Wholesale MAC) | Mode 0 — X9.9 | GenerateMac | Algorithm=ISO9797_ALGORITHM1 | X9.9 when used with 3DES is the same as ISO9797 Algorithm 1. Does not support legacy single DES. Supports up to 8192 hex characters or 4096 bytes. All inputs are in hex binary. |
| Y | Generate ISO9797-1 Algo 3 — X9.19/Retail MAC | Mode 1 — X9.19 | GenerateMac | Algorithm=ISO9797_ALGORITHM3 | Supports up to 8192 hex characters or 4096 bytes. All inputs are in hex binary. |
| Y | Generate AS2805 4.1 MAB | Mode 2 — AS2805 4.1 MAB | GenerateMac | Algorithm=AS2805_4_1 | Supports up to 8192 hex characters or 4096 bytes. All inputs are in hex binary. |
| Y | Generate AS2805 4.1 MAC | Mode 3 — AS2805 4.1 MAC | GenerateMac | Algorithm=AS2805_4_1 | Supports up to 8192 hex characters or 4096 bytes. All inputs are in hex binary. |
| Y | Generate MAC (General command) | | GenerateMac | | |

### Verify MAC (C4)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Verify ISO9797-1 Algo 1 — X9.9 (Wholesale MAC) | Mode 0 — X9.9 | VerifyMac | Algorithm=ISO9797_ALGORITHM1 | Same notes as C2 generation. |
| Y | Verify ISO9797-1 Algo 3 — X9.19/Retail MAC | Mode 1 — X9.19 | VerifyMac | Algorithm=ISO9797_ALGORITHM3 | |
| Y | Verify AS2805 4.1 MAB | Mode 2 — AS2805 4.1 MAB | VerifyMac | Algorithm=AS2805_4_1 | |
| Y | Verify AS2805 4.1 MAC | Mode 3 — AS2805 4.1 MAC | VerifyMac | Algorithm=AS2805_4_1 | |
| Y | Verify MAC (General command) | | VerifyMac | | |

---

## PIN Translation

### Translate PIN — TPK to ZPK/DUKPT (CA)

| Supported | Description | Sub-Command | APC Equivalent | Notes |
|-----------|-------------|-------------|----------------|-------|
| Y | Translate Pin from TPK to ZPK or DUKPT (BDK) | 3DES | TranslatePinData | The service follows X9.143 and all pin keys are known as pin encryption keys (PEK) or P0. If DUKPT keys, they are derived keys based on base key (BDK) or B0. |
| Y | Translate Pin from TPK to ZPK or DUKPT (BDK) | AES | TranslatePinData | Same as above. |
| Y | Translate Pin (General Command) | | TranslatePin | |

### Translate PIN — ZPK to ZPK (CC)

| Supported | Description | Sub-Command | APC Equivalent | Notes |
|-----------|-------------|-------------|----------------|-------|
| Y | Translate Pin from ZPK to another ZPK | AES | TranslatePinData | The service follows X9.143 and all pin keys are known as pin encryption keys (PEK) or P0. |
| Y | Translate Pin from ZPK to another ZPK | TDES | TranslatePinData | Same as above. |
| Y | Translate Pin (General Command) | | TranslatePinData | |

### Translate PIN — DUKPT to ZPK (CI)

| Supported | Description | Sub-Command | APC Equivalent | Notes |
|-----------|-------------|-------------|----------------|-------|
| Y | Translate Pin from DUKPT (BDK) to ZPK | TDES | TranslatePinData | Legacy command similar to CA or CC. |
| Y | Translate Pin (General Command) | | TranslatePinData | |


### TLS Setup (CONSOLE-SG)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | Setup TLS for HSM Communication | CONSOLE-SG | N/A | |

### Modify Key Block Fields (CS)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Modify certain fields in a key block like mode of use | CS | Export Key | |

### Load Key Components (CU)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Load Key Components into the system | CU | Generate Pin Data | |

---

## Card Verification

### Generate Card Data (CW)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|-------------|----------------|-----------------|-------|------|
| Y | Generate Visa CAVV V7 | CAVV V7 | GenerateCardData | CardGenerationAttributes=CardVerificationValue1 | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/use-cases-issuers.networkfunctions.visa.html#use-cases-issuers.networkfunctions.visa.cavv-v7) |
| Y | Generate CVV | CVV (service code varies, typically 101 or 121) | GenerateCardData | CardGenerationAttributes=CardVerificationValue1 | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/use-cases-issuers.generalfunctions.cvv.html) |
| Y | Generate CVV2 | CVV2 (service code of 000) | GenerateCardData | CardGenerationAttributes=CardVerificationValue2 | CVV2 is the three digit value historically on the back of a card and used for e-commerce transactions. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/use-cases-issuers.generalfunctions.cvv2.html) |
| Y | Generate iCVV | iCVV (service code of 999) | GenerateCardData | CardGenerationAttributes=CardVerificationValue1 | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/use-cases-issuers.generalfunctions.icvv.html) |
| Y | Generates various kinds of card data | | GenerateCardData | | | |

### Verify Card Data (CY)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Verify a Card Verification Code or Value | CY | Verify Card Data | |

### Console Key Operations (Console-IK, Console-KG)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Import Key | Console-IK | ImportKey | |
| Y | Create Key | Console-KG | CreateKey | |

---

## PIN Verification

### Verify PIN — IBM3624 (DA)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Verify pin using IBM3624 offset | DA | Verify Pin Data | |

### Verify PIN — ABA/Visa PVV (DC)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Verify pin using ABA/Visa PVV | DC | Verify Pin Data | |

### Generate PIN Offset/PVV (DE, DG)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Generate IBM3624 offset for an encrypted pin | DE | Generate Pin Data | |
| Y | Generate ABA/Visa PVV value for an encrypted pin | DG | Generate Pin Data | |

### Legacy BDK Import/Export (DW, DY)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Import BDK (Legacy Command) | DW | Import Key | Legacy command replaced by A6. |
| Y | Export BDK (Legacy Method) | DY | Export Key | Legacy command replaced by A8. |

---

## AS2805 KEK Validation

### KEK Validation (E0, E2)

| Supported | Description | Command | APC Equivalent | APC Sub-Command | Docs |
|-----------|-------------|---------|----------------|-----------------|------|
| Y | Generate KEK Validation Request | E0 | generate-as2805-kek-validation | KekValidationType=KekValidationRequest | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/as2805.kekvalidation.html) |
| Y | Generate KEK Validation Response | E2 | generate-as2805-kek-validation | KekValidationType=KekValidationResponse | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/as2805.kekvalidation.html) |

---

## PIN Verification (Extended)

### Verify/Generate PIN (EA, EC, EE)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Verify Pin using IBM3624 offset | EA | Verify Pin Data with IBM Offset Option | |
| Y | Verify Pin using ABA/Visa PVV | EC | VerifyPinData | |
| Y | Generate Random Pin and output IBM3624 offset | EE | Generate Pin Data | |

---

## RSA and Public Key Operations

### RSA Key Generation (EI)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Generate RSA Key | EI | Create-key, ASYMMETRIC_KEY_PAIR | |

### Public Key Management (EK, EM, EO, EQ, ES, EU)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | Load Private Key to Memory | EK | Import Key | |
| N/A | Translate Private key to new LMK | EM | N/A | The service manages main keys and any required rotation. |
| Y | Import Public Key | EO | Import Key (TrustedCertificatePublicKey) | The service expects keys to be imported in certificate form rather than as raw keys. |
| Y | Verify Public Key Under Key Block | EQ | Get Key | All keys within the Payment Cryptography service are valid, so there is no specific need for such a command. |
| Y | Import Public Key Certificate | ES | Import Key | This command only supports RSA but the service supports ECC and RSA. The service requires that CA must be at least as strong as child certificate. |
| N/A | Translate public key to new LMK | EU | N/A | The service manages main keys and any required rotation. |


---

## Legacy Key Commands (F-series)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Import ZPK (replaced by A6) | FA | Import Key | |
| N/A | Import keys (replaced by A6) | FC | Encrypt | |
| N/A | Export Keys (replaced by A8) | FE | Encrypt | |
| Y | Generate PVK (replaced by A0) | FG | Create Key | |
| Y | Create a ZEK or ZAK (replaced by A0) | FI | CreateKey | |
| Y | Import a ZAK or ZEK (replaced by A6) | FK | Import Key | |
| Y | Export a ZAK or ZEK | FM | exportKey | |
| Y | Generate ECC Key Pairs | FY | CreateKey | |

---

## DUKPT PIN Translation and Legacy Export (G-series)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Translate pin from DUKPT to PEK or DUKPT to DUKPT | G0 | TranslatePinData | |
| Y | Export ZPK (replaced by A8) | GC | Export Key | |

### Import/Export Key via RSA (GI, GK)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|-------------|----------------|-----------------|-------|------|
| Y | Import symmetric key protected by RSA | KeyDataBlockType=03 (unformatted) | Import Key | KeyMaterial=KEY_CRYPTOGRAM | Recommend using this command for establishing KEK only. Supports unformatted key blocks using OAEP padding for TDES or AES-128 keys. For X9.24 compliant formatted key blocks use KeyMaterial=Tr34KeyBlock. For AES-192 or higher keys or HMAC, use ECDH commands. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keys-import.html#keys-import-ecdh) |
| Y | Import key wrapped by RSA (Main Record) | | Import Key | | | |
| Y | Export symmetric key protected by RSA | KeyDataBlockType=03 (unformatted) | Export Key | KeyMaterial=KEY_CRYPTOGRAM | Recommend using this command for establishing KEK only. Supports unformatted key blocks using OAEP padding for TDES or AES-128 keys. For X9.24 compliant formatted key blocks use KeyMaterial=Tr34KeyBlock. For AES-192 or higher keys or HMAC, use ECDH commands. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keys-export.html#keys-export-ecdh) |
| Y | Export a key using RSA Wrap | | Export Key | | Same recommendation as above. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keys-export.html#keys-export-ecdh) |

### Hash and PIN Verification (GM, GO, GQ)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | Hash Data | GM | | Hash functions can be performed outside an HSM. |
| Y | General Record Verify pin using IBM3624 | GO | VerifyPin | Input can be DUKPT protected pin. |
| Y | General Record Verify pin using ABA/Visa PVV | GQ | TranslatePinData | Input can be DUKPT protected pin. |

### DUKPT MAC (GW)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|-------------|----------------|-----------------|-------|------|
| Y | Generate DUKPT MAC | Generate MAC (3DES + AES) | GenerateMac | DukptCmac, DukptIso9797Algorithm1 or DukptIso9797Algorithm3 | | |
| Y | Verify DUKPT MAC | Mode 1-3, Option 1 — Verify MAC — Retail MAC | VerifyMac | DukptCmac | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/generate-mac.html#generate-mac-dukpt-cmac) |
| Y | Verify DUKPT MAC | Mode 1-3, Option 2 — Verify MAC — AS2805 | VerifyMac | DukptCmac | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/generate-mac.html#generate-mac-dukpt-cmac) |
| Y | Verify DUKPT MAC | Mode 1-3, Option 4 or 5 — Verify MAC — CMAC | VerifyMac | DukptCmac | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/generate-mac.html#generate-mac-dukpt-cmac) |
| Y | Verify a MAC | Verify MAC (3DES + AES) | VerifyMac | DukptCmac, DukptIso9797Algorithm1 or DukptIso9797Algorithm3 | | |
| Y | Generate/Verify MAC (Main Record) | | GenerateMac | | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/generate-mac.html#generate-mac-dukpt-cmac) |
| Y | Generate or Verify DUKPT MAC | | GenerateMac/VerifyMac | | | |

---

## Legacy Key Generation (H-series, I-series)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | | HA | Create key | |
| Y | Generate a Key (replaced by A0) | HC | create-key | |
| Y | Generate a TPK (replaced by A0) | IA | createKey | |

### ECDH (IG)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Execute ECDH | IG | ImportKey, ExportKey, TranslatePin | The service uses ECDH as part of several operations rather than exposing it as a discrete operation. |

---

## Monitoring and Diagnostics (J-series)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Get Host Command Volume | J4 | CloudWatch | Complete details on command usage including non-sensitive parameters can be gathered via CloudTrail. |
| N/A | Reset Utilization Statistics | J6 | N/A | There is no need for such administrative commands with the service. |
| N/A | Get Health Count Stats | J8 | N/A | The service manages HSM health. |

### Random PIN Generation (JA, JC, JE, JG, JK)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Generate Random Pin | JA | GeneratePinData | All pins in the service are protected by a PEK and not a MFK which should not be used for protecting pins. |
| N/A | Translate pin to protection under MFK | JC | translatePinData | No pins are protected by MFK. Pins are always protected by pin keys (PEK). TranslatePin can be used to translate to a local pin key. |
| N/A | Translate pin to protection under MFK | JE | TranslatePinData | Same as JC. |
| N/A | Translate pin from MFK protection to ZPK | JG | TranslatePinData | Same as JC. |
| N/A | Get Current Health Status | JK | N/A | The service manages HSM health. |


---

## EMV Operations (K-series)

### Verify ARQC — Legacy Algorithms (KQ)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|-------------|----------------|-----------------|-------|------|
| Y | Visa VIS — CVN17 | Scheme 0 Visa | VerifyAuthRequest | MajorKeyDerivationMode=A, SessionKeyDerivation=Visa | This algorithm does not use ATC or UN despite being mandatory fields in payShield interface, hence they are not available in service interface for this option. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/use-cases-issuers.networkfunctions.visa.html#use-cases-issuers.networkfunctions.visa.cvn10) |
| Y | Mastercard SKD | Scheme 1 Mastercard SKD | VerifyAuthRequest | MajorKeyDerivationMode=A, SessionKeyDerivation=Mastercard | | |
| Y | Amex AEIPS | Scheme 2 Amex | VerifyAuthRequest | MajorKeyDerivationMode=A, SessionKeyDerivation=Amex | This algorithm does not use ATC or UN despite being mandatory fields in payShield interface. | |
| Y | Verify ARQC for older algorithms | | VerifyAuthRequest | | | |

### Generate EMV MAC (KU)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Generate EMV MAC — Visa | Scheme 0 — Visa VIS | EMV MAC, Generate Offline PIN, EMV Encrypt | SessionKeyDerivationMode=Visa | |
| Y | Generate EMV MAC — Mastercard | Scheme 1 — Mastercard M/Chip | EMV MAC, Generate Offline PIN, EMV Encrypt | SessionKeyDerivationMode=Mastercard | |
| Y | Generate EMV MAC — Amex | Scheme 2 — Amex AEIPS | EMV MAC, Generate Offline PIN, EMV Encrypt | SessionKeyDerivationMode=Amex | |
| Y | Generate EMV MAC — JCB 01 | Scheme 3 — JCB CVN 01 | EMV MAC, Generate Offline PIN, EMV Encrypt | SessionKeyDerivationMode=Visa | The Visa, Amex and JCB 01 schemes are all the same and can be used interchangeably. |
| Y | Generate EMV MAC — JCB 04 | Scheme 5 — JCB CVN 04 | EMV MAC, Generate Offline PIN, EMV Encrypt | SessionKeyDerivationMode=EmvCommon | |
| Y | Main Record — Generate EMV MAC, EMV encrypted data or EMV Pin Change | | EMV MAC, Generate Offline PIN | | |

### Verify EMV Auth Cryptogram (KW)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Verify ARQC for JCB CVN 01 | Option A — Validate — JCB CVN 01 | VerifyAuthRequestCryptogram | | |
| Y | Verify EMV Auth Cryptogram | Validate — EMV Option A/B | VerifyAuthRequestCryptogram | MajorKeyDerivationMode=A, MajorKeyDerivationMode=B, SessionKeyDerivation=EmvCommon | |
| Y | Verify EMV Auth Cryptogram | Validate — JCB CVN 04 | VerifyAuthRequestCryptogram | MajorKeyDerivationMode=A, SessionKeyDerivation=EmvCommon | |
| Y | ARQC Validation — General Record | | VerifyAuthRequestCryptogram | | |

### Generate EMV Issuer Scripts (KY)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Generate EMV Issuer Scripts | Mode 0 — Integrity Only | GenerateMac | EmvMac | Evaluate using CSU in ARQC for script updates. |
| Y | Generate EMV Issuer Scripts | Mode 2 — Integrity and Confidentiality | GenerateMac, EncryptData | EmvMac (GenerateMac), Emv (Encrypt Data) | Encrypting Data and MAC-ing data are completed separately unless the purpose is pin change. Evaluate using CSU in ARQC for script updates. |
| Y | Generate EMV Issuer Scripts | Mode 4 — Integrity and Pin Change | GenerateMacEmvPinChange | | Supports EmvCommon, Visa, Mastercard, EMV2000, Amex key derivation methods. |
| Y | Generate EMV Issuer Scripts | Mode 5 — Integrity Only | GenerateMac | EmvMac | Evaluate using CSU in ARQC for script updates. |
| Y | General EMV MAC, EMV encrypted data or pin change using EMV 4.x standards | | GenerateMac | | |

---

## HMAC Operations (L-series)

### HMAC Key and Generation (L0, LQ)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Generate HMAC key | | Create Key | | |
| N/A | Used for loading keys to HSM | LA | N/A | | Payment Cryptography abstracts HSM and there is no need to load keys. |
| Y | Generate HMAC | 05 — SHA-224 | GenerateMac | Algorithm=HMAC_SHA224 | |
| Y | Generate HMAC | 06 — SHA-256 | GenerateMac | Algorithm=HMAC_SHA256 | |
| Y | Generate HMAC | 07 — SHA-384 | GenerateMac | Algorithm=HMAC_SHA384 | |
| Y | Generate HMAC | 08 — SHA-512 | GenerateMac | Algorithm=HMAC_SHA512 | |
| Y | Generate an HMAC on a Block of Data | | GenerateMac | | |

### Verify HMAC (LS)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Verify an HMAC on a Block of Data | LS | VerifyMac | |

### HMAC Import/Export (LU, LW, LY)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Import HMAC | TR-31 | ImportKey | KeyMaterial=Tr31KeyBlock | HMAC keys are a special case of TR-31/X9.143 as they have the hash algorithm embedded. The service supports this using the standard import/export functions. |
| Y | Import an HMAC | | ImportKey | | HMAC require use of TR-31 optional header HM and can only be imported protected by AES-256 KEK. |
| Y | Export HMAC | TR-31 | ExportKey | KeyMaterial=Tr31KeyBlock | Same as import — the service supports this using the standard import/export functions. |
| Y | Export an HMAC | | ExportKey | | The service will automatically include the required HM header. KEK must be AES-256 to protect HMAC keys. |
| N/A | Rotate LMK protecting HMAC | LY | N/A | | The service doesn't expose MFK-protected keys and handles key rotation as part of shared responsibility. |

### PIN Translation — Main Key (LE, LG)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | Translate Pin from zone key to main key | LE | TranslatePin | No longer needed. The service follows X9.143 prohibitions against using one key for multiple purposes. Pins are never protected by main keys. |
| N/A | Translate pin from main key to zone key | LG | TranslatePin | Same as LE. |
| N/A | | LO | N/A | |


---

## Symmetric Encryption/Decryption (M-series)

### Encrypt Data (M0)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Encrypt Data using Symmetric Key | 00 ECB | EncryptData | Mode=ECB | |
| Y | Encrypt Data using Symmetric Key | 01 CBC | EncryptData | Mode=CBC | |
| Y | Encrypt Data using Symmetric Key | 02 CFB8 | EncryptData | Mode=CFB8 | |
| Y | Encrypt Data using Symmetric Key | 03 CFB64 | EncryptData | Mode=CFB64 | |
| Y | Encrypt Data using Symmetric Key | 05 OFB | EncryptData | Mode=OFB | |
| Y | Encrypt Data using Symmetric Key | | EncryptData | | Supports the most common symmetric encryption mechanisms. |

### Decrypt Data (M2)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Decrypt Data using Symmetric Key | 00 ECB | DecryptData | Mode=ECB | |
| Y | Decrypt Data using Symmetric Key | 01 CBC | DecryptData | Mode=CBC | |
| Y | Decrypt Data using Symmetric Key | 02 CFB8 | DecryptData | Mode=CFB8 | |
| Y | Decrypt Data using Symmetric Key | 03 CFB64 | DecryptData | Mode=CFB64 | |
| Y | Decrypt Data using Symmetric Key | 05 OFB | DecryptData | Mode=OFB | |
| Y | Decrypt Data | | DecryptData | | |

### Re-Encrypt Data (M4)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Translate data from one symmetric key to another | 00 ECB | ReEncryptData | Mode=ECB | Supports TDES, AES, TDES DUKPT and AES DUKPT. |
| Y | Translate data from one symmetric key to another | 01 CBC | ReEncryptData | Mode=CBC | Supports TDES, AES, TDES DUKPT and AES DUKPT. |
| Y | Translate data from one symmetric key to another | 02 CFB8 | ReEncryptData | Mode=CFB8 | Supports TDES, AES, TDES DUKPT and AES DUKPT. |
| Y | Translate data from one symmetric key to another | 03 CFB64 | ReEncryptData | Mode=CFB64 | Supports TDES, AES, TDES DUKPT and AES DUKPT. |
| Y | Reencrypt Visa | | ReEncryptData | | |

### Generate MAC — Extended (M6)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Generate MAC — Wholesale MAC | MAC option 1 (ISO9797-1 algorithm 1, TDES) | GenerateMac | Algorithm=ISO9797_ALGORITHM1 | The service expects all inputs to be hex-encoded binary (equivalent to HSM input format 1). Uses ISO9797 padding method 1. Methods 2 or 3 can be performed in code prior to calling the service. |
| Y | Generate MAC — Retail MAC | MAC option 3 (X9.19 or ISO9797-1 algo 3) | GenerateMac | Algorithm=ISO9797_ALGORITHM3 | Same as above. |
| Y | Generate MAC — CMAC | MAC option 6 (AES CMAC) | GenerateMac | Algorithm=CMAC | The service expects all inputs to be hex-encoded binary. |
| Y | Generate MAC — General Listing | | GenerateMac | | |

### Verify MAC — Extended (M8)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Verify MAC — Retail MAC | MAC option 1 (ISO9797-1 algorithm 3, TDES) | VerifyMac | Algorithm=ISO9797_ALGORITHM1 | Same input format notes as M6. |
| Y | Verify MAC — Retail MAC | MAC option 3 (X9.19 or ISO9797-1 algo 3) | VerifyMac | Algorithm=ISO9797_ALGORITHM3 | |
| Y | Verify MAC — CMAC | MAC option 6 (AES CMAC) | VerifyMac | Algorithm=CMAC | |
| Y | Verify MAC — General Listing | | | | |

### Legacy MAC Commands (MA, MG, MI, MQ, MS)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Generate a MAC (replaced by M6) | MA | GenerateMac | |
| Y | Export a MAC key (replaced by A8) | MG | exportKey | |
| Y | Import a MAC key (replaced by A6) | MI | importKey | |
| Y | Generate a MAC (replaced by M6) | MQ | GenerateMac | |
| Y | Generate a MAC (replaced by M6) | MS | GenerateMac | |

### Verify and Re-Generate MAC (MY)

| Supported | Description | Sub-Command | APC Equivalent | Notes |
|-----------|-------------|-------------|----------------|-------|
| Y | Verify MAC and then re-generate using a different key | MAC option 1 (ISO9797-1 algorithm 3, TDES) | VerifyMac, GenerateMac | The service can perform this function by calling VerifyMac followed by GenerateMac in sequence. |
| Y | Verify MAC and then re-generate using a different key | MAC option 3 (X9.19 or ISO9797-1 algo 3) | VerifyMac, GenerateMac | Same as above. |
| Y | Verify MAC and then re-generate using a different key | MAC option 5 CBC MAC (AES) | VerifyMac, GenerateMac | Same as above. |
| Y | Verify MAC and then re-generate using a different key | MAC option 6 CMAC (AES) | VerifyMac, GenerateMac | Same as above. |
| Y | Verify MAC and then re-generate using a different key | | | |

---

## Random Number and Diagnostics (N-series)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Generate a Random Value | N0 | KMS.GenerateRandom | |
| N/A | Perform HSM Diagnostics | NC | N/A | AWS manages HSM hardware behind the scenes. |
| N/A | HSM Management Commands | NI | N/A | |
| N/A | Return HSM Status | NO | N/A | AWS manages HSM health. |


---

## AS2805 Zone Keys and Data (O-series, P-series)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| Y | Generate and Export Zone Keys for AS2805 | OI | | |
| Y | Import Zone Keys for AS2805 | OK | importKey | |
| Y | Encrypt Data (AS2805) | PU | EncryptData | |
| Y | Decrypt Data (AS2805) | PW | DecryptData | |

---

## Audit (Q-series)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | Migrate Audit key to new LMK | Q0 | N/A | Audit logs are stored in CloudTrail and protected by KMS keys. |
| Y | Retrieve audit record | Q2 | AWS CloudTrail | CloudTrail can be configured to provide individual request level details including caller, command and non-sensitive parameters. Control Plane is enabled by default. |
| Y | Print audit record | Q4 | AWS CloudTrail | Same as Q2. |
| N/A | Delete Audit Record | Q6 | N/A | Audit logs are managed via CloudTrail. |
| N/A | Verify Audit Record | Q8 | N/A | Audit logs are managed via CloudTrail. |

---

## Certificate Requests (QE)

| Supported | Description | Sub-Command | APC Equivalent | Notes | Docs |
|-----------|-------------|-------------|----------------|-------|------|
| Y | Generate a Certificate Request | 01 — RSA | | Output is always Base64 encoded PEM. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keyexchange-byoca.html) |
| Y | Generate a Certificate Request | 02 — ECC | | Output is always Base64 encoded PEM. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keyexchange-byoca.html) |
| Y | Generate a Certificate Request (Main Record) | | | Output is always Base64 encoded PEM. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keyexchange-byoca.html) |

---

## Dynamic Card Verification (QY)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes |
|-----------|-------------|-------------|----------------|-----------------|-------|
| Y | Generate Dynamic Card Values | 0 Visa DCVV | GenerateCardVerificationData | DynamicCardVerificationValue | ATC value should represent the counter as expressed as a hex number. For instance, the 50th transaction is represented in hex as a value of 32. |
| Y | Generate Dynamic Card Verification Values (Main Record) | | GenerateCardVerificationData | | |

---

## Access Control (RA)

| Supported | Description | Command | APC Equivalent | Notes |
|-----------|-------------|---------|----------------|-------|
| N/A | Cancel Authorized Activities | RA | AWS IAM | Access controls are managed via AWS IAM. Contingent authorization can be used for temporary permissions. |

---

## Amex CSC (RY)

| Supported | Description | Sub-Command | APC Equivalent | APC Sub-Command | Notes | Docs |
|-----------|-------------|-------------|----------------|-----------------|-------|------|
| Y | Generate Amex CSC | 0 Version 1 | GenerateCardVerificationData | AmexCardSecurityCodeVersion1 | Always use expiration date as YYMM for Amex. Service supports CSC length of 3, 4, 5. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/use-cases-issuers.networkfunctions.amex.html#use-cases-issuers.networkfunctions.amex.csc) |
| Y | Generate Amex CSC | 1 Version 2 | GenerateCardVerificationData | AmexCardSecurityCodeVersion2 | Always use expiration date as YYMM for Amex. Service supports CSC length of 3, 4, 5. Service code is set according to card capabilities and usage such as 999 for iCSC. | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/use-cases-issuers.networkfunctions.amex.html#use-cases-issuers.networkfunctions.amex.csc2) |
| Y | Generate Amex CSC | 2 AEVV | GenerateCardVerificationData | AmexCardSecurityCodeVersion2 | | [Link](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/use-cases-issuers.networkfunctions.amex.html#use-cases-issuers.networkfunctions.amex.aevv) |
| Y | Verify AMEX CSC (Main Record) | | VerifyCardVerificationData | | | |

---

## HSM Certificate and Unsupported Commands (S-series, T-series, U-series, V-series, W-series)

| Supported | Command | Notes |
|-----------|---------|-------|
| N/A | SE | Payment Cryptography connects to AWS servers and uses AWS CA. There is no direct connection to HSMs. |
| N/A | TG | |
| N/A | TY | |
| N/A | UI | |
| N/A | VW | |
| N/A | VY | |
| N/A | WC | |
| N/A | WQ | |
| N/A | WW | |
| N/A | WY | |
