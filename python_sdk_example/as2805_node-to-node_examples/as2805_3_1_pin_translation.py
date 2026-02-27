"""
AS2805 PIN Translation with Session Key Derivation

This script demonstrates AS2805 PIN translation between Node 2 (software HSM)
and Node 1 (AWS Payment Cryptography) using the AS2805 session key derivation
scheme (section 6.4/6.6).

Scenario:
  A terminal sends a transaction with a PIN to Node 2 (acquirer).
  Node 2 derives a session PIN key (KPE) from its ZPK/KPP using the STAN
  and transaction amount per AS2805 section 6.6, encrypts the PIN block
  under the derived KPE, and sends it to Node 1 (APC).

  APC uses IncomingAs2805Attributes to perform the same derivation internally
  and translates the PIN block to the outgoing key.

AS2805 Section 6.6.3 - KPE Derivation:
  Field E: 6 digits of STAN, left justified, right zero-filled to 64 bits
  Field F: 12 digits of amount, right justified, left zero-filled to 64 bits
  D = E || F (16 bytes)
  KPE = OWF(KPP, D)

AS2805 OWF (One Way Function) for data > 8 bytes:
  1. MAC = 3DES-CBC-MAC(key, data, IV=0)  (last 8 bytes of CBC encryption)
  2. result = 3DES-CBC(key, data, IV=MAC)  (re-encrypt using MAC as IV)
  3. OWF = result XOR data

Prerequisites:
  - Mod_2_1 has been run (working key exchange complete)

Sample Data:
  PAN: 4242424242424242, PIN: 1234
  PIN Block (ISO Format 0): 041010DBDBDBDBDB
  STAN: 000438, Transaction Amount: 000000000328
"""

import json
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import keyring
import pathlib
import base64
import binascii
import os
import sys

script_dir = pathlib.Path(__file__).parent
output_dir = script_dir / "output"

print("=" * 70)
print("AS2805 PIN Translation (with Session Key Derivation)")
print("=" * 70)


# ============================================================================
# AS2805 OWF Implementation
# ============================================================================
def calculate_3des_mac(data: bytes, key: bytes) -> bytes:
    """3DES CBC-MAC: encrypt data with 3DES-CBC zero IV, return last 8 bytes."""
    cipher = Cipher(TripleDES(key), modes.CBC(b'\x00' * 8), backend=default_backend())
    enc = cipher.encryptor()
    encrypted = enc.update(data) + enc.finalize()
    return encrypted[-8:]


def calculate_owf_as2805(data: bytes, key: bytes) -> bytes:
    """
    AS2805 One Way Function for data > 8 bytes.
    1. MAC = 3DES-CBC-MAC(key, data, IV=0)
    2. result = 3DES-CBC-encrypt(key, data, IV=MAC)
    3. OWF = result XOR data
    """
    # Step 1: Calculate 3DES MAC (last 8 bytes of CBC encryption with zero IV)
    mac = calculate_3des_mac(data, key)

    # Step 2: Encrypt data again using MAC as IV
    cipher = Cipher(TripleDES(key), modes.CBC(mac), backend=default_backend())
    enc = cipher.encryptor()
    encrypted = enc.update(data) + enc.finalize()

    # Step 3: XOR with original data
    result = bytes(a ^ b for a, b in zip(encrypted, data))

    # Truncate to original input size
    return result[:len(data)]


# ============================================================================
# Sample transaction data
# ============================================================================
PAN = "4242424242424242"
PIN = "1234"
PIN_BLOCK_CLEAR = "041010DBDBDBDBDB"  # ISO Format 0 PIN block
STAN = "000438"
TRANSACTION_AMOUNT = "000000000328"

print(f"\nSample Transaction Data:")
print(f"  PAN:       {PAN}")
print(f"  PIN:       {PIN}")
print(f"  PIN Block: {PIN_BLOCK_CLEAR} (ISO Format 0)")
print(f"  STAN:      {STAN}")
print(f"  Amount:    {TRANSACTION_AMOUNT}")

# ============================================================================
# STEP 1: Load Prerequisites
# ============================================================================
print("\n[STEP 1] Loading prerequisites...")

keystore_path = output_dir / "node1_keystore.json"
if not keystore_path.exists():
    print(f"✗ Keystore not found: {keystore_path}")
    sys.exit(1)

try:
    keystore_password = keyring.get_password("node1_keystore", "workshop_user")
    if keystore_password is None:
        print("✗ Keystore password not found in keyring")
        sys.exit(1)

    salt = b'node1_keystore_salt_v1'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    encryption_key = base64.urlsafe_b64encode(kdf.derive(keystore_password.encode()))
    fernet = Fernet(encryption_key)

    with open(keystore_path, 'rb') as f:
        keystore = json.loads(fernet.decrypt(f.read()).decode())

    if "node2_zpk" not in keystore["keys"]:
        print("✗ Node 2 ZPK not found in keystore. Run Mod_2_1 first!")
        sys.exit(1)

    node2_zpk_bytes = base64.b64decode(keystore["keys"]["node2_zpk"]["key"])
    node2_zpk_kcv = keystore["keys"]["node2_zpk"]["check_value"]
    print(f"✓ Node 2 ZPK/KPP loaded: {len(node2_zpk_bytes)} bytes, KCV={node2_zpk_kcv}")

except Exception as e:
    print(f"✗ Error loading keystore: {e}")
    sys.exit(1)

for fname in ["working_key_details.json", "node2_imported_key_details.json"]:
    if not (output_dir / fname).exists():
        print(f"✗ {fname} not found. Run Mod_2_1 first!")
        sys.exit(1)

with open(output_dir / "working_key_details.json", 'r') as f:
    working_key_details = json.load(f)
with open(output_dir / "node2_imported_key_details.json", 'r') as f:
    node2_imported_details = json.load(f)

incoming_zpk_arn = node2_imported_details['zpk']['arn']
apc_zpk_arn = working_key_details['zpk']['arn']
print(f"✓ Incoming ZPK ARN: {incoming_zpk_arn}")
print(f"✓ Outgoing ZPK ARN: {apc_zpk_arn}")


# ============================================================================
# STEP 2: Initialize AWS Clients
# ============================================================================
print("\n[STEP 2] Initializing AWS Payment Cryptography clients...")

try:
    session = boto3.Session()

    credentials = session.get_credentials()
    if credentials is None:
        print("✗ No AWS credentials found!")
        print("\nPlease configure AWS credentials using one of these methods:")
        print("  1. AWS CLI: aws configure")
        print("  2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
        print("  3. AWS credentials file: ~/.aws/credentials")
        print("  4. IAM role (if running on EC2/ECS/Lambda)")
        sys.exit(1)

    frozen_credentials = credentials.get_frozen_credentials()
    print(f"✓ AWS credentials found")
    print(f"  Access Key ID: {frozen_credentials.access_key[:10]}...")

    if os.environ.get('AWS_ACCESS_KEY_ID'):
        print(f"  Source: Environment variables")
    elif os.environ.get('AWS_PROFILE'):
        print(f"  Source: AWS Profile ({os.environ.get('AWS_PROFILE')})")
    else:
        print(f"  Source: Default credential chain")

    sts_client = boto3.client('sts')
    identity = sts_client.get_caller_identity()

    print(f"✓ Credentials verified")
    print(f"  Account: {identity['Account']}")
    print(f"  User/Role ARN: {identity['Arn']}")

    region = session.region_name
    if region is None:
        print("\n⚠ Warning: No default region configured")
        print("  Using ap-southeast-2 as default")
        region = 'ap-southeast-2'
    else:
        print(f"✓ Region: {region}")

    data_client = boto3.client('payment-cryptography-data', region_name=region)
    print(f"✓ AWS Payment Cryptography Data client initialized")

except NoCredentialsError:
    print("✗ No AWS credentials found!")
    sys.exit(1)
except PartialCredentialsError:
    print("✗ Incomplete AWS credentials!")
    sys.exit(1)
except ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code in ['InvalidClientTokenId', 'SignatureDoesNotMatch', 'ExpiredToken']:
        print(f"✗ Invalid or expired AWS credentials!")
    else:
        print(f"✗ Error: {e.response['Error']['Message']}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Unexpected error: {e}")
    sys.exit(1)

# ============================================================================
# STEP 3: Derive Session KPE and Encrypt PIN Block
# ============================================================================
print("\n" + "=" * 70)
print("STEP 3: Derive Session KPE and Encrypt PIN Block")
print("=" * 70)
print("\nAS2805 section 6.6.3: Derive KPE from KPP using STAN and amount.")

try:
    # Build derivation data per AS2805 section 6.6.3:
    # Field E: 6 digits of STAN, left justified, right zero-filled to 64 bits
    field_e = STAN.ljust(6, '0').ljust(16, '0')
    # Field F: 12 digits of amount, right justified, left zero-filled to 64 bits
    field_f = TRANSACTION_AMOUNT.rjust(12, '0').rjust(16, '0')
    # D = E || F
    derivation_data = binascii.unhexlify(field_e + field_f)

    print(f"\n  Field E: {field_e}")
    print(f"  Field F: {field_f}")
    print(f"  D:       {(field_e + field_f)} ({len(derivation_data)} bytes)")
    print(f"  KPP:     {node2_zpk_bytes.hex().upper()}")

    # KPE = OWF(KPP, D) using AS2805 OWF
    session_kpe = calculate_owf_as2805(derivation_data, node2_zpk_bytes)
    print(f"  KPE:     {session_kpe.hex().upper()}")

    # Encrypt PIN block under session KPE using 3DES-ECB
    pin_block_bytes = binascii.unhexlify(PIN_BLOCK_CLEAR)
    cipher = Cipher(TripleDES(session_kpe), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    encrypted_pin_block = (enc.update(pin_block_bytes) + enc.finalize()).hex().upper()

    print(f"\n  Cleartext PIN Block:  {PIN_BLOCK_CLEAR}")
    print(f"  Encrypted PIN Block:  {encrypted_pin_block}")

except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)

# ============================================================================
# STEP 4: APC Translates PIN Block
# ============================================================================
print("\n" + "=" * 70)
print("STEP 4: APC Translates PIN Block (AS2805 KPE → Node 1 ZPK)")
print("=" * 70)
print("\nAPC uses IncomingAs2805Attributes to derive the same session KPE,")
print("decrypts the PIN block, and re-encrypts under Node 1's ZPK.")

try:
    translate_response = data_client.translate_pin_data(
        IncomingKeyIdentifier=incoming_zpk_arn,
        OutgoingKeyIdentifier=apc_zpk_arn,
        IncomingTranslationAttributes={
            'IsoFormat0': {
                'PrimaryAccountNumber': PAN
            }
        },
        OutgoingTranslationAttributes={
            'IsoFormat0': {
                'PrimaryAccountNumber': PAN
            }
        },
        EncryptedPinBlock=encrypted_pin_block,
        IncomingAs2805Attributes={
            'SystemTraceAuditNumber': STAN,
            'TransactionAmount': TRANSACTION_AMOUNT,
        },
    )

    translated_pin_block = translate_response['PinBlock']
    outgoing_kcv = translate_response['KeyCheckValue']

    print(f"\n  ✓ PIN block translated successfully")
    print(f"    Incoming PIN Block:   {encrypted_pin_block}")
    print(f"    STAN:                 {STAN}")
    print(f"    Transaction Amount:   {TRANSACTION_AMOUNT}")
    print(f"    Translated PIN Block: {translated_pin_block}")
    print(f"    Outgoing Key KCV:     {outgoing_kcv}")

except ClientError as e:
    print(f"✗ Error translating PIN: {e.response['Error']['Message']}")
    sys.exit(1)


# ============================================================================
# STEP 5: Verify Translation
# ============================================================================
print("\n" + "=" * 70)
print("STEP 5: Verify Translation")
print("=" * 70)
print("\nDecrypt the translated PIN block using Node 1's ZPK to verify")
print("the PIN block is intact after translation.")

try:
    if "apc_zpk" not in keystore["keys"]:
        print("✗ APC ZPK not found in keystore")
        sys.exit(1)

    node1_zpk_bytes = base64.b64decode(keystore["keys"]["apc_zpk"]["key"])
    translated_bytes = binascii.unhexlify(translated_pin_block)
    cipher = Cipher(TripleDES(node1_zpk_bytes), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    decrypted_pin_block = (dec.update(translated_bytes) + dec.finalize()).hex().upper()

    print(f"\n  Translated PIN Block:  {translated_pin_block}")
    print(f"  Decrypted PIN Block:   {decrypted_pin_block}")
    print(f"  Original PIN Block:    {PIN_BLOCK_CLEAR}")

    if decrypted_pin_block == PIN_BLOCK_CLEAR:
        print(f"\n  ✓ PIN block verified - translation successful")
    else:
        print(f"\n  ✗ PIN block mismatch after translation")

except Exception as e:
    print(f"✗ Error verifying: {e}")
    sys.exit(1)

# ============================================================================
# STEP 6: Generate MAC Over Transaction Data (Node 2 ZAK)
# ============================================================================
print("\n" + "=" * 70)
print("STEP 6: Generate MAC Over Transaction Data")
print("=" * 70)
print("\nNode 2 generates a MAC over the encrypted PIN block using its ZAK(s)")
print("per AS2805.4.1 (Retail MAC). This MAC is sent with the transaction")
print("for verification by Node 1 (APC).")

try:
    # Load Node 2's ZAK from keystore
    if "node2_zak" not in keystore["keys"]:
        print("✗ Node 2 ZAK not found in keystore. Run Mod_2_1 first!")
        sys.exit(1)

    node2_zak_bytes = base64.b64decode(keystore["keys"]["node2_zak"]["key"])
    node2_zak_kcv = keystore["keys"]["node2_zak"]["check_value"]
    print(f"  Node 2 ZAK loaded: KCV={node2_zak_kcv}")

    # Message data: the encrypted PIN block (as sent in the transaction)
    # In a real implementation, the MAC would cover more fields (PAN, amount, etc.)
    message_data = encrypted_pin_block
    message_bytes = binascii.unhexlify(message_data)

    # AS2805.4.1 MAC (Method 2 / Retail MAC / ISO 9797-1 Algorithm 3):
    # 1. Single-DES CBC with left key half for all blocks
    # 2. Decrypt final CBC result with right key half (single DES)
    # 3. Encrypt result with left key half (single DES)
    # 4. Truncate to 4 bytes
    # No padding needed if data is already block-aligned (Padding Method 1)
    key_left = node2_zak_bytes[:8]
    key_right = node2_zak_bytes[8:16]

    # Pad to block boundary if needed (Padding Method 1: zero-pad)
    padded = message_bytes
    if len(padded) % 8 != 0:
        padded = padded + b'\x00' * (8 - len(padded) % 8)

    # Single-DES CBC with left key half (K|K|K for single-DES in TripleDES)
    key_left_3 = key_left * 3
    cipher = Cipher(TripleDES(key_left_3), modes.CBC(b'\x00' * 8), backend=default_backend())
    enc = cipher.encryptor()
    cbc_result = enc.update(padded) + enc.finalize()
    intermediate = cbc_result[-8:]  # Last block

    # Decrypt with right key half
    key_right_3 = key_right * 3
    cipher = Cipher(TripleDES(key_right_3), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    decrypted = dec.update(intermediate) + dec.finalize()

    # Encrypt with left key half
    cipher = Cipher(TripleDES(key_left_3), modes.ECB(), backend=default_backend())
    enc = cipher.encryptor()
    mac_full = enc.update(decrypted) + enc.finalize()

    # Truncate to 4 bytes (8 hex chars)
    mac_value = mac_full[:4].hex().upper()

    print(f"\n  Message Data:    {message_data}")
    print(f"  MAC (AS2805.4.1): {mac_value}")
    print(f"  MAC Key KCV:     {node2_zak_kcv}")

    # Save transaction data for Mod_4_1
    transaction_data = {
        'encrypted_pin_block': encrypted_pin_block,
        'translated_pin_block': translated_pin_block,
        'pan': PAN,
        'stan': STAN,
        'transaction_amount': TRANSACTION_AMOUNT,
        'mac': mac_value,
        'message_data': message_data,
        'node2_zak_kcv': node2_zak_kcv,
    }

    transaction_file = output_dir / "transaction_data.json"
    with open(transaction_file, 'w') as f:
        json.dump(transaction_data, f, indent=2)

    print(f"  ✓ Transaction data saved to: {transaction_file.name}")

except Exception as e:
    print(f"✗ Error generating MAC: {e}")
    sys.exit(1)

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("PIN TRANSLATION COMPLETE - Summary")
print("=" * 70)
print(f"\n  PAN:                            {PAN}")
print(f"  STAN:                           {STAN}")
print(f"  Transaction Amount:             {TRANSACTION_AMOUNT}")
print(f"  Original PIN Block (clear):     {PIN_BLOCK_CLEAR}")
print(f"  Session KPE (derived):          {session_kpe.hex().upper()}")
print(f"  Encrypted under KPE:            {encrypted_pin_block}")
print(f"  Translated under Node 1 ZPK:    {translated_pin_block}")
print(f"  Decrypted (verification):       {decrypted_pin_block}")
print(f"\n  ✓ PIN successfully translated using AS2805 session key derivation")
print(f"  ✓ MAC generated over transaction data using AS2805.4.1")
print("=" * 70)
