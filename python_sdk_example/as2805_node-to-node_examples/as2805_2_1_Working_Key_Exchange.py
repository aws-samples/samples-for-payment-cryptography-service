"""
AS2805 Working Key (Session Key) Exchange

This script demonstrates the AS2805 working key exchange process between two nodes.
Node 2 (AWS Payment Cryptography) creates working keys and exports them using
AS2805 variant-based wrapping. Node 1 (local software HSM) unwraps and validates.

Working Keys:
  ZPK (Zone PIN Key)        - PIN encryption between nodes
  ZEK (Zone Encryption Key) - Data encryption between nodes
  ZAK (Zone Authentication Key) - MAC generation/verification between nodes

Prerequisites:
  - as2805_1_1 has been run (KEK exchange complete)
  - as2805_1_5 has been run (KEK validation complete)

AS2805 Key Exchange Process:
  1. Node 2 creates working keys in APC
  2. Node 2 exports each key wrapped under KEK(s) using AS2805 variant masks
  3. Wrapped keys are transmitted to Node 1
  4. Node 1 unwraps using matching variant mask on KEK(r)
  5. Node 1 computes KCVs and returns them to Node 2
  6. Node 2 validates KCVs against APC export response
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
import keystore_helper
import pathlib
import base64
import binascii
import os
import sys

script_dir = pathlib.Path(__file__).parent
output_dir = script_dir / "output"
output_dir.mkdir(exist_ok=True)

print("=" * 70)
print("AS2805 Working Key (Session Key) Exchange")
print("=" * 70)
print("\nThis script will:")
print("  1. Create ZPK, ZEK, and ZAK working keys in APC")
print("  2. Export each key using AS2805 variant-based wrapping")
print("  3. Node 1 unwraps and validates each key")
print("=" * 70)

# ============================================================================
# STEP 1: Load Prerequisites
# ============================================================================
print("\n[STEP 1] Loading prerequisites from previous modules...")

# Load KEK details (Node 2's KEKs ARN)
kek_details_file = output_dir / "apc_created_kek.json"
if not kek_details_file.exists():
    print(f"✗ KEK details file not found: {kek_details_file}")
    print("  Please run as2805_1_1 first!")
    sys.exit(1)

try:
    with open(kek_details_file, 'r') as f:
        kek_details = json.load(f)

    keks_arn = kek_details['arn']
    keks_kcv = kek_details['check_value']

    print(f"✓ Loaded KEKs (Node 2's sending KEK)")
    print(f"  ARN: {keks_arn}")
    print(f"  KCV: {keks_kcv}")

except Exception as e:
    print(f"✗ Error loading KEK details: {e}")
    sys.exit(1)

# Load Node 1's keystore (contains KEK(r) = Node 2's KEK(s))
keystore_path = output_dir / "node1_keystore.json"
if not keystore_path.exists():
    print(f"✗ Keystore not found: {keystore_path}")
    print("  Please run as2805_1_1 first!")
    sys.exit(1)

try:
    keystore_password = keystore_helper.get_or_prompt_password("node1_keystore", "workshop_user")

    salt = b'node1_keystore_salt_v1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    encryption_key = base64.urlsafe_b64encode(kdf.derive(keystore_password.encode()))
    fernet = Fernet(encryption_key)

    with open(keystore_path, 'rb') as f:
        encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        keystore = json.loads(decrypted_data.decode())

    # Node 1's KEK(r) is the APC-created KEK that was imported into the keystore
    # This is the same key as Node 2's KEK(s), just from Node 1's perspective
    if "apc_imported_kek" not in keystore["keys"]:
        print("✗ APC imported KEK not found in keystore")
        sys.exit(1)

    kekr_info = keystore["keys"]["apc_imported_kek"]
    kekr_bytes = base64.b64decode(kekr_info["key"])

    print(f"✓ Loaded Node 1's KEK(r) from keystore")
    print(f"  Alias: apc_imported_kek")
    print(f"  Length: {len(kekr_bytes)} bytes ({len(kekr_bytes) * 8} bits)")

except Exception as e:
    print(f"✗ Error loading keystore: {e}")
    sys.exit(1)

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

    control_client = boto3.client('payment-cryptography', region_name=region)
    data_client = boto3.client('payment-cryptography-data', region_name=region)

    try:
        control_client.list_keys(MaxResults=1)
        print(f"✓ AWS Payment Cryptography access verified")
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print(f"\n✗ Access Denied to AWS Payment Cryptography")
            print(f"  Error: {e.response['Error']['Message']}")
            sys.exit(1)
        raise

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
# STEP 3: Create Working Keys in APC
# ============================================================================
print("\n" + "=" * 70)
print("STEP 3: Create Working Keys in AWS Payment Cryptography")
print("=" * 70)

# Define the three working keys and their properties
WORKING_KEYS = {
    'zpk': {
        'name': 'ZPK (Zone PIN Key)',
        'key_usage': 'TR31_P0_PIN_ENCRYPTION_KEY',
        'modes_of_use': {
            'Encrypt': True,
            'Decrypt': True,
            'Wrap': True,
            'Unwrap': True
        },
        'as2805_variant': 'PIN_ENCRYPTION_KEY_VARIANT_28',
        'tag_name': 'AS2805-ZPK',
    },
    'zek': {
        'name': 'ZEK (Zone Encryption Key)',
        'key_usage': 'TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY',
        'modes_of_use': {
            'Encrypt': True,
            'Decrypt': True,
            'Wrap': True,
            'Unwrap': True
        },
        'as2805_variant': 'DATA_ENCRYPTION_KEY_VARIANT_22',
        'tag_name': 'AS2805-ZEK',
    },
    'zak': {
        'name': 'ZAK (Zone Authentication Key)',
        'key_usage': 'TR31_M0_ISO_16609_MAC_KEY',
        'modes_of_use': {
            'Generate': True,
            'Verify': True
        },
        'as2805_variant': 'MESSAGE_AUTHENTICATION_KEY_VARIANT_24',
        'tag_name': 'AS2805-ZAK',
    },
}

created_keys = {}

for key_id, key_config in WORKING_KEYS.items():
    print(f"\n  Creating {key_config['name']}...")

    try:
        create_response = control_client.create_key(
            KeyAttributes={
                'KeyAlgorithm': 'TDES_2KEY',
                'KeyClass': 'SYMMETRIC_KEY',
                'KeyUsage': key_config['key_usage'],
                'KeyModesOfUse': key_config['modes_of_use']
            },
            Exportable=True,
            Enabled=True,
            Tags=[
                {'Key': 'Name', 'Value': key_config['tag_name']},
                {'Key': 'Purpose', 'Value': 'AS2805-Working-Key'}
            ]
        )

        key_arn = create_response['Key']['KeyArn']
        key_kcv = create_response['Key']['KeyCheckValue']

        created_keys[key_id] = {
            'arn': key_arn,
            'kcv': key_kcv,
            'config': key_config
        }

        print(f"  ✓ {key_config['name']} created")
        print(f"    ARN: {key_arn}")
        print(f"    KCV: {key_kcv}")

    except ClientError as e:
        print(f"  ✗ Error creating {key_config['name']}: {e.response['Error']['Message']}")
        sys.exit(1)

print(f"\n✓ All {len(created_keys)} working keys created successfully")

# ============================================================================
# STEP 4: Export Working Keys Using AS2805 Variant Wrapping
# ============================================================================
print("\n" + "=" * 70)
print("STEP 4: Export Working Keys Using AS2805 Variant Wrapping")
print("=" * 70)
print("\nAPC applies the AS2805 variant mask to KEK(s) internally and returns")
print("the working key wrapped in AS2805-compliant format.")

exported_keys = {}

for key_id, key_info in created_keys.items():
    key_config = key_info['config']
    print(f"\n  Exporting {key_config['name']}...")
    print(f"    Variant: {key_config['as2805_variant']}")
    print(f"    Wrapping KEK: {keks_arn}")

    try:
        export_response = control_client.export_key(
            ExportKeyIdentifier=key_info['arn'],
            KeyMaterial={
                'As2805KeyCryptogram': {
                    'WrappingKeyIdentifier': keks_arn,
                    'As2805KeyVariant': key_config['as2805_variant']
                }
            }
        )

        wrapped_key = export_response['WrappedKey']
        wrapped_material = wrapped_key['KeyMaterial']
        export_kcv = wrapped_key['KeyCheckValue']
        kcv_algorithm = wrapped_key['KeyCheckValueAlgorithm']

        exported_keys[key_id] = {
            'wrapped_material': wrapped_material,
            'kcv': export_kcv,
            'kcv_algorithm': kcv_algorithm,
            'wrapping_key_arn': wrapped_key.get('WrappingKeyArn', keks_arn),
            'format': wrapped_key.get('WrappedKeyMaterialFormat', 'KEY_CRYPTOGRAM'),
        }

        print(f"  ✓ {key_config['name']} exported")
        print(f"    Wrapped Key: {wrapped_material}")
        print(f"    KCV: {export_kcv}")
        print(f"    KCV Algorithm: {kcv_algorithm}")

    except ClientError as e:
        print(f"  ✗ Error exporting {key_config['name']}: {e.response['Error']['Message']}")
        sys.exit(1)

print(f"\n✓ All {len(exported_keys)} working keys exported successfully")

# ============================================================================
# STEP 5: Node 1 Unwraps Working Keys
# ============================================================================
print("\n" + "=" * 70)
print("STEP 5: Node 1 Unwraps Working Keys")
print("=" * 70)
print("\nNode 1 applies the AS2805 variant mask to KEK(r) and decrypts")
print("each working key using 3DES-CBC with zero IV.")

# AS2805 variant masks (2-byte patterns repeated for 2-key TDES / 16 bytes)
AS2805_VARIANT_MASKS = {
    'PIN_ENCRYPTION_KEY_VARIANT_28': bytes.fromhex('28C0') * 8,              # 16 bytes
    'DATA_ENCRYPTION_KEY_VARIANT_22': bytes.fromhex('22C0') * 8,             # 16 bytes
    'MESSAGE_AUTHENTICATION_KEY_VARIANT_24': bytes.fromhex('24C0') * 8,      # 16 bytes
}

unwrapped_keys = {}

for key_id, export_info in exported_keys.items():
    key_config = created_keys[key_id]['config']
    variant_name = key_config['as2805_variant']

    print(f"\n  Unwrapping {key_config['name']}...")

    try:
        variant_mask = AS2805_VARIANT_MASKS[variant_name]
        print(f"    Variant: {variant_name}")
        print(f"    Mask: {variant_mask.hex().upper()}")

        # Apply variant mask to KEK(r) via XOR
        kek_variant = bytes(a ^ b for a, b in zip(kekr_bytes, variant_mask))

        wrapped_key_bytes = binascii.unhexlify(export_info['wrapped_material'])
        print(f"    Wrapped material: {export_info['wrapped_material']}")

        # Decrypt using 3DES-CBC with zero IV
        cipher = Cipher(
            TripleDES(kek_variant),
            modes.CBC(b'\x00' * 8),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        unwrapped_key = decryptor.update(wrapped_key_bytes) + decryptor.finalize()

        # Compute KCV (ANSI X9.24: encrypt 8 zero bytes with ECB, take first 3 bytes)
        kcv_cipher = Cipher(
            TripleDES(unwrapped_key),
            modes.ECB(),
            backend=default_backend()
        )
        kcv_enc = kcv_cipher.encryptor()
        computed_kcv = (kcv_enc.update(b'\x00' * 8) + kcv_enc.finalize())[:3].hex().upper()

        print(f"  ✓ {key_config['name']} unwrapped")
        print(f"    Key length: {len(unwrapped_key)} bytes ({len(unwrapped_key) * 8} bits)")
        print(f"    KCV: {computed_kcv}")

        unwrapped_keys[key_id] = unwrapped_key

    except Exception as e:
        print(f"  ✗ Error unwrapping {key_config['name']}: {e}")
        sys.exit(1)

print(f"\n✓ All {len(unwrapped_keys)} working keys unwrapped by Node 1")

# ============================================================================
# STEP 6: KCV Validation
# ============================================================================
print("\n" + "=" * 70)
print("STEP 6: KCV Validation")
print("=" * 70)
print("\nNode 1 computes KCVs for each unwrapped key (ANSI X9.24: encrypt")
print("8 zero bytes with ECB, take first 3 bytes) and compares against")
print("the KCVs returned by APC.")

all_kcvs_valid = True

for key_id, unwrapped_key in unwrapped_keys.items():
    key_config = created_keys[key_id]['config']
    create_kcv = created_keys[key_id]['kcv']
    export_kcv = exported_keys[key_id]['kcv']

    print(f"\n  Validating {key_config['name']}...")

    try:
        # Compute KCV: encrypt 8 zero bytes with 3DES-ECB, take first 3 bytes
        cipher = Cipher(
            TripleDES(unwrapped_key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        computed_kcv = (encryptor.update(b'\x00' * 8) + encryptor.finalize())[:3].hex().upper()

        print(f"    APC KCV (CreateKey): {create_kcv}")
        print(f"    APC KCV (ExportKey): {export_kcv}")
        print(f"    Computed KCV:        {computed_kcv}")

        if computed_kcv == create_kcv or computed_kcv == export_kcv:
            print(f"  ✓ KCV MATCH - {key_config['name']} validated")
        else:
            print(f"  ✗ KCV MISMATCH - {key_config['name']} validation FAILED")
            all_kcvs_valid = False

    except Exception as e:
        print(f"  ✗ Error validating {key_config['name']}: {e}")
        all_kcvs_valid = False

if all_kcvs_valid:
    print(f"\n✓ All working keys validated successfully")
else:
    print(f"\n✗ KCV validation failed for one or more keys")
    print(f"  DO NOT proceed with using these working keys")
    sys.exit(1)

# ============================================================================
# STEP 7: Store Working Keys in Node 1's Keystore
# ============================================================================
print("\n" + "=" * 70)
print("STEP 7: Store Working Keys in Node 1's Keystore")
print("=" * 70)

try:
    for key_id, unwrapped_key in unwrapped_keys.items():
        key_config = created_keys[key_id]['config']
        export_kcv = exported_keys[key_id]['kcv']
        key_arn = created_keys[key_id]['arn']

        keystore_alias = f"apc_{key_id}"
        keystore["keys"][keystore_alias] = {
            "type": "secret",
            "algorithm": "3DES",
            "key": base64.b64encode(unwrapped_key).decode('utf-8'),
            "length": len(unwrapped_key),
            "source": "AWS Payment Cryptography",
            "check_value": export_kcv,
            "source_arn": key_arn,
            "as2805_key_type": key_id.upper(),
            "as2805_variant": key_config['as2805_variant']
        }

        print(f"  ✓ Stored {key_config['name']} as '{keystore_alias}'")

    # Re-encrypt and save keystore
    keystore_json = json.dumps(keystore, indent=2)
    encrypted_keystore = fernet.encrypt(keystore_json.encode())
    with open(keystore_path, 'wb') as f:
        f.write(encrypted_keystore)

    print(f"\n✓ Keystore saved to: {keystore_path.name}")
    print(f"  Total keys in keystore: {len(keystore['keys'])}")

except Exception as e:
    print(f"✗ Error storing working keys: {e}")
    sys.exit(1)

# ============================================================================
# STEP 8: Save Working Key Details
# ============================================================================
print("\n[STEP 8] Saving working key details...")

try:
    working_key_details = {}
    for key_id, key_info in created_keys.items():
        working_key_details[key_id] = {
            'arn': key_info['arn'],
            'kcv': key_info['kcv'],
            'export_kcv': exported_keys[key_id]['kcv'],
            'as2805_variant': key_info['config']['as2805_variant'],
            'key_usage': key_info['config']['key_usage'],
            'keystore_alias': f"apc_{key_id}",
        }

    details_file = output_dir / "working_key_details.json"
    with open(details_file, 'w') as f:
        json.dump(working_key_details, f, indent=2)

    print(f"✓ Working key details saved to: {details_file.name}")

except Exception as e:
    print(f"✗ Error saving details: {e}")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("WORKING KEY EXCHANGE COMPLETE - Summary")
print("=" * 70)

print(f"\nNode 2 (AWS Payment Cryptography):")
print(f"  KEK(s) ARN: {keks_arn}")
print(f"  KEK(s) KCV: {keks_kcv}")

print(f"\nWorking Keys Created and Exchanged:")
for key_id, key_info in created_keys.items():
    key_config = key_info['config']
    export_kcv = exported_keys[key_id]['kcv']
    print(f"\n  {key_config['name']}:")
    print(f"    ARN: {key_info['arn']}")
    print(f"    KCV: {export_kcv}")
    print(f"    AS2805 Variant: {key_config['as2805_variant']}")
    print(f"    Keystore Alias: apc_{key_id}")

print(f"\nNode 1 Keystore:")
print(f"  Location: {keystore_path}")
print(f"  Total Keys: {len(keystore['keys'])}")

print(f"\n✓ All working keys created, exported, unwrapped, and validated")
print(f"✓ ZPK ready for PIN encryption between nodes")
print(f"✓ ZEK ready for data encryption between nodes")
print(f"✓ ZAK ready for MAC generation/verification between nodes")

# ============================================================================
# STEP 9: Node 1 Creates and Exports Working Keys to Node 2 (APC)
# ============================================================================
print("\n" + "=" * 70)
print("STEP 9: Node 1 Creates Working Keys and Wraps for Node 2")
print("=" * 70)
print("\nNode 1 generates its own set of working keys (send keys) and wraps")
print("them under its KEK(s) using AS2805 variant masks for import into APC.")

# Load Node 1's KEK(s) - this is the node1_kek in the keystore
node1_keks_bytes = base64.b64decode(keystore["keys"]["node1_kek"]["key"])
print(f"\n  Node 1 KEK(s) loaded: {len(node1_keks_bytes)} bytes")

# Load Node 2's KEK(r) ARN (the Node 1 KEK imported into APC)
kekr_details_file = output_dir / "imported_kek_details.json"
if not kekr_details_file.exists():
    print(f"✗ Imported KEK details not found: {kekr_details_file}")
    print("  Please run as2805_1_4 first!")
    sys.exit(1)

with open(kekr_details_file, 'r') as f:
    kekr_details = json.load(f)
node2_kekr_arn = kekr_details['arn']
print(f"  Node 2 KEK(r) ARN: {node2_kekr_arn}")

# Generate working keys locally on Node 1
node1_working_keys = {}

for key_id, key_config in WORKING_KEYS.items():
    print(f"\n  Generating Node 1 {key_config['name']}...")

    # Generate a random 2-key TDES key (16 bytes)
    wk_bytes = os.urandom(16)

    # Compute KCV
    kcv_cipher = Cipher(
        TripleDES(wk_bytes),
        modes.ECB(),
        backend=default_backend()
    )
    kcv_enc = kcv_cipher.encryptor()
    wk_kcv = (kcv_enc.update(b'\x00' * 8) + kcv_enc.finalize())[:3].hex().upper()

    node1_working_keys[key_id] = {
        'key': wk_bytes,
        'kcv': wk_kcv,
        'config': key_config,
    }

    print(f"  ✓ {key_config['name']} generated")
    print(f"    Length: {len(wk_bytes)} bytes")
    print(f"    KCV: {wk_kcv}")

# ============================================================================
# STEP 10: Wrap Node 2 Working Keys Under KEK(s) with Variant Masks
# ============================================================================
print("\n" + "=" * 70)
print("STEP 10: Wrap Node 1 Working Keys for Import into APC")
print("=" * 70)

node1_wrapped_keys = {}

for key_id, wk_info in node1_working_keys.items():
    key_config = wk_info['config']
    variant_name = key_config['as2805_variant']
    variant_mask = AS2805_VARIANT_MASKS[variant_name]

    print(f"\n  Wrapping {key_config['name']}...")
    print(f"    Variant: {variant_name}")

    # Apply variant mask to Node 1's KEK(s)
    kek_variant = bytes(a ^ b for a, b in zip(node1_keks_bytes, variant_mask))

    # Encrypt working key using 3DES-CBC with zero IV
    cipher = Cipher(
        TripleDES(kek_variant),
        modes.CBC(b'\x00' * 8),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    wrapped_hex = (encryptor.update(wk_info['key']) + encryptor.finalize()).hex().upper()

    node1_wrapped_keys[key_id] = wrapped_hex
    print(f"  ✓ Wrapped: {wrapped_hex}")

# ============================================================================
# STEP 11: Import Node 2 Working Keys into APC
# ============================================================================
print("\n" + "=" * 70)
print("STEP 11: Import Node 1 Working Keys into APC")
print("=" * 70)

imported_keys = {}

for key_id, wrapped_hex in node1_wrapped_keys.items():
    key_config = node1_working_keys[key_id]['config']
    expected_kcv = node1_working_keys[key_id]['kcv']

    print(f"\n  Importing {key_config['name']}...")

    try:
        import_response = control_client.import_key(
            KeyMaterial={
                'As2805KeyCryptogram': {
                    'WrappingKeyIdentifier': node2_kekr_arn,
                    'As2805KeyVariant': key_config['as2805_variant'],
                    'Exportable': True,
                    'KeyAlgorithm': 'TDES_2KEY',
                    'KeyModesOfUse': key_config['modes_of_use'],
                    'WrappedKeyCryptogram': wrapped_hex,
                }
            },
            KeyCheckValueAlgorithm='ANSI_X9_24',
            Enabled=True,
            Tags=[
                {'Key': 'Name', 'Value': f"Node1-{key_config['tag_name']}"},
                {'Key': 'Purpose', 'Value': 'AS2805-Working-Key-Node1'}
            ]
        )

        imported_arn = import_response['Key']['KeyArn']
        imported_kcv = import_response['Key']['KeyCheckValue']

        print(f"  ✓ {key_config['name']} imported into APC")
        print(f"    ARN: {imported_arn}")
        print(f"    APC KCV:      {imported_kcv}")
        print(f"    Expected KCV: {expected_kcv}")

        if imported_kcv == expected_kcv:
            print(f"    ✓ KCV MATCH")
        else:
            print(f"    ✗ KCV MISMATCH")

        imported_keys[key_id] = {
            'arn': imported_arn,
            'kcv': imported_kcv,
        }

    except ClientError as e:
        print(f"  ✗ Error importing {key_config['name']}: {e.response['Error']['Message']}")
        sys.exit(1)

print(f"\n✓ All {len(imported_keys)} Node 1 working keys imported into APC")

# ============================================================================
# STEP 12: Store Node 2 Working Keys in Keystore
# ============================================================================
print("\n" + "=" * 70)
print("STEP 12: Store Node 1 Working Keys in Keystore")
print("=" * 70)

try:
    for key_id, wk_info in node1_working_keys.items():
        key_config = wk_info['config']
        keystore_alias = f"node1_{key_id}"
        keystore["keys"][keystore_alias] = {
            "type": "secret",
            "algorithm": "3DES",
            "key": base64.b64encode(wk_info['key']).decode('utf-8'),
            "length": len(wk_info['key']),
            "source": "Node1-Generated",
            "check_value": wk_info['kcv'],
            "as2805_key_type": key_id.upper(),
            "as2805_variant": key_config['as2805_variant']
        }
        print(f"  ✓ Stored {key_config['name']} as '{keystore_alias}'")

    # Re-encrypt and save keystore
    keystore_json = json.dumps(keystore, indent=2)
    encrypted_keystore = fernet.encrypt(keystore_json.encode())
    with open(keystore_path, 'wb') as f:
        f.write(encrypted_keystore)

    print(f"\n✓ Keystore saved")
    print(f"  Total keys: {len(keystore['keys'])}")

except Exception as e:
    print(f"✗ Error storing keys: {e}")
    sys.exit(1)

# Save Node 1 imported key details for use by subsequent modules
try:
    node1_imported_details = {}
    for key_id, imp_info in imported_keys.items():
        node1_imported_details[key_id] = {
            'arn': imp_info['arn'],
            'kcv': imp_info['kcv'],
            'as2805_variant': node1_working_keys[key_id]['config']['as2805_variant'],
            'key_usage': node1_working_keys[key_id]['config']['key_usage'],
            'keystore_alias': f"node1_{key_id}",
        }

    node1_details_file = output_dir / "node1_imported_key_details.json"
    with open(node1_details_file, 'w') as f:
        json.dump(node1_imported_details, f, indent=2)
    print(f"\n✓ Node 1 imported key details saved to: {node1_details_file.name}")
except Exception as e:
    print(f"✗ Error saving Node 1 key details: {e}")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("WORKING KEY EXCHANGE COMPLETE - Summary")
print("=" * 70)

print(f"\n--- Node 2 → Node 1 (APC exports, Node 1 receives) ---")
for key_id, key_info in created_keys.items():
    key_config = key_info['config']
    export_kcv = exported_keys[key_id]['kcv']
    print(f"  {key_config['name']}: ARN={key_info['arn']}, KCV={export_kcv}")

print(f"\n--- Node 1 → Node 2 (Node 1 exports, APC imports) ---")
for key_id, imp_info in imported_keys.items():
    key_config = node1_working_keys[key_id]['config']
    print(f"  {key_config['name']}: ARN={imp_info['arn']}, KCV={imp_info['kcv']}")

print(f"\n✓ Bidirectional working key exchange complete")
print("=" * 70)
