"""
Node1: Export KEK for Import into AWS Payment Cryptography

This script demonstrates how to:
1. Load the AWS Payment Cryptography wrapping certificate and import parameters
2. Extract the Node1 KEK from the keystore
3. Wrap the KEK using the AWS wrapping certificate with RSA-OAEP
4. Create an import-ready package for AWS Payment Cryptography
"""

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
import base64
import json
import keystore_helper

script_dir = Path(__file__).parent
output_dir = script_dir / "output"
output_dir.mkdir(exist_ok=True)

print("=" * 70)
print("Node1: Export KEK for Import into AWS Payment Cryptography")
print("=" * 70)

# ============================================================================
# STEP 1: Load AWS Payment Cryptography Import Parameters
# ============================================================================
print("\n[STEP 1] Loading AWS Payment Cryptography import parameters...")

import_params_file = output_dir / "apc_import_parameters.json"

if not import_params_file.exists():
    print(f"✗ Import parameters file not found: {import_params_file}")
    print("  Ensure you have run the previous scripts first!")
    exit(1)

try:
    with open(import_params_file, 'r') as f:
        import_params = json.load(f)

    import_token = import_params['import_token']
    wrapping_key_cert_b64 = import_params['wrapping_key_certificate']
    parameters_valid_until = import_params['parameters_valid_until']
    wrapping_spec = import_params['wrapping_spec']

    print(f"✓ Import parameters loaded successfully!")
    print(f"  Import Token: [REDACTED - {len(import_token)} chars]")
    print(f"  Wrapping Certificate Length: {len(wrapping_key_cert_b64)} characters")
    print(f"  Parameters Valid Until: {parameters_valid_until}")
    print(f"  Wrapping Spec: {wrapping_spec}")

except Exception as e:
    print(f"✗ Error loading import parameters: {e}")
    raise

# ============================================================================
# STEP 2: Load and Parse AWS Wrapping Certificate
# ============================================================================
print("\n[STEP 2] Loading AWS wrapping certificate...")

try:
    # Decode the base64-encoded certificate to get PEM format
    cert_pem_bytes = base64.b64decode(wrapping_key_cert_b64)

    # Parse the X.509 certificate
    aws_certificate = x509.load_pem_x509_certificate(cert_pem_bytes)

    # Extract the public key from the certificate
    aws_public_key = aws_certificate.public_key()

    print(f"✓ AWS wrapping certificate loaded and parsed!")
    print(f"  Subject: {aws_certificate.subject.rfc4514_string()}")
    print(f"  Issuer: {aws_certificate.issuer.rfc4514_string()}")
    print(f"  Valid From: {aws_certificate.not_valid_before_utc}")
    print(f"  Valid Until: {aws_certificate.not_valid_after_utc}")
    print(f"  Public Key Type: RSA")
    print(f"  Key Size: {aws_public_key.key_size} bits")

except Exception as e:
    print(f"✗ Error loading AWS certificate: {e}")
    raise

# ============================================================================
# STEP 3: Load Node1 KEK from Keystore
# ============================================================================
print("\n[STEP 3] Loading Node1 KEK from keystore...")

keystore_path = output_dir / "node1_keystore.json"

if not keystore_path.exists():
    print(f"✗ Keystore not found: {keystore_path}")
    print("  Please run as2805_1_1_KEK_and_keystore_setup_both_nodes.py first!")
    exit(1)

try:
    # Get keystore password
    keystore_password = keystore_helper.get_or_prompt_password("node1_keystore", "workshop_user")

    # Decrypt keystore
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

    # Extract the Node1 KEK
    kek_alias = "node1_kek"

    if kek_alias not in keystore["keys"]:
        print(f"✗ KEK not found in keystore with alias: {kek_alias}")
        print(f"  Available keys: {', '.join(keystore['keys'].keys())}")
        exit(1)

    kek_info = keystore["keys"][kek_alias]
    kek_bytes = base64.b64decode(kek_info["key"])

    print(f"✓ Node1 KEK loaded from keystore!")
    print(f"  Alias: {kek_alias}")
    print(f"  Algorithm: {kek_info['algorithm']}")
    print(f"  Length: {len(kek_bytes)} bytes ({len(kek_bytes) * 8} bits)")

    # Verify it's a valid 3DES key
    if len(kek_bytes) != 16:
        print(f"⚠ Warning: Expected 16 bytes for 2-key 3DES, got {len(kek_bytes)}")
    else:
        print(f"✓ KEK length verified (16 bytes for 2-key 3DES)")

except Exception as e:
    print(f"✗ Error loading KEK from keystore: {e}")
    raise

# ============================================================================
# STEP 4: Wrap KEK using AWS Public Key with RSA-OAEP
# ============================================================================
print("\n[STEP 4] Wrapping KEK using AWS public key with RSA-OAEP-SHA-256...")

try:
    # Wrap the KEK using RSA-OAEP with SHA-256
    # This matches the WrappingSpec: RSA_OAEP_SHA_256
    wrapped_kek_bytes = aws_public_key.encrypt(
        kek_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Convert to hexadecimal for AWS Payment Cryptography API
    # AWS expects WrappedKeyCryptogram as hex string (pattern: [0-9A-F]+)
    wrapped_kek_hex = wrapped_kek_bytes.hex().upper()

    print(f"✓ KEK wrapped successfully!")
    print(f"  Wrapped KEK Length (binary): {len(wrapped_kek_bytes)} bytes")
    print(f"  Wrapped KEK Length (hex): {len(wrapped_kek_hex)} characters")
    print(f"  Wrapping Algorithm: RSA-OAEP-SHA-256")

except Exception as e:
    print(f"✗ Error wrapping KEK: {e}")
    raise

# ============================================================================
# STEP 5: Save Wrapped KEK to File
# ============================================================================
print("\n[STEP 5] Saving wrapped KEK to file...")

try:
    # Save the hex-encoded wrapped KEK (required format for AWS)
    wrapped_kek_file = output_dir / "node1_kek_wrapped_for_apc.txt"
    with open(wrapped_kek_file, 'w') as f:
        f.write(wrapped_kek_hex)

    print(f"✓ Wrapped KEK (hex) saved to: {wrapped_kek_file.name}")

    # Also save as binary for reference
    wrapped_kek_bin_file = output_dir / "node1_kek_wrapped_for_apc.bin"
    with open(wrapped_kek_bin_file, 'wb') as f:
        f.write(wrapped_kek_bytes)

    print(f"✓ Wrapped KEK (binary) saved to: {wrapped_kek_bin_file.name}")

except Exception as e:
    print(f"✗ Error saving wrapped KEK: {e}")
    raise

# ============================================================================
# STEP 6: Create Import Package for AWS Payment Cryptography
# ============================================================================
print("\n[STEP 6] Creating import package for AWS Payment Cryptography...")

try:
    # Create the complete import package structure
    # This matches the structure expected by the ImportKey API
    # Note: WrappedKeyCryptogram must be hex string (pattern: [0-9A-F]+)
    import_package = {
        'KeyMaterial': {
            'KeyCryptogram': {
                'Exportable': True,
                'WrappedKeyCryptogram': wrapped_kek_hex,
                'ImportToken': import_token,
                'WrappingSpec': wrapping_spec,
                'KeyAttributes': {
                    'KeyAlgorithm': 'TDES_2KEY',
                    'KeyClass': 'SYMMETRIC_KEY',
                    'KeyUsage': 'TR31_K0_KEY_ENCRYPTION_KEY',
                    'KeyModesOfUse': {
                        'Encrypt': True,
                        'Decrypt': True,
                        'Wrap': True,
                        'Unwrap': True,
                        'Generate': False,
                        'Sign': False,
                        'Verify': False,
                        'DeriveKey': False,
                        'NoRestrictions': False
                    }
                }
            }
        },
        'KeyCheckValueAlgorithm': 'CMAC',
        'Enabled': True,
        'Tags': [
            {'Key': 'Name', 'Value': 'Node1-KEK-Imported'},
            {'Key': 'Purpose', 'Value': 'AS2805-KEK'},
            {'Key': 'Source', 'Value': 'Node1-Keystore'}
        ]
    }

    # Save the import package
    import_package_file = output_dir / "node1_kek_import_package.json"
    with open(import_package_file, 'w') as f:
        json.dump(import_package, f, indent=2)

    print(f"✓ Import package created!")
    print(f"  Saved to: {import_package_file.name}")

    # Also create a redacted version for logging/reference
    import_package_redacted = json.loads(json.dumps(import_package))
    import_package_redacted['KeyMaterial']['KeyCryptogram']['WrappedKeyCryptogram'] = '[REDACTED]'
    import_package_redacted['KeyMaterial']['KeyCryptogram']['ImportToken'] = '[REDACTED]'

    import_package_redacted_file = output_dir / "node1_kek_import_package_redacted.json"
    with open(import_package_redacted_file, 'w') as f:
        json.dump(import_package_redacted, f, indent=2)

    print(f"✓ Redacted import package saved to: {import_package_redacted_file.name}")

except Exception as e:
    print(f"✗ Error creating import package: {e}")
    raise

# ============================================================================
# STEP 7: Create Metadata File
# ============================================================================
print("\n[STEP 7] Creating metadata file...")

try:
    metadata = {
        'source_kek_alias': kek_alias,
        'source_keystore': str(keystore_path),
        'kek_algorithm': kek_info['algorithm'],
        'kek_length_bytes': len(kek_bytes),
        'kek_length_bits': len(kek_bytes) * 8,
        'wrapping_algorithm': wrapping_spec,
        'wrapped_kek_file': wrapped_kek_file.name,
        'import_package_file': import_package_file.name,
        'parameters_valid_until': parameters_valid_until,
        'aws_certificate_subject': aws_certificate.subject.rfc4514_string(),
        'aws_certificate_key_size': aws_public_key.key_size
    }

    metadata_file = output_dir / "node1_kek_export_metadata.json"
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"✓ Metadata saved to: {metadata_file.name}")

except Exception as e:
    print(f"✗ Error creating metadata: {e}")
    raise

# ============================================================================
# STEP 8: Summary
# ============================================================================
print("\n" + "=" * 70)
print("EXPORT COMPLETE - Summary")
print("=" * 70)
print(f"\nNode1 KEK Details:")
print(f"  Alias: {kek_alias}")
print(f"  Algorithm: {kek_info['algorithm']}")
print(f"  Length: {len(kek_bytes)} bytes ({len(kek_bytes) * 8} bits)")
print(f"\nWrapping Details:")
print(f"  Algorithm: {wrapping_spec}")
print(f"  AWS Certificate Key Size: {aws_public_key.key_size} bits")
print(f"  Wrapped KEK Length: {len(wrapped_kek_bytes)} bytes")
print(f"\nGenerated Files:")
print(f"  1. {wrapped_kek_file.name} - Base64 wrapped KEK")
print(f"  2. {wrapped_kek_bin_file.name} - Binary wrapped KEK")
print(f"  3. {import_package_file.name} - Complete import package")
print(f"  4. {import_package_redacted_file.name} - Redacted package (for reference)")
print(f"  5. {metadata_file.name} - Export metadata")
print(f"\nNext Steps:")
print(f"  • Use the import package with AWS Payment Cryptography ImportKey API")
print(f"  • The wrapped KEK is ready to be imported into APC")
print(f"  • Import parameters are valid until: {parameters_valid_until}")
print("=" * 70)
