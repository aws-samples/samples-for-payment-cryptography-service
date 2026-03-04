"""
Complete KEK and Keystore Setup for Both Nodes

This script combines the functionality of:
- Mod_1_1: Node1 creates KEK and wrapping key pair, exports public key
- Mod_1_2: AWS Payment Cryptography creates KEK, imports Node1's certificate, exports wrapped KEK
- Mod_1_3: Node1 imports the wrapped KEK from AWS Payment Cryptography

The complete workflow:
1. Node1: Create local keystore with password protection
2. Node1: Generate 3DES KEK for local use
3. Node1: Generate RSA wrapping key pair with X.509 certificate
4. Node1: Export public key and certificate to files
5. AWS: Create 3DES KEK in AWS Payment Cryptography
6. AWS: Import Node1's certificate as root CA
7. AWS: Export (wrap) the AWS KEK using Node1's public key
8. Node1: Import and unwrap the AWS KEK into local keystore

This provides both nodes with their own KEKs and Node1 with the AWS KEK.
"""

import json
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_der_private_key
import pathlib
import keystore_helper
import os
import base64
import binascii
import datetime
import sys

script_dir = pathlib.Path(__file__).parent
output_dir = script_dir / "output"
output_dir.mkdir(exist_ok=True)

print("=" * 70)
print("Complete KEK and Keystore Setup for Both Nodes")
print("=" * 70)
print("\nThis script will:")
print("  1. Create Node1 keystore with KEK and wrapping key")
print("  2. Create AWS Payment Cryptography KEK")
print("  3. Exchange KEKs between Node1 and AWS")
print("=" * 70)

# ============================================================================
# STEP 1: NODE1 KEYSTORE AND KEY GENERATION
# ============================================================================
print("\n" + "=" * 70)
print("STEP 1: Node1 Keystore and Key Generation")
print("=" * 70)

keystore_path = output_dir / "node1_keystore.json"
keystore_service = "node1_keystore"
keystore_username = "workshop_user"

# ============================================================================
# STEP 1.1: Setup Keystore Password
# ============================================================================
print("\n[STEP 1.1] Setting up keystore password...")

try:
    keystore_password = keystore_helper.get_or_prompt_password(keystore_service, keystore_username)
except Exception as e:
    print(f"✗ Error accessing keystore password: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1.2: Derive Encryption Key
# ============================================================================
print("\n[STEP 1.2] Deriving encryption key from password...")

try:
    salt = b'node1_keystore_salt_v1'  # Fixed salt for deterministic key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    encryption_key = base64.urlsafe_b64encode(kdf.derive(keystore_password.encode()))
    fernet = Fernet(encryption_key)
    print("✓ Encryption key derived successfully")
except Exception as e:
    print(f"✗ Error deriving encryption key: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1.3: Initialize or Load Keystore
# ============================================================================
print("\n[STEP 1.3] Initializing keystore...")

try:
    if os.path.exists(keystore_path):
        with open(keystore_path, 'rb') as f:
            encrypted_data = f.read()
            decrypted_data = fernet.decrypt(encrypted_data)
            keystore = json.loads(decrypted_data.decode())
        print(f"✓ Loaded existing keystore from {keystore_path.name}")
        print(f"  Existing keys: {len(keystore['keys'])}")
    else:
        # Create new empty keystore
        keystore = {"keys": {}}
        print(f"✓ Created new keystore")
except Exception as e:
    print(f"✗ Error loading keystore: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1.4: Create 3DES KEK for Node1
# ============================================================================
print("\n[STEP 1.4] Creating 3DES KEK for Node1...")

try:
    # Generate a 2-key 3DES key (128 bits / 16 bytes for DEA-3)
    # TR31_K0_KEY_ENCRYPTION_KEY uses 2-key TDES per AS2805 standard
    kek_bytes = os.urandom(16)  # 16 bytes = 128 bits for 2-key 3DES

    # Verify the key is valid for 3DES
    TripleDES(kek_bytes)

    # Store the KEK in the keystore as base64-encoded string
    kek_alias = "node1_kek"
    keystore["keys"][kek_alias] = {
        "type": "secret",
        "algorithm": "3DES",
        "key": base64.b64encode(kek_bytes).decode('utf-8'),
        "length": len(kek_bytes)
    }

    print(f"✓ Created 3DES KEK with alias '{kek_alias}'")
    print(f"  Length: {len(kek_bytes)} bytes ({len(kek_bytes) * 8} bits)")
    print(f"  Compatible with: TR31_K0_KEY_ENCRYPTION_KEY")
except Exception as e:
    print(f"✗ Error creating 3DES KEK: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1.5: Create RSA Wrapping Key Pair
# ============================================================================
print("\n[STEP 1.5] Creating RSA wrapping key pair...")

try:
    # Generate RSA key pair (2048-bit is standard for key wrapping)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    print(f"✓ Generated RSA key pair (2048 bits)")
except Exception as e:
    print(f"✗ Error creating RSA key pair: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1.6: Create X.509 Certificate
# ============================================================================
print("\n[STEP 1.6] Creating X.509 certificate for wrapping key...")

try:
    # Create a self-signed X.509 certificate for the wrapping key
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "WA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Seattle"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Node1"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Node1 Wrapping Key"),
    ])

    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Certificate valid for 10 years
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        # Mark as CA certificate (required for root certificates)
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        # Key usage for digital signatures
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,  # Can sign other certificates (CA capability)
            crl_sign=True,       # Can sign CRLs (CA capability)
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("node1.local"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    print(f"✓ Created X.509 certificate")
    print(f"  Subject: {certificate.subject.rfc4514_string()}")
    print(f"  Valid: {certificate.not_valid_before_utc} to {certificate.not_valid_after_utc}")
except Exception as e:
    print(f"✗ Error creating certificate: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1.7: Store Wrapping Key in Keystore
# ============================================================================
print("\n[STEP 1.7] Storing wrapping key in keystore...")

try:
    wrapping_key_alias = "node1_wrapping_key"
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Store certificate in DER format
    certificate_bytes = certificate.public_bytes(serialization.Encoding.DER)

    # Store as base64-encoded string
    keystore["keys"][wrapping_key_alias] = {
        "type": "private",
        "algorithm": "RSA",
        "key": base64.b64encode(private_key_bytes).decode('utf-8'),
        "certificate": base64.b64encode(certificate_bytes).decode('utf-8'),
        "key_size": 2048,
        "format": "PKCS8"
    }

    print(f"✓ Stored wrapping key with alias '{wrapping_key_alias}'")
except Exception as e:
    print(f"✗ Error storing wrapping key: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1.8: Save Keystore to Disk
# ============================================================================
print("\n[STEP 1.8] Saving keystore to disk...")

try:
    keystore_json = json.dumps(keystore, indent=2)
    encrypted_keystore = fernet.encrypt(keystore_json.encode())
    with open(keystore_path, 'wb') as f:
        f.write(encrypted_keystore)
    print(f"✓ Keystore saved to: {keystore_path.name}")
    print(f"  Total keys: {len(keystore['keys'])}")
except Exception as e:
    print(f"✗ Error saving keystore: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1.9: Export Public Key and Certificate
# ============================================================================
print("\n[STEP 1.9] Exporting public key and certificate...")

try:
    # Export public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_key_file = output_dir / "node1_wrapping_key_public.pem"
    with open(public_key_file, 'wb') as f:
        f.write(public_key_pem)
    print(f"✓ Exported public key to: {public_key_file.name}")

    # Export certificate in PEM format
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    certificate_file = output_dir / "node1_wrapping_key_certificate.pem"
    with open(certificate_file, 'wb') as f:
        f.write(certificate_pem)
    print(f"✓ Exported certificate (PEM) to: {certificate_file.name}")
except Exception as e:
    print(f"✗ Error exporting keys: {e}")
    sys.exit(1)

# ============================================================================
# STEP 2: AWS PAYMENT CRYPTOGRAPHY SETUP
# ============================================================================
print("\n" + "=" * 70)
print("STEP 2: AWS Payment Cryptography Setup")
print("=" * 70)

# ============================================================================
# STEP 2.1: Check AWS Credentials
# ============================================================================
print("\n[STEP 2.1] Checking AWS credentials and permissions...")

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

    # Verify credentials work
    sts_client = boto3.client('sts')
    identity = sts_client.get_caller_identity()

    print(f"✓ Credentials verified")
    print(f"  Account: {identity['Account']}")
    print(f"  User/Role: {identity['Arn'].split('/')[-1]}")

    # Check region
    region = session.region_name or 'ap-southeast-2'
    print(f"✓ Region: {region}")

    # Initialize AWS Payment Cryptography client
    control_client = boto3.client('payment-cryptography', region_name=region)

    # Test permissions
    try:
        control_client.list_keys(MaxResults=1)
        print(f"✓ AWS Payment Cryptography access verified")
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException':
            print(f"\n✗ Access Denied to AWS Payment Cryptography")
            print(f"  Required permissions:")
            print(f"    - payment-cryptography:CreateKey")
            print(f"    - payment-cryptography:ImportKey")
            print(f"    - payment-cryptography:ExportKey")
            print(f"    - payment-cryptography:GetKey")
            sys.exit(1)
        raise

except (NoCredentialsError, PartialCredentialsError):
    print("✗ AWS credentials not configured properly!")
    sys.exit(1)
except ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code in ['InvalidClientTokenId', 'SignatureDoesNotMatch', 'ExpiredToken']:
        print(f"✗ Invalid or expired AWS credentials!")
    else:
        print(f"✗ Error verifying credentials: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Unexpected error: {e}")
    sys.exit(1)

# ============================================================================
# STEP 2.2: Create KEK in AWS Payment Cryptography
# ============================================================================
print("\n[STEP 2.2] Creating 3DES KEK in AWS Payment Cryptography...")

try:
    create_key_response = control_client.create_key(
        KeyAttributes={
            'KeyAlgorithm': 'TDES_2KEY',
            'KeyClass': 'SYMMETRIC_KEY',
            'KeyUsage': 'TR31_K0_KEY_ENCRYPTION_KEY',
            'KeyModesOfUse': {
                'Wrap': True,
                'Unwrap': True,
                'Encrypt': True,
                'Decrypt': True,
                'Generate': False,
                'Sign': False,
                'Verify': False,
                'DeriveKey': False,
                'NoRestrictions': False
            }
        },
        Exportable=True,  # MUST be True to export later
        Enabled=True,
        Tags=[
            {'Key': 'Name', 'Value': 'APC-Generated-KEK'},
            {'Key': 'Purpose', 'Value': 'Export-to-Node1'}
        ]
    )

    kek_arn = create_key_response['Key']['KeyArn']
    kek_check_value = create_key_response['Key']['KeyCheckValue']

    print(f"✓ KEK created successfully!")
    print(f"  ARN: {kek_arn}")
    print(f"  Check Value: {kek_check_value}")

    # Save KEK details
    kek_details = {
        'arn': kek_arn,
        'check_value': kek_check_value
    }
    with open(output_dir / "apc_created_kek.json", 'w') as f:
        json.dump(kek_details, f, indent=2)

except ClientError as e:
    print(f"✗ AWS API Error: {e.response['Error']['Message']}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error creating KEK: {e}")
    sys.exit(1)

# ============================================================================
# STEP 2.3: Import Node1's Certificate as Root CA
# ============================================================================
print("\n[STEP 2.3] Importing Node1's certificate as Root CA...")

try:
    # Read the certificate file we just created
    with open(certificate_file, 'rb') as f:
        certificate_pem_bytes = f.read()

    print(f"  Certificate loaded: {len(certificate_pem_bytes)} bytes")

    # AWS requires the PEM certificate to be base64 encoded
    certificate_b64_encoded = base64.b64encode(certificate_pem_bytes).decode('UTF-8')

    # Import as a root certificate
    import_response = control_client.import_key(
        KeyMaterial={
            'RootCertificatePublicKey': {
                'KeyAttributes': {
                    'KeyAlgorithm': 'RSA_2048',
                    'KeyClass': 'PUBLIC_KEY',
                    'KeyModesOfUse': {
                        'Verify': True,
                    },
                    'KeyUsage': 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
                },
                'PublicKeyCertificate': certificate_b64_encoded
            }
        },
        Enabled=True,
        Tags=[
            {'Key': 'Name', 'Value': 'Node1-Root-Certificate'},
            {'Key': 'Purpose', 'Value': 'RSA-Wrap-Export'}
        ]
    )

    root_cert_arn = import_response['Key']['KeyArn']
    print(f"✓ Root certificate imported successfully!")
    print(f"  ARN: {root_cert_arn}")

except ClientError as e:
    print(f"✗ AWS API Error: {e.response['Error']['Message']}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error importing certificate: {e}")
    sys.exit(1)

# ============================================================================
# STEP 2.4: Export KEK Wrapped with Node1's Public Key
# ============================================================================
print("\n[STEP 2.4] Exporting KEK wrapped with Node1's public key...")

try:
    certificate_b64_for_export = base64.b64encode(certificate_pem_bytes).decode('UTF-8')

    export_response = control_client.export_key(
        ExportKeyIdentifier=kek_arn,
        KeyMaterial={
            'KeyCryptogram': {
                'CertificateAuthorityPublicKeyIdentifier': root_cert_arn,
                'WrappingKeyCertificate': certificate_b64_for_export,
                'WrappingSpec': 'RSA_OAEP_SHA_256'
            }
        }
    )

    wrapped_key = export_response['WrappedKey']['KeyMaterial']
    key_check_value = export_response['WrappedKey']['KeyCheckValue']

    print(f"✓ KEK exported successfully!")
    print(f"  Check Value: {key_check_value}")
    print(f"  Wrapped Key Length: {len(wrapped_key)} characters")

except ClientError as e:
    print(f"✗ AWS API Error: {e.response['Error']['Message']}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error exporting KEK: {e}")
    sys.exit(1)

# ============================================================================
# STEP 2.5: Save Wrapped KEK to Files
# ============================================================================
print("\n[STEP 2.5] Saving wrapped KEK to files...")

try:
    # Format 1: Hex text file
    wrapped_kek_file = output_dir / "apc_wrapped_kek.txt"
    with open(wrapped_kek_file, 'w') as f:
        f.write(wrapped_key)
    print(f"✓ Saved wrapped KEK (hex) to: {wrapped_kek_file.name}")

    # Format 2: Binary file
    wrapped_kek_bin_file = output_dir / "apc_wrapped_kek.bin"
    with open(wrapped_kek_bin_file, 'wb') as f:
        f.write(base64.b64decode(wrapped_key))
    print(f"✓ Saved wrapped KEK (binary) to: {wrapped_kek_bin_file.name}")

except Exception as e:
    print(f"✗ Error saving wrapped KEK: {e}")
    sys.exit(1)

# ============================================================================
# STEP 3: NODE1 IMPORT AWS KEK
# ============================================================================
print("\n" + "=" * 70)
print("STEP 3: Node1 Import AWS KEK")
print("=" * 70)

# ============================================================================
# STEP 3.1: Load Wrapped KEK
# ============================================================================
print("\n[STEP 3.1] Loading wrapped KEK...")

try:
    # AWS Payment Cryptography returns wrapped keys as hexadecimal strings
    wrapped_key_bytes = binascii.unhexlify(wrapped_key)
    print(f"✓ Loaded wrapped KEK")
    print(f"  Hex length: {len(wrapped_key)} characters")
    print(f"  Binary length: {len(wrapped_key_bytes)} bytes")
except Exception as e:
    print(f"✗ Error loading wrapped KEK: {e}")
    sys.exit(1)

# ============================================================================
# STEP 3.2: Unwrap KEK using Node1's Private Key
# ============================================================================
print("\n[STEP 3.2] Unwrapping KEK using RSA-OAEP...")

try:
    # We already have the private_key in memory from Step 1
    unwrapped_kek = private_key.decrypt(
        wrapped_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print(f"✓ KEK unwrapped successfully!")
    print(f"  KEK Length: {len(unwrapped_kek)} bytes ({len(unwrapped_kek) * 8} bits)")

    # Verify it's a valid 3DES key
    if len(unwrapped_kek) != 16:
        print(f"⚠ Warning: Expected 16 bytes for 2-key 3DES, got {len(unwrapped_kek)}")
    else:
        print(f"✓ KEK length verified (16 bytes for 2-key 3DES)")

except Exception as e:
    print(f"✗ Error unwrapping KEK: {e}")
    sys.exit(1)

# ============================================================================
# STEP 3.3: Store AWS KEK in Node1's Keystore
# ============================================================================
print("\n[STEP 3.3] Storing AWS KEK in Node1's keystore...")

try:
    # Add the imported KEK to keystore
    apc_kek_alias = "apc_imported_kek"
    keystore["keys"][apc_kek_alias] = {
        "type": "secret",
        "algorithm": "3DES",
        "key": base64.b64encode(unwrapped_kek).decode('utf-8'),
        "length": len(unwrapped_kek),
        "source": "AWS Payment Cryptography",
        "check_value": key_check_value,
        "source_arn": kek_arn
    }

    # Re-encrypt and save keystore
    keystore_json = json.dumps(keystore, indent=2)
    encrypted_keystore = fernet.encrypt(keystore_json.encode())
    with open(keystore_path, 'wb') as f:
        f.write(encrypted_keystore)

    print(f"✓ AWS KEK stored in keystore with alias: {apc_kek_alias}")
    print(f"  Total keys in keystore: {len(keystore['keys'])}")

except Exception as e:
    print(f"✗ Error storing KEK: {e}")
    sys.exit(1)

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("SETUP COMPLETE - Summary")
print("=" * 70)

print(f"\nNode1 Keystore: {keystore_path.name}")
print(f"  Location: {keystore_path}")
print(f"  Total Keys: {len(keystore['keys'])}")
print(f"\nKeys in Keystore:")
for key_name, key_info in keystore['keys'].items():
    key_type = key_info['type']
    key_algo = key_info['algorithm']
    if key_type == 'secret':
        print(f"  • {key_name}")
        print(f"      Type: {key_algo} symmetric key")
        print(f"      Length: {key_info['length']} bytes")
        if 'source' in key_info:
            print(f"      Source: {key_info['source']}")
            print(f"      Check Value: {key_info['check_value']}")
    else:
        print(f"  • {key_name}")
        print(f"      Type: {key_algo} {key_type} key")
        print(f"      Key Size: {key_info['key_size']} bits")

print(f"\nAWS Payment Cryptography:")
print(f"  KEK ARN: {kek_arn}")
print(f"  KEK Check Value: {kek_check_value}")
print(f"  Root Certificate ARN: {root_cert_arn}")

print(f"\nExported Files:")
print(f"  • {public_key_file.name} - Node1 public key")
print(f"  • {certificate_file.name} - Node1 certificate (PEM)")
print(f"  • {wrapped_kek_file.name} - Wrapped AWS KEK (hex)")
print(f"  • {wrapped_kek_bin_file.name} - Wrapped AWS KEK (binary)")

print(f"\n✓ Both nodes now have their own KEKs")
print(f"✓ Node1 has imported the AWS KEK")
print(f"✓ Ready for AS2805 key exchange operations")
print("=" * 70)
