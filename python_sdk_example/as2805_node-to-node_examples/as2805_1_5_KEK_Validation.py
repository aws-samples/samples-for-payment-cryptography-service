"""
AS2805 KEK Validation

This script demonstrates the AS2805 KEK validation process between two nodes.
Node 1 is the local software HSM (simulated locally).
Node 2 (the "sending" node) uses AWS Payment Cryptography.

Key Mapping:
  Node 2's KEKs = apc_imported_kek in keystore (KCV: 054277) = AWS Created KEK
  Node 2's KEKr = node1_kek in keystore (KCV: 6D9005) = AWS Imported KEK

Validation Process:
1. Node 2 calls GenerateAs2805KekValidation API with its KEKs
2. API returns RandomKeySend (encrypted with request variant of KEKs)
   and RandomKeyReceive (encrypted with response variant of KEKr)
3. Node 2 stores RandomKeyReceive and sends RandomKeySend to Node 1
4. Node 1 decrypts RandomKeySend using request variant (0x82) of its KEK
5. Node 1 computes ~RNDs (bitwise NOT with parity adjustment)
6. Node 1 encrypts ~RNDs using response variant (0x84) of its KEK
7. Node 1 sends the result back to Node 2
8. Node 2 compares the received value with stored RandomKeyReceive

AS2805 Algorithm Details:
  - Variant masks are 16-byte constants (0x82... for request, 0x84... for response)
  - Encryption uses 3DES CBC mode with zero IV
  - "Inversion" is bitwise NOT with odd parity adjustment per byte
  - The SAME KEK is used for both decrypt and encrypt, with different variant masks
"""

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import json
import os
import sys
import keystore_helper

script_dir = Path(__file__).parent
output_dir = script_dir / "output"
output_dir.mkdir(exist_ok=True)

print("=" * 70)
print("AS2805 KEK Validation")
print("=" * 70)
print("\nThis script demonstrates KEK validation between Node 2 (AWS) and Node 1")
print("=" * 70)

# ============================================================================
# STEP 1: Load KEKs ARN from as2805_1_1
# ============================================================================
print("\n[STEP 1] Loading KEKs ARN from as2805_1_1...")

kek_details_file = output_dir / "apc_created_kek.json"

if not kek_details_file.exists():
    print(f"✗ KEK details file not found: {kek_details_file}")
    print("  Please run as2805_1_1 first to create the AWS KEK!")
    sys.exit(1)

try:
    with open(kek_details_file, 'r') as f:
        kek_details = json.load(f)

    selected_kek_arn = kek_details['arn']
    kek_check_value_from_file = kek_details['check_value']

    print(f"✓ Loaded KEKs ARN from {kek_details_file.name}")
    print(f"  ARN: {selected_kek_arn}")
    print(f"  Check Value: {kek_check_value_from_file}")

except Exception as e:
    print(f"✗ Error loading KEK details: {e}")
    sys.exit(1)

# Initialize AWS Payment Cryptography clients
print("\nChecking AWS credentials and permissions...")

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

    # Verify the key exists and get its details
    print(f"\nVerifying KEK exists in AWS Payment Cryptography...")
    key_details = control_client.get_key(KeyIdentifier=selected_kek_arn)
    key_info = key_details['Key']

    key_state = key_info['KeyState']
    key_origin = key_info.get('KeyOrigin', 'UNKNOWN')
    key_usage = key_info['KeyAttributes']['KeyUsage']
    key_algorithm = key_info['KeyAttributes']['KeyAlgorithm']

    print(f"✓ KEK verified:")
    print(f"  State: {key_state}")
    print(f"  Origin: {key_origin}")
    print(f"  Usage: {key_usage}")
    print(f"  Algorithm: {key_algorithm}")

    # Verify this is the AWS-created key (not imported)
    if key_origin != 'AWS_PAYMENT_CRYPTOGRAPHY':
        print(f"\n⚠ Warning: Key origin is '{key_origin}', expected 'AWS_PAYMENT_CRYPTOGRAPHY'")
        print(f"  This key may not be the correct KEKs for validation.")
        print(f"  KEKs should be the key created in AWS, not imported from external source.")

    if key_state != 'CREATE_COMPLETE':
        print(f"\n✗ Key state is '{key_state}', expected 'CREATE_COMPLETE'")
        print(f"  The key may not be ready for use.")
        sys.exit(1)

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
# STEP 2: Call GenerateAs2805KekValidation API
# ============================================================================
print("\n[STEP 2] Calling GenerateAs2805KekValidation API...")
print("  Using KEKs to generate validation request")

try:
    # Call the API with the selected KEK
    validation_request = data_client.generate_as2805_kek_validation(
        KekValidationType={
            'KekValidationRequest': {
                'DeriveKeyAlgorithm': 'TDES_2KEY'
            }
        },
        RandomKeySendVariantMask='VARIANT_MASK_82',
        KeyIdentifier=selected_kek_arn
    )

    # Extract the values
    random_key_send = validation_request['RandomKeySend']
    random_key_receive = validation_request['RandomKeyReceive']
    key_check_value = validation_request['KeyCheckValue']

    print(f"\n✓ GenerateAs2805KekValidation API call successful!")
    print(f"  Key ARN: {validation_request['KeyArn']}")
    print(f"  Key Check Value: {validation_request['KeyCheckValue']}")
    print(f"\n  RandomKeySend (to send to Node 1): {random_key_send}")
    print(f"  RandomKeyReceive (stored for comparison): {random_key_receive}")

    # Store the check value from the API response
    key_check_value = validation_request['KeyCheckValue']

    # Store RandomKeyReceive for later comparison
    node2_stored_krr = random_key_receive

except ClientError as e:
    print(f"✗ AWS API Error: {e.response['Error']['Message']}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)

# ============================================================================
# STEP 3: Simulate Node 1 Processing
# ============================================================================
print("\n" + "=" * 70)
print("NODE 1 PROCESSING (Simulated)")
print("=" * 70)

print("\n[STEP 3] Node 1 receives RandomKeySend and processes it...")
print(f"  Received from Node 2: {random_key_send}")

# Load Node 2's KEKr (which is the APC imported KEK in the keystore)
keystore_path = output_dir / "node1_keystore.json"

if not keystore_path.exists():
    print(f"\n✗ Keystore not found: {keystore_path}")
    print("  Please run as2805_1_1 first to create the keystore!")
    sys.exit(1)

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

    # Node 2's KEKs (AWS created) = apc_imported_kek in keystore
    # Node 2's KEKr (AWS imported) = node1_kek in keystore
    #
    # When simulating Node 1:
    # Node 1 uses the SAME key (apc_imported_kek) for both decrypt and encrypt,
    # but with DIFFERENT variant masks applied:
    #   - Request variant (0x82) for decrypting RandomKeySend
    #   - Response variant (0x84) for encrypting the response
    if "apc_imported_kek" in keystore["keys"]:
        kek_alias = "apc_imported_kek"
    else:
        print("✗ APC imported KEK not found in keystore")
        sys.exit(1)

    kek_info = keystore["keys"][kek_alias]
    node1_kek_bytes = base64.b64decode(kek_info["key"])

    print(f"✓ Node 1 loaded KEK from keystore")
    print(f"  Alias: {kek_alias}")
    print(f"  Length: {len(node1_kek_bytes)} bytes")

except Exception as e:
    print(f"✗ Error loading keystore: {e}")
    sys.exit(1)

# ============================================================================
# STEP 4: Node 1 Decrypts RandomKeySend using KEK with Request Variant
# ============================================================================
print("\n[STEP 4] Node 1 decrypts RandomKeySend using KEK with request variant mask...")

try:
    # AS2805 variant masks (16-byte constants)
    REQUEST_VARIANT_MASK = bytes.fromhex('82828282828282828282828282828282')
    RESPONSE_VARIANT_MASK = bytes.fromhex('84848484848484848484848484848484')

    # For 2-key TDES (16 bytes), masks are already the correct length
    request_mask = REQUEST_VARIANT_MASK
    response_mask = RESPONSE_VARIANT_MASK

    # Apply request variant mask to KEK for decryption
    kek_variant_request = bytes(a ^ b for a, b in zip(node1_kek_bytes, request_mask))

    print(f"  Request variant mask: {request_mask.hex().upper()}")
    print(f"  KEK with request variant: {kek_variant_request.hex().upper()}")

    # Decode hex to bytes
    random_key_send_bytes = bytes.fromhex(random_key_send)

    # Decrypt using 3DES CBC mode with zero IV
    cipher = Cipher(
        TripleDES(kek_variant_request),
        modes.CBC(b'\x00' * 8),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(random_key_send_bytes) + decryptor.finalize()

    print(f"✓ Decrypted RNDs (hex): {plaintext.hex().upper()}")

except Exception as e:
    print(f"✗ Error decrypting: {e}")
    sys.exit(1)

# ============================================================================
# STEP 5: Node 1 Inverts Plaintext and Encrypts with Response Variant
# ============================================================================
print("\n[STEP 5] Node 1 computes ~RNDs and encrypts with response variant mask...")

try:
    # AS2805 "one's complement": bitwise NOT
    rnds_complement = bytes(~b & 0xFF for b in plaintext)

    # Adjust for odd parity on each byte (DES requirement)
    parity_adjusted = bytearray()
    for byte in rnds_complement:
        bit_count = bin(byte).count('1')
        if bit_count % 2 == 0:
            byte ^= 0x01
        parity_adjusted.append(byte)
    rnds_complement = bytes(parity_adjusted)

    print(f"  Original RNDs (hex):       {plaintext.hex().upper()}")
    print(f"  ~RNDs (bitwise NOT + parity): {rnds_complement.hex().upper()}")

    # Apply response variant mask to KEK for encryption
    kek_variant_response = bytes(a ^ b for a, b in zip(node1_kek_bytes, response_mask))

    print(f"\n  Response variant mask: {response_mask.hex().upper()}")
    print(f"  KEK with response variant: {kek_variant_response.hex().upper()}")

    # Encrypt using 3DES CBC mode with zero IV
    cipher = Cipher(
        TripleDES(kek_variant_response),
        modes.CBC(b'\x00' * 8),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(rnds_complement) + encryptor.finalize()

    # Encode to hex (uppercase)
    node1_response = ciphertext.hex().upper()

    print(f"✓ RandomKeyReceive (hex): {node1_response}")
    print(f"\n  Node 1 sends this value back to Node 2: {node1_response}")

except Exception as e:
    print(f"✗ Error encrypting: {e}")
    sys.exit(1)

# ============================================================================
# STEP 6: Node 2 Validates Response
# ============================================================================
print("\n" + "=" * 70)
print("NODE 2 VALIDATION")
print("=" * 70)

print("\n[STEP 6] Node 2 compares received value with stored RandomKeyReceive...")

print(f"\n  Stored RandomKeyReceive:  {node2_stored_krr}")
print(f"  Received from Node 1:     {node1_response}")

# Compare the values
if node1_response == node2_stored_krr:
    print(f"\n✓ ✓ ✓ PASS 1 VALIDATION SUCCESSFUL! ✓ ✓ ✓")
    print(f"\n  The two values MATCH!")
    print(f"  Node 1's KEK is valid from Node 2's perspective.")
    pass1_passed = True
else:
    print(f"\n✗ ✗ ✗ PASS 1 VALIDATION FAILED! ✗ ✗ ✗")
    print(f"\n  The two values DO NOT MATCH!")
    print(f"  There is a problem with the KEK exchange.")
    print(f"  DO NOT proceed with sending session keys.")
    pass1_passed = False

# ============================================================================
# PASS 2: Node 1 Validates Node 2 (AS2805 Section 6.3 - Bidirectional)
# ============================================================================
print("\n" + "=" * 70)
print("PASS 2: NODE 1 VALIDATES NODE 2")
print("=" * 70)
print("\nNode 1 now initiates its own validation to confirm Node 2 holds")
print("the correct KEK. This completes the bidirectional validation")
print("required by AS2805 Section 6.3.")

# ============================================================================
# STEP 7: Node 1 Generates Its Own Validation Request
# ============================================================================
print("\n[STEP 7] Node 1 generates its own RandomKeySend and RandomKeyReceive...")

try:
    # Generate random plaintext (16 bytes for 2-key TDES)
    rnd_length = 16

    node1_rnds = os.urandom(rnd_length)

    # Compute ~RNDs (bitwise NOT with parity adjustment)
    node1_rnds_complement = bytes(~b & 0xFF for b in node1_rnds)
    parity_adjusted = bytearray()
    for byte in node1_rnds_complement:
        bit_count = bin(byte).count('1')
        if bit_count % 2 == 0:
            byte ^= 0x01
        parity_adjusted.append(byte)
    node1_rnds_complement = bytes(parity_adjusted)

    print(f"  RNDs (hex):                    {node1_rnds.hex().upper()}")
    print(f"  ~RNDs (NOT + parity) (hex):    {node1_rnds_complement.hex().upper()}")

    # Encrypt RNDs with request variant → Node 2's RandomKeySend
    cipher_req = Cipher(
        TripleDES(kek_variant_request),
        modes.CBC(b'\x00' * 8),
        backend=default_backend()
    )
    encryptor_req = cipher_req.encryptor()
    node1_random_key_send = (encryptor_req.update(node1_rnds) + encryptor_req.finalize()).hex().upper()

    # Encrypt ~RNDs with response variant → Node 2's RandomKeyReceive (stored for comparison)
    cipher_resp = Cipher(
        TripleDES(kek_variant_response),
        modes.CBC(b'\x00' * 8),
        backend=default_backend()
    )
    encryptor_resp = cipher_resp.encryptor()
    node1_stored_krr = (encryptor_resp.update(node1_rnds_complement) + encryptor_resp.finalize()).hex().upper()

    print(f"\n  Node 1's RandomKeySend:    {node1_random_key_send}")
    print(f"  Node 1's RandomKeyReceive: {node1_stored_krr} (stored for comparison)")
    print(f"\n  Node 1 sends RandomKeySend to Node 2...")

except Exception as e:
    print(f"✗ Error generating Node 1 validation request: {e}")
    sys.exit(1)

# ============================================================================
# STEP 8: Node 2 (APC) Generates Validation Response
# ============================================================================
print("\n[STEP 8] Node 2 (APC) processes Node 1's RandomKeySend...")

try:
    # Call the API with KekValidationResponse, passing Node 1's RandomKeySend
    validation_response = data_client.generate_as2805_kek_validation(
        KekValidationType={
            'KekValidationResponse': {
                'RandomKeySend': node1_random_key_send
            }
        },
        RandomKeySendVariantMask='VARIANT_MASK_82',
        KeyIdentifier=selected_kek_arn
    )

    node2_response = validation_response['RandomKeyReceive']

    print(f"✓ Node 2 (APC) generated validation response!")
    print(f"  RandomKeyReceive from Node 2: {node2_response}")
    print(f"\n  Node 2 sends this value back to Node 1...")

except ClientError as e:
    print(f"✗ AWS API Error: {e.response['Error']['Message']}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)

# ============================================================================
# STEP 9: Node 1 Validates Node 2's Response
# ============================================================================
print("\n" + "=" * 70)
print("NODE 1 VALIDATION")
print("=" * 70)

print("\n[STEP 9] Node 1 compares received value with stored RandomKeyReceive...")

print(f"\n  Stored RandomKeyReceive:  {node1_stored_krr}")
print(f"  Received from Node 2:     {node2_response}")

if node2_response == node1_stored_krr:
    print(f"\n✓ ✓ ✓ PASS 2 VALIDATION SUCCESSFUL! ✓ ✓ ✓")
    print(f"\n  The two values MATCH!")
    print(f"  Node 2's KEK is valid from Node 1's perspective.")
    pass2_passed = True
else:
    print(f"\n✗ ✗ ✗ PASS 2 VALIDATION FAILED! ✗ ✗ ✗")
    print(f"\n  The two values DO NOT MATCH!")
    print(f"  Node 2 does not hold the correct KEK.")
    print(f"  DO NOT proceed with sending session keys.")
    pass2_passed = False

# Overall result
validation_passed = pass1_passed and pass2_passed

# ============================================================================
# STEP 10: Save Validation Results
# ============================================================================
print("\n[STEP 10] Saving validation results...")

try:
    validation_results = {
        'pass1_node2_validates_node1': {
            'random_key_send': random_key_send,
            'random_key_receive_expected': node2_stored_krr,
            'node1_response': node1_response,
            'passed': pass1_passed
        },
        'pass2_node1_validates_node2': {
            'random_key_send': node1_random_key_send,
            'random_key_receive_expected': node1_stored_krr,
            'node2_response': node2_response,
            'passed': pass2_passed
        },
        'node2_keks_arn': selected_kek_arn,
        'node2_keks_check_value': key_check_value,
        'node1_kek_alias': kek_alias,
        'validation_passed': validation_passed,
        'variant_mask': 'VARIANT_MASK_82',
        'derive_key_algorithm': 'TDES_2KEY'
    }

    results_file = output_dir / "kek_validation_results.json"
    with open(results_file, 'w') as f:
        json.dump(validation_results, f, indent=2)

    print(f"✓ Validation results saved to: {results_file.name}")

except Exception as e:
    print(f"✗ Error saving results: {e}")

# ============================================================================
# Summary
# ============================================================================
print("\n" + "=" * 70)
print("KEK VALIDATION COMPLETE - Summary")
print("=" * 70)

print(f"\nNode 2 (AWS Payment Cryptography):")
print(f"  KEKs ARN: {selected_kek_arn}")
print(f"  KEKs Check Value: {key_check_value}")

print(f"\nNode 1 (Local Keystore):")
print(f"  KEK Alias: {kek_alias}")

print(f"\nPass 1 - Node 2 validates Node 1:")
print(f"  RandomKeySend: {random_key_send}")
print(f"  Expected RandomKeyReceive: {node2_stored_krr}")
print(f"  Actual Response from Node 1: {node1_response}")
print(f"  Result: {'✓ PASSED' if pass1_passed else '✗ FAILED'}")

print(f"\nPass 2 - Node 1 validates Node 2:")
print(f"  RandomKeySend: {node1_random_key_send}")
print(f"  Expected RandomKeyReceive: {node1_stored_krr}")
print(f"  Actual Response from Node 2: {node2_response}")
print(f"  Result: {'✓ PASSED' if pass2_passed else '✗ FAILED'}")

print(f"\nOverall Validation Result:")
if validation_passed:
    print(f"  ✓ PASSED - Bidirectional KEK validation successful")
    print(f"  Trust is established between both nodes.")
    print(f"  Ready to proceed with session key exchange.")
else:
    print(f"  ✗ FAILED - KEK validation incomplete")
    print(f"  DO NOT proceed with session key exchange.")

print("=" * 70)
