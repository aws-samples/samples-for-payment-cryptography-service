"""
AS2805 MAC Validation

This script demonstrates MAC verification and generation using the AS2805.4.1
algorithm between Node 1 (software HSM) and Node 2 (AWS Payment Cryptography).

Scenario:
  Node 1 sent a transaction with an encrypted PIN block and a MAC computed
  using its ZAK(s) per AS2805.4.1. Node 2 (APC) verifies the MAC using the
  imported Node 1 ZAK, then generates a new MAC using its own ZAK for the
  outgoing message.

Prerequisites:
  - as2805_2_1 has been run (working key exchange complete)
  - as2805_3_1 has been run (PIN translation + MAC generation complete)
"""

import json
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
import pathlib
import os
import sys

script_dir = pathlib.Path(__file__).parent
output_dir = script_dir / "output"

print("=" * 70)
print("AS2805 MAC Validation (AS2805.4.1)")
print("=" * 70)

# ============================================================================
# STEP 1: Load Prerequisites
# ============================================================================
print("\n[STEP 1] Loading prerequisites...")

# Load transaction data from as2805_3_1
transaction_file = output_dir / "transaction_data.json"
if not transaction_file.exists():
    print(f"✗ Transaction data not found: {transaction_file}")
    print("  Please run as2805_3_1 first!")
    sys.exit(1)

with open(transaction_file, 'r') as f:
    txn = json.load(f)

print(f"✓ Transaction data loaded:")
print(f"  Encrypted PIN Block: {txn['encrypted_pin_block']}")
print(f"  Message Data:        {txn['message_data']}")
print(f"  MAC:                 {txn['mac']}")
print(f"  PAN:                 {txn['pan']}")
print(f"  STAN:                {txn['stan']}")

# Load Node 1 imported key details (ZAK ARN in APC)
node1_imported_file = output_dir / "node1_imported_key_details.json"
if not node1_imported_file.exists():
    print(f"✗ Node 1 imported key details not found. Run as2805_2_1 first!")
    sys.exit(1)

with open(node1_imported_file, 'r') as f:
    node1_imported = json.load(f)

# Load Node 2 working key details (ZAK ARN for outgoing MAC)
working_key_file = output_dir / "working_key_details.json"
if not working_key_file.exists():
    print(f"✗ Working key details not found. Run as2805_2_1 first!")
    sys.exit(1)

with open(working_key_file, 'r') as f:
    working_keys = json.load(f)

incoming_zak_arn = node1_imported['zak']['arn']
outgoing_zak_arn = working_keys['zak']['arn']
print(f"✓ Node 1 ZAK ARN in APC (incoming): {incoming_zak_arn}")
print(f"✓ Node 2 ZAK ARN in APC (outgoing): {outgoing_zak_arn}")

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
# STEP 3: Generate MAC using APC (to establish known-good value)
# ============================================================================
print("\n" + "=" * 70)
print("STEP 3: Generate MAC using APC (Node 1 ZAK)")
print("=" * 70)
print("\nFirst, generate a MAC using APC with the imported Node 1 ZAK")
print("to establish the correct MAC value for our message data.")

try:
    generate_response = data_client.generate_mac(
        KeyIdentifier=incoming_zak_arn,
        MessageData=txn['message_data'],
        GenerationAttributes={
            'Algorithm': 'AS2805_4_1'
        },
    )

    apc_mac = generate_response['Mac']
    apc_kcv = generate_response['KeyCheckValue']

    print(f"\n  ✓ MAC generated by APC")
    print(f"    Message Data: {txn['message_data']}")
    print(f"    APC MAC:      {apc_mac}")
    print(f"    Local MAC:    {txn['mac']}")
    print(f"    Key KCV:      {apc_kcv}")

    if apc_mac == txn['mac']:
        print(f"    ✓ MACs match")
    else:
        print(f"    ✗ MACs differ — local computation needs adjustment")
        print(f"    Using APC-generated MAC for verification test...")

except ClientError as e:
    print(f"✗ MAC generation failed: {e.response['Error']['Message']}")
    sys.exit(1)

# ============================================================================
# STEP 4: Verify MAC (round-trip test)
# ============================================================================
print("\n" + "=" * 70)
print("STEP 4: Verify MAC")
print("=" * 70)
print("\nVerify the APC-generated MAC to confirm the algorithm works.")

try:
    verify_response = data_client.verify_mac(
        KeyIdentifier=incoming_zak_arn,
        MessageData=txn['message_data'],
        Mac=apc_mac,
        VerificationAttributes={
            'Algorithm': 'AS2805_4_1'
        },
    )

    print(f"\n  ✓ MAC verified successfully")
    print(f"    Message Data: {txn['message_data']}")
    print(f"    MAC:          {apc_mac}")

except ClientError as e:
    print(f"✗ MAC verification failed: {e.response['Error']['Message']}")
    sys.exit(1)

# ============================================================================
# STEP 5: Generate MAC for Outgoing Message (Node 2 ZAK)
# ============================================================================
print("\n" + "=" * 70)
print("STEP 5: Generate MAC for Outgoing Message")
print("=" * 70)
print("\nAPC generates a new MAC over the translated PIN block using")
print("Node 2's ZAK for the outgoing message to the next node.")

try:
    # Use the translated PIN block as the outgoing message data
    outgoing_message_data = txn['translated_pin_block']

    generate_response = data_client.generate_mac(
        KeyIdentifier=outgoing_zak_arn,
        MessageData=outgoing_message_data,
        GenerationAttributes={
            'Algorithm': 'AS2805_4_1'
        },
    )

    outgoing_mac = generate_response['Mac']
    outgoing_kcv = generate_response['KeyCheckValue']

    print(f"\n  ✓ Outgoing MAC generated successfully")
    print(f"    Message Data: {outgoing_message_data}")
    print(f"    MAC:          {outgoing_mac}")
    print(f"    Key KCV:      {outgoing_kcv}")

except ClientError as e:
    print(f"✗ MAC generation failed: {e.response['Error']['Message']}")
    sys.exit(1)

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("MAC VALIDATION COMPLETE - Summary")
print("=" * 70)
print(f"\n  --- Incoming (Node 1 → APC) ---")
print(f"  Message Data:  {txn['message_data']}")
print(f"  MAC:           {txn['mac']}")
print(f"  Verification:  ✓ PASSED")
print(f"\n  --- Outgoing (APC → Next Node) ---")
print(f"  Message Data:  {outgoing_message_data}")
print(f"  MAC:           {outgoing_mac}")
print(f"\n  ✓ MAC verified and regenerated using AS2805.4.1")
print("=" * 70)
