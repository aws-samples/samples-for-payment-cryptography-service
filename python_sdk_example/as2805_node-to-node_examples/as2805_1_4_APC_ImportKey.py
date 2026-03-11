"""
AWS Payment Cryptography - Import Wrapped KEK

This script imports a wrapped KEK into AWS Payment Cryptography.
The workflow includes:
1. Loading the wrapped KEK and import package created in previous scripts
2. Importing the key into AWS Payment Cryptography
3. Validating the imported key

Prerequisites:
- as2805_1_2 has been run to get import parameters
- as2805_1_3 has been run to wrap and export the Node1 KEK
"""

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from pathlib import Path
import base64
import json
import sys
import os

script_dir = Path(__file__).parent
output_dir = script_dir / "output"
output_dir.mkdir(exist_ok=True)

print("=" * 70)
print("AWS Payment Cryptography - Import Wrapped KEK")
print("=" * 70)

# ============================================================================
# STEP 0: Check AWS Credentials and Permissions
# ============================================================================
print("\n[STEP 0] Checking AWS credentials and permissions...")

try:
    # Create a session to check credentials
    session = boto3.Session()

    # Check if credentials are available
    credentials = session.get_credentials()
    if credentials is None:
        print("✗ No AWS credentials found!")
        print("\nPlease configure AWS credentials using one of these methods:")
        print("  1. AWS CLI: aws configure")
        print("  2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
        print("  3. AWS credentials file: ~/.aws/credentials")
        print("  4. IAM role (if running on EC2/ECS/Lambda)")
        sys.exit(1)

    # Get current credentials info
    frozen_credentials = credentials.get_frozen_credentials()
    print(f"✓ AWS credentials found")
    print(f"  Access Key ID: {frozen_credentials.access_key[:10]}...")

    # Check which credential source is being used
    if os.environ.get('AWS_ACCESS_KEY_ID'):
        print(f"  Source: Environment variables")
    elif os.environ.get('AWS_PROFILE'):
        print(f"  Source: AWS Profile ({os.environ.get('AWS_PROFILE')})")
    else:
        print(f"  Source: Default credential chain")

    # Verify credentials work by calling STS
    sts_client = boto3.client('sts')
    identity = sts_client.get_caller_identity()

    print(f"✓ Credentials verified")
    print(f"  Account: {identity['Account']}")
    print(f"  User/Role ARN: {identity['Arn']}")
    print(f"  User ID: {identity['UserId']}")

    # Check region configuration
    region = session.region_name
    if region is None:
        print("\n⚠ Warning: No default region configured")
        print("  Using ap-southeast-2 as default")
        region = 'ap-southeast-2'
    else:
        print(f"✓ Region: {region}")

    # Initialize AWS Payment Cryptography client with verified region
    control_client = boto3.client('payment-cryptography', region_name=region)

    # Test Payment Cryptography permissions by listing keys
    try:
        list_response = control_client.list_keys(MaxResults=1)
        print(f"✓ AWS Payment Cryptography access verified")
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            print(f"\n✗ Access Denied to AWS Payment Cryptography")
            print(f"  Your IAM user/role needs the following permissions:")
            print(f"    - payment-cryptography:ImportKey")
            print(f"    - payment-cryptography:GetKey")
            print(f"    - payment-cryptography:ListKeys")
            print(f"\n  Error details: {e.response['Error']['Message']}")
            sys.exit(1)
        else:
            raise

except NoCredentialsError:
    print("✗ No AWS credentials found!")
    print("\nPlease configure AWS credentials using one of these methods:")
    print("  1. AWS CLI: aws configure")
    print("  2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
    print("  3. AWS credentials file: ~/.aws/credentials")
    sys.exit(1)

except PartialCredentialsError:
    print("✗ Incomplete AWS credentials!")
    print("  Both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required")
    sys.exit(1)

except ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code == 'InvalidClientTokenId':
        print("✗ Invalid AWS credentials!")
        print("  The access key ID does not exist")
    elif error_code == 'SignatureDoesNotMatch':
        print("✗ Invalid AWS credentials!")
        print("  The secret access key is incorrect")
    elif error_code == 'ExpiredToken':
        print("✗ AWS credentials have expired!")
        print("  Please refresh your credentials")
    else:
        print(f"✗ Error verifying credentials: {e}")
    sys.exit(1)

except Exception as e:
    print(f"✗ Unexpected error checking credentials: {e}")
    sys.exit(1)

# ============================================================================
# STEP 1: Load Import Package
# ============================================================================
print("\n[STEP 1] Loading import package...")

import_package_file = output_dir / "node1_kek_import_package.json"

if not import_package_file.exists():
    print(f"✗ Import package file not found: {import_package_file}")
    print("  Please run as2805_1_3_Node1_Export_KEK_for_APC.py first!")
    sys.exit(1)

try:
    with open(import_package_file, 'r') as f:
        import_package = json.load(f)

    # Extract the key components from KeyMaterial.KeyCryptogram
    key_cryptogram = import_package['KeyMaterial']['KeyCryptogram']
    wrapped_key_cryptogram = key_cryptogram['WrappedKeyCryptogram']
    import_token = key_cryptogram['ImportToken']
    wrapping_spec = key_cryptogram['WrappingSpec']
    exportable = key_cryptogram['Exportable']
    key_attributes = key_cryptogram.get('KeyAttributes', {})

    print(f"✓ Import package loaded successfully!")
    print(f"  Wrapped Key Length: {len(wrapped_key_cryptogram)} characters")
    print(f"  Import Token: [REDACTED - {len(import_token)} chars]")
    print(f"  Wrapping Spec: {wrapping_spec}")
    print(f"  Exportable: {exportable}")

    if key_attributes:
        print(f"  Key Algorithm: {key_attributes.get('KeyAlgorithm', 'Not specified')}")
        print(f"  Key Usage: {key_attributes.get('KeyUsage', 'Not specified')}")

except Exception as e:
    print(f"✗ Error loading import package: {e}")
    sys.exit(1)

# ============================================================================
# STEP 2: Import the Key into AWS Payment Cryptography
# ============================================================================
print("\n[STEP 2] Importing key into AWS Payment Cryptography...")

try:
    # Build the KeyCryptogram structure with all required fields
    key_cryptogram_params = {
        'Exportable': exportable,
        'WrappedKeyCryptogram': wrapped_key_cryptogram,
        'ImportToken': import_token,
        'WrappingSpec': wrapping_spec
    }

    # Add KeyAttributes if present in the import package
    if key_attributes:
        key_cryptogram_params['KeyAttributes'] = key_attributes
        print(f"  Using KeyAttributes from import package")

    # Import the key with the package parameters
    import_response = control_client.import_key(
        KeyMaterial={
            'KeyCryptogram': key_cryptogram_params
        },
        Enabled=import_package.get('Enabled', True),
        Tags=import_package.get('Tags', [])
    )

    imported_key_arn = import_response['Key']['KeyArn']
    imported_key_check_value = import_response['Key']['KeyCheckValue']

    print(f"✓ Key imported successfully!")
    print(f"  ARN: {imported_key_arn}")
    print(f"  Check Value: {imported_key_check_value}")

    # Save imported key details
    imported_key_details = {
        'arn': imported_key_arn,
        'check_value': imported_key_check_value,
        'source_package': str(import_package_file),
        'imported_by': identity['Arn']
    }

    imported_key_file = output_dir / "imported_kek_details.json"
    with open(imported_key_file, 'w') as f:
        json.dump(imported_key_details, f, indent=2)
    print(f"  Saved details to: {imported_key_file.name}")

except ClientError as e:
    error_code = e.response['Error']['Code']
    error_msg = e.response['Error']['Message']
    print(f"✗ AWS API Error importing key: {error_code}")
    print(f"  {error_msg}")
    if error_code == 'InvalidKeyMaterialException':
        print("  The wrapped key material may be invalid or corrupted")
    elif error_code == 'ExpiredImportTokenException':
        print("  The import token has expired. Please re-run as2805_1_2 and as2805_1_3")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error importing key: {e}")
    sys.exit(1)

# ============================================================================
# STEP 3: Validate the Imported Key
# ============================================================================
print("\n[STEP 3] Validating imported key...")

try:
    # Get the key details to verify it was imported correctly
    get_key_response = control_client.get_key(
        KeyIdentifier=imported_key_arn
    )

    key_details = get_key_response['Key']

    # Verify key attributes
    key_state = key_details['KeyState']
    key_usage = key_details['KeyAttributes']['KeyUsage']
    key_algorithm = key_details['KeyAttributes']['KeyAlgorithm']
    key_modes = key_details['KeyAttributes']['KeyModesOfUse']

    print(f"✓ Key validation successful!")
    print(f"  State: {key_state}")
    print(f"  Usage: {key_usage}")
    print(f"  Algorithm: {key_algorithm}")
    print(f"  Modes of Use:")
    print(f"    Encrypt: {key_modes.get('Encrypt', False)}")
    print(f"    Decrypt: {key_modes.get('Decrypt', False)}")
    print(f"    Wrap: {key_modes.get('Wrap', False)}")
    print(f"    Unwrap: {key_modes.get('Unwrap', False)}")

    # Verify the key is enabled and has the correct usage
    validation_passed = True

    if key_state != 'CREATE_COMPLETE':
        print(f"⚠ Warning: Key state is {key_state}, expected CREATE_COMPLETE")
        validation_passed = False

    if key_usage != 'TR31_K0_KEY_ENCRYPTION_KEY':
        print(f"⚠ Warning: Key usage is {key_usage}, expected TR31_K0_KEY_ENCRYPTION_KEY")
        validation_passed = False

    # Verify required modes of use
    required_modes = ['Encrypt', 'Decrypt', 'Wrap', 'Unwrap']
    missing_modes = [mode for mode in required_modes if not key_modes.get(mode, False)]

    if missing_modes:
        print(f"⚠ Warning: Missing required modes: {', '.join(missing_modes)}")
        validation_passed = False
    else:
        print(f"✓ All required key modes are enabled")

    if not validation_passed:
        print(f"\n⚠ Key validation completed with warnings")

except ClientError as e:
    print(f"✗ AWS API Error validating key: {e.response['Error']['Message']}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error validating key: {e}")
    sys.exit(1)

# ============================================================================
# STEP 4: Summary
# ============================================================================
print("\n" + "=" * 70)
print("IMPORT COMPLETE - Summary")
print("=" * 70)
print(f"\nImported Key Details:")
print(f"  ARN: {imported_key_arn}")
print(f"  Check Value: {imported_key_check_value}")
print(f"  Source Package: {import_package_file.name}")
print(f"  State: {key_state}")
print(f"\nKey Configuration:")
print(f"  Usage: {key_usage}")
print(f"  Algorithm: {key_algorithm}")
print(f"  Enabled Modes: Encrypt, Decrypt, Wrap, Unwrap")
print(f"\nWorkflow Summary:")
print(f"  1. as2805_1_2 - Generated import parameters from APC")
print(f"  2. as2805_1_3 - Wrapped Node1 KEK using APC parameters")
print(f"  3. as2805_1_4 (this script) - Imported wrapped KEK into APC")
print(f"\nThe key is now ready to use as an AS2805 KEK in AWS Payment Cryptography.")
print("=" * 70)
