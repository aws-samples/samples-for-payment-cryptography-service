"""
AWS Payment Cryptography - Prepare for Key Import

This script prepares for importing a KEK into AWS Payment Cryptography by:
1. Calling GetParametersForImport API to obtain wrapping certificate and import token
2. Saving the import parameters to file for use when doing the key import
3. Saving the wrapping certificates for reference

Complete Workflow:
- Step 1: Run this script (Mod_1_2) to get import parameters from APC
- Step 2: Run Mod_1_3_Node1_Export_KEK_for_APC.py to wrap Node1 KEK using the parameters
- Step 3: Run Mod_1_4_APC_ImportKey.py to import the wrapped KEK into APC
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
print("AWS Payment Cryptography - Prepare for Key Import")
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
            print(f"    - payment-cryptography:GetParametersForImport")
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
# STEP 1: Get Parameters for Import
# ============================================================================
print("\n[STEP 1] Getting parameters for import from AWS Payment Cryptography...")

try:
    # Call GetParametersForImport to get the wrapping certificate and import token
    import_params_response = control_client.get_parameters_for_import(
        KeyMaterialType='KEY_CRYPTOGRAM',
        WrappingKeyAlgorithm='RSA_2048'
    )

    # Extract the important parameters
    import_token = import_params_response['ImportToken']
    wrapping_key_cert = import_params_response['WrappingKeyCertificate']
    wrapping_key_cert_chain = import_params_response['WrappingKeyCertificateChain']
    parameters_valid_until = import_params_response['ParametersValidUntilTimestamp']

    print(f"✓ Import parameters retrieved successfully!")
    print(f"  Import Token: {import_token[:50]}...")
    print(f"  Wrapping Certificate Length: {len(wrapping_key_cert)} characters")
    print(f"  Parameters Valid Until: {parameters_valid_until}")

    # Save import parameters for use by Mod_1_3
    import_params_for_export = {
        'import_token': import_token,
        'wrapping_key_certificate': wrapping_key_cert,
        'wrapping_key_certificate_chain': wrapping_key_cert_chain,
        'parameters_valid_until': str(parameters_valid_until),
        'wrapping_spec': 'RSA_OAEP_SHA_256',
        'key_material_type': 'KEY_CRYPTOGRAM',
        'wrapping_algorithm': 'RSA_2048'
    }

    import_params_file = output_dir / "apc_import_parameters.json"
    with open(import_params_file, 'w') as f:
        json.dump(import_params_for_export, f, indent=2)
    print(f"  Saved import parameters to: {import_params_file.name}")

    # Save the wrapping certificate to file for reference
    cert_file = output_dir / "aws_wrapping_certificate.pem"
    with open(cert_file, 'w') as f:
        # Decode the base64 certificate to get the PEM format
        cert_pem = base64.b64decode(wrapping_key_cert).decode('utf-8')
        f.write(cert_pem)
    print(f"  Saved wrapping certificate to: {cert_file.name}")

    # Save the certificate chain
    cert_chain_file = output_dir / "aws_wrapping_certificate_chain.pem"
    with open(cert_chain_file, 'w') as f:
        cert_chain_pem = base64.b64decode(wrapping_key_cert_chain).decode('utf-8')
        f.write(cert_chain_pem)
    print(f"  Saved certificate chain to: {cert_chain_file.name}")

except Exception as e:
    print(f"✗ Error getting import parameters: {e}")
    sys.exit(1)

# ============================================================================
# STEP 2: Summary and Next Steps
# ============================================================================
print("\n" + "=" * 70)
print("PREPARATION COMPLETE - Summary")
print("=" * 70)
print(f"\nImport Parameters Retrieved:")
print(f"  Import Token: [REDACTED - {len(import_token)} chars]")
print(f"  Wrapping Certificate: {len(wrapping_key_cert)} chars")
print(f"  Parameters Valid Until: {parameters_valid_until}")
print(f"\nGenerated Files:")
print(f"  1. {import_params_file.name} - Import parameters for Mod_1_3")
print(f"  2. {cert_file.name} - AWS wrapping certificate")
print(f"  3. {cert_chain_file.name} - Certificate chain")
print(f"\nNext Steps:")
print(f"  • Run Mod_1_3_Node1_Export_KEK_for_APC.py to wrap the Node1 KEK")
print(f"  • This will create node1_kek_wrapped_for_apc.txt and import package")
print(f"  • Then run Mod_1_4_APC_ImportKey.py to import the wrapped KEK into APC")
print(f"\n⚠ Important: Import parameters expire at {parameters_valid_until}")
print(f"  Complete all steps before expiration!")
print("=" * 70)
