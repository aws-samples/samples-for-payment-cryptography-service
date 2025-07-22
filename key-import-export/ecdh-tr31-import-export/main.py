#!/usr/bin/env python3
"""
AWS Payment Cryptography and Local CA Integration Application

This application demonstrates the integration between AWS Payment Cryptography and a local CA
for secure key management and cryptographic operations using ECDH key exchange.
The application supports both key export and import operations using TR31 format.
"""

import base64
import binascii
import boto3
import secrets
import inquirer
import argparse
import sys
from tr31 import unwrap_tr31, construct_tr31_header
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives import serialization
import psec
from crypto_utils import (
    CryptoUtils, find_or_create_local_ca, get_ca_certificate, import_ca_key_to_apc,
    create_aes_256_data_encryption_key, create_data_encryption_key, create_ecdh_key_pair_in_payment_crypto, 
    export_aes_key_under_tr31, import_key_under_tr31_ecdh
)

# Initialize AWS clients
payment_crypto_client = boto3.client('payment-cryptography')
payment_crypto_data_client = boto3.client('payment-cryptography-data')
KEY_ALIAS_PREFIX = "pindemo-"
TAG_KEY = "pindemo"

def select_operation():
    """
    Interactive CLI prompt to select operation mode with descriptive labels
    
    Returns:
        str: Selected operation ('import' or 'export')
    """
    questions = [
        inquirer.List('operation',
                      message="Select operation mode",
                      choices=[
                          ('Import a key from a raw plaintext key into AWS Payment Cryptography', 'import'),
                          ('Create a random key in AWS Payment Cryptography and export it to plaintext', 'export')
                      ],
                      carousel=True),
    ]
    answers = inquirer.prompt(questions)
    return answers['operation']

def select_import_method():
    """
    Interactive CLI prompt to select key import method
    
    Returns:
        str: Selected method ('random' or 'custom')
    """
    questions = [
        inquirer.List('import_method',
                      message="Select key import method",
                      choices=[
                          ('Generate a random key', 'random'),
                          ('Enter a custom hexadecimal key', 'custom')
                      ],
                      carousel=True),
    ]
    answers = inquirer.prompt(questions)
    return answers['import_method']

def select_key_type():
    """
    Interactive CLI prompt to select key type
    
    Returns:
        str: Selected key type ('AES_256', 'TDES_2KEY', or 'TDES_3KEY')
    """
    questions = [
        inquirer.List('key_type',
                      message="Select key type",
                      choices=[
                          ('AES-256 (32 bytes / 256 bits)', 'AES_256'),
                          ('Triple DES 2-Key (16 bytes / 128 bits)', 'TDES_2KEY'),
                          ('Triple DES 3-Key (24 bytes / 192 bits)', 'TDES_3KEY')
                      ],
                      carousel=True),
    ]
    answers = inquirer.prompt(questions)
    return answers['key_type']

def get_custom_key(key_type):
    """
    Prompt user to enter a custom key in hexadecimal format based on key type
    
    Args:
        key_type (str): Type of key ('AES_256', 'TDES_2KEY', or 'TDES_3KEY')
    
    Returns:
        bytes: The key as bytes
    """
    valid_key = False
    key_bytes = None
    
    # Define validation parameters based on key type
    if key_type == 'AES_256':
        expected_length = 64  # 32 bytes = 64 hex chars
        message = "Enter 32-byte (64 hex characters) AES-256 key"
    elif key_type == 'TDES_2KEY':
        expected_length = 32  # 16 bytes = 32 hex chars
        message = "Enter 16-byte (32 hex characters) Triple DES 2-Key"
    elif key_type == 'TDES_3KEY':
        expected_length = 48  # 24 bytes = 48 hex chars
        message = "Enter 24-byte (48 hex characters) Triple DES 3-Key"
    else:
        raise ValueError(f"Unsupported key type: {key_type}")
    
    while not valid_key:
        questions = [
            inquirer.Text('key_hex',
                         message=message,
                         validate=lambda _, x: len(x.strip()) == expected_length and all(c in '0123456789ABCDEFabcdef' for c in x.strip()),
                         max_length=128
                         )
        ]
        answers = inquirer.prompt(questions)
        key_hex = answers['key_hex'].strip().upper()
        
        try:
            key_bytes = binascii.unhexlify(key_hex)
            valid_key = True
        except binascii.Error:
            print("❌ Invalid hexadecimal format. Please try again.")
    
    return key_bytes

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AWS Payment Cryptography and Local CA Integration Application"
    )
    parser.add_argument(
        "--operation", 
        choices=["import", "export"],
        help="Operation mode: import or export"
    )
    parser.add_argument(
        "--import-method", 
        choices=["random", "custom"],
        help="Import method: random or custom key"
    )
    parser.add_argument(
        "--key-type",
        choices=["AES_256", "TDES_2KEY", "TDES_3KEY"],
        help="Type of key to import or export"
    )
    parser.add_argument(
        "--key", 
        help="Custom key in hexadecimal format (length depends on key type)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.import_method == "custom" and args.operation == "import" and not args.key:
        parser.error("--import-method custom requires --key to be specified")
    
    return args

def get_user_inputs():
    """
    Gather all user inputs at the beginning of the interaction
    
    Returns:
        dict: Dictionary containing all user inputs
    """
    inputs = {}
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Determine operation mode (from args or interactive)
    if args.operation:
        inputs['operation'] = args.operation
        print(f"\nUsing command-line specified operation: {inputs['operation'].upper()}")
    else:
        inputs['operation'] = select_operation()
        print(f"\nSelected operation: {inputs['operation'].upper()}")
    
    # Determine key type (from args or interactive)
    if args.key_type:
        inputs['key_type'] = args.key_type
        print(f"Using command-line specified key type: {inputs['key_type']}")
    else:
        inputs['key_type'] = select_key_type()
        print(f"Selected key type: {inputs['key_type']}")
    
    # If import operation, get import method and key
    if inputs['operation'] == 'import':
        # Determine import method (from args or interactive)
        if args.import_method:
            inputs['import_method'] = args.import_method
            print(f"Using command-line specified import method: {inputs['import_method']}")
        else:
            inputs['import_method'] = select_import_method()
            print(f"Selected import method: {inputs['import_method']}")
        
        # Get key based on import method
        if inputs['import_method'] == 'random':
            key_type_desc = "AES-256" if inputs['key_type'] == 'AES_256' else "TDES" 
            print(f"Will generate a random {key_type_desc} key during execution")
            inputs['plaintext_key_bytes'] = None  # Will be generated during execution
        else:  # custom
            # Check if key was provided via command line
            if args.key:
                try:
                    # Define expected length based on key type
                    if inputs['key_type'] == 'AES_256':
                        expected_length = 64  # 32 bytes = 64 hex chars
                    elif inputs['key_type'] == 'TDES_2KEY':
                        expected_length = 32  # 16 bytes = 32 hex chars
                    elif inputs['key_type'] == 'TDES_3KEY':
                        expected_length = 48  # 24 bytes = 48 hex chars
                    
                    # Validate the key format
                    if len(args.key) != expected_length or not all(c in '0123456789ABCDEFabcdef' for c in args.key):
                        print(f"❌ Invalid key format. Key must be {expected_length} hexadecimal characters for {inputs['key_type']}.")
                        sys.exit(1)
                    
                    inputs['plaintext_key_bytes'] = binascii.unhexlify(args.key.upper())
                    print(f"Using command-line provided key: {args.key.upper()}")
                except binascii.Error:
                    print("❌ Invalid hexadecimal format in provided key.")
                    sys.exit(1)
            else:
                print("Please enter your custom key:")
                inputs['plaintext_key_bytes'] = get_custom_key(inputs['key_type'])
                print(f"Using custom key: {binascii.hexlify(inputs['plaintext_key_bytes']).decode().upper()}")
    
    return inputs

def main():
    """Main function to orchestrate the application flow"""
    print("Starting AWS Payment Cryptography and Local CA Integration")
    
    # Gather all user inputs at the beginning
    inputs = get_user_inputs()
    operation = inputs['operation']
    
    print("\n=== Starting Execution ===")
    
    # Step 1: Create Local CA and import the public CA key into Payment Cryptography
    print("\n--- Step 1: Create Local CA and import public CA key ---")
    ca_id = find_or_create_local_ca()
    ca_certificate = get_ca_certificate(ca_id)
    ca_key_arn = import_ca_key_to_apc(ca_certificate)
    print(f"CA ID: {ca_id}")
    print(f"CA Key ARN in Payment Cryptography: {ca_key_arn}")
    
    # Step 2: Locally create an ECDH KeyPair
    print("\n--- Step 2: Locally create an ECDH KeyPair ---")
    private_key, public_key = CryptoUtils.generate_ecdh_key_pair()
    print("Local ECDH KeyPair created")
    
    # Step 3: Sign the local KeyPair with Local CA
    print("\n--- Step 3: Sign the local KeyPair with Local CA ---")
    # Generate CSR
    csr = CryptoUtils.generate_certificate_signing_request(private_key)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # Sign the CSR with Local CA
    certificate, chain = CryptoUtils.sign_with_private_ca(
        ca_id, 
        csr_pem, 
        {'Value': 7, 'Type': 'DAYS'}
    )
    print("Certificate signed by Private CA")
    
    # Step 4: Create an ECDH KeyPair in AWS Payment Cryptography
    print("\n--- Step 4: Create an ECDH KeyPair in AWS Payment Cryptography ---")
    server_ecdh_key_arn = create_ecdh_key_pair_in_payment_crypto()
    print(f"Server ECDH KeyPair created with ARN: {server_ecdh_key_arn}")
    
    # Step 5: Get the server's public key certificate
    print("\n--- Step 5: Get server's public key certificate ---")
    response = payment_crypto_client.get_public_key_certificate(
        KeyIdentifier=server_ecdh_key_arn
    )
    server_certificate = response['KeyCertificate']
    print("Retrieved server certificate for ECDH key exchange")
    
    # Step 6: Use static shared information for key derivation
    print("\n--- Step 6: Use static shared information for key derivation ---")
    # Using a hardcoded static secret (32 bytes)
    shared_info = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
    print(f"Using static shared information: {binascii.hexlify(shared_info).decode()}")
    
    # Step 7: Derive shared secret for key wrapping (common for both import and export)
    print("\n--- Step 7: Derive shared secret for key wrapping ---")
    shared_secret = CryptoUtils.generate_ecc_symmetric_key_client(
        server_certificate, 
        private_key, 
        shared_info
    )
    print("Shared secret derived successfully")
    key_type = inputs['key_type']
    if operation == 'export':
        # Export flow
        print("\n=== EXPORT OPERATION ===")
        
        # Step 8: Create a data encryption key in AWS Payment Cryptography based on selected key type
        print(f"\n--- Step 8: Create a {key_type} data encryption key in AWS Payment Cryptography ---")
        aes_key_arn = create_data_encryption_key(key_type)
        print(f"{key_type} data encryption key created with ARN: {aes_key_arn}")
        
        # Step 9: Export the AES-256 key wrapped under ECDH key using TR31
        print("\n--- Step 9: Export the AES-256 key wrapped under ECDH key using TR31 ---")
        tr31_keyblock = export_aes_key_under_tr31(
            aes_key_arn, 
            ca_key_arn,
            server_ecdh_key_arn, 
            shared_info,
            certificate
        )
        print(f"TR31 Keyblock: {tr31_keyblock}")

        # Step 10: Unwrap the key locally
        print("\n--- Step 10: Unwrap the exported key locally ---")
        unwrapped_key = unwrap_tr31(tr31_keyblock, shared_secret)
        print(f"Unwrapped key: {unwrapped_key}")
        
        # Store for KCV verification
        unwrapped_key_bytes = binascii.unhexlify(unwrapped_key)
        aes_key_arn = aes_key_arn
    
    elif operation == 'import':
        # Import flow
        print("\n=== IMPORT OPERATION ===")
        
        # Step 8: Get key to import (random or custom)
        print("\n--- Step 8: Get key to import ---")
        
        import_method = inputs['import_method']
        
        if import_method == 'random':
            # Generate random key based on key type
            
            if key_type == 'AES_256':
                print("Generating random AES-256 key...")
                plaintext_key_bytes = secrets.token_bytes(32)  # 32 bytes = 256 bits
            elif key_type == 'TDES_2KEY':
                print("Generating random Triple DES 2-Key...")
                plaintext_key_bytes = secrets.token_bytes(16)  # 16 bytes = 128 bits
            elif key_type == 'TDES_3KEY':
                print("Generating random Triple DES 3-Key...")
                plaintext_key_bytes = secrets.token_bytes(24)  # 24 bytes = 192 bits
            else:
                raise ValueError(f"Unsupported key type: {key_type}")
                
            print(f"Generated plaintext key: {binascii.hexlify(plaintext_key_bytes).decode().upper()}")
        else:  # custom
            plaintext_key_bytes = inputs['plaintext_key_bytes']
            print(f"Using provided custom key: {binascii.hexlify(plaintext_key_bytes).decode().upper()}")
        
        # Step 9: Wrap key using TR31 format
        print("\n--- Step 9: Wrap key using TR31 format ---")
        # Set algorithm based on key type
        if key_type == 'AES_256':
            algorithm = 'A'  # AES
        else:  # TDES keys
            algorithm = 'T'  # Triple DES
            
        # Construct TR31 header for the key to be imported
        header = construct_tr31_header(
            algorithm=algorithm,
            export_mode='E',
            key_type='D0',  # Symmetric Data Encryption Key
            mode_of_use='B',
            version_id='D'
        )
        wrapped_key = psec.tr31.wrap(
            kbpk=shared_secret, 
            header=header, 
            key=plaintext_key_bytes
        ).upper()
        print(f"TR31 wrapped key block: {wrapped_key}")
        
        # Step 10: Import the wrapped key into AWS Payment Cryptography
        print("\n--- Step 10: Import the wrapped key into AWS Payment Cryptography ---")
        imported_key_arn = import_key_under_tr31_ecdh(
            ca_key_arn, 
            server_ecdh_key_arn, 
            shared_info, 
            certificate, 
            wrapped_key
            
        )
        print(f"Key successfully imported with ARN: {imported_key_arn}")
        
        # Store for KCV verification
        aes_key_arn = imported_key_arn
        unwrapped_key_bytes = plaintext_key_bytes
    
    # Step 11: Calculate and verify Key Check Value (KCV)
    print("\n--- Step 11: Calculate and verify Key Check Value (KCV) ---")
    
    # Calculate KCV for the key based on key type
    if key_type == 'AES_256':
        # For AES keys, use CMAC
        cmac = CMAC(algorithms.AES(unwrapped_key_bytes))
        cmac.update(b'\x00' * 16)  # Zero block
        kcv = cmac.finalize()[:3]  # First 3 bytes
    else:  # TDES keys
        # For TDES keys, encrypt a zero block and take first 3 bytes
        if key_type == 'TDES_2KEY':
            # For 2-key TDES, duplicate the first 8 bytes to make it 24 bytes
            if len(unwrapped_key_bytes) == 16:  # 16 bytes = 128 bits
                tdes_key = unwrapped_key_bytes + unwrapped_key_bytes[:8]
            else:
                tdes_key = unwrapped_key_bytes
        else:  # TDES_3KEY
            tdes_key = unwrapped_key_bytes
            
        cipher = Cipher(algorithms.TripleDES(tdes_key), modes.ECB())
        encryptor = cipher.encryptor()
        kcv = encryptor.update(b'\x00' * 8)[:3]  # Encrypt zero block, take first 3 bytes
    
    key_check_value = binascii.hexlify(kcv).decode().upper()
    print(f"Calculated KCV for key: {key_check_value}")
    
    # Get the KCV from AWS Payment Cryptography
    aes_key_info = payment_crypto_client.get_key(KeyIdentifier=aes_key_arn)
    aws_kcv = aes_key_info['Key']['KeyCheckValue']
    print(f"AWS Payment Cryptography KCV: {aws_kcv}")
    
    # Verify KCV match
    if aws_kcv == key_check_value:
        print("✅ KCV values match! Key operation was successful.")
    else:
        print("❌ KCV values do not match. There might be an issue with the key operation.")
    
    # Step 12: Delete the ECDH key pair from AWS Payment Cryptography
    print("\n--- Step 12: Deleting ECDH key pair from AWS Payment Cryptography (used as KEK) ---")
    try:
        payment_crypto_client.delete_key(KeyIdentifier=server_ecdh_key_arn)
        print(f"Successfully deleted ECDH key pair (KEK) with ARN: {server_ecdh_key_arn}")
    except Exception as e:
        print(f"Warning: Failed to delete ECDH key pair: {e}")
    
    print("\nApplication completed successfully!")
    
    # At the end of the execution, print the relevant outputs (ARN and Plaintext key)

    print("\n===  OUTPUTS ===")
    print(f"Key ARN: {aes_key_arn}")
    print(f"Plaintext Key (hex): {binascii.hexlify(unwrapped_key_bytes).decode().upper()}")


if __name__ == "__main__":
    main()