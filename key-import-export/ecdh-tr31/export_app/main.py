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
from tr31 import unwrap_tr31, construct_tr31_header
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives import hashes, serialization

import psec
from crypto_utils import (
    CryptoUtils, find_or_create_local_ca, get_ca_certificate, import_ca_key_to_apc,
    create_aes_256_data_encryption_key, create_ecdh_key_pair_in_payment_crypto, 
    export_aes_key_under_tr31, import_aes_key_under_tr31
)

# Initialize AWS clients
payment_crypto_client = boto3.client('payment-cryptography')
payment_crypto_data_client = boto3.client('payment-cryptography-data')
KEY_ALIAS_PREFIX = "pindemo-"
TAG_KEY = "pindemo"

# Set operation mode: 'export' or 'import'
operation = "export"

def main():
    """Main function to orchestrate the application flow"""
    print("Starting AWS Payment Cryptography and Local CA Integration")
    
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
    
    # Step 6: Generate shared information for key derivation
    print("\n--- Step 6: Generate shared information for key derivation ---")
    shared_info = CryptoUtils.generate_shared_info()
    print(f"Generated shared information: {binascii.hexlify(shared_info).decode()}")
    
    # Step 7: Derive shared secret for key wrapping (common for both import and export)
    print("\n--- Step 7: Derive shared secret for key wrapping ---")
    shared_secret = CryptoUtils.generate_ecc_symmetric_key_client(
        server_certificate, 
        private_key, 
        shared_info
    )
    print("Shared secret derived successfully")
    
    if operation == 'export':
        # Export flow
        print("\n=== EXPORT OPERATION ===")
        
        # Step 8: Create an AES-256 data encryption key in AWS Payment Cryptography
        print("\n--- Step 8: Create an AES-256 data encryption key in AWS Payment Cryptography ---")
        aes_key_arn = create_aes_256_data_encryption_key()
        print(f"AES-256 data encryption key created with ARN: {aes_key_arn}")
        
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
    
    elif operation == 'import':
        # Import flow
        print("\n=== IMPORT OPERATION ===")
        
        # Step 8: Generate random key to import
        print("\n--- Step 8: Generate random key to import ---")
        plaintext_key_bytes = secrets.token_bytes(32)  # 32 bytes = 256 bits
        print(f"Generated plaintext key: {binascii.hexlify(plaintext_key_bytes).decode().upper()}")
        
        # Step 9: Wrap key using TR31 format
        print("\n--- Step 9: Wrap key using TR31 format ---")
        # Construct TR31 header for the key to be imported
        header = construct_tr31_header(
            algoirhtm='A',
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
        imported_key_arn = import_aes_key_under_tr31(
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
    
    # Calculate KCV for the key
    cmac = CMAC(algorithms.AES(unwrapped_key_bytes))
    cmac.update(b'\x00' * 16)  # Zero block
    kcv = cmac.finalize()[:3]  # First 3 bytes
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
    
    print("\nApplication completed successfully!")


if __name__ == "__main__":
    main()