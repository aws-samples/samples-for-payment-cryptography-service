#!/usr/bin/env python3
"""
AWS Payment Cryptography and AWS Private CA Integration Application

This application demonstrates the integration between AWS Payment Cryptography and AWS Private CA
for secure key management and cryptographic operations using ECDH key exchange.
"""

import base64
import binascii
import boto3
import time
from tr31 import unwrap_tr31
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography import x509
from crypto_utils import CryptoUtils, find_or_create_private_ca, import_ca_key_to_apc, create_alias, get_key_by_alias

# Initialize AWS clients
payment_crypto_client = boto3.client('payment-cryptography')
payment_crypto_data_client = boto3.client('payment-cryptography-data')
private_ca_client = boto3.client('acm-pca')
KEY_ALIAS_PREFIX = "pindemo-"
TAG_KEY = "pindemo"


def create_aes_256_data_encryption_key():
    """Create an AES-256 data encryption key in AWS Payment Cryptography"""
    alias = "aes256-dek"
    key_arn = get_key_by_alias(alias)
    if key_arn is None:
        print("Creating new AES-256 Data Encryption Key")
        key_arn = payment_crypto_client.create_key(
            Exportable=True,
            KeyAttributes={
                "KeyAlgorithm": "AES_256",
                "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
                "KeyClass": "SYMMETRIC_KEY",
                "KeyModesOfUse": {
                    "Encrypt": True,
                    "Decrypt": True,
                    "Wrap": True,
                    "Unwrap": True
                }
            },
            Tags=[{"Key": TAG_KEY, "Value": "1"}]
        )['Key']['KeyArn']
        create_alias(alias, key_arn)
    return key_arn


def create_ecdh_key_pair_in_payment_crypto():
    """Create an ECDH KeyPair in AWS Payment Cryptography"""
    alias = "server-ecdh"
    key_arn = get_key_by_alias(alias)
    if key_arn is None:
        print("Creating new ECDH Key Pair in AWS Payment Cryptography")
        key_arn = payment_crypto_client.create_key(
            Enabled=True,
            Exportable=True,
            KeyAttributes={
                'KeyAlgorithm': 'ECC_NIST_P521',
                'KeyClass': 'ASYMMETRIC_KEY_PAIR',
                'KeyModesOfUse': {
                    'DeriveKey': True
                },
                'KeyUsage': 'TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT'
            },
            DeriveKeyUsage= 'TR31_K1_KEY_BLOCK_PROTECTION_KEY',
            Tags=[{"Key": TAG_KEY, "Value": "1"}]
        )['Key']['KeyArn']
        create_alias(alias, key_arn)
    return key_arn


def export_aes_key_under_tr31(aes_key_arn, client_cert_key_arn, server_ecdh_key_arn, shared_info, public_key_certificate):
    """Export the AES-256 key wrapped under ECDH key using TR31 format"""
    print("Exporting AES-256 key wrapped under ECDH key using TR31 format")
    
    # Get the shared info in the format expected by AWS Payment Cryptography
    shared_info_hex = binascii.hexlify(shared_info).decode().upper()
    
    # Using the correct boto3 API structure for export_key with DiffieHellmanTr31KeyBlock
    response = payment_crypto_client.export_key(
        ExportKeyIdentifier=aes_key_arn,
        KeyMaterial={
            'DiffieHellmanTr31KeyBlock': {
                'CertificateAuthorityPublicKeyIdentifier': client_cert_key_arn,
                'DerivationData': {
                    'SharedInformation': shared_info_hex
                },
                'DeriveKeyAlgorithm': 'AES_256',
                'KeyDerivationFunction': 'NIST_SP800',
                'KeyDerivationHashAlgorithm': 'SHA_512',
                'PrivateKeyIdentifier': server_ecdh_key_arn,
                'PublicKeyCertificate': base64.b64encode(public_key_certificate.encode('UTF-8')).decode('UTF-8')
            }
        }
    )

    print(f"Export response: {response}")
    return response['WrappedKey']['KeyMaterial']


def main():
    """Main function to orchestrate the application flow"""
    print("Starting AWS Payment Cryptography and AWS Private CA Integration")
    
    # Step 1: Create Private CA and import the public CA key into Payment Cryptography
    print("\n--- Step 1: Create Private CA and import public CA key ---")
    ca_arn = find_or_create_private_ca()
    ca_certificate = private_ca_client.get_certificate_authority_certificate(
        CertificateAuthorityArn=ca_arn
    )['Certificate']
    ca_key_arn = import_ca_key_to_apc(ca_certificate)
    print(f"CA ARN: {ca_arn}")
    print(f"CA Key ARN in Payment Cryptography: {ca_key_arn}")
    
    # Step 2: Locally create an ECDH KeyPair
    print("\n--- Step 2: Locally create an ECDH KeyPair ---")
    private_key, public_key = CryptoUtils.generate_ecdh_key_pair()
    print("Local ECDH KeyPair created")
    
    # Step 3: Sign the local KeyPair with PrivateCA
    print("\n--- Step 3: Sign the local KeyPair with PrivateCA ---")
    # Generate CSR
    csr = CryptoUtils.generate_certificate_signing_request(private_key)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # Sign the CSR with Private CA
    certificate, chain = CryptoUtils.sign_with_private_ca(
        ca_arn, 
        csr_pem, 
        {'Value': 7, 'Type': 'DAYS'}  # Reduced validity for SHORT_LIVED_CERTIFICATE mode
    )
    print("Certificate signed by Private CA")
    
    # Step 5: Create an ECDH KeyPair in AWS Payment Cryptography
    print("\n--- Step 5: Create an ECDH KeyPair in AWS Payment Cryptography ---")
    server_ecdh_key_arn = create_ecdh_key_pair_in_payment_crypto()
    print(f"Server ECDH KeyPair created with ARN: {server_ecdh_key_arn}")
    
    # Get the server's public key certificate
    print("Attempting to get server's public key certificate")
    response = payment_crypto_client.get_public_key_certificate(
        KeyIdentifier=server_ecdh_key_arn
    )
    print(f"Response keys: {response.keys()}")
    server_certificate = response['KeyCertificate']
    print("Using server certificate for ECDH key exchange")

    # Step 6: Create an AES-256 data encryption key in AWS Payment Cryptography
    print("\n--- Step 6: Create an AES-256 data encryption key in AWS Payment Cryptography ---")
    aes_key_arn = create_aes_256_data_encryption_key()
    print(f"AES-256 data encryption key created with ARN: {aes_key_arn}")
    
    # Generate shared information for key derivation
    shared_info = CryptoUtils.generate_shared_info()
    print(f"Generated shared information: {binascii.hexlify(shared_info).decode()}")
    print(certificate)
    
    # Step 7: Export the AES-256 key wrapped under ECDH key using TR31
    print("\n--- Step 7: Export the AES-256 key wrapped under ECDH key using TR31 ---")
    tr31_keyblock = export_aes_key_under_tr31(
        aes_key_arn, 
        ca_key_arn,
        server_ecdh_key_arn, 
        shared_info,
        certificate
    )
    print(f"TR31 Keyblock: {tr31_keyblock}")
    print(tr31_keyblock)
    
    # Step 8: Derive the shared secret from the ECDH
    # Step 9: Decrypt the TR-31 keyblock and print the key
    print("\n--- Steps 8 & 9: Derive shared secret and decrypt TR31 keyblock ---")
    shared_secret = CryptoUtils.generate_ecc_symmetric_key_client(server_certificate, private_key, shared_info)
    print(f"Shared Secret {shared_secret}")
    unwrapped_key = unwrap_tr31(tr31_keyblock, shared_secret)
    print(f"Unwrapped key: {unwrapped_key}")
    
    # Calculate KCV for the unwrapped key (AES-256)
    unwrapped_key_bytes = binascii.unhexlify(unwrapped_key)
    cmac = CMAC(algorithms.AES(unwrapped_key_bytes))
    cmac.update(b'\x00' * 16)  # Zero block
    kcv = cmac.finalize()[:3]  # First 3 bytes
    key_check_value = binascii.hexlify(kcv).decode().upper()
    print(f"Calculated KCV for unwrapped key: {key_check_value}")
    
    # Step 10: Check that the Key Check Values (KCV) are equal
    print("\n--- Step 10: Check that the Key Check Values (KCV) are equal ---")
    # Get the KCV from AWS Payment Cryptography
    aes_key_info = payment_crypto_client.get_key(KeyIdentifier=aes_key_arn)
    aws_kcv = aes_key_info['Key']['KeyCheckValue']
    print(f"AWS Payment Cryptography KCV: {aws_kcv}")
    print(f"Locally calculated KCV: {key_check_value}")
    
    if aws_kcv == key_check_value:
        print("KCV values match! Key was successfully exported and decrypted.")
    else:
        print("KCV values do not match. There might be an issue with the key export or decryption.")
    
    print("\nApplication completed successfully!")


if __name__ == "__main__":
    main()
