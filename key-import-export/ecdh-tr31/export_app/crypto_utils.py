import boto3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import base64
import binascii
import time
import secrets
import datetime
import os
import uuid

controlplane_client = boto3.client("payment-cryptography")

# Local storage for CA information
CA_STORAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca_storage")
os.makedirs(CA_STORAGE_DIR, exist_ok=True)


class CryptoUtils:

    @staticmethod
    def generate_certificate_signing_request(private_key):
        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
        ])).sign(private_key, hashes.SHA256())

        return csr

    @staticmethod
    def generate_ecdh_key_pair():
        private_key = ec.generate_private_key(curve=ec.SECP521R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_shared_info():
        return secrets.token_bytes(32)

    @staticmethod
    def generate_ecc_symmetric_key_client(certificate, krd_private_key, info):
        """
        Generate a symmetric key using ECDH key agreement protocol
        
        Args:
            certificate (str): Base64-encoded certificate containing the public key
            krd_private_key (EC private key): The private key for ECDH
            info (bytes): Additional information for key derivation
            
        Returns:
            bytes: The derived symmetric key
        """
        pem = base64.b64decode(certificate)
        certificate = x509.load_pem_x509_certificate(pem)
        shared_key = krd_private_key.exchange(
            ec.ECDH(), certificate.public_key())
        # Perform key derivation.
        derived_key = ConcatKDFHash(  # ConcatKDFHash also known as NIST SP 800-56Ar3
            algorithm=hashes.SHA512(),
            length=32,  # 16 is AES-128, 32 is AES-256
            otherinfo=info,
        ).derive(shared_key)

        return derived_key

    @staticmethod
    def sign_with_private_ca(ca_id, csr_pem, validity, template=None):
        """
        Signs the client-side ECDH Key with local CA and returns the Certificate and Certificate Chain
        
        Args:
            ca_id (str): ID of the Certificate Authority
            csr_pem (str): Certificate Signing Request in PEM format
            validity (dict): Validity period for the certificate
            template (str): Not used in local implementation
            
        Returns:
            tuple: (Certificate, Certificate Chain)
        """
        # Load the CA certificate and private key
        ca_cert_path = os.path.join(CA_STORAGE_DIR, f"{ca_id}_cert.pem")
        ca_key_path = os.path.join(CA_STORAGE_DIR, f"{ca_id}_key.pem")
        
        with open(ca_cert_path, "rb") as f:
            ca_cert_data = f.read()
            ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
        
        with open(ca_key_path, "rb") as f:
            ca_key_data = f.read()
            ca_key = serialization.load_pem_private_key(ca_key_data, password=None)
        
        # Parse the CSR
        if isinstance(csr_pem, str):
            csr_pem = csr_pem.encode('utf-8')
        csr = x509.load_pem_x509_csr(csr_pem)
        
        # Calculate validity period
        now = datetime.datetime.utcnow()
        if validity['Type'] == 'DAYS':
            valid_until = now + datetime.timedelta(days=validity['Value'])
        elif validity['Type'] == 'YEARS':
            valid_until = now + datetime.timedelta(days=365 * validity['Value'])
        else:
            raise ValueError(f"Unsupported validity type: {validity['Type']}")
        
        # Generate Subject Key Identifier from the public key
        ski = x509.SubjectKeyIdentifier.from_public_key(csr.public_key())
        
        # Create Authority Key Identifier directly from the CA's public key
        # This avoids the need to extract it from the CA certificate
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
        
        # Create a certificate - aligning with payshield_hsm.py implementation
        builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            valid_until
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # Changed to match payshield_hsm
                key_encipherment=True,
                data_encipherment=True,   # Changed to match payshield_hsm
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")  # Smart Card Logon
            ]), critical=False
        ).add_extension(
            ski, critical=False
        ).add_extension(
            aki, critical=False
        )
        
        # Sign the certificate with the CA key - using SHA256 to match payshield_hsm
        certificate = builder.sign(
            private_key=ca_key,
            algorithm=hashes.SHA256(),
        )
        
        # Serialize the certificate to PEM format
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Return the certificate and chain (which is just the CA certificate in this case)
        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        return cert_pem, ca_cert_pem

def import_ca_key_to_apc(certificate_authority):
    print("Importing CA Key")
    key_arn = controlplane_client.import_key(
        Enabled=True, 
        KeyMaterial={
            'RootCertificatePublicKey': {
                'KeyAttributes': {
                    'KeyAlgorithm': 'ECC_NIST_P521',
                    'KeyClass': 'PUBLIC_KEY',
                    'KeyModesOfUse': {
                        'Verify': True,
                    },
                    'KeyUsage': 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
                },
                'PublicKeyCertificate': base64.b64encode(certificate_authority.encode('UTF-8')).decode('UTF-8')
            }
        }, 
        KeyCheckValueAlgorithm='ANSI_X9_24'
    )['Key']['KeyArn']

    return key_arn


def apc_generate_pgk():
    print("Creating new PGK")
    key_arn = controlplane_client.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_2KEY",
            "KeyUsage": "TR31_V2_VISA_PIN_VERIFICATION_KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyModesOfUse": {"Generate": True, "Verify": True}
        }
    )['Key']['KeyArn']
    return key_arn


def apc_generate_pek():
    print("Creating new PEK")
    key_arn = controlplane_client.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "TDES_3KEY",
            "KeyUsage": "TR31_P0_PIN_ENCRYPTION_KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyModesOfUse": {
                "Encrypt": True, 
                "Decrypt": True, 
                "Wrap": True,
                "Unwrap": True
            }
        }
    )['Key']['KeyArn']
    return key_arn


def create_local_ca():
    """
    Create a local Certificate Authority
    
    Returns:
        str: ID of the created CA
    """
    print("Creating local CA")
    
    # Generate a key pair for the CA
    private_key = ec.generate_private_key(curve=ec.SECP521R1())
    
    # Create a self-signed certificate for the CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "pindemo-ca"),
    ])
    
    # Create the CA certificate
    now = datetime.datetime.utcnow()
    
    # Generate Subject Key Identifier from the public key
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    
    # For a root CA, the Authority Key Identifier is the same as the Subject Key Identifier
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key())
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=True,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).add_extension(
        ski, critical=False  # Making Subject Key Identifier non-critical to match payshield_hsm
    ).sign(private_key, hashes.SHA256())
    
    # Generate a unique ID for the CA
    ca_id = str(uuid.uuid4())
    
    # Save the CA certificate and private key
    ca_cert_path = os.path.join(CA_STORAGE_DIR, f"{ca_id}_cert.pem")
    ca_key_path = os.path.join(CA_STORAGE_DIR, f"{ca_id}_key.pem")
    
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    with open(ca_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"Local CA created with ID: {ca_id}")
    return ca_id


def find_or_create_local_ca():
    """
    Find an existing local CA or create a new one
    
    Returns:
        str: ID of the CA
    """
    # Check if any CA exists in the storage directory
    for filename in os.listdir(CA_STORAGE_DIR):
        if filename.endswith("_cert.pem"):
            ca_id = filename.split("_")[0]
            print(f"Found existing CA: {ca_id}")
            return ca_id
    
    # If no CA exists, create one
    return create_local_ca()


def get_ca_certificate(ca_id):
    """
    Get the certificate of a CA
    
    Args:
        ca_id (str): ID of the CA
        
    Returns:
        str: PEM-encoded certificate
    """
    ca_cert_path = os.path.join(CA_STORAGE_DIR, f"{ca_id}_cert.pem")
    with open(ca_cert_path, "r") as f:
        return f.read()


def setup():
    """
    Set up the CA and import it into AWS Payment Cryptography
    
    Returns:
        tuple: (CA ID, CA Key ARN)
    """
    ca_id = find_or_create_local_ca()
    ca_certificate = get_ca_certificate(ca_id)
    ca_key_arn = import_ca_key_to_apc(ca_certificate)
    return ca_id, ca_key_arn


def create_aes_256_data_encryption_key():
    """Create an AES-256 data encryption key in AWS Payment Cryptography"""
    print("Creating new AES-256 Data Encryption Key")
    key_arn = controlplane_client.create_key(
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
        }
    )['Key']['KeyArn']
    return key_arn


def create_ecdh_key_pair_in_payment_crypto():
    """Create an ECDH KeyPair in AWS Payment Cryptography"""
    print("Creating new ECDH Key Pair in AWS Payment Cryptography")
    key_arn = controlplane_client.create_key(
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
        DeriveKeyUsage= 'TR31_K1_KEY_BLOCK_PROTECTION_KEY'
    )['Key']['KeyArn']
    return key_arn


def export_aes_key_under_tr31(aes_key_arn, client_cert_key_arn, server_ecdh_key_arn, shared_info, public_key_certificate):
    """Export the AES-256 key wrapped under ECDH key using TR31 format"""
    print("Exporting AES-256 key wrapped under ECDH key using TR31 format")
    
    # Get the shared info in the format expected by AWS Payment Cryptography
    shared_info_hex = binascii.hexlify(shared_info).decode().upper()
    
    # Using the correct boto3 API structure for export_key with DiffieHellmanTr31KeyBlock
    response = controlplane_client.export_key(
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

def import_aes_key_under_tr31(client_cert_key_arn, server_ecdh_key_arn, shared_info, public_key_certificate, tr31block):
    """Export the AES-256 key wrapped under ECDH key using TR31 format"""
    print("Exporting AES-256 key wrapped under ECDH key using TR31 format")
    
    # Get the shared info in the format expected by AWS Payment Cryptography
    shared_info_hex = binascii.hexlify(shared_info).decode().upper()
    
    # Using the correct boto3 API structure for export_key with DiffieHellmanTr31KeyBlock
    response = controlplane_client.import_key(
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
                'PublicKeyCertificate': base64.b64encode(public_key_certificate.encode('UTF-8')).decode('UTF-8'),
                'WrappedKeyBlock': tr31block
            }
        }
    )

    print(f"Export response: {response}")
    return response['Key']['KeyArn']