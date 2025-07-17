import boto3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import base64
import time
import secrets

private_ca_client = boto3.client('acm-pca')


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
    def sign_with_private_ca(ca_arn, csr, validity, template="arn:aws:acm-pca:::template/EndEntityCertificate/V1"):
        """
        Signs the client-side ECDH Key with AWS Private CA and returns the Certificate and Certificate Chain
        
        Args:
            ca_arn (str): ARN of the Certificate Authority
            csr (str): Certificate Signing Request
            validity (dict): Validity period for the certificate
            template (str): Template ARN to use for the certificate
            
        Returns:
            tuple: (Certificate, Certificate Chain)
        """
        response = private_ca_client.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr,
            TemplateArn=template,
            SigningAlgorithm='SHA512WITHECDSA',
            Validity=validity
        )
        certificate_arn = response['CertificateArn']
        time.sleep(0.5)

        while 1:
            try:
                certificate_response = private_ca_client.get_certificate(CertificateArn=certificate_arn,
                                                                         CertificateAuthorityArn=ca_arn)
                if 'CertificateChain' in certificate_response:
                    chain = certificate_response['CertificateChain']
                else:
                    chain = None
                return certificate_response['Certificate'], chain
            except private_ca_client.exceptions.RequestInProgressException:
                time.sleep(0.1)
