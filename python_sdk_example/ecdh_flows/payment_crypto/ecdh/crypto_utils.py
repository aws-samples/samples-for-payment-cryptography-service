import boto3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
# from Crypto.Hash import CMAC
# from Crypto.Cipher import AES
import psec
import psec.pinblock
import binascii
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
        private_key = ec.generate_private_key(curve=ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_shared_info():
        return secrets.token_bytes(32)
        # you could generate this random with KMS as well
        # kms_client = boto3.client('kms')
        # print(kms_client.generate_random(NumberOfBytes=32)["Plaintext"])
        # return kms_client.generate_random(NumberOfBytes=32)["Plaintext"]

    @staticmethod
    def generate_ecc_symmetric_key_client(certificate, krd_private_key, info):
        pem = base64.b64decode(certificate)
        certificate = x509.load_pem_x509_certificate(pem)
        shared_key = krd_private_key.exchange(
            ec.ECDH(), certificate.public_key())
        # Perform key derivation.
        derived_key = ConcatKDFHash(  # ConcatKDFHash also known as NIST SP 800-56Ar3
            algorithm=hashes.SHA512(),
            length=16,  # 16 is AES-128, 32 is AES-256
            otherinfo=info,
        ).derive(shared_key)

        # KCV code
        # print(binascii.hexlify(derived_key))
        # cobj = CMAC.new(derived_key, ciphermod=AES)
        # cobj.update(binascii.unhexlify('00000000000000000000000000000000'))
        # kcv = cobj.hexdigest()[0:6].upper()
        # print('Derived Key on Desktop - Calculated KCV(CMAC): ' + cobj.hexdigest()[0:6])

        return derived_key

    @staticmethod
    def generate_pin_block_iso_4(derived_key, pin, pan):
        return binascii.hexlify(psec.pinblock.encipher_pinblock_iso_4(derived_key, pin, pan)).decode().upper()

    @staticmethod
    def get_apc_ecdh_parameters(ca_key_arn, signed_client_certificate, shared_info):
        return {
            "WrappedKeyMaterial": {"DiffieHellmanSymmetricKey": {"CertificateAuthorityPublicKeyIdentifier": ca_key_arn,
                                                                 "KeyAlgorithm": "AES_128",
                                                                 "KeyDerivationFunction": "NIST_SP800",
                                                                 "KeyDerivationHashAlgorithm": "SHA_512",
                                                                 "PublicKeyCertificate": base64.b64encode(
                                                                     signed_client_certificate.encode('ascii')).decode(
                                                                     'ascii'),
                                                                 "SharedInformation": binascii.hexlify(
                                                                     shared_info).decode().upper()}}}

    @staticmethod
    def sign_with_private_ca(ca_arn, csr, validity, template="arn:aws:acm-pca:::template/EndEntityCertificate/V1"):
        """
        Signs the client-side ECDH Key with AWS Private CA and returns the Certificate and Certificate Chain
        :param validity:
        :param ca_arn:
        :param csr: Certificate Signing Request
        :param template: Template ARN to use for the certificate
        :return:
        """

        response = private_ca_client.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr,
            TemplateArn=template,
            SigningAlgorithm='SHA256WITHECDSA',
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
