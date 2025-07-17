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
controlplane_client = boto3.client("payment-cryptography")
private_ca = boto3.client("acm-pca")

KEY_ALIAS_PREFIX = "pindemo-"
TAG_KEY = "pindemo"


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

def import_ca_key_to_apc(certificate_authority):
    key_arn = get_key_by_alias("ca_key")
    if key_arn is None:
        print("Importing CA Key")
        key_arn = controlplane_client.import_key(Enabled=True, KeyMaterial={
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
        }, KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[{"Key":TAG_KEY, "Value":"1"}])['Key']['KeyArn']
        create_alias("ca_key", key_arn)

    return key_arn


def get_key_by_alias(alias):
    alias = "alias/%s%s" % (KEY_ALIAS_PREFIX, alias)
    try:
        answer = controlplane_client.get_alias(AliasName=alias)
        return answer["Alias"]["KeyArn"]
    except:
        return None


def create_alias(alias, key_arn):
    alias = "alias/%s%s" % (KEY_ALIAS_PREFIX, alias)
    controlplane_client.create_alias(AliasName=alias, KeyArn=key_arn)


def apc_generate_pgk():
    alias = "pgk"
    key_arn = get_key_by_alias(alias)
    if key_arn is None:
        print("Creating new PGK")
        key_arn = controlplane_client.create_key(Exportable=True,
                                                 KeyAttributes={
                                                     "KeyAlgorithm": "TDES_2KEY",
                                                     "KeyUsage": "TR31_V2_VISA_PIN_VERIFICATION_KEY",
                                                     "KeyClass": "SYMMETRIC_KEY",
                                                     "KeyModesOfUse": {"Generate": True, "Verify": True}
                                                 },
                                                 Tags=[{"Key": TAG_KEY, "Value": "1"}])['Key']['KeyArn']
        create_alias(alias, key_arn)
    return key_arn


def apc_generate_pek():
    alias = "pek"
    key_arn = get_key_by_alias(alias)
    if key_arn is None:
        print("Creating new PEK")
        key_arn = controlplane_client.create_key(Exportable=True,
                                                 KeyAttributes={
                                                     "KeyAlgorithm": "TDES_3KEY",
                                                     "KeyUsage": "TR31_P0_PIN_ENCRYPTION_KEY",
                                                     "KeyClass": "SYMMETRIC_KEY",
                                                     "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True,
                                                                       "Unwrap": True}
                                                 },
                                                 Tags=[{"Key": TAG_KEY, "Value": "1"}])['Key']['KeyArn']

        create_alias(alias, key_arn)
    return key_arn


def create_certificate_authority():
    # create Certificate Authority for short-lived certificates
    ca_arn = private_ca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            'KeyAlgorithm': 'EC_secp521r1',
            'SigningAlgorithm': 'SHA512WITHECDSA',
            'Subject': {
                'CommonName': 'pindemo',
            },
        },
        CertificateAuthorityType='ROOT',
        UsageMode='SHORT_LIVED_CERTIFICATE'
    )['CertificateAuthorityArn']

    state = "CREATING"
    while state == "CREATING":
        time.sleep(1)
        state = private_ca.describe_certificate_authority(CertificateAuthorityArn=ca_arn)['CertificateAuthority'][
            'Status']
        print(state)
    return ca_arn


def create_private_ca():
    print("Creating AWS Private CA")
    cert_authority_arn = create_certificate_authority()
    print("Newly created Private CA ARN: %s" % cert_authority_arn)
    # add tag to CA
    private_ca.tag_certificate_authority(
        CertificateAuthorityArn=cert_authority_arn,
        Tags=[
            {
                'Key': TAG_KEY,
                'Value': '1'
            },
        ]
    )
    print("Getting root CA CSR")
    csr = private_ca.get_certificate_authority_csr(CertificateAuthorityArn=cert_authority_arn)['Csr']
    print("self-signing root CA CSR")
    certificate, chain = CryptoUtils.sign_with_private_ca(cert_authority_arn, csr, {
        'Value': 10,
        'Type': 'YEARS'
    }, template='arn:aws:acm-pca:::template/RootCACertificate/V1')
    print("Importing signed certificate as ROOT")
    private_ca.import_certificate_authority_certificate(CertificateAuthorityArn=cert_authority_arn,
                                                        Certificate=certificate)
    print("CA Setup complete")
    return cert_authority_arn


def find_or_create_private_ca():
    # find existing CA
    for ca in private_ca.list_certificate_authorities()['CertificateAuthorities']:
        if ca['Status'] == 'ACTIVE':
            # get ca tags
            tags = private_ca.list_tags(CertificateAuthorityArn=ca['Arn'])
            for tag in tags['Tags']:
                if tag['Key'] == TAG_KEY:
                    # if tag is present, use this CA
                    print("Found existing CA: %s" % ca['Arn'])
                    return ca['Arn']
    return create_private_ca()


def setup():
    ca_arn = find_or_create_private_ca()
    ca_certificate = private_ca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)['Certificate']
    ca_key_arn = import_ca_key_to_apc(ca_certificate)
    return ca_arn, ca_key_arn