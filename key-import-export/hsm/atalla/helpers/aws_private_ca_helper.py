import boto3
import time
from botocore.exceptions import ClientError

TAG_KEY = "APC_TR34"
controlplane_client = boto3.client("payment-cryptography")
private_ca = boto3.client("acm-pca")

def create_certificate_authority():
    # create Certificate Authority for short-lived certificates
    ca_arn = private_ca.create_certificate_authority(
        CertificateAuthorityConfiguration={
            'KeyAlgorithm': 'RSA_2048',
            'SigningAlgorithm': 'SHA256WITHRSA',
            'Subject': {
                'Country': 'US',
                'Organization': 'AWS Samples',
                'OrganizationalUnit': 'APC',
                'State': 'CA',
                'CommonName': 'AWS Samples',
            }
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
                'Value': 'Sample'
            },
        ]
    )
    print("Getting root CA CSR")
    csr = private_ca.get_certificate_authority_csr(CertificateAuthorityArn=cert_authority_arn)['Csr']
    print("self-signing root CA CSR")
    certificate, chain = sign_with_private_ca(cert_authority_arn, csr, {
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
                    return ca['Arn']
    return create_private_ca()

def issue_certificate(csr_content):
    """
    Issues a certificate using AWS Private CA
    
    Args:
        ca_arn (str): ARN of the private CA
        csr_file_path (str): Path to the CSR file
    
    Returns:
        str: Certificate ARN if successful, None otherwise
    """
    try:
        # Create ACM PCA client
        acmpca_client = boto3.client('acm-pca')
        ca_arn = find_or_create_private_ca()
        # Request to issue certificate
        response = acmpca_client.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr_content,
            SigningAlgorithm='SHA256WITHRSA',
            Validity={
                'Value': 7,
                'Type': 'DAYS'
            },
            TemplateArn='arn:aws:acm-pca:::template/EndEntityCertificate/V1'
        )
        
        certificate_arn = response['CertificateArn']
        
        # Wait for certificate to be issued
        waiter = acmpca_client.get_waiter('certificate_issued')
        waiter.wait(
            CertificateAuthorityArn=ca_arn,
            CertificateArn=certificate_arn
        )
        
        # Get the issued certificate
        response = acmpca_client.get_certificate(
            CertificateAuthorityArn=ca_arn,
            CertificateArn=certificate_arn
        )
        
        certificate = response['Certificate']
        certificate_chain = response['CertificateChain']
        
        """ # Save the certificate and chain to files
        with open('certificate.pem', 'w') as f:
            f.write(certificate)
        
        with open('certificate_chain.pem', 'w') as f:
            f.write(certificate_chain) """
            
        return certificate, certificate_chain
        
    except ClientError as e:
        print(f"Error issuing certificate: {e}")
        return None
    
def sign_with_private_ca(ca_arn, csr, validity, template="arn:aws:acm-pca:::template/EndEntityCertificate/V1"):
        """
        Signs the client-side Key with AWS Private CA and returns the Certificate and Certificate Chain
        :param validity:
        :param ca_arn:
        :param csr: Certificate Signing Request
        :param template: Template ARN to use for the certificate
        :return:
        """
        client = boto3.client('acm-pca')
        response = client.issue_certificate(
            CertificateAuthorityArn=ca_arn,
            Csr=csr,
            TemplateArn=template,
            SigningAlgorithm='SHA256WITHRSA',
            Validity=validity
        )
        certificate_arn = response['CertificateArn']
        time.sleep(0.5)

        while 1:
            try:
                certificate_response = client.get_certificate(CertificateArn=certificate_arn,
                                                              CertificateAuthorityArn=ca_arn)
                if 'CertificateChain' in certificate_response:
                    chain = certificate_response['CertificateChain']
                else:
                    chain = None
                return certificate_response['Certificate'], chain
            except client.exceptions.RequestInProgressException:
                time.sleep(0.1)    

""" def setup():
    ca_arn = find_or_create_private_ca()
    #ca_certificate = private_ca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)['Certificate']
    print("CA Certificate: %s" % ca_arn)
    return ca_arn, ca_arn

setup() """