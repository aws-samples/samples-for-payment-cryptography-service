import boto3
import base64
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import logging

apc_client = boto3.client('payment-cryptography')
publicKeyCertificateAliasName = 'alias/tr34-key-import-kdh-ca'
#un-comment to see debug logs for AWS SDK
#boto3.set_stream_logger('', logging.DEBUG)
#boto3.set_stream_logger('boto3.resources', logging.INFO)

def verify_certificate_state(key_arn):
    """
    Verifies the state of the imported certificate
    
    Args:
        key_arn (str): ARN of the imported key
        
    Returns:
        bool: True if certificate is enabled and complete, False otherwise
    """
    try:
        response = apc_client.describe_key(
            KeyIdentifier=key_arn
        )
        
        key_state = response['Key']['KeyState']
        is_enabled = response['Key']['Enabled']
        
        if key_state == 'CREATE_COMPLETE' and is_enabled:
            print(f"Certificate status: {key_state}, Enabled: {is_enabled}")
            return True
        else:
            print(f"Certificate not ready. Status: {key_state}, Enabled: {is_enabled}")
            return False
            
    except ClientError as e:
        print(f"Error verifying certificate state: {e}")
        return False

def importPublicCACertificate(kdhPublicKeyCertificate):
    cert_data = kdhPublicKeyCertificate.encode('ascii')
    """ with open(publicKeyCertificatePath, 'rb') as cert_file:
        cert_data = cert_file.read() """
    # Load the certificate
    cert = x509.load_pem_x509_certificate(cert_data)
    
    #keyAlias = apc_client.get_alias(AliasName=publicKeyCertificateAliasName)
    
    kdh_ca_key_arn = apc_client.import_key(Enabled=True, KeyMaterial={
            'RootCertificatePublicKey': {
                'KeyAttributes': {
                    'KeyAlgorithm': 'RSA_2048',
                    'KeyClass': 'PUBLIC_KEY',
                    'KeyModesOfUse': {
                        'Verify': True,
                    },
                    'KeyUsage': 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
                },
                'PublicKeyCertificate': base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8')
            }
        }, KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[])['Key']['KeyArn']
    
    tagResponse = apc_client.tag_resource(
        ResourceArn= kdh_ca_key_arn,
        Tags=[
            {
                'Key': 'project',
                'Value': 'sample-atalla-tr34-exchange'
            },
        ]
    )
    """     aliasResponse = apc_client.create_alias(
            AliasName=publicKeyCertificateAliasName,
            KeyArn=kdh_ca_key_arn
        )
        print(f"aliasResponse: {aliasResponse}")
    """
    print(f"Imported KDH CA certificate into APC with key ARN: {kdh_ca_key_arn}")
    return kdh_ca_key_arn

def getKeyIfExixts(alias_name):
    try:
        keyAlias = apc_client.get_alias(AliasName=alias_name)
        
        # Check if response has the expected structure
        if (keyAlias and 
            isinstance(keyAlias, dict) and 
            'Alias' in keyAlias and 
            isinstance(keyAlias['Alias'], dict) and 
            'AliasName' in keyAlias['Alias']):
            
            return keyAlias['Alias']['AliasName']
        return None
        
    except apc_client.exceptions.NotFoundException:
        return None

def deleteKeyIfExixts(key_arn):
    try:
        payment_crypto = boto3.client('payment-cryptography')
    
        # Schedule the key for deletion
        response = payment_crypto.delete_key(
            KeyIdentifier=key_arn,
            DeleteKeyInDays=3
        )
    
        print(f"Key {key_arn} scheduled for deletion in 3 days")
        return True
        
    except payment_crypto.exceptions.NotFoundException:
        print(f"Key {key_arn} not found")
        return False
    except payment_crypto.exceptions.InvalidStateException:
        print(f"Key {key_arn} is in an invalid state for deletion")
        return False
    except Exception as e:
        print(f"Error deleting key: {str(e)}")
        return False
            
def importTR34Payload(tr34Payload,nonce,kdh_ca_key_arn,kdh_ca_certificate,importToken):
    print("Importing TR34 payload into APC ...")
    # Load the certificate
    cert = x509.load_pem_x509_certificate(kdh_ca_certificate.encode('ascii'))

    trt34_import_res = apc_client.import_key(
            Enabled=True,
            KeyMaterial={
                "Tr34KeyBlock": {
                    'CertificateAuthorityPublicKeyIdentifier': kdh_ca_key_arn,
                    'ImportToken': importToken,
                    'KeyBlockFormat': 'X9_TR34_2012',
                    'SigningKeyCertificate': base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8'),
                    'WrappedKeyBlock': tr34Payload,
                    'RandomNonce': nonce,
                }
            },
            KeyCheckValueAlgorithm='ANSI_X9_24',
            Tags= [{"Key": "Type", "Value" : "Atalla-Test"}]
        )
    KeyArn=trt34_import_res['Key']['KeyArn']
    print(f"Imported TR34 payload with key ARN: {KeyArn}")

def importTR31Payload(tr31_payload,wrappingKeyARN):
    print("Importing TR31 payload into ", tr31_payload, "APC with wrapping key ", wrappingKeyARN)
    keyMaterial={
        "Tr31KeyBlock": {
            'WrappedKeyBlock': tr31_payload.upper(),
            'WrappingKeyIdentifier': wrappingKeyARN
        }
    }

    try:
        imported_symmetric_key_res = apc_client.import_key(
        Enabled=True,
        KeyMaterial=keyMaterial)
        return imported_symmetric_key_res["Key"]["KeyArn"],imported_symmetric_key_res["Key"]["KeyCheckValue"]
    except Exception as e:
    # Capture error information
        output = "failed: " + str(e)
        detail = traceback.format_exc()
        print(output+" "+ detail)
        raise Exception("Error")   