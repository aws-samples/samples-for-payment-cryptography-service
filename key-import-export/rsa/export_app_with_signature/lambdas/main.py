import sys
import json
import base64
from datetime import datetime
import boto3
import requests
import os
import traceback
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509 import ocsp
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils as asymmetric_utils

def lambda_handler(event, context):
    try:

        # Get environment variables
        CERTIFICATE_S3_URI = os.environ.get('CERTIFICATE_S3_URI')
        ROOT_CERTIFICATE_S3_URI = os.environ.get('ROOT_CERTIFICATE_S3_URI')
        ICA_CERTIFICATE_S3_URI = os.environ.get('ICA_CERTIFICATE_S3_URI')
        DATA_TYPE = os.environ.get('DATA_TYPE')
        ENVIRONMENT = os.environ.get('ENVIRONMENT')
        KMS_KEY_ARN = os.environ.get('KMS_KEY_ARN')
        APC_KEY_ARN = os.environ.get('APC_KEY_ARN')
        APC_ROOT_KEY_ARN = os.environ.get('APC_ROOT_KEY_ARN')
        APC_ICA_KEY_ARN = os.environ.get('APC_ICA_KEY_ARN')
        S3_PREFIX = 'results/'
        S3_BUCKET = os.environ.get('S3_BUCKET')
        s3_client = boto3.client('s3')

        
        if not CERTIFICATE_S3_URI:
            print("Error: CERTIFICATE_S3_URI environment variable is not set")
            raise ValueError("CERTIFICATE_S3_URI is missing")

        parsed_uri = urlparse(CERTIFICATE_S3_URI)
        s3_bucket_name = parsed_uri.netloc
        s3_file_key = parsed_uri.path.lstrip('/')

        tmp_file_path = f"/tmp/{os.path.basename(s3_file_key)}"

        try:
            s3_client.download_file(s3_bucket_name, s3_file_key, tmp_file_path)
        except ClientError as e:
            print(f"Error downloading file from S3: {e}")
            raise

        with open(tmp_file_path, 'rb') as certificate_pem:
            cert_contents = certificate_pem.read()
            cert = x509.load_pem_x509_certificate(cert_contents)

        if ROOT_CERTIFICATE_S3_URI is None and APC_ROOT_KEY_ARN is None:
            print("Error: Neither ROOT_CERTIFICATE_S3_URI nor APC_ROOT_KEY_ARN environment variable is set")
            raise ValueError("Either ROOT_CERTIFICATE_S3_URI or APC_ROOT_KEY_ARN must be provided")

        if ROOT_CERTIFICATE_S3_URI:
            parsed_uri_root = urlparse(ROOT_CERTIFICATE_S3_URI)
            s3_bucket_name_root = parsed_uri_root.netloc
            s3_file_key_root = parsed_uri_root.path.lstrip('/')

            tmp_file_path_root = f"/tmp/{os.path.basename(s3_file_key_root)}"
            #print("ROOT INFO Bucket:",s3_bucket_name_root,"File Key Root",s3_file_key_root,"Tmp Location",tmp_file_path_root)

            try:
                s3_client.download_file(s3_bucket_name_root, s3_file_key_root, tmp_file_path_root)
            except ClientError as e:
                print(f"Error downloading file from S3: {e}")
                raise

            with open(tmp_file_path_root, 'rb') as cert_file:
                root_cert_contents = cert_file.read()
                root_cert = x509.load_pem_x509_certificate(root_cert_contents, default_backend())

        if not ICA_CERTIFICATE_S3_URI and not APC_ICA_KEY_ARN:
            print("Error: Neither ICA_CERTIFICATE_S3_URI nor APC_ICA_KEY_ARN environment variable is set")
            raise ValueError("Either ICA_CERTIFICATE_S3_URI or APC_ICA_KEY_ARN must be provided")

        if ICA_CERTIFICATE_S3_URI:
            parsed_uri_ica = urlparse(ICA_CERTIFICATE_S3_URI)
            s3_bucket_name_ica = parsed_uri_ica.netloc
            s3_file_key_ica = parsed_uri_ica.path.lstrip('/')

            tmp_file_path_ica = f"/tmp/{os.path.basename(s3_file_key_ica)}"

            try:
                s3_client.download_file(s3_bucket_name_ica, s3_file_key_ica, tmp_file_path_ica)
            except ClientError as e:
                print(f"Error downloading file from S3: {e}")
                raise

            with open(tmp_file_path_ica, 'rb') as ica_certificate_pem:
                ica_cert = ica_certificate_pem.read()
        
        # Check if Root Cert ARN & ICA Cert ARN are present, if not, import them
        if not APC_ROOT_KEY_ARN:
            APC_ROOT_KEY_ARN = import_public_key_to_payment_crypto(root_cert, ica_cert)
        else:
            print("Root Key ARN already found:", APC_ROOT_KEY_ARN)

        # Check if APC Key ARN is present, if not, create a new one
        if not APC_KEY_ARN:
            APC_KEY_ARN, kcv = generate_aes_128_key()
        else:
            kcv = get_key_check_value(APC_KEY_ARN)
        
        # Check if KMS key ARN is present, if not, create a new one
        if not KMS_KEY_ARN:
            KMS_KEY_ARN = generate_rsa_key_pair_in_kms()
        
        # Verify certificate
        if datetime.utcnow() > cert.not_valid_after or datetime.utcnow() < cert.not_valid_before:
            raise ValueError("Certificate has expired or is not yet valid")

        if not check_revocation_status(cert, root_cert):
            raise ValueError("Certificate has been revoked")

        expected_uid = get_expected_uid(ENVIRONMENT, DATA_TYPE)
        
        if not verify_custom_uid(cert, expected_uid):
            raise ValueError(f"Certificate does not have the expected UID: {expected_uid}")

        # Extract the public key
        public_key = cert.public_key()

        # Export AES_KEY1 using RSA-OAEP with RSA_KEY1 as the wrapping key
        enc_aes_key1 = export_aes_key(APC_KEY_ARN, cert_contents, APC_ROOT_KEY_ARN)

        # Prepend the appropriate key block header to ENC_AES_KEY1
        enc_aes_key1_with_header = prepend_key_block_header(enc_aes_key1, DATA_TYPE)

        # Sign enc_aes_key1_with_header using RSA_KEY2 in AWS KMS
        signature = sign_with_kms(enc_aes_key1_with_header, KMS_KEY_ARN)

        hex_signature = signature.hex()

        # Prepare the result
        result = {
            'APC_ROOT_KEY_ARN': APC_ROOT_KEY_ARN,
            'KMS_KEY_ARN': KMS_KEY_ARN,
            'APC_KEY_ARN': APC_KEY_ARN,
            'enc_aes_key1': enc_aes_key1,  # This is already a string
            'kcv': kcv,  # Assume this is already in the correct format
            'signature': hex_signature
        }


        # Optionally store results in S3
        if S3_BUCKET:
            s3_locations = store_results_in_s3(result, S3_BUCKET, S3_PREFIX)
            result['s3_locations'] = s3_locations
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'All operations completed successfully',
                'result': result
            })
        }
    except Exception as e:
        # Get the full traceback
        tb = traceback.extract_tb(sys.exc_info()[2])
        # Get the last frame (where the error occurred)
        last_frame = tb[-1]
        # Extract the filename, line number, and function name
        file_name = last_frame.filename
        line_number = last_frame.lineno
        func_name = last_frame.name

        error_message = f"Error in {file_name}, line {line_number}, in {func_name}: {str(e)}"
        
        print(error_message)  # Log the error message

        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Error processing request',
                'error': error_message,
                'traceback': traceback.format_exc()  # Include full traceback for more details
            })
        }

def get_key_check_value(key_arn):
    """
    Retrieves the key check value for a given key ARN using AWS Payment Cryptography.

    :param key_arn: The ARN of the key to retrieve the check value for.
    :return: The key check value if successful, None otherwise.
    """
    # Create a boto3 client for the payment-cryptography service
    client = boto3.client('payment-cryptography')

    try:
        # Call the getKey API
        response = client.get_key(
            KeyIdentifier=key_arn
        )
        # Extract and return the key check value
        key_check_value = response['Key']['KeyCheckValue']
        return key_check_value

    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def check_revocation_status(cert, root):
    try:
        aia_extension = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_server = next((desc.access_location.value for desc in aia_extension.value 
                            if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP), None)
        
        if not ocsp_server:
            print("OCSP server information not found in the certificate")
            return True  # Or handle this case as appropriate for your use case
    except x509.ExtensionNotFound:
        print("Authority Information Access extension not found in the certificate")
        return True  # Or handle this case as appropriate

    print("OCSP Server URL:", ocsp_server)

    root_ca = root

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, root_ca, hashes.SHA256())
    ocsp_request = builder.build()

    try:
        ocsp_response = requests.post(
            ocsp_server,
            data=ocsp_request.public_bytes(serialization.Encoding.DER),
            headers={'Content-Type': 'application/ocsp-request'},
            timeout=10
        )
        ocsp_response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error contacting OCSP server: {e}")
        return True  # Or handle this error as appropriate

    print("OCSP Response Status Code:", ocsp_response.status_code)
    print("OCSP Response Content:", ocsp_response.content[:100])  # Print first 100 bytes

    try:
        ocsp_response_parsed = ocsp.load_der_ocsp_response(ocsp_response.content)
    except ValueError as e:
        print(f"Error parsing OCSP response: {e}")
        return True  # Or handle this error as appropriate

    if ocsp_response_parsed.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        print(f"OCSP response not successful: {ocsp_response_parsed.response_status}")
        return True  # Or handle this case as appropriate

    if ocsp_response_parsed.certificate_status == ocsp.OCSPCertStatus.GOOD:
        return True
    elif ocsp_response_parsed.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        return False
    else:
        print(f"Unexpected OCSP status: {ocsp_response_parsed.certificate_status}")
        return True  # Or handle this case as appropriate

def get_expected_uid(environment, DATA_TYPE):
    uids = {
        'non-production': {
            'cardholder': 'identity:idms.group.9091073',
            'pin': 'identity:idms.group.9091071'
        },
        'production': {
            'cardholder': 'identity:idms.group.7814046',
            'pin': 'identity:idms.group.6509948'
        }
    }
    return uids[environment][DATA_TYPE]

def verify_custom_uid(cert, expected_uid):
    # Check in Subject field
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.USER_ID:
            if attr.value == expected_uid:
                return True
    
    # Check in Subject Alternative Name extension
    try:
        san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_extension.value:
            if isinstance(name, x509.UniformResourceIdentifier):
                if expected_uid in name.value:
                    return True
    except x509.ExtensionNotFound:
        pass

    return False

def import_public_key_to_payment_crypto(root_cert, ica_cert):
    payment_crypto_client = boto3.client('payment-cryptography')

    try:
        # Check if root_cert is already a certificate object
        if isinstance(root_cert, bytes):
            root_ca = x509.load_pem_x509_certificate(root_cert)
        else:
            root_ca = root_cert

        # Serialize the certificate object to PEM format, encode to base64, and decode to string
        root_certificate_pem = base64.b64encode(root_ca.public_bytes(encoding=serialization.Encoding.PEM)).decode('utf-8')
        
        response = payment_crypto_client.import_key(
            KeyMaterial={
                'RootCertificatePublicKey': {
                    'KeyAttributes': {
                        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
                        "KeyClass": "PUBLIC_KEY",
                        "KeyAlgorithm": "RSA_4096",
                        "KeyModesOfUse": {
                            "Verify": True
                        }
                    },
                    'PublicKeyCertificate': root_certificate_pem,
                }
            },
            KeyCheckValueAlgorithm='CMAC',
            Enabled=True,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': 'IMPORTED_ROOT_CA_CERT'
                },
                {
                    'Key': 'Description',
                    'Value': 'Imported Root certificate public key'
                }
            ]
        )

        rootARN = response['Key']['KeyArn']

        # Check if ica_cert is already a certificate object
        if isinstance(ica_cert, bytes):
            ica_ca = x509.load_pem_x509_certificate(ica_cert)
        else:
            ica_ca = ica_cert

        # Serialize the certificate object to PEM format, encode to base64, and decode to string
        ica_certificate_pem = base64.b64encode(ica_ca.public_bytes(encoding=serialization.Encoding.PEM)).decode('utf-8')

        response = payment_crypto_client.import_key(
            KeyMaterial={
                'TrustedCertificatePublicKey': {
                    'CertificateAuthorityPublicKeyIdentifier': rootARN,
                    'KeyAttributes': {
                        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
                        "KeyClass": "PUBLIC_KEY",
                        "KeyAlgorithm": "RSA_4096",
                        "KeyModesOfUse": {
                            "Verify": True
                        }
                    },
                    'PublicKeyCertificate': ica_certificate_pem,
                }
            },
            KeyCheckValueAlgorithm='CMAC',
            Enabled=True,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': 'IMPORTED_ICA_CERT'
                },
                {
                    'Key': 'Description',
                    'Value': 'Imported public key from intermediate CA certificate'
                }
            ]
        )

        intermediateARN = response['Key']['KeyArn']

        return intermediateARN

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"Error importing public key: {error_code} - {error_message}")
        raise
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        raise e

def generate_rsa_key_pair_in_kms():
    kms_client = boto3.client('kms')
    
    response = kms_client.create_key(
        Description='RSA_KEY2 for signing',
        KeyUsage='SIGN_VERIFY',
        KeySpec='RSA_2048',
        MultiRegion=False
    )
    
    return response['KeyMetadata']['Arn']

class KMSPrivateKey:
    def __init__(self, key_id):
        self.key_id = key_id
        self.client = boto3.client('kms')

    def sign(self, data, padding, algorithm):
        if not isinstance(algorithm, hashes.SHA256):
            raise ValueError("Only SHA256 is supported")

        response = self.client.sign(
            KeyId=self.key_id,
            Message=data,
            MessageType='DIGEST',
            SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
        )

        return response['Signature']

    def public_key(self):
        response = self.client.get_public_key(KeyId=self.key_id)
        return serialization.load_der_public_key(response['PublicKey'])

def generate_aes_128_key():
    payment_crypto_client = boto3.client('payment-cryptography')

    response = payment_crypto_client.create_key(
        KeyAttributes={
            "KeyUsage": "TR31_K0_KEY_ENCRYPTION_KEY",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyAlgorithm": "AES_128",
            "KeyModesOfUse": {
                "Encrypt": True,
                "Decrypt": True,
                "Wrap": True,
                "Unwrap": True,
                "Generate": False,
                "Sign": False,
                "Verify": False,
                "DeriveKey": False,
                "NoRestrictions": False
            }
        },
        KeyCheckValueAlgorithm='CMAC',
        Exportable=True,
        Enabled=True,
        Tags=[
            {
                'Key': 'Name',
                'Value': 'AES128_PSP_KEK'
            },
            {
                'Key': 'Description',
                'Value': 'AES 128 Key for encryption and key wrapping'
            }
        ]
    )

    # Extract the correct fields from the response
    key_arn = response['Key']['KeyArn']
    key_check_value = response['Key']['KeyCheckValue']

    return key_arn, key_check_value

def export_aes_key(aes_key_arn, certificate_pem, ICA_ROOT_KEY_ARN):
    payment_crypto_client = boto3.client('payment-cryptography')

    certificate_body = base64.b64encode(certificate_pem).decode('utf-8')

    response = payment_crypto_client.export_key(
        KeyMaterial={
            'KeyCryptogram': {
                'CertificateAuthorityPublicKeyIdentifier': ICA_ROOT_KEY_ARN,
                'WrappingKeyCertificate': certificate_body,
                'WrappingSpec': 'RSA_OAEP_SHA_256'
            }
        },
        ExportKeyIdentifier=aes_key_arn
    )

    return response['WrappedKey']['KeyMaterial']

def prepend_key_block_header(enc_aes_key, DATA_TYPE):
    if DATA_TYPE == 'cardholder':
        header = '3130303030545041454159'
    elif DATA_TYPE == 'pin':
        header = '3130303030545041454959'
    else:
        raise ValueError(f"Invalid DATA_TYPE: {DATA_TYPE}. Expected 'cardholder' or 'pin'.")
    
    return header + enc_aes_key

def sign_with_kms(data_to_sign, key_arn):
    kms_client = boto3.client('kms')
    
    response = kms_client.sign(
        KeyId=key_arn,
        Message=data_to_sign.encode(),
        MessageType='RAW',
        SigningAlgorithm='RSASSA_PKCS1_V1_5_SHA_256'
    )

    return response['Signature']

def store_results_in_s3(result, bucket, prefix):
    s3_client = boto3.client('s3')
    s3_locations = {}

    for key, value in result.items():
        if value is None:
            print(f"Skipping storing {key} in S3 as the value is None.")
            continue

        if key in ['APC_ROOT_KEY_ARN', 'KMS_KEY_ARN', 'APC_KEY_ARN']:
            # These are not files, just store them as text
            content = str(value)
        elif key in ['enc_aes_key1', 'kcv']:
            # These are already in hex format, store as is
            content = str(value)
        elif key == 'signature':
            content = value if isinstance(value, str) else base64.b64encode(value).decode('utf-8')
        else:
            # For other values, assume they're base64 encoded
            try:
                content = base64.b64decode(value).hex()
            except:
                content = str(value)

        file_key = f"{prefix}{key}.txt"
        try:
            s3_client.put_object(
                Bucket=bucket,
                Key=file_key,
                Body=content.encode('utf-8')
            )
            s3_locations[key] = f"s3://{bucket}/{file_key}"
        except ClientError as e:
            print(f"Error storing {key} in S3: {e}")
            raise
    return s3_locations