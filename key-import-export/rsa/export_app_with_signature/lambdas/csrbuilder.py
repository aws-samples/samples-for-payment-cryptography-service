import boto3
from asn1crypto import x509, csr, pem, algos
from oscrypto import asymmetric
import inspect
import os
import re
import sys
import textwrap
import json
import traceback
import cfnresponse

kms = boto3.client('kms')
s3_client = boto3.client('s3')

def lambda_handler(event, context):
    try:
        # Extract parameters from the event properties
        request_type = event['RequestType']

        if request_type == 'Create':
            COUNTRY_NAME = event['ResourceProperties']['COUNTRY_NAME']
            COMMON_NAME = event['ResourceProperties']['COMMON_NAME']
            LOCALITY_NAME = event['ResourceProperties']['LOCALITY_NAME']
            ORGANIZATION_NAME = event['ResourceProperties']['ORGANIZATION_NAME']
            STATE_OR_PROVINCE_NAME = event['ResourceProperties']['STATE_OR_PROVINCE_NAME']
            KMS_ARN = event['ResourceProperties']['KMS_ARN']
            RESULTS_BUCKET = event['ResourceProperties']['RESULTS_BUCKET']

            subject_dict = {
                "country_name": COUNTRY_NAME,
                "state_or_province_name": STATE_OR_PROVINCE_NAME,
                "locality_name": LOCALITY_NAME,
                "organization_name": ORGANIZATION_NAME,
                "common_name": COMMON_NAME
            }

            subject = x509.Name.build(subject_dict)

            # Create KMSCSRBuilder instance
            csr_builder = KMSCSRBuilder(subject, KMS_ARN)

            # Build the CSR
            certification_request = csr_builder.build_with_kms(KMS_ARN)

            # PEM encode the CSR
            pem_csr = pem_armor_csr(certification_request)

            # Convert byte string to regular string
            pem_csr_str = pem_csr.decode('utf-8')

            # Write the CSR to the S3 bucket
            s3_client.put_object(Bucket=RESULTS_BUCKET, Key='results/csr.pem', Body=pem_csr_str)

            # Return a success response without a physical resource ID
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "CSR written to S3")

        elif request_type == 'Delete':
            # No action needed for deletion
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "Resource deletion successful")

    except ValueError as ve:
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, str(ve))
    except boto3.exceptions.Boto3Error as be:
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, str(be))
    except Exception as e:
        # Log the full error for debugging
        print(f"Unexpected error: {str(e)}")
        print(traceback.format_exc())

        cfnresponse.send(event, context, cfnresponse.FAILED, {}, 'An unexpected error occurred')

def _writer(func):
    """
    Decorator for a custom writer, but a default reader
    """
    name = func.__name__
    return property(fget=lambda self: getattr(self, '_%s' % name), fset=func)

def pem_armor_csr(certification_request):
    """
    Encodes a CSR into PEM format
    """
    if not isinstance(certification_request, csr.CertificationRequest):
        raise TypeError(_pretty_message(
            '''
            certification_request must be an instance of
            asn1crypto.csr.CertificationRequest, not %s
            ''',
            _type_name(certification_request)
        ))

    return pem.armor(
        'CERTIFICATE REQUEST',
        certification_request.dump()
    )

class KMSCSRBuilder(object):
    _subject = None
    _KMS_ARN = None
    _hash_algo = None
    _basic_constraints = None
    _subject_alt_name = None
    _key_usage = None
    _extended_key_usage = None
    _other_extensions = None
    _kms_signature_algo = None

    _special_extensions = set([
        'basic_constraints',
        'subject_alt_name',
        'key_usage',
        'extended_key_usage',
    ])

    def __init__(self, subject, KMS_ARN):
        self.subject = subject
        self.KMS_ARN = KMS_ARN
        self.ca = False

        self._hash_algo = 'sha256'
        self._other_extensions = {}
        self._kms_signature_algo = 'RSASSA_PKCS1_V1_5_SHA_256'

    @_writer
    def subject(self, value):
        if not isinstance(value, x509.Name) and not isinstance(value, dict):
            raise TypeError(_pretty_message(
                '''
                subject must be an instance of asn1crypto.x509.Name or a dict,
                not %s
                ''',
                _type_name(value)
            ))

        if isinstance(value, dict):
            value = x509.Name.build(value)

        self._subject = value

    @_writer
    def KMS_ARN(self, value):
        try:
            PKresponse = kms.get_public_key(KeyId=value)
        except:
            print("Could not get PublicKey")

        if not PKresponse['KeyUsage'] == "SIGN_VERIFY":
            raise ValueError("KMS_ARN must be an ARN for a KMS Key with SIGN_VERIFY")
        
        rawPublicKey = PKresponse['PublicKey']
        definedPubKey = asymmetric.load_public_key(rawPublicKey)
        self._subject_public_key = definedPubKey.asn1
        self._KMS_ARN = value

    @_writer
    def hash_algo(self, value):
        if value not in set(['sha1', 'sha256', 'sha512']):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", "sha512", not %s
                ''',
                repr(value)
            ))
        self._hash_algo = value

    @_writer
    def kms_signature_algo(self, value):
        valid_algos = [
            'RSASSA_PSS_SHA_256', 
            'RSASSA_PSS_SHA_384', 
            'RSASSA_PSS_SHA_512',
            'RSASSA_PKCS1_V1_5_SHA_256',
            'RSASSA_PKCS1_V1_5_SHA_384',
            'RSASSA_PKCS1_V1_5_SHA_512',
            'ECDSA_SHA_256',
            'ECDSA_SHA_384',
            'ECDSA_SHA_512'
        ]

        if value not in valid_algos:
            raise ValueError(_pretty_message(
                '''
                kms_signature_algo must be supported by AWS KMS, not %s
                ''',
                repr(value)
            ))
        self._hash_algo = 'sha' + value[-3:]
        self._kms_signature_algo = value

    def build_with_kms(self, KMS_ARN):
        kms_algos = kms.describe_key(KeyId=KMS_ARN)['KeyMetadata']['SigningAlgorithms']
        if "RSASSA_PSS_SHA_256" in kms_algos:
            signature_algo = 'rsa'
        elif "ECDSA_SHA_256" in kms_algos:
            signature_algo = 'ecdsa'
        
        if "ecdsa" in signature_algo:
            signature_algorithm_id = {
                'algorithm': '%s_%s' % (self._hash_algo, signature_algo)
            }
            self.kms_signature_algo = '%s_%s' % ("ECDSA_SHA", self._hash_algo[-3:])
        elif "rsa" in signature_algo:
            if "PSS" in self._kms_signature_algo:
                signature_algorithm_id = algos.SignedDigestAlgorithm({
                    'algorithm': 'rsassa_pss',
                    'parameters': algos.RSASSAPSSParams({
                        'hash_algorithm': algos.DigestAlgorithm({
                            'algorithm': self._hash_algo
                        }),
                        'mask_gen_algorithm': algos.MaskGenAlgorithm({
                            'algorithm': 'mgf1',
                            'parameters': algos.DigestAlgorithm({
                                'algorithm': self._hash_algo
                            }),
                        }),
                        'salt_length': int(self._hash_algo[-3:])//8
                    })   
                })
                self.kms_signature_algo = '%s_%s' % ("RSASSA_PSS_SHA", self._hash_algo[-3:])
            else:   
                signature_algorithm_id = {
                    'algorithm': '%s_%s' % (self._hash_algo, signature_algo)
                }
                self.kms_signature_algo = '%s_%s' % ("RSASSA_PKCS1_V1_5_SHA", self._hash_algo[-3:])

        def _make_extension(name, value):
            return {
                'extn_id': name,
                'critical': self._determine_critical(name),
                'extn_value': value
            }

        extensions = []
        for name in sorted(self._special_extensions):
            value = getattr(self, '_%s' % name)
            if value is not None:
                extensions.append(_make_extension(name, value))

        for name in sorted(self._other_extensions.keys()):
            extensions.append(_make_extension(name, self._other_extensions[name]))

        attributes = []
        if extensions:
            attributes.append({
                'type': 'extension_request',
                'values': [extensions]
            })

        certification_request_info = csr.CertificationRequestInfo({
            'version': 'v1',
            'subject': self._subject,
            'subject_pk_info': self._subject_public_key,
            'attributes': attributes
        })

        signature = kms.sign(KeyId=KMS_ARN, SigningAlgorithm=self._kms_signature_algo, Message=certification_request_info.dump())['Signature']
        return csr.CertificationRequest({
            'certification_request_info': certification_request_info,
            'signature_algorithm': signature_algorithm_id,
            'signature': signature
        })

    def _determine_critical(self, name):
        if name == 'subject_alt_name':
            return len(self._subject) == 0

        if name == 'basic_constraints':
            return self.ca is True

        return {
            'subject_directory_attributes': False,
            'key_usage': True,
            'issuer_alt_name': False,
            'name_constraints': True,
            'certificate_policies': False,
            'policy_mappings': True,
            'policy_constraints': True,
            'extended_key_usage': False,
            'inhibit_any_policy': True,
            'subject_information_access': False,
            'tls_feature': False,
            'ocsp_no_check': False,
        }.get(name, False)

def _pretty_message(string, *params):
    """
    Takes a multi-line string and does the following:

    - dedents
    - converts newlines with text before and after into a single line
    - strips leading and trailing whitespace
    """
    output = textwrap.dedent(string)

    if output.find('\n') != -1:
        output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)

    if params:
        output = output % params

    output = output.strip()

    return output

def _type_name(value):
    """
    :param value:
        A value to get the object name of

    :return:
        A unicode string of the object name
    """
    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)