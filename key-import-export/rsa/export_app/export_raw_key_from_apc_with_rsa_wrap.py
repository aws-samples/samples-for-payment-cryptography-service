'''
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The following api calls may be subject to https://aws.amazon.com/service-terms/ section 2 - Beta & Previews

Usage - export_raw_key_from_apc_with_rsa_wrap.py
'''

from datetime import datetime
from datetime import datetime

import botocore.session
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import argparse
import base64
import binascii
import boto3
from cryptography import x509
import binascii
from cryptography.hazmat.primitives import serialization
import base64
from Crypto.Hash import SHA256
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import binascii
from datetime import timedelta


regionName = 'us-east-1'
session = botocore.session.Session()
config = session.get_scoped_config()
credentials = session.get_credentials()
region = config.get('region', regionName)

def create_test_symmetric_key():
    apc_client = boto3.client('payment-cryptography',region_name=region)
    print('Creating new random key')
    create_key_res = apc_client.create_key(Enabled=True, Exportable=True, KeyAttributes={
        'KeyAlgorithm': 'TDES_3KEY',
        'KeyClass': 'SYMMETRIC_KEY',
        'KeyModesOfUse': {
            'Decrypt': True,
            'Encrypt': True,
            'Unwrap': True,
            'Wrap': True
        },
        'KeyUsage': 'TR31_K0_KEY_ENCRYPTION_KEY'
    }, KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[])
    key_to_export_wrapped = create_key_res['Key']['KeyArn']
    kcv = create_key_res['Key']['KeyCheckValue']
    keyAlgorithm = create_key_res['Key']['KeyAttributes']["KeyAlgorithm"]
    print(f'Created Key:{key_to_export_wrapped}. KCV:{kcv}')
    return key_to_export_wrapped,kcv,keyAlgorithm

def trust_krd_certs(krd_ca_certificate,krd_certificate):
    apc_client = boto3.client('payment-cryptography',region_name=region)
    krd_wrapped_ca_cert = apc_client.import_key(Enabled=True, KeyMaterial={
        'RootCertificatePublicKey': {
            'KeyAttributes': {
                'KeyAlgorithm': 'RSA_4096',
                'KeyClass': 'PUBLIC_KEY',
                'KeyModesOfUse': {
                    'Verify': True,
                },
                'KeyUsage': 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
            },
            'PublicKeyCertificate': base64.b64encode(krd_ca_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8')
        }
    }, KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[])['Key']['KeyArn']
    return krd_wrapped_ca_cert,None

def generate_krd_certs():

    #boto3.client('payment-cryptography')
    ###########################################################
    # Generate KRD Certificates
    ###########################################################

    krd_ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    krd_ca_public_key = krd_ca_private_key.public_key()

    krd_ca_certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])) \
        .not_valid_before(datetime.today() - timedelta(1, 0, 0)) \
        .not_valid_after(datetime.today() + timedelta(90, 0, 0)) \
        .serial_number(int(100)) \
        .public_key(krd_ca_public_key) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(krd_ca_public_key), critical=False) \
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True, data_encipherment=True, key_agreement=True, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True) \
        .sign(private_key=krd_ca_private_key, algorithm=hashes.SHA256())

    krd_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    krd_public_key = krd_private_key.public_key()

    krd_certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])) \
        .not_valid_before(datetime.today() - timedelta(1, 0, 0)) \
        .not_valid_after(datetime.today() + timedelta(30, 0, 0)) \
        .serial_number(int(200)) \
        .public_key(krd_public_key) \
        .sign(private_key=krd_ca_private_key, algorithm=hashes.SHA256())
    return krd_private_key,krd_ca_certificate,krd_certificate

def ExportKey(KeyToExportArn,RootKeyArn,PublicKeyCertificate):
    apc_client = boto3.client('payment-cryptography',region_name=region)
    export_res = apc_client.export_key(ExportKeyIdentifier=KeyToExportArn, KeyMaterial={
        'KeyCryptogram': {
            'CertificateAuthorityPublicKeyIdentifier': RootKeyArn,
            "WrappingSpec": "RSA_OAEP_SHA_256",
            'WrappingKeyCertificate': base64.b64encode(PublicKeyCertificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8')
        }
    })
    return export_res['WrappedKey']["KeyMaterial"]

def GenerateAesKcv(key):
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(binascii.unhexlify('00000000000000000000000000000000'))
    kcv = cobj.hexdigest()[0:6].upper()
    return kcv

def GenerateTdesKcv(key):
    kcv = DES3.new(key, DES3.MODE_ECB).encrypt(bytes.fromhex('0000000000000000'))[:3].hex().upper()
    return kcv

def GetKey(keyArn):
    apc_client = boto3.client('payment-cryptography',region_name=region)
    return apc_client.get_key(KeyIdentifier=keyArn)

def UnWrapKey(private_key,WrappedKeyHexBinary):
    decrypted = private_key.decrypt(binascii.a2b_hex(WrappedKeyHexBinary),
                padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
    return decrypted

##############################################################################

if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='RSA Wrapped Key Export Sample Code',
                                     description='Sample code to export a RSA wrapped key from AWS Payment Cryptography Service.',
                                     epilog='This is intended as sample code and comes with no warranty and is not intended for us with production keys.')
    parser.add_argument("--keyArn", help="ARN of symmetric key to export",)
    parser.add_argument("--rootKeyArn", help="ARN of root key that wraps/encrypts the symmetric key which is to be export",)
    args = parser.parse_args()

    if args.keyArn == None:
        print("No key passed. Generating new one.")
        SymmetricKeyArn,kcv,keyAlgorithm = create_test_symmetric_key()
    else:
        print("Passed key arn: ", args.keyArn)
        create_key_res = GetKey(args.keyArn)
        SymmetricKeyArn = create_key_res['Key']['KeyArn']
        kcv = create_key_res['Key']['KeyCheckValue']
        keyAlgorithm = create_key_res['Key']['KeyAttributes']["KeyAlgorithm"]
    print("Step #1 - Symmetric Key on APC to export:",SymmetricKeyArn,"KCV:",kcv)

    #SymmetricKeyArn,kcv,keyAlgorithm = create_test_symmetric_key()
    # you could also specify key on command line parameter
    #print("Step #1 - Create Symmetric Key on APC:",SymmetricKeyArn,"KCV:",kcv)

    krd_private_key,krd_ca_certificate,krd_certificate = generate_krd_certs()
    print("Step #2 - Generate Root and leaf CA")
    #krd_bytes = krd_certificate.public_bytes(serialization.Encoding.DER)

    RootKeyARN,LeafKeyArn = trust_krd_certs(krd_ca_certificate,krd_certificate)
    print("Step #3 - Import Root Key:",RootKeyARN)

    WrappedKey = ExportKey(SymmetricKeyArn,RootKeyARN,krd_certificate)
    print("Step #4 - Exported Key Cryptogram:",WrappedKey)

    #Step #6 - decrypt key using private key and then print as hex
    decryptedKey = UnWrapKey(krd_private_key,WrappedKey)
    print("Step #5 - Decrypted Key:",decryptedKey)

    #Step #6 - generate KCV and match it against exported KCV
    if keyAlgorithm == 'TDES_3KEY':
        decryptedKeyKcv = GenerateTdesKcv(decryptedKey)
        print("Step #6 TDES_3KEY KCV:" + decryptedKeyKcv)    
        print("KCV from created symmetric key matches with KCV from decrypted key: ", kcv.lower() == decryptedKeyKcv.lower())
    elif keyAlgorithm == 'AES_128':
        cobj = CMAC.new(decryptedKey, ciphermod=AES)
        cobj.update(binascii.unhexlify('00000000000000000000000000000000'))
        decryptedKeyKcv = cobj.hexdigest()[0:6].upper()
        print ('Step #6 - AES Key KCV: ' + cobj.hexdigest()[0:6].upper())
        print("KCV from created symmetric key matches with KCV from decrypted key: ", kcv.lower() == decryptedKeyKcv.lower())
    else:
        print("Invalid Key Algorithm for this sample code")
        sys.exit(1)

    #Step #7 - remove any keys created in this script
    #print("Step #7 - Final Step Deleting RootKey and SymmetricKey - if symmetric key was generated in this script")
    apc_client = boto3.client('payment-cryptography',region_name=region)
    if args.keyArn == None:
        deleteSymmetricKeyRes = apc_client.delete_key(KeyIdentifier=SymmetricKeyArn, DeleteKeyInDays=3)
        print("Deleted key " + deleteSymmetricKeyRes['Key']['KeyArn'])
    deleteRootKeyRes = apc_client.delete_key(KeyIdentifier=RootKeyARN, DeleteKeyInDays=3)
    print("Deleted root key " + deleteRootKeyRes['Key']['KeyArn'])
    # print(json.dumps(deleteRootKeyRes, indent=4, sort_keys=True, default=str)
    
