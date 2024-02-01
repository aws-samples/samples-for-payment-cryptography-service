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

Usage - python3 import_raw_key_into_apc_with_rsa_wrap.py
'''
import boto3
import botocore.session
import secrets
import argparse
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import base64
import binascii
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Cipher import DES3

service = 'payment-cryptography'
host = 'controlplane.payment-cryptography.us-east-1.amazonaws.com'
regionName = 'us-east-1'

session = botocore.session.Session()

config = session.get_scoped_config()
credentials = session.get_credentials()

region = config.get('region', regionName)

def DeleteKey(keyArn):
    apc_client = boto3.client('payment-cryptography',region_name=region)
    apc_client.delete_key(KeyIdentifier=keyArn, DeleteKeyInDays=3)

def GetParametersForImport():
    apc_client = boto3.client('payment-cryptography',region_name=region)
    import_parameters_res = apc_client.get_parameters_for_import(
        KeyMaterialType='KEY_CRYPTOGRAM',
        WrappingKeyAlgorithm='RSA_4096')
    
    responseDict = dict()
    responseDict["ImportToken"] = import_parameters_res['ImportToken']
    responseDict["WrappingKeyAlgorithm"] = import_parameters_res["WrappingKeyAlgorithm"]
    responseDict["WrappingKeyCertificateChain"] = import_parameters_res["WrappingKeyCertificateChain"]
    responseDict["WrappingKeyCertificate"] = import_parameters_res['WrappingKeyCertificate']
    return responseDict

def ImportRootCert(PublicKeyCertificate):
    apc_client = boto3.client('payment-cryptography',region_name=region)
    imported_symmetric_key_res = apc_client.import_key(
                Enabled=True,
                KeyCheckValueAlgorithm="CMAC", 
                KeyMaterial={
                    "RootCertificatePublicKey": {
                        "KeyAttributes": {
                            "KeyAlgorithm": "RSA_4096", 
                            "KeyClass": "PUBLIC_KEY", 
                            "KeyModesOfUse": {
                                "Decrypt": false, 
                                "DeriveKey": false, 
                                "Encrypt": false, 
                                "Generate": false, 
                                "NoRestrictions": false, 
                                "Sign": false, 
                                "Unwrap": false, 
                                "Verify": true, 
                                "Wrap": false
                            }, 
                            "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE"
                        }, 
                        "PublicKeyCertificate": PublicKeyCertificate
                    } 
                } 
            )
    return imported_symmetric_key_res["Key"]["KeyArn"]

def ImportKey(WrappedKey,ImportToken,KeyAlgorithm="AES_128",KeyModesOfUse='{"Decrypt": true, "DeriveKey": false, "Encrypt": true, "Generate": false,"NoRestrictions": false, "Sign": false, "Unwrap": true, "Verify": false, "Wrap": true}',KeyUsage="TR31_K0_KEY_ENCRYPTION_KEY",KCVType="CMAC"):
    apc_client = boto3.client('payment-cryptography',region_name=region)
    imported_symmetric_key_res = apc_client.import_key(
            Enabled=True,
            KeyMaterial={
                "KeyCryptogram": {
                "Exportable": True, 
                "ImportToken": ImportToken, 
                "KeyAttributes": {
                    "KeyAlgorithm": KeyAlgorithm, 
                    "KeyClass": "SYMMETRIC_KEY", 
                    "KeyModesOfUse": KeyModesOfUse, 
                    "KeyUsage": KeyUsage
                }, 
                "WrappedKeyCryptogram": WrappedKey, 
                "WrappingSpec": "RSA_OAEP_SHA_256"
            } 
            },
            KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[]
        )
    
    print('************************ DONE *****************')
    print('Key Arn: ' + imported_symmetric_key_res['Key']['KeyArn'])
    print('Reported KCV: ' + imported_symmetric_key_res['Key']['KeyCheckValue'])
    """ print('Calculated KCV: ' + DES3.new(symmetric_key_binary, DES3.MODE_ECB).encrypt(bytes.fromhex('0000000000000000'))[:3].hex().upper()) """
    print('Reported Type: ' + imported_symmetric_key_res['Key']['KeyAttributes']['KeyAlgorithm'])
    
    return imported_symmetric_key_res["Key"]["KeyArn"],imported_symmetric_key_res["Key"]["KeyCheckValue"]

def GenerateAes128SymmetricKey():
    ephemeral_key = secrets.token_bytes(16)
    return ephemeral_key

def GenerateAesKcv(key):
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(binascii.unhexlify('00000000000000000000000000000000'))
    kcv = cobj.hexdigest()[0:6].upper()
    return kcv

def GenerateTdes_2Key_SymmetricKey():
    ephemeral_key = secrets.token_bytes(16)
    return ephemeral_key

def GenerateTdesKcv(key):
    kcv = DES3.new(key, DES3.MODE_ECB).encrypt(bytes.fromhex('0000000000000000'))[:3].hex().upper()
    return kcv

def WrapKey(wrappingCert,keyToWrap):
    wrappingCert = x509.load_pem_x509_certificate(base64.b64decode(wrappingCert))
    publicKey = wrappingCert.public_key()

    encrypted = publicKey.encrypt(
        keyToWrap,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return binascii.hexlify(encrypted).decode("UTF-8").upper()

########################################################################

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--action", help="Actions this script can perform",choices={"generateWrappingKey","importKey","demo"},default="demo")

    parser.add_argument("--wrappedKey", "-w", help="Wrapped Key to import in RSA cryptogram format", default="")
    parser.add_argument("--importToken", "-t", help="Pointer to key to unwrap key with",default="")

    args = parser.parse_args()

    if args.action == 'generateWrappingKey':
         print("Generating a wrapping key.  Export your key using this wrapping key and then call with action=importKey")
         print(GetParametersForImport())
    elif args.action == 'demo':
        if args.wrappedKey == "" or args.importToken == "":
            print("Demo mode.  Generates a wrapping key on the service, then generates a random symmetric key. This symmetric key is then encrypted using the wrapping key. \
                  Finally, the key is loaded into the service. The key is imported as a KEK but that can be modified.")
            print("Get parameters for import")
            importRes = GetParametersForImport()
            importToken = importRes["ImportToken"]
            wrappingKeyAlgorithm = importRes["WrappingKeyAlgorithm"]
            wrappingKeyCertificateChain = importRes["WrappingKeyCertificateChain"]
            wrappingKeyCertificate = importRes["WrappingKeyCertificate"]

            KeyAlgo = 'TDES_2KEY' #AES_128 or TDES_2KEY

            if KeyAlgo == 'AES_128':
                print("Generating AES-128 symmetric key")
                sampleKey = GenerateAes128SymmetricKey()
                sourceKcv = GenerateAesKcv(sampleKey)
                KcvType= "CMAC"
            elif KeyAlgo == 'TDES_2KEY':
                print("Generating 2 key TDES symmetric key")
                KcvType= "ANSI_X9_24"
                sampleKey = GenerateTdes_2Key_SymmetricKey()
                sourceKcv = GenerateTdesKcv(sampleKey)
            else:
                print("Invalid Key Algorithm for this sample code")
                sys.exit(1)

            print("Generated Key. Algo:",KeyAlgo,". Clear Key:",binascii.hexlify(sampleKey).decode()," Calculated KCV: ", sourceKcv)
            wrappedKey = WrapKey(wrappingKeyCertificate,sampleKey)
            print("Wrapped keyType",KeyAlgo,"Result:",wrappedKey)

            ImportKeyArn,importedKcv = ImportKey(wrappedKey,importToken,KeyAlgorithm=KeyAlgo,KCVType=KcvType,KeyModesOfUse={"DeriveKey": True},KeyUsage="TR31_B0_BASE_DERIVATION_KEY")
            print("Done - Imported Key Cryptogram:",ImportKeyArn,"KCV:",importedKcv) 
            print("KCV Matches?",importedKcv==sourceKcv)
    else:
        if args.wrappedKey == "" or args.importToken == "":
            print("Import Token and wrappedKey required for importKey")
            sys.exit(1)
        ImportKeyArn = ImportKey(args.wrappedKey,args.importToken)
        print("Step #1 - Imported Key Cryptogram:",ImportKeyArn) 