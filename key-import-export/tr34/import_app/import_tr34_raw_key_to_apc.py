

# python3 -m pip install boto3
# python3 -m pip install pycryptodome

import boto3

import time
import base64
import secrets
import datetime
import binascii
import logging
import argparse


from Crypto.Hash import SHA256, CMAC
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

from cryptography.x509.name import _ASN1Type



# un-comment to see debug logs for AWS SDK
#boto3.set_stream_logger('', logging.DEBUG)
#boto3.set_stream_logger('boto3.resources', logging.INFO)



OID_MGF1 = bytes.fromhex('2A864886F70D010108')
OID_SHA256 = bytes.fromhex('608648016503040201')

OID_DES_EDE3_CBC =   bytes.fromhex('2A864886F70D0307')
OID_AES_AES128_CBC = bytes.fromhex('608648016503040102')

OID_PKCS7_DATA = bytes.fromhex('2A864886F70D010701')
OID_RSAES_OEAP = bytes.fromhex('2A864886F70D010107')
OID_P_SPECIFIED = bytes.fromhex('2A864886F70D010109')
OID_CONTENT_TYPE = bytes.fromhex('2A864886F70D010903')
OID_MESSAGE_DIGEST = bytes.fromhex('2A864886F70D010904')
OID_RSA_ENCRYPTION = bytes.fromhex('2A864886F70D010101')
OID_PKCS7_SIGNED_DATA = bytes.fromhex('2A864886F70D010702')
OID_PKCS7_ENVELOPED_DATA = bytes.fromhex('2A864886F70D010703')
OID_PKCS_9_AT_RANDOM_NONCE = bytes.fromhex('2A864886F70D01091903')

KDH_CA_KEY_ALIAS = 'alias/tr34-key-import-kdh-ca'
IMPORT_KEY_ALIAS = 'alias/tr34-key-import'




def constructTr34Header(algo,keyType,modeOfUse,exportMode):
    """
    Constructs the TR34 header (which is the same as TR-31 header with the length ignored
    """
    versionID = 'D' #ignored in tr-34
    length = '9999' #ignored in tr-34


    header = versionID + length + keyType + algo + modeOfUse + "00" + exportMode + "0000"
    return header




###########################################################
# Some ASN1 Stuff
###########################################################

def parse_asn_header(data: bytes, offset=0):
    if len(data) < 2 + offset:
        raise Exception('Header too short')

    tag = data[offset]
    constructed = tag & 0x20 != 0

    length = int.from_bytes(data[offset + 1:offset + 2], 'big')
    length_of_length = length & 0x7F
    if length & 0x80 and len(data) < 2 + offset + length_of_length:
        raise Exception('Payload is too short to extract length at offset ' + str(offset))
    elif length & 0x80:
        length = int.from_bytes(data[offset + 2:offset + 2 + length_of_length], 'big')
    else:
        length_of_length = 0
    if len(data) < 2 + offset + length_of_length + length:
        raise Exception('Payload is too short at offset ' + str(offset))
    payload_offset = offset + 2 + length_of_length

    return (tag, constructed, payload_offset, length, 2 + length_of_length + length)

def parse_asn(data: bytes, offset=0, limit=-1):
    items = []

    if len(data) == 0 or limit >= 0 and offset >= limit:
        return items

    current_limit = limit
    if current_limit < 0:
        current_limit = len(data)
    current_offset = offset

    while current_offset < current_limit:
        (tag, constructed, payload_offset, payload_length, total_length) = parse_asn_header(data, current_offset)
        if not constructed:
            items.append((tag, False, data[payload_offset:payload_offset + payload_length]))
        else:
            items.append((tag, True, parse_asn(data, payload_offset, payload_offset + payload_length)))
        current_offset += total_length
    return items

def encode_asn(asn_data):
    buffer = b''

    for value in asn_data:
        child_data = value[2]
        if value[1]:
            child_data = encode_asn(value[2])

        buffer += value[0].to_bytes(1, 'big')
        length = len(child_data)
        if length > 0x7F:
            field_length = ((length.bit_length() + 7) // 8)
            buffer += (field_length | 0x80).to_bytes(1, 'big')
            buffer += length.to_bytes(field_length, 'big')
        else:
            buffer += length.to_bytes(1, 'big')
        buffer += child_data
    return buffer



    """
    Imports a TR34 payload into the AWS Payment Cryptography service given a clear text key. Given the use of clear keys and self signed 
    certificates this is meant for development purposes only. This assumes permissions to run relevant commands on the service.
    If run in offline mode (runMode = OFFLINE), then this script can be run without direct access to the service as well.
    """
def importTr34(runMode,clearKey,exportMode,algorithm,keyType,modeOfUse,region,krdCert="",bdkAliasName=None,deleteOldKeys=False):
    global KDH_CA_KEY_ALIAS


    if region==None or region == "":
        apc_client = boto3.client('payment-cryptography')
    else:
        apc_client = boto3.client('payment-cryptography',region_name=region)


    if bdkAliasName is not None:
        KDH_CA_KEY_ALIAS = bdkAliasName

    ###########################################################
    # Generate KDH Certificates
    ###########################################################

    kdh_ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    kdh_ca_public_key = kdh_ca_private_key.public_key()

    kdh_ca_certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])) \
        .not_valid_before(datetime.datetime.today() - datetime.timedelta(1, 0, 0)) \
        .not_valid_after(datetime.datetime.today() + datetime.timedelta(90, 0, 0)) \
        .serial_number(int(100)) \
        .public_key(kdh_ca_public_key) \
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(kdh_ca_public_key), critical=False) \
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True, data_encipherment=True, key_agreement=True, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True) \
        .sign(private_key=kdh_ca_private_key, algorithm=hashes.SHA256())

    kdh_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    kdh_public_key = kdh_private_key.public_key()

    kdh_certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])) \
        .not_valid_before(datetime.datetime.today() - datetime.timedelta(1, 0, 0)) \
        .not_valid_after(datetime.datetime.today() + datetime.timedelta(30, 0, 0)) \
        .serial_number(int(200)) \
        .public_key(kdh_public_key) \
        .sign(private_key=kdh_ca_private_key, algorithm=hashes.SHA256())



    #only needed for online mode
    if runMode != 'OFFLINE':
        kdh_ca_alias_res = None
        try:
            kdh_ca_alias_res = apc_client.get_alias(AliasName=KDH_CA_KEY_ALIAS)
        except apc_client.exceptions.ResourceNotFoundException:
            kdh_ca_alias_res = apc_client.create_alias(AliasName=KDH_CA_KEY_ALIAS)

        if 'KeyArn' in kdh_ca_alias_res['Alias']:
            apc_client.update_alias(AliasName=kdh_ca_alias_res['Alias']['AliasName'])
            keyDetails = apc_client.get_key(KeyIdentifier=kdh_ca_alias_res['Alias']['KeyArn'])
            if (keyDetails['Key']['KeyState'] == 'CREATE_COMPLETE'):
                apc_client.delete_key(KeyIdentifier=kdh_ca_alias_res['Alias']['KeyArn'], DeleteKeyInDays=3)

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
                'PublicKeyCertificate': base64.b64encode(kdh_ca_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8')
            }
        }, KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[])['Key']['KeyArn']
        
        try: 
            apc_client.get_alias(AliasName=KDH_CA_KEY_ALIAS) 
            apc_client.update_alias(AliasName=KDH_CA_KEY_ALIAS, KeyArn=kdh_ca_key_arn)
        except apc_client.exceptions.ResourceNotFoundException: 
            apc_client.create_alias(AliasName=KDH_CA_KEY_ALIAS, KeyArn=kdh_ca_key_arn)

        ###########################################################
        # Delete Key (if required)
        ###########################################################
        if deleteOldKeys:

            alias_res = None
            try:
                alias_res = apc_client.get_alias(AliasName=IMPORT_KEY_ALIAS)
            except apc_client.exceptions.ResourceNotFoundException:
                alias_res = apc_client.create_alias(AliasName=IMPORT_KEY_ALIAS)

            if 'KeyArn' in alias_res['Alias']:
                delete_key_arn = alias_res['Alias']['KeyArn']
                alias_res = apc_client.update_alias(AliasName=alias_res['Alias']['AliasName'])
                keyDetails = apc_client.get_key(KeyIdentifier=delete_key_arn)
                if (keyDetails['Key']['KeyState'] == 'CREATE_COMPLETE'):
                    apc_client.delete_key(KeyIdentifier=delete_key_arn, DeleteKeyInDays=3)




    ###########################################################
    # Generate a key
    ###########################################################
    if (clearKey == None or clearKey == ""):
        symmetric_key_binary = secrets.token_bytes(16)
    else:
        #TODO Validate input
        symmetric_key_binary = binascii.unhexlify(clearKey.replace(" ","")) #remove any spaces

    ###########################################################
    # Generate a Nonce
    ###########################################################

    tr34_2pass_nonce = secrets.token_bytes(8)

    ###########################################################
    # Fetch TR-34 Import Parameters
    ###########################################################

    if (runMode == "OFFLINE"):
        krd_cert_base64 = krdCert
    else:
        # RSA_3072 allows for an AES-128 ephemeral key to be used, extending TR-34 wrapped key support up to AES-128
        import_parameters_res = apc_client.get_parameters_for_import(
            KeyMaterialType='TR34_KEY_BLOCK',
            WrappingKeyAlgorithm='RSA_3072') 
        import_token = import_parameters_res['ImportToken']

        krd_cert_base64 = import_parameters_res['WrappingKeyCertificate'];



    krd_certificate = x509.load_pem_x509_certificate(base64.b64decode(krd_cert_base64))
    # HSMs may require this. But we pulled the cert out of the same Auth'd API so we trust the certificate without having to verify the chain.
    # krd_certificate_chain_pem = base64.b64decode(import_parameters_res['WrappingKeyCertificateChain']).hex()

    ###########################################################
    # Calculate TR-34 Identities
    ###########################################################

    krd_certificate_asn = parse_asn(krd_certificate.public_bytes(serialization.Encoding.DER))
    krd_certificate_serial_number_asn = krd_certificate_asn[0][2][0][2][1]
    krd_certificate_issuer_asn = krd_certificate_asn[0][2][0][2][3]
    krd_certificate_id_asn = (0x30, True, [krd_certificate_issuer_asn, krd_certificate_serial_number_asn])

    kdh_certificate_asn = parse_asn(kdh_certificate.public_bytes(serialization.Encoding.DER))
    kdh_certificate_serial_number_asn = kdh_certificate_asn[0][2][0][2][1]
    kdh_certificate_issuer_asn = kdh_certificate_asn[0][2][0][2][3]
    kdh_certificate_id_asn = (0x30, True, [kdh_certificate_issuer_asn, kdh_certificate_serial_number_asn])

    ###########################################################
    # Generate ephemeral key and iv
    ###########################################################

    # All key blocks may be protected with AES128-CBC-Pad, the purpose
    # of this validation is to demonstrate the use of both methods
    if algorithm == "A":
        key_block_encryption_oid = OID_AES_AES128_CBC
        key_block_encryption_block_size = AES.block_size
        ephemeral_key_size = 16
    else:
        key_block_encryption_oid = OID_DES_EDE3_CBC
        key_block_encryption_block_size = DES3.block_size
        ephemeral_key_size = 24

    key_block_iv = secrets.token_bytes(key_block_encryption_block_size) #8 for 3DES, #16 for AES
    ephemeral_key = secrets.token_bytes(ephemeral_key_size) #24 for 3DES3key, #16 for AES-128

    ###########################################################
    # Build TR-34 Key Block
    ###########################################################

    key_block_header_attr = (0x30, True, [
        (0x06, False, OID_PKCS7_DATA),
        (0x31, True, [
            (0x04, False, constructTr34Header(algorithm,keyType,modeOfUse,exportMode).encode())
        ])
    ])

    key_block_unpadded = encode_asn([(0x30, True, [
        (0x02, False, bytes.fromhex('01')),
        kdh_certificate_id_asn,
        (0x04, False, symmetric_key_binary),
        key_block_header_attr,
    ])])


    key_block_pkcs_padding = b''
    # Padding is always applied, even when the unpadded data matches a
    # block size multiple, to allow for unambiguous padding removal.
    padding_length = key_block_encryption_block_size - (len(key_block_unpadded) % key_block_encryption_block_size)
    key_block_pkcs_padding = bytes.fromhex((str("{:02x}".format(padding_length)))*padding_length)
    key_block = key_block_unpadded + key_block_pkcs_padding

    ###########################################################
    # Encrypt Key Block
    ###########################################################

    if key_block_encryption_oid == OID_AES_AES128_CBC:
        tr34_key_block_cipher = AES.new(ephemeral_key, AES.MODE_CBC, key_block_iv)
    else:
        tr34_key_block_cipher = DES3.new(ephemeral_key, DES3.MODE_CBC, key_block_iv)

    encrypted_key_block = tr34_key_block_cipher.encrypt(key_block)

    ###########################################################
    # Encrypt ephemeral key
    ###########################################################

    ephermal_key_cipher = PKCS1_OAEP.new(
        RSA.importKey(krd_certificate.public_bytes(encoding=serialization.Encoding.PEM)),
        SHA256,
    );
    encrypted_ephermal_key = ephermal_key_cipher.encrypt(ephemeral_key)

    ###########################################################
    # Build TR-34 Key Block Envelope
    ###########################################################

    tr34_key_block_envelope = encode_asn([
        (0x02, False, bytes.fromhex('00')),
        (0x31, True, [
            (0x30, True, [
                (0x02, False, bytes.fromhex('00')),
                krd_certificate_id_asn,
                (0x30, True, [
                    (0x06, False, OID_RSAES_OEAP),
                    (0x30, True, [
                        (0x30, True, [
                            (0x06, False, OID_SHA256),
                            (0x05, False, b'')
                        ]),
                        (0x30, True, [
                            (0x06, False, OID_MGF1),
                            (0x30, True, [
                                (0x06, False, OID_SHA256)
                            ])
                        ]),
                        (0x30, True, [
                            (0x06, False, OID_P_SPECIFIED),
                            (0x04, False, b'')
                        ])
                    ])
                ]),
                (0x04, False, encrypted_ephermal_key)
            ])
        ]),
        (0x30, True, [
            (0x06, False, OID_PKCS7_DATA),
            (0x30, True, [
                (0x06, False, key_block_encryption_oid),
                (0x04, False, key_block_iv),
                (0x80, False, encrypted_key_block)
            ])
        ])
    ])

    ###########################################################
    # Calculate TR-34 Envelope Data Checksum
    ###########################################################

    tr34_envelope_digest = SHA256.new(tr34_key_block_envelope).digest()

    ###########################################################
    # Generate the TR-34 Authentication Data
    ###########################################################


    tr34_authentication_data_asn = [
        (0x30, True, [
            (0x06, False, OID_CONTENT_TYPE),
            (0x31, True, [
                (0x06, False, OID_PKCS7_ENVELOPED_DATA)
            ])
        ]),
        (0x30, True, [
            (0x06, False, OID_PKCS_9_AT_RANDOM_NONCE),
            (0x31, True, [
                (0x04, False, tr34_2pass_nonce)
            ])
        ]),
        key_block_header_attr,
        (0x30, True, [
            (0x06, False, OID_MESSAGE_DIGEST),
            (0x31, True, [
                (0x04, False, tr34_envelope_digest)
            ])
        ])
    ]

    ###########################################################
    # Generate the TR-34 Authentication Data Signature
    ###########################################################

    tr34_authentication_data_signature = PKCS115_SigScheme(
        RSA.importKey(kdh_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption()))
    ).sign(SHA256.new(encode_asn([(0x31, True, tr34_authentication_data_asn)])))

    ###########################################################
    # Build the full TR-34 payload
    ###########################################################

    tr34_payload = encode_asn([
        (0x30, True, [
            (0x06, False, OID_PKCS7_SIGNED_DATA),
            (0xA0, True, [
                (0x30, True, [
                    (0x02, False, bytes.fromhex('01')),
                    (0x31, True, [
                        (0x30, True, [
                            (0x06, False, OID_SHA256)
                        ])
                    ]),
                    (0x30, True, [
                        (0x06, False, OID_PKCS7_ENVELOPED_DATA),
                        (0xA0, True, [
                            (0x04, False, tr34_key_block_envelope)
                        ])
                    ]),
                    (0x31, True, [
                        (0x30, True, [
                            (0x02, False, bytes.fromhex('01')),
                            kdh_certificate_id_asn,
                            (0x30, True, [
                                (0x06, False, OID_SHA256)
                            ]),
                            (0xA0, True, tr34_authentication_data_asn),
                            (0x30, True, [
                                (0x06, False, OID_RSA_ENCRYPTION),
                                (0x05, False, b'')
                            ]),
                            (0x04, False, tr34_authentication_data_signature)
                        ])
                    ])
                ])
            ])
        ])
    ])

    ###########################################################
    # Import the key
    ###########################################################
    if (runMode == "OFFLINE"):

        print("------------Offline import---------");
        print("KDH CA cert:",base64.b64encode(kdh_ca_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8'))
        print("TR-34 Payload:",tr34_payload.hex().upper())
        print("KDH Signing cert:",base64.b64encode(kdh_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8'))
        print("Nonce:",tr34_2pass_nonce.hex().upper())

    else:

        imported_symmetric_key_res = apc_client.import_key(
            Enabled=True,
            KeyMaterial={
                "Tr34KeyBlock": {
                    'CertificateAuthorityPublicKeyIdentifier': kdh_ca_key_arn,
                    'ImportToken': import_token,
                    'KeyBlockFormat': 'X9_TR34_2012',
                    'SigningKeyCertificate': base64.b64encode(kdh_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8'),
                    'WrappedKeyBlock': tr34_payload.hex().upper(),
                    'RandomNonce': tr34_2pass_nonce.hex().upper(),
                }
            },
            KeyCheckValueAlgorithm="CMAC" if algorithm == "A" else 'ANSI_X9_24', Tags=[]
        )
        try: 
            apc_client.get_alias(AliasName=IMPORT_KEY_ALIAS) 
            apc_client.update_alias(AliasName=IMPORT_KEY_ALIAS, KeyArn=imported_symmetric_key_res['Key']['KeyArn']) 
        except apc_client.exceptions.ResourceNotFoundException: 
            apc_client.create_alias(AliasName=IMPORT_KEY_ALIAS, KeyArn=imported_symmetric_key_res['Key']['KeyArn'])

        if algorithm == "A":
            calculated_kcv = CMAC.new(symmetric_key_binary, msg=bytes.fromhex('00'*AES.block_size), ciphermod=AES).digest()[:3].hex().upper()
        else:
            calculated_kcv = DES3.new(symmetric_key_binary, DES3.MODE_ECB).encrypt(bytes.fromhex('00'*DES3.block_size))[:3].hex().upper()

        print('************************ DONE *****************')
        print('Imported Key: ' + symmetric_key_binary.hex())
        print('Key Arn: ' + imported_symmetric_key_res['Key']['KeyArn'])
        print('Reported KCV: ' + imported_symmetric_key_res['Key']['KeyCheckValue'])
        print('Calculated KCV: ' + calculated_kcv)
        print('Reported Type: ' + imported_symmetric_key_res['Key']['KeyAttributes']['KeyAlgorithm'])

        return imported_symmetric_key_res['Key']['KeyArn'],IMPORT_KEY_ALIAS


if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='TR-34 Key Import Sample Code',
                                     description='Sample code to generate a TR-34 2012 non-CMS format and import it into AWS Payment Cryptography.  Clear keys up to AES-128 are supported, in the same way as RSA Wrap.  The application can be run in the default \
                        mode which will directly import the key into the service. Alternately, it can be run in offline mode where you specify the KRD X509 cert (in base64) \
                            and it will only produce the tr-34 payload but leave the importing up to you.',
                                     epilog='This is intended as sample code and comes with no warranty and is not intended for us with production keys.')
    parser.add_argument("--clearkey", help="Clear Text Key to import", default="8A8349794C9EE9A4C2927098F249FED6")
    parser.add_argument("--exportmode", "-e", help="Export Mode - E, S or N", default="E",choices=['E', 'S', 'N'])
    parser.add_argument("--algorithm", "-a", help="Algorithm of key - (T)DES or (A)ES", default="T", choices=['A', 'T'])
    parser.add_argument("--keytype", "-t", help="Key Type according to TR-31 norms. For instance K0, B0, etc", default="K0",choices=['K0', 'K1', 'B0', 'D0','P0','E0','E3','E6','E1','C0','E2'])
    parser.add_argument("--modeofuse", "-m", help="Mode of use according to TR-31 norms.  For instance B (encrypt/decrypt),X (derive key)", default="B",choices=['B', 'X', 'N','E','D','C','G','V'])
    parser.add_argument("--runmode", help="Run mode. APC will directly import will offline will only produce tr-34 payload", default="APC",choices=['APC', 'OFFLINE'])
    parser.add_argument("--krdcert", "-cert", help="KRD cert base64 encoded Only use for offline mode. This would be provided by KRD", default="")
    parser.add_argument("--region", "-r", help="AWS Region to run in", default="us-east-1",choices=['us-east-1', 'us-west-2'])
    parser.add_argument("--deleteoldkeys", "-d", help="Delete old keys", default=False,type=bool)


    args = parser.parse_args()

    print ("Sample code to generate a TR-34 2012 non-CMS format and import it into AWS Payment Cryptography")
    print ("Clear keys up to AES-128 are supported, in the same way as RSA Wrap.")
    print ("Can be run in the default mode where it generates the payload and directly makes all required service calls OR ")
    print ("Given the additional input of a KRD X509 cert, it will produce the appropriate payload to be imported at a later time.")

    print ("Key to import:",args.clearkey)
    print ("Export Mode:",args.exportmode)
    print ("Key Type:",args.keytype)
    print ("Key Mode of use:",args.modeofuse)
    print ("Key Algorithm:",args.algorithm)


    if (args.runmode == 'OFFLINE'):
        if args.krdcert == "":
            raise Exception('KRD Certificate (from getParametersForImport) should be provided in base64 format if using offline mode')
    else:
        print ("AWS Region:%s" % (args.region))

        importTr34(args.runmode,args.clearkey,args.exportmode,args.algorithm,args.keytype,args.modeofuse,args.region,args.krdcert,None,args.deleteoldkeys)

        print('')
        print('')
        print('If this key was a key encryption key (K0), use TR-31 to import subsequent keys.')