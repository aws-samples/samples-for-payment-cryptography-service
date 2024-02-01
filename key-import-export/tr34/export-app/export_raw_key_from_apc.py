# python3 -m pip install boto3
# python3 -m pip install pycryptodome
# python3 -m pip install cryptography

import secrets
import sys
import boto3

import time
import base64
import datetime

from Crypto.Hash import SHA256
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import argparse
import binascii


EXPORT_KEY_ALIAS = 'alias/tr34-key-export'
KRD_CA_KEY_ALIAS = 'alias/tr34-key-export-krd-ca'

def exportKey(keyArn, region):

    apc_client = boto3.client('payment-cryptography', region_name=region)


    OID_MGF1 = bytes.fromhex('2A864886F70D010108')
    OID_SHA256 = bytes.fromhex('608648016503040201')
    OID_PKCS7_DATA = bytes.fromhex('2A864886F70D010701')
    OID_RSAES_OEAP = bytes.fromhex('2A864886F70D010107')
    OID_DES_EDE3_CBC = bytes.fromhex('2A864886F70D0307')
    OID_P_SPECIFIED = bytes.fromhex('2A864886F70D010109')
    OID_CONTENT_TYPE = bytes.fromhex('2A864886F70D010903')
    OID_SIGNING_TIME = bytes.fromhex('2A864886F70D010905')
    OID_MESSAGE_DIGEST = bytes.fromhex('2A864886F70D010904')
    OID_RSA_ENCRYPTION = bytes.fromhex('2A864886F70D010101')
    OID_PKCS7_SIGNED_DATA = bytes.fromhex('2A864886F70D010702')
    OID_PKCS7_ENVELOPED_DATA = bytes.fromhex('2A864886F70D010703')
    OID_PKCS_9_AT_RANDOM_NONCE = bytes.fromhex('2A864886F70D01091903')

    TR_34_PAYLOAD_STRUCTURE = [
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
                            (0x04, False, 'tr34_key_block_envelope')
                        ])
                    ]),
                    (0x31, True, [
                        (0x30, True, [
                            (0x02, False, bytes.fromhex('01')),
                            'kdh_certificate_id_asn',
                            (0x30, True, [
                                (0x06, False, OID_SHA256)
                            ]),
                            (0xA0, True, 'tr34_authentication_data_asn'),
                            (0x30, True, [
                                (0x06, False, OID_RSA_ENCRYPTION),
                                (0x05, False, b'')
                            ]),
                            (0x04, False, 'tr34_authentication_data_signature')
                        ])
                    ])
                ])
            ])
        ])
    ]

    TR_34_AUTHENTICATION_DATA_ASN = [
        (0x30, True, [
            (0x06, False, OID_CONTENT_TYPE),
            (0x31, True, [
                (0x06, False, OID_PKCS7_ENVELOPED_DATA)
            ])
        ]),
        (0x30, True, [
            (0x06, False, OID_PKCS_9_AT_RANDOM_NONCE),
            (0x31, True, [
                (0x04, False, 'tr34_2pass_nonce')
            ])
        ]),
        (0x30, True, [
            (0x06, False, OID_PKCS7_DATA),
            (0x31, True, [
                (0x04, False, 'tr31_header')
            ])
        ]),
        (0x30, True, [
            (0x06, False, OID_MESSAGE_DIGEST),
            (0x31, True, [
                (0x04, False, 'tr34_envelope_digest')
            ])
        ])
    ]

    TR_34_KEY_BLOCK_ENVELOPE = [
        (0x02, False, bytes.fromhex('00')),
        (0x31, True, [
            (0x30, True, [
                (0x02, False, bytes.fromhex('00')),
                'krd_certificate_id_asn',
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
                (0x04, False, 'encrypted_ephermal_key')
            ])
        ]),
        (0x30, True, [
            (0x06, False, OID_PKCS7_DATA),
            (0x30, True, [
                (0x06, False, OID_DES_EDE3_CBC),
                (0x04, False, 'key_block_iv'),
                (0x80, False, 'encrypted_key_block')
            ])
        ])
    ]

    TR_34_KEY_BLOCK = [
        (0x30, True, [
            (0x02, False, bytes.fromhex('01')),
            'kdh_certificate_id_asn',
            (0x04, False, 'symmetric_key_binary'),
            (0x30, True, [
                (0x06, False, OID_PKCS7_DATA),
                (0x31, True, [
                    (0x04, False, 'tr31_header')
                ])
            ])
        ])]


    ###########################################################
    # Generate KRD Certificates
    ###########################################################

    krd_ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    krd_ca_public_key = krd_ca_private_key.public_key()

    krd_ca_certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Desktop HSM CA'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'The Organization'),
    ])) \
        .not_valid_before(datetime.datetime.today() - datetime.timedelta(1, 0, 0)) \
        .not_valid_after(datetime.datetime.today() + datetime.timedelta(90, 0, 0)) \
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
        .not_valid_before(datetime.datetime.today() - datetime.timedelta(1, 0, 0)) \
        .not_valid_after(datetime.datetime.today() + datetime.timedelta(30, 0, 0)) \
        .serial_number(int(200)) \
        .public_key(krd_public_key) \
        .sign(private_key=krd_ca_private_key, algorithm=hashes.SHA256())

    krd_ca_alias_res = None
    try:
        krd_ca_alias_res = apc_client.get_alias(AliasName=KRD_CA_KEY_ALIAS)
    except apc_client.exceptions.ResourceNotFoundException:
        krd_ca_alias_res = apc_client.create_alias(AliasName=KRD_CA_KEY_ALIAS)

    if 'KeyArn' in krd_ca_alias_res['Alias']:
        apc_client.update_alias(AliasName=krd_ca_alias_res['Alias']['AliasName'])
        apc_client.delete_key(KeyIdentifier=krd_ca_alias_res['Alias']['KeyArn'], DeleteKeyInDays=3)

    krd_ca_key_arn = apc_client.import_key(Enabled=True, KeyMaterial={
        'RootCertificatePublicKey': {
            'KeyAttributes': {
                'KeyAlgorithm': 'RSA_2048',
                'KeyClass': 'PUBLIC_KEY',
                'KeyModesOfUse': {
                    'Verify': True,
                },
                'KeyUsage': 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
            },
            'PublicKeyCertificate': base64.b64encode(krd_ca_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8')
        }
    }, KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[])['Key']['KeyArn']
    apc_client.update_alias(AliasName=KRD_CA_KEY_ALIAS, KeyArn=krd_ca_key_arn)

    ###########################################################
    # Generate Key (if required)
    ###########################################################

    if keyArn == None:
        alias_res = None
        try:
            alias_res = apc_client.get_alias(AliasName=EXPORT_KEY_ALIAS)
        except apc_client.exceptions.ResourceNotFoundException:
            alias_res = apc_client.create_alias(AliasName=EXPORT_KEY_ALIAS)

        if 'KeyArn' in alias_res['Alias']:
            print('Found existing random key to export from previous run')
            keyArn = alias_res['Alias']['KeyArn']
        else:
            print('Creating new random key')
            create_key_res = apc_client.create_key(Enabled=True, Exportable=True, KeyAttributes={
                'KeyAlgorithm': 'TDES_2KEY',
                'KeyClass': 'SYMMETRIC_KEY',
                'KeyModesOfUse': {
                    'Decrypt': True,
                    'Encrypt': True,
                    'Unwrap': True,
                    'Wrap': True
                },
                'KeyUsage': 'TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY'
            }, KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[])
            keyArn = create_key_res['Key']['KeyArn']
            apc_client.update_alias(AliasName=EXPORT_KEY_ALIAS, KeyArn=keyArn)
    else:
        try:
            apc_client.get_key(KeyIdentifier=keyArn)
        except apc_client.exceptions.ResourceNotFoundException:
            raise Exception("Key specified %s is not found in this region: %s" % (keyArn,region))
    ###########################################################
    # Export Key
    ###########################################################

    export_parameters_res = apc_client.get_parameters_for_export(
        KeyMaterialType='TR34_KEY_BLOCK',
        SigningKeyAlgorithm='RSA_2048'
    )
    kdh_certificate = x509.load_pem_x509_certificate(base64.b64decode((export_parameters_res['SigningKeyCertificate'])))

    nonce = secrets.token_bytes(8)

    export_res = apc_client.export_key(ExportKeyIdentifier=keyArn, KeyMaterial={
        'Tr34KeyBlock': {
            'CertificateAuthorityPublicKeyIdentifier': krd_ca_key_arn,
            'ExportToken': export_parameters_res['ExportToken'],
            'KeyBlockFormat': 'X9_TR34_2012',
            'RandomNonce': nonce.hex().upper(),
            'WrappingKeyCertificate': base64.b64encode(krd_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8')
        }
    })

    ###########################################################
    # Calculate the expected cred ids
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
    # Export Key
    ###########################################################

    tr34_payload = parse_asn(bytearray.fromhex(export_res['WrappedKey']['KeyMaterial']))

    extracted_data = {}
    walk_asn1_structure(tr34_payload, TR_34_PAYLOAD_STRUCTURE, extracted_data)

    tr34_authentication_data_signature = extracted_data['tr34_authentication_data_signature']
    tr34_authentication_data_asn = extracted_data['tr34_authentication_data_asn']
    tr34_kdh_certificate_id_asn = extracted_data['kdh_certificate_id_asn']
    tr34_key_block_envelope = extracted_data['tr34_key_block_envelope']

    print('Verifying Auth Data Signature\t', end='')
    tr34_authentication_signed_data = encode_asn([(0x31, True, tr34_authentication_data_asn)])
    kdh_certificate.public_key().verify(bytes(tr34_authentication_data_signature), tr34_authentication_signed_data, padding.PKCS1v15(), hashes.SHA256())
    print('OK')

    print('Verifying KDH Cred Id\t\t', end='')
    if encode_asn([tr34_kdh_certificate_id_asn]) != encode_asn([kdh_certificate_id_asn]):
        raise Exception("Mismatched KDH Cred Id.\n\tExpecting: %s\n\tFound: %s" % (encode_asn([tr34_kdh_certificate_id_asn]), encode_asn([kdh_certificate_id_asn])))
    print('OK')

    extracted_auth_data = {}
    walk_asn1_structure(tr34_authentication_data_asn, TR_34_AUTHENTICATION_DATA_ASN, extracted_auth_data)

    tr31_header = extracted_auth_data['tr31_header']
    tr34_2pass_nonce = extracted_auth_data['tr34_2pass_nonce']
    tr34_envelope_digest = extracted_auth_data['tr34_envelope_digest']

    print('Verifying Envelope Digest\t', end='')
    if SHA256.new(tr34_key_block_envelope).digest() != tr34_envelope_digest:
        raise Exception('Envelope digest does not match auth data digest')
    print('OK')

    print('Verifying Nonce\t\t\t', end='')
    if tr34_2pass_nonce != nonce:
        raise Exception("Mismatched Nonce: %s\n\tFound: %s" % (tr34_2pass_nonce, nonce))
    print('OK')

    extracted_envelope_data = {}
    tr34_envelope = parse_asn(tr34_key_block_envelope)
    walk_asn1_structure(tr34_envelope, TR_34_KEY_BLOCK_ENVELOPE, extracted_envelope_data)

    tr34_krd_certificate_id_asn = extracted_envelope_data['krd_certificate_id_asn']
    tr34_encrypted_ephermal_key = extracted_envelope_data['encrypted_ephermal_key']
    tr34_encrypted_key_block = extracted_envelope_data['encrypted_key_block']
    tr34_key_block_iv = extracted_envelope_data['key_block_iv']

    print('Verifying KRD Cred Id\t\t', end='')
    if encode_asn([tr34_krd_certificate_id_asn]) != encode_asn([krd_certificate_id_asn]):
        raise Exception("Mismatched KRD Cred Id.\n\tExpecting: %s\n\tFound: %s" % (encode_asn([tr34_krd_certificate_id_asn]), encode_asn([krd_certificate_id_asn])))
    print('OK')

    ephermal_key_cipher = PKCS1_OAEP.new(
        RSA.importKey(krd_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())),
        SHA256,
    );
    ephermal_key = ephermal_key_cipher.decrypt(tr34_encrypted_ephermal_key)

    tr34_key_block_cipher = DES3.new(ephermal_key, DES3.MODE_CBC, tr34_key_block_iv)

    exported_key_block = tr34_key_block_cipher.decrypt(tr34_encrypted_key_block)
    credential_id_and_key_length = parse_asn_header(exported_key_block)[4]
    credential_id_and_key = parse_asn(exported_key_block[:credential_id_and_key_length])

    extracted_key_block = {}
    walk_asn1_structure(credential_id_and_key, TR_34_KEY_BLOCK, extracted_key_block)

    exported_tr31_header = extracted_key_block['tr31_header']
    tr34_key_block_kdh_cred_id = extracted_key_block['kdh_certificate_id_asn']
    exported_key = extracted_key_block['symmetric_key_binary']

    print('Verifying Inner KDH Cred Id\t', end='')
    if encode_asn([tr34_key_block_kdh_cred_id]) != encode_asn([kdh_certificate_id_asn]):
        raise Exception("Mismatched KRD Cred Id.\n\tExpecting: %s\n\tFound: %s" % (encode_asn([tr34_key_block_kdh_cred_id]).hex(), encode_asn([kdh_certificate_id_asn]).hex()))
    print('OK')

    print('Verifying TR-31 Header\t\t', end='')
    if exported_tr31_header != tr31_header:
        raise Exception("Mismatched KRD Cred Id.\n\tExpecting: %s\n\tFound: %s" % (exported_tr31_header, tr31_header))
    print('OK')

    print('Key Arn: ' + keyArn)
    kcv = apc_client.get_key(KeyIdentifier=keyArn)['Key']['KeyCheckValue']

    print('Calculated KCV: ' + DES3.new(exported_key, DES3.MODE_ECB).encrypt(bytes.fromhex('0000000000000000'))[:3].hex().upper())
    print('TR31 Header: ' + exported_tr31_header.decode('utf-8'))
    return (kcv, exported_key.hex().upper())

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

def walk_asn1_structure(asn1_payload, asn1_schema, extracted_data, nesting=[]):
    if len(asn1_payload) != len(asn1_schema):
        raise Exception("Length of structures is different in construct " + str(nesting))

    for i in range(0, len(asn1_payload)):
        inner = asn1_schema[i]

        if type(inner) == str:
            extracted_data[inner] = asn1_payload[i]
            continue

        inner_tag = asn1_schema[i][0]
        inner_constructed = asn1_schema[i][1]
        inner_data = asn1_schema[i][2]

        if inner_tag != asn1_payload[i][0]:
            raise Exception("Tags are different in construct %s element %s, expected is %s actual is %s" % (str(nesting), i, inner_tag, asn1_payload[i][0]))
        if inner_constructed != asn1_payload[i][1]:
            raise Exception("Structure is different in construct %s element %s, expected is %s actual is %s" % (str(nesting), i, inner_constructed, asn1_payload[i][1]))

        if type(inner_data) == str:
            extracted_data[inner_data] = asn1_payload[i][2]
            continue

        if inner_constructed:
            next_nesting = list(nesting)
            next_nesting.append(inner_tag)
            walk_asn1_structure(asn1_payload[i][2], inner_data, extracted_data, next_nesting)
        elif inner_data != asn1_payload[i][2]:
            raise Exception("Payload is different in construct %s element %s, expected is %s actual is %s" % (str(nesting), i, encode_asn(inner_data), encode_asn(asn1_payload[i][2])))




if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog='TR-34 Key Export to Clear Key',
                                     description='This code will export a key and print the clear key using TR-34 export. This supports TDES keys only at this time. This \
                                        will export a specified key or if one isn\'t provided.',
                                     epilog='This is intended as sample code and comes with no warranty and is not intended for us with production keys.')
    parser.add_argument("--keyarn", help="Key to export")
    parser.add_argument("--region", "-r", help="Region to execute command in", default="us-east-1")

    args = parser.parse_args()

    print ("TR-34 Key Export to Clear Key")

    if args.keyarn != None:
        print ("Key to export:",args.keyarn)
        region = args.keyarn.split(":")[3] #imply region from keyARN if not provided
        print ("Region implied from keyARN",region)

    else:
        region = args.region
        print ("Region:",args.region)

    keyInfo = exportKey(args.keyarn, region)

    print('')
    print('')
    print('*************************************************')


    # key components are created by generating a random value and then XOR-ing it.  One key becomes the random value and one becomes the XOR result
    # repeat this again for 3 component keys. The # of components is not related to the key length

    two = secrets.token_bytes(16)

    keyBinary = binascii.unhexlify(keyInfo[1])

    one_xor_two = bytes(a ^ b for (a, b) in zip(keyBinary, two))

    print('Clear Key:%s' % keyInfo[1])
    print('KCV:%s' % keyInfo[0])

    print("Components:")
    print("\tComponent One:",binascii.hexlify(one_xor_two).decode().upper())
    print("\tComponent Two:",binascii.hexlify(two).decode().upper())


