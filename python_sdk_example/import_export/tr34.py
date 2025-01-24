import boto3

import base64
import secrets
import datetime
import binascii

from Crypto.Hash import SHA256
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization



OID_DES_EDE3_CBC = bytes.fromhex('2A864886F70D0307')
OID_AES_AES128_CBC = bytes.fromhex('608648016503040102')

OID_ENCRYPTION = OID_DES_EDE3_CBC
BLOCK_SIZE = 8

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



def construct_tr34_header(key_usage, mode_of_use, export_mode, key_algorithm='T', key_version_number='00',
                          optional_blocks='00'):
    """
    Constructs the TR34 header (which is the same as TR-31 header with the length ignored
    """
    version_id = 'D'
    length = '9999'  # ignored in tr-34

    header = version_id + length + key_usage + key_algorithm + mode_of_use + key_version_number + export_mode + optional_blocks + "00"
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


def generate_local_certificate_authority():
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
        .add_extension(
        x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=True, data_encipherment=True,
                      key_agreement=True, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
        critical=True) \
        .sign(private_key=kdh_ca_private_key, algorithm=hashes.SHA256())

    return kdh_ca_private_key, kdh_ca_certificate


def import_ca_certificate_into_apc(kdh_ca_certificate, apc_client):
    return apc_client.import_key(Enabled=True, KeyMaterial={
        'RootCertificatePublicKey': {
            'KeyAttributes': {
                'KeyAlgorithm': 'RSA_2048',
                'KeyClass': 'PUBLIC_KEY',
                'KeyModesOfUse': {
                    'Verify': True,
                },
                'KeyUsage': 'TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE',
            },
            'PublicKeyCertificate': base64.b64encode(
                kdh_ca_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8')
        }
    }, KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[])['Key']['KeyArn']


def generate_kdh_certificate(kdh_ca_private_key):
    kdh_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    kdh_public_key = kdh_private_key.public_key()

    # REFACTOR: move this as a function create_local_kdh_certificate
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
    return kdh_private_key, kdh_certificate


def generate_tr34_payload(clear_key_bytes, krd_certificate, kdh_certificate, kdh_private_key, tr34header):
    # Generate a TDES_3DES key

    # Generate a Nonce
    tr34_2pass_nonce = secrets.token_bytes(8)

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
    # Build TR-34 Key Block
    ###########################################################

    key_block_unpadded = encode_asn([(0x30, True, [
        (0x02, False, bytes.fromhex('01')),
        kdh_certificate_id_asn,
        (0x04, False, clear_key_bytes),
        (0x30, True, [
            (0x06, False, OID_PKCS7_DATA),
            (0x31, True, [
                (0x04, False, tr34header.encode())
            ])
        ])
    ])])

    key_block_pkcs_padding = b''
    if len(key_block_unpadded) % BLOCK_SIZE != 0:
        padding_length = BLOCK_SIZE - (len(key_block_unpadded) % BLOCK_SIZE)
        key_block_pkcs_padding = bytes.fromhex((str("{:02d}".format(padding_length))) * padding_length)
    key_block = key_block_unpadded + key_block_pkcs_padding

    ###########################################################
    # Generate ephemeral key and iv
    ###########################################################

    key_block_iv = secrets.token_bytes(BLOCK_SIZE)  # 8 for 3DES
    ephemeral_key = secrets.token_bytes(24)  # 24 for 3DES

    ###########################################################
    # Encrypt Key Block
    ###########################################################

    tr34_key_block_cipher = DES3.new(ephemeral_key, DES3.MODE_CBC, key_block_iv)

    encrypted_key_block = tr34_key_block_cipher.encrypt(key_block)

    ###########################################################
    # Encrypt ephemeral key
    ###########################################################

    ephermal_key_cipher = PKCS1_OAEP.new(
        RSA.importKey(krd_certificate.public_bytes(encoding=serialization.Encoding.PEM)),
        SHA256,
    )
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
                (0x06, False, OID_ENCRYPTION),
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
        (0x30, True, [
            (0x06, False, OID_PKCS7_DATA),
            (0x31, True, [
                (0x04, False, tr34header.encode())
            ])
        ]),
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
    return tr34_payload, tr34_2pass_nonce


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




def decode_tr34_key(key_material, krd_certificate, kdh_certificate, nonce, krd_private_key):
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

    tr34_payload = parse_asn(bytearray.fromhex(key_material))

    extracted_data = {}
    walk_asn1_structure(tr34_payload, TR_34_PAYLOAD_STRUCTURE, extracted_data)

    tr34_authentication_data_signature = extracted_data['tr34_authentication_data_signature']
    tr34_authentication_data_asn = extracted_data['tr34_authentication_data_asn']
    tr34_kdh_certificate_id_asn = extracted_data['kdh_certificate_id_asn']
    tr34_key_block_envelope = extracted_data['tr34_key_block_envelope']

    tr34_authentication_signed_data = encode_asn([(0x31, True, tr34_authentication_data_asn)])
    kdh_certificate.public_key().verify(bytes(tr34_authentication_data_signature), tr34_authentication_signed_data, padding.PKCS1v15(), hashes.SHA256())

    if encode_asn([tr34_kdh_certificate_id_asn]) != encode_asn([kdh_certificate_id_asn]):
        raise Exception("Mismatched KDH Cred Id.\n\tExpecting: %s\n\tFound: %s" % (encode_asn([tr34_kdh_certificate_id_asn]), encode_asn([kdh_certificate_id_asn])))

    extracted_auth_data = {}
    walk_asn1_structure(tr34_authentication_data_asn, TR_34_AUTHENTICATION_DATA_ASN, extracted_auth_data)

    tr31_header = extracted_auth_data['tr31_header']
    tr34_2pass_nonce = extracted_auth_data['tr34_2pass_nonce']
    tr34_envelope_digest = extracted_auth_data['tr34_envelope_digest']

    if SHA256.new(tr34_key_block_envelope).digest() != tr34_envelope_digest:
        raise Exception('Envelope digest does not match auth data digest')

    if tr34_2pass_nonce != nonce:
        raise Exception("Mismatched Nonce: %s\n\tFound: %s" % (tr34_2pass_nonce, nonce))

    extracted_envelope_data = {}
    tr34_envelope = parse_asn(tr34_key_block_envelope)
    walk_asn1_structure(tr34_envelope, TR_34_KEY_BLOCK_ENVELOPE, extracted_envelope_data)

    tr34_krd_certificate_id_asn = extracted_envelope_data['krd_certificate_id_asn']
    tr34_encrypted_ephermal_key = extracted_envelope_data['encrypted_ephermal_key']
    tr34_encrypted_key_block = extracted_envelope_data['encrypted_key_block']
    tr34_key_block_iv = extracted_envelope_data['key_block_iv']

    if encode_asn([tr34_krd_certificate_id_asn]) != encode_asn([krd_certificate_id_asn]):
        raise Exception("Mismatched KRD Cred Id.\n\tExpecting: %s\n\tFound: %s" % (encode_asn([tr34_krd_certificate_id_asn]), encode_asn([krd_certificate_id_asn])))

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

    if encode_asn([tr34_key_block_kdh_cred_id]) != encode_asn([kdh_certificate_id_asn]):
        raise Exception("Mismatched KRD Cred Id.\n\tExpecting: %s\n\tFound: %s" % (encode_asn([tr34_key_block_kdh_cred_id]).hex(), encode_asn([kdh_certificate_id_asn]).hex()))

    if exported_tr31_header != tr31_header:
        raise Exception("Mismatched KRD Cred Id.\n\tExpecting: %s\n\tFound: %s" % (exported_tr31_header, tr31_header))

    return (exported_key.hex().upper())

def calculate_kcv(clear_key_bytes):
    return DES3.new(clear_key_bytes, DES3.MODE_ECB).encrypt(bytes.fromhex('0000000000000000'))[:3].hex().upper()


def setup_local_ca(apc_client):
    # We generate a Local Certificate Authority to allow key import
    kdh_ca_private_key, kdh_ca_certificate = generate_local_certificate_authority()
    # We generate a key, signed by the Certificate Authority, to allow the import
    kdh_private_key, kdh_certificate = generate_kdh_certificate(kdh_ca_private_key)
    # We import the Certificate Authority into AWS Payment Cryptography
    kdh_ca_key_arn = import_ca_certificate_into_apc(kdh_ca_certificate, apc_client)
    return kdh_private_key, kdh_certificate, kdh_ca_key_arn


def import_tr_34(clear_key: str, export_mode: str, key_type: str, mode_of_use: str, algorithm, kdh_certificate,
                 kdh_private_key, kdh_ca_key_arn, apc_client):
    # We prep the key as bytes
    clear_key_bytes = binascii.unhexlify(clear_key.replace(" ", ""))

    # We begin an import by calling AWS Payment Cryptography getParametersForImport
    import_parameters_res = apc_client.get_parameters_for_import(
        KeyMaterialType='TR34_KEY_BLOCK',
        WrappingKeyAlgorithm='RSA_2048')
    import_token = import_parameters_res['ImportToken']
    krd_cert_base64 = import_parameters_res['WrappingKeyCertificate']
    krd_certificate = x509.load_pem_x509_certificate(base64.b64decode(krd_cert_base64))

    # We construct the TR-34 payload
    tr34header = construct_tr34_header(key_type, mode_of_use, export_mode, algorithm)
    tr34_payload, tr34_2pass_nonce = generate_tr34_payload(clear_key_bytes, krd_certificate, kdh_certificate,
                                                           kdh_private_key, tr34header)

    # Finally, we can import the key into AWS Payment Cryptography
    imported_symmetric_key_res = apc_client.import_key(
        Enabled=True,
        KeyMaterial={
            "Tr34KeyBlock": {
                'CertificateAuthorityPublicKeyIdentifier': kdh_ca_key_arn,
                'ImportToken': import_token,
                'KeyBlockFormat': 'X9_TR34_2012',
                'SigningKeyCertificate': base64.b64encode(
                    kdh_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8'),
                'WrappedKeyBlock': tr34_payload.hex().upper(),
                'RandomNonce': tr34_2pass_nonce.hex().upper(),
            }
        },
        KeyCheckValueAlgorithm='ANSI_X9_24', Tags=[]
    )

    # print('************************ DONE *****************')
    # print('Imported Key: ' + clear_key)
    # print('Key Arn: ' + imported_symmetric_key_res['Key']['KeyArn'])
    # print('Reported KCV: ' + imported_symmetric_key_res['Key']['KeyCheckValue'])
    # print('Calculated KCV: ' + calculate_kcv(clear_key_bytes))
    # print('Reported Type: ' + imported_symmetric_key_res['Key']['KeyAttributes']['KeyAlgorithm'])

    # return both key ARNs imported into APC, the KEK and the CA Key.
    return imported_symmetric_key_res['Key']['KeyArn']


def export_tr_34(key_arn, krd_ca_key_arn, krd_certificate, krd_private_key, apc_client):
    nonce = secrets.token_bytes(8)

    export_parameters_res = apc_client.get_parameters_for_export(
        KeyMaterialType='TR34_KEY_BLOCK',
        SigningKeyAlgorithm='RSA_2048'
    )
    kdh_certificate = x509.load_pem_x509_certificate(base64.b64decode((export_parameters_res['SigningKeyCertificate'])))

    export_res = apc_client.export_key(ExportKeyIdentifier=key_arn, KeyMaterial={
        'Tr34KeyBlock': {
            'CertificateAuthorityPublicKeyIdentifier': krd_ca_key_arn,
            'ExportToken': export_parameters_res['ExportToken'],
            'KeyBlockFormat': 'X9_TR34_2012',
            'RandomNonce': nonce.hex().upper(),
            'WrappingKeyCertificate': base64.b64encode(krd_certificate.public_bytes(encoding=serialization.Encoding.PEM)).decode('UTF-8')
        }
    })
    key_material = export_res['WrappedKey']['KeyMaterial']
    exported_key = decode_tr34_key(key_material, krd_certificate, kdh_certificate, nonce, krd_private_key)
    return exported_key