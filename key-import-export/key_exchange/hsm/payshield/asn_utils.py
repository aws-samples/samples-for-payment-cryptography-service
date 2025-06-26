import sys
from collections import namedtuple

AsnPayload = namedtuple(
    "AsnPayload", ["Tag", "Payload", "PayloadOffset", "PayloadLength", "TotalLength"]
)

OID_DES_EDE3_CBC = bytes.fromhex("2A864886F70D0307")
OID_AES_AES128_CBC = bytes.fromhex("608648016503040102")

OID_ENCRYPTION = OID_DES_EDE3_CBC


OID_MGF1 = bytes.fromhex("2A864886F70D010108")
OID_SHA256 = bytes.fromhex("608648016503040201")
OID_PKCS7_DATA = bytes.fromhex("2A864886F70D010701")
OID_RSAES_OEAP = bytes.fromhex("2A864886F70D010107")
OID_DES_EDE3_CBC = bytes.fromhex("2A864886F70D0307")
OID_P_SPECIFIED = bytes.fromhex("2A864886F70D010109")
OID_CONTENT_TYPE = bytes.fromhex("2A864886F70D010903")
OID_SIGNING_TIME = bytes.fromhex("2A864886F70D010905")
OID_MESSAGE_DIGEST = bytes.fromhex("2A864886F70D010904")
OID_RSA_ENCRYPTION = bytes.fromhex("2A864886F70D010101")
OID_PKCS7_SIGNED_DATA = bytes.fromhex("2A864886F70D010702")
OID_PKCS7_ENVELOPED_DATA = bytes.fromhex("2A864886F70D010703")
OID_PKCS_9_AT_RANDOM_NONCE = bytes.fromhex("2A864886F70D01091903")

TR_34_PAYLOAD_STRUCTURE = [
    (
        0x30,
        True,
        [
            (0x06, False, OID_PKCS7_SIGNED_DATA),
            (
                0xA0,
                True,
                [
                    (
                        0x30,
                        True,
                        [
                            (0x02, False, bytes.fromhex("01")),
                            (0x31, True, [(0x30, True, [(0x06, False, OID_SHA256)])]),
                            (
                                0x30,
                                True,
                                [
                                    (0x06, False, OID_PKCS7_ENVELOPED_DATA),
                                    (0xA0, True, [(0x04, False, "tr34_key_block_envelope")]),
                                ],
                            ),
                            (
                                0x31,
                                True,
                                [
                                    (
                                        0x30,
                                        True,
                                        [
                                            (0x02, False, bytes.fromhex("01")),
                                            "kdh_certificate_id_asn",
                                            (0x30, True, [(0x06, False, OID_SHA256)]),
                                            (0xA0, True, "tr34_authentication_data_asn"),
                                            (
                                                0x30,
                                                True,
                                                [
                                                    (0x06, False, OID_RSA_ENCRYPTION),
                                                    (0x05, False, b""),
                                                ],
                                            ),
                                            (0x04, False, "tr34_authentication_data_signature"),
                                        ],
                                    )
                                ],
                            ),
                        ],
                    )
                ],
            ),
        ],
    )
]

TR_34_AUTHENTICATION_DATA_ASN = [
    (
        0x30,
        True,
        [(0x06, False, OID_CONTENT_TYPE), (0x31, True, [(0x06, False, OID_PKCS7_ENVELOPED_DATA)])],
    ),
    (
        0x30,
        True,
        [
            (0x06, False, OID_PKCS_9_AT_RANDOM_NONCE),
            (0x31, True, [(0x04, False, "tr34_2pass_nonce")]),
        ],
    ),
    (0x30, True, [(0x06, False, OID_PKCS7_DATA), (0x31, True, [(0x04, False, "tr31_header")])]),
    (
        0x30,
        True,
        [(0x06, False, OID_MESSAGE_DIGEST), (0x31, True, [(0x04, False, "tr34_envelope_digest")])],
    ),
]

TR_34_KEY_BLOCK_ENVELOPE = [
    (0x02, False, bytes.fromhex("00")),
    (
        0x31,
        True,
        [
            (
                0x30,
                True,
                [
                    (0x02, False, bytes.fromhex("00")),
                    "krd_certificate_id_asn",
                    (
                        0x30,
                        True,
                        [
                            (0x06, False, OID_RSAES_OEAP),
                            (
                                0x30,
                                True,
                                [
                                    (0x30, True, [(0x06, False, OID_SHA256), (0x05, False, b"")]),
                                    (
                                        0x30,
                                        True,
                                        [
                                            (0x06, False, OID_MGF1),
                                            (0x30, True, [(0x06, False, OID_SHA256)]),
                                        ],
                                    ),
                                    (
                                        0x30,
                                        True,
                                        [(0x06, False, OID_P_SPECIFIED), (0x04, False, b"")],
                                    ),
                                ],
                            ),
                        ],
                    ),
                    (0x04, False, "encrypted_ephermal_key"),
                ],
            )
        ],
    ),
    (
        0x30,
        True,
        [
            (0x06, False, OID_PKCS7_DATA),
            (
                0x30,
                True,
                [
                    (0x06, False, OID_DES_EDE3_CBC),
                    (0x04, False, "key_block_iv"),
                    (0x80, False, "encrypted_key_block"),
                ],
            ),
        ],
    ),
]

TR_34_KEY_BLOCK = [
    (
        0x30,
        True,
        [
            (0x02, False, bytes.fromhex("01")),
            "kdh_certificate_id_asn",
            (0x04, False, "symmetric_key_binary"),
            (
                0x30,
                True,
                [(0x06, False, OID_PKCS7_DATA), (0x31, True, [(0x04, False, "tr31_header")])],
            ),
        ],
    )
]


def parse_asn_header(data: bytes, offset=0):
    if len(data) < 2 + offset:
        print("Error occured : Header too short")
        sys.exit(1)

    tag = data[offset]
    constructed = tag & 0x20 != 0

    length = int.from_bytes(data[offset + 1 : offset + 2], "big")
    length_of_length = length & 0x7F
    if length & 0x80 and len(data) < 2 + offset + length_of_length:
        print("Error occured : Payload is too short to extract length at offset " + str(offset))
        sys.exit(1)
    elif length & 0x80:
        length = int.from_bytes(data[offset + 2 : offset + 2 + length_of_length], "big")
    else:
        length_of_length = 0
    if len(data) < 2 + offset + length_of_length + length:
        print("Error occured : Payload is too short at offset " + str(offset))
        sys.exit(1)
    payload_offset = offset + 2 + length_of_length

    return AsnPayload(
        Tag=tag,
        Payload=constructed,
        PayloadOffset=payload_offset,
        PayloadLength=length,
        TotalLength=2 + length_of_length + length,
    )


def parse_asn(data: bytes, offset=0, limit=-1):
    items = []

    if len(data) == 0 or limit >= 0 and offset >= limit:
        return items

    current_limit = limit
    if current_limit < 0:
        current_limit = len(data)
    current_offset = offset

    while current_offset < current_limit:
        asn_payload = parse_asn_header(data, current_offset)
        tag = asn_payload.Tag
        constructed = asn_payload.Payload
        payload_offset = asn_payload.PayloadOffset
        payload_length = asn_payload.PayloadLength
        total_length = asn_payload.TotalLength
        if not constructed:
            items.append((tag, False, data[payload_offset : payload_offset + payload_length]))
        else:
            items.append(
                (tag, True, parse_asn(data, payload_offset, payload_offset + payload_length))
            )
        current_offset += total_length
    return items


def encode_asn(asn_data):
    buffer = b""

    for value in asn_data:
        child_data = value[2]
        if value[1]:
            child_data = encode_asn(value[2])

        buffer += value[0].to_bytes(1, "big")
        length = len(child_data)
        if length > 0x7F:
            field_length = (length.bit_length() + 7) // 8
            buffer += (field_length | 0x80).to_bytes(1, "big")
            buffer += length.to_bytes(field_length, "big")
        else:
            buffer += length.to_bytes(1, "big")
        buffer += child_data
    return buffer


def walk_asn1_structure(asn1_payload, asn1_schema, extracted_data, nesting=[]):
    if len(asn1_payload) != len(asn1_schema):
        print("Error occured : Length of structures is different in construct " + str(nesting))
        sys.exit(1)

    for i in range(0, len(asn1_payload)):
        inner = asn1_schema[i]

        if isinstance(inner, str):
            extracted_data[inner] = asn1_payload[i]
            continue

        inner_tag = asn1_schema[i][0]
        inner_constructed = asn1_schema[i][1]
        inner_data = asn1_schema[i][2]

        if inner_tag != asn1_payload[i][0]:
            print(
                "Error occured : Tags are different in construct %s element %s, expected is %s actual is %s"
                % (str(nesting), i, inner_tag, asn1_payload[i][0])
            )
            sys.exit(1)
        if inner_constructed != asn1_payload[i][1]:
            print(
                "Error occured : Structure is different in construct %s element %s, expected is %s actual is %s"
                % (str(nesting), i, inner_constructed, asn1_payload[i][1])
            )
            sys.exit(1)

        if isinstance(inner_data, str):
            extracted_data[inner_data] = asn1_payload[i][2]
            continue

        if inner_constructed:
            next_nesting = list(nesting)
            next_nesting.append(inner_tag)
            walk_asn1_structure(asn1_payload[i][2], inner_data, extracted_data, next_nesting)
        elif inner_data != asn1_payload[i][2]:
            print(
                "Error occured : Payload is different in construct %s element %s, expected is %s actual is %s"
                % (str(nesting), i, encode_asn(inner_data), encode_asn(asn1_payload[i][2]))
            )
            sys.exit(1)
