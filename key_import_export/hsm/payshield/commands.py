import binascii
import socket
import sys
from collections import namedtuple
from struct import pack
from typing import Tuple

from key_import_export.utils.enums import (
    AsymmetricKeyUsage,
    RsaKeyAlgorithm,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)

RSA_KEY_LENGTH = {
    RsaKeyAlgorithm.RSA_2048: "2048",
    RsaKeyAlgorithm.RSA_3072: "3072",
    RsaKeyAlgorithm.RSA_4096: "4096",
}

RSA_KEY_TYPE = {
    AsymmetricKeyUsage.KEY_AGREEMENT_KEY: "1",
    AsymmetricKeyUsage.VERIFY: "0",
    AsymmetricKeyUsage.SIGN: "0",
}

KEY_USAGE = {
    SymmetricKeyUsage.BDK: "B0",
    SymmetricKeyUsage.KEK: "K0",
    SymmetricKeyUsage.PEK: "P0",
    SymmetricKeyUsage.KBPK: "K1",
}

KEY_ALGORITHM = {
    SymmetricKeyAlgorithm.TDES_2KEY: "T2",
    SymmetricKeyAlgorithm.TDES_3KEY: "T3",
    SymmetricKeyAlgorithm.AES_128: "A1",
    SymmetricKeyAlgorithm.AES_192: "A2",
    SymmetricKeyAlgorithm.AES_256: "A3",
}

THALES_HEADER = "0000"
RANDOM_NONCE = "ABCDABCDABCDABCD"

Tr34Payload = namedtuple(
    "Tr34Payload", ["Tr34EnvelopeData", "Tr34SignatureData", "Tr34AuthData", "RandomNonce", "Kcv"]
)


class PayshieldCommands:
    """
    Commands are assuming that it is using KeyBlock LMK.
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def a0_command(self, key_algorithm: SymmetricKeyAlgorithm, key_usage: SymmetricKeyUsage):
        key_usage = KEY_USAGE[key_usage]
        key_algorithm = KEY_ALGORITHM[key_algorithm]

        command = "A00FFFS#" + key_usage + key_algorithm + "N00E00"

        result = self._send_receive(command)
        wrapped_key, kcv = self._decode_a0(bytes(result))
        return wrapped_key, kcv

    def ei_command(self, key_algorithm: RsaKeyAlgorithm, key_usage: AsymmetricKeyUsage):
        rsa_key_type = RSA_KEY_TYPE[key_usage]
        rsa_key_length = RSA_KEY_LENGTH[key_algorithm]

        command = "EI" + rsa_key_type + rsa_key_length + "02" + "#" + "00" + "00" + "&N"

        result = self._send_receive(command)
        public_key, private_key = self._decode_ei(bytes(result))
        return public_key, private_key

    def qe_command(self, public_key, private_key, key_algorithm):
        if key_algorithm.name in RsaKeyAlgorithm.__members__:
            signature_id = "01"
            public_key_encoding = "02"
            pan_mode_identifier = "01"
        else:
            signature_id = "02"
            public_key_encoding = "03"
            pan_mode_identifier = ""

        command = (
            "QE"
            + "00"
            + signature_id
            + public_key_encoding
            + "<"
            + public_key
            + private_key
            + ">"
            + pan_mode_identifier
            + "061Public Cert;Payshield Certificate;AWS Sample Org;Arlington;VA;US;"
        )

        result = self._send_receive(command)
        csr = self._decode_qe(bytes(result))
        return csr

    def a8_command(self, transport_key, kek):
        lmk_id = "00"

        # For TDES keys, set it as B and for AES set it as D.
        key_block_version = "B"
        command = "A8" + "FFF" + kek + transport_key + "R" + "%" + lmk_id + "!" + key_block_version
        result = self._send_receive(command)
        tr31_payload, kcv = self._decode_a8(bytes(result))

        return tr31_payload, kcv

    def b8_command(
        self, kdh_cred_id_der, krd_cred_id_der, kdh_private_key, krd_public_key, wrapped_key
    ):
        kdh_credential = "<" + kdh_cred_id_der + ">"
        krd_public_key = "<" + krd_public_key + ">"
        krd_credential_input = "<" + krd_cred_id_der + ">"
        nonce_input = "<" + RANDOM_NONCE + ">"
        tr34_version = "0"
        nonce_length = format(len(self._build_command(nonce_input)), "X").zfill(2)

        command = (
            "B8"
            + tr34_version
            + "FFF"
            + wrapped_key
            + kdh_credential
            + "000001"
            + krd_credential_input
            + krd_public_key
            + "00"
            + "99"
            + "FFFF<"
            + kdh_private_key
            + ">010"
            + nonce_length
            + nonce_input
            + "&N!D"
        )

        result = self._send_receive(command)
        tr34_payload = self._decode_b8(bytes(result))
        return tr34_payload

    def _decode_a0(self, response_to_decode: bytes):
        response_to_decode_str, msg_len, str_pointer = self._common_parser(response_to_decode)

        if response_to_decode_str[str_pointer : str_pointer + 2] == "00":
            wrapped_key = response_to_decode_str[6 + len(THALES_HEADER) : -6]
            kcv = response_to_decode_str[msg_len - 4 : msg_len + 2]
            return wrapped_key, kcv
        else:
            print("Error Response Received : {}".format(response_to_decode_str[str_pointer:]))
            sys.exit(1)

    def _decode_a8(self, response_to_decode: bytes):
        response_to_decode_str, msg_len, str_pointer = self._common_parser(response_to_decode)

        head_len = len(THALES_HEADER)
        if response_to_decode_str[str_pointer : str_pointer + 2] == "00":
            key = response_to_decode_str[6 + head_len : -6]
            kcv = response_to_decode_str[msg_len - 4 : msg_len + 2]
            if key[0] == "R":  # TR-31 - Thales prefixs with an R
                key = key[1:]
            return key, kcv
        else:
            print("Error Response Received : {}".format(response_to_decode_str[str_pointer:]))
            sys.exit(1)

    def _decode_b8(self, response_to_decode: bytes):
        response_to_decode_str, msg_len, str_pointer = self._common_parser(response_to_decode)

        if response_to_decode_str[str_pointer : str_pointer + 2] == "00":
            str_pointer = str_pointer + 2
            max_length_of_byte_one = 128

            length = 0
            length_of_length = int(
                str(bytes.hex(response_to_decode[str_pointer + 1 : str_pointer + 2])), 16
            )
            if length_of_length > max_length_of_byte_one:
                length_of_length = length_of_length - max_length_of_byte_one  # the actual length
                length = int(
                    str(
                        bytes.hex(
                            response_to_decode[str_pointer + 2 : str_pointer + 2 + length_of_length]
                        )
                    ),
                    16,
                )  # convert length from hex to decimal
            else:
                length = length_of_length
                length_of_length = 0

            tr34_auth_data = response_to_decode[
                str_pointer : str_pointer + 2 + length_of_length + length
            ]
            str_pointer = str_pointer + 2 + length_of_length + length
            kcv_length = 3
            kcv = bytes.hex(response_to_decode[str_pointer : str_pointer + kcv_length])
            str_pointer = str_pointer + kcv_length

            # Get Envelope data
            length = 0
            length_of_length = int(
                str(bytes.hex(response_to_decode[str_pointer + 1 : str_pointer + 2])), 16
            )
            if length_of_length > max_length_of_byte_one:
                length_of_length = length_of_length - max_length_of_byte_one  # the actual length
                length = int(
                    str(
                        bytes.hex(
                            response_to_decode[str_pointer + 2 : str_pointer + 2 + length_of_length]
                        )
                    ),
                    16,
                )  # convert length from hex to decimal
            else:
                length = length_of_length
                length_of_length = 0

            envelope_data = response_to_decode[
                str_pointer : str_pointer + 2 + length_of_length + length
            ]

            str_pointer = str_pointer + 2 + length_of_length + length  # move past envelope_data
            sig_length = int((response_to_decode_str[str_pointer : str_pointer + 4]))

            str_pointer = str_pointer + 4

            signature_data = response_to_decode[str_pointer : str_pointer + sig_length]

            if len(signature_data) != sig_length:
                print("Signature length is incorrect")
                sys.exit(1)

            return Tr34Payload(
                Tr34EnvelopeData=envelope_data,
                Tr34SignatureData=signature_data,
                Tr34AuthData=tr34_auth_data,
                RandomNonce=RANDOM_NONCE,
                Kcv=kcv,
            )
        else:
            print("Error Response Received : {}".format(response_to_decode_str[str_pointer:]))
            sys.exit(1)

    def _decode_ei(self, response_to_decode: bytes):
        response_to_decode_str, msg_len, str_pointer = self._common_parser(response_to_decode)

        if response_to_decode_str[str_pointer : str_pointer + 2] == "00":
            str_pointer = str_pointer + 2

            length = 0
            # in ASN, structure is 0 followed by length. If length >80 (hex, 128 decimal), then this indicates how many subsequent bytes are the length
            # so if <128, 2nd byte is length, otherwise keep reading for the actual length
            length_of_length = int(
                str(bytes.hex(response_to_decode[str_pointer + 1 : str_pointer + 2])), 16
            )
            max_length_of_byte_one = 128
            if length_of_length > max_length_of_byte_one:
                length_of_length = length_of_length - max_length_of_byte_one
                # the actual length
                length = int(
                    str(
                        bytes.hex(
                            response_to_decode[str_pointer + 2 : str_pointer + 2 + length_of_length]
                        )
                    ),
                    16,
                )
                # convert length from hex to decimal

            else:
                length = length_of_length
                length_of_length = 0

            rsa_public_key = response_to_decode[
                str_pointer : str_pointer + 2 + length_of_length + length
            ]
            str_pointer = str_pointer + 2 + length_of_length + length
            # move past RSA public key
            str_pointer = str_pointer + 4
            # Skip over FFFF for key blocks. This only works for key blocks.

            private_key_reference = response_to_decode[str_pointer:]

            return bytes.hex(rsa_public_key), bytes.hex(private_key_reference)
        else:
            print("Error Response Received : {}".format(response_to_decode_str[str_pointer:]))
            sys.exit(1)

    def _decode_qe(self, response_to_decode: bytes):
        response_to_decode_str, msg_len, str_pointer = self._common_parser(response_to_decode)

        if response_to_decode_str[str_pointer : str_pointer + 2] == "00":
            str_pointer = str_pointer + 2

            csr_length = int(response_to_decode_str[str_pointer : str_pointer + 4])
            str_pointer = str_pointer + 4

            csr = response_to_decode_str[str_pointer : str_pointer + csr_length]

            return csr
        else:
            print("Error Response Received : {}".format(response_to_decode_str[str_pointer:]))
            sys.exit(1)

    def _common_parser(self, response_to_decode: bytes) -> Tuple[str, int, int]:
        """
        Converts the response_to_decode in ascii, calculates the message size.
        """

        head_len = len(THALES_HEADER)
        msg_len = int.from_bytes(response_to_decode[:2], byteorder="big", signed=False)
        response_to_decode = response_to_decode.decode("ascii", "replace")
        str_pointer: int = 2
        str_pointer = str_pointer + head_len
        str_pointer = str_pointer + 2

        if msg_len != len(response_to_decode) - 2:  # -2 because of the length itself
            print(
                "Missing part of response.  Expected length %s but received %s"
                % (msg_len, len(response_to_decode) - 2)
            )
            sys.exit(1)

        return response_to_decode, msg_len, str_pointer

    def _send_receive(self, command) -> bytes:
        size = pack(">h", len(THALES_HEADER + command))
        message = bytes(size) + (THALES_HEADER + command).encode()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(8.000)

                sock.connect((self.host, self.port))
                host_command = self._build_command(THALES_HEADER + command)
                size = pack(">h", len(host_command))
                message = size + host_command
                sock.send(message)
                response = sock.recv(4096)

                return response
        except Exception as e:
            print("Failed to execute the HSM comamnd : {}".format(str(e)))
            sys.exit(1)

    def _build_command(self, command):
        h_command_parts = []
        i = 0
        while i < len(command):
            if command[i : i + 1] == "<":
                i += 1
                while i < len(command):
                    h_command_parts.append(binascii.a2b_hex(command[i : i + 2]))
                    i += 2
                    if command[i : i + 1] == ">":
                        i += 1
                        break
            else:
                h_command_parts.append(command[i].encode())
                i += 1

        return b"".join(h_command_parts)
