import binascii
import socket
import sys
from collections import namedtuple
from struct import pack
from typing import Tuple

from key_exchange.utils.enums import (
    AsymmetricKeyUsage,
    EccKeyAlgorithm,
    KeyDerivationFunction,
    RsaKeyAlgorithm,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)

RSA_KEY_LENGTH = {
    RsaKeyAlgorithm.RSA_2048: "2048",
    RsaKeyAlgorithm.RSA_3072: "3072",
    RsaKeyAlgorithm.RSA_4096: "4096",
}

ECC_KEY_ALGORITHM = {
    EccKeyAlgorithm.ECC_NIST_P256: "00",
    EccKeyAlgorithm.ECC_NIST_P384: "01",
    EccKeyAlgorithm.ECC_NIST_P521: "02",
}

RSA_KEY_TYPE = {
    AsymmetricKeyUsage.KEY_AGREEMENT_KEY: "1",
    AsymmetricKeyUsage.VERIFY: "0",
    AsymmetricKeyUsage.SIGN: "0",
}

ECC_KEY_TYPE = {
    AsymmetricKeyUsage.KEY_AGREEMENT_KEY: "X",
    AsymmetricKeyUsage.VERIFY: "S",
    AsymmetricKeyUsage.SIGN: "S",
}

KEY_USAGE = {
    SymmetricKeyUsage.BDK: "B0",
    SymmetricKeyUsage.KEK: "K0",
    SymmetricKeyUsage.PEK: "P0",
    SymmetricKeyUsage.KBPK: "K1",
}

KEY_USAGE_VARIANT = {
    SymmetricKeyUsage.BDK: "009",
    SymmetricKeyUsage.KEK: "000",
    SymmetricKeyUsage.PEK: "001",
    SymmetricKeyUsage.KBPK: "000",
}

KEY_ALGORITHM = {
    SymmetricKeyAlgorithm.TDES_2KEY: "T2",
    SymmetricKeyAlgorithm.TDES_3KEY: "T3",
    SymmetricKeyAlgorithm.AES_128: "A1",
    SymmetricKeyAlgorithm.AES_192: "A2",
    SymmetricKeyAlgorithm.AES_256: "A3",
}

KEY_USAGE_VARIANT = {
    SymmetricKeyUsage.BDK: "009",
    SymmetricKeyUsage.KEK: "000",
    SymmetricKeyUsage.PEK: "001",
    SymmetricKeyUsage.KBPK: "000",
}

KDF_METHOD = {
    KeyDerivationFunction.NIST_SP800: "1",
    KeyDerivationFunction.ANSI_X963: "2",
}

DERIVE_KEY_LENGTH = {
    SymmetricKeyAlgorithm.TDES_2KEY: "00128",
    SymmetricKeyAlgorithm.TDES_3KEY: "00192",
    SymmetricKeyAlgorithm.AES_128: "00128",
    SymmetricKeyAlgorithm.AES_192: "00192",
    SymmetricKeyAlgorithm.AES_256: "00256",
}

THALES_HEADER = "0000"
RANDOM_NONCE = "ABCDABCDABCDABCD"

Tr34Payload = namedtuple(
    "Tr34Payload", ["Tr34EnvelopeData", "Tr34SignatureData", "Tr34AuthData", "RandomNonce", "Kcv"]
)


class PayshieldCommands:

    def __init__(self, host, port, variant_lmk, variant_lmk_identifier):
        self.host = host
        self.port = port
        if variant_lmk:
            self.command_builder = VariantLmkCommandBuilder(variant_lmk_identifier)
        else:
            self.command_builder = KeyBlockLmkCommandBuilder()

    def a0_command(self, key_algorithm: SymmetricKeyAlgorithm, key_usage: SymmetricKeyUsage):
        command = self.command_builder.build_a0_command(key_usage, key_algorithm)

        result = self._send_receive(command)
        wrapped_key, kcv = self._decode_a0(bytes(result))
        return wrapped_key, kcv

    def ei_command(self, key_algorithm: RsaKeyAlgorithm, key_usage: AsymmetricKeyUsage):
        rsa_key_type = RSA_KEY_TYPE[key_usage]
        rsa_key_length = RSA_KEY_LENGTH[key_algorithm]

        command = self.command_builder.build_ei_command(rsa_key_type, rsa_key_length)
        
        result = self._send_receive(command)
        public_key, private_key = self._decode_ei(bytes(result))
        return public_key, private_key

    def fy_command(self, key_algorithm: EccKeyAlgorithm, key_usage: AsymmetricKeyUsage):
        ecc_key_algorithm = ECC_KEY_ALGORITHM[key_algorithm]
        ecc_key_type = ECC_KEY_TYPE[key_usage]

        command = self.command_builder.build_fy_command(ecc_key_type, ecc_key_algorithm)

        result = self._send_receive(command)
        public_key, private_key = self._decode_fy(bytes(result))
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

    def a8_command(self, transport_key, kek, transport_key_algorithm):
        if transport_key_algorithm.startswith("AES"):
            key_block_version = "D"
        else:
            key_block_version = "B"
        command = self.command_builder.build_a8_command(kek, transport_key, key_block_version)
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

        command = self.command_builder.build_b8_command(
            tr34_version,
            wrapped_key,
            kdh_credential,
            krd_credential_input,
            krd_public_key,
            kdh_private_key,
            nonce_length,
            nonce_input
        )

        result = self._send_receive(command)
        tr34_payload = self._decode_b8(bytes(result))
        return tr34_payload

    def ig_command(
         self,
         kdh_private_key,
         krd_public_key,
         derive_key_algorithm,
         key_derivation_function,
         hash_algorithm,
         shared_info,
     ):
        kdf = KDF_METHOD[key_derivation_function]
        derive_key_length = DERIVE_KEY_LENGTH[derive_key_algorithm]
        key_algorithm = KEY_ALGORITHM[derive_key_algorithm]
  
        command = (
            "IG"
            + "2103"
            + "<"
            + krd_public_key
            + ">"
            + kdh_private_key
            + kdf
            + "06"
            + "100"
            + str(len(shared_info))
            + shared_info
            + ";01"
            + derive_key_length
            + "K1"
            + key_algorithm
            + "B00E00;:"
        )
        result = self._send_receive(command)
        derived_key = self._decode_ig(bytes(result))
  
        return derived_key

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

    def _decode_fy(self, response_to_decode: bytes):
        response_to_decode_str, msg_len, str_pointer = self._common_parser(response_to_decode)

        if response_to_decode_str[str_pointer : str_pointer + 2] == "00":
            str_pointer = str_pointer + 2
            public_key_length = int(response_to_decode_str[str_pointer : str_pointer + 4])
            str_pointer = str_pointer + 4
            public_key = bytes.hex(
                response_to_decode[str_pointer : str_pointer + public_key_length]
            )
            str_pointer = str_pointer + public_key_length
            wrapped_private_key = response_to_decode[str_pointer:].decode()

            return public_key, wrapped_private_key
        else:
            print("Error Response Received : {}".format(response_to_decode_str[str_pointer:]))
            sys.exit(1)

    def _decode_ig(self, response_to_decode: bytes):
        response_to_decode_str, msg_len, str_pointer = self._common_parser(response_to_decode)
  
        if response_to_decode_str[str_pointer : str_pointer + 2] == "00":
            str_pointer = str_pointer + 2
            kcv_length = 3
            derived_key = response_to_decode_str[str_pointer:-kcv_length]
            return derived_key
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


class KeyBlockLmkCommandBuilder:

    def build_ei_command(self, rsa_key_type, rsa_key_length):
        command = "EI" + rsa_key_type + rsa_key_length + "02" + "#" + "00" + "00" + "&N"
        return command

    def build_a0_command(self, key_usage, key_algorithm):
        usage = KEY_USAGE[key_usage]
        algorithm = KEY_ALGORITHM[key_algorithm]
        command = "A00FFFS#" + usage + algorithm + "N00E00"
        return command

    def build_b8_command(self, tr34_version, wrapped_key, kdh_credential, krd_credential_input, krd_public_key, kdh_private_key, nonce_length, nonce_input):
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
            + "&N!B"
        )
        return command

    def build_a8_command(self, kek, transport_key, key_block_version):
        lmk_id = "00"
        command = "A8" + "FFF" + kek + transport_key + "R" + "%" + lmk_id + "!" + key_block_version
        return command

    def build_fy_command(self, ecc_key_type, ecc_key_algorithm):
        command = (
            "FY"
            + "01"
            + ecc_key_algorithm
            + "03"
            + "%"
            + "00"
            + "#"
            + ecc_key_type
            + "00"
            + "S"
            + "00"
        )
        return command


class VariantLmkCommandBuilder:
    def __init__(self, lmk_identifier):
        self.lmk_identifier = lmk_identifier

    def build_ei_command(self, rsa_key_type, rsa_key_length):
        command = "EI" + rsa_key_type + rsa_key_length + "02" + "%" + self.lmk_identifier
        return command

    def build_a0_command(self, key_usage, key_algorithm):
        usage = KEY_USAGE_VARIANT[key_usage]
        command = "A00" + usage + "U" + "%" + self.lmk_identifier
        return command

    def build_b8_command(self, tr34_version, wrapped_key, kdh_credential, krd_credential_input, krd_public_key, kdh_private_key, nonce_length, nonce_input):
        command = (
            "B8"
            + tr34_version
            + "000"
            + wrapped_key
            + kdh_credential
            + "000001"
            + krd_credential_input
            + krd_public_key
            + "00"
            + "99"
            + str(int(len(kdh_private_key)/2)).zfill(4)
            + "<"
            + kdh_private_key
            + ">010"
            + nonce_length
            + nonce_input
            + "%" + self.lmk_identifier 
            + "&K1B00S00!B"
        )
        return command

    def build_a8_command(self, kek, transport_key, key_block_version):
        # Exporting a BDK. This can be changed to support any other type of key
        key_type = "009"
        key_usage = "B0"
        mode_of_use = "X"
        command = 'A8' + key_type + kek + transport_key + 'R' + '%' + self.lmk_identifier \
                   + '&' + key_usage + mode_of_use + '00' + 'S' + '00' + '!' + key_block_version
        return command

