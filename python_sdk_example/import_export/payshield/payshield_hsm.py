import datetime

import pytz
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from import_export.payshield import asn_utils
from import_export.payshield.commands import PayshieldCommands
from import_export.utils.enums import (
    AsymmetricKeyUsage,
    KeyExchangeType,
    RsaKeyAlgorithm,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)


class PayshieldHsm(object):

    def __init__(self, config):
        self.config = config
        self.payshield_commands = PayshieldCommands(config["host"], config["port"])

    def create_rsa_key_pair(self, key_algorithm: RsaKeyAlgorithm, key_usage: AsymmetricKeyUsage):
        public_key, private_key = self.payshield_commands.ei_command(key_algorithm, key_usage)
        return public_key, private_key

    def create_symmetric_key(
        self, key_algorithm: SymmetricKeyAlgorithm, key_usage: SymmetricKeyUsage
    ):
        wrapped_key, kcv = self.payshield_commands.a0_command(key_algorithm, key_usage)
        return wrapped_key, kcv

    def generate_certificate_request(self, public_key, private_key, key_algorithm):
        csr = self.payshield_commands.qe_command(public_key, private_key, key_algorithm)
        return csr

    def generate_certificate_and_chain(
        self,
        key_algorithm: RsaKeyAlgorithm,
        ca_key_algorithm: RsaKeyAlgorithm,
        key_usage: AsymmetricKeyUsage,
        key_exchange_type: KeyExchangeType,
    ):
        public_key, private_key = self.create_rsa_key_pair(
            RsaKeyAlgorithm(key_algorithm), key_usage
        )

        csr = self.generate_certificate_request(public_key, private_key, key_algorithm)
        print("Created CSR")
        print(csr)

        print("Generating CA Key Pair (locally)")
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(ca_key_algorithm.name.split("_")[1]),
        )
        ca_public_key = ca_private_key.public_key()

        print("Generating CA Certificate (locally)")
        ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "TEST CA"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "The Organization"),
                    ]
                )
            )
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, "TEST CA"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "The Organization"),
                    ]
                )
            )
            .not_valid_before(datetime.datetime.now(pytz.UTC) - datetime.timedelta(1, 0, 0))
            .not_valid_after(datetime.datetime.now(pytz.UTC) + datetime.timedelta(90, 0, 0))
            .serial_number(int(100))
            .public_key(ca_public_key)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_public_key), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
        )

        csr_pem = x509.load_pem_x509_csr(csr.encode("utf-8"))

        print("Signing Cert (locally)")
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr_pem.subject)
            .issuer_name(ca_certificate.subject)
            .public_key(csr_pem.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(pytz.UTC) - datetime.timedelta(1, 0, 0))
            .not_valid_after(datetime.datetime.now(pytz.UTC) + datetime.timedelta(30, 0, 0))
            .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
        )

        return ca_certificate, private_key, certificate

    def trust_certificate_chain(self, ca_certificate, ca_key_algorithm):
        # Payshield doesn't require importing CA chain
        return ca_certificate

    def export_symmetric_key_using_tr34(
        self,
        kdh_certificate,
        kdh_private_key,
        krd_certificate,
        krd_ca_certificate_tpk,
        transport_key,
    ):
        krd_pubkey_der = krd_certificate.public_bytes(encoding=serialization.Encoding.DER)

        krd_cert_asn = asn_utils.parse_asn(krd_pubkey_der)
        krd_serial_number_asn = krd_cert_asn[0][2][0][2][1]
        krd_issuer_asn = krd_cert_asn[0][2][0][2][3]
        krd_public_key = krd_cert_asn[0][2][0][2][6][2][1][2][1:].hex()
        krd_cred_id_asn = (0x30, True, [krd_issuer_asn, krd_serial_number_asn])
        krd_cred_id_der = asn_utils.encode_asn([krd_cred_id_asn]).hex()
        print("Created KRD Credential")

        # Extract KDH Cred Id
        kdh_cert_asn = asn_utils.parse_asn(kdh_certificate.public_bytes(serialization.Encoding.DER))
        kdh_serial_number_asn = kdh_cert_asn[0][2][0][2][1]
        kdh_issuer_asn = kdh_cert_asn[0][2][0][2][3]
        kdh_cred_id_asn = (0x30, True, [kdh_issuer_asn, kdh_serial_number_asn])
        kdh_cred_id_der = asn_utils.encode_asn([kdh_cred_id_asn]).hex()
        print("Created KDH Credential")

        # Generate Auth and Env Data
        print("Generating TR-34 payload using B8 command for key")

        tr34_payload = self.payshield_commands.b8_command(
            kdh_cred_id_der, krd_cred_id_der, kdh_private_key, krd_public_key, transport_key
        )
        tr34_envelope_data = tr34_payload.Tr34EnvelopeData
        tr34_signature_data = tr34_payload.Tr34SignatureData
        tr34_auth_data = tr34_payload.Tr34AuthData
        random_nonce = tr34_payload.RandomNonce
        print("Received data from Payshield")

        # Generate TR-34 payload
        tr34_payload_asn = (
            0x30,
            True,
            [
                (0x06, False, bytes.fromhex("2A864886F70D010702")),
                (
                    0xA0,
                    True,
                    [
                        (
                            0x30,
                            True,
                            [
                                (0x02, False, (1).to_bytes(1, "big")),
                                (
                                    0x31,
                                    True,
                                    [
                                        (
                                            0x30,
                                            True,
                                            [
                                                (0x06, False, bytes.fromhex("608648016503040201")),
                                            ],
                                        )
                                    ],
                                ),
                                (
                                    0x30,
                                    True,
                                    [
                                        (0x06, False, bytes.fromhex("2A864886F70D010703")),
                                        (
                                            0xA0,
                                            True,
                                            [
                                                (
                                                    0x04,
                                                    False,
                                                    asn_utils.encode_asn(
                                                        asn_utils.parse_asn(tr34_envelope_data)[0][
                                                            2
                                                        ]
                                                    ),
                                                )
                                            ],
                                        ),
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
                                                (0x02, False, (1).to_bytes(1, "big")),
                                                kdh_cred_id_asn,
                                                (
                                                    0x30,
                                                    True,
                                                    [
                                                        (
                                                            0x06,
                                                            False,
                                                            bytes.fromhex("608648016503040201"),
                                                        ),  # id-sha256
                                                    ],
                                                ),
                                                (
                                                    0xA0,
                                                    True,
                                                    asn_utils.parse_asn(tr34_auth_data)[0][2],
                                                ),
                                                (
                                                    0x30,
                                                    True,
                                                    [
                                                        (
                                                            0x06,
                                                            False,
                                                            bytes.fromhex("2A864886F70D010101"),
                                                        ),  # public key algorithm (rsaEncryption)
                                                        (0x05, False, b""),
                                                    ],
                                                ),
                                                (0x04, False, tr34_signature_data),
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
        tr34_payload = asn_utils.encode_asn([tr34_payload_asn]).hex().upper()

        return tr34_payload, random_nonce

    def export_symmetric_key_using_tr31(self, transport_key, kek):
        wrapped_key, kcv = self.payshield_commands.a8_command(transport_key, kek)

        return wrapped_key
