import binascii
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from key_exchange.hsm.futurex.commands import FuturexCommands
from key_exchange.utils.enums import (
    AsymmetricKeyAlgorithm,
    AsymmetricKeyUsage,
    EccKeyAlgorithm,
    KeyExchangeType,
    RsaKeyAlgorithm,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)


class FuturexHsm(object):

    def __init__(self, config):
        self.config = config
        self.futurex_commands = FuturexCommands(config["host"], config["port"])

    def create_symmetric_key(
        self, key_algorithm: SymmetricKeyAlgorithm, key_usage: SymmetricKeyUsage
    ):
        """
        Creates a symmetric key and output as TR31 key block wrapped under HSM major key.
        The intended KeyUsage, KeyAlgorithm and KeyModesOfUse are provided in the key block header.
        """
        key_block_header = self.generate_key_block_header(key_algorithm, key_usage)
        wrapped_key, kcv = self.futurex_commands.gpgs_command(key_block_header, key_algorithm)

        return wrapped_key, kcv

    def generate_key_block_header(
        self, key_algorithm: SymmetricKeyAlgorithm, key_usage: SymmetricKeyUsage
    ):
        """
        KeyBlockHeader will be generated according to the HSM.
        A sample key block heaer is [D][0000][K0][A][B]00E0000, where D represents an AES HSM Major key.
        Length will be calculated from the key an updated the header with.
        K0 is the KeyUsage and A represents the key algorithm. B represents the key modes of use.
        E indicates the key is exportable.
        """

        usage = algorithm = modes_of_use = ""
        if key_usage == SymmetricKeyUsage.PEK:
            usage = "P0"
            modes_of_use = "B"
        elif key_usage == SymmetricKeyUsage.BDK:
            usage = "B0"
            modes_of_use = "X"
        elif key_usage == SymmetricKeyUsage.KEK:
            usage = "K0"
            modes_of_use = "B"
        elif key_usage == SymmetricKeyUsage.KBPK:
            usage = "K1"
            modes_of_use = "B"

        if key_algorithm in [SymmetricKeyAlgorithm.TDES_2KEY, SymmetricKeyAlgorithm.TDES_3KEY]:
            algorithm = "T"
        elif key_algorithm in [
            SymmetricKeyAlgorithm.AES_128,
            SymmetricKeyAlgorithm.AES_192,
            SymmetricKeyAlgorithm.AES_256,
        ]:
            algorithm = "A"

        key_block_header = f"D0000{usage}{algorithm}{modes_of_use}00E0000"
        return key_block_header

    def create_rsa_key_pair(self, key_algorithm: RsaKeyAlgorithm, key_usage: AsymmetricKeyUsage):
        wrapped_private_key, trusted_public_key, clear_public_key = (
            self.futurex_commands.grsa_command(key_algorithm, key_usage)
        )

        return wrapped_private_key, trusted_public_key, clear_public_key

    def create_ecc_key_pair(self, key_algorithm: EccKeyAlgorithm, key_usage: AsymmetricKeyUsage):
        wrapped_private_key, trusted_public_key, clear_public_key = (
            self.futurex_commands.gecc_command(key_algorithm, key_usage)
        )

        return wrapped_private_key, trusted_public_key, clear_public_key

    def generate_certificate_and_chain(
        self,
        key_algorithm: AsymmetricKeyAlgorithm,
        ca_key_algorithm: AsymmetricKeyAlgorithm,
        key_usage: AsymmetricKeyUsage,
        key_exchange_type: KeyExchangeType,
    ):
        """
        Creates an asymmetric key pair. Creates a CertificateAuthority key pair to sign the public key.
        Generates the CSR for the public key. Signs the CSR using the CertificateAuthority key.
        Returns the private key, certificate generated and also the certificate chain.
        """

        # CA Key will be created with KeyUsage SIGN
        if key_algorithm.name in RsaKeyAlgorithm.__members__:
            wrapped_private_key, trusted_public_key, clear_public_key = self.create_rsa_key_pair(
                RsaKeyAlgorithm(key_algorithm), key_usage
            )
            ca_wrapped_private_key, ca_trusted_public_key, ca_clear_public_key = (
                self.create_rsa_key_pair(RsaKeyAlgorithm(ca_key_algorithm), AsymmetricKeyUsage.SIGN)
            )
        else:
            wrapped_private_key, trusted_public_key, clear_public_key = self.create_ecc_key_pair(
                EccKeyAlgorithm(key_algorithm), key_usage
            )
            ca_wrapped_private_key, ca_trusted_public_key, ca_clear_public_key = (
                self.create_ecc_key_pair(EccKeyAlgorithm(ca_key_algorithm), AsymmetricKeyUsage.SIGN)
            )

        ca_certificate_der = self.generate_self_signed_certificate(ca_wrapped_private_key)
        ca_certificate = x509.load_der_x509_certificate(bytes.fromhex(ca_certificate_der))

        certificate_der = self.generate_signed_certificate(
            wrapped_private_key, ca_wrapped_private_key, ca_certificate_der
        )
        certificate = x509.load_der_x509_certificate(bytes.fromhex(certificate_der))

        return ca_certificate, wrapped_private_key, certificate

    def generate_self_signed_certificate(self, private_key):
        certificate_der = self.futurex_commands.asgc_command(private_key)

        return certificate_der

    def generate_signed_certificate(self, private_key, ca_private_key, ca_certificate_der):
        csr = self.futurex_commands.asyr_command(private_key)
        certificate_der = self.futurex_commands.assr_command(
            csr, ca_private_key, ca_certificate_der
        )

        return certificate_der

    def trust_certificate_chain(self, ca_certificate, ca_key_algorithm):
        ca_certificate_der = (
            binascii.b2a_hex(ca_certificate.public_bytes(serialization.Encoding.DER))
            .decode()
            .upper()
        )
        ca_certificate_tpk = self.futurex_commands.avpc_command(ca_certificate_der)

        return ca_certificate_tpk

    def trust_certificate(self, certificate, ca_tpk):
        certificate_der = (
            binascii.b2a_hex(certificate.public_bytes(serialization.Encoding.DER)).decode().upper()
        )
        certificate_tpk = self.futurex_commands.avpc_command(certificate_der, ca_tpk)

        return certificate_tpk

    def export_symmetric_key_using_tr34(
        self,
        kdh_certificate,
        kdh_private_key,
        krd_certificate,
        krd_ca_certificate_tpk,
        transport_key,
    ):
        kdh_certificate_der = (
            binascii.b2a_hex(kdh_certificate.public_bytes(encoding=serialization.Encoding.DER))
            .decode()
            .upper()
        )
        krd_certificate_der = (
            binascii.b2a_hex(krd_certificate.public_bytes(encoding=serialization.Encoding.DER))
            .decode()
            .upper()
        )

        random_nonce = secrets.token_hex(8).upper()
        tr34_payload = self.futurex_commands.trtp_command(
            kdh_certificate_der,
            kdh_private_key,
            krd_certificate_der,
            krd_ca_certificate_tpk,
            transport_key,
            random_nonce,
        )

        return tr34_payload, random_nonce

    def export_symmetric_key_using_tr31(self, transport_key, kek):
        wrapped_key = self.futurex_commands.twka_command(transport_key, kek)
        return wrapped_key
