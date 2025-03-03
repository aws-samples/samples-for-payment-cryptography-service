import base64

import boto3
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from key_import_export.utils.enums import (
    AsymmetricKeyAlgorithm,
    AsymmetricKeyUsage,
    KeyExchangeType,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)


class Apc(object):
    def __init__(self, config):
        self.apc_client = boto3.client("payment-cryptography", region_name=config["region"])

    def create_symmetric_key(
        self, key_algorithm: SymmetricKeyAlgorithm, key_usage: SymmetricKeyUsage
    ):
        if key_usage == SymmetricKeyUsage.PEK:
            usage = "TR31_P0_PIN_ENCRYPTION_KEY"
            modes_of_use = {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True}
        elif key_usage == SymmetricKeyUsage.BDK:
            usage = "TR31_B0_BASE_DERIVATION_KEY"
            modes_of_use = {"DeriveKey": True}
        elif key_usage == SymmetricKeyUsage.KBPK:
            usage = "TR31_K1_KEY_BLOCK_PROTECTION_KEY"
            modes_of_use = {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True}
        elif key_usage == SymmetricKeyUsage.KEK:
            usage = "TR31_K0_KEY_ENCRYPTION_KEY"
            modes_of_use = {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True}

        key_attributes = {
            "KeyAlgorithm": key_algorithm.name,
            "KeyUsage": usage,
            "KeyClass": "SYMMETRIC_KEY",
            "KeyModesOfUse": modes_of_use,
        }
        response = self.apc_client.create_key(Exportable=True, KeyAttributes=key_attributes)
        return response["Key"]["KeyArn"], response["Key"]["KeyCheckValue"]

    def generate_certificate_and_chain(
        self,
        key_algorithm: AsymmetricKeyAlgorithm,
        ca_key_algorithm: AsymmetricKeyAlgorithm,
        key_usage: AsymmetricKeyUsage,
        key_exchange_type: KeyExchangeType,
    ):
        """
        In APC, if KeyExchangeType is TR34_KEY_BLOCK or KEY_CRYPTOGRAM,
        it would call getParametersForImport or getParametersForExport APIs accordingly.
        For KeyExchangeType TR34_KEY_BLOCK or KEY_CRYPTOGRAM, CA key algorithm is by default RSA_4096
        """

        if key_exchange_type == KeyExchangeType.IMPORT_TR34_KEY_BLOCK:
            import_token_response = self.apc_client.get_parameters_for_import(
                KeyMaterialType="TR34_KEY_BLOCK", WrappingKeyAlgorithm=key_algorithm.name
            )
            private_key_token = import_token_response["ImportToken"]
            certificate_base64 = import_token_response["WrappingKeyCertificate"]
            ca_certificate_base64 = import_token_response["WrappingKeyCertificateChain"]
        elif key_exchange_type == KeyExchangeType.EXPORT_TR34_KEY_BLOCK:
            export_token_response = self.apc_client.get_parameters_for_export(
                KeyMaterialType="TR34_KEY_BLOCK", SigningKeyAlgorithm=key_algorithm.name
            )
            private_key_token = export_token_response["ExportToken"]
            certificate_base64 = export_token_response["SigningKeyCertificate"]
            ca_certificate_base64 = export_token_response["SigningKeyCertificateChain"]

        certificate = x509.load_pem_x509_certificate(base64.b64decode(certificate_base64))
        ca_certificate = x509.load_pem_x509_certificate(base64.b64decode(ca_certificate_base64))

        # ImportToken/ExportToken points to the service side private key
        return ca_certificate, private_key_token, certificate

    def trust_certificate_chain(self, ca_certificate, ca_key_algorithm: AsymmetricKeyAlgorithm):
        """
        Imports the certificate chain as the RootCertificatePublicKey
        """
        response = self.apc_client.import_key(
            Enabled=True,
            KeyMaterial={
                "RootCertificatePublicKey": {
                    "KeyAttributes": {
                        "KeyAlgorithm": ca_key_algorithm.name,
                        "KeyClass": "PUBLIC_KEY",
                        "KeyModesOfUse": {
                            "Verify": True,
                        },
                        "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
                    },
                    "PublicKeyCertificate": base64.b64encode(
                        ca_certificate.public_bytes(encoding=serialization.Encoding.PEM)
                    ).decode("UTF-8"),
                }
            },
        )
        return response["Key"]["KeyArn"]

    def import_symmetric_key_using_tr34(
        self,
        krd_certificate,
        krd_private_key,
        kdh_certificate,
        kdh_ca_certificate_trusted,
        tr34_payload,
        nonce,
    ):
        kdh_certificate_base64 = base64.b64encode(
            kdh_certificate.public_bytes(encoding=serialization.Encoding.PEM)
        ).decode("UTF-8")

        key_material = {
            "Tr34KeyBlock": {
                "CertificateAuthorityPublicKeyIdentifier": kdh_ca_certificate_trusted,
                "ImportToken": krd_private_key,
                "KeyBlockFormat": "X9_TR34_2012",
                "SigningKeyCertificate": kdh_certificate_base64,
                "WrappedKeyBlock": tr34_payload.upper(),
                "RandomNonce": nonce.upper(),
            }
        }

        response = self.apc_client.import_key(Enabled=True, KeyMaterial=key_material)
        return response["Key"]["KeyArn"], response["Key"]["KeyCheckValue"]

    def import_symmetric_key_using_tr31(self, key_to_import, kek):
        key_material = {
            "Tr31KeyBlock": {
                "WrappingKeyIdentifier": kek,
                "WrappedKeyBlock": key_to_import,
            }
        }

        response = self.apc_client.import_key(Enabled=True, KeyMaterial=key_material)
        return response["Key"]["KeyArn"], response["Key"]["KeyCheckValue"]
