import base64

import boto3
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from key_exchange.utils.enums import (
    AsymmetricKeyAlgorithm,
    AsymmetricKeyUsage,
    KeyDerivationFunction,
    KeyDerivationHashAlgorithm,
    KeyExchangeType,
    RsaWrappingSpec,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)


class Apc(object):
    def __init__(self, config):
        # Use a named AWS profile if provided, otherwise fall back to the
        # default credential chain (env vars, default profile, instance role).
        session = boto3.Session(profile_name=config.get("profile") or None)
        self.apc_client = session.client("payment-cryptography", region_name=config["region"])

    @staticmethod
    def _key_check_value_algorithm(key_algorithm: SymmetricKeyAlgorithm) -> str:
        """
        Resolves the KeyCheckValueAlgorithm for the transferred key: ANSI_X9_24
        for TDES keys, CMAC otherwise. Mirrors the reference pattern in
        key-import-export/rsa/import_app/import_raw_key_rsa.py (TDES -> ANSI_X9_24,
        AES -> CMAC). See:
        https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_ImportKey.html
        """
        if key_algorithm.name.startswith("TDES"):
            return "ANSI_X9_24"
        return "CMAC"

    @staticmethod
    def _key_check_value_algorithm_from_key_block(transport_key: str) -> str:
        """
        Resolves the KeyCheckValueAlgorithm from a payShield/TR-31 key block
        header instead of a declared algorithm: ANSI_X9_24 for TDES keys, CMAC
        otherwise.

        Used by the ECDH flow, where the transport key's own algorithm must not
        be conflated with the AES ECDH-derived KEK used to wrap it. ECDH always
        uses a key-block LMK (variant LMK is rejected up front), so the transport
        key is always an 'S1'-scheme TR-31 key block. The algorithm indicator is
        the single character following the scheme byte, block-version byte and
        the 4-char length field (e.g. "S1" + "0096" + "E2" + "T"...), where
        T=TDES, A=AES, D=single DES.
        """
        try:
            algorithm_char = transport_key[8].upper()
        except (IndexError, TypeError):
            # Fall back to CMAC if the header cannot be parsed.
            return "CMAC"
        return "ANSI_X9_24" if algorithm_char == "T" else "CMAC"

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
        elif key_exchange_type == KeyExchangeType.IMPORT_KEY_CRYPTOGRAM:
            # For an RSA key cryptogram import, APC returns the RSA wrapping public
            # key certificate (and chain) that the KDH will use to wrap the key.
            import_token_response = self.apc_client.get_parameters_for_import(
                KeyMaterialType="KEY_CRYPTOGRAM", WrappingKeyAlgorithm=key_algorithm.name
            )
            private_key_token = import_token_response["ImportToken"]
            certificate_base64 = import_token_response["WrappingKeyCertificate"]
            ca_certificate_base64 = import_token_response["WrappingKeyCertificateChain"]
        elif key_exchange_type == KeyExchangeType.EXPORT_KEY_CRYPTOGRAM:
            # For an RSA key cryptogram export, APC returns the RSA signing public
            # key certificate (and chain) used when APC is the key distribution host.
            export_token_response = self.apc_client.get_parameters_for_export(
                KeyMaterialType="KEY_CRYPTOGRAM", SigningKeyAlgorithm=key_algorithm.name
            )
            private_key_token = export_token_response["ExportToken"]
            certificate_base64 = export_token_response["SigningKeyCertificate"]
            ca_certificate_base64 = export_token_response["SigningKeyCertificateChain"]
        elif key_exchange_type == KeyExchangeType.ECDH:
            # If it is key agreement using ECDH, an ECC key pair is generated in APC
            key_modes_of_use = {"DeriveKey": True}
            key_usage = "TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT"
            key_attributes = {
                "KeyAlgorithm": key_algorithm.name,
                "KeyUsage": key_usage,
                "KeyClass": "ASYMMETRIC_KEY_PAIR",
                "KeyModesOfUse": key_modes_of_use,
            }
  
            create_key_response = self.apc_client.create_key(
                Exportable=True,
                KeyAttributes=key_attributes,
                DeriveKeyUsage="TR31_K1_KEY_BLOCK_PROTECTION_KEY",
            )
            private_key_token = create_key_response["Key"]["KeyArn"]
  
            get_public_key_certificate_response = self.apc_client.get_public_key_certificate(
                KeyIdentifier=private_key_token
            )
            certificate_base64 = get_public_key_certificate_response["KeyCertificate"]
            ca_certificate_base64 = get_public_key_certificate_response["KeyCertificateChain"]

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
        key_algorithm: SymmetricKeyAlgorithm,
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

        response = self.apc_client.import_key(
            Enabled=True,
            KeyCheckValueAlgorithm=self._key_check_value_algorithm(key_algorithm),
            KeyMaterial=key_material,
        )
        return response["Key"]["KeyArn"], response["Key"]["KeyCheckValue"]

    def import_symmetric_key_using_tr31(self, key_to_import, kek, key_algorithm: SymmetricKeyAlgorithm):
        key_material = {
            "Tr31KeyBlock": {
                "WrappingKeyIdentifier": kek,
                "WrappedKeyBlock": key_to_import,
            }
        }

        response = self.apc_client.import_key(
            Enabled=True,
            KeyCheckValueAlgorithm=self._key_check_value_algorithm(key_algorithm),
            KeyMaterial=key_material,
        )
        return response["Key"]["KeyArn"], response["Key"]["KeyCheckValue"]

    # Default APC KeyUsage and KeyModesOfUse for each coarse SymmetricKeyUsage.
    # Used when an explicit apc_key_usage / apc_key_modes_of_use is not provided.
    # Values follow the valid combinations documented at:
    # https://docs.aws.amazon.com/payment-cryptography/latest/userguide/crypto-ops-validkeys-ops.html
    _DEFAULT_APC_KEY_USAGE = {
        SymmetricKeyUsage.PEK: (
            "TR31_P0_PIN_ENCRYPTION_KEY",
            {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
        ),
        SymmetricKeyUsage.BDK: (
            "TR31_B0_BASE_DERIVATION_KEY",
            {"DeriveKey": True},
        ),
        SymmetricKeyUsage.KBPK: (
            "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
            {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
        ),
        SymmetricKeyUsage.KEK: (
            "TR31_K0_KEY_ENCRYPTION_KEY",
            {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
        ),
    }

    def _resolve_apc_key_usage_and_modes(
        self, key_usage: SymmetricKeyUsage, apc_key_usage: str, apc_key_modes_of_use: dict
    ):
        """
        Resolves the APC KeyUsage (TR31_* string) and KeyModesOfUse dict to send
        to ImportKey. An explicit apc_key_usage / apc_key_modes_of_use always
        takes precedence; otherwise a default is derived from the coarse
        SymmetricKeyUsage enum. When only one of the two is provided explicitly,
        the other falls back to the enum default.
        """
        default_usage, default_modes = self._DEFAULT_APC_KEY_USAGE.get(
            key_usage, self._DEFAULT_APC_KEY_USAGE[SymmetricKeyUsage.KEK]
        )
        usage = apc_key_usage if apc_key_usage else default_usage
        modes_of_use = apc_key_modes_of_use if apc_key_modes_of_use else default_modes
        return usage, modes_of_use

    def import_symmetric_key_using_rsa(
        self,
        import_token,
        wrapped_key_cryptogram,
        key_algorithm: SymmetricKeyAlgorithm,
        key_usage: SymmetricKeyUsage,
        wrapping_spec: RsaWrappingSpec,
        apc_key_usage: str = None,
        apc_key_modes_of_use: dict = None,
    ):
        """
        Imports a symmetric key that has been RSA-wrapped (KEY_CRYPTOGRAM) under the
        APC wrapping public key returned during get_parameters_for_import. The
        import_token references the service side RSA private key used to unwrap it.

        The APC key usage and key modes of use may be supplied explicitly via
        apc_key_usage (a TR31_* KeyUsage value) and apc_key_modes_of_use (a dict
        of KeyModesOfUse booleans). When not supplied, they are derived from the
        coarse SymmetricKeyUsage enum for backwards compatibility. See:
        https://docs.aws.amazon.com/payment-cryptography/latest/userguide/crypto-ops-validkeys-ops.html
        """
        usage, modes_of_use = self._resolve_apc_key_usage_and_modes(
            key_usage, apc_key_usage, apc_key_modes_of_use
        )

        key_material = {
            "KeyCryptogram": {
                "Exportable": True,
                "ImportToken": import_token,
                "KeyAttributes": {
                    "KeyAlgorithm": key_algorithm.name,
                    "KeyClass": "SYMMETRIC_KEY",
                    "KeyModesOfUse": modes_of_use,
                    "KeyUsage": usage,
                },
                "WrappedKeyCryptogram": wrapped_key_cryptogram.upper(),
                "WrappingSpec": wrapping_spec.name,
            }
        }

        response = self.apc_client.import_key(
            Enabled=True,
            KeyCheckValueAlgorithm=self._key_check_value_algorithm(key_algorithm),
            KeyMaterial=key_material,
        )
        return response["Key"]["KeyArn"], response["Key"]["KeyCheckValue"]

    def import_symmetric_key_using_ecdh(
        self,
        private_key,
        ca_certificate_trusted,
        public_key_certificate,
        derive_key_algorithm: SymmetricKeyAlgorithm,
        key_derivation_function: KeyDerivationFunction,
        hash_algorithm: KeyDerivationHashAlgorithm,
        shared_info,
        key_to_import,
        transport_key_block: str,
    ):
        response = self.apc_client.import_key(
            Enabled=True,
            # KCV algorithm is derived from the transport key's own TR-31 key
            # block header (T=TDES -> ANSI_X9_24, else CMAC), NOT from the AES
            # ECDH-derived KEK used to wrap it. This keeps the KCV correct for a
            # TDES transport key without affecting the wrap key-block version.
            KeyCheckValueAlgorithm=self._key_check_value_algorithm_from_key_block(
                transport_key_block
            ),
            KeyMaterial={
                "DiffieHellmanTr31KeyBlock": {
                    "CertificateAuthorityPublicKeyIdentifier": ca_certificate_trusted,
                    "DerivationData": {"SharedInformation": shared_info},
                    "DeriveKeyAlgorithm": derive_key_algorithm.name,
                    "KeyDerivationFunction": key_derivation_function.name,
                    "KeyDerivationHashAlgorithm": hash_algorithm.name,
                    "PrivateKeyIdentifier": private_key,
                    "PublicKeyCertificate": base64.b64encode(
                        public_key_certificate.public_bytes(encoding=serialization.Encoding.PEM)
                    ).decode("UTF-8"),
                    "WrappedKeyBlock": key_to_import,
                }
            },
        )
        return response["Key"]["KeyArn"], response["Key"]["KeyCheckValue"]

    def export_symmetric_key_using_ecdh(
        self,
        private_key,
        ca_certificate_trusted,
        public_key_certificate,
        derive_key_algorithm: SymmetricKeyAlgorithm,
        key_derivation_function: KeyDerivationFunction,
        hash_algorithm: KeyDerivationHashAlgorithm,
        shared_info,
        key_to_export,
        key_algorithm,
    ):
        response = self.apc_client.export_key(
            ExportKeyIdentifier=key_to_export,
            KeyMaterial={
                "DiffieHellmanTr31KeyBlock": {
                    "CertificateAuthorityPublicKeyIdentifier": ca_certificate_trusted,
                    "DerivationData": {"SharedInformation": shared_info},
                    "DeriveKeyAlgorithm": derive_key_algorithm.name,
                    "KeyDerivationFunction": key_derivation_function.name,
                    "KeyDerivationHashAlgorithm": hash_algorithm.name,
                    "PrivateKeyIdentifier": private_key,
                    "PublicKeyCertificate": base64.b64encode(
                        public_key_certificate.public_bytes(encoding=serialization.Encoding.PEM)
                    ).decode("UTF-8"),
                }
            },
        )
        return response["WrappedKey"]["KeyMaterial"]
