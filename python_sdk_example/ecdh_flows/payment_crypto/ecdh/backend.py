import boto3
from cryptography.hazmat.primitives import serialization

from payment_crypto.ecdh.crypto_utils import CryptoUtils

controlplane_client = boto3.client("payment-cryptography")
dataplane_client = boto3.client("payment-cryptography-data")


class Backend:

    def __init__(self, ca_arn, apc_pek_arn, apc_client_ca_key_arn, apc_pgk_arn, apc_ecdh_key_arn):
        """
        :param ca_arn: AWS Private Certificate Authority ARN
        :param apc_pek_arn: AWS Payment Cryptography's Pin Encryption Key ARN
        :param apc_client_ca_key_arn:  AWS Private Authority Public Key ARN (CA.crt) stored in AWS Payment Cryptography
        :param apc_pgk_arn: AWS Payment Cryptography's Pin Generation Key ARN
        :param apc_ecdh_key_arn: AWS Payment Cryptography's ECDH's Key ARN
        """
        self.aws_private_ca_arn = ca_arn
        self.apc_pek_arn = apc_pek_arn
        self.apc_client_ca_key_arn = apc_client_ca_key_arn
        self.apc_pgk_arn = apc_pgk_arn
        self.apc_ecdh_key_arn = apc_ecdh_key_arn
        self.pvv = None
        self.tmp_pek_pinblock = None

    def get_apc_certificates(self):
        """
        Obtains the Certificate and the Certificate Chain for the ECDH Public Key
        :return:
        """
        response = controlplane_client.get_public_key_certificate(KeyIdentifier=self.apc_ecdh_key_arn)
        return response['KeyCertificateChain'], response['KeyCertificate']

    def sign_with_private_ca(self, csr):
        """
        Signs the client-side ECDH Key with AWS Private CA and returns the Certificate and Certificate Chain
        :param csr: Certificate Signing Request
        :return:
        """
        validity = {
            'Type': 'DAYS',
            'Value': 1
        }
        return CryptoUtils.sign_with_private_ca(self.aws_private_ca_arn, csr.public_bytes(serialization.Encoding.PEM),
                                                validity)

    def store_pvv(self, pvv):
        # here we would store the PVV in a safe storage
        self.pvv = pvv

    def set_pin(self, pan, encrypted_pinblock, ecdsa_csr, shared_info):
        # Sign the client's CSR
        signed_client_certificate, ca_chain = self.sign_with_private_ca(ecdsa_csr)

        # request ECDSA Symmetric to PEK translation
        newEncryptedPinBlock = dataplane_client.translate_pin_data(
            EncryptedPinBlock=encrypted_pinblock,
            IncomingKeyIdentifier=self.apc_ecdh_key_arn,
            OutgoingKeyIdentifier=self.apc_pek_arn,
            IncomingWrappedKey=CryptoUtils.get_apc_ecdh_parameters(self.apc_client_ca_key_arn,
                                                                   signed_client_certificate,
                                                                   shared_info),
            IncomingTranslationAttributes={"IsoFormat4": {'PrimaryAccountNumber': pan}},
            OutgoingTranslationAttributes={"IsoFormat0": {'PrimaryAccountNumber': pan}}
        )['PinBlock']

        # generate the PVV for the Encrypted Pinblock
        genAttrib = {
            "VisaPinVerificationValue": {"PinVerificationKeyIndex": 1, "EncryptedPinBlock": newEncryptedPinBlock}}

        response = dataplane_client.generate_pin_data(
            GenerationKeyIdentifier=self.apc_pgk_arn,
            EncryptionKeyIdentifier=self.apc_pek_arn,
            PinBlockFormat='ISO_FORMAT_0',
            PrimaryAccountNumber=pan,
            GenerationAttributes=genAttrib
        )
        pvv = response["PinData"]["VerificationValue"]
        self.tmp_pek_pinblock = response["EncryptedPinBlock"]
        self.store_pvv(pvv)
        return "success"

    def get_ecdh_pinblock(self, pan, pek_encrypted_pinblock, ecdsa_csr, shared_info):
        # Sign the client's CSR
        signed_client_certificate, ca_chain = self.sign_with_private_ca(ecdsa_csr)
        # Pinblock Translate from PEK to ECDSA Symmetric translation
        newEncryptedPinBlock = dataplane_client.translate_pin_data(
            EncryptedPinBlock=pek_encrypted_pinblock,
            OutgoingKeyIdentifier=self.apc_ecdh_key_arn,
            IncomingKeyIdentifier=self.apc_pek_arn,
            OutgoingWrappedKey=CryptoUtils.get_apc_ecdh_parameters(self.apc_client_ca_key_arn,
                                                                   signed_client_certificate,
                                                                   shared_info),
            OutgoingTranslationAttributes={"IsoFormat4": {'PrimaryAccountNumber': pan}},
            IncomingTranslationAttributes={"IsoFormat0": {'PrimaryAccountNumber': pan}}
        )['PinBlock']

        return newEncryptedPinBlock

    def reset_pin(self, pan, ecdsa_csr, shared_info):
        # Generate a new random PIN
        pin_data = dataplane_client.generate_pin_data(
            GenerationKeyIdentifier=self.apc_pgk_arn,
            EncryptionKeyIdentifier=self.apc_pek_arn,
            PrimaryAccountNumber=pan,
            PinBlockFormat="ISO_FORMAT_0",
            GenerationAttributes={"VisaPin": {"PinVerificationKeyIndex": 1}},
        )
        pvv = pin_data["PinData"]["VerificationValue"]
        pek_encrypted_pinblock = pin_data["EncryptedPinBlock"]

        # Sign the client's CSR
        signed_client_certificate, ca_chain = self.sign_with_private_ca(ecdsa_csr)

        # Pinblock Translate from PEK to ECDSA Symmetric translation
        newEncryptedPinBlock = dataplane_client.translate_pin_data(
            EncryptedPinBlock=pek_encrypted_pinblock,
            OutgoingKeyIdentifier=self.apc_ecdh_key_arn,
            IncomingKeyIdentifier=self.apc_pek_arn,
            OutgoingWrappedKey=CryptoUtils.get_apc_ecdh_parameters(self.apc_client_ca_key_arn,
                                                                   signed_client_certificate,
                                                                   shared_info),
            OutgoingTranslationAttributes={"IsoFormat4": {'PrimaryAccountNumber': pan}},
            IncomingTranslationAttributes={"IsoFormat0": {'PrimaryAccountNumber': pan}}
        )
        # print("APC Derived Key KCV: %s" % newEncryptedPinBlock['KeyCheckValue'])

        # Store  the PVV
        self.store_pvv(pvv)

        # return pinblock to client
        return newEncryptedPinBlock['PinBlock']

    def standalone_set_pin(self, pin, pan):
        # Generate local ecdh key-pair
        private_key, public_key = CryptoUtils.generate_ecdh_key_pair()
        # Generate shared info
        shared_info = CryptoUtils.generate_shared_info()
        # get AWS Payment Cryptography Certificates
        apc_ca_certificate, apc_certificate = self.get_apc_certificates()
        # Derive ECDH symmetric key
        derived_key = CryptoUtils.generate_ecc_symmetric_key_client(apc_certificate, private_key, shared_info)
        # encrypt pinblock with Derived Key
        encrypted_pin_block = CryptoUtils.generate_pin_block_iso_4(derived_key, pin, pan)
        # generate Certificate Signing Request
        csr = CryptoUtils.generate_certificate_signing_request(private_key)
        # tell the backend to set the PIN
        self.set_pin(pan, encrypted_pin_block, csr, shared_info)
