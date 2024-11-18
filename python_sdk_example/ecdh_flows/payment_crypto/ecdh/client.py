import psec
import psec.pinblock

from payment_crypto.ecdh.backend import Backend
from payment_crypto.ecdh.crypto_utils import CryptoUtils


class Client:

    @staticmethod
    def set_pin(pin: str, pan: str, backend: Backend):
        # Generate local ecdh key-pair
        private_key, public_key = CryptoUtils.generate_ecdh_key_pair()
        # Generate shared info
        shared_info = CryptoUtils.generate_shared_info()
        # get AWS Payment Cryptography Certificates
        apc_ca_certificate, apc_certificate = backend.get_apc_certificates()
        # Derive ECDH symmetric key
        derived_key = CryptoUtils.generate_ecc_symmetric_key_client(apc_certificate, private_key, shared_info)
        # encrypt pinblock with Derived Key
        encrypted_pin_block = CryptoUtils.generate_pin_block_iso_4(derived_key, pin, pan)
        # generate Certificate Signing Request
        csr = CryptoUtils.generate_certificate_signing_request(private_key)
        # tell the backend to set the PIN
        backend.set_pin(pan, encrypted_pin_block, csr, shared_info)

    @staticmethod
    def pin_reveal(pek_pinblock, pan, backend):
        # Generate local ecdh key-pair
        private_key, public_key = CryptoUtils.generate_ecdh_key_pair()
        # Generate shared info
        shared_info = CryptoUtils.generate_shared_info()
        # get AWS Payment Cryptography Certificates
        apc_ca_certificate, apc_certificate = backend.get_apc_certificates()
        # Derive ECDH symmetric key
        derived_key = CryptoUtils.generate_ecc_symmetric_key_client(apc_certificate, private_key, shared_info)
        # generate Certificate Signing Request
        csr = CryptoUtils.generate_certificate_signing_request(private_key)
        # get ECDH encrypted pinblock
        encrypted_pinblock = backend.get_ecdh_pinblock(pan, pek_pinblock, csr, shared_info)
        bytes_pinblock = bytes.fromhex(encrypted_pinblock)
        # decrypt pinblock with derived_key and print
        pin = psec.pinblock.decipher_pinblock_iso_4(derived_key, bytes_pinblock, pan)
        return pin

    @staticmethod
    def pin_reset(pan, backend):
        # Generate local ecdh key-pair
        private_key, public_key = CryptoUtils.generate_ecdh_key_pair()
        # Generate shared info
        shared_info = CryptoUtils.generate_shared_info()
        # get AWS Payment Cryptography Certificates
        apc_ca_certificate, apc_certificate = backend.get_apc_certificates()
        # Derive ECDH symmetric key
        derived_key = CryptoUtils.generate_ecc_symmetric_key_client(apc_certificate, private_key, shared_info)
        # generate Certificate Signing Request
        csr = CryptoUtils.generate_certificate_signing_request(private_key)
        # get ECDH encrypted pinblock
        encrypted_pinblock = backend.reset_pin(pan, csr, shared_info)
        bytes_pinblock = bytes.fromhex(encrypted_pinblock)
        # decrypt pinblock with derived_key and print
        pin = psec.pinblock.decipher_pinblock_iso_4(derived_key, bytes_pinblock, pan)
        return pin
