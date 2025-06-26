from enum import Enum


class SymmetricKeyAlgorithm(Enum):
    TDES_2KEY = "TDES_2KEY"
    TDES_3KEY = "TDES_3KEY"
    AES_128 = "AES_128"
    AES_192 = "AES_192"
    AES_256 = "AES_256"


class SymmetricKeyUsage(Enum):
    PEK = "PEK"
    BDK = "BDK"
    KEK = "KEK"
    KBPK = "KBPK"


class AsymmetricKeyAlgorithm(Enum):
    RSA_2048 = "RSA_2046"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    ECC_NIST_P256 = "ECC_NIST_P256"
    ECC_NIST_P384 = "ECC_NIST_P384"
    ECC_NIST_P521 = "ECC_NIST_P521"


class EccKeyAlgorithm(Enum):
    ECC_NIST_P256 = "ECC_NIST_P256"
    ECC_NIST_P384 = "ECC_NIST_P384"
    ECC_NIST_P521 = "ECC_NIST_P521"


class RsaKeyAlgorithm(Enum):
    RSA_2048 = "RSA_2046"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"


class AsymmetricKeyUsage(Enum):
    KEY_AGREEMENT_KEY = "KEY_AGREEMENT_KEY"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    SIGN = "SIGN"
    VERIFY = "VERIFY"


class KeyExchangeType(Enum):
    IMPORT_TR34_KEY_BLOCK = "IMPORT_TR34_KEY_BLOCK"
    EXPORT_TR34_KEY_BLOCK = "EXPORT_TR34_KEY_BLOCK"
    ECDH = "ECDH"


class KeyDerivationFunction(Enum):
    NIST_SP800 = "NIST_SP800"
    ANSI_X963 = "ANSI_X963"


class KeyDerivationHashAlgorithm(Enum):
    SHA_256 = "SHA_256"
    SHA_384 = "SHA_384"
    SHA_512 = "SHA_512"
