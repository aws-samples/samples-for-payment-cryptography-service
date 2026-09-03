# flake8: noqa: E402

import argparse
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_exchange.hsm.futurex.futurex_hsm import FuturexHsm
from key_exchange.hsm.payshield.payshield_hsm import PayshieldHsm
from key_exchange.utils.apc import Apc
from key_exchange.utils.enums import (
    AsymmetricKeyUsage,
    KeyExchangeType,
    RsaKeyAlgorithm,
    RsaWrappingSpec,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)


def _get_command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--kdh",
        help="Key Distribution Host. Options are [futurex, payshield]",
        required=True,
        choices=["futurex", "payshield"],
    )
    parser.add_argument(
        "--krd",
        help="Key Receiving Device. Options are [apc]",
        required=False,
        default="apc",
        choices=["apc"],
    )

    return parser.parse_args()


def _get_kdh_krd_hosts(kdh, krd, kdh_config, krd_config):
    # For KRD, only APC is supported for now
    krd_host = Apc(krd_config)

    if "futurex" == kdh:
        kdh_host = FuturexHsm(kdh_config)
    elif "payshield" == kdh:
        kdh_host = PayshieldHsm(kdh_config)

    return kdh_host, krd_host


def main():
    args = _get_command_line_args()
    config = dict()
    with open(os.path.dirname(__file__) + "/input_config.json", "r") as jsonfile:
        config = json.load(jsonfile)

    kdh = args.kdh
    krd = args.krd

    print("\n####### Key Exchange using RSA (Key Cryptogram) #######")
    print("\nKey Distribution Host (KDH) : ", kdh.upper())
    print("Key Receiving Device (KRD) : ", krd.upper())

    kdh_config = config["kdh"][kdh]
    krd_config = config["krd"][krd]
    kdh_host, krd_host = _get_kdh_krd_hosts(kdh, krd, kdh_config, krd_config)

    # Transport key metadata (algorithm and usage) is read from the KDH's rsa
    # config so it matches the actual key being exported. This is what APC
    # validates against the wrapped key material during import; a mismatch
    # raises "Actual KeyAlgorithm of the WrappedKey is mismatching ...".
    # Defaults preserve the previous behaviour when not specified in config.
    rsa_config = kdh_config.get("rsa", {})
    key_algorithm = SymmetricKeyAlgorithm(rsa_config.get("key_algorithm", "TDES_3KEY"))

    # Coarse usage used only for HSM-side key generation (when the transport key
    # is not provided in config and a new key is created on the KDH). APC import
    # uses apc_key_usage / apc_key_modes_of_use below.
    key_usage = SymmetricKeyUsage.KEK

    # APC key metadata used when importing into APC (KRD). apc_key_usage maps
    # directly to a TR31_* KeyUsage value and apc_key_modes_of_use to a
    # KeyModesOfUse dict. When omitted, they default from key_usage above. See:
    # https://docs.aws.amazon.com/payment-cryptography/latest/userguide/crypto-ops-validkeys-ops.html
    apc_key_usage = rsa_config.get("apc_key_usage")
    apc_key_modes_of_use = rsa_config.get("apc_key_modes_of_use")

    # APC returns an RSA wrapping public key certificate (and chain) for the
    # cryptogram import. RSA_4096 is used as the wrapping key algorithm.
    krd_wrapping_key_algorithm = RsaKeyAlgorithm.RSA_4096
    wrapping_spec = RsaWrappingSpec.RSA_OAEP_SHA_512

    print(
        "\nStep 1 ({}) : Get the RSA wrapping public key certificate and chain.".format(krd.upper())
    )
    print("KRD Wrapping Key Algorithm : {}".format(krd_wrapping_key_algorithm.name))
    krd_ca_certificate, import_token, krd_certificate = krd_host.generate_certificate_and_chain(
        key_algorithm=krd_wrapping_key_algorithm,
        ca_key_algorithm=krd_wrapping_key_algorithm,
        key_usage=AsymmetricKeyUsage.KEY_AGREEMENT_KEY,
        key_exchange_type=KeyExchangeType.IMPORT_KEY_CRYPTOGRAM,
    )
    print("KRD CA Certificate : {}".format(krd_ca_certificate))
    print("KRD Import Token : {}".format(import_token))
    print("KRD Certificate : {}".format(krd_certificate))

    transport_key = kdh_config["rsa"]["transport_key"]
    transport_key_kcv = kdh_config["rsa"]["transport_key_kcv"]
    if transport_key and transport_key_kcv:
        print("\nStep 2 ({}) : Using the transport key from input config".format(kdh.upper()))
        print("Transport Key : ", transport_key)
        print("KCV : ", transport_key_kcv)
    else:
        print(
            "\nStep 2 ({}) : Generate symmetric transport key with KeyUsage : {} and KeyAlgorithm : {}".format(
                kdh.upper(), key_usage.name, key_algorithm.name
            )
        )
        transport_key, transport_key_kcv = kdh_host.create_symmetric_key(key_algorithm, key_usage)
        print("Transport Key : ", transport_key)
        print("KCV : ", transport_key_kcv)

    print(
        "\nStep 3 ({}) : Export the transport key as an RSA key cryptogram (WrappingSpec : {}).".format(
            kdh.upper(), wrapping_spec.name
        )
    )
    if "futurex" == kdh:
        # Futurex needs the KRD CA trusted before the KRD certificate can be used
        # as the RSA wrapping key.
        print("Trusting KRD certificate chain on {}".format(kdh.upper()))
        krd_ca_certificate_trusted = kdh_host.trust_certificate_chain(
            krd_ca_certificate, krd_wrapping_key_algorithm
        )
        rsa_cryptogram = kdh_host.export_symmetric_key_using_rsa(
            krd_ca_certificate_trusted,
            krd_certificate,
            transport_key,
            key_algorithm.name,
            wrapping_spec,
        )
    else:
        # payShield imports the KRD public key directly under the LMK for wrapping.
        rsa_cryptogram = kdh_host.export_symmetric_key_using_rsa(
            krd_certificate,
            transport_key,
            key_algorithm.name,
            wrapping_spec,
        )
    print("RSA Key Cryptogram : {}".format(rsa_cryptogram))

    print("\nStep 4 ({}) : Import the transport key using the RSA key cryptogram.".format(krd.upper()))
    imported_key, imported_key_kcv = krd_host.import_symmetric_key_using_rsa(
        import_token,
        rsa_cryptogram,
        key_algorithm,
        key_usage,
        wrapping_spec,
        apc_key_usage=apc_key_usage,
        apc_key_modes_of_use=apc_key_modes_of_use,
    )
    print("\nImported Key : {}".format(imported_key))
    print("Imported Key KCV : {}".format(imported_key_kcv))


if __name__ == "__main__":
    main()
