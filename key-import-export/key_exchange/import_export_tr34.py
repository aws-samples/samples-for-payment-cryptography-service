# flake8: noqa: E402

import argparse
import json
import os
import re
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_exchange.hsm.futurex.futurex_hsm import FuturexHsm
from key_exchange.hsm.payshield.payshield_hsm import PayshieldHsm
from key_exchange.utils.apc import Apc
from key_exchange.utils.enums import (
    AsymmetricKeyUsage,
    KeyExchangeType,
    RsaKeyAlgorithm,
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

    print("\n####### Key Exchange using TR34 #######")
    print("\nKey Distribution Host (KDH) : ", kdh.upper())
    print("Key Receiving Device (KRD) : ", krd.upper())

    kdh_config = config["kdh"][kdh]
    krd_config = config["krd"][krd]
    kdh_host, krd_host = _get_kdh_krd_hosts(kdh, krd, kdh_config, krd_config)

    key_usage = SymmetricKeyUsage.KBPK
    key_algorithm = SymmetricKeyAlgorithm.TDES_3KEY

    kdh_ca_algorithm = RsaKeyAlgorithm.RSA_2048
    kdh_algorithm = RsaKeyAlgorithm.RSA_2048
    krd_ca_algorithm = RsaKeyAlgorithm.RSA_4096
    krd_algorithm = RsaKeyAlgorithm.RSA_2048

    print(
        "\nStep 1 ({}) : Creating KDH certificate (for signing the key block) and certificate chain.".format(
            kdh.upper()
        )
    )
    print(
        "KDH Certificate KeyAlgorithm : {} , KDH CertificateAuthority KeyAlgorithm : {}".format(
            kdh_algorithm.name, kdh_ca_algorithm.name
        )
    )
    kdh_ca_certificate, kdh_private_key, kdh_certificate = kdh_host.generate_certificate_and_chain(
        key_algorithm=kdh_algorithm,
        ca_key_algorithm=kdh_ca_algorithm,
        key_usage=AsymmetricKeyUsage.SIGN,
        key_exchange_type=KeyExchangeType.EXPORT_TR34_KEY_BLOCK,
    )
    print("KDH CA Certificate : {}".format(kdh_ca_certificate))
    print("KDH Private Key : {}".format(kdh_private_key))
    print("KDH Certificate : {}".format(kdh_certificate))
    
    print("\nStep 2 ({}) : Get the wrapping public key certificate and chain.".format(krd.upper()))
    print(
        "KRD Certificate KeyAlgorithm : {} , KRD CertificateAuthority KeyAlgorithm : {}".format(
            krd_algorithm.name, krd_ca_algorithm.name
        )
    )
    krd_ca_certificate, krd_private_key, krd_certificate = krd_host.generate_certificate_and_chain(
        key_algorithm=krd_algorithm,
        ca_key_algorithm=krd_ca_algorithm,
        key_usage=AsymmetricKeyUsage.SIGN,
        key_exchange_type=KeyExchangeType.IMPORT_TR34_KEY_BLOCK,
    )
    print("KRD CA Certificate : {}".format(krd_ca_certificate))
    print("KRD Private Key : {}".format(krd_private_key))
    print("KRD Certificate : {}".format(krd_certificate))

    print("\nStep 3 ({}) : Trust KRD certificate chain".format(kdh.upper()))
    krd_ca_certificate_trusted = kdh_host.trust_certificate_chain(
        krd_ca_certificate, krd_ca_algorithm
    )
    print("KRD CA Certificate Trusted : {}".format(krd_ca_certificate_trusted))

    print("\nStep 4 ({}) : Trust KDH certificate chain.".format(krd.upper()))
    kdh_ca_certificate_trusted = krd_host.trust_certificate_chain(
        kdh_ca_certificate, kdh_ca_algorithm
    )
    print("KDH CA Certificate Trusted : {}".format(kdh_ca_certificate_trusted))

    transport_key = kdh_config["tr34"]["transport_key"]
    transport_key_kcv = kdh_config["tr34"]["transport_key_kcv"]
    if transport_key and transport_key_kcv:
        print("\nStep 5 ({}) : Using the transport key from input config".format(kdh.upper()))
        print("Transport Key : ", transport_key)
        print("KCV : ", transport_key_kcv)
    else:
        print(
            "\nStep 5 ({}) : Generate symmetric transport key with KeyUsage : {} and KeyAlgorithm : {}".format(
                kdh.upper(), key_usage.name, key_algorithm.name
            )
        )
        transport_key, transport_key_kcv = kdh_host.create_symmetric_key(key_algorithm, key_usage)
        print("Transport Key : ", transport_key)
        print("KCV : ", transport_key_kcv)

    print("\nStep 6 ({}) : Export the transport key using TR34 (2Pass).".format(kdh.upper()))
    tr34_payload, nonce = kdh_host.export_symmetric_key_using_tr34(
        kdh_certificate, kdh_private_key, krd_certificate, krd_ca_certificate_trusted, transport_key
    )
    print("TR34 Payload : {}".format(tr34_payload))
    print("Nonce : {}".format(nonce))

    print("\nStep 7 ({}) : Import the transport key using TR34 (2Pass).".format(krd.upper()))
    imported_key, imported_key_kcv = krd_host.import_symmetric_key_using_tr34(
        krd_certificate,
        krd_private_key,
        kdh_certificate,
        kdh_ca_certificate_trusted,
        tr34_payload,
        nonce,
    )
    print("\nImported Key : {}".format(imported_key))
    print("Imported Key KCV : {}".format(imported_key_kcv))


if __name__ == "__main__":
    main()
