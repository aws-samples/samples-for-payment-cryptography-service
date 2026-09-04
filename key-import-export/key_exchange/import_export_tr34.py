# flake8: noqa: E402
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

from key_exchange.hsm.futurex.futurex_hsm import FuturexHsm
from key_exchange.hsm.payshield.payshield_hsm import PayshieldHsm
from key_exchange.utils.apc import Apc
from key_exchange.utils import phases
from key_exchange.utils.enums import (
    AsymmetricKeyUsage,
    KeyExchangeType,
    RsaKeyAlgorithm,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)
from key_exchange.utils.serialization import certificate_from_pem, certificate_to_pem

FLOW = "tr34"
DEFAULT_PARAMS_FILE = phases.default_params_file(FLOW)
DEFAULT_EXPORT_FILE = phases.default_export_file(FLOW)


def _get_command_line_args():
    parser = phases.new_parser(
        description=(
            "Exchange a symmetric key from a KDH (HSM) to a KRD (AWS Payment "
            "Cryptography) using TR-34 (2-pass). Run the whole flow end to end "
            "(--mode full), or split it into get-params (APC), export (HSM), "
            "and import (APC) so the HSM and APC can run in separate "
            "environments."
        )
    )
    return parser.parse_args()


def _get_kdh_host(kdh, kdh_config):
    if "futurex" == kdh:
        return FuturexHsm(kdh_config)
    elif "payshield" == kdh:
        return PayshieldHsm(kdh_config)
    raise ValueError("Unsupported KDH: {}".format(kdh))


def _get_krd_host(krd, krd_config):
    # For KRD, only APC is supported for now
    return Apc(krd_config)


def _load_config():
    with open(os.path.dirname(__file__) + "/input_config.json", "r") as jsonfile:
        return json.load(jsonfile)


def phase_get_params(krd, krd_config, krd_algorithm, krd_ca_algorithm):
    """
    APC side. Generates the KRD's TR-34 import certificate + chain and import
    token, which the HSM needs to build the TR-34 payload against.
    """
    krd_host = _get_krd_host(krd, krd_config)

    print(
        "\nPhase 'get-params' ({}) : Get the wrapping public key certificate and chain.".format(
            krd.upper()
        )
    )
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
    print("KRD Import Token : {}".format(krd_private_key))
    print("KRD Certificate : {}".format(krd_certificate))

    return {
        "krd": krd,
        "krd_algorithm": krd_algorithm.name,
        "krd_ca_algorithm": krd_ca_algorithm.name,
        "krd_private_key": krd_private_key,
        "krd_certificate_pem": certificate_to_pem(krd_certificate),
        "krd_ca_certificate_pem": certificate_to_pem(krd_ca_certificate),
    }


def phase_export(kdh, kdh_config, params_state, kdh_algorithm, kdh_ca_algorithm, key_algorithm, key_usage):
    """
    HSM side. Generates the KDH's signing certificate + chain, trusts the
    KRD CA (locally, on the HSM), and builds the TR-34 2-pass payload wrapping
    the transport key under the KRD's public key.
    """
    kdh_host = _get_kdh_host(kdh, kdh_config)

    krd_certificate = certificate_from_pem(params_state["krd_certificate_pem"])
    krd_ca_certificate = certificate_from_pem(params_state["krd_ca_certificate_pem"])
    # Reconstruct by enum member NAME (not value) since that's what was stored;
    # RsaKeyAlgorithm.RSA_2048's value does not equal its member name.
    krd_ca_algorithm = RsaKeyAlgorithm[params_state["krd_ca_algorithm"]]

    print(
        "\nPhase 'export' ({}) : Creating KDH certificate (for signing the key block) and certificate chain.".format(
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

    print("\nPhase 'export' ({}) : Trust KRD certificate chain".format(kdh.upper()))
    krd_ca_certificate_trusted = kdh_host.trust_certificate_chain(krd_ca_certificate, krd_ca_algorithm)
    print("KRD CA Certificate Trusted : {}".format(krd_ca_certificate_trusted))

    transport_key = kdh_config["tr34"]["transport_key"]
    transport_key_kcv = kdh_config["tr34"]["transport_key_kcv"]
    if transport_key and transport_key_kcv:
        print("\nPhase 'export' ({}) : Using the transport key from input config".format(kdh.upper()))
        print("Transport Key : ", transport_key)
        print("KCV : ", transport_key_kcv)
    else:
        print(
            "\nPhase 'export' ({}) : Generate symmetric transport key with KeyUsage : {} and KeyAlgorithm : {}".format(
                kdh.upper(), key_usage.name, key_algorithm.name
            )
        )
        transport_key, transport_key_kcv = kdh_host.create_symmetric_key(key_algorithm, key_usage)
        print("Transport Key : ", transport_key)
        print("KCV : ", transport_key_kcv)

    print("\nPhase 'export' ({}) : Export the transport key using TR34 (2Pass).".format(kdh.upper()))
    tr34_payload, nonce = kdh_host.export_symmetric_key_using_tr34(
        kdh_certificate, kdh_private_key, krd_certificate, krd_ca_certificate_trusted, transport_key
    )
    print("TR34 Payload : {}".format(tr34_payload))
    print("Nonce : {}".format(nonce))

    export_state = dict(params_state)
    export_state["kdh"] = kdh
    export_state["kdh_algorithm"] = kdh_algorithm.name
    export_state["kdh_ca_algorithm"] = kdh_ca_algorithm.name
    export_state["kdh_certificate_pem"] = certificate_to_pem(kdh_certificate)
    export_state["kdh_ca_certificate_pem"] = certificate_to_pem(kdh_ca_certificate)
    export_state["tr34_payload"] = tr34_payload
    export_state["nonce"] = nonce
    export_state["key_algorithm"] = key_algorithm.name
    export_state["transport_key_kcv"] = transport_key_kcv
    return export_state


def phase_import(krd, krd_config, export_state):
    """
    APC side. Trusts the KDH CA (locally, on APC) and imports the TR-34
    payload produced by the export phase, using the import token from the
    get-params phase.
    """
    krd_host = _get_krd_host(krd, krd_config)

    krd_certificate = certificate_from_pem(export_state["krd_certificate_pem"])
    krd_private_key = export_state["krd_private_key"]
    kdh_certificate = certificate_from_pem(export_state["kdh_certificate_pem"])
    kdh_ca_certificate = certificate_from_pem(export_state["kdh_ca_certificate_pem"])
    kdh_ca_algorithm = RsaKeyAlgorithm[export_state["kdh_ca_algorithm"]]
    tr34_payload = export_state["tr34_payload"]
    nonce = export_state["nonce"]
    key_algorithm = SymmetricKeyAlgorithm[export_state["key_algorithm"]]

    print("\nPhase 'import' ({}) : Trust KDH certificate chain.".format(krd.upper()))
    kdh_ca_certificate_trusted = krd_host.trust_certificate_chain(kdh_ca_certificate, kdh_ca_algorithm)
    print("KDH CA Certificate Trusted : {}".format(kdh_ca_certificate_trusted))

    print("\nPhase 'import' ({}) : Import the transport key using TR34 (2Pass).".format(krd.upper()))
    imported_key, imported_key_kcv = krd_host.import_symmetric_key_using_tr34(
        krd_certificate,
        krd_private_key,
        kdh_certificate,
        kdh_ca_certificate_trusted,
        tr34_payload,
        nonce,
        key_algorithm,
    )
    print("\nImported Key : {}".format(imported_key))
    print("Imported Key KCV : {}".format(imported_key_kcv))
    return imported_key, imported_key_kcv


def main():
    args = _get_command_line_args()
    config = _load_config()

    kdh = args.kdh
    krd = args.krd
    mode = args.mode

    print("\n####### Key Exchange using TR34 #######")
    print("Mode : ", mode)
    print("Key Distribution Host (KDH) : ", kdh.upper())
    print("Key Receiving Device (KRD) : ", krd.upper())

    kdh_config = config["kdh"][kdh]
    krd_config = config["krd"][krd]

    key_usage = SymmetricKeyUsage.KBPK
    key_algorithm = SymmetricKeyAlgorithm.TDES_3KEY

    kdh_ca_algorithm = RsaKeyAlgorithm.RSA_2048
    kdh_algorithm = RsaKeyAlgorithm.RSA_2048
    krd_ca_algorithm = RsaKeyAlgorithm.RSA_4096
    krd_algorithm = RsaKeyAlgorithm.RSA_2048

    if mode == phases.MODE_GET_PARAMS:
        output_file = args.output_file or DEFAULT_PARAMS_FILE
        state = phase_get_params(krd, krd_config, krd_algorithm, krd_ca_algorithm)
        phases.save_state(output_file, state)
        print("\nWrote import parameters to : {}".format(output_file))
        print("Transfer this file to the HSM environment and run --mode export.")

    elif mode == phases.MODE_EXPORT:
        input_file = args.input_file or DEFAULT_PARAMS_FILE
        output_file = args.output_file or DEFAULT_EXPORT_FILE
        params_state = phases.load_state(input_file)
        state = phase_export(
            kdh, kdh_config, params_state, kdh_algorithm, kdh_ca_algorithm, key_algorithm, key_usage
        )
        phases.save_state(output_file, state)
        print("\nWrote TR34 export output to : {}".format(output_file))
        print("Transfer this file to the APC environment and run --mode import.")

    elif mode == phases.MODE_IMPORT:
        input_file = args.input_file or DEFAULT_EXPORT_FILE
        export_state = phases.load_state(input_file)
        phase_import(krd, krd_config, export_state)

    else:  # full
        params_state = phase_get_params(krd, krd_config, krd_algorithm, krd_ca_algorithm)
        export_state = phase_export(
            kdh, kdh_config, params_state, kdh_algorithm, kdh_ca_algorithm, key_algorithm, key_usage
        )
        phase_import(krd, krd_config, export_state)


if __name__ == "__main__":
    main()
