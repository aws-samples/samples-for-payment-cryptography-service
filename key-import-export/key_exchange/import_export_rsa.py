# flake8: noqa: E402
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
    RsaWrappingSpec,
    SymmetricKeyAlgorithm,
    SymmetricKeyUsage,
)
from key_exchange.utils.serialization import (
    certificate_from_pem,
    certificate_to_pem,
)

FLOW = "rsa"
DEFAULT_PARAMS_FILE = phases.default_params_file(FLOW)
DEFAULT_EXPORT_FILE = phases.default_export_file(FLOW)


def _get_command_line_args():
    parser = phases.new_parser(
        description=(
            "Exchange a symmetric key from a KDH (HSM) to a KRD (AWS Payment "
            "Cryptography) as an RSA key cryptogram. Run the whole flow end to "
            "end (--mode full), or split it into get-params (APC), export "
            "(HSM), and import (APC) so the HSM and APC can run in separate "
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


def _rsa_metadata(kdh_config):
    """Reads the transport key metadata from the KDH's rsa config block."""
    rsa_config = kdh_config.get("rsa", {})
    key_algorithm = SymmetricKeyAlgorithm(rsa_config.get("key_algorithm", "TDES_3KEY"))
    # APC key metadata used when importing into APC (KRD). apc_key_usage maps
    # directly to a TR31_* KeyUsage value and apc_key_modes_of_use to a
    # KeyModesOfUse dict. When omitted, they default inside the Apc client. See:
    # https://docs.aws.amazon.com/payment-cryptography/latest/userguide/crypto-ops-validkeys-ops.html
    apc_key_usage = rsa_config.get("apc_key_usage")
    apc_key_modes_of_use = rsa_config.get("apc_key_modes_of_use")
    return key_algorithm, apc_key_usage, apc_key_modes_of_use


def phase_get_params(krd, krd_config, key_algorithm, apc_key_usage, apc_key_modes_of_use):
    """
    APC side. Calls GetParametersForImport and returns the state needed by the
    HSM export phase: the import token and the RSA wrapping certificate + chain.
    """
    krd_host = _get_krd_host(krd, krd_config)

    # APC returns an RSA wrapping public key certificate (and chain) for the
    # cryptogram import. RSA_4096 is used as the wrapping key algorithm.
    krd_wrapping_key_algorithm = RsaKeyAlgorithm.RSA_4096

    print(
        "\nPhase 'get-params' ({}) : Get the RSA wrapping public key certificate and chain.".format(
            krd.upper()
        )
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

    return {
        "krd": krd,
        "krd_wrapping_key_algorithm": krd_wrapping_key_algorithm.name,
        "key_algorithm": key_algorithm.name,
        "apc_key_usage": apc_key_usage,
        "apc_key_modes_of_use": apc_key_modes_of_use,
        "import_token": import_token,
        "krd_certificate_pem": certificate_to_pem(krd_certificate),
        "krd_ca_certificate_pem": certificate_to_pem(krd_ca_certificate),
    }


def phase_export(kdh, kdh_config, params_state, key_algorithm, wrapping_spec):
    """
    HSM side. Uses the KRD wrapping certificate from the get-params phase to
    RSA-wrap the transport key, returning the RSA key cryptogram.
    """
    kdh_host = _get_kdh_host(kdh, kdh_config)

    krd_certificate = certificate_from_pem(params_state["krd_certificate_pem"])
    krd_ca_certificate = certificate_from_pem(params_state["krd_ca_certificate_pem"])
    krd_wrapping_key_algorithm = RsaKeyAlgorithm[params_state["krd_wrapping_key_algorithm"]]

    # Coarse usage used only for HSM-side key generation (when the transport key
    # is not provided in config and a new key is created on the KDH).
    key_usage = SymmetricKeyUsage.KEK

    transport_key = kdh_config["rsa"]["transport_key"]
    transport_key_kcv = kdh_config["rsa"]["transport_key_kcv"]
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

    print(
        "\nPhase 'export' ({}) : Export the transport key as an RSA key cryptogram (WrappingSpec : {}).".format(
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

    # Carry forward everything the import phase needs.
    export_state = dict(params_state)
    export_state["kdh"] = kdh
    export_state["rsa_cryptogram"] = rsa_cryptogram
    export_state["transport_key_kcv"] = transport_key_kcv
    export_state["wrapping_spec"] = wrapping_spec.name
    return export_state


def phase_import(krd, krd_config, export_state):
    """
    APC side. Imports the RSA key cryptogram produced by the export phase using
    the import token from the get-params phase.
    """
    krd_host = _get_krd_host(krd, krd_config)

    import_token = export_state["import_token"]
    rsa_cryptogram = export_state["rsa_cryptogram"]
    key_algorithm = SymmetricKeyAlgorithm(export_state["key_algorithm"])
    wrapping_spec = RsaWrappingSpec(export_state["wrapping_spec"])
    apc_key_usage = export_state.get("apc_key_usage")
    apc_key_modes_of_use = export_state.get("apc_key_modes_of_use")

    # Coarse usage retained only as the enum-based fallback inside the Apc client.
    key_usage = SymmetricKeyUsage.KEK

    print("\nPhase 'import' ({}) : Import the transport key using the RSA key cryptogram.".format(krd.upper()))
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
    return imported_key, imported_key_kcv


def main():
    args = _get_command_line_args()
    config = _load_config()

    kdh = args.kdh
    krd = args.krd
    mode = args.mode

    print("\n####### Key Exchange using RSA (Key Cryptogram) #######")
    print("Mode : ", mode)
    print("Key Distribution Host (KDH) : ", kdh.upper())
    print("Key Receiving Device (KRD) : ", krd.upper())

    kdh_config = config["kdh"][kdh]
    krd_config = config["krd"][krd]

    key_algorithm, apc_key_usage, apc_key_modes_of_use = _rsa_metadata(kdh_config)
    wrapping_spec = RsaWrappingSpec.RSA_OAEP_SHA_512

    if mode == phases.MODE_GET_PARAMS:
        output_file = args.output_file or DEFAULT_PARAMS_FILE
        state = phase_get_params(
            krd, krd_config, key_algorithm, apc_key_usage, apc_key_modes_of_use
        )
        phases.save_state(output_file, state)
        print("\nWrote import parameters to : {}".format(output_file))
        print("Transfer this file to the HSM environment and run --mode export.")

    elif mode == phases.MODE_EXPORT:
        input_file = args.input_file or DEFAULT_PARAMS_FILE
        output_file = args.output_file or DEFAULT_EXPORT_FILE
        params_state = phases.load_state(input_file)
        state = phase_export(kdh, kdh_config, params_state, key_algorithm, wrapping_spec)
        phases.save_state(output_file, state)
        print("\nWrote RSA key cryptogram output to : {}".format(output_file))
        print("Transfer this file to the APC environment and run --mode import.")

    elif mode == phases.MODE_IMPORT:
        input_file = args.input_file or DEFAULT_EXPORT_FILE
        export_state = phases.load_state(input_file)
        phase_import(krd, krd_config, export_state)

    else:  # full
        params_state = phase_get_params(
            krd, krd_config, key_algorithm, apc_key_usage, apc_key_modes_of_use
        )
        export_state = phase_export(kdh, kdh_config, params_state, key_algorithm, wrapping_spec)
        phase_import(krd, krd_config, export_state)


if __name__ == "__main__":
    main()
