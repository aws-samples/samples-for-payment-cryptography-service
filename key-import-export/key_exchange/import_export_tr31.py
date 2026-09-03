# flake8: noqa: E402
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json

from key_exchange.hsm.futurex.futurex_hsm import FuturexHsm
from key_exchange.hsm.payshield.payshield_hsm import PayshieldHsm
from key_exchange.utils.apc import Apc
from key_exchange.utils import phases
from key_exchange.utils.enums import SymmetricKeyAlgorithm, SymmetricKeyUsage

FLOW = "tr31"
DEFAULT_EXPORT_FILE = phases.default_export_file(FLOW)


def _get_command_line_args():
    # TR31 uses a KEK that must already be established on both sides (e.g. via
    # TR34 or ECDH), so there is no APC "get-params" phase for this flow.
    parser = phases.new_parser(
        description=(
            "Exchange a symmetric key from a KDH (HSM) to a KRD (AWS Payment "
            "Cryptography) under a pre-shared KEK using TR-31. Run the whole "
            "flow end to end (--mode full), or split it into export (HSM) and "
            "import (APC) so the HSM and APC can run in separate environments."
        ),
        supports_get_params=False,
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


def phase_export(kdh, kdh_config, key_algorithm, key_usage):
    """
    HSM side. Wraps the transport key under the KDH's pre-shared KEK using
    TR-31, producing a TR-31 key block. Requires kdh_config["tr31"]["kek"] to
    already be set (e.g. established previously via TR-34 or ECDH).
    """
    kdh_host = _get_kdh_host(kdh, kdh_config)

    kdh_kek = kdh_config["tr31"]["kek"]
    if not kdh_kek:
        print(
            "\nFor export using TR31, a KEK needs to be established on the KDH. "
            "Use TR34 or ECDH to establish the KEK and update input_config file."
        )
        sys.exit(1)

    transport_key = kdh_config["tr31"]["transport_key"]
    transport_key_kcv = kdh_config["tr31"]["transport_key_kcv"]
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

    print("\nPhase 'export' ({}) : Export the transport key under the KEK using TR31.".format(kdh.upper()))
    exported_key = kdh_host.export_symmetric_key_using_tr31(transport_key, kdh_kek, key_algorithm.name)
    print("Exported Key using KEK : {}".format(exported_key))

    return {
        "kdh": kdh,
        "key_algorithm": key_algorithm.name,
        "exported_key": exported_key,
        "transport_key_kcv": transport_key_kcv,
    }


def phase_import(krd, krd_config, export_state):
    """
    APC side. Imports the TR-31 key block produced by the export phase under
    the KRD's pre-shared KEK. Requires krd_config["tr31"]["kek"] to already be
    set (the same KEK established on the KDH side).
    """
    krd_host = _get_krd_host(krd, krd_config)

    krd_kek = krd_config["tr31"]["kek"]
    if not krd_kek:
        print(
            "\nFor import using TR31, a KEK needs to be established on the KRD. "
            "Use TR34 or ECDH to establish the KEK and update input_config file."
        )
        sys.exit(1)

    exported_key = export_state["exported_key"]
    key_algorithm = SymmetricKeyAlgorithm[export_state["key_algorithm"]]

    print("\nPhase 'import' ({}) : Import the transport key under the KEK using TR31.".format(krd.upper()))
    imported_key, imported_key_kcv = krd_host.import_symmetric_key_using_tr31(
        exported_key, krd_kek, key_algorithm
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

    print("\n####### Key Exchange using TR31 #######")
    print("Mode : ", mode)
    print("Key Distribution Host (KDH) : ", kdh.upper())
    print("Key Receiving Device (KRD) : ", krd.upper())

    kdh_config = config["kdh"][kdh]
    krd_config = config["krd"][krd]

    key_usage = SymmetricKeyUsage.BDK
    key_algorithm = SymmetricKeyAlgorithm.TDES_3KEY

    if mode == phases.MODE_EXPORT:
        output_file = args.output_file or DEFAULT_EXPORT_FILE
        state = phase_export(kdh, kdh_config, key_algorithm, key_usage)
        phases.save_state(output_file, state)
        print("\nWrote TR31 export output to : {}".format(output_file))
        print("Transfer this file to the APC environment and run --mode import.")

    elif mode == phases.MODE_IMPORT:
        input_file = args.input_file or DEFAULT_EXPORT_FILE
        export_state = phases.load_state(input_file)
        phase_import(krd, krd_config, export_state)

    else:  # full
        export_state = phase_export(kdh, kdh_config, key_algorithm, key_usage)
        phase_import(krd, krd_config, export_state)


if __name__ == "__main__":
    main()
