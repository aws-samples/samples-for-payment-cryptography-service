# flake8: noqa: E402
import argparse
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_import_export.hsm.futurex.futurex_hsm import FuturexHsm
from key_import_export.hsm.payshield.payshield_hsm import PayshieldHsm
from key_import_export.utils.apc import Apc
from key_import_export.utils.enums import SymmetricKeyAlgorithm, SymmetricKeyUsage


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

    print("\n####### Key Exchange using TR31 #######")
    print("\nKey Distribution Host (KDH) : ", kdh.upper())
    print("Key Receiving Device (KRD) : ", krd.upper())

    kdh_config = config["kdh"][kdh]
    krd_config = config["krd"][krd]
    kdh_host, krd_host = _get_kdh_krd_hosts(kdh, krd, kdh_config, krd_config)

    key_usage = SymmetricKeyUsage.BDK
    key_algorithm = SymmetricKeyAlgorithm.TDES_3KEY

    kdh_kek = kdh_config["tr31"]["kek"]
    krd_kek = krd_config["tr31"]["kek"]
    if not kdh_kek or not krd_kek:
        print(
            "\nFor import using TR31, a KEK needs to be established between KDH and KRD. Use TR34 to establish the KEK and update input_config file."
        )
        sys.exit(1)

    transport_key = kdh_config["tr31"]["transport_key"]
    transport_key_kcv = kdh_config["tr31"]["transport_key_kcv"]
    if transport_key and transport_key_kcv:
        print("\nStep 1 ({}) : Using the transport key from input config".format(kdh.upper()))
        print("Transport Key : ", transport_key)
        print("KCV : ", transport_key_kcv)
    else:
        print(
            "\nStep 1 ({}) : Generate symmetric transport key with KeyUsage : {} and KeyAlgorithm : {}".format(
                kdh.upper(), key_usage.name, key_algorithm.name
            )
        )
        transport_key, transport_key_kcv = kdh_host.create_symmetric_key(key_algorithm, key_usage)
        print("Transport Key : ", transport_key)
        print("KCV : ", transport_key_kcv)

    print("\nStep 2 ({}) : Export the transport key under the KEK using TR31.".format(kdh.upper()))
    exported_key = kdh_host.export_symmetric_key_using_tr31(transport_key, kdh_kek)
    print("Exported Key using KEK : {}".format(exported_key))

    print("\nStep 3 ({}) : Import the transport key under the KEK using TR31.".format(krd.upper()))
    imported_key, imported_key_kcv = krd_host.import_symmetric_key_using_tr31(exported_key, krd_kek)
    print("\nImported Key : {}".format(imported_key))
    print("Imported Key KCV : {}".format(imported_key_kcv))


if __name__ == "__main__":
    main()
