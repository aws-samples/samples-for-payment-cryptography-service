"""
Shared plumbing for splitting a key exchange into phases that can run in
separate environments (HSM side vs AWS Payment Cryptography side).

Each import_export_*.py script wires its own phase functions, but they all
share the same command line surface (--mode / --output-file / --input-file)
and the same JSON state hand-off, which lives here.

Phase model per flow:
  * rsa  : get-params (APC) -> export (HSM) -> import (APC)
  * tr34 : get-params (APC) -> export (HSM) -> import (APC)
  * ecdh : get-params (APC) -> export (HSM) -> import (APC)
  * tr31 : export (HSM) -> import (APC)          (no get-params; uses a KEK)
"""

import argparse

from key_exchange.utils.serialization import read_state, write_state

# All phase modes. 'full' runs every phase in one process (original behavior).
MODE_FULL = "full"
MODE_GET_PARAMS = "get-params"
MODE_EXPORT = "export"
MODE_IMPORT = "import"

# Default interim file names, parameterized by flow so the four scripts do not
# collide when run from the same working directory.
def default_params_file(flow):
    return "{}_import_params.json".format(flow)


def default_export_file(flow):
    return "{}_export_output.json".format(flow)


def add_phase_arguments(parser, supports_get_params=True, kdh_choices=None):
    """
    Adds the shared --kdh/--krd/--mode/--output-file/--input-file arguments.

    supports_get_params=False omits 'get-params' from the allowed modes (TR31,
    which uses a pre-shared KEK and has no APC parameter-fetch phase).

    kdh_choices overrides the allowed --kdh values (defaults to
    [futurex, payshield]; ECDH additionally allows "apc" as its own KDH).
    """
    kdh_choices = kdh_choices or ["futurex", "payshield"]
    parser.add_argument(
        "--kdh",
        help="Key Distribution Host. Options are {}".format(kdh_choices),
        required=True,
        choices=kdh_choices,
    )
    parser.add_argument(
        "--krd",
        help="Key Receiving Device. Options are [apc]",
        required=False,
        default="apc",
        choices=["apc"],
    )

    modes = [MODE_FULL, MODE_EXPORT, MODE_IMPORT]
    if supports_get_params:
        modes.insert(1, MODE_GET_PARAMS)

    parser.add_argument(
        "--mode",
        help=(
            "Which phase(s) to run. 'full' (default) runs everything end to end. "
            "Split modes let the HSM (KDH) and AWS Payment Cryptography (KRD) run "
            "in separate environments, exchanging a JSON state file."
        ),
        required=False,
        default=MODE_FULL,
        choices=modes,
    )
    parser.add_argument(
        "--output-file",
        help="Path to write interim JSON state (used by get-params and export).",
        required=False,
        default=None,
    )
    parser.add_argument(
        "--input-file",
        help="Path to read interim JSON state from (used by export and import).",
        required=False,
        default=None,
    )
    return parser


def new_parser(description, supports_get_params=True, kdh_choices=None):
    parser = argparse.ArgumentParser(description=description)
    return add_phase_arguments(
        parser, supports_get_params=supports_get_params, kdh_choices=kdh_choices
    )


def load_state(path):
    """Read interim exchange state from a JSON file."""
    return read_state(path)


def save_state(path, state):
    """Write interim exchange state to a JSON file."""
    write_state(path, state)
