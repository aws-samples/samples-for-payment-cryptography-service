#!/usr/bin/env python3
"""
Re-mode a symmetric key in AWS Payment Cryptography from TR-31 mode of use
'N' (NoRestrictions) to a mode that X9.143 allows for its key usage.

A payShield accepts mode N on keys such as CVKs (C0), EMV issuer master keys
(E*), MAC keys (M*), PIN keys (P0, V*) and KEKs (K*). AWS Payment
Cryptography imports these keys, but:
  - C0, E0, E1, E4, E6, M1, M3, M6, M7, V1 and V2 keys with mode N are
    refused by the operations that use them, so they must be re-moded.
  - B0, D0, E2, K0, K1 and P0 keys with mode N still work. Re-moding them
    restricts the key to the X9.143 modes for its usage, which is
    recommended but optional.
  - E5 (card personalization) isn't used by any AWS Payment Cryptography
    operation, but can still be re-moded.

The TR-31 header is MAC-bound, so the mode byte can't be edited in place.
Instead the key is exported under a temporary KEK with KeyBlockHeaders
narrowing the modes of use, then re-imported from that new block.

Supported key usages and target modes (default first):
  B0, E0, E1, E2, E4, E5, E6          X (DeriveKey)
  C0, M1, M3, M6, M7, V1, V2          C (Generate+Verify), G (Generate), V (Verify)
  D0, K0, K1, P0                      B (Encrypt+Decrypt+Wrap+Unwrap),
                                      E (Encrypt+Wrap), D (Decrypt+Unwrap)

Flow:
  1. (outside this script) Import the clear KEK with the ECDH importer in this repo:
       ../../key-import-export/ecdh/import_app/import_raw_key_ecdh.py \\
         --clearkey <hex> --key-type K0 --algorithm T --mode-of-use B --export-mode E
     -> KEK_ARN (pass as --kek-arn)
  2. Create a temporary AES-256 KEK                              -> KEK2_ARN
  3. Import the mode-N key (TR-31) under KEK_ARN                  -> key (mode N)
     (skipped if --key-arn is given instead of --key-block)
  4. Export the key under KEK2_ARN, changing mode of use N -> --mode
  5. Import the step-4 block under KEK2_ARN                       -> key (new mode)
  6. Delete KEK2_ARN (always, even on failure)
  Optional: --delete-original also schedules the mode-N key for deletion.

Examples:
  # CVK block exported from payShield, re-moded to C (the C0 default)
  python3 remode_key.py --region us-east-1 \\
      --kek-arn alias/import-kek-ecdh-result \\
      --key-block B0080C0TN00E0000...

  # EMV issuer master key already in AWS Payment Cryptography with mode N
  python3 remode_key.py --region us-east-1 --key-arn arn:...:key/abcd1234

  # PIN encryption key re-moded to encrypt-only
  python3 remode_key.py --region us-east-1 --kek-arn <KEK> \\
      --key-block B0080P0TN00E0000... --mode E

  # Decode a block header without calling AWS Payment Cryptography:
  python3 remode_key.py --parse-only --key-block B0080C0TN00E0000...
"""

import argparse
import sys

import boto3

MODE_NAMES = {
    "B": "Encrypt+Decrypt / Wrap+Unwrap",
    "C": "Generate+Verify",
    "D": "Decrypt/Unwrap only",
    "E": "Encrypt/Wrap only",
    "G": "Generate only",
    "N": "No restrictions",
    "S": "Sign only",
    "T": "Sign+Verify",
    "V": "Verify only",
    "X": "Derive keys",
    "Y": "Create key variants",
}

# Every flag in the KeyModesOfUse structure. Target modes set each one
# explicitly, so NoRestrictions (mode N) is always turned off.
_MODE_FLAGS = ("Encrypt", "Decrypt", "Wrap", "Unwrap", "Generate", "Sign",
               "Verify", "DeriveKey", "NoRestrictions")


def _modes(*enabled: str) -> dict:
    return {flag: flag in enabled for flag in _MODE_FLAGS}


# TR-31 mode of use -> AWS Payment Cryptography KeyModesOfUse
TARGET_MODES = {
    "B": _modes("Encrypt", "Decrypt", "Wrap", "Unwrap"),
    "E": _modes("Encrypt", "Wrap"),
    "D": _modes("Decrypt", "Unwrap"),
    "C": _modes("Generate", "Verify"),
    "G": _modes("Generate"),
    "V": _modes("Verify"),
    "X": _modes("DeriveKey"),
}

# Key usage -> target modes X9.143 allows for it (first entry is the default).
# Every symmetric key usage that AWS Payment Cryptography accepts with mode N.
_DERIVE = ("X",)
_ENCRYPT = ("B", "E", "D")
_GEN_VERIFY = ("C", "G", "V")
KEY_USAGE_MODES = {
    "B0": _DERIVE,       # Base derivation key (BDK)
    "C0": _GEN_VERIFY,   # Card verification key (CVK)
    "D0": _ENCRYPT,      # Symmetric data encryption key
    "E0": _DERIVE,       # EMV issuer master key: application cryptograms
    "E1": _DERIVE,       # EMV issuer master key: secure messaging confidentiality
    "E2": _DERIVE,       # EMV issuer master key: secure messaging integrity
    "E4": _DERIVE,       # EMV issuer master key: dynamic numbers
    "E5": _DERIVE,       # EMV issuer master key: card personalization
    "E6": _DERIVE,       # EMV issuer master key: other
    "K0": _ENCRYPT,      # Key encryption key
    "K1": _ENCRYPT,      # TR-31 key block protection key
    "M1": _GEN_VERIFY,   # ISO 9797-1 MAC algorithm 1
    "M3": _GEN_VERIFY,   # ISO 9797-1 MAC algorithm 3
    "M6": _GEN_VERIFY,   # ISO 9797-1 MAC algorithm 5 (CMAC)
    "M7": _GEN_VERIFY,   # HMAC
    "P0": _ENCRYPT,      # PIN encryption key
    "V1": _GEN_VERIFY,   # IBM 3624 PIN verification key
    "V2": _GEN_VERIFY,   # Visa PIN verification key (PVV)
}


def parse_tr31_header(block: str) -> dict:
    """Decode the fixed 16-char TR-31 header."""
    if len(block) < 16:
        raise ValueError("Key block too short to contain a TR-31 header")
    hdr = {
        "version": block[0],
        "length": int(block[1:5]),
        "usage": block[5:7],
        "algorithm": block[7],
        "mode_of_use": block[8],
        "key_version": block[9:11],
        "exportability": block[11],
        "num_optional_blocks": int(block[12:14]),
    }
    if hdr["length"] != len(block):
        raise ValueError(f"Header length {hdr['length']} != actual block length {len(block)}")
    return hdr


def print_header(label: str, block: str) -> dict:
    hdr = parse_tr31_header(block)
    print(f"{label}: {block}")
    print(f"  version={hdr['version']} usage={hdr['usage']} alg={hdr['algorithm']} "
          f"mode={hdr['mode_of_use']} ({MODE_NAMES.get(hdr['mode_of_use'], '?')}) "
          f"kv={hdr['key_version']} export={hdr['exportability']} "
          f"optblocks={hdr['num_optional_blocks']}")
    return hdr


def print_key(key: dict) -> None:
    modes = [m for m, on in key["KeyAttributes"]["KeyModesOfUse"].items() if on]
    print(f"  ARN:   {key['KeyArn']}")
    print(f"  Usage: {key['KeyAttributes']['KeyUsage']}  Alg: {key['KeyAttributes']['KeyAlgorithm']}")
    print(f"  KCV:   {key['KeyCheckValue']}  Exportable: {key['Exportable']}  Modes: {modes}")


def key_usage_code(key: dict) -> str:
    """TR31_C0_CARD_VERIFICATION_KEY -> C0"""
    return key["KeyAttributes"]["KeyUsage"].split("_")[1]


def resolve_mode(usage: str, requested: str) -> str:
    """Return the target mode for a key usage, or raise if it isn't allowed."""
    allowed = KEY_USAGE_MODES.get(usage)
    if allowed is None:
        raise ValueError(f"Key usage {usage} isn't supported. "
                         f"Supported: {', '.join(KEY_USAGE_MODES)}")
    mode = requested or allowed[0]
    if mode not in allowed:
        raise ValueError(f"Mode {mode} isn't allowed for key usage {usage}. "
                         f"Allowed: {', '.join(allowed)}")
    return mode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--key-block", help="TR-31 key block (mode N) wrapped under --kek-arn")
    src.add_argument("--key-arn",
                     help="Existing key in AWS Payment Cryptography to re-mode (skips step 3)")
    ap.add_argument("--kek-arn", help="KEK_ARN from step 1 (required with --key-block)")
    ap.add_argument("--mode", choices=TARGET_MODES,
                    help="Target mode of use. Defaults to X for derivation keys "
                         "(B0, E*), C for generate/verify keys (C0, M*, V*) and "
                         "B for encryption keys (D0, K0, K1, P0)")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--delete-original", action="store_true",
                    help="Also schedule the mode-N key for deletion")
    ap.add_argument("--parse-only", action="store_true",
                    help="Decode --key-block header and exit without calling "
                         "AWS Payment Cryptography")
    args = ap.parse_args()

    block = args.key_block.strip().upper() if args.key_block else None
    if args.parse_only:
        if not block:
            ap.error("--parse-only requires --key-block")
        print_header("Block", block)
        return 0
    if block and not args.kek_arn:
        ap.error("--kek-arn is required with --key-block")

    # Check the key usage and target mode before creating anything
    if block:
        try:
            hdr = parse_tr31_header(block)
            mode = resolve_mode(hdr["usage"], args.mode)
        except ValueError as exc:
            ap.error(str(exc))

    cp = boto3.client("payment-cryptography", region_name=args.region)
    kek2_arn = None
    try:
        if not block:
            source = cp.get_key(KeyIdentifier=args.key_arn)["Key"]
            try:
                mode = resolve_mode(key_usage_code(source), args.mode)
            except ValueError as exc:
                ap.error(str(exc))

        # 2. Temporary AES-256 KEK used only for the re-mode round trip
        print("[2] Creating temporary AES-256 KEK (KEK2)")
        kek2 = cp.create_key(
            KeyAttributes={
                "KeyUsage": "TR31_K0_KEY_ENCRYPTION_KEY",
                "KeyClass": "SYMMETRIC_KEY",
                "KeyAlgorithm": "AES_256",
                "KeyModesOfUse": TARGET_MODES["B"],
            },
            Exportable=False,
            Enabled=True,
        )["Key"]
        kek2_arn = kek2["KeyArn"]
        print_key(kek2)

        # 3. Import the mode-N key under KEK_ARN (or use an existing key)
        if block:
            print("\n[3] Importing mode-N key under KEK_ARN")
            print_header("  Block", block)
            source = cp.import_key(
                KeyMaterial={"Tr31KeyBlock": {
                    "WrappingKeyIdentifier": args.kek_arn,
                    "WrappedKeyBlock": block,
                }},
                Enabled=True,
            )["Key"]
        else:
            print("\n[3] Skipped (using existing key)")
        print_key(source)
        source_arn, source_kcv = source["KeyArn"], source["KeyCheckValue"]

        # 4. Export under KEK2 with modes narrowed N -> target. Exportability
        #    is left unset so it carries over from the source key.
        print(f"\n[4] Exporting key under KEK2 with mode {mode} ({MODE_NAMES[mode]})")
        new_block = cp.export_key(
            ExportKeyIdentifier=source_arn,
            KeyMaterial={"Tr31KeyBlock": {
                "WrappingKeyIdentifier": kek2_arn,
                "KeyBlockHeaders": {"KeyModesOfUse": TARGET_MODES[mode]},
            }},
        )["WrappedKey"]["KeyMaterial"]
        new_hdr = print_header("  New block", new_block)
        if new_hdr["mode_of_use"] != mode:
            raise RuntimeError(
                f"Expected mode {mode} in exported header, got {new_hdr['mode_of_use']}")

        # 5. Import the re-moded block under KEK2
        print(f"\n[5] Importing mode-{mode} block under KEK2")
        final = cp.import_key(
            KeyMaterial={"Tr31KeyBlock": {
                "WrappingKeyIdentifier": kek2_arn,
                "WrappedKeyBlock": new_block,
            }},
            Enabled=True,
        )["Key"]
        print_key(final)
        if final["KeyCheckValue"] != source_kcv:
            raise RuntimeError(
                f"KCV mismatch: source {source_kcv} vs re-imported {final['KeyCheckValue']}")
        print("  ✓ KCV matches source")
        if final["KeyAttributes"]["KeyModesOfUse"] != TARGET_MODES[mode]:
            raise RuntimeError(
                f"Unexpected modes of use on re-imported key: "
                f"{final['KeyAttributes']['KeyModesOfUse']}")
        print(f"  ✓ Modes of use match {mode}")

        if args.delete_original:
            cp.delete_key(KeyIdentifier=source_arn, DeleteKeyInDays=3)
            print(f"\nScheduled mode-N key for deletion (3 days, restorable): {source_arn}")

        print("\n✅ Done. Re-moded key:")
        print(f"   {final['KeyArn']}")
        return 0

    except Exception as exc:  # surface the AWS Payment Cryptography error text as-is
        print(f"\n❌ Failed: {exc}")
        return 1

    finally:
        # 6. KEK2 was only temporary. AWS Payment Cryptography's minimum deletion
        #    window is 3 days.
        if kek2_arn:
            try:
                cp.delete_key(KeyIdentifier=kek2_arn, DeleteKeyInDays=3)
                print(f"\n[6] Scheduled KEK2 for deletion: {kek2_arn}")
            except Exception as exc:
                print(f"\n⚠ [6] Could not delete KEK2 {kek2_arn}: {exc}")


if __name__ == "__main__":
    sys.exit(main())
