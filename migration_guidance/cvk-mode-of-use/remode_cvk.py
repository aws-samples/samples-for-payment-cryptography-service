#!/usr/bin/env python3
"""
Re-mode a CVK (C0) in AWS Payment Cryptography from mode of use 'N'
(NoRestrictions) to 'C' (Generate+Verify), 'G' (Generate) or 'V' (Verify)
so it works with GenerateCardData / VerifyCardData.

Mode N is accepted by a payShield but doesn't meet X9.143 requirements for a
C0 key, and AWS Payment Cryptography doesn't support it.

The TR-31 header is MAC-bound, so the mode byte can't be edited in place.
Instead the key is exported under a temporary KEK with KeyBlockHeaders
narrowing the modes to Generate+Verify, then re-imported from that new block.

Flow:
  1. (outside this script) Import the clear KEK with the ECDH importer in this repo:
       ../../key-import-export/ecdh/import_app/import_raw_key_ecdh.py \
         --clearkey <hex> --key-type K0 --algorithm T --mode-of-use B --export-mode E
     -> KEK_ARN (pass as --kek-arn)
  2. Create a temporary AES-256 KEK                              -> KEK2_ARN
  3. Import the sample CVK (TR-31, mode N) under KEK_ARN          -> CVK (mode N)
     (skipped if --cvk-arn is given instead of --key-block)
  4. Export the CVK under KEK2_ARN, changing mode of use N -> --mode (default C)
  5. Import the step-4 block under KEK2_ARN                       -> CVK (new mode)
  6. Delete KEK2_ARN (always, even on failure)
  Optional: --delete-original also schedules the mode-N CVK for deletion.

Examples:
  python3 remode_cvk.py --region us-east-1 \
      --kek-arn alias/import-kek-ecdh-result \
      --key-block B0080C0TN00S0000...   # TR-31 CVK block wrapped under the KEK

  python3 remode_cvk.py --region us-east-1 --cvk-arn arn:...:key/abcd1234

  # Decode a block header without calling AWS Payment Cryptography:
  python3 remode_cvk.py --parse-only --key-block B0080C0TN00S0000...
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


# Target modes X9.143 allows for a C0 CVK -> AWS Payment Cryptography KeyModesOfUse
TARGET_MODES = {
    "C": {"Generate": True, "Verify": True},
    "G": {"Generate": True},
    "V": {"Verify": True},
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--key-block", help="TR-31 CVK block (mode N) wrapped under --kek-arn")
    src.add_argument("--cvk-arn",
                     help="Existing CVK in AWS Payment Cryptography to re-mode (skips step 3)")
    ap.add_argument("--kek-arn", help="KEK_ARN from step 1 (required with --key-block)")
    ap.add_argument("--mode", choices=TARGET_MODES, default="C",
                    help="Target mode of use: C=Generate+Verify (default), G=Generate, V=Verify")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--delete-original", action="store_true",
                    help="Also schedule the mode-N CVK for deletion")
    ap.add_argument("--parse-only", action="store_true",
                    help="Decode --key-block header and exit without calling "
                         "AWS Payment Cryptography")
    args = ap.parse_args()

    if args.parse_only:
        if not args.key_block:
            ap.error("--parse-only requires --key-block")
        print_header("Block", args.key_block.strip().upper())
        return 0
    if args.key_block and not args.kek_arn:
        ap.error("--kek-arn is required with --key-block")

    cp = boto3.client("payment-cryptography", region_name=args.region)
    kek2_arn = None

    try:
        # 2. Temporary AES-256 KEK used only for the re-mode round trip
        print("[2] Creating temporary AES-256 KEK (KEK2)")
        kek2 = cp.create_key(
            KeyAttributes={
                "KeyUsage": "TR31_K0_KEY_ENCRYPTION_KEY",
                "KeyClass": "SYMMETRIC_KEY",
                "KeyAlgorithm": "AES_256",
                "KeyModesOfUse": {"Encrypt": True, "Decrypt": True,
                                  "Wrap": True, "Unwrap": True},
            },
            Exportable=False,
            Enabled=True,
        )["Key"]
        kek2_arn = kek2["KeyArn"]
        print_key(kek2)

        # 3. Import the sample CVK under KEK_ARN (or use an existing CVK)
        if args.key_block:
            block = args.key_block.strip().upper()
            print("\n[3] Importing sample CVK under KEK_ARN")
            hdr = print_header("  Block", block)
            if hdr["usage"] != "C0":
                print(f"  ⚠ Key usage is {hdr['usage']}, not C0")
            source = cp.import_key(
                KeyMaterial={"Tr31KeyBlock": {
                    "WrappingKeyIdentifier": args.kek_arn,
                    "WrappedKeyBlock": block,
                }},
                Enabled=True,
            )["Key"]
        else:
            print("\n[3] Skipped (using existing CVK)")
            source = cp.get_key(KeyIdentifier=args.cvk_arn)["Key"]
        print_key(source)
        source_arn, source_kcv = source["KeyArn"], source["KeyCheckValue"]

        # 4. Export under KEK2 with modes narrowed N -> target. Exportability
        #    is left unset so it carries over from the source key.
        print(f"\n[4] Exporting CVK under KEK2 with mode {args.mode} ({MODE_NAMES[args.mode]})")
        new_block = cp.export_key(
            ExportKeyIdentifier=source_arn,
            KeyMaterial={"Tr31KeyBlock": {
                "WrappingKeyIdentifier": kek2_arn,
                "KeyBlockHeaders": {"KeyModesOfUse": TARGET_MODES[args.mode]},
            }},
        )["WrappedKey"]["KeyMaterial"]
        new_hdr = print_header("  New block", new_block)
        if new_hdr["mode_of_use"] != args.mode:
            raise RuntimeError(
                f"Expected mode {args.mode} in exported header, got {new_hdr['mode_of_use']}")

        # 5. Import the re-moded block under KEK2
        print(f"\n[5] Importing mode-{args.mode} block under KEK2")
        final = cp.import_key(
            KeyMaterial={"Tr31KeyBlock": {
                "WrappingKeyIdentifier": kek2_arn,
                "WrappedKeyBlock": new_block,
            }},
            Enabled=True,
        )["Key"]
        print_key(final)
        if final["KeyCheckValue"] != source_kcv:
            raise RuntimeError(f"KCV mismatch: source {source_kcv} vs re-imported {final['KeyCheckValue']}")
        print("  ✓ KCV matches source")

        if args.delete_original:
            cp.delete_key(KeyIdentifier=source_arn, DeleteKeyInDays=3)
            print(f"\nScheduled mode-N CVK for deletion (3 days, restorable): {source_arn}")

        print("\n✅ Done. Use this key for GenerateCardData / VerifyCardData:")
        print(f"   {final['KeyArn']}")
        return 0

    except Exception as exc:  # surface the AWS Payment Cryptography error text as-is
        print(f"\n❌ Failed: {exc}")
        return 1

    finally:
        # 6. KEK2 was only temporary. AWS Payment Cryptography's minimum deletion
        # window is 3 days.
        if kek2_arn:
            try:
                cp.delete_key(KeyIdentifier=kek2_arn, DeleteKeyInDays=3)
                print(f"\n[6] Scheduled KEK2 for deletion: {kek2_arn}")
            except Exception as exc:
                print(f"\n⚠ [6] Could not delete KEK2 {kek2_arn}: {exc}")


if __name__ == "__main__":
    sys.exit(main())
