'''
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The following api calls may be subject to https://aws.amazon.com/service-terms/ section 2 - Beta & Previews

============================================================================
 WARNING: DEVELOPMENT / TESTING USE ONLY
============================================================================
This script handles cryptographic key material in cleartext (via stdout) and uses a
locally-generated, self-signed certificate for its Certificate Authority trust chain.
This approach is NOT compliant with PCI PIN Security, PCI DSS, or similar payment
industry key-management requirements for production use.

This script is intended strictly for development, testing, and proof-of-concept
purposes. Do not run it against production AWS accounts or production AWS Payment
Cryptography key material.

Running this script requires interactively typing "yes" at a confirmation prompt
(see --help / README.md for details); it cannot be bypassed via an environment
variable or command-line flag, since that could be baked into a script/CI job and
defeat the purpose of the confirmation.
============================================================================

This is the mirror image of ../import_app/import_raw_key_ecdh.py: instead of importing a
cleartext key into AWS Payment Cryptography (APC) using an ECDH-derived TR-31 wrapping key,
this script EXPORTS an existing APC key (identified by KeyArn) back out to cleartext, again
using an ECDH-derived TR-31 wrapping key so the key material is never sent unprotected over
the network.

It also supports exporting an IPEK (Initial PIN Encryption Key) for DUKPT, which APC derives
on the fly from a BDK (Base Derivation Key, TR-31 key usage B0) plus a supplied KSN (Key
Serial Number). This only works when the key identified by --key-arn is a B0 key and
--ksn is provided; the derived IPEK does not persist in APC and must be re-derived (with the
same KSN) every time it's needed.

Note: As this script prints/handles cleartext key material, it is intended strictly for
testing environments and proof-of-concept purposes.

Usage:
    python export_raw_key_ecdh.py --region us-east-1 --key-arn <KeyArn> --output full
    python export_raw_key_ecdh.py --region us-east-1 --key-arn <KeyArn> --output 2-component
    python export_raw_key_ecdh.py --region us-east-1 --key-arn <KeyArn> --output 3-component
    python export_raw_key_ecdh.py --region us-east-1 --key-arn <BDK KeyArn> --ksn <KSN hex> --output full
'''
import argparse
import base64
import boto3
from cryptography import x509
import os
import re
import secrets
import sys
import datetime
import getpass
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.x509.oid import NameOID
from Crypto.Hash import CMAC
from Crypto.Cipher import AES, DES3
import psec

def _enforce_non_production_guardrail():
    """
    Refuses to run unless the operator interactively confirms they understand this script
    is not suitable for production use. This is a lightweight guardrail, not a security
    control, and cannot verify whether the target AWS account/credentials actually belong
    to a production environment -- it only forces a deliberate, affirmative step (typed at
    a terminal, not settable via an environment variable or flag) before this
    development/testing tool handles cleartext key material.
    """
    print("\n" + "=" * 78)
    print("WARNING: This script is for DEVELOPMENT / TESTING purposes only.")
    print("It handles cleartext key material and self-signed certificates and is")
    print("likely NOT compliant with production payment key-management requirements")
    print("(e.g. PCI PIN Security, PCI DSS). Do not use it against production key")
    print("material or production AWS accounts.")
    print("=" * 78 + "\n")

    try:
        confirmation = input(
            "Type 'yes' to confirm you understand this and want to proceed "
            "(development/testing environments only): "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirmation = ""

    if confirmation != "yes":
        print("Confirmation not received. Exiting without making any changes.")
        sys.exit(1)


SENDER_KEY_ALIAS = "alias/export-ecdh-sender"
RECEIVER_ROOT_CA_ALIAS = "alias/export-ecdh-receiver-root"

RECEIVER_KEY_FILE = "certs/receiver_key.pem"
RECEIVER_CERT_FILE = "certs/receiver_cert.pem"


def _calculate_kcv(key_bytes: bytes, algo: str) -> str:
    """
    Calculate KCV. algo is 'A' for AES or 'T' for TDES.

    NOTE for static analysis: the TDES branch intentionally uses DES3 in ECB mode. This is
    not encrypting data for confidentiality; it is the ANSI X9.24 Key Check Value algorithm
    (encrypt a fixed all-zero block and keep the first 3 bytes), which by definition uses a
    single ECB block operation to detect whether two parties hold the same key. There is no
    IV to manage and no plaintext being protected, so ECB's chosen-plaintext weaknesses do
    not apply here. Using a different mode would produce a KCV that no other TR-31/PCI
    tooling would recognize as valid. This same pattern is used throughout this repository
    (e.g. key-import-export/ecdh/import_app/import_raw_key_ecdh.py).
    """
    if algo == 'A':
        return CMAC.new(key_bytes, msg=bytes(AES.block_size), ciphermod=AES).digest()[:3].hex().upper()
    else:
        return DES3.new(key_bytes, DES3.MODE_ECB).encrypt(bytes(DES3.block_size))[:3].hex().upper()


def _algo_letter_from_apc(apc_key_algorithm: str) -> str:
    """Maps an APC KeyAlgorithm (e.g. 'AES_256', 'TDES_2KEY') to the 'A'/'T' KCV algo letter."""
    if apc_key_algorithm.startswith("AES"):
        return 'A'
    if apc_key_algorithm.startswith("TDES"):
        return 'T'
    if apc_key_algorithm.startswith("HMAC"):
        return 'H'
    raise ValueError(f"Unsupported/unwrappable symmetric key algorithm: {apc_key_algorithm}")


def prepare_for_key_creation(client, alias_name):
    """
    Checks if an alias exists. If it does not, it creates it.
    """
    try:
        client.get_alias(AliasName=alias_name)
    except client.exceptions.ResourceNotFoundException:
        print(f"Alias {alias_name} does not exist. It will be created.")
        client.create_alias(AliasName=alias_name)


def update_alias(client, alias_name, key_arn):
    """
    Updates or creates an alias to point to the new key arn.
    """
    try:
        client.update_alias(AliasName=alias_name, KeyArn=key_arn)
    except client.exceptions.ResourceNotFoundException:
        client.create_alias(AliasName=alias_name, KeyArn=key_arn)
    print(f"Updated alias {alias_name} to point to {key_arn}")


def get_or_create_receiver_credentials():
    """
    Generates (or loads, if already present) the local "receiver" ECC key pair and
    self-signed Root CA certificate. This plays the symmetric role to the sender
    credentials in the import script: here, WE are receiving the exported key, so
    AWS needs to trust OUR public key certificate before it will encrypt an
    ECDH-derived wrapping key to us.
    """
    if os.path.exists(RECEIVER_KEY_FILE) and os.path.exists(RECEIVER_CERT_FILE):
        print("Loading existing receiver credentials...")
        with open(RECEIVER_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )
        with open(RECEIVER_CERT_FILE, "rb") as cert_file:
            certificate = x509.load_pem_x509_certificate(cert_file.read())
        return certificate, private_key, certificate.public_key()

    print("Generating new receiver credentials...")
    # Generate private key (P-521)
    private_key = ec.generate_private_key(ec.SECP521R1())

    # Generate certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Receiver CA"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            # Valid for 1 year
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Ensure certs directory exists if we are creating files
    os.makedirs(os.path.dirname(RECEIVER_KEY_FILE), exist_ok=True)

    # Save to files
    with open(RECEIVER_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(RECEIVER_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Receiver credentials saved to {RECEIVER_KEY_FILE} and {RECEIVER_CERT_FILE}")
    return cert, private_key, private_key.public_key()


def print_full_key(key_bytes: bytes, kcv: str, suppress_key_output: bool):
    print("\n--- Exported Key: Full Clear Key ---")
    if suppress_key_output:
        print("  (key value suppressed; only KCV is shown)")
    else:
        print(f"  Clear Key : {key_bytes.hex().upper()}")
    print(f"  KCV       : {kcv}")
    print("-------------------------------------\n")


def print_key_components(key_bytes: bytes, num_components: int, algo: str, suppress_key_output: bool):
    """
    Splits key_bytes into `num_components` random components that XOR back to the
    original key (the standard manual key-component-entry XOR scheme), and prints
    each component's KCV alongside the combined KCV so operators can cross check
    without ever having the full key material on screen if suppress_key_output is set.
    """
    length = len(key_bytes)
    components = [secrets.token_bytes(length) for _ in range(num_components - 1)]
    last = bytearray(key_bytes)
    for component in components:
        for i in range(length):
            last[i] ^= component[i]
    components.append(bytes(last))

    print(f"\n--- Exported Key: {num_components}-Component Form ---")
    for idx, component in enumerate(components, start=1):
        kcv = _calculate_kcv(component, algo)
        if suppress_key_output:
            print(f"  Component {idx} KCV : {kcv}  (value suppressed)")
        else:
            print(f"  Component {idx}     : {component.hex().upper()}")
            print(f"  Component {idx} KCV : {kcv}")

    combined_kcv = _calculate_kcv(key_bytes, algo)
    print(f"\n  Combined key KCV (for cross-check): {combined_kcv}")
    print("-----------------------------------------\n")
    return components


def _validate_ksn(ksn_hex: str, apc_key_algorithm: str) -> str:
    """
    Validates a KSN hex string for IPEK export. Per the AWS Payment Cryptography ExportKey
    API, the KSN must be 20 hex chars for a TDES_2KEY BDK or 24 hex chars for an AES BDK,
    and it must already be padded (the caller is responsible for supplying a correctly
    padded/formatted KSN -- this script does not pad or reformat it).
    """
    ksn_hex = ksn_hex.strip().upper()
    if not re.fullmatch(r"[0-9A-F]{20}|[0-9A-F]{24}", ksn_hex):
        raise ValueError(
            "--ksn must be 20 hex characters (for a TDES_2KEY BDK) or 24 hex characters "
            f"(for an AES BDK). Got {len(ksn_hex)} characters: {ksn_hex!r}"
        )
    if apc_key_algorithm.startswith("TDES") and len(ksn_hex) != 20:
        raise ValueError(
            f"--key-arn is a {apc_key_algorithm} BDK, which requires a 20 hex character KSN. "
            f"Got {len(ksn_hex)} characters."
        )
    if apc_key_algorithm.startswith("AES") and len(ksn_hex) != 24:
        raise ValueError(
            f"--key-arn is a {apc_key_algorithm} BDK, which requires a 24 hex character KSN. "
            f"Got {len(ksn_hex)} characters."
        )
    return ksn_hex


def main():
    parser = argparse.ArgumentParser(
        description="Export a symmetric key from AWS Payment Cryptography using ECDH. "
                     "DEVELOPMENT/TESTING USE ONLY -- see the warning banner printed above "
                     "and at the top of this file; not compliant for production key material."
    )
    parser.add_argument("--region", required=True, help="AWS Region")
    parser.add_argument("--profile", default=None, help="AWS Profile (optional, uses default credential chain if omitted)")
    parser.add_argument("--key-arn", "-k", required=True,
                         help="KeyArn (or key alias) of the APC key to export. For IPEK export "
                              "(--ksn), this must be a Base Derivation Key (TR-31 key usage B0).")
    parser.add_argument(
        "--ksn",
        default=None,
        help="Key Serial Number (hex), to export an IPEK (Initial PIN Encryption Key) derived "
             "from a BDK instead of exporting --key-arn's own key material directly. Only valid "
             "when --key-arn identifies a B0 (Base Derivation Key). Must be pre-padded per the "
             "AWS Payment Cryptography ExportKey API: 20 hex chars for a TDES_2KEY BDK, 24 hex "
             "chars for an AES BDK. The IPEK is derived fresh by APC on every export call and "
             "does not persist within AWS Payment Cryptography.",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Form in which to output the exported clear key",
        default="full",
        choices=["full", "2-component", "3-component"],
    )
    parser.add_argument(
        "--suppress-key-output",
        action="store_true",
        help="Do not print clear key/component values to stdout; only KCVs are shown. "
             "Useful when this script is run in view of others (e.g. a dual-control key ceremony).",
    )
    parser.add_argument(
        "--shared-info",
        help="Hex SharedInformation to use for the ECDH key derivation (optional; a random "
             "value is generated if omitted). Must match what APC uses -- there is normally "
             "no reason to override this.",
        default=None,
    )

    args = parser.parse_args()

    # Confirmation happens after argument parsing so --help exits immediately without
    # requiring interactive confirmation first.
    _enforce_non_production_guardrail()

    session = boto3.Session(profile_name=args.profile if args.profile else None, region_name=args.region)
    client = session.client("payment-cryptography")

    # Step 1: Look up the key to export, to learn its algorithm (needed for KCV calc and
    # to determine the wrapped payload's expected length) and, for IPEK export, to confirm
    # it's actually a BDK (B0) before going through the ECDH ceremony.
    print("\n" + "-" * 60)
    print("Step 1: Looking up key to export...")
    key_response = client.get_key(KeyIdentifier=args.key_arn)
    key_arn = key_response["Key"]["KeyArn"]
    apc_key_algorithm = key_response["Key"]["KeyAttributes"]["KeyAlgorithm"]
    apc_key_usage = key_response["Key"]["KeyAttributes"]["KeyUsage"]
    if not key_response["Key"].get("Exportable", False):
        print(f"Key {key_arn} is not Exportable (Exportable=False). Cannot proceed.")
        sys.exit(1)
    algo_letter = _algo_letter_from_apc(apc_key_algorithm)
    print(f"Key ARN        : {key_arn}")
    print(f"Key Algorithm  : {apc_key_algorithm}")
    print(f"Key Usage      : {apc_key_usage}")

    exporting_ipek = args.ksn is not None
    ksn_hex = None
    if exporting_ipek:
        if apc_key_usage != "TR31_B0_BASE_DERIVATION_KEY":
            print(
                f"--ksn was provided, but --key-arn's KeyUsage is {apc_key_usage}, not "
                "TR31_B0_BASE_DERIVATION_KEY (B0). IPEK export requires a BDK. Cannot proceed."
            )
            sys.exit(1)
        try:
            ksn_hex = _validate_ksn(args.ksn, apc_key_algorithm)
        except ValueError as exc:
            print(f"Invalid --ksn: {exc}")
            sys.exit(1)
        print(f"KSN            : {ksn_hex}")
        print("Exporting an IPEK derived from this BDK + KSN (IPEK does not persist in APC).")

    # Step 2: Create (or reuse) the APC-side ECC key pair used as the "sender" for this
    # ECDH exchange. Its private key never leaves AWS Payment Cryptography; we only ever
    # reference it by KeyArn (PrivateKeyIdentifier).
    print("\n" + "-" * 60)
    print("Step 2: Preparing APC-side ECDH key (AWS side)...")
    prepare_for_key_creation(client, SENDER_KEY_ALIAS)

    print("Creating ECC Key Pair in APC (if one does not already exist for this alias)...")
    try:
        sender_key_arn = client.get_alias(AliasName=SENDER_KEY_ALIAS)["Alias"]["KeyArn"]
        client.get_key(KeyIdentifier=sender_key_arn)
        print(f"Reusing existing APC ECDH key: {sender_key_arn}")
    except (client.exceptions.ResourceNotFoundException, KeyError, TypeError):
        key_response = client.create_key(
            Exportable=True,
            KeyAttributes={
                "KeyAlgorithm": "ECC_NIST_P521",
                "KeyClass": "ASYMMETRIC_KEY_PAIR",
                "KeyModesOfUse": {"DeriveKey": True},
                "KeyUsage": "TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT",
            },
            DeriveKeyUsage="TR31_K1_KEY_BLOCK_PROTECTION_KEY",
        )
        sender_key_arn = key_response["Key"]["KeyArn"]
        print(f"Created APC ECDH key pair ARN: {sender_key_arn}")
        update_alias(client, SENDER_KEY_ALIAS, sender_key_arn)

    # Step 3: Get the public key certificate for APC's ECDH key. We'll use this to derive
    # the shared secret locally.
    print("\n" + "-" * 60)
    print("Step 3: Getting APC ECDH Public Key Certificate...")
    cert_response = client.get_public_key_certificate(KeyIdentifier=sender_key_arn)
    apc_certificate_pem_b64 = cert_response["KeyCertificate"]
    apc_certificate = x509.load_pem_x509_certificate(base64.b64decode(apc_certificate_pem_b64))
    print("Successfully loaded APC's ECDH certificate.")

    # Step 4: Generate (or load) our local receiver ECC key pair + self-signed Root CA.
    print("\n" + "-" * 60)
    print("Step 4: Generate/Load Local Receiver ECC Key Pair and CA Certificate...")
    receiver_ca, receiver_key, receiver_public_key = get_or_create_receiver_credentials()
    print("Receiver Key and Certificate obtained.")

    # Step 5: Import our Root CA certificate into APC so it will trust our receiving
    # certificate for this ECDH exchange.
    print("\n" + "-" * 60)
    print("Step 5: Preparing Receiver Root CA trust in APC...")
    prepare_for_key_creation(client, RECEIVER_ROOT_CA_ALIAS)

    print("Importing Receiver Root Certificate to AWS...")
    receiver_ca_pem = receiver_ca.public_bytes(serialization.Encoding.PEM)
    receiver_cert_b64 = base64.b64encode(receiver_ca_pem).decode("utf-8")

    import_response = client.import_key(
        Enabled=True,
        KeyMaterial={
            "RootCertificatePublicKey": {
                "KeyAttributes": {
                    "KeyAlgorithm": "ECC_NIST_P521",
                    "KeyClass": "PUBLIC_KEY",
                    "KeyModesOfUse": {"Verify": True},
                    "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
                },
                "PublicKeyCertificate": receiver_cert_b64,
            }
        },
    )
    receiver_root_ca_arn = import_response["Key"]["KeyArn"]
    print(f"Imported Receiver Root Certificate ARN: {receiver_root_ca_arn}")
    update_alias(client, RECEIVER_ROOT_CA_ALIAS, receiver_root_ca_arn)

    # Step 6: Derive the shared secret and AES-256 unwrapping key, locally.
    print("\n" + "-" * 60)
    print("Step 6: Deriving Shared Secret and Unwrapping Key (locally)...")

    # ECDH Exchange: our receiver private key + APC's ECDH public key.
    shared_secret = receiver_key.exchange(ec.ECDH(), apc_certificate.public_key())

    # We must pass the SAME SharedInformation to APC's ExportKey call, so the two sides
    # derive identical wrapping keys.
    if args.shared_info:
        shared_info_hex = args.shared_info
    else:
        shared_info_hex = os.urandom(16).hex()
    shared_info = bytes.fromhex(shared_info_hex)

    kdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        otherinfo=shared_info,
    )
    aes_unwrapping_key = kdf.derive(shared_secret)
    print(f"Derived AES Unwrapping Key (hex): {aes_unwrapping_key.hex()}")

    # Step 7: Call ExportKey, asking APC to wrap the target key using the same ECDH
    # derivation parameters, so it produces an identical AES-256 wrapping key on its side.
    print("\n" + "-" * 60)
    print("Step 7: Exporting Key from AWS via ECDH...")

    receiver_cert_pem = receiver_key.public_key().public_bytes(
        serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Use the actual X.509 self-signed leaf certificate (not a bare SPKI) so APC can
    # validate it against the trusted Root CA imported in Step 5. Since our "receiver_ca"
    # certificate IS the leaf (self-signed, CA:true), we can reuse it directly here.
    receiver_leaf_cert_pem = receiver_ca.public_bytes(serialization.Encoding.PEM)
    receiver_cert_b64_for_export = base64.b64encode(receiver_leaf_cert_pem).decode("utf-8")

    export_key_kwargs = dict(
        ExportKeyIdentifier=key_arn,
        KeyMaterial={
            "DiffieHellmanTr31KeyBlock": {
                "PrivateKeyIdentifier": sender_key_arn,
                "CertificateAuthorityPublicKeyIdentifier": receiver_root_ca_arn,
                "PublicKeyCertificate": receiver_cert_b64_for_export,
                "DeriveKeyAlgorithm": "AES_256",
                "KeyDerivationFunction": "NIST_SP800",
                "KeyDerivationHashAlgorithm": "SHA_256",
                "DerivationData": {"SharedInformation": shared_info_hex},
            }
        },
    )
    if exporting_ipek:
        # ExportDukptInitialKey tells APC to derive an IPEK from key_arn (the BDK) and
        # ksn_hex on the fly, and wrap THAT (rather than the BDK itself) in the returned
        # TR-31 key block. The IPEK is never persisted within AWS Payment Cryptography.
        export_key_kwargs["ExportAttributes"] = {
            "ExportDukptInitialKey": {"KeySerialNumber": ksn_hex}
        }

    export_response = client.export_key(**export_key_kwargs)

    wrapped_key = export_response["WrappedKey"]
    tr31_key_block = wrapped_key["KeyMaterial"]
    reported_kcv = wrapped_key.get("KeyCheckValue", "N/A")
    print(f"Received TR-31 Key Block: {tr31_key_block}")
    print(f"APC-reported KCV of exported key: {reported_kcv}")

    # Step 8: Unwrap the TR-31 key block locally using our independently-derived
    # AES-256 unwrapping key.
    print("\n" + "-" * 60)
    print("Step 8: Unwrapping TR-31 Key Block (locally)...")
    header, clear_key = psec.tr31.unwrap(kbpk=aes_unwrapping_key, key_block=tr31_key_block)
    print(f"TR-31 Header -- version_id: {header.version_id}, key_usage: {header.key_usage}, "
          f"algorithm: {header.algorithm}, mode_of_use: {header.mode_of_use}, "
          f"exportability: {header.exportability}")

    # Validate locally-calculated KCV against APC's reported KCV, when possible.
    if algo_letter in ('A', 'T'):
        calculated_kcv = _calculate_kcv(clear_key, algo_letter)
        print(f"Locally-calculated KCV: {calculated_kcv}")
        if reported_kcv != "N/A":
            print("KCV Match:", "PASS" if calculated_kcv == reported_kcv else "FAIL "
                  f"(calculated={calculated_kcv}, reported={reported_kcv})")
    else:
        calculated_kcv = reported_kcv

    # Step 9: Output the clear key in the requested form.
    print("\n" + "-" * 60)
    print("Step 9: Output...")
    if exporting_ipek:
        print("(The following is the derived IPEK, not the BDK identified by --key-arn.)")
    if args.output == "full":
        print_full_key(clear_key, calculated_kcv, args.suppress_key_output)
    elif args.output == "2-component":
        print_key_components(clear_key, 2, algo_letter, args.suppress_key_output)
    elif args.output == "3-component":
        print_key_components(clear_key, 3, algo_letter, args.suppress_key_output)


if __name__ == "__main__":
    main()
