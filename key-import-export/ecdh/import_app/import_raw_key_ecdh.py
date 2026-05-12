import argparse
import base64
import boto3
from cryptography import x509
import os
import sys
import datetime
import hashlib
import hmac as hmac_module
import termios
import tty
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.x509.oid import NameOID
from Crypto.Hash import CMAC
from Crypto.Cipher import AES, DES3
import psec

RECEIVER_KEY_ALIAS = "alias/import-ecdh-receiver"
SENDER_ROOT_CA_ALIAS = "alias/import-ecdh-sender-root"
IMPORTED_KEY_ALIAS = "alias/import-ecdh-result"

SENDER_KEY_FILE = "certs/sender_key.pem"
SENDER_CERT_FILE = "certs/sender_cert.pem"


def _calculate_kcv(key_bytes: bytes, algo: str) -> str:
    """Calculate KCV. algo is 'A' for AES or 'T' for TDES."""
    if algo == 'A':
        return CMAC.new(key_bytes, msg=bytes(AES.block_size), ciphermod=AES).digest()[:3].hex().upper()
    else:
        return DES3.new(key_bytes, DES3.MODE_ECB).encrypt(bytes(DES3.block_size))[:3].hex().upper()


def _read_masked_hex(prompt: str, optional: bool = False) -> str:
    """Read hex from the terminal echoing '*' per character."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    chars = []
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ('\r', '\n'):
                sys.stdout.write('\n')
                sys.stdout.flush()
                break
            elif ch in ('\x7f', '\x08'):
                if chars:
                    chars.pop()
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch == '\x03':
                sys.stdout.write('\n')
                raise KeyboardInterrupt
            else:
                chars.append(ch)
                sys.stdout.write('*')
                sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ''.join(chars).replace(' ', '')


def prompt_key_components(algo: str) -> bytes:
    """Interactive masked component entry. Returns combined key as bytes."""
    VALID_LENGTHS = {
        'A': {16: 'AES-128', 24: 'AES-192', 32: 'AES-256'},
        'T': {16: 'TDES-2KEY', 24: 'TDES-3KEY'},
    }

    def read_component(label: str, expected_len: int = 0, optional: bool = False) -> str:
        while True:
            raw = _read_masked_hex(f"  Enter {label} (hex): ", optional=optional)
            if optional and raw == '':
                return ''
            if not raw:
                print("  Error: value cannot be empty.")
                continue
            if not all(c in '0123456789abcdefABCDEF' for c in raw):
                print("  Error: only hex characters (0-9, a-f, A-F) are allowed.")
                continue
            if len(raw) % 2 != 0:
                print(f"  Error: must be an even number of hex characters (got {len(raw)}).")
                continue
            key_bytes_len = len(raw) // 2
            valid = VALID_LENGTHS.get(algo, {16: 'AES-128', 24: 'AES-192', 32: 'AES-256'})
            if key_bytes_len not in valid:
                valid_desc = ', '.join(f"{b*2} hex chars ({v})" for b, v in valid.items())
                print(f"  Error: {key_bytes_len} bytes is not a valid key length.")
                print(f"  Valid lengths: {valid_desc}.")
                continue
            if expected_len and key_bytes_len != expected_len:
                print(f"  Error: this component is {key_bytes_len} bytes but previous components were {expected_len} bytes.")
                continue
            kcv = _calculate_kcv(bytes.fromhex(raw), algo)
            print(f"  {label} KCV: {kcv}")
            return raw

    print("\n--- Key Component Entry ---")
    c1 = read_component("Component 1")
    expected = len(c1) // 2
    c2 = read_component("Component 2", expected_len=expected)
    c3 = read_component("Component 3 (press Enter to skip for 2-component entry)", expected_len=expected, optional=True)

    if c3 == '':
        combined = bytes(a ^ b for a, b in zip(bytes.fromhex(c1), bytes.fromhex(c2)))
    else:
        combined = bytes(a ^ b ^ c for a, b, c in zip(bytes.fromhex(c1), bytes.fromhex(c2), bytes.fromhex(c3)))

    combined_kcv = _calculate_kcv(combined, algo)
    print(f"\n  Combined key KCV: {combined_kcv}")
    print("---------------------------\n")

    while True:
        confirm = input(f"  Confirm import of key with KCV [{combined_kcv}]? (yes/no): ").strip().lower()
        if confirm == 'yes':
            break
        elif confirm == 'no':
            print("  Import cancelled.")
            sys.exit(0)
        else:
            print("  Please type 'yes' or 'no'.")

    return combined


def construct_tr31_header(algo, export_mode, key_type, mode_of_use, version_id):
    header = psec.tr31.Header(
        version_id=version_id,
        key_usage=key_type,
        algorithm=algo,
        mode_of_use=mode_of_use,
        version_num="00",
        exportability=export_mode,
    )
    return header


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


def get_or_create_sender_credentials():
    if os.path.exists(SENDER_KEY_FILE) and os.path.exists(SENDER_CERT_FILE):
        print("Loading existing sender credentials...")
        with open(SENDER_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )
        with open(SENDER_CERT_FILE, "rb") as cert_file:
            certificate = x509.load_pem_x509_certificate(cert_file.read())
        return certificate, private_key, certificate.public_key()

    print("Generating new sender credentials...")
    # Generate private key (P-521)
    private_key = ec.generate_private_key(ec.SECP521R1())

    # Generate certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Sender CA"),
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

    # Ensure APC directory exists if we are creating files
    os.makedirs(os.path.dirname(SENDER_KEY_FILE), exist_ok=True)

    # Save to files
    with open(SENDER_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(SENDER_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Sender credentials saved to {SENDER_KEY_FILE} and {SENDER_CERT_FILE}")
    return cert, private_key, private_key.public_key()


def main():
    parser = argparse.ArgumentParser(
        description="Import a symmetric key into AWS Payment Cryptography using ECDH"
    )
    parser.add_argument("--region", required=True, help="AWS Region")
    parser.add_argument("--profile", default=None, help="AWS Profile (optional, uses default credential chain if omitted)")
    parser.add_argument("--clearkey", help="Clear Text Key to import (Hex). If using key components, leave this empty.", default="")
    parser.add_argument("--component1", help="First key component (hex). All three components are XORed to form the final key.", default="")
    parser.add_argument("--component2", help="Second key component (hex).", default="")
    parser.add_argument("--component3", help="Third key component (hex).", default="")
    parser.add_argument("--prompt-components", action="store_true",
                        help="Interactively prompt for key components with masked input and KCV display.")
    parser.add_argument(
        "--export-mode",
        "-e",
        help="Export Mode - E, S or N",
        default="E",
        choices=["E", "S", "N"],
    )
    parser.add_argument(
        "--key-type",
        "-t",
        help="Key Type according to TR-31 norms. For instance K0, B0, M7 (HMAC), etc",
        default="K0",
        choices=["K0", "B0", "D0", "P0", "D1", "K1", "M7"],
    )
    parser.add_argument(
        "--mode-of-use",
        "-m",
        help="Mode of use according to TR-31 norms. For instance B (encrypt/decrypt), X (derive key)",
        default="B",
        choices=["B", "X", "N", "E", "D", "G", "C", "V"],
    )
    parser.add_argument(
        "--algorithm",
        "-a",
        help="Algorithm of key - (T)DES, (A)ES, or (H)MAC. H is only valid with --key-type M7.",
        default="A",
        choices=["A", "T", "R", "H"],
    )
    parser.add_argument(
        "--hash-algorithm",
        help="Hash algorithm for HMAC (M7) keys. Required when --key-type is M7.",
        default=None,
        choices=["HMAC_SHA1", "HMAC_SHA256", "HMAC_SHA384", "HMAC_SHA512"],
    )

    args = parser.parse_args()

    # HMAC (M7) validation
    if args.key_type == "M7":
        if not args.hash_algorithm:
            parser.error("--hash-algorithm is required when --key-type is M7 (HMAC).")
        if args.mode_of_use not in ("C", "G", "V"):
            parser.error("For HMAC (M7) keys, --mode-of-use must be C, G, or V.")
        # Override algorithm to H (HMAC) for TR-31 header
        args.algorithm = "H"
    else:
        if args.hash_algorithm:
            parser.error("--hash-algorithm is only valid when --key-type is M7 (HMAC).")
        if args.algorithm == "H":
            parser.error("Algorithm H (HMAC) is only valid when --key-type is M7.")

    # Determine the key: prompt, --clearkey, or --component flags
    has_components = args.component1 or args.component2 or args.component3
    suppress_key_output = args.prompt_components

    if args.prompt_components:
        if args.clearkey or has_components:
            parser.error("Cannot combine --prompt-components with --clearkey or --component flags.")
        algo_name = "AES" if args.algorithm == "A" else "TDES"
        print("\n--- Key Import Summary ---")
        print(f"  Algorithm  : {algo_name}")
        print(f"  Key Type   : {args.key_type}")
        print(f"  Mode of Use: {args.mode_of_use}")
        print(f"  Export Mode: {args.export_mode}")
        print(f"  AWS Region : {args.region}")
        print("--------------------------")
        key_bytes = prompt_key_components(args.algorithm)
    elif args.clearkey and has_components:
        parser.error("Provide either --clearkey or all three --component flags, not both.")
    elif has_components:
        if not (args.component1 and args.component2 and args.component3):
            parser.error("All three key components (--component1, --component2, --component3) must be provided.")
        try:
            c1 = bytes.fromhex(args.component1.replace(" ", ""))
            c2 = bytes.fromhex(args.component2.replace(" ", ""))
            c3 = bytes.fromhex(args.component3.replace(" ", ""))
        except ValueError:
            parser.error("All key components must be valid hex strings.")
        if not (len(c1) == len(c2) == len(c3)):
            parser.error(f"All three key components must be the same length. Got {len(c1)}, {len(c2)}, {len(c3)} bytes.")
        key_bytes = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, c3))
        print(f"Component 1: {args.component1}")
        print(f"Component 2: {args.component2}")
        print(f"Component 3: {args.component3}")
        print(f"Combined key (XOR): {key_bytes.hex().upper()}")
    elif args.clearkey:
        try:
            key_bytes = bytes.fromhex(args.clearkey)
        except ValueError:
            parser.error("clearkey must be a valid hex string.")
        if len(args.clearkey) % 2 != 0:
            parser.error("clearkey hex string must have an even length.")
    else:
        parser.error("Provide either --clearkey, --component flags, or --prompt-components.")

    # Check for valid key lengths
    if args.key_type == "M7":
        # HMAC keys can be 16-64 bytes
        if len(key_bytes) < 16 or len(key_bytes) > 64:
            parser.error(
                f"HMAC key length ({len(key_bytes)} bytes) must be between 16 and 64 bytes."
            )
    else:
        valid_lengths = [16, 24, 32]
        if len(key_bytes) not in valid_lengths:
            parser.error(
                f"Key length ({len(key_bytes)} bytes) is not standard (16, 24, or 32 bytes)."
            )

    session = boto3.Session(profile_name=args.profile if args.profile else None, region_name=args.region)
    client = session.client("payment-cryptography")

    # Step 1: Generate ECC Key Pair
    print("\n" + "-" * 60)
    print("Step 1: Preparing Receiver Key (AWS side)...")
    prepare_for_key_creation(client, RECEIVER_KEY_ALIAS)

    print("Creating ECC Key Pair...")
    # Create a key pair for key exchange (ECDH)
    # The private key stays in AWS. The public key will be retrieved later.
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

    receiver_key_arn = key_response["Key"]["KeyArn"]
    print(f"Created Receiver Key pair ARN: {receiver_key_arn}")
    update_alias(client, RECEIVER_KEY_ALIAS, receiver_key_arn)

    # Step 2: Get Public Key Certificate
    print("\n" + "-" * 60)
    print("Step 2: Getting Public Key Certificate...")
    cert_response = client.get_public_key_certificate(KeyIdentifier=receiver_key_arn)

    certificate = cert_response["KeyCertificate"]
    certificate_chain = cert_response["KeyCertificateChain"]

    # Load certificates
    receiver_cert = x509.load_pem_x509_certificate(base64.b64decode(certificate))

    print("Successfully loaded certificates using x509.")

    # Step 3: Generate Local Sender ECC Key Pair and CA Certificate
    print("\n" + "-" * 60)
    print("Step 3: Generate Local Sender ECC Key Pair and CA Certificate...")
    sender_ca, sender_key, sender_public_key = get_or_create_sender_credentials()
    print("Sender Key and Certificate obtained.")

    # Step 4: Import Root Certificate
    print("\n" + "-" * 60)
    print("Step 4: Preparing Sender Root CA...")
    prepare_for_key_creation(client, SENDER_ROOT_CA_ALIAS)

    print("Importing Root Certificate to AWS...")
    sender_ca_pem = sender_ca.public_bytes(serialization.Encoding.PEM)
    sender_cert_b64 = base64.b64encode(sender_ca_pem).decode("utf-8")

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
                "PublicKeyCertificate": sender_cert_b64,
            }
        },
    )
    sender_root_ca_arn = import_response["Key"]["KeyArn"]
    print(f"Imported Root Certificate ARN: {sender_root_ca_arn}")
    update_alias(client, SENDER_ROOT_CA_ALIAS, sender_root_ca_arn)

    # Step 5: Load key from CLI
    print("\n" + "-" * 60)
    print("Step 5: Load key from CLI...")
    KEY_HEX = key_bytes.hex().upper()
    if not suppress_key_output:
        print(f"Using key to import: {KEY_HEX}")

    # Step 6: Derive Shared Secret and AES Wrapping Key
    print("\n" + "-" * 60)
    print("Step 6: Deriving Shared Secret and Wrapping Key...")

    # ECDH Exchange
    shared_secret = sender_key.exchange(ec.ECDH(), receiver_cert.public_key())

    # KDF (NIST SP 800-56A Concatenation KDF)
    # We use a random SharedInformation here. It must match what is passed to ImportKey.
    shared_info_hex = os.urandom(16).hex()
    shared_info = bytes.fromhex(shared_info_hex)

    kdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        otherinfo=shared_info,
    )

    aes_wrapping_key = kdf.derive(shared_secret)
    if not suppress_key_output:
        print(f"Derived AES Wrapping Key (hex): {aes_wrapping_key.hex()}")

    # Step 7: Wrap Key into TR-31 Key Block
    print("\n" + "-" * 60)
    print("Step 7: Wrapping Key into TR-31 Key Block...")

    # Since the wrapping key (KBPK) derived in Step 6 is essentially AES-256,
    # we must use TR-31 Key Block Version 'D' (AES Key Bundle), regardless of
    # whether the payload key is AES or TDES.
    version_id = "D"

    # Build optional blocks for HMAC keys (HM header required per TR-31)
    # HM block value: hash algorithm ID per X9.143
    HMAC_OPT_BLOCK_MAP = {
        "HMAC_SHA1": "10",
        "HMAC_SHA256": "21",
        "HMAC_SHA384": "22",
        "HMAC_SHA512": "23",
    }

    tr31_header = psec.tr31.Header(
        version_id=version_id,
        key_usage=args.key_type,
        algorithm=args.algorithm,
        mode_of_use=args.mode_of_use,
        version_num="00",
        exportability=args.export_mode,
    )

    if args.key_type == "M7":
        hm_value = HMAC_OPT_BLOCK_MAP[args.hash_algorithm]
        tr31_header.blocks["HM"] = hm_value

    print(f"Constructed TR-31 Header: {tr31_header}")

    key_to_wrap = bytes.fromhex(KEY_HEX)

    tr31_key_block = psec.tr31.wrap(
        kbpk=aes_wrapping_key, header=tr31_header, key=key_to_wrap
    )
    if not suppress_key_output:
        print(f"TR-31 Key Block: {tr31_key_block}")

    # Step 8: Import Key into AWS
    print("\n" + "-" * 60)
    print("Step 8: Importing Key into AWS...")
    prepare_for_key_creation(client, IMPORTED_KEY_ALIAS)

    # Prepare sender certificate (The leaf certificate signed by the Root CA, which is the same in this self-signed case)
    sender_ca_pem = sender_ca.public_bytes(serialization.Encoding.PEM)
    sender_cert_b64 = base64.b64encode(sender_ca_pem).decode("utf-8")

    final_import_response = client.import_key(
        Enabled=True,
        KeyCheckValueAlgorithm="CMAC" if args.algorithm == "A" else ("HMAC" if args.algorithm == "H" else "ANSI_X9_24"),
        KeyMaterial={
            "DiffieHellmanTr31KeyBlock": {
                "CertificateAuthorityPublicKeyIdentifier": sender_root_ca_arn,
                "DerivationData": {"SharedInformation": shared_info_hex},
                "DeriveKeyAlgorithm": "AES_256",
                "KeyDerivationFunction": "NIST_SP800",
                "KeyDerivationHashAlgorithm": "SHA_256",
                "PrivateKeyIdentifier": receiver_key_arn,
                "PublicKeyCertificate": sender_cert_b64,
                "WrappedKeyBlock": tr31_key_block,
            }
        },
    )

    imported_key_arn = final_import_response["Key"]["KeyArn"]
    imported_key_kcv = final_import_response["Key"].get("KeyCheckValue", "N/A")
    print(f"Successfully Imported Key ARN: {imported_key_arn}")
    print(f"Imported Key KCV: {imported_key_kcv}")

    # Calculate KCV locally and validate against APC
    HMAC_HASH_MAP = {
        "HMAC_SHA1": hashlib.sha1,
        "HMAC_SHA256": hashlib.sha256,
        "HMAC_SHA384": hashlib.sha384,
        "HMAC_SHA512": hashlib.sha512,
    }


    if args.key_type == "M7":
        # HMAC KCV: HMAC(key, empty_message, hash_algorithm) truncated to first 3 bytes
        hash_fn = HMAC_HASH_MAP[args.hash_algorithm]
        hmac_kcv = hmac_module.new(key_bytes, b'', hash_fn).digest()[:3].hex().upper()
        print(f"Calculated HMAC KCV: {hmac_kcv}")
    elif args.algorithm == "A":
        hmac_kcv = CMAC.new(key_bytes, msg=bytes(AES.block_size), ciphermod=AES).digest()[:3].hex().upper()
        print(f"Calculated CMAC KCV: {hmac_kcv}")
    else:
        hmac_kcv = DES3.new(key_bytes, DES3.MODE_ECB).encrypt(bytes(DES3.block_size))[:3].hex().upper()
        print(f"Calculated KCV: {hmac_kcv}")

    if imported_key_kcv != "N/A":
        if hmac_kcv == imported_key_kcv:
            print("KCV Match: PASS")
        else:
            print(f"KCV Match: FAIL (calculated={hmac_kcv}, reported={imported_key_kcv})")

    update_alias(client, IMPORTED_KEY_ALIAS, imported_key_arn)

if __name__ == "__main__":
    main()