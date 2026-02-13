import argparse
import base64
import boto3
from cryptography import x509
import os
import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.x509.oid import NameOID
import psec

RECEIVER_KEY_ALIAS = "alias/import-kek-ecdh-receiver"
SENDER_ROOT_CA_ALIAS = "alias/import-kek-ecdh-sender-root"
IMPORTED_KEK_ALIAS = "alias/import-kek-ecdh-result"

SENDER_KEY_FILE = "certs/sender_key.pem"
SENDER_CERT_FILE = "certs/sender_cert.pem"


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
        description="Import an AES-256 KEK into AWS Payment Cryptography using ECDH"
    )
    parser.add_argument("--region", required=True, help="AWS Region")
    parser.add_argument("--profile", required=True, help="AWS Profile")
    parser.add_argument("--kek", required=True, help="Cleartext KEK to import (Hex)")
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
        help="Key Type according to TR-31 norms. For instance K0, B0, etc",
        default="K0",
        choices=["K0", "B0", "D0", "P0", "D1"],
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
        help="Algorithm of key - (T)DES or (A)ES",
        default="A",
        choices=["A", "T", "R"],
    )

    args = parser.parse_args()

    # Validate KEK input
    try:
        kek_bytes = bytes.fromhex(args.kek)
    except ValueError:
        parser.error("KEK must be a valid hex string.")

    if len(args.kek) % 2 != 0:
        parser.error("KEK hex string must have an even length.")

    # Check for common key lengths (16, 24, 32 bytes for AES/TDES)
    valid_lengths = [16, 24, 32]
    if len(kek_bytes) not in valid_lengths:
        parser.error(
            f"KEK length ({len(kek_bytes)} bytes) is not standard (16, 24, or 32 bytes)."
        )

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
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

    # Step 5: Use KEK from CLI
    print("\n" + "-" * 60)
    print("Step 5: Load KEK from CLI...")
    KEK_HEX = args.kek.upper()
    print(f"Using KEK to import: {KEK_HEX}")

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
    print(f"Derived AES Wrapping Key (hex): {aes_wrapping_key.hex()}")

    # Step 7: Wrap Key into TR-31 Key Block
    print("\n" + "-" * 60)
    print("Step 7: Wrapping Key into TR-31 Key Block...")

    # Since the wrapping key (KBPK) derived in Step 6 is essentially AES-256,
    # we must use TR-31 Key Block Version 'D' (AES Key Bundle), regardless of
    # whether the payload key is AES or TDES.
    version_id = "D"
    tr31_header = psec.tr31.Header(
        version_id=version_id,
        key_usage=args.key_type,
        algorithm=args.algorithm,
        mode_of_use=args.mode_of_use,
        version_num="00",
        exportability=args.export_mode,
    )
    print(f"Constructed TR-31 Header: {tr31_header}")

    key_to_wrap = bytes.fromhex(KEK_HEX)

    tr31_key_block = psec.tr31.wrap(
        kbpk=aes_wrapping_key, header=tr31_header, key=key_to_wrap
    )

    print(f"TR-31 Key Block: {tr31_key_block}")

    # Step 8: Import Key into AWS
    print("\n" + "-" * 60)
    print("Step 8: Importing Key into AWS...")
    prepare_for_key_creation(client, IMPORTED_KEK_ALIAS)

    # Prepare sender certificate (The leaf certificate signed by the Root CA, which is the same in this self-signed case)
    sender_ca_pem = sender_ca.public_bytes(serialization.Encoding.PEM)
    sender_cert_b64 = base64.b64encode(sender_ca_pem).decode("utf-8")

    final_import_response = client.import_key(
        Enabled=True,
        KeyCheckValueAlgorithm="CMAC",
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

    imported_kek_arn = final_import_response["Key"]["KeyArn"]
    imported_kek_kcv = final_import_response["Key"].get("KeyCheckValue", "N/A")
    print(f"Successfully Imported KEK ARN: {imported_kek_arn}")
    print(f"Imported KEK KCV: {imported_kek_kcv}")
    update_alias(client, IMPORTED_KEK_ALIAS, imported_kek_arn)


if __name__ == "__main__":
    main()