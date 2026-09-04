"""
Helpers for passing RSA key-cryptogram exchange state between environments.

When the KDH (HSM) and KRD (AWS Payment Cryptography) run in separate
environments, the interim results of each phase are handed off as a JSON file.
x509 certificates cannot be JSON serialized directly, so they are encoded as
PEM text here and reconstructed on the other side.
"""

import json

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def certificate_to_pem(certificate: x509.Certificate) -> str:
    """Serialize an x509 certificate to a PEM string."""
    return certificate.public_bytes(encoding=serialization.Encoding.PEM).decode("UTF-8")


def certificate_from_pem(pem: str) -> x509.Certificate:
    """Reconstruct an x509 certificate from a PEM string."""
    return x509.load_pem_x509_certificate(pem.encode("UTF-8"))


def write_state(path: str, state: dict) -> None:
    """Write interim exchange state to a JSON file."""
    with open(path, "w") as f:
        json.dump(state, f, indent=4, sort_keys=True)


def read_state(path: str) -> dict:
    """Read interim exchange state from a JSON file."""
    with open(path, "r") as f:
        return json.load(f)
