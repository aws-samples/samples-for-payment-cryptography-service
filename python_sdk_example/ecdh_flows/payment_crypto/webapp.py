"""
Browser-based "Select PIN" demo server.

Unlike main.py (which performs ECDH key agreement and ISO Format 4 PIN block
encryption entirely in Python for demonstration purposes), this Flask app
backs a browser UI where ECDH key generation, key derivation, and PIN block
formatting all happen client-side using the WebCrypto API. This server only
performs the operations that must happen server-side:

  1. Provisioning the demo AWS Private CA + AWS Payment Cryptography keys
     (once, on first request), reusing ecdh.setup.setup().
  2. Handing the browser AWS Payment Cryptography's ECDH public key
     certificate, so the browser can derive the same shared secret.
  3. Signing the browser-generated Certificate Signing Request (CSR) with
     the demo AWS Private CA, so AWS Payment Cryptography can trust the
     browser's ephemeral public key.
  4. Forwarding the browser-encrypted PIN block to AWS Payment Cryptography
     (TranslatePinData + GeneratePinData) to obtain and store the PVV.

The browser never sends the AWS Private CA or AWS Payment Cryptography a
plaintext PIN. Only an ISO Format 4 PIN block, encrypted client-side with a
key that AWS Payment Cryptography derives independently via ECDH, is ever
sent over the wire.

Run with:
    python3 payment_crypto/webapp.py

Then open http://127.0.0.1:5000 in a browser.

SECURITY NOTE: This Flask app is a local development demo. It has no
authentication, is single-process/single-worker, and is not intended to be
exposed beyond localhost or used as-is in production.

DEMO SIMPLIFICATION: This page assumes the user is already authenticated and would normally
select a card from a list of cards on their account, not type a PAN by hand. The free-text PAN
field in the UI (and the `pan` field accepted below) exists only so this demo can be exercised
without building out account lookup/authentication -- it is not representative of how a real
cardholder-facing "Select PIN" flow would obtain the PAN.
"""
import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, request, send_from_directory

from payment_crypto import api_call_log
from payment_crypto.ecdh.backend import Backend
from payment_crypto.ecdh.setup import setup

api_call_log.install()

logger = logging.getLogger(__name__)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web_static")

app = Flask(__name__, static_folder=None)

# Provisioned lazily on first request so `python3 payment_crypto/webapp.py`
# fails fast with a clear Flask startup message rather than blocking on AWS
# calls at import time.
_backend = None


def get_backend():
    global _backend
    if _backend is None:
        ca_arn, apc_client_ca_key_arn, apc_pgk_arn, apc_pek_arn, apc_ecdsa_key_arn = setup()
        _backend = Backend(ca_arn, apc_pek_arn, apc_client_ca_key_arn, apc_pgk_arn, apc_ecdsa_key_arn)
    return _backend


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)


@app.route("/api/apc-certificate", methods=["GET"])
def apc_certificate():
    """
    Returns AWS Payment Cryptography's ECDH public key certificate and its
    certificate chain. The browser uses the certificate's public key to
    perform the ECDH exchange and derive the shared symmetric key locally.
    """
    with api_call_log.track_api_calls() as calls:
        # get_backend() runs first-time setup() (CreateKey, ImportKey,
        # CreateCertificateAuthority, etc.) the very first time it's called,
        # so those AWS calls are captured here too on a cold start.
        backend = get_backend()
        chain, certificate = backend.get_apc_certificates()

    return jsonify({
        "certificate": certificate,
        "certificateChain": chain,
        "apiCalls": calls,
    })


@app.route("/api/sign-csr", methods=["POST"])
def sign_csr():
    """
    Signs the browser-generated PKCS#10 CSR with the demo AWS Private CA. This proves the
    browser's ephemeral ECDH public key (submitted as the CSR's subject public key) is
    trusted for the ECDH key agreement, without AWS Payment Cryptography ever seeing the
    browser's private key.

    This is a distinct step from /api/set-pin so the signing operation (and the resulting
    signed certificate) is visible to the demo UI as its own checkpoint, rather than
    happening silently as an implementation detail of setting the PIN.

    Expected JSON body:
      { "csr": "<PEM-encoded PKCS#10 CSR signed by the browser's ephemeral key>" }
    """
    data = request.get_json(silent=True) or {}
    csr_pem = data.get("csr", "")
    if not csr_pem:
        return jsonify({"error": "csr is required"}), 400

    backend = get_backend()
    try:
        with api_call_log.track_api_calls() as calls:
            signed_certificate = backend.sign_csr(csr_pem)
    except Exception:
        # Log the full exception server-side (visible in this process's own terminal, run
        # by whoever started the demo) but do not reflect exception details -- which may
        # include internal paths, AWS error internals, etc. -- back to the HTTP client.
        logger.exception("sign-csr failed")
        return jsonify({"error": "Failed to sign CSR. See server logs for details."}), 502

    return jsonify({"signedCertificate": signed_certificate, "apiCalls": calls})


@app.route("/api/set-pin", methods=["POST"])
def set_pin():
    """
    Accepts a browser-encrypted ISO Format 4 PIN block plus the AWS Private CA-signed
    certificate obtained from /api/sign-csr, and asks AWS Payment Cryptography to translate
    the PIN block to the backend's PIN Encryption Key and generate a PVV.

    Expected JSON body:
      {
        "pan": "<primary account number, digits only>",
        "encryptedPinBlock": "<hex, 16-byte ISO Format 4 PIN block>",
        "signedCertificate": "<PEM-encoded certificate returned by /api/sign-csr>",
        "sharedInfo": "<hex, the OtherInfo/SharedInformation used in the browser's ConcatKDF>"
      }

    The plaintext PIN is never included in this request; it was already
    encrypted client-side before this call.
    """
    data = request.get_json(silent=True) or {}
    pan = data.get("pan", "")
    encrypted_pin_block = data.get("encryptedPinBlock", "")
    signed_certificate = data.get("signedCertificate", "")
    shared_info_hex = data.get("sharedInfo", "")

    if not pan or not pan.isdigit() or len(pan) < 12 or len(pan) > 19:
        return jsonify({"error": "pan must be a 12-19 digit numeric string"}), 400
    if not encrypted_pin_block:
        return jsonify({"error": "encryptedPinBlock is required"}), 400
    if not signed_certificate:
        return jsonify({"error": "signedCertificate is required"}), 400
    if not shared_info_hex:
        return jsonify({"error": "sharedInfo is required"}), 400

    try:
        shared_info = bytes.fromhex(shared_info_hex)
    except ValueError:
        return jsonify({"error": "sharedInfo must be a hex string"}), 400

    backend = get_backend()

    try:
        with api_call_log.track_api_calls() as calls:
            backend.set_pin_with_signed_certificate(pan, encrypted_pin_block, signed_certificate, shared_info)
    except Exception:
        # See the comment in sign_csr() above: log full details server-side only.
        logger.exception("set-pin failed")
        return jsonify({"error": "Failed to set PIN. See server logs for details."}), 502

    return jsonify({
        "status": "success",
        "pvv": backend.pvv,
        "pekEncryptedPinBlock": backend.tmp_pek_pinblock,
        "apiCalls": calls,
    })


if __name__ == "__main__":
    # debug=False: the Werkzeug debugger (debug=True) lets anyone who can reach this
    # server execute arbitrary code via the browser. Even for a localhost-only demo,
    # that's not a pattern worth normalizing. Flask's auto-reloader (via `use_reloader`)
    # is independent of debug mode and not needed here, so it's left at its default (off).
    logging.basicConfig(level=logging.INFO)
    app.run(host="127.0.0.1", port=5000, debug=False)
