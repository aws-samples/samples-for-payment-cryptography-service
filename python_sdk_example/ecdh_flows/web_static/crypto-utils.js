// Browser-side cryptography for the "Select PIN" demo.
//
// Everything in this file runs in the browser using the WebCrypto API
// (window.crypto.subtle) plus pkijs/asn1js for X.509/PKCS#10 parsing and
// construction. No PIN, key material, or PIN block formatting logic is sent
// to or computed by the server -- the server only signs the browser's CSR
// (proving the browser's ephemeral public key is legitimate for this demo's
// AWS Private CA) and forwards the already-encrypted PIN block to AWS
// Payment Cryptography.
//
// pkijs/asn1js are loaded from esm.sh as ES modules; no build/bundle step
// is required to run this demo. See README.md for details.
import * as asn1js from "https://esm.sh/asn1js@3.0.10";
import { Certificate, CertificationRequest, AttributeTypeAndValue, setEngine, CryptoEngine } from "https://esm.sh/pkijs@3.4.0";

// pkijs looks for a globally registered CryptoEngine when it isn't running
// under a framework that sets one up automatically.
setEngine(
  "browser",
  new CryptoEngine({ name: "browser", crypto: window.crypto, subtle: window.crypto.subtle })
);

const subtle = window.crypto.subtle;

// ---------------------------------------------------------------------------
// Byte/hex helpers
// ---------------------------------------------------------------------------

export function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function derToPem(derBytes, label) {
  const b64 = btoa(String.fromCharCode(...derBytes));
  const wrapped = b64.replace(/(.{64})/g, "$1\n");
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

// ---------------------------------------------------------------------------
// ECDH key agreement (NIST P-256, matching AWS Payment Cryptography's
// ECC_NIST_P256 ECDH key used in payment_crypto/ecdh/setup.py)
// ---------------------------------------------------------------------------

/**
 * Generates an ephemeral P-256 key pair for ECDH key agreement. The key is
 * marked extractable so it can also be re-imported under the ECDSA
 * algorithm identifier to sign the CSR with the same key material (mirrors
 * how payment_crypto/ecdh/crypto_utils.py uses one `cryptography` EC key
 * object for both operations).
 */
export async function generateEcdhKeyPair() {
  return subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

/**
 * Extracts the SubjectPublicKeyInfo from a PEM certificate (as returned by
 * AWS Payment Cryptography's GetPublicKeyCertificate) and imports it as a
 * WebCrypto ECDH public key.
 */
export async function importEcdhPublicKeyFromCertificatePem(certificatePem) {
  const der = pemToDer(certificatePem);
  const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  const certificate = new Certificate({ schema: asn1.result });
  const spkiDer = certificate.subjectPublicKeyInfo.toSchema().toBER(false);
  // extractable=true: this is a PUBLIC key (AWS Payment Cryptography's ECDH public key
  // certificate), not secret material, so it's safe to re-export for display purposes.
  return subtle.importKey("spki", spkiDer, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

/**
 * Exports a public key's raw (uncompressed point) bytes as hex, for display/logging
 * purposes. Only ever called with public keys -- never use this on private key material.
 */
export async function exportPublicKeyRawHex(publicKey) {
  const raw = new Uint8Array(await subtle.exportKey("raw", publicKey));
  return bytesToHex(raw);
}

/**
 * Performs the ECDH exchange and returns the raw shared secret (Z).
 */
export async function deriveSharedSecret(privateKey, peerPublicKey) {
  // P-256 shared secret (the X coordinate) is 32 bytes.
  const bits = await subtle.deriveBits({ name: "ECDH", public: peerPublicKey }, privateKey, 256);
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// NIST SP 800-56A Concatenation KDF ("ConcatKDFHash"), single-step, matching
// cryptography.hazmat.primitives.kdf.concatkdf.ConcatKDFHash used server-side.
// WebCrypto has no native ConcatKDF, so it's implemented here directly on
// top of SubtleCrypto's SHA-512 digest primitive.
// ---------------------------------------------------------------------------

export async function concatKdfHashSha512(sharedSecret, otherInfo, lengthBytes) {
  const hashLenBytes = 64; // SHA-512
  const reps = Math.ceil(lengthBytes / hashLenBytes);
  const chunks = [];
  for (let i = 1; i <= reps; i++) {
    const counter = new Uint8Array(4);
    counter[0] = (i >>> 24) & 0xff;
    counter[1] = (i >>> 16) & 0xff;
    counter[2] = (i >>> 8) & 0xff;
    counter[3] = i & 0xff;
    const input = concatBytes(counter, sharedSecret, otherInfo);
    const digest = new Uint8Array(await subtle.digest("SHA-512", input));
    chunks.push(digest);
  }
  return concatBytes(...chunks).slice(0, lengthBytes);
}

/**
 * Generates a random 32-byte "shared information" value used as OtherInfo
 * in the ConcatKDF, matching CryptoUtils.generate_shared_info() server-side.
 */
export function generateSharedInfo() {
  return window.crypto.getRandomValues(new Uint8Array(32));
}

// ---------------------------------------------------------------------------
// AES-ECB single/double block operations, implemented on top of WebCrypto's
// AES-CBC primitive (WebCrypto has no native ECB mode). A single ECB block
// encrypt is exactly the first ciphertext block of AES-CBC with a zero IV
// applied to that block (WebCrypto PKCS7-pads a full extra block since the
// input is already block-aligned). This is used to build the ISO Format 4
// PIN block per ISO 9564.
// ---------------------------------------------------------------------------

async function importAesEcbHelperKey(rawKey) {
  return subtle.importKey("raw", rawKey, { name: "AES-CBC" }, false, ["encrypt"]);
}

async function ecbEncryptBlock(rawKey, block16) {
  const key = await importAesEcbHelperKey(rawKey);
  const iv = new Uint8Array(16);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, key, block16));
  return ct.slice(0, 16);
}

// ---------------------------------------------------------------------------
// ISO 9564 PIN block format 4 (ISO Format 4), matching psec.pinblock's
// encipher_pinblock_iso_4 used server-side for the PEK-encrypted pinblock,
// and AWS Payment Cryptography's IsoFormat4 translation attribute.
// ---------------------------------------------------------------------------

function encodePinFieldIso4(pin, randomPad8) {
  if (pin.length < 4 || pin.length > 12 || !/^\d+$/.test(pin)) {
    throw new Error("PIN must be 4-12 digits");
  }
  const lenNibble = pin.length.toString(16);
  const fill = "A".repeat(14 - pin.length);
  const hex = "4" + lenNibble + pin + fill + bytesToHex(randomPad8);
  return hexToBytes(hex);
}

function encodePanFieldIso4(pan) {
  if (pan.length < 1 || pan.length > 19 || !/^\d+$/.test(pan)) {
    throw new Error("PAN must be 1-19 digits");
  }
  const lenDigit = String(Math.max(0, pan.length - 12));
  const field = (lenDigit + pan.padStart(12, "0")).padEnd(32, "0");
  return hexToBytes(field);
}

/**
 * Encrypts `pin` for `pan` under `key` (16-byte AES-128 key, as derived by
 * concatKdfHashSha512 with lengthBytes=16) using ISO 9564 PIN block format 4.
 * Returns the 16-byte enciphered PIN block as an uppercase hex string,
 * matching the format AWS Payment Cryptography's TranslatePinData API and
 * psec.pinblock.encipher_pinblock_iso_4 both expect/produce.
 */
/**
 * @param {Uint8Array} key - 16-byte AES-128 key
 * @param {string} pin - plaintext PIN (NEVER passed to onTrace)
 * @param {string} pan - PAN
 * @param {{onTrace?: (step: string, hex: string) => void}} [options] - optional callback
 *        invoked with intermediate (non-secret-PIN-revealing) values, for demo logging.
 *        The PIN field (which encodes the PIN digits themselves) is intentionally never
 *        passed to onTrace.
 */
export async function encipherPinBlockIso4(key, pin, pan, { onTrace } = {}) {
  const randomPad = window.crypto.getRandomValues(new Uint8Array(8));
  // pinField encodes the PIN digits directly (control nibble + length + PIN + fill/pad).
  // It is NEVER passed to onTrace, logged, or exposed outside this function.
  const pinField = encodePinFieldIso4(pin, randomPad);
  const panField = encodePanFieldIso4(pan);
  onTrace?.("panField (ISO Format 4 PAN field, not secret)", bytesToHex(panField));

  const intermediateA = await ecbEncryptBlock(key, pinField);
  onTrace?.("intermediateBlockA = AES-ECB-Encrypt(key, pinField)", bytesToHex(intermediateA));

  const intermediateB = xorBytes(intermediateA, panField);
  onTrace?.("intermediateBlockB = intermediateBlockA XOR panField", bytesToHex(intermediateB));

  const cipherBlock = await ecbEncryptBlock(key, intermediateB);
  const hex = bytesToHex(cipherBlock).toUpperCase();
  onTrace?.("finalEncryptedPinBlock = AES-ECB-Encrypt(key, intermediateBlockB)", hex);
  return hex;
}

// ---------------------------------------------------------------------------
// PKCS#10 Certificate Signing Request (CSR) generation and signing, matching
// CryptoUtils.generate_certificate_signing_request server-side. The CSR
// proves possession of the private key half of the ECDH key pair used
// above, by re-importing the same key material under the ECDSA algorithm
// identifier and signing with it (WebCrypto requires a key to be tagged
// with a single algorithm; ECDH keys can't sign directly).
// ---------------------------------------------------------------------------

async function retagEcdhKeyPairAsEcdsa(ecdhKeyPair) {
  const privJwk = await subtle.exportKey("jwk", ecdhKeyPair.privateKey);
  const pubJwk = await subtle.exportKey("jwk", ecdhKeyPair.publicKey);

  const ecdsaPrivJwk = { ...privJwk, key_ops: ["sign"] };
  delete ecdsaPrivJwk.alg;
  const ecdsaPubJwk = { ...pubJwk, key_ops: ["verify"] };
  delete ecdsaPubJwk.alg;

  const privateKey = await subtle.importKey(
    "jwk",
    ecdsaPrivJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const publicKey = await subtle.importKey(
    "jwk",
    ecdsaPubJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
  return { privateKey, publicKey };
}

/**
 * Builds and signs a PKCS#10 CSR for the given ECDH key pair's public key,
 * returning PEM text ready to send to the server for signing by the demo
 * AWS Private CA.
 */
export async function buildSignedCsr(ecdhKeyPair, commonName = "browser-select-pin-demo") {
  const ecdsaKeyPair = await retagEcdhKeyPairAsEcdsa(ecdhKeyPair);

  const csr = new CertificationRequest();
  csr.version = 0;
  csr.subject.typesAndValues.push(
    new AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1js.Utf8String({ value: commonName }) })
  );
  csr.attributes = [];

  await csr.subjectPublicKeyInfo.importKey(ecdsaKeyPair.publicKey);
  await csr.sign(ecdsaKeyPair.privateKey, "SHA-256");

  const der = csr.toSchema().toBER(false);
  return derToPem(new Uint8Array(der), "CERTIFICATE REQUEST");
}
