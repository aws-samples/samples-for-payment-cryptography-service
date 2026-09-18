import {
  generateEcdhKeyPair,
  importEcdhPublicKeyFromCertificatePem,
  exportPublicKeyRawHex,
  deriveSharedSecret,
  concatKdfHashSha512,
  generateSharedInfo,
  encipherPinBlockIso4,
  buildSignedCsr,
  bytesToHex,
} from "./crypto-utils.js";

const form = document.getElementById("select-pin-form");
const panInput = document.getElementById("pan");
const pinInput = document.getElementById("pin");
const pinConfirmInput = document.getElementById("pin-confirm");
const pinMismatchEl = document.getElementById("pin-mismatch");
const submitButton = document.getElementById("submit-btn");
const statusEl = document.getElementById("status");
const logEl = document.getElementById("log");
const resultEl = document.getElementById("result");

function pinsMatch() {
  return pinInput.value === pinConfirmInput.value;
}

function updatePinMismatchUI() {
  const shouldShow = pinConfirmInput.value.length > 0 && !pinsMatch();
  pinMismatchEl.hidden = !shouldShow;
  pinConfirmInput.setCustomValidity(shouldShow ? "PINs do not match." : "");
}

pinInput.addEventListener("input", updatePinMismatchUI);
pinConfirmInput.addEventListener("input", updatePinMismatchUI);

function log(message) {
  const line = document.createElement("div");
  line.textContent = message;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

function logApiCalls(calls) {
  if (!calls || calls.length === 0) return;
  for (const call of calls) {
    log(`[server -> AWS] ${call.service}.${call.operation}(${JSON.stringify(call.params)})`);
  }
}

function setStatus(message, kind) {
  statusEl.textContent = message;
  statusEl.className = kind ? `status status--${kind}` : "status";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  submitButton.disabled = true;
  logEl.innerHTML = "";
  resultEl.hidden = true;
  setStatus("Working...", "working");

  const pan = panInput.value.trim();
  const pin = pinInput.value.trim();
  const pinConfirm = pinConfirmInput.value.trim();

  try {
    if (!/^\d{12,19}$/.test(pan)) {
      throw new Error("PAN must be 12-19 digits");
    }
    if (!/^\d{4,12}$/.test(pin)) {
      throw new Error("PIN must be 4-12 digits");
    }
    if (pin !== pinConfirm) {
      updatePinMismatchUI();
      throw new Error("PIN and confirmation do not match");
    }

    log("[browser] Generating ephemeral ECDH key pair (P-256)...");
    const ecdhKeyPair = await generateEcdhKeyPair();
    const ephemeralPublicKeyHex = await exportPublicKeyRawHex(ecdhKeyPair.publicKey);
    log(`[browser]   ephemeral public key (not secret): ${ephemeralPublicKeyHex}`);

    log("[browser] Fetching AWS Payment Cryptography's ECDH public key certificate...");
    const certResponse = await fetch("/api/apc-certificate");
    if (!certResponse.ok) throw new Error("Failed to fetch APC certificate");
    const certResult = await certResponse.json();
    logApiCalls(certResult.apiCalls);
    const apcPublicKey = await importEcdhPublicKeyFromCertificatePem(atobPem(certResult.certificate));
    const apcPublicKeyHex = await exportPublicKeyRawHex(apcPublicKey);
    log(`[browser]   APC ECDH public key extracted from certificate: ${apcPublicKeyHex}`);

    log("[browser] Performing ECDH key agreement (browser private key + APC public key)...");
    const sharedSecret = await deriveSharedSecret(ecdhKeyPair.privateKey, apcPublicKey);
    log(`[browser]   shared secret Z (never leaves browser): ${bytesToHex(sharedSecret)}`);

    log("[browser] Deriving AES-128 key via NIST SP 800-56A Concatenation KDF (SHA-512)...");
    const sharedInfo = generateSharedInfo();
    log(`[browser]   sharedInfo / OtherInfo (sent to server, not secret): ${bytesToHex(sharedInfo)}`);
    const derivedKey = await concatKdfHashSha512(sharedSecret, sharedInfo, 16);
    log(`[browser]   derived AES-128 key (never leaves browser): ${bytesToHex(derivedKey)}`);

    log("[browser] Encrypting PIN block (ISO 9564 Format 4) with derived key. Plaintext PIN never leaves the browser.");
    const encryptedPinBlock = await encipherPinBlockIso4(derivedKey, pin, pan, {
      onTrace: (step, hex) => log(`[browser]   ${step}: ${hex}`),
    });
    log(`[browser]   final encrypted PIN block (sent to server): ${encryptedPinBlock}`);

    log("[browser] Building and signing PKCS#10 CSR to prove possession of the ephemeral key...");
    const csrPem = await buildSignedCsr(ecdhKeyPair);
    log("[browser]   self-signed CSR (not secret, contains only the public key):");
    log(csrPem.trim());

    log("[browser] Sending CSR to server to be signed by the demo AWS Private CA...");
    const signCsrResponse = await fetch("/api/sign-csr", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ csr: csrPem }),
    });
    const signCsrResult = await signCsrResponse.json();
    if (!signCsrResponse.ok) {
      throw new Error(signCsrResult.error || "Server rejected the CSR");
    }
    logApiCalls(signCsrResult.apiCalls);
    log("[server] AWS Private CA signed the browser's ephemeral public key:");
    log(signCsrResult.signedCertificate.trim());

    log("[browser] Sending encrypted PIN block + signed certificate + shared info to server (no plaintext PIN included)...");
    const setPinResponse = await fetch("/api/set-pin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pan,
        encryptedPinBlock,
        signedCertificate: signCsrResult.signedCertificate,
        sharedInfo: bytesToHex(sharedInfo),
      }),
    });

    const setPinResult = await setPinResponse.json();
    if (!setPinResponse.ok) {
      throw new Error(setPinResult.error || "Server rejected the request");
    }

    logApiCalls(setPinResult.apiCalls);
    log("[server] AWS Payment Cryptography translated the pin block and generated a PVV.");
    setStatus("PIN set successfully", "success");
    pinInput.value = "";
    pinConfirmInput.value = "";
    updatePinMismatchUI();
    resultEl.hidden = false;
    resultEl.innerHTML = `
      <div><strong>PAN:</strong> ${pan}</div>
      <div><strong>PVV (Visa PIN Verification Value):</strong> ${setPinResult.pvv}</div>
      <div><strong>PEK-encrypted PIN block (server side):</strong> ${setPinResult.pekEncryptedPinBlock}</div>
      <div class="result__note">The plaintext PIN was never transmitted. Only the browser-encrypted
      ISO Format 4 PIN block (encrypted under a key AWS Payment Cryptography derived independently via ECDH)
      was sent to the server.</div>
    `;
  } catch (err) {
    console.error(err);
    setStatus(`Error: ${err.message}`, "error");
    log(`[error] ${err.message}`);
  } finally {
    submitButton.disabled = false;
  }
});

function atobPem(base64PemBody) {
  // AWS Payment Cryptography's GetPublicKeyCertificate response fields
  // (KeyCertificate / KeyCertificateChain) are base64-encoded PEM text.
  return atob(base64PemBody);
}
