// Envelope-scoped session keypair (browser side).
//
// Generates a NON-EXTRACTABLE ECDSA P-256 keypair per envelope and stores it in
// IndexedDB under the envelope id. Modern browsers (Chrome, Safari, Firefox)
// preserve unextractable CryptoKey objects across the structured-clone boundary
// used by IndexedDB. The private key never leaves the IDB store — even this
// module can't export it.
//
// Every protected request to the Worker must carry a signature over
//   canonicalJson({envelope_id, action, nonce, timestamp})
// produced by this keypair. The Worker verifies it against the JWK persisted on
// the envelope row at creation time. See the server-side session module and
// invariant #11 for the contract.
//
// canonicalJson MUST stay byte-identical to the server-side canonicalJson. The
// server-side duplication for the existing /sign payload signature remains
// intact — this file only adds a third party (the browser session module) that
// uses the same serialization.

const DB_NAME = "free-sign-session-v1";
const STORE_NAME = "keys";

// Cache of opened DB connections — at most one open handle per browsing context.
let dbPromise = null;

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("indexeddb_open_failed"));
  });
  return dbPromise;
}

async function idbGet(envelopeId) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).get(envelopeId);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(envelopeId, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(value, envelopeId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error("indexeddb_aborted"));
  });
}

/**
 * Returns `{publicKeyJwk, privateKey}` for the given envelope, generating and
 * persisting a new keypair on first use. Public key JWK is also cached
 * alongside the CryptoKeyPair so we don't have to re-export from a (possibly
 * non-extractable) key every call.
 */
export async function getOrCreateSessionKey(envelopeId) {
  const existing = await idbGet(envelopeId);
  if (existing && existing.privateKey && existing.publicKeyJwk) {
    return { publicKeyJwk: existing.publicKeyJwk, privateKey: existing.privateKey };
  }
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false, // extractable=false → private key never leaves IDB / WebCrypto
    ["sign"],
  );
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  // Drop key_ops / ext from the JWK — the server only needs the curve + coords
  // and the canonicalSessionPubkeyJson() helper on the server only commits
  // {crv, kty, x, y} to the pubkey hash anyway.
  const slimJwk = { crv: publicKeyJwk.crv, kty: publicKeyJwk.kty, x: publicKeyJwk.x, y: publicKeyJwk.y };
  await idbPut(envelopeId, {
    privateKey: keyPair.privateKey,
    publicKeyJwk: slimJwk,
    createdAt: new Date().toISOString(),
  });
  return { publicKeyJwk: slimJwk, privateKey: keyPair.privateKey };
}

/**
 * Check whether a session key exists in IndexedDB for the given envelope. Used
 * by the UI to detect "this signing link belongs to another browser" — when an
 * envelope id arrived via the URL but no session key is on this device, the
 * user cannot sign and must start a fresh ceremony.
 */
export async function hasSessionKey(envelopeId) {
  const existing = await idbGet(envelopeId);
  return !!(existing && existing.privateKey && existing.publicKeyJwk);
}

/**
 * Produce a session signature for an envelope action. The Worker verifies the
 * same `canonicalJson({envelope_id, action, nonce, timestamp})` string.
 */
export async function signSessionAction(envelopeId, action, privateKey) {
  const nonce = randomHex32();
  const timestamp = new Date().toISOString();
  const payloadText = canonicalJson({
    action,
    envelope_id: envelopeId,
    nonce,
    timestamp,
  });
  const sigBuf = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(payloadText),
  );
  return {
    signatureBase64url: base64Url(new Uint8Array(sigBuf)),
    nonce,
    timestamp,
  };
}

/**
 * Mutates the `headers` object/array in place, attaching the four session
 * headers the Worker expects.
 */
export function attachSessionHeaders(headers, sig, action) {
  headers["x-fsig-session-signature"] = sig.signatureBase64url;
  headers["x-fsig-session-nonce"] = sig.nonce;
  headers["x-fsig-session-timestamp"] = sig.timestamp;
  headers["x-fsig-session-action"] = action;
  return headers;
}

// Byte-identical to the server-side canonicalJson and the legacy browser
// duplicate (which now imports from here). See invariant #1.
export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function randomHex32() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
