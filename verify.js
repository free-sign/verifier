// FreeSign PDF Verifier — runs entirely in the browser. Drop a signed PDF, get
// five evidence checks: CMS signature, certificate chain, RFC 3161 timestamp,
// OpenTimestamps Bitcoin anchor, and an explanation of Adobe AATL.
//
// Privacy invariant: the PDF bytes never leave the browser. Network calls are
// limited to (1) optional GETs to allowlisted OpenTimestamps calendar hosts
// when upgrading an embedded calendar-only proof, and (2) an optional GET to
// blockstream.info to resolve a Bitcoin block height for display. The document
// hash is not sent to those services beyond the OTS commitment path already
// embedded in the PDF.
//
// Format references:
//   PDF 32000-1:2008 §12.8 (signature dictionary, ByteRange)
//   RFC 5652 (CMS SignedData), RFC 5280 (X.509), RFC 3161 (TimeStampToken),
//   github.com/opentimestamps/python-opentimestamps (.ots format).

// canonicalJson is shared with the signing side — invariant #1: the verifier
// must canonicalize the embedded evidence's canonical_payload byte-identically
// to how the browser signed it.
import { canonicalJson } from "./session.js";
import { upgradeTimestampFromTree } from "./ots-timestamp.js";

// -----------------------------------------------------------------------------
// OID constants — kept byte-identical with the server-side CMS module.
// -----------------------------------------------------------------------------

const OID = {
  cmsData: "1.2.840.113549.1.7.1",
  cmsSignedData: "1.2.840.113549.1.7.2",
  contentTypeAttr: "1.2.840.113549.1.9.3",
  messageDigestAttr: "1.2.840.113549.1.9.4",
  signingTimeAttr: "1.2.840.113549.1.9.5",
  signingCertificate: "1.2.840.113549.1.9.16.2.12",       // ESS v1 (SHA-1)
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",     // ESS v2 (SHA-256+)
  signatureTimeStampToken: "1.2.840.113549.1.9.16.2.14",
  // Digests.
  sha1: "1.3.14.3.2.26",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  // Signature algorithms.
  ecdsaWithSha256: "1.2.840.10045.4.3.2",
  ecdsaWithSha384: "1.2.840.10045.4.3.3",
  ecdsaWithSha512: "1.2.840.10045.4.3.4",
  rsaEncryption: "1.2.840.113549.1.1.1",      // legacy; pair with SignerInfo.digestAlgorithm
  sha1WithRsa: "1.2.840.113549.1.1.5",
  sha256WithRsa: "1.2.840.113549.1.1.11",
  sha384WithRsa: "1.2.840.113549.1.1.12",
  sha512WithRsa: "1.2.840.113549.1.1.13",
  rsassaPss: "1.2.840.113549.1.1.10",         // params carry hash, MGF1 hash, saltLength
  mgf1: "1.2.840.113549.1.1.8",
  ed25519: "1.3.101.112",
  ed448: "1.3.101.113",
  // SubjectPublicKeyInfo algorithm OIDs.
  ecPublicKey: "1.2.840.10045.2.1",
  // Named curves (parameter inside ecPublicKey AlgorithmIdentifier).
  p256Curve: "1.2.840.10045.3.1.7",
  p384Curve: "1.3.132.0.34",
  p521Curve: "1.3.132.0.35",
  // X.509 RDN attribute types + extensions.
  commonName: "2.5.4.3",
  country: "2.5.4.6",
  organization: "2.5.4.10",
  subjectAltName: "2.5.29.17",
  subjectKeyIdentifier: "2.5.29.14",
  // FreeSign-specific OpenTimestamps unsignedAttribute.
  freeSignOtsCommitment: "1.3.6.1.4.1.65834.1.1",
  // FreeSign-specific signing-evidence record signedAttribute. OCTET STRING
  // { utf8(evidence JSON) } — the pre-seal ceremony record.
  freeSignEvidence: "1.3.6.1.4.1.65834.1.2",
};

// Mapping from digest OID to WebCrypto hash name + raw byte size.
// NOTE: SHA-1 is intentionally NOT in this table. It's known to be vulnerable
// to chosen-prefix collisions (SHAttered, 2017) and unsuitable for new
// signatures. A SHA-1 signature lands as "unsupported digest" rather than
// being silently accepted — matches what Adobe Reader does for SHA-1
// signatures on Acrobat ≥ DC 2017.
const DIGEST_INFO = {
  [OID.sha256]: { name: "SHA-256", size: 32 },
  [OID.sha384]: { name: "SHA-384", size: 48 },
  [OID.sha512]: { name: "SHA-512", size: 64 },
};

// Mapping from signature algorithm OID to {kind, implicitDigest?}. ECDSA OIDs
// carry the digest in their own name; rsaEncryption is the "bring your own
// digest" form that must read from SignerInfo.digestAlgorithm.
const SIGALG_INFO = {
  [OID.ecdsaWithSha256]: { kind: "ECDSA",   implicitDigestOid: OID.sha256 },
  [OID.ecdsaWithSha384]: { kind: "ECDSA",   implicitDigestOid: OID.sha384 },
  [OID.ecdsaWithSha512]: { kind: "ECDSA",   implicitDigestOid: OID.sha512 },
  [OID.sha256WithRsa]:   { kind: "RSA",     implicitDigestOid: OID.sha256 },
  [OID.sha384WithRsa]:   { kind: "RSA",     implicitDigestOid: OID.sha384 },
  [OID.sha512WithRsa]:   { kind: "RSA",     implicitDigestOid: OID.sha512 },
  [OID.rsaEncryption]:   { kind: "RSA",     implicitDigestOid: null }, // BYO digest
  [OID.rsassaPss]:       { kind: "RSA-PSS", implicitDigestOid: null }, // params carry hash, MGF1, saltLength
  [OID.ed25519]:         { kind: "Ed25519", implicitDigestOid: null },
  [OID.ed448]:           { kind: "Ed448",   implicitDigestOid: null },
};

// EC named-curve OID → WebCrypto name + raw integer byte size (for P1363 r||s).
const CURVE_INFO = {
  [OID.p256Curve]: { name: "P-256", scalarBytes: 32 },
  [OID.p384Curve]: { name: "P-384", scalarBytes: 48 },
  [OID.p521Curve]: { name: "P-521", scalarBytes: 66 },
};

// OpenTimestamps .ots file magic (HEADER_MAGIC).
const OTS_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73,
  0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00,
  0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const BTC_ATTESTATION_TAG = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
const OTS_OP_SHA256 = 0x08;
// After this age, calendar-only embedded proof + failed live upgrade → INFO,
// not the hourglass "on its way" copy (production PDFs embed the calendar
// response at /seal time; Bitcoin confirmation arrives later via upgrade).
const OTS_STALE_AFTER_SIGNING_MS = 3 * 60 * 60 * 1000;
const DEFAULT_OTS_CALENDARS = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://finney.calendar.eternitywall.com",
];

// -----------------------------------------------------------------------------
// Bytes / hex / base64.
// -----------------------------------------------------------------------------

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

function bytesEqAt(hay, needle, off) {
  if (hay.length - off < needle.length) return false;
  for (let i = 0; i < needle.length; i += 1) if (hay[off + i] !== needle[i]) return false;
  return true;
}

function hexToBytes(hexStr) {
  const clean = hexStr.replace(/\s+/g, "");
  if (clean.length % 2 !== 0) throw new Error("hex length odd");
  // STRICT hex: reject anything that isn't 0-9A-Fa-f. parseInt(.., 16) silently
  // truncates at the first non-hex char (issue #9 from /cr) — an attacker could
  // stuff `4ZZ` and have it decode to 0x04. Validate first.
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error("hex contains non-hex characters");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function b64uToBytes(value) {
  let s = String(value).replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64u(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Minimal CBOR reader — only what a COSE_Key map needs (unsigned ints,
// negative ints, byte/text strings, definite-length maps). Used to re-verify
// an embedded WebAuthn passkey assertion (Stage 6E).
function cborReadCoseKey(bytes) {
  let p = 0;
  function read() {
    if (p >= bytes.length) throw new Error("cbor: truncated");
    const b = bytes[p]; p += 1;
    const major = b >> 5;
    const info = b & 0x1f;
    let len = info;
    if (info === 24) { len = bytes[p]; p += 1; }
    else if (info === 25) { len = (bytes[p] << 8) | bytes[p + 1]; p += 2; }
    else if (info === 26) {
      len = ((bytes[p] << 24) | (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3]) >>> 0;
      p += 4;
    } else if (info > 26) throw new Error("cbor: unsupported length encoding");
    if (major === 0) return len;
    if (major === 1) return -1 - len;
    if (major === 2) { const v = bytes.slice(p, p + len); p += len; return v; }
    if (major === 3) { const v = new TextDecoder().decode(bytes.slice(p, p + len)); p += len; return v; }
    if (major === 5) {
      const m = new Map();
      for (let i = 0; i < len; i += 1) { const k = read(); m.set(k, read()); }
      return m;
    }
    throw new Error("cbor: unsupported major type " + major);
  }
  return read();
}

// FreeSign's production WebAuthn relying-party identity. The offline verifier
// pins these as CONSTANTS — deriving the expected origin / rpId from the
// assertion's own clientData (a circular check) could never reject a
// wrong-relying-party assertion.
const WEBAUTHN_RP_ID = "free-sign.com";
const WEBAUTHN_ORIGIN = "https://free-sign.com";

// Re-verify an embedded WebAuthn passkey assertion (Stage 6E): its ECDSA
// signature against the embedded COSE public key, its challenge against
// SHA-256(canonicalJson(canonical_payload)) (intent binding), its origin /
// rpId against FreeSign's production RP identity (NOT against values read from
// the assertion itself), the user-presence + user-verification flags, and that
// it names the SAME credential the primary-signed canonical_payload committed
// to. The embedded COSE key is self-asserted — for a passkey signer the trust
// anchor is the server-issued CMS, not this standalone re-check; this function
// confirms the assertion is well-formed and bound to the signed payload.
// Returns { ok, detail }.
async function verifyEmbeddedWebauthnAssertion(ev, {
  expectedOrigin = WEBAUTHN_ORIGIN,
  expectedRpId = WEBAUTHN_RP_ID,
} = {}) {
  const wa = ev.webauthn_assertion;
  for (const k of ["cose_public_key", "authenticator_data", "client_data_json", "signature"]) {
    if (!wa || !wa[k]) return { ok: false, detail: "passkey assertion record is incomplete" };
  }
  const cose = cborReadCoseKey(b64uToBytes(wa.cose_public_key));
  if (!(cose instanceof Map) || cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1) {
    return { ok: false, detail: "passkey COSE key is not an ES256 / P-256 key" };
  }
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (!(x instanceof Uint8Array) || x.length !== 32 || !(y instanceof Uint8Array) || y.length !== 32) {
    return { ok: false, detail: "passkey COSE key coordinates are malformed" };
  }
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: bytesToB64u(x), y: bytesToB64u(y) },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
  );
  const authData = b64uToBytes(wa.authenticator_data);
  if (authData.length < 37) return { ok: false, detail: "passkey authenticatorData is too short" };
  const clientDataBytes = b64uToBytes(wa.client_data_json);
  const clientDataHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataBytes));
  const signed = new Uint8Array(authData.length + clientDataHash.length);
  signed.set(authData, 0);
  signed.set(clientDataHash, authData.length);
  const sigP1363 = ecdsaDerToP1363(b64uToBytes(wa.signature), 32);
  const sigOk = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sigP1363, signed);
  if (!sigOk) {
    return { ok: false, detail: "passkey assertion signature did NOT verify against its COSE key" };
  }
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  if (clientData.type !== "webauthn.get") {
    return { ok: false, detail: "passkey assertion clientData.type is not webauthn.get" };
  }
  // Origin + rpId are checked against FreeSign's production RP — never against
  // values pulled from the assertion (that would be circular and unfalsifiable).
  if (clientData.origin !== expectedOrigin) {
    return { ok: false, detail: `passkey assertion origin "${clientData.origin || "?"}" is not ${expectedOrigin}` };
  }
  const expectedRpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(expectedRpId)),
  );
  const rpIdHash = authData.slice(0, 32);
  for (let i = 0; i < 32; i += 1) {
    if (rpIdHash[i] !== expectedRpIdHash[i]) {
      return { ok: false, detail: `passkey assertion rpIdHash does not match ${expectedRpId}` };
    }
  }
  const flags = authData[32];
  if ((flags & 0x01) === 0) return { ok: false, detail: "passkey assertion user-presence flag not set" };
  if ((flags & 0x04) === 0) return { ok: false, detail: "passkey assertion user-verification flag not set" };
  // Intent binding — the assertion's challenge must equal the payload hash.
  const payloadHash = new Uint8Array(await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(canonicalJson(ev.canonical_payload || {})),
  ));
  if (clientData.challenge !== bytesToB64u(payloadHash)) {
    return { ok: false, detail: "passkey assertion challenge does not match the signed payload hash" };
  }
  // The assertion must name a credential.
  if (!wa.credential_id) {
    return { ok: false, detail: "passkey assertion record is missing credential_id" };
  }
  // Identity binding. When the signed canonical_payload commits a credential id
  // (legacy in-payload flow), the assertion must name THAT exact credential, so a
  // forged assertion can't be substituted wholesale. Discoverable (resident)
  // passkeys cannot commit the id inside the challenge-bound payload — the browser
  // only learns which credential the authenticator picked AFTER get() — so it
  // rides on the assertion instead (canonical_payload.webauthn is just the marker
  // {}). There the binding is the challenge check above (the assertion is signed
  // over THIS payload's hash) plus the assertion-signature check; the credential
  // id is reported, not cross-checked against the payload.
  const committedCredId = ev.canonical_payload && ev.canonical_payload.webauthn
    && ev.canonical_payload.webauthn.credential_id;
  if (committedCredId && wa.credential_id !== committedCredId) {
    return { ok: false, detail: "passkey assertion credential_id does not match the signed payload's webauthn.credential_id" };
  }
  return {
    ok: true,
    detail: `the passkey holder authorised this exact payload (origin ${clientData.origin}); the credential's public key shown here is the server-verified record — the trust anchor for a passkey signer is the FreeSign-issued CMS, not this standalone re-check`,
  };
}

// -----------------------------------------------------------------------------
// ASN.1 DER reader.
// -----------------------------------------------------------------------------

function readLength(buf, off) {
  const first = buf[off];
  if (first < 0x80) return { length: first, headerLen: 1, indefinite: false };
  // BER indefinite-length form: length byte = 0x80. The content runs until
  // an end-of-contents marker (00 00). Common in some CMS emitters; PAdES
  // signatures from a few production vendors arrive in BER form.
  if (first === 0x80) return { length: -1, headerLen: 1, indefinite: true };
  const n = first & 0x7f;
  if (n === 0 || n > 4) throw new Error("unsupported ASN.1 length");
  let len = 0;
  for (let i = 0; i < n; i += 1) len = len * 256 + buf[off + 1 + i];
  return { length: len, headerLen: 1 + n, indefinite: false };
}

function readTlv(buf, off) {
  if (off >= buf.length) throw new Error("readTlv past end");
  const tag = buf[off];
  const { length, headerLen, indefinite } = readLength(buf, off + 1);
  const start = off + 1 + headerLen;
  if (indefinite) {
    // Walk children until we hit an end-of-contents marker (tag 0x00, len 0x00).
    let cursor = start;
    while (cursor + 1 < buf.length) {
      if (buf[cursor] === 0x00 && buf[cursor + 1] === 0x00) {
        return { tag, start, end: cursor, contentLen: cursor - start, headerLen: 1 + headerLen, indefinite: true, eocEnd: cursor + 2 };
      }
      const inner = readTlv(buf, cursor);
      cursor = inner.indefinite ? inner.eocEnd : inner.end;
    }
    throw new Error("BER indefinite-length value missing EOC marker");
  }
  return { tag, start, end: start + length, contentLen: length, headerLen: 1 + headerLen, indefinite: false };
}

function tlvSlice(buf, off) {
  const t = readTlv(buf, off);
  return buf.slice(off, t.end);
}

function decodeOid(buf, start, end) {
  if (start >= end) throw new Error("empty OID");
  const first = buf[start];
  const parts = [Math.floor(first / 40), first % 40];
  let val = 0;
  for (let i = start + 1; i < end; i += 1) {
    val = val * 128 + (buf[i] & 0x7f);
    if ((buf[i] & 0x80) === 0) {
      parts.push(val);
      val = 0;
    }
  }
  return parts.join(".");
}

function decodeInteger(buf, start, end) {
  // Returns BigInt for arbitrary precision.
  let n = 0n;
  for (let i = start; i < end; i += 1) n = (n << 8n) | BigInt(buf[i]);
  return n;
}

function decodeTime(buf, tlv) {
  const s = new TextDecoder().decode(buf.slice(tlv.start, tlv.end));
  if (tlv.tag === 0x17) {
    // UTCTime YYMMDDHHMMSSZ
    const m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) throw new Error("invalid UTCTime " + s);
    const yy = parseInt(m[1], 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  }
  if (tlv.tag === 0x18) {
    // GeneralizedTime YYYYMMDDHHMMSSZ
    const m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!m) throw new Error("invalid GeneralizedTime " + s);
    return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  }
  throw new Error("not a time tag 0x" + tlv.tag.toString(16));
}

function childrenOf(buf, tlv) {
  const out = [];
  let cur = tlv.start;
  while (cur < tlv.end) {
    const t = readTlv(buf, cur);
    out.push(t);
    // For BER indefinite-length children, t.end is the offset of the EOC
    // marker (00 00) — we must advance PAST it (eocEnd) before reading the
    // next sibling. Without this, the next iteration reads the EOC bytes
    // as an empty TLV and indexes get shifted (parseCms then reports
    // "expected signerInfos SET" because position 4 holds an EOC, not the
    // SET). Bug surfaced on Docuten-emitted PDFs.
    cur = t.indefinite ? t.eocEnd : t.end;
  }
  return out;
}

// -----------------------------------------------------------------------------
// X.509 certificate parser — extracts what we need for verification + display.
// -----------------------------------------------------------------------------

function parseCertificate(certDer) {
  const top = readTlv(certDer, 0);
  if (top.tag !== 0x30) throw new Error("Certificate not SEQUENCE");
  // Top-level Certificate SEQUENCE has three children: tbsCertificate,
  // signatureAlgorithm, signatureValue. To verify the cert signature later we
  // need the tbsCertificate DER bytes (slice INCLUDING tag+length, since that
  // is what the issuer signed) and the cert-level signature bytes.
  const tbs = readTlv(certDer, top.start);
  if (tbs.tag !== 0x30) throw new Error("tbsCertificate not SEQUENCE");
  const tbsBytes = certDer.slice(tbs.start - tbs.headerLen, tbs.end);
  const certSigAlgTlv = readTlv(certDer, tbs.end);
  const certSigAlgKids = childrenOf(certDer, certSigAlgTlv);
  const certSigAlgOid = decodeOid(certDer, certSigAlgKids[0].start, certSigAlgKids[0].end);
  // For RSA-PSS the parameters carry RSASSA-PSS-params. Plain RSA / ECDSA
  // / Ed25519 / Ed448 cert sigs have absent or NULL parameters.
  const certSigAlgParamsTlv = certSigAlgKids[1] || null;
  const certSigBitTlv = readTlv(certDer, certSigAlgTlv.end);
  if (certSigBitTlv.tag !== 0x03) throw new Error("Certificate signatureValue not BIT STRING");
  // BIT STRING content starts with a single byte of unused-bits count (always 0
  // for cert signatures), followed by the raw signature bytes.
  const certSigBytes = certDer.slice(certSigBitTlv.start + 1, certSigBitTlv.end);

  let cursor = tbs.start;
  let version = 0;
  // Optional [0] EXPLICIT version
  if (certDer[cursor] === 0xa0) {
    const wrap = readTlv(certDer, cursor);
    const inner = readTlv(certDer, wrap.start);
    version = Number(decodeInteger(certDer, inner.start, inner.end));
    cursor = wrap.end;
  }
  // serialNumber INTEGER
  const serialTlv = readTlv(certDer, cursor);
  const serialHex = toHex(certDer.slice(serialTlv.start, serialTlv.end));
  cursor = serialTlv.end;
  // signature AlgorithmIdentifier (skip — same OID as top-level signatureAlgorithm)
  const sigAlgTlv = readTlv(certDer, cursor);
  cursor = sigAlgTlv.end;
  // issuer Name
  const issuerTlv = readTlv(certDer, cursor);
  const issuerDer = certDer.slice(cursor, issuerTlv.end);
  const issuerString = dnToString(certDer, issuerTlv);
  cursor = issuerTlv.end;
  // validity SEQUENCE { notBefore, notAfter }
  const validityTlv = readTlv(certDer, cursor);
  const validityKids = childrenOf(certDer, validityTlv);
  const notBefore = decodeTime(certDer, validityKids[0]);
  const notAfter = decodeTime(certDer, validityKids[1]);
  cursor = validityTlv.end;
  // subject Name
  const subjectTlv = readTlv(certDer, cursor);
  const subjectDer = certDer.slice(cursor, subjectTlv.end);
  const subjectString = dnToString(certDer, subjectTlv);
  const subjectCn = extractRdnValue(certDer, subjectTlv, OID.commonName);
  cursor = subjectTlv.end;
  // subjectPublicKeyInfo SEQUENCE { AlgId, BIT STRING }
  const spkiTlv = readTlv(certDer, cursor);
  const spkiDer = certDer.slice(cursor, spkiTlv.end);
  cursor = spkiTlv.end;

  // Walk remaining for extensions [3] EXPLICIT
  let san = null;
  let ski = null;
  let basicConstraintsCa = false;
  let keyUsageKeyCertSign = false;
  while (cursor < tbs.end) {
    const t = readTlv(certDer, cursor);
    if (t.tag === 0xa3) {
      const extsTlv = readTlv(certDer, t.start);
      const extList = childrenOf(certDer, extsTlv);
      for (const ext of extList) {
        const extKids = childrenOf(certDer, ext);
        const extOid = decodeOid(certDer, extKids[0].start, extKids[0].end);
        // skip critical BOOLEAN if present
        let valTlv = extKids[extKids.length - 1];
        if (extOid === OID.subjectAltName) {
          // valTlv is OCTET STRING wrapping SEQUENCE of GeneralName.
          // OCTET STRING content IS the SEQUENCE TLV — read it once, then walk children.
          const sanSeq = readTlv(certDer, valTlv.start);
          const sanKids = childrenOf(certDer, sanSeq);
          for (const gn of sanKids) {
            // rfc822Name = [1] IMPLICIT IA5String
            if (gn.tag === 0x81) {
              san = new TextDecoder().decode(certDer.slice(gn.start, gn.end));
              break;
            }
          }
        } else if (extOid === OID.subjectKeyIdentifier) {
          // SubjectKeyIdentifier ::= KeyIdentifier (OCTET STRING).
          // extnValue is OCTET STRING containing OCTET STRING(keyId).
          const inner = readTlv(certDer, valTlv.start);
          ski = certDer.slice(inner.start, inner.end);
        } else if (extOid === "2.5.29.19") {
          // basicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
          // extnValue is OCTET STRING wrapping the SEQUENCE.
          const inner = readTlv(certDer, valTlv.start);
          if (inner.tag === 0x30) {
            const bcKids = childrenOf(certDer, inner);
            for (const k of bcKids) {
              if (k.tag === 0x01) basicConstraintsCa = certDer[k.start] === 0xff;
            }
          }
        } else if (extOid === "2.5.29.15") {
          // keyUsage ::= BIT STRING. extnValue is OCTET STRING wrapping BIT STRING.
          // Bit assignments (RFC 5280 §4.2.1.3, big-endian):
          //   0: digitalSignature, 1: nonRepudiation, 2: keyEncipherment,
          //   3: dataEncipherment, 4: keyAgreement, 5: keyCertSign,
          //   6: cRLSign, 7: encipherOnly, 8: decipherOnly
          const inner = readTlv(certDer, valTlv.start);
          if (inner.tag === 0x03 && inner.contentLen >= 2) {
            // First byte of BIT STRING content = unused-bits count; remaining = bits.
            const bits = certDer[inner.start + 1] || 0;
            keyUsageKeyCertSign = (bits & (1 << (7 - 5))) !== 0; // bit 5
          }
        }
      }
    }
    cursor = t.end;
  }

  return {
    der: certDer,
    version,
    serialHex,
    issuerDer,
    issuerString,
    subjectDer,
    subjectString,
    subjectCn,
    spkiDer,
    notBefore,
    notAfter,
    rfc822Name: san,
    ski,
    basicConstraintsCa,
    keyUsageKeyCertSign,
    // Bytes + algorithm needed to verify the cert's own signature against an
    // issuer's public key (used by verifyCertSignature in the chain check).
    tbsBytes,
    certSigAlgOid,
    certSigAlgParamsTlv,
    certSigAlgParamsBuf: certSigAlgParamsTlv ? certDer : null,
    certSigBytes,
  };
}

// The legacy freesign_verified_seal variant (/platform-seal route) used ONE
// shared, self-signed platform certificate — an organisational e-seal, CN
// "(Free)Sign Platform Seal", O "free-sign.com", and no rfc822Name SAN. Those
// subject/SAN fields are attacker-controlled in an arbitrary embedded CMS, so
// they are only safe as a compatibility hint for the legacy self-signed seal.
// Never use subject text alone to grant FreeSign platform-seal trust or to skip
// evidence-record signer-name binding for CA-issued leaves: a malicious CMS can
// embed its own CA and issue a spoofed "FreeSign Platform Seal" certificate.
function looksLikePlatformSeal(leaf) {
  if (!leaf) return false;
  if (!bytesEq(leaf.issuerDer, leaf.subjectDer)) return false;
  const cn = String(leaf.subjectCn || "");
  const subject = String(leaf.subjectString || "").toLowerCase();
  return /platform seal/i.test(cn)
    && subject.includes("free-sign.com")
    && !leaf.rfc822Name;
}

// Universal helper: given the SignerInfo signature bytes + the data the
// signer signed + verify params + SPKI info, return {alg, sig, data} ready
// for crypto.subtle.verify. This unifies the RSA/ECDSA/RSA-PSS/Ed25519/Ed448
// dispatch (issue #23, #24).
function buildVerifyInput(signatureBytes, dataBytes, verifyParams, spkiInfo) {
  if (verifyParams.kind === "ECDSA") {
    return {
      alg: { name: "ECDSA", hash: verifyParams.hashName },
      sig: ecdsaDerToP1363(signatureBytes, spkiInfo.scalarBytes),
      data: dataBytes,
    };
  }
  if (verifyParams.kind === "RSA") {
    return { alg: { name: "RSASSA-PKCS1-v1_5" }, sig: signatureBytes, data: dataBytes };
  }
  if (verifyParams.kind === "RSA-PSS") {
    return {
      alg: { name: "RSA-PSS", saltLength: verifyParams.saltLength },
      sig: signatureBytes,
      data: dataBytes,
    };
  }
  if (verifyParams.kind === "Ed25519" || verifyParams.kind === "Ed448") {
    return { alg: { name: verifyParams.kind }, sig: signatureBytes, data: dataBytes };
  }
  throw new Error("buildVerifyInput: unknown kind " + verifyParams.kind);
}

function describeAlg(verifyParams, spkiInfo) {
  if (verifyParams.kind === "ECDSA") return `ECDSA ${spkiInfo.curveName} + ${verifyParams.hashName}`;
  if (verifyParams.kind === "RSA") return `RSA PKCS#1 v1.5 + ${verifyParams.hashName}`;
  if (verifyParams.kind === "RSA-PSS") return `RSA-PSS + ${verifyParams.hashName} (salt ${verifyParams.saltLength}B)`;
  if (verifyParams.kind === "Ed25519") return "Ed25519";
  if (verifyParams.kind === "Ed448") return "Ed448";
  return verifyParams.kind;
}

// Map a known signatureAlgorithm OID to a friendly label even when the
// verifier doesn't fully support it. Used for the summary fallback so users
// see "RSA-PSS / Ed25519 / SHA-1-with-RSA" instead of a bare dotted OID.
function sigAlgFriendlyName(oid) {
  const map = {
    [OID.ecdsaWithSha256]: "ECDSA + SHA-256",
    [OID.ecdsaWithSha384]: "ECDSA + SHA-384",
    [OID.ecdsaWithSha512]: "ECDSA + SHA-512",
    [OID.sha256WithRsa]:   "RSA PKCS#1 v1.5 + SHA-256",
    [OID.sha384WithRsa]:   "RSA PKCS#1 v1.5 + SHA-384",
    [OID.sha512WithRsa]:   "RSA PKCS#1 v1.5 + SHA-512",
    [OID.sha1WithRsa]:     "RSA PKCS#1 v1.5 + SHA-1 (weak — rejected)",
    [OID.rsaEncryption]:   "RSA (digest from SignerInfo.digestAlgorithm)",
    [OID.rsassaPss]:       "RSA-PSS",
    [OID.ed25519]:         "Ed25519",
    [OID.ed448]:           "Ed448",
  };
  return map[oid] || "unknown algorithm";
}

// Verify a nested CMS SignedData's SignerInfo signature against its own
// embedded signer cert. Used by the TST check: the TimeStampToken is itself a
// CMS whose SignerInfo proves the TSA's intent over the TSTInfo. Returns
// {ok, detail, signerCert} so the caller can also do validity-window checks
// against TSTInfo.genTime.
async function verifyInnerCmsSignature(innerCms, innerCmsDer) {
  const inSi = innerCms.signerInfo;
  if (!inSi.signedAttrsAsHashed) {
    return { ok: false, detail: "inner CMS has no SignedAttributes" };
  }
  // Locate the signer cert by sid (same logic as outer verifySignature).
  let signerCert = null;
  if (inSi.sidIssuerDer && inSi.sidSerialHex) {
    signerCert = innerCms.certs.find((c) =>
      bytesEq(c.issuerDer, inSi.sidIssuerDer)
      && normalizeSerialHex(c.serialHex) === normalizeSerialHex(inSi.sidSerialHex)
    ) || null;
  } else if (inSi.sidSki) {
    signerCert = innerCms.certs.find((c) => c.ski && bytesEq(c.ski, inSi.sidSki)) || null;
  }
  if (!signerCert) {
    if (innerCms.certs.length === 1) signerCert = innerCms.certs[0];
    else return { ok: false, detail: "could not match inner SignerInfo sid to any embedded cert" };
  }
  let innerVerifyParams;
  try {
    innerVerifyParams = pickVerifyParams({
      sigAlgOid: inSi.sigAlgOid,
      digestOid: inSi.digestAlgOid,
      sigAlgParams: inSi.sigAlgParamsTlv ? { paramsBuf: inSi.sigAlgParamsBuf, paramsTlv: inSi.sigAlgParamsTlv } : null,
    });
  } catch (e) {
    return { ok: false, detail: "unsupported inner sigAlg: " + e.message };
  }
  const innerSpkiInfo = parseSpki(signerCert.spkiDer);
  const innerPubKey = await importPublicKey(signerCert.spkiDer, innerSpkiInfo, innerVerifyParams);
  const v = buildVerifyInput(inSi.signatureBytes, inSi.signedAttrsAsHashed, innerVerifyParams, innerSpkiInfo);
  let sigOk = await crypto.subtle.verify(v.alg, innerPubKey, v.sig, v.data);
  if (!sigOk && innerVerifyParams.kind === "RSA") {
    sigOk = await rsaPkcs1V15LooseVerify(signerCert.spkiDer, inSi.signatureBytes, inSi.signedAttrsAsHashed, innerVerifyParams.hashName);
  }
  if (!sigOk) return { ok: false, detail: `${describeAlg(innerVerifyParams, innerSpkiInfo)} signature did not verify against signer cert SPKI`, signerCert };
  // Cross-check the inner messageDigest attr against digest of eContent
  // (TSTInfo, embedded as OCTET STRING under [0] EXPLICIT in encapContentInfo).
  const mdAttr = findAttr(inSi.signedAttrs, OID.messageDigestAttr);
  if (mdAttr) {
    const eContentBytes = extractEContentOctets(innerCmsDer);
    if (eContentBytes) {
      const mdHashName = innerVerifyParams.hashName || (DIGEST_INFO[inSi.digestAlgOid] && DIGEST_INFO[inSi.digestAlgOid].name);
      if (mdHashName) {
        const expected = await digestBytes(mdHashName, eContentBytes);
        if (!bytesEq(mdAttr.valueBytes, expected)) {
          return { ok: false, detail: "inner messageDigest attr does not match digest of eContent", signerCert };
        }
      }
    }
  }
  return { ok: true, detail: `${describeAlg(innerVerifyParams, innerSpkiInfo)} verified against ${signerCert.subjectString}`, signerCert };
}

// Pull eContent OCTET STRING bytes (the actual encapsulated content) from a
// CMS ContentInfo DER. Used to compute messageDigest cross-checks for nested
// CMS instances (e.g. the TSTInfo inside a TimeStampToken).
function extractEContentOctets(cmsDer) {
  const ci = readTlv(cmsDer, 0);
  const ciKids = childrenOf(cmsDer, ci);
  if (!ciKids[1] || ciKids[1].tag !== 0xa0) return null;
  const sd = readTlv(cmsDer, ciKids[1].start);
  const sdKids = childrenOf(cmsDer, sd);
  // encapContentInfo at sdKids[2] = SEQUENCE { eContentType, [0] EXPLICIT eContent? }
  const encapKids = childrenOf(cmsDer, sdKids[2]);
  if (encapKids.length < 2 || encapKids[1].tag !== 0xa0) return null;
  // Inside [0] EXPLICIT is the OCTET STRING; its content is the actual eContent.
  const octet = readTlv(cmsDer, encapKids[1].start);
  if (octet.tag !== 0x04) return null;
  return cmsDer.slice(octet.start, octet.end);
}

// Strip a leading 0x00 sign byte (DER INTEGER encoding pads positive integers
// when the high bit of the magnitude is set). Used for normalizing serial
// numbers before comparing two encodings of the same number — issue #10.
function normalizeSerialHex(hexStr) {
  let s = String(hexStr).toLowerCase();
  while (s.length > 2 && s.startsWith("00")) s = s.slice(2);
  return s;
}

// Verify the cryptographic signature on `child` against `parent`'s public key.
// Returns {ok, detail}. Uses the same dispatch path as the SignerInfo verify —
// supports RSA PKCS#1 v1.5 and ECDSA P-256/P-384/P-521, SHA-256/384/512.
async function verifyCertSignature(child, parent) {
  let verifyParams;
  try {
    verifyParams = pickVerifyParams({
      sigAlgOid: child.certSigAlgOid,
      digestOid: null,
      sigAlgParams: child.certSigAlgParamsTlv ? { paramsBuf: child.certSigAlgParamsBuf, paramsTlv: child.certSigAlgParamsTlv } : null,
    });
  } catch (e) {
    return { ok: false, detail: `unsupported cert sigAlg ${child.certSigAlgOid}: ${e.message}` };
  }
  const spkiInfo = parseSpki(parent.spkiDer);
  const need = verifyParams.kind === "RSA-PSS" ? "RSA" : verifyParams.kind;
  if (spkiInfo.kind !== need) {
    return { ok: false, detail: `cert sigAlg ${verifyParams.kind} but issuer key ${spkiInfo.kind}` };
  }
  const pubKey = await importPublicKey(parent.spkiDer, spkiInfo, verifyParams);
  const v = buildVerifyInput(child.certSigBytes, child.tbsBytes, verifyParams, spkiInfo);
  let ok = await crypto.subtle.verify(v.alg, pubKey, v.sig, v.data);
  if (!ok && verifyParams.kind === "RSA") {
    // Same loose-DigestInfo fallback as the SignerInfo path — some legacy
    // CA cert signatures omit the NULL parameter in the DigestInfo too.
    ok = await rsaPkcs1V15LooseVerify(parent.spkiDer, child.certSigBytes, child.tbsBytes, verifyParams.hashName);
  }
  return { ok, detail: ok ? `${describeAlg(verifyParams, spkiInfo)} on TBSCertificate verifies against parent SPKI` : "cert signature did not verify against parent SPKI" };
}

function dnToString(buf, tlv) {
  // Distinguished Name = SEQUENCE OF RDN (SET OF AttributeTypeAndValue)
  const parts = [];
  for (const rdn of childrenOf(buf, tlv)) {
    for (const atv of childrenOf(buf, rdn)) {
      const atvKids = childrenOf(buf, atv);
      const oid = decodeOid(buf, atvKids[0].start, atvKids[0].end);
      const val = atvKids[1];
      const text = new TextDecoder().decode(buf.slice(val.start, val.end));
      const label = oid === OID.commonName ? "CN" : oid === OID.organization ? "O" : oid === OID.country ? "C" : oid;
      parts.push(`${label}=${text}`);
    }
  }
  return parts.join(", ");
}

function extractRdnValue(buf, tlv, wantedOid) {
  for (const rdn of childrenOf(buf, tlv)) {
    for (const atv of childrenOf(buf, rdn)) {
      const atvKids = childrenOf(buf, atv);
      const oid = decodeOid(buf, atvKids[0].start, atvKids[0].end);
      if (oid === wantedOid) {
        return new TextDecoder().decode(buf.slice(atvKids[1].start, atvKids[1].end));
      }
    }
  }
  return null;
}

// -----------------------------------------------------------------------------
// CMS SignedData parser.
// -----------------------------------------------------------------------------

function parseCms(cmsDer) {
  const contentInfo = readTlv(cmsDer, 0);
  if (contentInfo.tag !== 0x30) throw new Error("ContentInfo not SEQUENCE");
  const ciKids = childrenOf(cmsDer, contentInfo);
  const ctOid = decodeOid(cmsDer, ciKids[0].start, ciKids[0].end);
  if (ctOid !== OID.cmsSignedData) throw new Error("Not signed-data (got OID " + ctOid + ")");
  if (ciKids[1].tag !== 0xa0) throw new Error("expected [0] EXPLICIT content");
  const sdTlv = readTlv(cmsDer, ciKids[1].start);
  const sdKids = childrenOf(cmsDer, sdTlv);

  // SignedData: version, digestAlgorithms (SET), encapContentInfo, [0] certs?, [1] crls?, signerInfos (SET)
  let idx = 0;
  const version = Number(decodeInteger(cmsDer, sdKids[idx].start, sdKids[idx].end));
  idx += 1;
  // digestAlgorithms
  idx += 1;
  // encapContentInfo SEQUENCE { eContentType OID, [0] EXPLICIT eContent? }
  const encapKids = childrenOf(cmsDer, sdKids[idx]);
  const encapContentTypeOid = decodeOid(cmsDer, encapKids[0].start, encapKids[0].end);
  idx += 1;
  // Optional [0] IMPLICIT certs
  const certs = [];
  if (sdKids[idx].tag === 0xa0) {
    let cur = sdKids[idx].start;
    while (cur < sdKids[idx].end) {
      const certTlv = readTlv(cmsDer, cur);
      const certDer = cmsDer.slice(cur, certTlv.end);
      certs.push(parseCertificate(certDer));
      cur = certTlv.end;
    }
    idx += 1;
  }
  // Optional [1] IMPLICIT crls (skip)
  if (sdKids[idx].tag === 0xa1) idx += 1;
  // signerInfos SET
  const signerInfosTlv = sdKids[idx];
  if (signerInfosTlv.tag !== 0x31) throw new Error("expected signerInfos SET");
  const signerInfoTlv = readTlv(cmsDer, signerInfosTlv.start);
  const signerInfo = parseSignerInfo(cmsDer, signerInfoTlv);

  return { version, certs, signerInfo, encapContentTypeOid };
}

// ESSCertIDv2 ::= SEQUENCE {
//   hashAlgorithm AlgorithmIdentifier DEFAULT id-sha256,
//   certHash OCTET STRING,
//   issuerSerial IssuerSerial OPTIONAL }
// SigningCertificateV2 ::= SEQUENCE {
//   certs SEQUENCE OF ESSCertIDv2,
//   policies SEQUENCE OF PolicyInformation OPTIONAL }
// The OUTER attribute value here is the SigningCertificateV2 SEQUENCE; we
// pull the first ESSCertIDv2's certHash bytes for comparison against
// SHA-256(leafDer).
function extractEssCertIdV2Hash(buf, scv2ValueTlv) {
  if (scv2ValueTlv.tag !== 0x30) return null;
  const scv2Kids = childrenOf(buf, scv2ValueTlv);
  if (!scv2Kids[0] || scv2Kids[0].tag !== 0x30) return null;
  const certsSeqKids = childrenOf(buf, scv2Kids[0]);
  if (!certsSeqKids[0]) return null;
  const essKids = childrenOf(buf, certsSeqKids[0]);
  if (!essKids.length) return null;
  // First child is either hashAlgorithm SEQUENCE (when present) or OCTET STRING
  // certHash (when hashAlgorithm defaulted to id-sha256 and is omitted).
  for (const kid of essKids) {
    if (kid.tag === 0x04) return buf.slice(kid.start, kid.end);
  }
  return null;
}

function parseSignerInfo(buf, siTlv) {
  const kids = childrenOf(buf, siTlv);
  let idx = 0;
  const siVersion = Number(decodeInteger(buf, kids[idx].start, kids[idx].end));
  idx += 1;
  // sid: either IssuerAndSerialNumber SEQUENCE (v1, tag 0x30) or
  //      [0] IMPLICIT SubjectKeyIdentifier OCTET STRING (v3, tag 0x80).
  const sidTlv = kids[idx];
  let sidIssuerDer = null;
  let sidSerialHex = null;
  let sidSki = null;
  if (sidTlv.tag === 0x30) {
    const sidKids = childrenOf(buf, sidTlv);
    sidIssuerDer = buf.slice(sidKids[0].start - sidKids[0].headerLen, sidKids[0].end);
    sidSerialHex = toHex(buf.slice(sidKids[1].start, sidKids[1].end));
  } else if (sidTlv.tag === 0x80) {
    // [0] IMPLICIT OCTET STRING — content is the SKI bytes directly.
    sidSki = buf.slice(sidTlv.start, sidTlv.end);
  } else {
    throw new Error("unsupported SignerInfo sid tag 0x" + sidTlv.tag.toString(16));
  }
  idx += 1;
  // digestAlgorithm AlgorithmIdentifier — extract OID, not just skip.
  const digAlgTlv = kids[idx];
  const digAlgKids = childrenOf(buf, digAlgTlv);
  const digestAlgOid = decodeOid(buf, digAlgKids[0].start, digAlgKids[0].end);
  idx += 1;
  // signedAttrs [0] IMPLICIT  (optional but always present in our flow)
  let signedAttrsAsHashed = null;
  let signedAttrs = null;
  if (kids[idx].tag === 0xa0) {
    const ctTlv = kids[idx];
    const lengthOctets = buf.slice(ctTlv.start - ctTlv.headerLen + 1, ctTlv.start);
    const content = buf.slice(ctTlv.start, ctTlv.end);
    signedAttrsAsHashed = new Uint8Array(1 + lengthOctets.length + content.length);
    signedAttrsAsHashed[0] = 0x31;
    signedAttrsAsHashed.set(lengthOctets, 1);
    signedAttrsAsHashed.set(content, 1 + lengthOctets.length);
    signedAttrs = parseAttributeSet(buf, ctTlv);
    idx += 1;
  }
  // signatureAlgorithm AlgorithmIdentifier { OID, parameters ANY DEFINED BY OID OPTIONAL }
  // For RSA-PSS the parameters carry RSASSA-PSS-params (hash, MGF1, saltLength).
  // For ECDSA / Ed25519 / RSA PKCS#1 v1.5 the parameters are absent or NULL.
  const sigAlgTlv = kids[idx];
  const sigAlgKids = childrenOf(buf, sigAlgTlv);
  const sigAlgOid = decodeOid(buf, sigAlgKids[0].start, sigAlgKids[0].end);
  const sigAlgParamsTlv = sigAlgKids[1] || null;
  const sigAlgParamsBuf = sigAlgParamsTlv ? buf : null;
  idx += 1;
  // signature OCTET STRING
  const sigTlv = kids[idx];
  const signatureBytes = buf.slice(sigTlv.start, sigTlv.end);
  idx += 1;
  // unsignedAttrs [1] IMPLICIT (optional)
  let unsignedAttrs = null;
  if (idx < kids.length && kids[idx].tag === 0xa1) {
    unsignedAttrs = parseAttributeSet(buf, kids[idx]);
  }

  return {
    version: siVersion,
    sidIssuerDer,
    sidSerialHex,
    sidSki,
    digestAlgOid,
    signedAttrsAsHashed,
    signedAttrs,
    sigAlgOid,
    sigAlgParamsTlv,
    sigAlgParamsBuf,
    signatureBytes,
    unsignedAttrs,
  };
}

// Parse RSASSA-PSS-params from the SignerInfo sigAlg parameters bytes.
// RSASSA-PSS-params ::= SEQUENCE {
//   hashAlgorithm           [0] HashAlgorithm    DEFAULT sha1Identifier,
//   maskGenAlgorithm        [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
//   saltLength              [2] INTEGER          DEFAULT 20,
//   trailerField            [3] INTEGER          DEFAULT 1 }
// Per RFC 4055 §3.1 / RFC 5754: for a valid PAdES PSS signature, the
// maskGenAlgorithm MUST be MGF1 and its inner hash MUST equal the
// messageHashAlgorithm. The trailerField MUST be 1 (no other value is
// defined by the spec — WebCrypto silently assumes 1 and ignores the param).
// Defaults are unsafe (SHA-1) so we REQUIRE the hash to be explicitly
// specified and reject SHA-1.
function parseRsaPssParams(buf, paramsTlv) {
  if (!paramsTlv || paramsTlv.tag !== 0x30) {
    throw new Error("RSA-PSS without parameters not supported (SHA-1 default is too weak to accept)");
  }
  const kids = childrenOf(buf, paramsTlv);
  let hashOid = null;
  let mgfHashOid = null;
  let saltLength = 20;
  let trailerField = 1;
  for (const kid of kids) {
    if (kid.tag === 0xa0) {
      // [0] EXPLICIT HashAlgorithm — AlgorithmIdentifier { hash OID, NULL }
      const hashAlgTlv = readTlv(buf, kid.start);
      const hashAlgKids = childrenOf(buf, hashAlgTlv);
      hashOid = decodeOid(buf, hashAlgKids[0].start, hashAlgKids[0].end);
    } else if (kid.tag === 0xa1) {
      // [1] EXPLICIT MaskGenAlgorithm — AlgorithmIdentifier { mgf1 OID, hashAlg AlgorithmIdentifier }
      const mgfTlv = readTlv(buf, kid.start);
      const mgfKids = childrenOf(buf, mgfTlv);
      const mgfOid = decodeOid(buf, mgfKids[0].start, mgfKids[0].end);
      if (mgfOid !== OID.mgf1) {
        throw new Error(`RSA-PSS maskGenAlgorithm must be MGF1 (${OID.mgf1}); got ${mgfOid}`);
      }
      // The MGF1 inner hash is itself an AlgorithmIdentifier — read its OID.
      if (mgfKids[1] && mgfKids[1].tag === 0x30) {
        const innerHashKids = childrenOf(buf, mgfKids[1]);
        mgfHashOid = decodeOid(buf, innerHashKids[0].start, innerHashKids[0].end);
      }
    } else if (kid.tag === 0xa2) {
      // [2] EXPLICIT saltLength INTEGER
      const intTlv = readTlv(buf, kid.start);
      saltLength = Number(decodeInteger(buf, intTlv.start, intTlv.end));
    } else if (kid.tag === 0xa3) {
      // [3] EXPLICIT trailerField INTEGER
      const intTlv = readTlv(buf, kid.start);
      trailerField = Number(decodeInteger(buf, intTlv.start, intTlv.end));
    }
  }
  if (!hashOid) {
    throw new Error("RSA-PSS hashAlgorithm parameter required (default SHA-1 rejected)");
  }
  const hashInfo = DIGEST_INFO[hashOid];
  if (!hashInfo) throw new Error("RSA-PSS uses unsupported hash OID " + hashOid);
  if (mgfHashOid && mgfHashOid !== hashOid) {
    throw new Error(`RSA-PSS MGF1 inner hash (${mgfHashOid}) must equal messageHash (${hashOid}) — RFC 4055 §3.1`);
  }
  if (trailerField !== 1) {
    throw new Error(`RSA-PSS trailerField must be 1; got ${trailerField}`);
  }
  return { hashName: hashInfo.name, hashOid, saltLength };
}

function parseAttributeSet(buf, setTlv) {
  // setTlv is either tag 0x31 (SET) or 0xa0/0xa1 (context-implicit SET).
  // Iterate Attribute = SEQUENCE { OID, SET OF AttributeValue }
  const out = [];
  let cur = setTlv.start;
  while (cur < setTlv.end) {
    const attrTlv = readTlv(buf, cur);
    const attrKids = childrenOf(buf, attrTlv);
    const oid = decodeOid(buf, attrKids[0].start, attrKids[0].end);
    const valuesSet = attrKids[1];
    const valueTlvs = childrenOf(buf, valuesSet);
    out.push({
      oid,
      valueTlv: valueTlvs[0],
      valueBytes: valueTlvs[0] ? buf.slice(valueTlvs[0].start, valueTlvs[0].end) : null,
      valueRawWithHeader: valueTlvs[0] ? buf.slice(valueTlvs[0].start - valueTlvs[0].headerLen, valueTlvs[0].end) : null,
      buf,
    });
    // BER indefinite-length Attribute SEQUENCEs (`30 80 … 00 00`) end at the
    // EOC marker — advance past it (eocEnd), not onto it, or the next
    // iteration reads a phantom 00 00 TLV and shifts every later attribute.
    cur = attrTlv.indefinite ? attrTlv.eocEnd : attrTlv.end;
  }
  return out;
}

function findAttr(attrs, oid) {
  if (!attrs) return null;
  return attrs.find((a) => a.oid === oid) || null;
}

// -----------------------------------------------------------------------------
// ECDSA signature: DER ECDSA-Sig-Value (SEQUENCE { r INTEGER, s INTEGER }) →
// IEEE P1363 raw r||s (64 bytes for P-256), the form WebCrypto expects.
// -----------------------------------------------------------------------------

function ecdsaDerToP1363(derSig, curveBytes = 32) {
  const seq = readTlv(derSig, 0);
  if (seq.tag !== 0x30) throw new Error("ECDSA sig not SEQUENCE");
  const kids = childrenOf(derSig, seq);
  // Strict shape: ECDSA-Sig-Value is exactly two INTEGERs, nothing else
  // (issue #22 from /cr). Reject trailing garbage.
  if (kids.length !== 2) throw new Error("ECDSA sig SEQUENCE must have exactly 2 children, got " + kids.length);
  if (kids[0].tag !== 0x02 || kids[1].tag !== 0x02) throw new Error("ECDSA sig children must be INTEGERs");
  const r = unsignedIntegerBytes(derSig, kids[0]);
  const s = unsignedIntegerBytes(derSig, kids[1]);
  const out = new Uint8Array(curveBytes * 2);
  out.set(leftPad(r, curveBytes), 0);
  out.set(leftPad(s, curveBytes), curveBytes);
  return out;
}

function unsignedIntegerBytes(buf, intTlv) {
  let bytes = buf.slice(intTlv.start, intTlv.end);
  while (bytes.length > 1 && bytes[0] === 0x00) bytes = bytes.slice(1);
  return bytes;
}

function leftPad(bytes, len) {
  if (bytes.length === len) return bytes;
  if (bytes.length > len) throw new Error("integer too large for curve");
  const out = new Uint8Array(len);
  out.set(bytes, len - bytes.length);
  return out;
}

// -----------------------------------------------------------------------------
// Algorithm-dispatch helpers — universal RSA + ECDSA support.
// -----------------------------------------------------------------------------

// Inspect a SubjectPublicKeyInfo DER and return {kind, curve?, name?}.
// SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
// AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY DEFINED BY algorithm OPTIONAL }
//   - RSA: parameters = NULL
//   - EC: parameters = namedCurve OID (P-256 / P-384 / P-521)
export function parseSpki(spkiDer) {
  const top = readTlv(spkiDer, 0);
  if (top.tag !== 0x30) throw new Error("SPKI not SEQUENCE");
  const kids = childrenOf(spkiDer, top);
  const algIdKids = childrenOf(spkiDer, kids[0]);
  const algOid = decodeOid(spkiDer, algIdKids[0].start, algIdKids[0].end);
  if (algOid === OID.rsaEncryption) {
    return { kind: "RSA" };
  }
  if (algOid === OID.ecPublicKey) {
    if (algIdKids.length < 2) throw new Error("ecPublicKey SPKI missing curve parameters");
    const curveTlv = algIdKids[1];
    if (curveTlv.tag !== 0x06) throw new Error("ecPublicKey SPKI parameter is not OID (PKCS#1 explicit curves not supported)");
    const curveOid = decodeOid(spkiDer, curveTlv.start, curveTlv.end);
    const info = CURVE_INFO[curveOid];
    if (!info) throw new Error("unsupported EC named curve OID " + curveOid);
    return { kind: "ECDSA", curveOid, curveName: info.name, scalarBytes: info.scalarBytes };
  }
  if (algOid === OID.ed25519) return { kind: "Ed25519" };
  if (algOid === OID.ed448)   return { kind: "Ed448" };
  throw new Error("unsupported SPKI algorithm OID " + algOid);
}

// Compose WebCrypto verify params from {sigAlgOid, digestOid, sigAlgParams}.
// Throws if the combination is unsupported / inconsistent. For RSA-PSS the
// caller must pass sigAlgParams = {paramsBuf, paramsTlv} so we can decode the
// PSS hash + saltLength from the AlgorithmIdentifier parameters. For Ed25519
// and Ed448 there is no digest dispatch — the algorithm encodes the message
// itself.
export function pickVerifyParams({ sigAlgOid, digestOid, sigAlgParams }) {
  const sig = SIGALG_INFO[sigAlgOid];
  if (!sig) throw new Error("unsupported SignerInfo signatureAlgorithm OID " + sigAlgOid);
  // Ed25519 / Ed448 — algorithm is digest-less.
  if (sig.kind === "Ed25519" || sig.kind === "Ed448") {
    return { kind: sig.kind, hashName: null, digestOid: null, digestSize: null };
  }
  // RSA-PSS — read params from the AlgorithmIdentifier.
  if (sig.kind === "RSA-PSS") {
    if (!sigAlgParams || !sigAlgParams.paramsTlv) {
      throw new Error("RSA-PSS requires AlgorithmIdentifier parameters");
    }
    const pss = parseRsaPssParams(sigAlgParams.paramsBuf, sigAlgParams.paramsTlv);
    return { kind: "RSA-PSS", hashName: pss.hashName, digestOid: pss.hashOid, digestSize: DIGEST_INFO[pss.hashOid].size, saltLength: pss.saltLength };
  }
  // RSA PKCS#1 v1.5 / ECDSA — digest from the sigAlg OID or from SignerInfo.digestAlgorithm.
  const effectiveDigestOid = sig.implicitDigestOid || digestOid;
  const dig = DIGEST_INFO[effectiveDigestOid];
  if (!dig) throw new Error("unsupported digest OID " + effectiveDigestOid);
  if (sig.implicitDigestOid && digestOid && sig.implicitDigestOid !== digestOid) {
    throw new Error("digestAlgorithm mismatch between sigAlg and SignerInfo.digestAlgorithm");
  }
  return { kind: sig.kind, hashName: dig.name, digestOid: effectiveDigestOid, digestSize: dig.size };
}

// Import a SPKI cert public key under the curve / algorithm WebCrypto needs.
// `verifyParams` is what pickVerifyParams returned.
export async function importPublicKey(spkiDer, spkiInfo, verifyParams) {
  if (verifyParams.kind === "ECDSA") {
    if (spkiInfo.kind !== "ECDSA") throw new Error("ECDSA signature but non-EC public key in leaf cert");
    return crypto.subtle.importKey("spki", spkiDer, { name: "ECDSA", namedCurve: spkiInfo.curveName }, false, ["verify"]);
  }
  if (verifyParams.kind === "RSA") {
    if (spkiInfo.kind !== "RSA") throw new Error("RSA signature but non-RSA public key in leaf cert");
    return crypto.subtle.importKey("spki", spkiDer, { name: "RSASSA-PKCS1-v1_5", hash: verifyParams.hashName }, false, ["verify"]);
  }
  if (verifyParams.kind === "RSA-PSS") {
    if (spkiInfo.kind !== "RSA") throw new Error("RSA-PSS signature but non-RSA public key in leaf cert");
    return crypto.subtle.importKey("spki", spkiDer, { name: "RSA-PSS", hash: verifyParams.hashName }, false, ["verify"]);
  }
  if (verifyParams.kind === "Ed25519" || verifyParams.kind === "Ed448") {
    if (spkiInfo.kind !== verifyParams.kind) throw new Error(`${verifyParams.kind} signature but SPKI is ${spkiInfo.kind}`);
    return crypto.subtle.importKey("spki", spkiDer, { name: verifyParams.kind }, false, ["verify"]);
  }
  throw new Error("unknown signature kind " + verifyParams.kind);
}

async function digestBytes(hashName, bytes) {
  return new Uint8Array(await crypto.subtle.digest(hashName, bytes));
}

// ----- RSA PKCS#1 v1.5 LOOSE verify ------------------------------------------
// WebCrypto (and OpenSSL strict mode) reject EMSA-PKCS1-v1_5 encoded signatures
// whose DigestInfo's AlgorithmIdentifier OMITS the NULL parameter — even
// though RFC 4055 says NULL is the DEFAULT and may be absent. Several
// production signers (notably the Polish eIDAS QTSP EuroCert / "Profil
// Zaufany" gov.pl seals, some older BouncyCastle versions) emit the no-NULL
// form. Adobe Reader accepts both; we want to as well.
//
// Strategy: when WebCrypto's strict verify returns false on an RSA PKCS#1 v1.5
// signature, do a manual raw-RSA decrypt with the public key, validate the
// PKCS#1 v1.5 padding shape, and require the recovered DigestInfo to be
// byte-exactly one of the two legitimate EMSA-PKCS1-v1_5 encodings (with or
// without the NULL AlgorithmIdentifier parameter) followed by the expected
// hash. The exact-match — NOT a "check only the trailing hash" parser —
// leaves no unchecked region, so it accepts every valid signature while still
// rejecting Bleichenbacher low-exponent forgeries.
async function rsaPkcs1V15LooseVerify(spkiDer, signatureBytes, dataBytes, hashName) {
  // Export modulus + exponent. extractable=true is required for jwk export.
  const key = await crypto.subtle.importKey("spki", spkiDer, { name: "RSASSA-PKCS1-v1_5", hash: hashName }, true, ["verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  const n = base64UrlToBigInt(jwk.n);
  const e = base64UrlToBigInt(jwk.e);
  const sigInt = bytesToBigInt(signatureBytes);
  if (sigInt >= n) return false; // signature MUST be less than modulus
  const m = modPow(sigInt, e, n);
  const recovered = bigIntToBytes(m, signatureBytes.length);
  // PKCS#1 v1.5 padding: 0x00 0x01 0xFF...0xFF (≥8) 0x00 <DigestInfo>
  if (recovered[0] !== 0x00 || recovered[1] !== 0x01) return false;
  let i = 2;
  while (i < recovered.length && recovered[i] === 0xff) i += 1;
  if (i < 10) return false; // need at least 8 0xFF bytes per RFC 8017
  if (recovered[i] !== 0x00) return false;
  i += 1;
  const di = recovered.slice(i);
  // The recovered DigestInfo MUST be byte-exactly one of the two legitimate
  // EMSA-PKCS1-v1_5 encodings (prefix WITH or WITHOUT the NULL parameter)
  // immediately followed by the digest — nothing before, nothing after. This
  // fixed-prefix exact-match (the approach Go's crypto/rsa and OpenSSL take)
  // leaves NO unchecked region, so it cannot be defeated by a Bleichenbacher
  // low-public-exponent forgery, and it pins the digest-algorithm OID so a
  // forger cannot substitute a different algorithm's DigestInfo.
  const prefixes = digestInfoPrefixes(hashName);
  if (!prefixes) return false; // unknown hash — refuse rather than guess
  const expectedDigest = new Uint8Array(await crypto.subtle.digest(hashName, dataBytes));
  for (const prefix of prefixes) {
    if (di.length !== prefix.length + expectedDigest.length) continue;
    let ok = true;
    for (let k = 0; k < prefix.length && ok; k += 1) {
      if (di[k] !== prefix[k]) ok = false;
    }
    for (let k = 0; k < expectedDigest.length && ok; k += 1) {
      if (di[prefix.length + k] !== expectedDigest[k]) ok = false;
    }
    if (ok) return true;
  }
  return false;
}

// EMSA-PKCS1-v1_5 DigestInfo prefixes — the fixed DER bytes that precede the
// raw hash. Two accepted forms per algorithm: WITH the NULL AlgorithmIdentifier
// parameter (RFC 5754 — what WebCrypto / OpenSSL emit) and WITHOUT it (RFC 4055
// DEFAULT-absent — the Polish gov.pl QTSP form). Any other prefix is rejected.
function digestInfoPrefixes(hashName) {
  switch (hashName) {
    case "SHA-1": return [
      Uint8Array.from([0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14]),
      Uint8Array.from([0x30,0x1f,0x30,0x07,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x04,0x14]),
    ];
    case "SHA-256": return [
      Uint8Array.from([0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]),
      Uint8Array.from([0x30,0x2f,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x04,0x20]),
    ];
    case "SHA-384": return [
      Uint8Array.from([0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30]),
      Uint8Array.from([0x30,0x3f,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x04,0x30]),
    ];
    case "SHA-512": return [
      Uint8Array.from([0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40]),
      Uint8Array.from([0x30,0x4f,0x30,0x0b,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x04,0x40]),
    ];
    default: return null;
  }
}

function base64UrlToBigInt(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - b64url.length % 4) % 4);
  const bin = atob(b64);
  let n = 0n;
  for (let i = 0; i < bin.length; i += 1) n = (n << 8n) | BigInt(bin.charCodeAt(i));
  return n;
}

function bytesToBigInt(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigIntToBytes(n, len) {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

// Back-compat alias used by the TST + OTS paths that always hash SHA-256.
async function sha256(bytes) {
  return digestBytes("SHA-256", bytes);
}

// -----------------------------------------------------------------------------
// PDF /Sig + /ByteRange extraction.
// -----------------------------------------------------------------------------

// Hard upper bounds for parsing. The Worker writes ~200 KB sealed PDFs; even
// long multi-signer documents rarely exceed 100 MB. Capping protects against
// pathological inputs that would otherwise crash a low-memory tab.
// Issue #35 from /cr: WebCrypto's `crypto.subtle.digest` requires a single
// contiguous buffer (no streaming digest API), so we ALSO allocate a
// `Uint8Array(len1 + len2)` copy of the signed region per signature. The 200
// MB cap matches the PDF-bytes cap so multi-sig PDFs near the limit get an
// upper-bound allocation of ~200 MB per /Sig — acceptable on desktop, fatal
// on memory-constrained mobile. The PDF cap is the gating constraint.
const MAX_PDF_BYTES = 200 * 1024 * 1024;             // 200 MB
const MAX_SIGNED_REGION_BYTES = 200 * 1024 * 1024;   // matches PDF cap
const MAX_SIG_DICT_SCAN = 65536;                     // 64 KB window for sig-dict display fields

function extractSignatures(pdfBytes) {
  if (pdfBytes.length > MAX_PDF_BYTES) {
    throw new Error(`PDF too large (${pdfBytes.length} bytes; cap ${MAX_PDF_BYTES})`);
  }
  // Treat PDF as latin-1 text to scan for /ByteRange — PDF syntax is ASCII so
  // binary content streams won't match by chance. A signature must cover the
  // PDF from offset 0 through the signed revision, except for the /Contents
  // gap; otherwise leading bytes can affect viewer rendering while remaining
  // outside the CMS messageDigest. For each /ByteRange we look for the nearest /Contents
  // in BOTH directions (issue #14) within the same enclosing dict, so signers
  // who emit /Contents BEFORE /ByteRange (allowed — PDF dicts are unordered)
  // verify cleanly.
  const text = new TextDecoder("latin1").decode(pdfBytes);
  const found = [];
  const brRe = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;
  let m;
  while ((m = brRe.exec(text)) !== null) {
    const a0 = parseInt(m[1], 10);
    const len1 = parseInt(m[2], 10);
    const off2 = parseInt(m[3], 10);
    const len2 = parseInt(m[4], 10);
    if (a0 < 0 || len1 < 0 || off2 < a0 + len1 || len2 < 0) continue;
    // Skip an out-of-cap /ByteRange like any other invalid match (continue, not
    // throw): attacker-controlled PDF text can carry a fake oversized /ByteRange
    // literal anywhere — throwing here would abort extraction of the real later
    // signature and, on the signing hot path (selfVerifySealedPdf), grief the
    // whole ceremony. A real signature is still gated by the /Contents check below.
    if (len1 + len2 > MAX_SIGNED_REGION_BYTES) continue;
    if (a0 + len1 > pdfBytes.length || off2 + len2 > pdfBytes.length) continue;
    const signedEnd = off2 + len2;
    // Locate the nearest /Contents <hex> within ±MAX_SIG_DICT_SCAN of this
    // /ByteRange. Tries forward first (most common), then backward.
    const span = findContentsSpan(text, m.index, MAX_SIG_DICT_SCAN);
    if (!span) continue;
    if (span.ltIdx !== a0 + len1 || span.gtIdx + 1 !== off2) continue;
    let cmsDer;
    try {
      cmsDer = trimTrailingZeros(hexToBytes(text.slice(span.hexStart, span.hexEnd)));
    } catch {
      continue;
    }
    // Compute signed region = [a0..a0+len1) + [off2..off2+len2).
    const signed = new Uint8Array(len1 + len2);
    signed.set(pdfBytes.slice(a0, a0 + len1), 0);
    signed.set(pdfBytes.slice(off2, off2 + len2), len1);
    found.push({
      byteRange: { a: a0, len1, off2, len2 },
      pdfLength: pdfBytes.length,
      byteRangeEnd: signedEnd,
      hasUnsignedAppend: false,
      cmsDer,
      signedRegion: signed,
      bracketStart: span.ltIdx,
      bracketEnd: span.gtIdx,
      sigDictText: extractSigDictText(text, m.index),
    });
  }
  for (const sig of found) {
    const hasLaterSignedRevision = found.some((other) => other.byteRangeEnd > sig.byteRangeEnd);
    // Trailing bytes after the last signed revision are an unsigned append —
    // UNLESS they are a benign PAdES-B-LT /DSS (LTV) incremental update. FreeSign's
    // own signing flow appends a /DSS revision (leaf+CA certs, CRLs, re-emitted
    // Catalog) AFTER the signature, because the leaf cert is minted during /seal
    // once the ByteRange is already frozen. That is legitimate and must not be
    // reported as a tampering append (it would otherwise abort selfVerifySealedPdf
    // and break the ceremony). isBenignDssAppend() recognises a DSS/LTV-only tail
    // and still rejects any tail that adds content or a new (unsigned) signature.
    const trailingAppend = sig.byteRangeEnd !== pdfBytes.length && !hasLaterSignedRevision;
    sig.hasUnsignedAppend = trailingAppend
      && !isBenignDssAppend(text, sig.byteRangeEnd);
  }
  return found;
}

// True iff the bytes after `fromOffset` are ONLY a PAdES-B-LT /DSS (LTV)
// incremental update — a /DSS dictionary plus cert/CRL streams and a re-emitted
// Catalog, with no new signature and no new document content. Used so the
// verifier (and the in-ceremony self-check) accept FreeSign's own DSS revision
// while still rejecting any other unsigned append. Conservative: the tail MUST
// declare a /DSS dict and MUST NOT introduce a new signature (/ByteRange,
// /Type /Sig) or new renderable content (/Type /Page, /Type /XObject, /Annots).
function isBenignDssAppend(text, fromOffset) {
  const tail = text.slice(fromOffset);
  // Must actually carry DSS/LTV material — otherwise it is not an LTV revision.
  if (!/\/DSS\b/.test(tail) && !/\/Type\s*\/DSS\b/.test(tail)) return false;
  // A new signature in the tail is never benign here: a real later signature is
  // already represented by hasLaterSignedRevision, so any /ByteRange or /Type /Sig
  // appearing after the signed region without its own covering revision is an
  // unsigned-append attempt to smuggle a signature.
  if (/\/ByteRange\b/.test(tail)) return false;
  if (/\/Type\s*\/Sig\b/.test(tail)) return false;
  // No new renderable content / structure may be introduced after the signature.
  if (/\/Type\s*\/Page\b/.test(tail)) return false;
  if (/\/Type\s*\/XObject\b/.test(tail)) return false;
  if (/\/Annots\b/.test(tail)) return false;
  return true;
}

// Find the /Contents <hex> span nearest to byteRangeIdx — search forward
// first (common case), then backward. Returns {ltIdx, gtIdx, hexStart, hexEnd}
// or null. Skips PDF literal strings (...) so /Contents (something with <
// inside) doesn't fool the locator.
function findContentsSpan(text, byteRangeIdx, window) {
  // Forward search.
  let fwd = text.indexOf("/Contents", byteRangeIdx);
  if (fwd !== -1 && fwd - byteRangeIdx > window) fwd = -1;
  if (fwd !== -1) {
    const span = readContentsHex(text, fwd);
    if (span) return span;
  }
  // Backward search — find LAST /Contents before byteRangeIdx.
  const earliest = Math.max(0, byteRangeIdx - window);
  let bwd = -1;
  let scan = earliest;
  while (true) {
    const idx = text.indexOf("/Contents", scan);
    if (idx === -1 || idx >= byteRangeIdx) break;
    bwd = idx;
    scan = idx + 1;
  }
  if (bwd !== -1) {
    const span = readContentsHex(text, bwd);
    if (span) return span;
  }
  return null;
}

function readContentsHex(text, contentsIdx) {
  // After "/Contents", PDF allows either <hex> or (literal) form. For PAdES
  // signatures the binary CMS is always <hex>. Skip whitespace, look for `<`.
  let i = contentsIdx + "/Contents".length;
  while (i < text.length && /\s/.test(text[i])) i += 1;
  if (text[i] !== "<") return null;
  // Reject the <<...>> dict open token (two angle brackets in a row).
  if (text[i + 1] === "<") return null;
  const ltIdx = i;
  const gtIdx = text.indexOf(">", ltIdx + 1);
  if (gtIdx === -1) return null;
  return { ltIdx, gtIdx, hexStart: ltIdx + 1, hexEnd: gtIdx };
}

function extractSigDictText(text, byteRangeIdx) {
  // Walk backward looking for the OUTER signature dict's `<<`, tracking depth
  // so nested sub-dicts (`/Prop_Build <<...>>`, `/Reference <<...>>`) before
  // /ByteRange don't confuse us (issue #16 from /cr). Then walk forward to
  // find the matching `>>` at the same depth (issue #28 — larger window).
  // Display-only — never trusted for verification.
  // Issue #28: 32 KB was too small for real-world /Sig dicts with large
  // /Reference arrays or signed-attribute metadata. Raise to 128 KB back /
  // 256 KB forward — still bounded so we don't scan the whole 200 MB cap
  // for what's actually a display-only nice-to-have.
  const BACK = 131072;
  const FWD = 262144;
  let depth = 0;
  let openIdx = -1;
  for (let i = byteRangeIdx; i >= 1 && i > byteRangeIdx - BACK; i -= 1) {
    if (text[i - 1] === ">" && text[i] === ">") depth += 1;
    else if (text[i - 1] === "<" && text[i] === "<") {
      if (depth === 0) { openIdx = i - 1; break; }
      depth -= 1;
    }
  }
  if (openIdx < 0) return "";
  let fwdDepth = 0;
  let closeIdx = -1;
  for (let i = byteRangeIdx; i < text.length - 1 && i < byteRangeIdx + FWD; i += 1) {
    if (text[i] === "<" && text[i + 1] === "<") { fwdDepth += 1; i += 1; continue; }
    if (text[i] === ">" && text[i + 1] === ">") {
      if (fwdDepth === 0) { closeIdx = i + 2; break; }
      fwdDepth -= 1;
      i += 1;
    }
  }
  if (closeIdx < 0) return "";
  return text.slice(openIdx, closeIdx);
}

function parseSigDictField(dictText, key) {
  // Parse a /Key (literal string) entry. PDF literal strings allow balanced
  // parens, octal escapes (\nnn), and line continuations (\\<newline>).
  // Issue #32 from /cr: previous regex only handled \), \(, \\. Now handles
  // octal escapes and balanced parens.
  const keyMarker = "/" + key;
  let i = dictText.indexOf(keyMarker);
  while (i !== -1) {
    let j = i + keyMarker.length;
    while (j < dictText.length && /\s/.test(dictText[j])) j += 1;
    if (dictText[j] !== "(") { i = dictText.indexOf(keyMarker, i + 1); continue; }
    // Walk through balanced parens, respecting escapes.
    let depth = 1;
    let out = "";
    j += 1;
    while (j < dictText.length && depth > 0) {
      const ch = dictText[j];
      if (ch === "\\") {
        const next = dictText[j + 1];
        if (next === "n") { out += "\n"; j += 2; }
        else if (next === "r") { out += "\r"; j += 2; }
        else if (next === "t") { out += "\t"; j += 2; }
        else if (next === "b") { out += "\b"; j += 2; }
        else if (next === "f") { out += "\f"; j += 2; }
        else if (next === "(") { out += "("; j += 2; }
        else if (next === ")") { out += ")"; j += 2; }
        else if (next === "\\") { out += "\\"; j += 2; }
        else if (/[0-7]/.test(next)) {
          // Octal escape: 1-3 octal digits.
          let oct = "";
          let k = 0;
          while (k < 3 && /[0-7]/.test(dictText[j + 1 + k])) { oct += dictText[j + 1 + k]; k += 1; }
          out += String.fromCharCode(parseInt(oct, 8));
          j += 1 + k;
        } else if (next === "\n" || next === "\r") {
          // Line continuation — skip newline.
          j += (next === "\r" && dictText[j + 2] === "\n") ? 3 : 2;
        } else {
          // Unknown escape — drop the backslash.
          out += next || "";
          j += 2;
        }
      } else if (ch === "(") { depth += 1; out += ch; j += 1; }
      else if (ch === ")") { depth -= 1; if (depth > 0) out += ch; j += 1; }
      else { out += ch; j += 1; }
    }
    return depth === 0 ? out : null;
  }
  return null;
}

// Parse a /Key entry whose value is a PDF name (e.g. /SubFilter /adbe.pkcs7.detached).
// Names run until whitespace or a delimiter; we don't decode #xx escapes since the
// names we care about (SubFilter values) never contain them.
function parseSigDictName(dictText, key) {
  const keyMarker = "/" + key;
  let i = dictText.indexOf(keyMarker);
  while (i !== -1) {
    let j = i + keyMarker.length;
    while (j < dictText.length && /\s/.test(dictText[j])) j += 1;
    if (dictText[j] === "/") {
      const m = /^[^\s/<>[\]()]+/.exec(dictText.slice(j + 1));
      if (m) return m[0];
    }
    i = dictText.indexOf(keyMarker, i + 1);
  }
  return null;
}

function trimTrailingZeros(bytes) {
  // /Contents hex is padded with 0x00 to a fixed placeholder width. Trim by
  // reading the outer SEQUENCE's length. Handles BER indefinite-length too:
  // for that case readTlv walks until the EOC marker and gives us .eocEnd.
  if (bytes.length === 0) return bytes;
  if (bytes[0] !== 0x30) throw new Error("CMS does not start with SEQUENCE");
  const { length, headerLen, indefinite } = readLength(bytes, 1);
  if (indefinite) {
    // Need to find the matching EOC. Easiest: parse the top TLV.
    const t = readTlv(bytes, 0);
    const total = t.eocEnd != null ? t.eocEnd : t.end;
    if (total > bytes.length) throw new Error("BER CMS truncated");
    return bytes.slice(0, total);
  }
  const total = 1 + headerLen + length;
  if (total > bytes.length) throw new Error("CMS truncated");
  return bytes.slice(0, total);
}

// -----------------------------------------------------------------------------
// Verification pipeline.
// -----------------------------------------------------------------------------

async function verifySignature(sig) {
  const cms = parseCms(sig.cmsDer);
  const si = cms.signerInfo;

  // ---- Locate the leaf cert. Three matching strategies, in order:
  //   (1) sid=IssuerAndSerialNumber → byte-match issuerDer + serial
  //   (2) sid=SubjectKeyIdentifier → byte-match the cert's SKI extension
  //   (3) fallback: first cert in the CMS certs set
  // Locate the leaf cert by sid (issue #10 + #34 from /cr): normalize serials
  // so a leading 0x00 sign byte in one encoding doesn't break the byte-match,
  // and report when sid-match fails entirely rather than silently using
  // certs[0] (which can pick the wrong cert in non-leaf-first orderings).
  let leaf = null;
  let leafFallbackReason = null;
  if (si.sidIssuerDer && si.sidSerialHex) {
    const wantedSerial = normalizeSerialHex(si.sidSerialHex);
    leaf = cms.certs.find((c) =>
      bytesEq(c.issuerDer, si.sidIssuerDer)
      && normalizeSerialHex(c.serialHex) === wantedSerial
    ) || null;
    if (!leaf) leafFallbackReason = "no cert in CMS matches SignerInfo.sid {issuer DN, serial}";
  } else if (si.sidSki) {
    leaf = cms.certs.find((c) => c.ski && bytesEq(c.ski, si.sidSki)) || null;
    if (!leaf) leafFallbackReason = "no cert in CMS matches SignerInfo.sid (SubjectKeyIdentifier)";
  }
  if (!leaf) {
    if (cms.certs.length === 1) {
      leaf = cms.certs[0];
      leafFallbackReason = null;
    } else if (cms.certs.length > 1) {
      // Multiple certs and sid didn't match — bail rather than guess. Better
      // to surface a CMS check failure than silently pick the wrong cert.
      throw new Error(leafFallbackReason || "could not match SignerInfo.sid to any cert in CMS");
    } else {
      throw new Error("no certificates in CMS");
    }
  }
  // CA candidate = any cert whose subject matches the leaf's issuer (and that
  // isn't the leaf itself). For self-signed CAs in test fixtures this can
  // collapse to the same cert; treat that as "no separate CA in CMS".
  const ca = cms.certs.find((c) => c !== leaf && bytesEq(c.subjectDer, leaf.issuerDer)) || null;

  // Parse the TST genTime EARLY so the chain check (below) can prefer it over
  // the signer-claimed signingTime when deciding "was the cert valid at
  // signing time?". Full TST CMS verification (issue #2) runs as Check 3.
  let tstSignedAt = null;
  let tstInfoEarly = null;
  const tstAttrEarly = findAttr(si.unsignedAttrs, OID.signatureTimeStampToken);
  if (tstAttrEarly) {
    try {
      tstInfoEarly = extractTstInfo(tstAttrEarly.valueRawWithHeader);
      tstSignedAt = tstInfoEarly.genTime;
    } catch {
      // leave tstSignedAt null; the TST check below will report the parse error
    }
  }
  const signingTimeAttr = findAttr(si.signedAttrs, OID.signingTimeAttr);
  const signerClaimedAt = signingTimeAttr ? decodeTime(signingTimeAttr.buf, signingTimeAttr.valueTlv) : null;

  // ---- Check 1: cryptographic signature (universal: RSA + ECDSA).
  // Enforces (in order): supported sigAlg, well-formed SignedAttributes,
  // contentType attr == encapContentInfo.eContentType (RFC 5652 §11.1),
  // signingCertificateV2.ESSCertIDv2.certHash == SHA-256(leafDer)
  // (RFC 5126 / RFC 5035, PAdES-required), outer SignerInfo signature
  // cryptographically verifies against the leaf SPKI, messageDigest attr
  // matches the digest of the ByteRange. Any one of those failing → FAIL.
  let cmsState = "fail";
  let cmsOk = false;
  let cmsDetail = "";
  let verifyParams = null;
  let spkiInfo = null;
  try {
    if (sig.byteRange?.a !== 0) {
      throw new Error("ByteRange starts after offset 0 — unsigned leading PDF bytes could affect the displayed document");
    }
    if (sig.hasUnsignedAppend) {
      throw new Error(`ByteRange ends at byte ${sig.byteRangeEnd}, but the current PDF is ${sig.pdfLength} bytes; unsigned bytes were appended after the signed revision`);
    }
    if (!si.signedAttrsAsHashed) throw new Error("SignedAttributes missing");
    if (!si.digestAlgOid) throw new Error("SignerInfo.digestAlgorithm missing");
    verifyParams = pickVerifyParams({
      sigAlgOid: si.sigAlgOid,
      digestOid: si.digestAlgOid,
      sigAlgParams: si.sigAlgParamsTlv ? { paramsBuf: si.sigAlgParamsBuf, paramsTlv: si.sigAlgParamsTlv } : null,
    });
    spkiInfo = parseSpki(leaf.spkiDer);
    // contentType attr — must be present AND equal encapContentInfo.eContentType.
    const ctAttr = findAttr(si.signedAttrs, OID.contentTypeAttr);
    if (!ctAttr) throw new Error("contentType SignedAttribute missing (RFC 5652 §11.1)");
    const ctValOid = decodeOid(ctAttr.buf, ctAttr.valueTlv.start, ctAttr.valueTlv.end);
    if (cms.encapContentTypeOid && ctValOid !== cms.encapContentTypeOid) {
      throw new Error(`contentType attr (${ctValOid}) != encapContentInfo.eContentType (${cms.encapContentTypeOid})`);
    }
    // signingCertificate(V2) — when present, binds the SignerInfo to a hash
    // of the leaf cert. RFC 5126 §5.7.3 + ETSI EN 319 122-1 §5.2.2.3 make
    // it mandatory for PAdES-B-B specifically, but pure CMS (RFC 5652
    // §5.3) only requires contentType + messageDigest. Many production
    // signers (Docuten, older Acrobat, plain CAdES) emit signatures
    // without it. So: ENFORCE the leaf binding WHEN the attribute is
    // present; treat absence as a profile-conformance note, not a
    // verification failure. Adobe Reader behaves the same way.
    const scv2 = findAttr(si.signedAttrs, OID.signingCertificateV2);
    const scv1 = scv2 ? null : findAttr(si.signedAttrs, OID.signingCertificate);
    if (scv2) {
      const certHash = extractEssCertIdV2Hash(scv2.buf, scv2.valueTlv);
      if (!certHash) throw new Error("signingCertificateV2 ESSCertIDv2.certHash unparseable");
      const leafHash = new Uint8Array(await crypto.subtle.digest("SHA-256", leaf.der));
      if (!bytesEq(certHash, leafHash)) {
        throw new Error("signingCertificateV2 ESSCertIDv2.certHash does not match SHA-256 of leaf cert — leaf substitution attempt");
      }
    } else if (scv1) {
      // Legacy ESS v1: ESSCertID.certHash is SHA-1 of the leaf cert. SHA-1
      // is broken for collision resistance in adversarial contexts, but
      // for a "pointer to which cert in the certs set is the signer's"
      // it's still meaningful — the actual signature uses SHA-256 and the
      // leaf is verified cryptographically below.
      const certHash = extractEssCertIdV2Hash(scv1.buf, scv1.valueTlv);
      // The attribute is present, so its leaf binding MUST be enforceable: an
      // unparseable or non-20-byte certHash cannot be silently waved through
      // while the detail below still claims "leaf-binding enforced".
      if (!certHash || certHash.length !== 20) {
        throw new Error("signingCertificate v1 ESSCertID.certHash unparseable or not 20 bytes (SHA-1)");
      }
      const leafSha1 = new Uint8Array(await crypto.subtle.digest("SHA-1", leaf.der));
      if (!bytesEq(certHash, leafSha1)) {
        throw new Error("signingCertificate v1 ESSCertID.certHash does not match SHA-1 of leaf cert");
      }
    }
    const pubKey = await importPublicKey(leaf.spkiDer, spkiInfo, verifyParams);

    const verifyInput = buildVerifyInput(si.signatureBytes, si.signedAttrsAsHashed, verifyParams, spkiInfo);
    let ok = await crypto.subtle.verify(verifyInput.alg, pubKey, verifyInput.sig, verifyInput.data);
    if (!ok && verifyParams.kind === "RSA") {
      // Fallback for the DigestInfo-without-NULL-parameter encoding (Polish
      // QTSP "Profil Zaufany" seals, some BouncyCastle outputs). Adobe
      // accepts both; WebCrypto only accepts the with-NULL form.
      ok = await rsaPkcs1V15LooseVerify(leaf.spkiDer, si.signatureBytes, si.signedAttrsAsHashed, verifyParams.hashName);
    }
    if (!ok) throw new Error(`${verifyParams.kind} signature verification failed`);
    // Cross-check messageDigest == digest(signedRegion). For RSA / ECDSA the
    // digest comes from SignerInfo.digestAlgorithm; for RSA-PSS we use the
    // PSS hash; for Ed25519/Ed448 (no digest dispatch) we still check the
    // SignerInfo.digestAlgorithm of the messageDigest attr.
    const mdAttr = findAttr(si.signedAttrs, OID.messageDigestAttr);
    if (!mdAttr) throw new Error("messageDigest attribute missing");
    const expectedMd = mdAttr.valueBytes;
    const mdHashName = verifyParams.hashName || (DIGEST_INFO[si.digestAlgOid] && DIGEST_INFO[si.digestAlgOid].name);
    if (!mdHashName) throw new Error("cannot determine digest for messageDigest cross-check");
    const actualMd = await digestBytes(mdHashName, sig.signedRegion);
    if (!bytesEq(expectedMd, actualMd)) {
      throw new Error(`messageDigest (${mdHashName}) does not match ByteRange digest — document was modified after signing`);
    }
    cmsOk = true;
    const algLabel = describeAlg(verifyParams, spkiInfo);
    const extras = [];
    if (scv2) {
      cmsState = "ok";
      extras.push("signingCertificateV2 leaf-binding enforced");
    } else if (scv1) {
      cmsState = "ok";
      extras.push("signingCertificate v1 leaf-binding enforced (legacy ESS / SHA-1)");
    } else {
      // The signature verifies, but with NO signingCertificate(V2) attribute
      // the leaf is bound to this SignerInfo only by sid (issuer + serial) —
      // unsigned CMS metadata, weaker than a signed certificate hash. Surface
      // it as a caveat (yellow), not a clean green. The wording depends on the
      // /SubFilter: ETSI.CAdES.detached *declares* PAdES, so omitting the ESS
      // attribute is a real conformance defect; adbe.pkcs7.* is legacy Adobe
      // PKCS#7, where signingCertificateV2 is genuinely optional — there it is
      // "valid CMS, just not PAdES", not "broken".
      cmsState = "warn";
      const subFilter = parseSigDictName(sig.sigDictText || "", "SubFilter");
      const sidNote = "the leaf is bound to this signature only by the unsigned SignerInfo.sid (issuer + serial), not a signed certificate hash";
      if (subFilter === "ETSI.CAdES.detached") {
        extras.push(`SubFilter is ETSI.CAdES.detached (declares PAdES) yet carries no signingCertificate(V2) attribute — NOT PAdES-conformant (ETSI EN 319 122-1 §5.2.2 makes signingCertificateV2 mandatory); ${sidNote}`);
      } else if (subFilter && subFilter.startsWith("adbe.")) {
        extras.push(`legacy Adobe PKCS#7 signature (SubFilter ${subFilter}) — valid CMS, but not a PAdES signature: no signingCertificate(V2) attribute (optional for this SubFilter, mandatory for PAdES), so ${sidNote}`);
      } else {
        extras.push(`no signingCertificate(V2) attribute present — basic CMS, not PAdES-conformant; ${sidNote}`);
      }
    }
    extras.push(`contentType attr = ${ctValOid}`);
    cmsDetail = `${algLabel} over SignedAttributes verifies against leaf SPKI; messageDigest attr matches ${mdHashName}(ByteRange) (${toHex(actualMd).slice(0, 16)}…); ${extras.join("; ")}.`;
  } catch (e) {
    cmsDetail = "FAILED: " + e.message;
  }

  // ---- Check 2: certificate chain.
  // Robust against AATL-anchored signatures where the root lives in Adobe's
  // local trust store and isn't embedded in the CMS — that case is INFO, not
  // FAIL. Only an explicit issuer/subject mismatch OR a forged cert signature
  // is FAIL. For the trust-time decision we PREFER the TST genTime over the
  // signer-claimed signingTime (PAdES requires it when present) — see below.
  let chainState = "fail";
  let chainOk = false;
  let chainDetail = "";
  try {
    const selfSigned = bytesEq(leaf.issuerDer, leaf.subjectDer);
    if (selfSigned) {
      // A self-signed leaf is internally consistent at best — we explicitly
      // flag this as WARN, not INFO (issue #31 from /cr). Anyone can make a
      // self-signed cert claiming any subject or SAN email; a green-looking
      // tile would invite impersonation. Crypto-verify the self-signature so
      // a tampered self-signed cert is still surfaced as FAIL.
      const sigCheck = await verifyCertSignature(leaf, leaf);
      if (!sigCheck.ok) throw new Error("self-signed leaf signature failed cryptographic verification: " + sigCheck.detail);
      chainState = "warn";
      if (looksLikePlatformSeal(leaf)) {
        // The freesign_verified_seal platform e-seal on a legacy self-signed
        // cert. It is an ORGANISATIONAL seal, not a personal signature — it
        // makes no individual-identity claim (no typed name, no SAN email), so
        // the generic "displayed signer identity is un-verified" wording does
        // not apply. The relevant caveat is authenticity of the seal itself.
        chainDetail = `⚠ This is the FreeSign platform e-seal ("${leaf.subjectString}") — an organisational seal, not a personal signature. It attests that the document passed through the FreeSign platform; it deliberately does NOT vouch for any individual's identity (that is the job of the per-user signer certificate and the embedded evidence record). The seal certificate is self-signed (${sigCheck.detail}), so it is not anchored to any public trust root — you can only confirm it is genuinely FreeSign's seal by checking its certificate fingerprint out of band.`;
      } else {
        // A self-signed per-person leaf: here the CN and SAN email ARE
        // identity claims, and self-signed means nobody vouched for them.
        chainDetail = `⚠ Leaf cert is SELF-SIGNED (issuer == subject = "${leaf.subjectString}"). Its self-signature is internally consistent (${sigCheck.detail}), but ANY identity claim in this cert — the typed name, the SAN email — is asserted by the signer themselves with NO third party vouching. Treat the displayed signer identity as un-verified unless you separately confirm you trust the cert's fingerprint out of band.`;
      }
    } else if (!ca) {
      // We can't cryptographically verify the chain without the issuer cert,
      // but we CAN report the bind shape so the user knows what to look up.
      chainState = "info";
      chainDetail = `Leaf cert subject "${leaf.subjectString}", issuer "${leaf.issuerString}". Intermediate / root NOT embedded in CMS — for AATL- or EUTL-anchored signatures the chain terminates in the verifier's local trust store. This page cannot complete path validation without the issuer cert; treat this as "structure looks plausible, trust depends on whether you have the issuer in your local store".`;
    } else {
      if (!bytesEq(leaf.issuerDer, ca.subjectDer)) throw new Error("leaf.issuer DN != embedded CA cert subject DN");
      // Cryptographically verify the leaf's signature against the CA's
      // public key — the byte-match alone proves nothing (issue #1 from the
      // /cr review). A forged CA cert with a matching subject DN would
      // otherwise sneak through this branch.
      const sigCheck = await verifyCertSignature(leaf, ca);
      if (!sigCheck.ok) throw new Error("leaf cert signature did not verify against embedded CA: " + sigCheck.detail);
      // RFC 5280 §4.2.1.9 / §4.2.1.3: the issuing CA cert MUST have
      // basicConstraints.cA = TRUE AND keyUsage.keyCertSign asserted. A cert
      // missing either is not authorized to issue subordinate certs; a
      // forged "CA" without these extensions but with a real key would
      // otherwise satisfy the signature check above.
      if (!ca.basicConstraintsCa) throw new Error("embedded CA cert is missing basicConstraints.cA=TRUE");
      if (!ca.keyUsageKeyCertSign) throw new Error("embedded CA cert is missing keyUsage.keyCertSign");
      const expectedFreeSignCaSha256 = await fetchExpectedFreeSignCaSha256();
      if (expectedFreeSignCaSha256) {
        const caSha256 = toHex(await sha256(ca.der));
        if (caSha256 !== expectedFreeSignCaSha256) {
          throw new Error("embedded CA cert does not match this deployment's pinned FreeSign CA fingerprint");
        }
      }
      // PAdES: when a TST is present, the AUTHORITATIVE signing time is
      // tstSignedAt (genTime). Fall back to signer-claimed only when no TST.
      const trustTime = tstSignedAt || signerClaimedAt;
      if (trustTime) {
        if (trustTime < leaf.notBefore || trustTime > leaf.notAfter) throw new Error("leaf cert not valid at signing time " + trustTime.toISOString());
        if (trustTime < ca.notBefore || trustTime > ca.notAfter) throw new Error("CA cert not valid at signing time " + trustTime.toISOString());
      }
      chainState = "ok";
      chainOk = true;
      const timeSource = tstSignedAt ? `TST genTime ${tstSignedAt.toISOString()} (authoritative)` : (signerClaimedAt ? `signer-claimed ${signerClaimedAt.toISOString()} (no TST, unattested)` : "no signing time available");
      chainDetail = `Leaf signature verifies against embedded CA pubkey (${sigCheck.detail}). DN match on Issuer/Subject. Leaf validity: ${leaf.notBefore.toISOString()} → ${leaf.notAfter.toISOString()}. Checked against: ${timeSource}.`;
    }
  } catch (e) {
    chainDetail = "FAILED: " + e.message;
  }

async function fetchExpectedFreeSignCaSha256() {
  // Browser /verify runs on the same origin that serves the deployment's
  // FreeSign CA fingerprint. Node-based unit tests import this module without
  // a browser location; keep those deterministic and skip the live pin there.
  if (typeof window === "undefined" || typeof fetch !== "function") return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const res = await fetch("/.well-known/free-sign-signing-ca.sha256.txt", {
      cache: "no-store",
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const fp = (await res.text()).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(fp)) throw new Error("malformed fingerprint response");
    return fp;
  } catch (e) {
    throw new Error("could not load pinned FreeSign CA fingerprint: " + e.message);
  } finally {
    clearTimeout(timer);
  }
}

  // ---- Check 3: RFC 3161 timestamp (PAdES-B-T).
  // A TST is itself a CMS SignedData with eContentType id-ct-TSTInfo. To say
  // anything trustworthy about it we must verify:
  //   (a) messageImprint == digest(outer SignerInfo.signature), with the
  //       digest algorithm the TSTInfo declares (not assumed SHA-256);
  //   (b) the TST's own SignerInfo signature verifies against the embedded
  //       TSA cert's public key — same dispatch as the outer SignerInfo;
  //   (c) the TSA cert is valid at TSTInfo.genTime.
  // (Trust-root validation of the TSA cert chain is delegated — Adobe Reader
  // has DigiCert/Sectigo/etc. in its store; this page reports the TSA cert
  // subject and lets the user / their downstream policy decide.)
  // PAdES-B-B is valid PAdES — it just doesn't carry a TST. Absent → INFO.
  let tstState = "fail";
  let tstOk = false;
  let tstDetail = "";
  try {
    if (!tstAttrEarly) {
      tstState = "info";
      tstDetail = "No RFC 3161 TimeStampToken embedded. This is a PAdES-B-B signature — valid PAdES, just without an embedded TSA timestamp. The signingTime attribute (if present) is signer-claimed, not third-party attested. Many B-B signatures get an LTV/T upgrade later.";
    } else {
      const tstCmsDer = tstAttrEarly.valueRawWithHeader;
      const tstCms = parseCms(tstCmsDer);
      const tstInfo = tstInfoEarly || extractTstInfo(tstCmsDer);
      // (a) messageImprint cross-check.
      const imprintHashInfo = DIGEST_INFO[tstInfo.imprintHashOid];
      if (!imprintHashInfo) throw new Error("unsupported TST messageImprint hash OID " + tstInfo.imprintHashOid);
      const outerSigDigest = await digestBytes(imprintHashInfo.name, si.signatureBytes);
      if (!bytesEq(tstInfo.imprint, outerSigDigest)) {
        throw new Error(`TST messageImprint does not match ${imprintHashInfo.name}(outer signature)`);
      }
      // (b) TST's own SignerInfo signature must verify against the TSA cert.
      const tsaCheck = await verifyInnerCmsSignature(tstCms, tstCmsDer);
      if (!tsaCheck.ok) throw new Error("TST SignerInfo signature did not verify: " + tsaCheck.detail);
      // (c) TSA cert validity window covers TSTInfo.genTime.
      if (tstSignedAt && tsaCheck.signerCert) {
        const tsa = tsaCheck.signerCert;
        if (tstSignedAt < tsa.notBefore || tstSignedAt > tsa.notAfter) {
          throw new Error("TSA cert not valid at TST genTime " + tstSignedAt.toISOString());
        }
      }
      const tsaSubject = tsaCheck.signerCert ? tsaCheck.signerCert.subjectString : "(no TSA cert embedded)";
      tstState = "ok";
      tstOk = true;
      tstDetail = `RFC 3161 TimeStampToken cryptographically verified. TSA: ${tsaSubject}. genTime: ${tstSignedAt ? tstSignedAt.toISOString() : "(unparsed)"}. messageImprint matches ${imprintHashInfo.name}(outer signature). TST SignerInfo signature: ${tsaCheck.detail}. Trust-anchor decision for the TSA cert (AATL / EUTL / private trust list) is left to the verifier's policy layer.`;
    }
  } catch (e) {
    tstDetail = "FAILED: " + e.message;
  }

  // ---- Check 4: OpenTimestamps / Bitcoin anchor (FreeSign-specific bonus).
  // No other signing vendor embeds this attribute today. The OTS attribute
  // itself is just a commitment — anyone can synthesize one with the right
  // shape. Only a Bitcoin block-header attestation is cryptographic evidence
  // a third party didn't backdate the file. So:
  //   - Absent → INFO ("not a FreeSign signature, this anchor doesn't apply").
  //   - Calendar-only present, no Bitcoin attestation yet → INFO ("provisional,
  //     calendar promise to upgrade; this verifier won't call it green").
  //   - Bitcoin attestation present + block hash resolvable → OK.
  //   - Malformed / digest mismatch / etc. → FAIL.
  let otsState = "fail";
  let otsOk = false;
  let otsDetail = "";
  let otsBlockHash = null;
  try {
    const otsAttr = findAttr(si.unsignedAttrs, OID.freeSignOtsCommitment);
    if (!otsAttr) {
      otsState = "info";
      otsDetail = "No OpenTimestamps Bitcoin anchor (unsignedAttribute 1.3.6.1.4.1.65834.1.1) — this is a FreeSign-specific bonus. Adobe Sign / DocuSign / GlobalSign / QTSP signatures don't use it; their RFC 3161 timestamp is the durability layer. Doesn't reduce the validity of this signature.";
    } else {
      if (otsAttr.valueTlv.tag !== 0x04) throw new Error("OTS attribute value is not OCTET STRING");
      const otsBytes = otsAttr.valueBytes;
      const docDigest = await sha256(sig.signedRegion);
      const signingTimeMs = tstSignedAt ? tstSignedAt.getTime() : (signerClaimedAt ? signerClaimedAt.getTime() : null);
      const otsEval = await evaluateEmbeddedOtsProof(otsBytes, docDigest, { signingTimeMs });
      otsState = otsEval.state;
      otsOk = otsEval.ok;
      otsDetail = otsEval.detail;
      otsBlockHash = otsEval.blockHash;
    }
  } catch (e) {
    otsDetail = "FAILED: " + e.message;
  }

  // ---- FreeSign signing-evidence record (signedAttribute 1.3.6.1.4.1.65834.1.2).
  // The pre-seal ceremony JSON the browser produced is embedded by /seal into
  // THIS signer's CMS signedAttrs. Because signedAttrs are covered by the
  // outer CMS signature, changing the evidence in the PDF /Contents gap now
  // invalidates Check 2 instead of producing a forged-but-verified record. We
  // still re-verify the browser ECDSA signature inside the evidence as a
  // second, independent check of the ceremony payload.
  let evidenceState = "info";
  let evidenceDetail = "";
  let evidenceData = null;
  try {
    const signedEvAttr = findAttr(si.signedAttrs, OID.freeSignEvidence);
    const unsignedEvAttr = findAttr(si.unsignedAttrs, OID.freeSignEvidence);
    const evAttr = signedEvAttr || unsignedEvAttr;
    if (!evAttr) {
      evidenceState = "info";
      evidenceDetail = "No FreeSign evidence record (signedAttribute 1.3.6.1.4.1.65834.1.2). Pre-embedding PDFs and non-FreeSign signatures don't carry one — it does not reduce signature validity.";
    } else if (!signedEvAttr) {
      evidenceState = "fail";
      evidenceDetail = "FreeSign evidence record is present only as a CMS unsignedAttribute. That location is not covered by the CMS signature and may be modified without invalidating the PDF signature, so this embedded evidence is not trusted. Re-seal the document with a version that embeds evidence as a signedAttribute.";
    } else {
      if (evAttr.valueTlv.tag !== 0x04) throw new Error("evidence attribute value is not OCTET STRING");
      const ev = JSON.parse(new TextDecoder().decode(evAttr.valueBytes));
      evidenceData = ev;
      const cp = ev.canonical_payload;
      const jwk = ev.public_key_jwk;
      const sigB64u = ev.signature_base64url;
      if (!cp || !jwk || !sigB64u) {
        evidenceState = "warn";
        evidenceDetail = `Evidence record embedded (signer "${ev.signer_name || "?"}", schema ${ev.schema || "?"}) but missing canonical_payload / public_key_jwk / signature — cannot re-verify its primary signature here.`;
      } else {
        const key = await crypto.subtle.importKey(
          "jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
          { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
        );
        const sigStd = String(sigB64u).replace(/-/g, "+").replace(/_/g, "/");
        const sigBin = atob(sigStd + "=".repeat((4 - sigStd.length % 4) % 4));
        const sigBytes = Uint8Array.from(sigBin, (c) => c.charCodeAt(0));
        const msg = new TextEncoder().encode(canonicalJson(cp));
        const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sigBytes, msg);
        if (ok) {
          // Bind the record to THIS signature. The per-user FreeSign seal
          // (signer_certificate variant) mints a fresh leaf cert per signer
          // with Subject CN = the typed name, and the evidence
          // canonical_payload carries the same name. The evidence attribute is
          // NOT covered by the outer CMS signature, so a valid record could be
          // lifted wholesale into a different signer's CMS — verifying its own
          // self-signature does not prove it belongs here. A name mismatch is
          // a transplant: fail it instead of showing it as this signer's.
          //
          // EXCEPTION: the legacy self-signed freesign_verified_seal variant
          // (/platform-seal route) signs every document with ONE shared platform
          // certificate ("(Free)Sign Platform Seal") — its CN is deliberately
          // not a person, so a name mismatch there is expected. CA-issued
          // certificates must not get this exception from spoofable subject
          // text alone; otherwise transplanted evidence could be accepted for
          // an attacker-controlled "platform seal" leaf.
          const evName = String(cp.signer_name || "").trim();
          const certName = String(leaf.subjectCn || "").trim();
          const isPlatformSeal = looksLikePlatformSeal(leaf);
          if (!isPlatformSeal && evName && certName && evName !== certName) {
            evidenceState = "fail";
            evidenceDetail = `FreeSign evidence record's own ECDSA signature verifies, but the record names signer "${evName}" while this signature's certificate names "${certName}" — the record does not belong to this CMS (transplanted from another signature).`;
          } else {
            evidenceState = "ok";
            // Report the cryptographically-VERIFIED values from canonical_payload
            // (covered by the signature we just checked), not the cosmetic
            // top-level copies (which are not signed and could be edited).
            const identity = (ev.identity_method === "passkey" || ev.webauthn_assertion)
              ? "passkey (biometric / device PIN)"
              : `email OTP verified ${cp.otp_verified_at || "?"}`;
            const bindingClause = isPlatformSeal
              ? `the record names signer "${evName || "?"}" — this document carries the shared FreeSign Platform Seal certificate (one cert for every signer), so the certificate itself cannot bind the record to an individual by name; the record's own ECDSA signature is what stands behind it`
              : `the record's signer name matches this signature's certificate`;
            evidenceDetail = `FreeSign evidence record verified — the primary ECDSA P-256 signature over canonical_payload checks out against the embedded public_key_jwk, and ${bindingClause}. Signer "${cp.signer_name || "?"}", consent ${cp.consent_version || "?"}, identity: ${identity}. This is the signer's own pre-seal ceremony record, embedded in their CMS — extractable and checkable with no FreeSign server call. Fields outside canonical_payload (request fingerprint, etc.) are contextual and not covered by this signature.`;
            // Stage 6E: a passkey signer also carries a WebAuthn assertion.
            // Re-verify it — ECDSA signature against the embedded COSE key,
            // challenge against SHA-256(canonical_payload) — so a tampered
            // assertion FAILS here instead of being shown as fact.
            if (ev.webauthn_assertion) {
              try {
                const wa = await verifyEmbeddedWebauthnAssertion(ev);
                if (wa.ok) {
                  evidenceDetail += ` WebAuthn passkey assertion re-verified — ${wa.detail}.`;
                } else {
                  evidenceState = "fail";
                  evidenceDetail = `FreeSign evidence record: ${wa.detail}.`;
                }
              } catch (waErr) {
                evidenceState = "fail";
                evidenceDetail = `FreeSign evidence record: passkey assertion check failed — ${waErr.message}.`;
              }
            }
          }
        } else {
          evidenceState = "fail";
          evidenceDetail = "FreeSign evidence record is present but its primary signature did NOT verify against the embedded public key — the canonical_payload or the signature was altered after signing.";
        }
      }
    }
  } catch (e) {
    evidenceState = "fail";
    evidenceDetail = "FAILED: " + e.message;
  }

  // Display fields.
  // PAdES: TST genTime is AUTHORITATIVE when present; signer-claimed time is
  // unattested. Display order corrected (issue #25 from /cr): TST first.
  const displayTime = tstSignedAt || signerClaimedAt;
  const byteRangeDigest = await sha256(sig.signedRegion);
  const sigDict = sig.sigDictText || "";
  const sigDictName = parseSigDictField(sigDict, "Name");
  const sigDictContact = parseSigDictField(sigDict, "ContactInfo");
  // Human-friendly signature algorithm label even when verifyParams isn't
  // populated (issue #29 from /cr). When the OID is recognized but
  // unsupported, we still report something users can google.
  let sigAlgLabel;
  if (verifyParams && spkiInfo) {
    sigAlgLabel = describeAlg(verifyParams, spkiInfo);
  } else {
    sigAlgLabel = sigAlgFriendlyName(si.sigAlgOid) + ` (OID ${si.sigAlgOid})`;
  }

  return {
    cms,
    leaf,
    ca,
    summary: {
      signerName: leaf.subjectCn || sigDictName || "(unknown)",
      // /ContactInfo is "Signer contact" per PDF spec, not specifically email.
      // Prefer the cert's verified rfc822Name SAN; show /ContactInfo only as
      // free-form fallback (issue #30 from /cr).
      signerEmail: leaf.rfc822Name || "(none in cert)",
      signerContact: sigDictContact || "(none)",
      signingTime: displayTime ? displayTime.toISOString() : "(unknown)",
      signingTimeSource: tstSignedAt ? "TST (third-party attested)" : (signerClaimedAt ? "signer-claimed (unattested)" : "(unknown)"),
      byteRangeSha256: toHex(byteRangeDigest),
      cmsProfile: tstOk ? "PAdES-B-T" : "PAdES-B-B",
      sigAlg: sigAlgLabel,
      caSubject: ca ? ca.subjectString : (chainState === "info" ? "(not embedded — verify externally)" : "(missing)"),
      platformSeal: looksLikePlatformSeal(leaf),
    },
    checks: {
      cms:   { ok: cmsOk,   state: cmsState,   detail: cmsDetail },
      chain: { ok: chainOk, state: chainState, detail: chainDetail },
      tst:   { ok: tstOk,   state: tstState,   detail: tstDetail },
      ots:   { ok: otsOk,   state: otsState,   detail: otsDetail, blockHash: otsBlockHash },
      evidence: { ok: evidenceState === "ok", state: evidenceState, detail: evidenceDetail, data: evidenceData },
    },
  };
}

function extractTstInfo(tstContentInfoDer) {
  // ContentInfo { OID id-signedData, [0] EXPLICIT SignedData }
  // Per RFC 3161 §2.4.2 TSTInfo ::= SEQUENCE {
  //   version    INTEGER,
  //   policy     TSAPolicyId (OID),
  //   messageImprint MessageImprint,
  //   serialNumber INTEGER,
  //   genTime    GeneralizedTime,
  //   ... }
  // Issue #26 from /cr: assert tag conformance per child position. A
  // non-conformant emitter that shifts offsets must FAIL rather than read
  // garbage as the imprint.
  const ci = readTlv(tstContentInfoDer, 0);
  if (ci.tag !== 0x30) throw new Error("TST ContentInfo not SEQUENCE");
  const ciKids = childrenOf(tstContentInfoDer, ci);
  if (ciKids[1].tag !== 0xa0) throw new Error("TST ContentInfo missing [0] EXPLICIT content");
  const sd = readTlv(tstContentInfoDer, ciKids[1].start);
  if (sd.tag !== 0x30) throw new Error("TST SignedData not SEQUENCE");
  const sdKids = childrenOf(tstContentInfoDer, sd);
  const enc = sdKids[2];
  if (enc.tag !== 0x30) throw new Error("TST encapContentInfo not SEQUENCE");
  const encKids = childrenOf(tstContentInfoDer, enc);
  const wrapper = encKids[1];
  if (wrapper.tag !== 0xa0) throw new Error("expected [0] EXPLICIT eContent");
  const octet = readTlv(tstContentInfoDer, wrapper.start);
  if (octet.tag !== 0x04) throw new Error("TST eContent not OCTET STRING");
  const tstInfoTlv = readTlv(tstContentInfoDer, octet.start);
  if (tstInfoTlv.tag !== 0x30) throw new Error("TSTInfo not SEQUENCE");
  const tiKids = childrenOf(tstContentInfoDer, tstInfoTlv);
  if (tiKids.length < 5) throw new Error("TSTInfo too few fields");
  if (tiKids[0].tag !== 0x02) throw new Error("TSTInfo.version not INTEGER");
  if (tiKids[1].tag !== 0x06) throw new Error("TSTInfo.policy not OID");
  if (tiKids[2].tag !== 0x30) throw new Error("TSTInfo.messageImprint not SEQUENCE");
  if (tiKids[3].tag !== 0x02) throw new Error("TSTInfo.serialNumber not INTEGER");
  if (tiKids[4].tag !== 0x18) throw new Error("TSTInfo.genTime not GeneralizedTime");
  const miKids = childrenOf(tstContentInfoDer, tiKids[2]);
  if (miKids[0].tag !== 0x30) throw new Error("messageImprint.hashAlgorithm not SEQUENCE");
  if (miKids[1].tag !== 0x04) throw new Error("messageImprint.hashedMessage not OCTET STRING");
  const hashAlgKids = childrenOf(tstContentInfoDer, miKids[0]);
  const imprintHashOid = decodeOid(tstContentInfoDer, hashAlgKids[0].start, hashAlgKids[0].end);
  const imprint = tstContentInfoDer.slice(miKids[1].start, miKids[1].end);
  const genTime = decodeTime(tstContentInfoDer, tiKids[4]);
  return { imprint, imprintHashOid, genTime };
}

function findBitcoinAttestation(blob) {
  // Bound was strict `<` (issue #20 from /cr) — that missed a marker whose
  // last byte was the final byte of `blob`. Now `<=`.
  for (let i = 0; i + BTC_ATTESTATION_TAG.length <= blob.length; i += 1) {
    if (!bytesEqAt(blob, BTC_ATTESTATION_TAG, i)) continue;
    try {
      const { offset: payloadStart } = readVarUint(blob, i + BTC_ATTESTATION_TAG.length);
      const { value: blockHeight } = readVarUint(blob, payloadStart);
      if (Number.isInteger(blockHeight) && blockHeight > 0 && blockHeight < 1e9) {
        return { found: true, blockHeight };
      }
    } catch {
      // marker bytes appeared inside arbitrary content — keep scanning
    }
  }
  return { found: false };
}

/**
 * Poll public calendars for a Bitcoin-upgraded Timestamp tree when the
 * embedded .ots in the PDF is still calendar-only (normal at /seal time).
 */
async function tryUpgradeOtsTimestamp(timestampBytes, msgBytes, { fetchImpl, signal, timeoutMs } = {}) {
  return upgradeTimestampFromTree(timestampBytes, msgBytes, { fetchImpl, signal, timeoutMs });
}

/**
 * Evaluate an embedded FreeSign .ots blob against SHA-256(ByteRange). When the
 * PDF carries a calendar-only proof, queries public calendars for the BTC
 * upgrade before showing the hourglass state.
 */
async function evaluateEmbeddedOtsProof(otsBytes, byteRangeDigest, { signingTimeMs, fetchImpl, signal, timeoutMs } = {}) {
  if (otsBytes.length < OTS_MAGIC.length + 1 + 1 + 32) throw new Error(".ots truncated");
  for (let i = 0; i < OTS_MAGIC.length; i += 1) {
    if (otsBytes[i] !== OTS_MAGIC[i]) throw new Error(".ots magic mismatch");
  }
  if (otsBytes[OTS_MAGIC.length + 1] !== OTS_OP_SHA256) {
    throw new Error(".ots uses a non-SHA-256 file_hash_op");
  }
  const msgStart = OTS_MAGIC.length + 1 + 1;
  const otsMsg = otsBytes.slice(msgStart, msgStart + 32);
  if (!bytesEq(otsMsg, byteRangeDigest)) {
    throw new Error(".ots commits to a different digest than SHA-256(ByteRange) — document was modified after signing");
  }
  const anchoredHashHex = toHex(otsMsg);
  const embeddedBlob = otsBytes.slice(msgStart + 32);
  let timestampBlob = embeddedBlob;
  let upgradedFromCalendar = null;
  // The Bitcoin attestation is only authoritative when its marker is present in
  // the proof that the PDF actually embeds (committed at signing time). A marker
  // found ONLY after replacing the embedded blob with bytes fetched live from a
  // public calendar is NOT cryptographically bound here: findBitcoinAttestation
  // is a marker SCAN, not an OTS-tree validation, so a malicious/compromised
  // calendar could return arbitrary bytes carrying the BTC tag + a plausible
  // height. Such an unvalidated calendar upgrade must NOT drive state="ok"
  // (secu2.md finding) — it stays a non-confirming "waiting".
  let btc = findBitcoinAttestation(timestampBlob);
  const btcFromEmbedded = btc.found;
  if (!btc.found) {
    const up = await tryUpgradeOtsTimestamp(timestampBlob, otsMsg, { fetchImpl, signal, timeoutMs });
    if (up.upgraded) {
      upgradedFromCalendar = up.calendarUrl;
      timestampBlob = up.timestampBytes;
      btc = findBitcoinAttestation(timestampBlob);
    }
  }

  // A marker that only appears in live-fetched calendar bytes is unvalidated:
  // do not present it as a confirmed Bitcoin attestation.
  if (btc.found && !btcFromEmbedded) {
    return {
      ok: false,
      state: "waiting",
      blockHash: null,
      detail: `A public calendar${upgradedFromCalendar ? ` (${upgradedFromCalendar})` : ""} returned an upgrade carrying a Bitcoin attestation marker (block height ${btc.blockHeight}), but those bytes are fetched live and are NOT cryptographically bound to this document here — this page scans for the marker, it does not validate the full OpenTimestamps merkle path. Treating the proof as still calendar-only / pending. Run \`ots verify <file.ots>\` offline to confirm the Bitcoin anchor cryptographically.`,
    };
  }

  if (btc.found) {
    const blockHash = await fetchBlockHashSilently(btc.blockHeight);
    const upgradeNote = "";
    if (blockHash) {
      return {
        ok: true,
        state: "ok",
        blockHash,
        detail: `OpenTimestamps Bitcoin attestation at block height ${btc.blockHeight}, block hash ${blockHash} (blockstream.info).${upgradeNote} This check confirms marker shape + that the block exists — for full merkle-path proof run \`ots verify <file.ots>\` offline.`,
      };
    }
    if (BLOCKSTREAM_LOOKUP_ENABLED) {
      return {
        ok: false,
        state: "info",
        blockHash: null,
        detail: `Bitcoin attestation marker at block height ${btc.blockHeight}, but blockstream.info returned no hash.${upgradeNote} Use \`ots verify\` offline for full validation.`,
      };
    }
    return {
      ok: false,
      state: "info",
      blockHash: null,
      detail: `Bitcoin attestation marker at block height ${btc.blockHeight}.${upgradeNote} Block-hash lookup is OFF — run \`ots verify\` offline for cryptographic proof.`,
    };
  }

  const ageMs = signingTimeMs != null ? Date.now() - signingTimeMs : null;
  const stale = ageMs != null && ageMs > OTS_STALE_AFTER_SIGNING_MS;
  if (stale) {
    return {
      ok: false,
      state: "info",
      blockHash: null,
      detail: `Embedded OpenTimestamps proof is calendar-only (${otsBytes.length} bytes) and public calendars did not return a Bitcoin attestation for this commitment when queried just now. Signing was ${Math.round(ageMs / 3_600_000)}h ago — if you expected on-chain confirmation, download a fresh \`.ots\` from the receipt's proof URL (server cron upgrades stored proofs) or run \`ots upgrade\` on the embedded bytes. This does NOT reduce CMS signature validity.`,
    };
  }
  return {
    ok: false,
    state: "waiting",
    blockHash: null,
    detail: `OpenTimestamps proof embedded (${otsBytes.length} bytes) and matches SHA-256(ByteRange). Public calendars were queried; Bitcoin confirmation is still pending (typically within about an hour of signing). This expected right after signing does NOT reduce signature validity.`,
  };
}

function readVarUint(buf, offset) {
  let result = 0;
  let shift = 0;
  let i = offset;
  while (i < buf.length) {
    const byte = buf[i];
    i += 1;
    result |= (byte & 0x7f) << shift;
    if (!(byte & 0x80)) return { value: result, offset: i };
    shift += 7;
    if (shift > 35) throw new Error("varuint too long");
  }
  throw new Error("varuint truncated");
}

// Bitcoin block-height → block hash resolution via blockstream.info. Called
// whenever a Bitcoin attestation marker is present in the OTS proof. Block
// heights are public — the height itself doesn't leak document content; the
// Referer header IS suppressed via referrerPolicy:"no-referrer" so the page
// URL doesn't leak either. Default ON because without the lookup, the OTS
// tile can only ever go INFO ("marker found but unverified") which is worse
// UX than the privacy cost of a single anonymized GET. Tests / paranoid
// callers can flip via setBlockstreamLookupEnabled(false).
let BLOCKSTREAM_LOOKUP_ENABLED = true;
function setBlockstreamLookupEnabled(v) { BLOCKSTREAM_LOOKUP_ENABLED = !!v; }
async function fetchBlockHashSilently(height) {
  if (!BLOCKSTREAM_LOOKUP_ENABLED) return null;
  try {
    const res = await fetch(`https://blockstream.info/api/block-height/${height}`, {
      method: "GET",
      headers: { accept: "text/plain" },
      referrer: "",
      referrerPolicy: "no-referrer",
    });
    if (!res.ok) return null;
    const text = (await res.text()).trim();
    return /^[0-9a-f]{64}$/.test(text) ? text : null;
  } catch {
    return null;
  }
}

// The result shape rendered for a signature whose CMS could not even be
// parsed. It MUST carry every check key renderResultIntoBlock reads
// (cms/chain/tst/ots/evidence) — a missing key throws inside the renderer and
// aborts the whole block, which in a multi-signature PDF would suppress every
// other signature's result too. Exported so test/verifier.test.mjs can pin
// that contract.
export function parseErrorResult(message) {
  const notEval = "Not evaluated — CMS parse failed.";
  return {
    summary: { signerName: "(parse error)", signerEmail: "", signingTime: "", signingTimeSource: "", byteRangeSha256: "", cmsProfile: "", sigAlg: "", caSubject: "" },
    checks: {
      cms:      { ok: false, state: "fail", detail: "FAILED: " + message },
      chain:    { ok: false, state: "fail", detail: notEval },
      tst:      { ok: false, state: "fail", detail: notEval },
      ots:      { ok: false, state: "fail", detail: notEval, blockHash: null },
      evidence: { ok: false, state: "fail", detail: notEval },
    },
  };
}

// Exported for Node-side smoke testing (tools/smoke-verify-js.mjs) and for
// the dispatch-helper unit tests in test/verifier.test.mjs. The browser path
// uses the side-effect listeners further down. setBlockstreamLookupEnabled
// is also exported so the UI checkbox + future test harnesses can flip the
// opt-in (issue: prior regression — flag was defined but unreachable).
export {
  extractSignatures, verifySignature, parseCms, parseCertificate,
  OID, DIGEST_INFO, SIGALG_INFO, CURVE_INFO,
  setBlockstreamLookupEnabled,
  findBitcoinAttestation,
  tryUpgradeOtsTimestamp,
  evaluateEmbeddedOtsProof,
  DEFAULT_OTS_CALENDARS,
  BTC_ATTESTATION_TAG,
  // Lower-level helpers — exported for test/verifier.test.mjs to exercise
  // edge-case paths (BER indefinite-length parsing, loose-DigestInfo RSA
  // verify) without re-implementing them in the test. The bigint helpers are
  // exported so the test crafts signatures with the SAME modexp the
  // production loose-verify uses — not a divergent copy.
  readTlv, readLength, childrenOf, rsaPkcs1V15LooseVerify,
  base64UrlToBigInt, bytesToBigInt, bigIntToBytes, modPow,
  // Stage 6E — exported so test/verifier.test.mjs can exercise the embedded
  // WebAuthn passkey-assertion re-verification directly.
  cborReadCoseKey, verifyEmbeddedWebauthnAssertion,
  // Exported so test/verifier.test.mjs can pin the platform-seal identity gate:
  // the evidence transplant-check exception must be bound to the real FreeSign
  // Platform Seal cert identity, never to "is self-signed" alone.
  looksLikePlatformSeal,
};

// -----------------------------------------------------------------------------
// UI wiring — only runs in the browser.
// -----------------------------------------------------------------------------

if (typeof document === "undefined") {
  // Imported in Node for testing; skip the DOM section.
} else if (document.getElementById("verify-dropzone")) {
  // Only the /verify page carries #verify-dropzone. public/main.js imports
  // this module purely for extractSignatures + verifySignature (the post-seal
  // self-check) and must NOT trigger the verifier's drop-zone UI wiring.
  bindUi();
}

function bindUi() {
const els = {
  dropzone: document.getElementById("verify-dropzone"),
  file: document.getElementById("verify-file"),
  status: document.getElementById("verify-status"),
  results: document.getElementById("verify-results"),
  template: document.getElementById("verify-result-template"),
};

function setStatus(msg, kind = "info") {
  if (!msg) {
    els.status.hidden = true;
    return;
  }
  els.status.hidden = false;
  els.status.textContent = msg;
  els.status.classList.toggle("is-error", kind === "error");
  els.status.classList.toggle("is-ok", kind === "ok");
  // A caveat banner (e.g. self-signed leaf): deliberately NOT green. Falls back
  // to neutral styling where .is-warn is unstyled — the point is to withhold the
  // reassuring green "valid" presentation, not to look like an error.
  els.status.classList.toggle("is-warn", kind === "warn");
}

function setPanelStatus(value, pill, done = false) {
  const valueEl = document.getElementById("verify-panel-status-value");
  const pillEl = document.getElementById("verify-panel-status-pill");
  if (valueEl) valueEl.textContent = value;
  if (pillEl) {
    pillEl.textContent = pill;
    pillEl.classList.toggle("is-done", done);
  }
}

function setPanelStatusInitial() {
  const valueEl = document.getElementById("verify-panel-status-value");
  const pillEl = document.getElementById("verify-panel-status-pill");
  if (valueEl) {
    valueEl.replaceChildren(
      Object.assign(document.createElement("span"), {
        className: "panel-status-value-long",
        textContent: "Drop a PDF to run five checks locally",
      }),
      Object.assign(document.createElement("span"), {
        className: "panel-status-value-short",
        textContent: "Drop PDF to check locally",
      }),
    );
  }
  if (pillEl) {
    pillEl.textContent = "WAITING";
    pillEl.classList.remove("is-done");
  }
}

function makeResultBlock(sigIndex, sigCount) {
  const frag = els.template.content.cloneNode(true);
  const block = frag.querySelector(".verify-result-block");
  block.dataset.sigIndex = String(sigIndex);
  const heading = block.querySelector("[data-field='heading']");
  if (sigCount > 1) {
    heading.innerHTML = `Signature <span class="sig-index">${sigIndex + 1} of ${sigCount}</span>`;
  } else {
    heading.textContent = "Signature details";
  }
  els.results.appendChild(block);
  return block;
}

function renderCheck(checkEl, state, summary, detail) {
  checkEl.classList.remove("is-green", "is-yellow", "is-red", "is-grey");
  const icon = checkEl.querySelector(".verify-check-icon");
  if (state === "ok") {
    checkEl.classList.add("is-green");
    icon.textContent = "✓"; // check mark
  } else if (state === "warn") {
    checkEl.classList.add("is-yellow");
    icon.textContent = "⚠"; // warning sign
  } else if (state === "fail") {
    checkEl.classList.add("is-red");
    icon.textContent = "✗"; // ballot X
  } else if (state === "info") {
    checkEl.classList.add("is-grey");
    icon.textContent = "○"; // hollow circle — "not applicable / not used by this signature"
  } else if (state === "waiting") {
    checkEl.classList.add("is-grey");
    icon.textContent = "⏳"; // hourglass — anchor in progress, Bitcoin confirmation pending (~1h)
  } else {
    checkEl.classList.add("is-grey");
    icon.textContent = "…"; // ellipsis (pending)
  }
  checkEl.querySelector("[data-field='summary']").textContent = summary;
  checkEl.querySelector("[data-field='detail']").textContent = detail || "";
}

function fillSummary(block, summary) {
  const summaryEl = block.querySelector(".verify-summary");
  if (!summaryEl) return;
  for (const [k, v] of Object.entries(summary)) {
    const dd = summaryEl.querySelector(`[data-field='${camelToKebab(k)}']`);
    if (dd) dd.textContent = v;
  }
  summaryEl.hidden = false;
}

function camelToKebab(s) {
  return s.replace(/[A-Z]/g, (m) => "-" + m.toLowerCase());
}

function renderResultIntoBlock(block, result) {
  fillSummary(block, result.summary);
  const cmsSummary = {
    ok:   `${result.summary.sigAlg} verified; messageDigest matches the ByteRange digest.`,
    fail: "Signature failed to verify — see details.",
    info: "Signature not evaluated.",
    warn: "Signature verified with caveats — see details.",
  };
  const chainSummary = {
    ok:   `Leaf chains to "${result.summary.caSubject}"; signature on TBSCertificate verifies; validity windows cover the signing time.`,
    fail: "Chain check failed — see details.",
    info: "Leaf cert present; intermediate / root not embedded in CMS. Common for AATL-anchored signatures.",
    warn: "Self-signed leaf — identity claims in the cert are NOT third-party-attested.",
  };
  const tstSummary = {
    ok:   "RFC 3161 timestamp present and verified against the outer signature.",
    fail: "RFC 3161 timestamp is present but broken — see details.",
    info: "No RFC 3161 timestamp embedded (PAdES-B-B). Valid PAdES — just no third-party attested signing time.",
    warn: "RFC 3161 timestamp present with caveats — see details.",
  };
  const otsSummary = {
    ok: `OpenTimestamps Bitcoin attestation confirmed (block ${result.checks.ots.blockHash || "resolved"}). The verifier queries public calendars when the PDF still embeds a calendar-only snapshot.`,
    fail: "OpenTimestamps proof is present but broken — see details.",
    waiting: "OpenTimestamps proof matches the document; public calendars were queried and Bitcoin confirmation is still pending (usually within about an hour of signing). Doesn't reduce signature validity.",
    info: "OpenTimestamps anchor not evaluated as cryptographically green here (absent, marker-without-block-hash, or shape-only check). Doesn't reduce signature validity. Details below explain which case.",
    warn: "OpenTimestamps anchor with caveats — see details.",
  };
  const evidenceSummary = {
    ok:   "FreeSign evidence record embedded in this signer's CMS — its primary signature re-verifies against the embedded public key.",
    fail: "FreeSign evidence record is present but did not re-verify — see details.",
    info: "No FreeSign evidence record embedded. Pre-embedding or non-FreeSign signatures don't carry one; doesn't reduce signature validity.",
    warn: "FreeSign evidence record embedded but incomplete — see details.",
  };
  renderCheck(block.querySelector("[data-check='cms']"),   result.checks.cms.state,   cmsSummary[result.checks.cms.state]     || "", result.checks.cms.detail);
  renderCheck(block.querySelector("[data-check='chain']"), result.checks.chain.state, chainSummary[result.checks.chain.state] || "", result.checks.chain.detail);
  renderCheck(block.querySelector("[data-check='tst']"),   result.checks.tst.state,   tstSummary[result.checks.tst.state]     || "", result.checks.tst.detail);
  renderCheck(block.querySelector("[data-check='ots']"),   result.checks.ots.state,   otsSummary[result.checks.ots.state]     || "", result.checks.ots.detail);
  renderCheck(block.querySelector("[data-check='evidence']"), result.checks.evidence.state, evidenceSummary[result.checks.evidence.state] || "", result.checks.evidence.detail);
  updateAatlTile(block, result);
}

async function handleFile(file) {
  if (!file || typeof file !== "object" || typeof file.arrayBuffer !== "function") {
    setStatus("Drop one PDF file (folder/text-drag not supported).", "error");
    setPanelStatusInitial();
    return;
  }
  if (file.size > MAX_PDF_BYTES) {
    setStatus(`That PDF is ${formatBytes(file.size)} — over the ${formatBytes(MAX_PDF_BYTES)} cap. Refusing to load it in-memory.`, "error");
    setPanelStatus("File too large to verify in-browser", "ERROR");
    return;
  }
  setStatus(`Verifying ${file.name} (${formatBytes(file.size)}) — fully in this browser, no upload.`);
  setPanelStatus("Running CMS · X.509 · RFC 3161 · OpenTimestamps · evidence checks…", "CHECKING");
  // Clear previous results.
  while (els.results.firstChild) els.results.removeChild(els.results.firstChild);
  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    if (buf.length < 5 || buf[0] !== 0x25 || buf[1] !== 0x50 || buf[2] !== 0x44 || buf[3] !== 0x46) {
      throw new Error("File does not start with %PDF — not a PDF.");
    }
    const sigs = extractSignatures(buf);
    if (sigs.length === 0) throw new Error("No /Sig dict found in this PDF. It may be unsigned, or signed with a flavor this page doesn't understand.");
    // Multi-signature: render ONE result block per /Sig in document order.
    // Earlier revisions come first; the latest revision sits at the bottom.
    // Each block is fully independent — the cert chain, TST, OTS for sig #1
    // may differ from sig #2 (different signers, different times, possibly
    // different vendors entirely if the document was countersigned).
    let priorBroken = null;
    let priorExpired = null;
    let anyFail = false;
    let allCoreOk = true;
    let anyCaveat = false; // a non-fatal warn (e.g. self-signed leaf) — green banner is withheld
    // Envelope ids pulled from embedded FreeSign evidence records — handed to
    // verify-audit.js after the loop so it can fetch + re-verify the audit
    // chain. All signers of one document share one envelope, so this collects
    // at most one id in practice.
    const auditEnvelopeIds = [];
    for (let i = 0; i < sigs.length; i += 1) {
      const block = makeResultBlock(i, sigs.length);
      try {
        const result = await verifySignature(sigs[i]);
        renderResultIntoBlock(block, result);
        // Audit handoff: use the SIGNED canonical_payload.envelope_id (covered by
        // the evidence record's own ECDSA signature we just re-verified), never
        // the UNSIGNED top-level evidence.envelope_id (an attacker can repoint
        // that in the CMS unsignedAttribute without breaking any signature).
        // Only hand off when the evidence check actually passed.
        if (result.checks?.evidence?.state === "ok") {
          const evEnvId = result.checks?.evidence?.data?.canonical_payload?.envelope_id;
          if (typeof evEnvId === "string" && /^env_[a-f0-9]{32}$/.test(evEnvId) && !auditEnvelopeIds.includes(evEnvId)) {
            auditEnvelopeIds.push(evEnvId);
          }
        }
        const sigFail = result.checks.cms.state === "fail"
          || result.checks.chain.state === "fail"
          || result.checks.tst.state === "fail"
          || result.checks.ots.state === "fail"
          || result.checks.evidence.state === "fail";
        // "warn" (e.g. a self-signed leaf whose identity is self-asserted) is NOT
        // a green outcome — anyone can mint a self-signed cert claiming any name.
        // Treat warn as a caveat that withholds the green "valid" banner, while
        // not being an outright failure. Only ok/info count toward all-core-ok.
        const sigCoreOk = result.checks.cms.state === "ok"
          && (result.checks.chain.state === "ok" || result.checks.chain.state === "info");
        const sigCaveat = result.checks.cms.state === "warn"
          || result.checks.chain.state === "warn"
          || result.checks.tst.state === "warn"
          || result.checks.ots.state === "warn"
          || result.checks.evidence.state === "warn";
        if (sigFail) anyFail = true;
        if (sigCaveat) anyCaveat = true;
        if (!sigCoreOk) allCoreOk = false;
        // Surface earlier-revision tampering vs cert-expiry separately:
        // tampering breaks documents, expiry is normal long-lived aging.
        if (i < sigs.length - 1) {
          const cmsTampered = result.checks.cms.state === "fail" && /messageDigest|signature verification failed/i.test(result.checks.cms.detail);
          const chainForged = result.checks.chain.state === "fail" && /signature did not verify|signature failed cryptographic/i.test(result.checks.chain.detail);
          const chainExpired = result.checks.chain.state === "fail" && /not valid at signing time/i.test(result.checks.chain.detail);
          if (!priorBroken && (cmsTampered || chainForged)) {
            priorBroken = { index: i + 1, total: sigs.length, detail: result.checks.cms.detail || result.checks.chain.detail };
          } else if (!priorExpired && chainExpired) {
            priorExpired = { index: i + 1, total: sigs.length, detail: result.checks.chain.detail };
          }
        }
      } catch (e) {
        // Per-sig hard failure (parse error etc.) — render the block with
        // all tiles as fail and continue to the next sig. parseErrorResult
        // carries every check key the renderer reads, so one bad signature
        // cannot abort the remaining signatures' blocks.
        renderResultIntoBlock(block, parseErrorResult(e.message));
        anyFail = true;
        allCoreOk = false;
        if (i < sigs.length - 1 && !priorBroken) {
          priorBroken = { index: i + 1, total: sigs.length, detail: e.message };
        }
      }
    }

    if (priorBroken) {
      setStatus(`Verification complete — signature ${priorBroken.index} of ${priorBroken.total} (earlier revision) did NOT verify: ${priorBroken.detail}.`, "error");
      setPanelStatus("Earlier revision failed — expand tiles for detail", "FAIL");
    } else if (anyFail) {
      setStatus("Verification complete — one or more checks did not pass. Expand each tile for details.", "error");
      setPanelStatus("One or more checks did not pass", "REVIEW");
    } else if (anyCaveat) {
      // Cryptographically intact, but carrying a trust caveat (e.g. a self-signed
      // leaf). NOT a green banner: the signer identity is self-asserted, so the
      // recipient must confirm the cert fingerprint out of band before trusting it.
      setStatus(`Verification complete — ${sigs.length === 1 ? "the signature is cryptographically intact" : `all ${sigs.length} signatures are cryptographically intact`}, but at least one carries a trust caveat (e.g. a self-signed certificate whose identity is NOT third-party-attested). Expand the certificate-chain tile and confirm the signer identity out of band.`, "warn");
      setPanelStatus("Cryptographically intact — review identity (self-asserted / not trust-anchored)", "REVIEW");
    } else if (allCoreOk) {
      const expiredNote = priorExpired ? ` Note: signature ${priorExpired.index} of ${priorExpired.total}'s cert expired post-signing (legitimate aging, not tampering).` : "";
      setStatus(`Verification complete — ${sigs.length === 1 ? "signature is valid" : `all ${sigs.length} signatures verify`}.${expiredNote}`, "ok");
      setPanelStatus("CMS · X.509 · RFC 3161 · OpenTimestamps · evidence — core checks passed", "PASS", true);
    } else {
      setStatus("Verification complete — see per-signature details.", "info");
      setPanelStatus("Verification finished — see per-signature details", "REVIEW");
    }
    // Hand off any envelope ids to verify-audit.js (loaded only on /verify) so
    // it can fetch + re-verify the server-side audit chain. The event is inert
    // when no listener is registered.
    document.dispatchEvent(new CustomEvent("freesign:verify-complete", {
      detail: { envelopeIds: auditEnvelopeIds },
    }));
  } catch (e) {
    setStatus("Could not verify: " + e.message, "error");
    setPanelStatus("Could not verify this file", "ERROR");
  }
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function updateAatlTile(block, result) {
  const el = block.querySelector("[data-check='aatl']");
  if (!el) return;
  const body = el.children[1];
  if (!body) return;
  const caSubject = (result.summary && result.summary.caSubject) || "";
  const chainState = result.checks && result.checks.chain && result.checks.chain.state;
  const isFreeSign = /FreeSign CA/i.test(caSubject);

  // Self-signed leaf — there's no third-party issuer for AATL to vouch for;
  // recipient must trust the cert fingerprint out of band.
  if (chainState === "warn") {
    const isSeal = !!(result.summary && result.summary.platformSeal);
    body.innerHTML = `<h3>Adobe Reader AATL trust</h3>
      <p>${isSeal
        ? "This document carries the <strong>FreeSign platform e-seal</strong> on a self-signed certificate. AATL is a list of trusted third-party CAs &mdash; it doesn't apply to an organisational seal. Adobe Reader will show a yellow triangle; a recipient confirms the seal is genuinely FreeSign's by checking its certificate fingerprint out of band."
        : "This signer used a <strong>self-signed certificate</strong>. AATL is a list of trusted third-party CAs &mdash; it doesn't apply here. Adobe Reader will show a yellow triangle, and there is no &ldquo;add this CA to AATL&rdquo; path. The recipient has to explicitly trust the cert fingerprint out of band before Reader will go green."}</p>
      <div class="verify-cta-row">
        <a href="/faq#adobe">Why yellow &ne; invalid for self-signed</a>
      </div>`;
    return;
  }
  // CA not embedded in the CMS (chain state = info) — we can't say anything
  // about AATL membership without the issuer cert.
  if (chainState === "info" || !caSubject || /^\(/.test(caSubject)) {
    body.innerHTML = `<h3>Adobe Reader AATL trust</h3>
      <p>This signature's issuer cert isn't embedded in the CMS, so this page can't report on AATL membership directly. Adobe Reader will use its local trust store to decide whether to show green or yellow &mdash; depends on what's installed locally / shipped in the Reader AATL bundle.</p>
      <div class="verify-cta-row">
        <a href="/faq#adobe">Why Adobe trust status is separate from cryptographic validity</a>
      </div>`;
    return;
  }
  if (isFreeSign) {
    body.innerHTML = `<h3>Adobe Reader AATL trust</h3>
      <p>Adobe Reader shows a yellow triangle because the <strong>FreeSign CA</strong> is not on the Adobe Approved Trust List. The signature is cryptographically valid &mdash; this is a UX warning about issuer recognition, not a verification failure. Repeat recipients can add the FreeSign CA to local Adobe trust:</p>
      <div class="verify-cta-row">
        <a class="button-primary" href="/guides/trust-freesign-in-adobe">FreeSign Adobe Trust Setup</a>
        <a href="/faq#adobe">Why yellow &ne; invalid</a>
      </div>`;
    return;
  }
  body.innerHTML = `<h3>Adobe Reader AATL trust</h3>
    <p>Whether this signature shows a green check in Adobe Reader depends on whether <strong>${escapeHtml(caSubject)}</strong> is on the Adobe Approved Trust List (AATL) or in your local Adobe trust store. This page does not make AATL trust decisions &mdash; ask your Adobe Reader or check Adobe&rsquo;s AATL listing directly. The cryptographic checks above are independent of AATL.</p>
    <div class="verify-cta-row">
      <a href="/faq#adobe">Why Adobe trust status is separate from cryptographic validity</a>
    </div>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}

els.dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  els.dropzone.classList.add("is-drag");
});
els.dropzone.addEventListener("dragleave", () => els.dropzone.classList.remove("is-drag"));
els.dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  els.dropzone.classList.remove("is-drag");
  // Reject empty drops (text, links, folders w/o files) explicitly instead
  // of silently doing nothing. Surfaces a friendly status message instead
  // of leaving the user wondering why the drop didn't react.
  if (!e.dataTransfer || !e.dataTransfer.files || e.dataTransfer.files.length === 0) {
    setStatus("Drop a single PDF file. Folders, links, and text aren't accepted.", "error");
    return;
  }
  if (e.dataTransfer.files.length > 1) {
    setStatus("Drop only one PDF at a time. Verifying the first; ignoring the rest.", "info");
  }
  handleFile(e.dataTransfer.files[0]);
});
els.file.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) handleFile(file);
});
}  // bindUi
