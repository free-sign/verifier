# FreeSign Verifier

The open-source, client-side verifier for [FreeSign](https://free-sign.com)
signed PDFs.

This repository contains the **exact verification code** served at
**[free-sign.com/verify](https://free-sign.com/verify)** — published so that
anyone can read it, audit it, run it offline, and check a FreeSign-signed PDF
**without trusting the FreeSign service at all**.

It runs **100% in your browser**. No upload, no backend, no account, no
telemetry. The PDF you check never leaves your machine.

---

## Why this is open source

FreeSign's hosted *signing* service is closed-source. The **verification path is
not** — and that split is deliberate.

The whole point of a FreeSign signature is that its validity does **not** depend
on trusting FreeSign. That promise is only credible if the code that *checks* the
signature is something you can read, audit and run yourself. This repository is
that code.

You do not even strictly need this verifier: a FreeSign signed PDF is a standard
**PAdES-B-T** document that Adobe Reader, `openssl` and `pyHanko` also verify
(see [Cross-check with other tools](#cross-check-with-other-tools)). This verifier
simply makes the *full* check — including the FreeSign-specific evidence record
and audit chain — a single drag-and-drop, with no software to install.

---

## Quick start

```sh
git clone https://github.com/free-sign/verifier.git
cd verifier
python3 -m http.server 8000
# then open http://localhost:8000/verify.html and drop in a signed PDF
```

Browser ES modules require an HTTP origin, so a static file server is needed
(`file://` will not work). Any static server does — `python3 -m http.server`,
`npx serve`, `caddy file-server`, etc.

**Nothing is sent anywhere.** Open DevTools → Network and watch: once the page
has loaded, verifying a PDF makes **zero** network requests. You can also unplug
from the network entirely and it still works.

Prefer not to clone? The identical code runs at
[free-sign.com/verify](https://free-sign.com/verify).

---

## What it verifies

Drop in a signed PDF and the verifier reports, **for each signature** in the file:

| Check | What it establishes |
|-------|---------------------|
| **PDF revisions** | Each signature covers a genuine incremental-update revision; any later change to the file appears as a separate, attributable revision rather than silently altering signed content. |
| **CMS signature** (PKCS#7, RFC 5652) | The signed byte range hashes to exactly what the signer's key signed — the document content has not been modified since signing. |
| **Certificate chain** | The per-signer X.509 leaf certificate chains to the FreeSign signing CA. |
| **Signer identity** | The signer's typed legal name (certificate Subject CN) and OTP-verified e-mail address (certificate Subject Alternative Name). |
| **RFC 3161 timestamp** | An independent DigiCert timestamp authority attests *when* the signature was made (PAdES-B-T). |
| **OpenTimestamps proof** | An independent timestamp anchored into the Bitcoin blockchain's block headers — datable even if FreeSign and DigiCert both vanish. |
| **Embedded evidence record** | The consent text, identity method (OTP or passkey), canonical signed payload and request fingerprint that FreeSign embedded inside the signature. |
| **Audit hash chain** | The per-document tamper-evident event log replays consistently — every event is hash-chained to the previous one. |
| **Dual signature** | The same browser-held key signed both the *intent* payload and the *final* PDF — a post-consent swap of the file is detectable. |

### Integrity vs. trust — two separate verdicts

The verifier deliberately separates two questions that consumer PDF readers tend
to blur together:

- **Integrity** — *is the maths valid and the document unmodified?* This is a
  pure cryptographic fact. It does not depend on anyone's opinion.
- **Trust** — *is the issuing CA one your software already trusts?* FreeSign runs
  its own CA, which is **not** on the Adobe Approved Trust List (AATL). So Adobe
  Reader shows a yellow banner by default — that is a *trust-list* statement, not
  an *integrity* failure.

A FreeSign signature can be **cryptographically perfect** (integrity ✓) and still
show as "not trusted" until you add the FreeSign CA to your local trust store.
The verifier shows both verdicts so you are never misled by a single colour.

---

## The FreeSign signing & cryptography model

This section explains, at the level a security reviewer needs, how a FreeSign
signature is produced and what each part guarantees. It describes only the
**public, standards-based design** — see
[What is deliberately not here](#what-is-deliberately-not-in-this-repository).

### 1. The document never leaves your browser

The PDF is hashed **locally**, in the browser, with the WebCrypto API. Only the
resulting 32-byte SHA-256 digests are ever sent to the server — never the
document bytes. There is no upload endpoint; the API and the MCP contract both
advertise `documentUpload: false`. The server is structurally incapable of
reading what you signed.

### 2. Signer identity

Identity is established by **e-mail one-time-passcode (OTP)**: the signer proves
control of an inbox at signing time. Optionally, a **WebAuthn passkey** can be
enrolled as an additional identity factor (Touch ID / Windows Hello / a security
key). The passkey is an *identity* layer only — it is **not** the key that signs
the PDF — and FreeSign only ever stores its public half.

### 3. The browser-held evidence key

At the start of a signing session the browser generates a **non-extractable
ECDSA P-256 key pair** and stores it in IndexedDB. It cannot be exported by
script. Every privileged request in the ceremony is signed with it
(envelope-scoped session binding), and its public half is recorded as evidence.
This proves the whole ceremony ran in one consistent browser context.

### 4. The seal — PAdES-B-T / CMS PKCS#7

When the document is sealed, the server-side ceremony:

1. generates a **fresh, ephemeral ECDSA P-256 key pair** for this one signature —
   it is never written to disk, never returned, and is destroyed when the
   ceremony ends;
2. issues a per-signature **X.509 leaf certificate** for that key under the
   FreeSign signing CA, with the signer's typed name in the Subject and the
   verified e-mail in the Subject Alternative Name;
3. signs the PDF's signed attributes (the `ByteRange` digest, signing time, and a
   `signingCertificateV2` binding) producing a **CMS PKCS#7** signature
   (RFC 5652, ECDSA-with-SHA-256);
4. requests an **RFC 3161 timestamp token** from a public timestamp authority
   (DigiCert) and embeds it — upgrading the signature to **PAdES-B-T**;
5. assembles the CMS with the leaf and CA certificates included, and writes it
   into the PDF as an **incremental update** (the original bytes are never
   rewritten).

The output is a standard signed PDF. Nothing about it is proprietary.

### 5. The certificate authority (HSM-backed)

The FreeSign signing CA's private key lives in a **hardware security module** —
Google Cloud KMS, FIPS 140-2 Level 3. It is non-exportable. The HSM signs only
the digest of each leaf certificate's to-be-signed block; it never sees the PDF,
the signature, or any personal data. The CA certificate itself is public:

- PEM: <https://free-sign.com/.well-known/free-sign-signing-ca.pem>
- SHA-256 fingerprint: <https://free-sign.com/.well-known/free-sign-signing-ca.sha256.txt>

Publishing the fingerprint lets you pin exactly which CA is allowed to have
issued the certificate in your document.

### 6. Independent timestamps

Signing time is anchored **twice, by parties unrelated to FreeSign**:

- an **RFC 3161** token from DigiCert's timestamp authority, embedded in the CMS;
- an **OpenTimestamps** proof, which settles into the **Bitcoin** blockchain's
  block headers. Even if FreeSign *and* DigiCert disappeared, an OpenTimestamps
  proof remains independently checkable against public block headers with the
  `ots` CLI.

### 7. Two signatures, not one

Every envelope carries **two** ECDSA signatures from the browser-held key:

- a **primary** signature over the canonical *intent* payload (what you agreed
  to, before the PDF was stamped);
- a **final** signature over the *final* payload, which includes the hash of the
  finished PDF.

Because the same key signs both, an attacker who controlled the network between
your browser and the server still could not swap the final PDF after you
consented — the final signature would not match.

### 8. The tamper-evident audit chain

Every step (envelope creation, OTP request, OTP verification, signing, sealing,
finalisation) is recorded as an event whose hash includes the hash of the
previous event. Altering or removing any one event breaks every later hash. The
verifier replays this chain and reports whether it is intact.

### 9. The embedded evidence record

FreeSign embeds a JSON **evidence record** inside the signature's CMS as an
unsigned attribute, under FreeSign's IANA Private Enterprise Number
(`1.3.6.1.4.1.65834`). It carries the consent text, identity method, canonical
signed payload, public key and request fingerprint — so a multi-signer PDF
carries every signer's evidence, travelling with the file itself. Its schema is
public: <https://free-sign.com/guides/evidence-json-schema>.

### 10. Long-term validation

When the deployment publishes a CA revocation list, the seal additionally gets a
**PAdES-B-LT** revision (a `/DSS` dictionary with the certificate and revocation
material), so the file keeps verifying even after the leaf certificate's validity
window eventually elapses.

---

## Trust model & honest limitations

We would rather you verify than assume — so, plainly:

- **Not a Qualified Electronic Signature (QES).** A FreeSign signature is an
  electronic signature valid under the US ESIGN Act / UETA and is built to the EU
  eIDAS **advanced** electronic signature (AES) evidence model. It is **not** a
  QES, and the operator is not a Qualified Trust Service Provider. For documents
  that legally require QES or notarisation, FreeSign is not the right tool.
- **Not on the Adobe Approved Trust List (AATL).** Adobe Reader shows a yellow
  trust banner by default. That is trust-list membership, not document integrity.
- **The hosted service is closed-source and offered best-effort**, with no
  warranty and no third-party SOC/ISO audit published yet. This *verifier* is
  open source precisely so that the security-critical half does not require you
  to take anyone's word for it.
- **The verifier checks cryptography, not law.** A valid signature is evidence;
  whether a given document is legally effective depends on context and
  jurisdiction. Nothing here is legal advice.

More: [free-sign.com/trust](https://free-sign.com/trust) ·
[free-sign.com/faq](https://free-sign.com/faq)

---

## Cross-check with other tools

This verifier should never be your *only* check if the stakes are high. A
FreeSign PDF is a standard signed PDF, so independent tools agree:

```sh
# CMS signature (integrity) — OpenSSL
openssl cms -verify -in signed.pdf -inform PDF -noverify   # structural check

# PAdES validation — pyHanko
pyhanko sign validate --pretty-print signed.pdf

# OpenTimestamps proof — official CLI, against public Bitcoin block headers
ots verify signed.pdf.ots
```

A step-by-step, vendor-independent walkthrough:
<https://free-sign.com/guides/verify-signed-pdf-with-openssl>

---

## What is deliberately not in this repository

This repo is the **verifier** — the client-side, read-only checker. It is the
complete trust-critical path and it needs nothing else.

It deliberately does **not** contain the FreeSign server, the signing-ceremony
backend, any secret or key material, or operational internals (rate-limiting
thresholds, abuse heuristics, infrastructure configuration). None of that is
required to verify a signature — verification relies only on public standards
(PAdES, CMS, X.509, RFC 3161, OpenTimestamps) and the **published** FreeSign CA
certificate. Omitting it keeps this repository safe to publish without handing an
attacker a map.

---

## Reporting a problem

- **Security issues:** see <https://free-sign.com/.well-known/security.txt>
- **General contact:** support@coderai.dev

If this verifier ever reports a FreeSign-signed PDF as valid when it is not — or
invalid when it is — that is a security bug. Please report it.

---

## License

[MIT](./LICENSE) © 2026 2Dynamic Games sp. z o.o. (Coder AI), Kraków, Poland.

The hosted FreeSign service is a separate, proprietary product. This license
covers the verifier code in this repository.
