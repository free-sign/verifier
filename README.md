# FreeSign Verifier

The open-source verifier **library** for [FreeSign](https://free-sign.com)
signed PDFs.

This repository contains the **exact verification code** that runs at
**[free-sign.com/verify](https://free-sign.com/verify)** — published so anyone
can read it, audit it, and run it offline to check a FreeSign-signed PDF
**without trusting the FreeSign service at all**.

It is an ES-module library: no UI, no framework, no build step. It runs
unchanged in a browser and in Node ≥ 18 (both provide the WebCrypto, `fetch`,
`btoa` and `AbortSignal.timeout` globals it uses). Every classical check runs on
those built-ins alone — the single dependency, `@noble/post-quantum`, is
imported lazily and only when a PDF carries the ML-DSA post-quantum
co-signature. The PDF you check never leaves your machine.

> **This is a generated mirror.** The library files (`verify.js`,
> `ots-timestamp.js`, `audit-verify.js`, `session.js`) are copied **byte-for-byte**
> from the FreeSign codebase that serves `/verify` — so the code you audit here is
> the code that actually checks signatures. **Do not edit them here**; fixes go
> upstream and are re-published. Only the `examples/` and this README are
> repo-specific.

---

## Quick start (Node)

```sh
git clone https://github.com/free-sign/verifier.git
cd verifier
node examples/verify-pdf.mjs path/to/signed.pdf
```

No `npm install` for the classical checks — they run on Node built-ins alone.
Only the post-quantum check needs one dependency (`@noble/post-quantum`, loaded
lazily); without it that check reports a caveat and every other check still runs.
You need Node ≥ 18.

```
Signatures found: 1

Signature 1 — Jane Doe <jane@example.com>
  CMS signature        ✓ ok
  Certificate chain    ✓ ok
  RFC 3161 timestamp   ✓ ok
  OpenTimestamps       ✓ ok
  Embedded evidence    ✓ ok
  Post-quantum (ML-DSA)✓ ok
  ...
PASS: every signature is cryptographically intact (CMS + certificate chain).
```

Re-derive the tamper-evident audit chain yourself:

```sh
# from a saved API response or a bare events array:
node examples/verify-audit-chain.mjs events.json
# or pull it live (raw + unauthenticated by design):
node examples/verify-audit-chain.mjs --envelope env_0123…  --base https://free-sign.com
```

The same files also load directly in a browser as ES modules (`import` from
`verify.js`); this repo just ships them without a page wrapped around them.

---

## Library API

```js
import { extractSignatures, verifySignature } from "./verify.js";
import { verifyAuditChain } from "./audit-verify.js";

const bytes = new Uint8Array(/* the PDF */);
const sigs = extractSignatures(bytes);          // one entry per CMS signature
for (const sig of sigs) {
  const result = await verifySignature(sig);
  // result.checks.{cms,chain,tst,ots,evidence,pq} → { state, ok, detail }
  // result.summary.{signerName,signerEmail,signingTime,cmsProfile,caSubject,…}
}

// Audit chain (events from GET /api/envelopes/{id}/audit):
const verdict = await verifyAuditChain(events, attestedHeadHash /* optional */);
// → { valid, event_count, broken_at, reason, head_checked, head_match, events }
```

`verify.js` also exports the lower-level primitives it is built from (`parseCms`,
`parseCertificate`, the OID/algorithm tables, the OpenTimestamps helpers
`evaluateEmbeddedOtsProof` / `findBitcoinAttestation`, and the WebAuthn assertion
verifier) for callers that want to inspect a signature piece by piece. See the
source — it is short and commented.

**Integrity vs. trust — two separate verdicts.** `cms` + `chain` answer *is the
maths valid and the document unmodified?* — a pure cryptographic fact. They do
**not** depend on whether your software already trusts the FreeSign CA. FreeSign
runs its own CA, which is **not** on the Adobe Approved Trust List, so Adobe
Reader shows a yellow banner by default — a *trust-list* statement, not an
*integrity* failure. A FreeSign signature can be cryptographically perfect and
still show "not trusted" until you add the FreeSign CA to your trust store.

---

## For AI agents

An [Agent Skill](./free-sign-agent/SKILL.md) ships in this repo
(`free-sign-agent/SKILL.md`). It teaches an AI agent how to **verify** a
FreeSign PDF offline with the library above, and how to **sign** one by driving
the hosted ceremony at free-sign.com without ever uploading the PDF. Drop it
into a Claude / agent skills directory, or just read it as a concise operator's
guide to both flows.

---

## What it verifies

For **each signature** in the PDF:

| Check | What it establishes |
|-------|---------------------|
| **CMS signature** (PKCS#7, RFC 5652) | The signed byte range hashes to exactly what the signer's key signed — content unmodified since signing. |
| **Certificate chain** | The per-signer X.509 leaf certificate chains to the FreeSign signing CA; Subject CN = typed name, SAN = OTP-verified e-mail. |
| **RFC 3161 timestamp** | An independent DigiCert timestamp authority attests *when* the signature was made (PAdES-B-T). |
| **OpenTimestamps proofs** | Independent timestamps anchored into the Bitcoin blockchain — datable even if FreeSign and DigiCert both vanish. A FreeSign seal carries two, both reported under this one verdict: one over the signed document (`…65834.1.1`) and one over the CMS SignedAttributes (`…65834.1.5`, surfaced as `checks.ots.signedAttrs`) — the latter is what dates the post-quantum key commitment. When an embedded proof is still calendar-only, the verifier queries public OTS calendars for the Bitcoin upgrade before reporting. |
| **Embedded evidence record** | The consent text, identity method (OTP or passkey), canonical signed payload and request fingerprint FreeSign embedded inside the signature (CMS **signed** attribute `1.3.6.1.4.1.65834.1.2`, under FreeSign's PEN — editing it invalidates the CMS signature; a record found only in the unsigned set is rejected). |
| **Post-quantum co-signature** | A second signature over the same signed attributes, made with ML-DSA (FIPS 204). Present only on documents sealed with the post-quantum option on; its public key is committed to *inside* the signed attributes, so the classical signature is what binds it to the signer. Verified with [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — the one check that needs `npm install`; every other check runs on Node built-ins. |
| **Audit hash chain** | `verifyAuditChain` replays the per-document event log; every event is hash-chained to the previous one, and the optional attested head catches a re-forged but internally consistent chain. |

For the full signing & cryptography model (ephemeral leaf certs under an
HSM-backed CA, the two browser-held signatures, PAdES-B-LT/DSS long-term
validation), see **[free-sign.com/trust](https://free-sign.com/trust)**.

---

## Trust model & honest limitations

- **Not a Qualified Electronic Signature (QES).** A FreeSign signature is valid
  under the US ESIGN Act / UETA and built to the EU eIDAS **advanced** electronic
  signature (AES) evidence model. It is **not** a QES, and the operator is not a
  Qualified Trust Service Provider.
- **Not on the Adobe AATL.** Adobe Reader shows a yellow trust banner by default
  — trust-list membership, not document integrity.
- **The hosted signing service is closed-source**, best-effort, no warranty, no
  third-party SOC/ISO audit published yet. This *verifier* is open source
  precisely so the security-critical half needs no one's word.
- **The verifier checks cryptography, not law.** A valid signature is evidence;
  legal effect depends on context and jurisdiction. Not legal advice.

---

## Cross-check with other tools

A FreeSign PDF is a standard PAdES-B-T document, so independent tools agree.

**OpenSSL** can't read a PDF directly (`-inform` accepts only DER/PEM/SMIME, not
`PDF`). You must first extract the embedded CMS/PKCS#7 from the signature dict and
the signed ByteRange content, then verify the detached signature over that
content — exactly what `tools/validate-sealed-pdf.mjs` does in this codebase:

```sh
# After extracting the CMS blob to sig.der and the signed bytes to content.bin
# (see the walkthrough for the extraction step):
openssl cms -verify -in sig.der -inform DER -content content.bin -noverify   # CMS structural + content match
```

Full extract-then-verify walkthrough:
<https://free-sign.com/guides/verify-signed-pdf-with-openssl>

```sh
pyhanko sign validate --pretty-print signed.pdf            # PAdES validation
```

**OpenTimestamps:** the embedded FreeSign `.ots` proofs commit to the signature's
**ByteRange SHA-256** (the bytes the CMS signs) and to **SHA-256 of the CMS
SignedAttributes** — **not** to `SHA-256(signed.pdf)`. So a bare
`ots verify signed.pdf.ots` verifies the wrong digest and will not match. Fetch a
proof from the receipt's proof URL
(`/api/envelopes/{id}/anchors/{anchor_id}/proof.ots`; `/api/receipts/{id}` lists
both anchors with their `kind`) and verify it against the digest that anchor
claims — for the document anchor, the one the verifier reports as
`result.summary.byteRangeSha256`:

```sh
# Verify the OTS proof against the ByteRange digest (hex), not the whole file:
ots verify -d <byteRangeSha256-hex> proof.ots
```

The Node example (`verify-pdf.mjs`) already evaluates the embedded proof for you
against the correct digest; the CLI above is only for an independent cross-check.

---

## What is deliberately not in this repository

The verifier is the complete trust-critical path and needs nothing else. It does
**not** contain the FreeSign server, the signing-ceremony backend, any secret or
key material, or operational internals. Verification relies only on public
standards (PAdES, CMS, X.509, RFC 3161, OpenTimestamps) and the **published**
FreeSign CA certificate:

- PEM: <https://free-sign.com/.well-known/free-sign-signing-ca.pem>
- SHA-256: <https://free-sign.com/.well-known/free-sign-signing-ca.sha256.txt>

---

## Reporting a problem

- **Security issues:** <https://free-sign.com/.well-known/security.txt>
- **General contact:** support@coderai.dev

If this verifier ever reports a FreeSign-signed PDF as valid when it is not — or
invalid when it is — that is a security bug. Please report it.

---

## License

[MIT](./LICENSE) © 2026 2Dynamic Games sp. z o.o. (Coder AI), Kraków, Poland.

The hosted FreeSign service is a separate, proprietary product. This license
covers the verifier code in this repository.
