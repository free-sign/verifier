#!/usr/bin/env node
// Verify a FreeSign-sealed PDF from Node — no browser, no upload, no account.
//
//   node examples/verify-pdf.mjs <signed.pdf>
//
// This is the same verification code that runs at free-sign.com/verify
// (verify.js is shipped verbatim). It needs only Node >= 18: WebCrypto, fetch,
// btoa and AbortSignal.timeout are all global there. The PDF bytes never leave
// this process; the only optional network calls are OpenTimestamps calendar /
// blockstream.info lookups used to confirm the Bitcoin anchor for display.

import { readFileSync } from "node:fs";
import { extractSignatures, verifySignature } from "../verify.js";

const path = process.argv[2];
if (!path) {
  console.error("usage: node examples/verify-pdf.mjs <signed.pdf>");
  process.exit(2);
}

const bytes = new Uint8Array(readFileSync(path));
let sigs;
try {
  sigs = extractSignatures(bytes);
} catch (e) {
  console.error(`Could not parse PDF signatures: ${e.message}`);
  process.exit(1);
}
if (sigs.length === 0) {
  console.error("No CMS signature (/Sig dict) found in this PDF.");
  process.exit(1);
}
console.log(`Signatures found: ${sigs.length}\n`);

// verifySignature returns { checks: { cms, chain, tst, ots, evidence }, summary }.
// Each check has { state, ok, detail }. The full state enum the library emits is
// "ok" | "warn" | "info" | "waiting" | "fail" (cms: ok/warn/fail; chain:
// ok/warn/info/fail; tst/ots: ok/info/fail; ots also "waiting"; evidence:
// ok/warn/info/fail). `ok` is true only when state === "ok".
//
// Fatal-for-integrity classification mirrors free-sign.com/verify: a check fails
// ONLY when its state is "fail". "warn" is a real, distinct outcome (e.g. the
// self-signed freesign_verified_seal platform-seal cert, enabled by default) —
// a valid signature carrying a trust caveat, NOT a failure.
//
// IMPORTANT: a "fail" in ANY of the five load-bearing checks (cms, chain, tst,
// ots, evidence) fails the process — exactly as the hosted /verify sets its
// REVIEW verdict (`sigFail`). The embedded FreeSign evidence and the timestamp
// material are CMS UNSIGNED attributes, so they are NOT covered by the outer
// CMS signature and an attacker can tamper with them while leaving cms+chain
// intact; treating only cms+chain as fatal would silently accept that tamper.
const FATAL = (state) => state === "fail";
const FATAL_CHECKS = ["cms", "chain", "tst", "ots", "evidence"];
const mark = (c) =>
  c.state === "ok" ? "✓ ok"
  : c.state === "warn" ? "⚠ warn"
  : c.state === "waiting" ? "⏳ pending"
  : c.state === "info" ? "· info"
  : "✗ fail";

let allIntegrityOk = true; // no signature has a FATAL state in any of the 5 checks
let anyCaveat = false;     // some non-fatal warn surfaced (trust caveat)
for (let i = 0; i < sigs.length; i += 1) {
  let r;
  try {
    r = await verifySignature(sigs[i]);
  } catch (e) {
    // A throw here (malformed CMS, oversized ByteRange, …) is itself an
    // integrity failure for this signature — record it and keep going.
    console.log(`Signature ${i + 1} — could not be verified: ${e.message}\n`);
    allIntegrityOk = false;
    continue;
  }
  const c = r.checks;
  console.log(`Signature ${i + 1} — ${r.summary.signerName} <${r.summary.signerEmail}>`);
  console.log(`  CMS signature        ${mark(c.cms)}`);
  console.log(`  Certificate chain    ${mark(c.chain)}`);
  console.log(`  RFC 3161 timestamp   ${mark(c.tst)}`);
  console.log(`  OpenTimestamps       ${mark(c.ots)}`);
  console.log(`  Embedded evidence    ${mark(c.evidence)}`);
  console.log(`  Signing time         ${r.summary.signingTime}`);
  console.log(`  Profile              ${r.summary.cmsProfile}`);
  console.log(`  CA subject           ${r.summary.caSubject}`);
  for (const [name, chk] of Object.entries(c)) {
    if (chk.state !== "ok" && chk.detail) console.log(`    ${name}: ${chk.detail}`);
  }
  console.log("");
  // A "fail" in ANY load-bearing check (cms, chain, tst, ots, evidence) fails
  // the verdict — matching the hosted verifier's REVIEW condition. "warn" stays
  // a non-fatal caveat.
  if (FATAL_CHECKS.some((name) => FATAL(c[name].state))) allIntegrityOk = false;
  if (FATAL_CHECKS.some((name) => c[name].state === "warn")) anyCaveat = true;
}

// Note: a clean integrity verdict is independent of Adobe AATL trust-list
// membership — FreeSign runs its own CA, so Adobe Reader shows yellow by design.
if (!allIntegrityOk) {
  console.error("FAIL: at least one signature has a failed load-bearing check (CMS, certificate chain, RFC 3161 timestamp, OpenTimestamps, or embedded evidence).");
  process.exit(1);
}
if (anyCaveat) {
  console.log("PASS (with trust caveat): every load-bearing check (CMS, certificate chain, timestamp, OpenTimestamps, evidence) is intact, but at least one carries a ⚠ warn — e.g. a self-signed / platform-seal cert that is not anchored to a public trust root. Confirm the cert fingerprint out of band.");
} else {
  console.log("PASS: every signature passes all load-bearing checks (CMS, certificate chain, timestamp, OpenTimestamps, evidence).");
}
