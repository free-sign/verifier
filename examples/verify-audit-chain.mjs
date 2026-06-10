#!/usr/bin/env node
// Re-derive a FreeSign audit-chain verdict yourself — don't trust the server's.
//
//   node examples/verify-audit-chain.mjs <events.json>
//   node examples/verify-audit-chain.mjs --envelope env_<32hex> [--base https://free-sign.com]
//
// GET /api/envelopes/{id}/audit returns the raw, unauthenticated event list (and
// the signer-attested chain head) precisely so a recipient can replay it locally
// with verifyAuditChain — the same code the /verify page runs. A file argument
// accepts either a bare array of events or the full API response object.

import { readFileSync } from "node:fs";
import { verifyAuditChain } from "../audit-verify.js";

const args = process.argv.slice(2);

function flag(name) {
  const i = args.indexOf(name);
  return i !== -1 && i + 1 < args.length ? args[i + 1] : null;
}

async function load() {
  const envelope = flag("--envelope");
  if (envelope) {
    const base = (flag("--base") || "https://free-sign.com").replace(/\/$/, "");
    const res = await fetch(`${base}/api/envelopes/${envelope}/audit`);
    if (!res.ok) {
      console.error(`GET ${base}/api/envelopes/${envelope}/audit -> ${res.status}`);
      process.exit(1);
    }
    return res.json();
  }
  const path = args[0];
  if (!path) {
    console.error("usage: node examples/verify-audit-chain.mjs <events.json> | --envelope env_<32hex> [--base URL]");
    process.exit(2);
  }
  return JSON.parse(readFileSync(path, "utf8"));
}

const data = await load();
const events = Array.isArray(data) ? data : data.events || [];
// The attested head, when present, is the audit-chain head the signer froze in
// the signed final payload. Passing it makes verifyAuditChain reject a re-forged
// but internally-consistent chain (reason: "head_mismatch").
//
// Gate exactly as the server does (src/read-routes.js `trustedHead`): only
// cross-check against a head whose final-payload SIGNATURE verified
// (attested_head_signature_verified === true). An unverified head comes from a
// tampered final_payload_json — feeding it back would let a re-forged-and-
// rewritten chain read as "valid", so we drop it to null.
const attestedHead = !Array.isArray(data) && data.attested_head_signature_verified === true
  ? data.attested_audit_chain_head_hash || null
  : null;

const verdict = await verifyAuditChain(events, attestedHead);

console.log(`events:        ${verdict.event_count}`);
console.log(`valid:         ${verdict.valid}`);
if (!verdict.valid) {
  console.log(`broken_at seq: ${verdict.broken_at}`);
  console.log(`reason:        ${verdict.reason}`);
}
if (verdict.head_checked) {
  console.log(`head_match:    ${verdict.head_match} (cross-checked against signer-attested head)`);
}

process.exit(verdict.valid ? 0 : 1);
