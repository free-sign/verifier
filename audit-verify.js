import { canonicalJson } from "./session.js";

// Browser-side mirror of the server's audit-chain verifier. The /verify page
// uses it to re-derive the audit-chain verdict in-browser from the raw events
// the /api/envelopes/{id}/audit endpoint returns — so a recipient never has to
// trust the server's own `chain.valid`. verifyAuditChain below is a verbatim
// copy of the server's; only buildAuditMaterial / sha256Hex are sourced
// locally — all built on the shared canonicalJson from session.js. The test
// suite feeds this module and the server module the same fixture battery and
// asserts identical verdicts.

const _encoder = new TextEncoder();

async function sha256Hex(value) {
  const bytes = typeof value === "string" ? _encoder.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Verbatim mirror of the server's buildAuditMaterial — the canonical hash
// input. The eight fields and their order-independent key names ARE the audit
// chain's wire contract; keep byte-identical to the server.
function buildAuditMaterial({ envelopeId, signerId, eventType, eventDataJson, prevEventHash, ipHash, userAgentHash, cfCountry }) {
  return canonicalJson({
    envelope_id: envelopeId,
    signer_id: signerId ?? null,
    event_type: eventType,
    event_data_json: eventDataJson,
    prev_event_hash: prevEventHash ?? null,
    ip_hash: ipHash ?? null,
    user_agent_hash: userAgentHash ?? null,
    cf_country: cfCountry ?? null,
  });
}

// --- verbatim copy of the server's verifyAuditChain ---
// See the server module for the verdict `reason` enum (including
// head_mismatch), the expectedHeadHash cross-check rationale, and the rest
// of the contract.
export async function verifyAuditChain(events, expectedHeadHash = null) {
  const list = Array.isArray(events) ? events : [];
  const checked = [];
  let valid = true;
  let brokenAt = null;
  let reason = null;
  const fail = (seq, r) => {
    if (valid) {
      valid = false;
      brokenAt = seq;
      reason = r;
    }
  };
  let prevHash = null;
  const computedHashes = [];
  for (let i = 0; i < list.length; i += 1) {
    const ev = list[i] || {};
    const expectedSeq = i + 1;
    const seq = Number.isInteger(ev.seq) ? ev.seq : null;

    const material = buildAuditMaterial({
      envelopeId: ev.envelope_id,
      signerId: ev.signer_id ?? null,
      eventType: ev.event_type,
      eventDataJson: ev.event_data_json,
      prevEventHash: ev.prev_event_hash ?? null,
      ipHash: ev.ip_hash ?? null,
      userAgentHash: ev.user_agent_hash ?? null,
      cfCountry: ev.cf_country ?? null,
    });
    const computedHash = await sha256Hex(material);
    computedHashes.push(computedHash);
    const hashOk = computedHash === ev.event_hash;
    const linkOk = (ev.prev_event_hash ?? null) === prevHash;
    const seqOk = seq === expectedSeq;

    checked.push({
      seq,
      id: ev.id ?? null,
      event_type: ev.event_type ?? null,
      created_at: ev.created_at ?? null,
      hash_ok: hashOk,
      link_ok: linkOk,
      seq_ok: seqOk,
    });

    if (!hashOk) {
      fail(seq, "hash_mismatch");
    } else if (!linkOk) {
      fail(seq, "broken_link");
    } else if (!seqOk) {
      if (expectedSeq === 1) fail(seq, "seq_bad_start");
      else if (seq !== null && seq > expectedSeq) fail(seq, "seq_gap");
      else fail(seq, "seq_duplicate");
    }

    prevHash = ev.event_hash ?? null;
  }

  let headChecked = false;
  let headMatch = null;
  if (typeof expectedHeadHash === "string" && expectedHeadHash) {
    headChecked = true;
    headMatch = computedHashes.includes(expectedHeadHash);
    if (valid && !headMatch) fail(null, "head_mismatch");
  }

  return {
    valid,
    event_count: list.length,
    broken_at: brokenAt,
    reason,
    events: checked,
    head_checked: headChecked,
    head_match: headMatch,
  };
}
