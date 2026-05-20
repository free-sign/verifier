// Audit-trail re-check for the /verify page. Fetches an envelope's audit
// chain from GET /api/envelopes/{id}/audit and re-derives the integrity
// verdict IN THIS BROWSER via verifyAuditChain — it never trusts the server's
// own `chain.valid`. If the server's verdict and the locally recomputed
// verdict disagree, that is surfaced loudly.
//
// This module is loaded only by verify.html (it self-wires when #audit-section
// is in the DOM) and is independent of verify.js — verify.js merely dispatches
// a `freesign:verify-complete` DOM event carrying any envelope ids it found in
// embedded evidence records, which this module listens for to auto-run.
import { verifyAuditChain } from "./audit-verify.js";

const ENVELOPE_ID_RE = /^env_[a-f0-9]{32}$/;

// Bounded verdict-reason enum (mirrors the shared audit verifier) → human text.
const REASON_TEXT = {
  hash_mismatch: "an event's recorded contents do not match its hash — it was altered after being written.",
  broken_link: "the hash linkage is broken — an event was removed or the chain was re-spliced.",
  seq_bad_start: "the first audit event is missing — the chain does not start at sequence 1.",
  seq_gap: "an audit event is missing — the sequence numbers skip.",
  seq_duplicate: "the audit event sequence is inconsistent — numbers repeat or run backwards.",
  head_mismatch: "the audit chain was re-forged after the document was finalized — its head no longer matches the value the signer froze in the signed PDF.",
};

if (typeof document !== "undefined" && document.getElementById("audit-section")) {
  initAuditUi();
}

function initAuditUi() {
  const input = document.getElementById("audit-envelope-input");
  const button = document.getElementById("audit-verify-button");
  const statusEl = document.getElementById("audit-status");
  const resultsEl = document.getElementById("audit-results");

  let running = false;

  function setStatus(msg, kind) {
    if (!msg) {
      statusEl.hidden = true;
      return;
    }
    statusEl.hidden = false;
    statusEl.textContent = msg;
    statusEl.classList.toggle("is-error", kind === "error");
    statusEl.classList.toggle("is-ok", kind === "ok");
  }

  async function run(rawId) {
    const envelopeId = String(rawId || "").trim();
    if (!ENVELOPE_ID_RE.test(envelopeId)) {
      setStatus("Enter a valid envelope id — env_ followed by 32 hex characters.", "error");
      return;
    }
    if (running) return;
    running = true;
    button.disabled = true;
    while (resultsEl.firstChild) resultsEl.removeChild(resultsEl.firstChild);
    setStatus(`Fetching the audit chain for ${envelopeId}…`);
    try {
      const res = await fetch(`/api/envelopes/${encodeURIComponent(envelopeId)}/audit`, {
        headers: { accept: "application/json" },
      });
      if (res.status === 404) {
        setStatus(`No envelope ${envelopeId} found on this FreeSign service.`, "error");
        return;
      }
      if (!res.ok) {
        setStatus(`The FreeSign service returned ${res.status} for that envelope.`, "error");
        return;
      }
      const data = await res.json();
      const events = Array.isArray(data.events) ? data.events : [];
      // Re-derive the verdict locally — this is the whole point of the check.
      // For a finalized envelope the server returns the chain head the signer
      // froze in the v2 final payload (G-01); feeding it into verifyAuditChain
      // runs the cross-check that catches an internally-consistent re-forge.
      const attestedHead = data.attested_audit_chain_head_hash || null;
      // The head's provenance: did the server re-verify the signature over the
      // final payload that carries it? An unverified head must NOT feed the
      // cross-check (a tampered final payload could otherwise produce a
      // reassuring head_match) — only a signature-verified head is trusted,
      // mirroring src/index.js#getAuditChain.
      const headSigVerified = data.attested_head_signature_verified === true;
      const trustedHead = headSigVerified ? attestedHead : null;
      // A finalized envelope (attestedHead present) whose final-payload
      // signature did not verify has broken signed evidence — its attested
      // head cannot be trusted, regardless of the chain's internal consistency.
      const attestedHeadBroken = attestedHead !== null && !headSigVerified;
      const local = await verifyAuditChain(events, trustedHead);
      const server = data.chain || {};
      const agree = local.valid === server.valid
        && (local.reason ?? null) === (server.reason ?? null)
        && (local.broken_at ?? null) === (server.broken_at ?? null)
        && local.event_count === server.event_count;
      renderVerdict(resultsEl, local, agree, attestedHeadBroken);
      renderTimeline(resultsEl, local);
      if (!agree) {
        setStatus("Warning: the server's verdict disagrees with the in-browser recomputation — see below.", "error");
      } else if (attestedHeadBroken) {
        setStatus("Audit chain did NOT verify — the signature over this document's final payload could not be confirmed, so the attested chain head is untrusted.", "error");
      } else if (local.valid) {
        const headNote = local.head_checked
          ? " The audit-chain head matches the value the signer froze in the signed PDF."
          : "";
        setStatus(`Audit chain verified in your browser — ${local.event_count} event${local.event_count === 1 ? "" : "s"}, every hash and link checks out.${headNote}`, "ok");
      } else {
        setStatus("Audit chain did NOT verify — see the details below.", "error");
      }
    } catch (err) {
      setStatus(`Could not reach the FreeSign service: ${err && err.message ? err.message : err}`, "error");
    } finally {
      running = false;
      button.disabled = false;
    }
  }

  button.addEventListener("click", () => run(input.value));
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      run(input.value);
    }
  });

  // verify.js dispatches this after a PDF is verified, carrying any envelope
  // ids it pulled out of embedded FreeSign evidence records. Auto-fill and
  // auto-run when an id was discovered. All signers of one document share one
  // envelope, so in practice envelopeIds has at most one entry.
  document.addEventListener("freesign:verify-complete", (e) => {
    const ids = (e.detail && Array.isArray(e.detail.envelopeIds)) ? e.detail.envelopeIds : [];
    if (ids.length) {
      input.value = ids[0];
      run(ids[0]);
    }
  });
}

function renderVerdict(container, local, agree, attestedHeadBroken) {
  const box = document.createElement("div");
  box.className = "audit-verdict " + (local.valid && agree && !attestedHeadBroken ? "is-ok" : "is-fail");
  box.dataset.testid = "audit-verdict";
  const headline = document.createElement("strong");
  if (!agree) {
    headline.textContent = "Server verdict ≠ in-browser verdict";
    box.appendChild(headline);
    box.appendChild(document.createTextNode(
      "FreeSign's own response claimed a different result than recomputing the chain in your browser produced. Treat this audit trail as untrustworthy.",
    ));
  } else if (attestedHeadBroken) {
    headline.textContent = "Attested chain head unverified";
    box.appendChild(headline);
    box.appendChild(document.createTextNode(
      "The signature over this document's final payload — the artifact that freezes the audit-chain head — could not be verified. The attested head cannot be trusted, so a re-forged chain would not be caught here. Treat this audit trail as unverified.",
    ));
  } else if (local.valid) {
    headline.textContent = "Audit chain intact";
    box.appendChild(headline);
    box.appendChild(document.createTextNode(
      `All ${local.event_count} event${local.event_count === 1 ? "" : "s"} re-hashed in your browser; every event_hash, prev_event_hash link and seq number checks out.`,
    ));
  } else {
    headline.textContent = "Audit chain broken";
    box.appendChild(headline);
    const why = REASON_TEXT[local.reason] || "the chain failed an integrity check.";
    // head_mismatch is a whole-chain verdict: no single event is at fault, so
    // broken_at is null — render the reason alone, not "event #null".
    const text = local.broken_at != null
      ? `Broken at event #${local.broken_at}: ${why}`
      : why.charAt(0).toUpperCase() + why.slice(1);
    box.appendChild(document.createTextNode(text));
  }
  container.appendChild(box);
}

function renderTimeline(container, local) {
  if (!local.events.length) return;
  const wrap = document.createElement("div");
  wrap.className = "audit-timeline";
  wrap.dataset.testid = "audit-timeline";
  for (const ev of local.events) {
    const ok = ev.hash_ok && ev.link_ok && ev.seq_ok;
    const row = document.createElement("div");
    row.className = "audit-event" + (ok ? "" : " is-bad");

    const seq = document.createElement("span");
    seq.className = "audit-event-seq";
    seq.textContent = "#" + (ev.seq ?? "?");
    row.appendChild(seq);

    const type = document.createElement("span");
    type.className = "audit-event-type";
    type.textContent = ev.event_type || "(unknown event)";
    row.appendChild(type);

    const flags = document.createElement("span");
    flags.className = "audit-event-flags";
    flags.textContent = `hash ${mark(ev.hash_ok)}  link ${mark(ev.link_ok)}  seq ${mark(ev.seq_ok)}`;
    row.appendChild(flags);

    const time = document.createElement("span");
    time.className = "audit-event-time";
    time.textContent = ev.created_at || "";
    row.appendChild(time);

    wrap.appendChild(row);
  }
  container.appendChild(wrap);
}

function mark(ok) {
  return ok ? "✓" : "✗";
}
