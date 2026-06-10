/**
 * OpenTimestamps Timestamp tree helpers — calendar upgrade by commitment.
 * Wire format: github.com/opentimestamps/python-opentimestamps
 *
 * Pool POST /digest returns OpAppend + OpSHA256 + OpAppend + PendingAttestation.
 * Upgrade GET must use the calendar URL in the blob and the commitment digest
 * at the PendingAttestation node (after all ops on that path), not the raw
 * file hash from the .ots header.
 */

const PENDING_ATTESTATION_TAG = new Uint8Array([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);
const BTC_ATTESTATION_TAG = new Uint8Array([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
const OP_SHA256 = 0x08;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;

/** Per-calendar GET budget (browser verify + Node tools). */
export const OTS_CALENDAR_FETCH_TIMEOUT_MS = 15_000;

function calendarFetchSignal(signal, timeoutMs = OTS_CALENDAR_FETCH_TIMEOUT_MS) {
  const timeout = AbortSignal.timeout(timeoutMs);
  if (!signal) return timeout;
  return AbortSignal.any([signal, timeout]);
}

/** Host suffixes allowed for browser-side calendar upgrade GETs. */
export const ALLOWED_OTS_CALENDAR_HOST_SUFFIXES = [
  ".calendar.opentimestamps.org",
  ".opentimestamps.org",
];

/** Explicit hosts (not covered by suffix alone). */
export const ALLOWED_OTS_CALENDAR_HOSTS = new Set([
  "finney.calendar.eternitywall.com",
]);

export function isAllowedCalendarUrl(calendarUrl) {
  let parsed;
  try {
    parsed = new URL(String(calendarUrl));
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  const host = parsed.hostname.toLowerCase();
  if (ALLOWED_OTS_CALENDAR_HOSTS.has(host)) return true;
  return ALLOWED_OTS_CALENDAR_HOST_SUFFIXES.some(
    (suffix) => host.endsWith(suffix) || host === suffix.slice(1),
  );
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
    if (shift > 35) throw new Error("OTS varuint too long");
  }
  throw new Error("OTS varuint truncated");
}

function readVarBytes(buf, offset, maxLen = 4096) {
  const { value: len, offset: start } = readVarUint(buf, offset);
  if (len > maxLen) throw new Error("OTS varbytes too long");
  if (start + len > buf.length) throw new Error("OTS varbytes truncated");
  return { bytes: buf.slice(start, start + len), offset: start + len };
}

async function sha256Bytes(msg) {
  const d = await crypto.subtle.digest("SHA-256", msg);
  return new Uint8Array(d);
}

function applyUnaryOp(tag, msg) {
  if (tag === OP_SHA256) return sha256Bytes(msg);
  throw new Error(`unsupported OTS unary op 0x${tag.toString(16)}`);
}

function applyBinaryOp(tag, msg, arg) {
  if (tag === OP_APPEND) {
    const out = new Uint8Array(msg.length + arg.length);
    out.set(msg, 0);
    out.set(arg, msg.length);
    return out;
  }
  if (tag === OP_PREPEND) {
    const out = new Uint8Array(arg.length + msg.length);
    out.set(arg, 0);
    out.set(msg, arg.length);
    return out;
  }
  throw new Error(`unsupported OTS binary op 0x${tag.toString(16)}`);
}

function bytesEqTag(buf, offset, tag) {
  if (offset + tag.length > buf.length) return false;
  for (let i = 0; i < tag.length; i += 1) {
    if (buf[offset + i] !== tag[i]) return false;
  }
  return true;
}

function parsePendingUri(payload) {
  const { bytes: uriBytes } = readVarBytes(payload, 0, 1000);
  const raw = new TextDecoder("latin1").decode(uriBytes).trim();
  if (!raw) throw new Error("empty pending attestation URI");
  const httpsMatch = raw.match(/https:\/\/[A-Za-z0-9._:/?#-]+/);
  if (httpsMatch) return httpsMatch[0].replace(/\/$/, "");
  const hostMatch = raw.match(/[a-z0-9][a-z0-9.-]*\.calendar\.opentimestamps\.org/i);
  if (hostMatch) return `https://${hostMatch[0]}`.replace(/\/$/, "");
  if (raw.startsWith("http://")) {
    return `https://${raw.slice("http://".length)}`.replace(/\/$/, "");
  }
  return `https://${raw}`.replace(/\/$/, "");
}

function parseAttestationAfterStreamTag(buf, offset) {
  if (offset + 8 > buf.length) throw new Error("attestation tag truncated");
  const attTagOff = offset;
  const { bytes: payload, offset: next } = readVarBytes(buf, offset + 8);
  if (bytesEqTag(buf, attTagOff, PENDING_ATTESTATION_TAG)) {
    return { type: "pending", uri: parsePendingUri(payload), nextOffset: next };
  }
  if (bytesEqTag(buf, attTagOff, BTC_ATTESTATION_TAG)) {
    return { type: "bitcoin", nextOffset: next };
  }
  return { type: "unknown", nextOffset: next };
}

async function deserializeTimestampAsync(buf, offset, initialMsg, recursionLimit = 64) {
  if (!(initialMsg instanceof Uint8Array)) throw new Error("initialMsg must be Uint8Array");
  if (recursionLimit <= 0) throw new Error("OTS timestamp recursion limit");
  const cursor = { pos: offset };
  const stamp = { msg: initialMsg, attestations: [], children: [] };

  async function doTagOrAttestation(tag) {
    if (tag === 0x00) {
      const att = parseAttestationAfterStreamTag(buf, cursor.pos);
      cursor.pos = att.nextOffset;
      stamp.attestations.push(att);
      return;
    }
    let arg = new Uint8Array(0);
    if (tag === OP_APPEND || tag === OP_PREPEND) {
      const vb = readVarBytes(buf, cursor.pos);
      arg = vb.bytes;
      cursor.pos = vb.offset;
    }
    let resultMsg;
    if (tag === OP_APPEND || tag === OP_PREPEND) {
      resultMsg = applyBinaryOp(tag, stamp.msg, arg);
    } else {
      resultMsg = await applyUnaryOp(tag, stamp.msg);
    }
    const child = await deserializeTimestampAsync(buf, cursor.pos, resultMsg, recursionLimit - 1);
    cursor.pos = child.offset;
    stamp.children.push(child.stamp);
  }

  if (cursor.pos >= buf.length) throw new Error("empty timestamp serialization");

  let tag = buf[cursor.pos];
  cursor.pos += 1;
  while (tag === 0xff) {
    if (cursor.pos >= buf.length) throw new Error("timestamp truncated after 0xff");
    const inner = buf[cursor.pos];
    cursor.pos += 1;
    await doTagOrAttestation(inner);
    if (cursor.pos >= buf.length) return { stamp, offset: cursor.pos };
    tag = buf[cursor.pos];
    cursor.pos += 1;
  }
  await doTagOrAttestation(tag);
  return { stamp, offset: cursor.pos };
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function collectPendingTargets(stamp, out) {
  for (const att of stamp.attestations) {
    if (att.type === "pending" && isAllowedCalendarUrl(att.uri)) {
      out.push({ calendarUrl: att.uri, commitmentHex: bytesToHex(stamp.msg) });
    }
  }
  for (const child of stamp.children) collectPendingTargets(child, out);
}

/**
 * Commitment digest for each embedded pending calendar (full op path).
 */
export { deserializeTimestampAsync };

export async function listPendingUpgradeTargets(timestampBytes, msgBytes) {
  if (!(timestampBytes instanceof Uint8Array) || timestampBytes.length === 0) return [];
  if (!(msgBytes instanceof Uint8Array) || msgBytes.length !== 32) return [];
  try {
    const { stamp } = await deserializeTimestampAsync(timestampBytes, 0, msgBytes);
    const targets = [];
    collectPendingTargets(stamp, targets);
    return targets;
  } catch {
    return [];
  }
}

/** @deprecated Use listPendingUpgradeTargets — kept for tests that pin first-append only. */
export function computeCalendarCommitmentHex(timestampBytes, msgBytes) {
  try {
    if (!(timestampBytes instanceof Uint8Array) || timestampBytes.length === 0) return null;
    if (!(msgBytes instanceof Uint8Array) || msgBytes.length !== 32) return null;
    if (timestampBytes[0] !== OP_APPEND) return null;
    const { value: argLen, offset: argStart } = readVarUint(timestampBytes, 1);
    if (argLen <= 0 || argStart + argLen > timestampBytes.length) return null;
    const out = new Uint8Array(msgBytes.length + argLen);
    out.set(msgBytes, 0);
    out.set(timestampBytes.slice(argStart, argStart + argLen), msgBytes.length);
    return bytesToHex(out);
  } catch {
    return null;
  }
}

export async function fetchCalendarUpgradeByCommitment(calendarUrl, commitmentHex, { fetchImpl, signal, timeoutMs } = {}) {
  if (!isAllowedCalendarUrl(calendarUrl)) {
    throw new Error(`OTS calendar URL not allowlisted: ${String(calendarUrl).slice(0, 80)}`);
  }
  if (!/^[0-9a-f]+$/.test(commitmentHex) || commitmentHex.length < 2) {
    throw new Error("commitmentHex must be lowercase hex");
  }
  const base = String(calendarUrl).replace(/\/$/, "");
  const url = `${base}/timestamp/${commitmentHex}`;
  const doFetch = fetchImpl || fetch;
  const res = await doFetch(url, {
    method: "GET",
    headers: {
      accept: "application/vnd.opentimestamps.v1",
    },
    signal: calendarFetchSignal(signal, timeoutMs),
    referrer: "",
    referrerPolicy: "no-referrer",
  });
  if (res.status === 404) return { upgraded: false, reason: "not_yet" };
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`OTS calendar upgrade HTTP ${res.status}: ${text.slice(0, 120)}`);
  }
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length < 8) throw new Error("OTS calendar empty upgrade response");
  return { upgraded: true, timestampBytes: buf, calendarUrl: base };
}

export async function upgradeTimestampFromTree(timestampBytes, msgBytes, { fetchImpl, signal, timeoutMs } = {}) {
  const targets = await listPendingUpgradeTargets(timestampBytes, msgBytes);
  const attempts = [];
  for (const t of targets) {
    try {
      const r = await fetchCalendarUpgradeByCommitment(t.calendarUrl, t.commitmentHex, {
        fetchImpl,
        signal,
        timeoutMs,
      });
      if (r.upgraded) return { upgraded: true, timestampBytes: r.timestampBytes, calendarUrl: r.calendarUrl, targets };
      attempts.push(`${t.calendarUrl}: ${r.reason}`);
    } catch (e) {
      attempts.push(`${t.calendarUrl}: ${e.message}`);
    }
  }
  return { upgraded: false, attempts, targets };
}
