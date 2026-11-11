#!/usr/bin/env node
/** Reference CLI verifier for .lcp packages.
 *  Usage: node verify-passport.mjs file.lcp
 *  Reports per-check results with honest claims - no bare "verified".
 *  Mirrors src/lib/passport/verify.ts; kept dependency-light on purpose. */
import { readFileSync } from "node:fs";
import { createHash, createVerify, createPublicKey } from "node:crypto";
import JSZip from "jszip";

const file = process.argv[2];
if (!file) { console.error("usage: node verify-passport.mjs file.lcp"); process.exit(2); }

const b64u = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
// JCS-lite: sorted keys at every depth, JSON.stringify primitives.
const canon = (v) => Array.isArray(v)
  ? `[${v.map(canon).join(",")}]`
  : v && typeof v === "object"
    ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`
    : JSON.stringify(v);
const sha = (data) => b64u(createHash("sha256").update(data).digest());
let failed = false;
const check = (status, label, detail) => {
  if (status === "fail") failed = true;
  console.log(`${status === "pass" ? "PASS" : status === "fail" ? "FAIL" : status === "warn" ? "WARN" : "INFO"}  ${label}: ${detail}`);
};
const fail = (label, detail) => { check("fail", label, detail); process.exit(1); };

const zip = await JSZip.loadAsync(readFileSync(file));
const safe = (p) => !p.includes("..") && !p.startsWith("/") && !/^[a-zA-Z]:/.test(p) && p.split("/").length <= 6;
for (const p of Object.keys(zip.files)) if (!safe(p)) fail("Package parsed safely", `unsafe path: ${p}`);
check("pass", "Package parsed safely", `${Object.keys(zip.files).length} entries within limits`);

const manifestEntry = zip.file("manifest.json");
if (!manifestEntry) fail("Manifest present", "manifest.json missing");
const manifest = JSON.parse(await manifestEntry.async("string"));
if (manifest.format !== "lawcribs-matter-passport") fail("Manifest schema valid", "wrong format tag");
if (!Array.isArray(manifest.records)) fail("Manifest schema valid", "records is not an array");
check("pass", "Manifest schema valid", `v${manifest.formatVersion}, scope ${manifest.scope?.type ?? "unknown"}`);
if (manifest.protocol?.maintainer) check("info", "Protocol steward", `${manifest.protocol.name} - maintained by ${manifest.protocol.maintainer}`);

let digestFails = 0, skipped = 0;
const seen = new Set();
const parsedEvents = [];
for (const rec of manifest.records) {
  if (seen.has(rec.recordId)) fail("Record digests match", `duplicate recordId ${rec.recordId}`);
  seen.add(rec.recordId);
  const entry = zip.file(rec.contentLocation ?? `records/${rec.recordId}/content.bin`);
  if (!entry) { skipped++; continue; }
  if (sha(await entry.async("uint8array")) !== rec.digest.value) digestFails++;
}
check(digestFails ? "fail" : skipped ? "warn" : "pass", "Record digests match",
  digestFails ? `${digestFails} of ${manifest.records.length} fail` : skipped ? `${skipped} records not in package (scope ${manifest.scope.type})` : `all ${manifest.records.length} match`);

const eventDigests = [];
const eventsEntry = zip.file("events/events.jsonl");
if (eventsEntry) {
  const lines = (await eventsEntry.async("string")).trim().split("\n").filter(Boolean);
  let ok = true, prev = null;
  // The declared range can start anywhere - sequence follows the
  // manifest window, not an assumed 1..N.
  const fromSeq = manifest.eventRange?.fromSequence ?? 1;
  let seq = fromSeq - 1;
  for (const line of lines) {
    seq++;
    const ev = JSON.parse(line);
    // A windowed range's first event commits to history outside the
    // package - accepted as an opaque boundary, disclosed in detail.
    const prevOk = seq === fromSeq && fromSeq > 1
      ? typeof ev.previousEventDigest === "string" && ev.previousEventDigest.length > 0
      : ev.previousEventDigest === prev;
    const pd = sha(JSON.stringify(ev.payload));
    const recomputed = sha(`${ev.sequenceNumber}|${ev.eventType}|${ev.previousEventDigest ?? ""}|${pd}`);
    if (ev.sequenceNumber !== seq || !prevOk || recomputed !== ev.eventDigest || pd !== ev.payloadDigest) { ok = false; break; }
    parsedEvents.push(ev);
    eventDigests.push(ev.eventDigest); prev = ev.eventDigest;
  }
  check(ok ? "pass" : "fail", "Event chain intact",
    ok
      ? fromSeq > 1
        ? `${lines.length} events consistent from sequence ${fromSeq} - link to earlier events not verifiable from this package`
        : `${lines.length} events consistent`
      : `broken at sequence ${seq}`);
  if (manifest.eventRange) {
    const expected = manifest.eventRange.toSequence - manifest.eventRange.fromSequence + 1;
    if (expected !== lines.length || manifest.eventRange.fromSequence > manifest.eventRange.toSequence || manifest.eventRange.fromSequence < 1) {
      check("fail", "Event range matches manifest", `manifest declares ${manifest.eventRange.fromSequence}-${manifest.eventRange.toSequence} (${expected} events), file has ${lines.length}`);
    }
  }
} else {
  check("warn", "Event chain intact", "no event file in package");
}

if (manifest.integrity?.merkleRoot) {
  const tag = "lc-pproof-v1";
  const leaf = (l) => sha(`${tag}|leaf|${l}`);
  const node = (a, b) => sha(`${tag}|node|${a}|${b}`);
  const leaves = [...manifest.records.map((r) => r.digest.value), ...eventDigests].sort();
  let level = leaves.map(leaf);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(node(level[i], level[i + 1] ?? level[i]));
    level = next;
  }
  check(level[0] === manifest.integrity.merkleRoot ? "pass" : "fail", "Merkle root matches signed manifest",
    level[0] === manifest.integrity.merkleRoot ? `root ${manifest.integrity.merkleRoot.slice(0, 20)}...` : "recomputed root differs - contents altered after signing");
}

const sigEntry = zip.file("signatures/manifest-signature.json");
if (sigEntry) {
  const sig = JSON.parse(await sigEntry.async("string"));
  let ok = false;
  try {
    const spki = Buffer.concat([Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"), Buffer.from([4]), Buffer.from(sig.publicKeyJwk.x, "base64url"), Buffer.from(sig.publicKeyJwk.y, "base64url")]);
    const key = createPublicKey({ key: spki, format: "der", type: "spki" });
    ok = createVerify("SHA256").update(canon(manifest), "utf8").verify({ key, dsaEncoding: "ieee-p1363" }, Buffer.from(sig.signatureValue, "base64url"));
  } catch { ok = false; }
  check(ok ? "pass" : "fail", "Manifest signature valid", ok ? `ES256 by key ${sig.keyId}` : "does not verify");
  check("info", "Signer identity", "signature proves key possession only; identity requires separate evidence");

  const keyEvents = parsedEvents.filter((e) => e.eventType === "key.registered" || e.eventType === "key.rotated");
  if (keyEvents.length) {
    const inChain = keyEvents.some((e) => e.payload?.keyId === sig.keyId);
    check(inChain ? "pass" : "warn", "Signing key registered in chain",
      inChain ? "signature key appears in the event chain's key lifecycle" : "signature key does not appear in the chain's key events");
  } else {
    check("info", "Signing key registered in chain", "no key lifecycle events in package - manifest predates key lineage tracking");
  }
  check("info", "Signing key status", "revocation state is not verifiable from the package alone - hosted verification reports live key status from the directory");
} else {
  check("warn", "Manifest signature valid", "no signature file in package");
}

if (manifest.previousSnapshotDigest) {
  check("info", "Snapshot lineage", `manifest declares a link to prior snapshot ${manifest.previousSnapshotId ?? "unknown"} - verifiable against an earlier package`);
}
check("info", "Timestamp assurance", "timestamps are client-reported; check hosted verification for relay-anchored digest timestamps");
if (manifest.scope?.type !== "full") check("info", "Package scope", `${manifest.scope?.type ?? "unknown"} - not a complete matter record`);

process.exit(failed ? 1 : 0);


