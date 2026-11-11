/**
 * Conformance fixture generator. Produces real, valid .lcp packages
 * plus manifests, signatures, expected reports, receipt vectors, and
 * canonicalization/merkle/event/envelope vectors under a fixtures
 * directory so external verifiers can run against known-good data.
 * Defaults to docs/matter-passport/fixtures/; pass a different
 * output directory as the first argument for standalone-repo use.
 *
 * Replicates the app's formulas exactly: JCS-lite canonicalization,
 * base64url SHA-256 digests, the passport event-digest string format,
 * the lc-pproof-v1 Merkle domain tags, ES256 over the canonical
 * manifest (signed AFTER signatures[] is populated), and raw
 * IEEE-P1363 (r||s) ECDSA signatures - WebCrypto format, NOT DER.
 *
 * Run: node generate-passport-fixtures.mjs [fixtures-dir]
 */
import { createHash, generateKeyPairSync, sign as cryptoSign, createCipheriv } from "crypto";
import { mkdirSync, writeFileSync, readFileSync, rmSync } from "fs";
import { join } from "path";
import JSZip from "jszip";

const ROOT = process.argv[2] ?? "docs/matter-passport/fixtures";
const b64url = (buf) => Buffer.from(buf).toString("base64url");
const sha256b64 = (data) => createHash("sha256").update(data).digest("base64url");
const b64std = (buf) => Buffer.from(buf).toString("base64");

/** JCS-lite: sorted object keys, UTF-8, JSON.stringify primitives. */
function canonicalize(v) {
  if (v === undefined) throw new Error("canonicalize: undefined not allowed");
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
}

const TAG = "lc-pproof-v1";
const leafHash = (leaf) => sha256b64(`${TAG}|leaf|${leaf}`);
const nodeHash = (l, r) => sha256b64(`${TAG}|node|${l}|${r}`);

function buildMerkle(items) {
  const leaves = [...items].sort();
  let level = leaves.map(leafHash);
  const tree = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(nodeHash(level[i], level[i + 1] ?? level[i]));
    tree.push(next);
    level = next;
  }
  return { root: leaves.length ? tree[tree.length - 1][0] : "", leaves, levels: tree };
}
function proofOf(tree, idx) {
  const siblings = [];
  let i = idx;
  for (let l = 0; l < tree.levels.length - 1; l++) {
    const row = tree.levels[l];
    const sib = i % 2 === 0 ? i + 1 : i - 1;
    siblings.push({ position: i % 2 === 0 ? "right" : "left", digest: sib < row.length ? row[sib] : row[i] });
    i = Math.floor(i / 2);
  }
  return { leafIndex: idx, siblings, root: tree.root };
}

/** ES256 signature in WebCrypto format: raw r||s (64 bytes), b64url. */
function signP1363(privateKey, dataUtf8) {
  const sig = cryptoSign("sha256", Buffer.from(dataUtf8, "utf8"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return b64url(sig);
}
function newKey(id) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const publicKeyJwk = publicKey.export({ format: "jwk" });
  const fingerprint = sha256b64(JSON.stringify({ kty: publicKeyJwk.kty, crv: publicKeyJwk.crv, x: publicKeyJwk.x, y: publicKeyJwk.y }));
  return { id, privateKey, publicKeyJwk, fingerprint };
}
const PROTOCOL = { name: "LawCribs Matter Passport", maintainer: "LawCribs", specUrl: "https://lawcribs.com/matter-passport-spec/PROTOCOL.md" };

// --- Shared fixture builders ------------------------------------------------

function makeRecord(recordId, filename, mediaType, bytes, contentLocation) {
  return {
    recordId, recordType: filename.includes("agreement") ? "contract" : "evidence",
    filename, mediaType, size: bytes ? bytes.byteLength : 4096,
    digest: { algorithm: "sha-256", encoding: "base64url", value: sha256b64(bytes ?? "referenced-content-placeholder") },
    contentLocation,
    provenanceClass: "user-supplied",
  };
}

/** A passport event chain builder replicating appendEvent ordering:
 *  snapshot manifests are computed BEFORE their snapshot.created /
 *  snapshot.signed events are appended, matching createSnapshot. */
function makeChain(passportId) {
  const events = [];
  let prev = null;
  let seq = 0;
  return {
    events,
    async add(eventType, actorId, actorType, payload) {
      seq++;
      const payloadDigest = sha256b64(JSON.stringify(payload));
      const eventDigest = sha256b64(`${seq}|${eventType}|${prev ?? ""}|${payloadDigest}`);
      const ev = {
        id: `fx-evt-${String(seq).padStart(3, "0")}`, passportId,
        sequenceNumber: seq, eventType, actorId, actorType,
        payload, payloadDigest, previousEventDigest: prev, eventDigest,
        clientTime: "2026-01-15T10:00:00.000Z", createdAt: "2026-01-15T10:00:00.000Z",
      };
      events.push(ev);
      prev = eventDigest;
      return ev;
    },
    head: () => prev,
  };
}

async function buildSnapshotPackage({ dir, passportId, snapshotId, key, records, events, scope, previous, fileName }) {
  const tree = buildMerkle([...records.map((r) => r.digest.value), ...events.map((e) => e.eventDigest)]);
  // embeddedBytes is generator plumbing - the manifest record shape is fixed.
  const manifestRecords = records.map(({ embeddedBytes, ...r }) => r);
  const manifest = {
    format: "lawcribs-matter-passport",
    formatVersion: "1.1.0",
    schemaVersion: "1.1.0",
    protocol: PROTOCOL,
    matterId: "fx-matter-001",
    snapshotId,
    ...(previous ? { previousSnapshotId: previous.snapshotId, previousSnapshotDigest: previous.manifestDigest } : {}),
    createdAt: "2026-01-15T10:00:00.000Z",
    scope: { type: scope, description: scope === "full" ? "Conformance fixture - full snapshot" : "Conformance fixture - selected records" },
    records: manifestRecords,
    eventRange: { fromSequence: events[0]?.sequenceNumber ?? 0, toSequence: events[events.length - 1]?.sequenceNumber ?? 0 },
    integrity: { canonicalization: "JCS-lite", manifestDigestAlgorithm: "sha-256", merkleRoot: tree.root },
    signatures: [{ signatureId: `${snapshotId}-sig`, algorithm: "ES256", keyId: key.id }],
  };
  const canonical = canonicalize(manifest);
  const manifestDigest = sha256b64(canonical);
  const signature = {
    id: `${snapshotId}-sig`, snapshotId, keyId: key.id,
    algorithm: "ES256", payloadDigest: sha256b64(canonical),
    signatureValue: signP1363(key.privateKey, canonical),
    publicKeyJwk: key.publicKeyJwk, timeAssuranceLevel: "client-reported",
    createdAt: "2026-01-15T10:00:00.000Z",
  };

  const zip = new JSZip();
  zip.file("manifest.json", canonical);
  zip.file("signatures/manifest-signature.json", JSON.stringify(signature, null, 2));
  zip.file("events/events.jsonl", events.map((e) => JSON.stringify(e)).join("\n"));
  zip.file("events/checkpoint.json", JSON.stringify({ lastSequence: events[events.length - 1]?.sequenceNumber ?? 0, lastEventDigest: events[events.length - 1]?.eventDigest ?? "" }, null, 2));
  zip.file("proofs/merkle-root.txt", tree.root);
  for (const rec of records) {
    const idx = tree.leaves.indexOf(rec.digest.value);
    if (idx >= 0) zip.file(`proofs/merkle-proofs/${rec.recordId}.json`, JSON.stringify(proofOf(tree, idx), null, 2));
    zip.file(`records/${rec.recordId}/metadata.json`, JSON.stringify({
      recordId: rec.recordId, recordType: rec.recordType, filename: rec.filename, mediaType: rec.mediaType,
      sizeBytes: rec.size, digest: rec.digest, contentLocation: rec.contentLocation, provenanceClass: rec.provenanceClass,
    }, null, 2));
  }
  // Embedded record bytes travel as content.bin; referenced records carry
  // metadata only (their bytes never existed on the exporting device).
  for (const rec of records) {
    if (rec.embeddedBytes) zip.file(`records/${rec.recordId}/content.bin`, rec.embeddedBytes);
  }
  zip.file("verification/README.txt", `LAWCRIBS MATTER PASSPORT - CONFORMANCE FIXTURE\n\nA known-good package for verifier conformance testing.\n`);

  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, fileName), await zip.generateAsync({ type: "nodebuffer" }));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  writeFileSync(join(dir, "manifest-signature.json"), JSON.stringify(signature, null, 2));
  return { manifest, manifestDigest, signature, tree, recordCount: records.length, eventCount: events.length };
}

function writeExpected(dir, pkg, checks) {
  writeFileSync(join(dir, "expected-report.json"), JSON.stringify({
    description: "Expected check results for a conformant verifier",
    checks,
    recordCount: pkg.recordCount, eventCount: pkg.eventCount, scope: pkg.manifest.scope.type,
    manifestDigest: pkg.manifestDigest, merkleRoot: pkg.tree.root,
  }, null, 2));
}

// --- legacy-v1: a valid 1.0.0-schema package (pre-v-next) --------------------

async function genLegacy() {
  const dir = join(ROOT, "legacy-v1");
  rmSync(dir, { recursive: true, force: true });
  const key = newKey("fx-key-legacy");
  const contentBytes = Buffer.from("Matter Passport conformance fixture - exhibit A contents.");
  const recordA = { ...makeRecord("fx-record-001", "exhibit-a.txt", "text/plain", contentBytes, "records/fx-record-001/content.bin"), embeddedBytes: contentBytes };
  const recordB = makeRecord("fx-record-002", "retainer-agreement.pdf", "application/pdf", null, "records/fx-record-002/content.bin");
  const chain = makeChain("fx-passport-legacy");
  await chain.add("passport.created", "fx-user", "user", { matterId: "fx-matter-001" });
  await chain.add("record.registered", "fx-user", "user", { recordId: recordA.recordId, filename: recordA.filename, digestValue: recordA.digest.value });
  await chain.add("record.registered", "fx-user", "user", { recordId: recordB.recordId, filename: recordB.filename, digestValue: recordB.digest.value });
  const events = [...chain.events]; // snapshot.created appended after manifest, excluded from range
  const tree = buildMerkle([... [recordA, recordB].map((r) => r.digest.value), ...events.map((e) => e.eventDigest)]);
  const manifest = {
    format: "lawcribs-matter-passport",
    formatVersion: "1.0.0",
    schemaVersion: "1.0.0",
    matterId: "fx-matter-001",
    snapshotId: "fx-snap-legacy",
    createdAt: "2026-01-15T10:00:00.000Z",
    scope: { type: "full", description: "Legacy v1 conformance fixture - full snapshot" },
    records: [recordA, recordB].map(({ embeddedBytes, ...r }) => r),
    eventRange: { fromSequence: 1, toSequence: 3 },
    integrity: { canonicalization: "JCS-lite", manifestDigestAlgorithm: "sha-256", merkleRoot: tree.root },
    signatures: [{ signatureId: "fx-sig-legacy", algorithm: "ES256", keyId: key.id }],
  };
  const canonical = canonicalize(manifest);
  const manifestDigest = sha256b64(canonical);
  const signature = {
    id: "fx-sig-legacy", snapshotId: "fx-snap-legacy", keyId: key.id,
    algorithm: "ES256", payloadDigest: sha256b64(canonical),
    signatureValue: signP1363(key.privateKey, canonical),
    publicKeyJwk: key.publicKeyJwk, timeAssuranceLevel: "client-reported",
    createdAt: "2026-01-15T10:00:00.000Z",
  };
  const zip = new JSZip();
  zip.file("manifest.json", canonical);
  zip.file("signatures/manifest-signature.json", JSON.stringify(signature, null, 2));
  zip.file("events/events.jsonl", events.map((e) => JSON.stringify(e)).join("\n"));
  zip.file("events/checkpoint.json", JSON.stringify({ lastSequence: 3, lastEventDigest: events[2].eventDigest }, null, 2));
  zip.file("proofs/merkle-root.txt", tree.root);
  for (const rec of [recordA, recordB]) {
    const idx = tree.leaves.indexOf(rec.digest.value);
    zip.file(`proofs/merkle-proofs/${rec.recordId}.json`, JSON.stringify(proofOf(tree, idx), null, 2));
    zip.file(`records/${rec.recordId}/metadata.json`, JSON.stringify({
      recordId: rec.recordId, recordType: rec.recordType, filename: rec.filename, mediaType: rec.mediaType,
      sizeBytes: rec.size, digest: rec.digest, contentLocation: rec.contentLocation, provenanceClass: rec.provenanceClass,
    }, null, 2));
  }
  zip.file(`records/${recordA.recordId}/content.bin`, contentBytes);
  zip.file("verification/README.txt", "LAWCRIBS MATTER PASSPORT - LEGACY V1 FIXTURE\n\nA valid 1.0.0-schema package - proves pre-v-next packages still verify.\n");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "passport.lcp"), await zip.generateAsync({ type: "nodebuffer" }));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest, null, 2));
  writeFileSync(join(dir, "manifest-signature.json"), JSON.stringify(signature, null, 2));
  writeExpected(dir, { recordCount: 2, eventCount: 3, manifest: { scope: { type: "full" } }, manifestDigest, tree }, [
    { id: "parse", status: "pass" }, { id: "manifest", status: "pass" }, { id: "schema", status: "pass" },
    { id: "records", status: "warn" }, { id: "events", status: "pass" }, { id: "merkle", status: "pass" },
    { id: "signature", status: "pass" }, { id: "identity", status: "info" },
    { id: "keylineage", status: "info" }, { id: "keystatus", status: "info" },
    { id: "timestamp", status: "info" },
  ]);
  console.log("legacy-v1 written");
}

// --- basic: two chained v-next snapshots --------------------------------------

async function genBasic() {
  const keyA = newKey("fx-key-a");
  const keyB = newKey("fx-key-b");
  const passportId = "fx-passport-001";
  const chain = makeChain(passportId);

  const contentA = Buffer.from("Matter Passport conformance fixture - exhibit A contents.");
  const recordA = { ...makeRecord("fx-record-001", "exhibit-a.txt", "text/plain", contentA, "records/fx-record-001/content.bin"), embeddedBytes: contentA };
  const recordB = makeRecord("fx-record-002", "retainer-agreement.pdf", "application/pdf", null, "records/fx-record-002/content.bin");

  // Snapshot A: genesis -> records -> key.registered(keyA) -> manifest.
  await chain.add("passport.created", "fx-user", "user", { matterId: "fx-matter-001" });
  await chain.add("record.registered", "fx-user", "user", { recordId: recordA.recordId, filename: recordA.filename, digestValue: recordA.digest.value });
  await chain.add("record.registered", "fx-user", "user", { recordId: recordB.recordId, filename: recordB.filename, digestValue: recordB.digest.value });
  await chain.add("key.registered", "fx-user", "user", { keyId: keyA.id, fingerprint: keyA.fingerprint, ownerType: "workspace", ownerId: "fx-workspace" });
  const eventsA = [...chain.events];
  const dirA = join(ROOT, "basic", "snapshot-a");
  const pkgA = await buildSnapshotPackage({
    dir: dirA, passportId, snapshotId: "fx-snap-a", key: keyA,
    records: [recordA, recordB], events: eventsA, scope: "full", fileName: "passport.lcp",
  });
  await chain.add("snapshot.created", "fx-user", "user", { snapshotId: "fx-snap-a", scope: "full", recordCount: 2 });
  await chain.add("snapshot.signed", "fx-user", "user", { snapshotId: "fx-snap-a", keyId: keyA.id, manifestDigest: pkgA.manifestDigest });

  // Snapshot B: key rotation to keyB + a third record; chains to A.
  await chain.add("key.rotated", "fx-user", "user", { previousFingerprint: keyA.fingerprint, fingerprint: keyB.fingerprint, keyId: keyB.id });
  await chain.add("key.registered", "fx-user", "user", { keyId: keyB.id, fingerprint: keyB.fingerprint, ownerType: "workspace", ownerId: "fx-workspace" });
  const contentC = Buffer.from("Interim production covering note - fixture record C.");
  const recordC = { ...makeRecord("fx-record-003", "covering-note.txt", "text/plain", contentC, "records/fx-record-003/content.bin"), embeddedBytes: contentC };
  recordC.recordType = "document";
  await chain.add("record.registered", "fx-user", "user", { recordId: recordC.recordId, filename: recordC.filename, digestValue: recordC.digest.value });
  const eventsB = [...chain.events];
  const dirB = join(ROOT, "basic", "snapshot-b");
  const pkgB = await buildSnapshotPackage({
    dir: dirB, passportId, snapshotId: "fx-snap-b", key: keyB,
    records: [recordA, recordB, recordC], events: eventsB, scope: "selected",
    previous: { snapshotId: "fx-snap-a", manifestDigest: pkgA.manifestDigest }, fileName: "passport.lcp",
  });

  writeExpected(dirA, pkgA, [
    { id: "parse", status: "pass" }, { id: "manifest", status: "pass" }, { id: "schema", status: "pass" },
    { id: "protocol", status: "info" },
    { id: "records", status: "warn" }, { id: "events", status: "pass" }, { id: "merkle", status: "pass" },
    { id: "signature", status: "pass" }, { id: "identity", status: "info" },
    { id: "keylineage", status: "pass" }, { id: "keystatus", status: "info" },
    { id: "timestamp", status: "info" },
  ]);
  writeExpected(dirB, pkgB, [
    { id: "parse", status: "pass" }, { id: "manifest", status: "pass" }, { id: "schema", status: "pass" },
    { id: "protocol", status: "info" },
    { id: "records", status: "warn" }, { id: "events", status: "pass" }, { id: "merkle", status: "pass" },
    { id: "signature", status: "pass" }, { id: "identity", status: "info" },
    { id: "keylineage", status: "pass" }, { id: "keystatus", status: "info" },
    { id: "lineage", status: "info" }, { id: "timestamp", status: "info" },
    { id: "scope", status: "info" },
  ]);
  console.log("basic written");
}

// --- receipts -----------------------------------------------------------------

async function genReceipts() {
  const dir = join(ROOT, "receipts");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const key = newKey("fx-recipient-key");
  const base = {
    version: "lc-transfer-receipt-v1",
    tokenHash: sha256b64("fx-transfer-token-0001"),
    snapshotId: "fx-snap-a",
    manifestDigest: "fx-manifest-digest-placeholder",
    decision: "accepted",
    createdAt: "2026-01-15T11:00:00.000Z",
  };
  const sign = (payload) => ({
    payload,
    algorithm: "ES256",
    signatureValue: signP1363(key.privateKey, canonicalize(payload)),
    publicKeyJwk: key.publicKeyJwk,
    keyFingerprint: key.fingerprint,
  });
  // Accepted receipt bound to the real snapshot-a manifest digest.
  const snapAManifest = JSON.parse(readFileSync(join(ROOT, "basic", "snapshot-a", "manifest.json"), "utf8"));
  const digestA = sha256b64(canonicalize(snapAManifest));
  const good = sign({ ...base, manifestDigest: digestA });
  // Wrong binding: valid signature over a different manifest digest.
  const wrongBinding = sign({ ...base, manifestDigest: sha256b64("a-different-package") });
  // Tampered payload: signature from `good`, payload altered after signing.
  const tampered = JSON.parse(JSON.stringify(good));
  tampered.payload.manifestDigest = sha256b64("tampered-after-signing");
  writeFileSync(join(dir, "receipt-accepted.json"), JSON.stringify(good, null, 2));
  writeFileSync(join(dir, "receipt-wrong-binding.json"), JSON.stringify(wrongBinding, null, 2));
  writeFileSync(join(dir, "receipt-tampered-payload.json"), JSON.stringify(tampered, null, 2));
  writeFileSync(join(dir, "expected-report.json"), JSON.stringify({
    description: "Expected receipt verification results",
    receipts: [
      { file: "receipt-accepted.json", signature: "pass", binding: "must-match-caller-supplied-digests" },
      { file: "receipt-wrong-binding.json", signature: "pass", binding: "fails against snapshot-a manifestDigest" },
      { file: "receipt-tampered-payload.json", signature: "fail", note: "payload altered after signing - canonical bytes no longer match signature" },
    ],
  }, null, 2));
  console.log("receipts written");
}

// --- vectors -------------------------------------------------------------------

async function genVectors() {
  const dir = join(ROOT, "vectors");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  const canonCases = [
    ["flat object", { b: 1, a: 2 }],
    ["nested key sort", { z: { b: 1, a: 2 }, a: [{ d: 4, c: 3 }] }],
    ["array order preserved", { list: [3, 1, 2], items: [{ y: 1, x: 2 }, { b: 1, a: 2 }] }],
    ["unicode", { text: "Crème brûlée - solicitor's café" }],
    ["astral characters", { note: "scales of justice ⚖ and mathematical 𝐥𝐚𝐰" }],
    ["string escapes", { s: "quote\" backslash\\ newline\n tab\t nul" }],
    ["line separator", { s: "a b c" }],
    ["empty containers", { obj: {}, arr: [] }],
    ["primitives", { n: null, t: true, f: false, i: 42, neg: -7 }],
    ["number forms", { int: 9007199254740991, float: 1.5, exp: 1e21, negzero: -0 }],
    ["utf16 key order", { "b": 1, "A": 2, "a": 3, "Z": 4 }],
    ["deep nesting", { a: { b: { c: { d: { e: [1, { f: 2 }] } } } } }],
  ];
  const canonicalization = canonCases.map(([name, input]) => ({
    name, input, canonical: canonicalize(input), sha256: sha256b64(canonicalize(input)),
  }));
  writeFileSync(join(dir, "canonicalization.json"), JSON.stringify({
    description: "JCS-lite canonicalization vectors - canonical form and SHA-256 b64url digest of the canonical bytes",
    vectors: canonicalization,
  }, null, 2));

  const merkleLeaves = ["alpha-digest", "bravo-digest", "charlie-digest", "delta-digest", "echo-digest"];
  const merkleTree = buildMerkle(merkleLeaves);
  writeFileSync(join(dir, "merkle.json"), JSON.stringify({
    description: "lc-pproof-v1 Merkle vectors - sorted leaves, domain-tagged leaf/node hashes, odd-leaf duplication",
    leaves: merkleTree.leaves,
    root: merkleTree.root,
    proofs: merkleLeaves.map((l) => proofOf(merkleTree, merkleTree.leaves.indexOf(l))),
  }, null, 2));

  const evPayload = { matterId: "fx-matter-001", note: "genesis payload" };
  const payloadDigest1 = sha256b64(JSON.stringify(evPayload));
  const eventDigest1 = sha256b64(`1|passport.created||${payloadDigest1}`);
  const evPayload2 = { recordId: "fx-record-001", filename: "exhibit-a.txt", digestValue: "abc123" };
  const payloadDigest2 = sha256b64(JSON.stringify(evPayload2));
  const eventDigest2 = sha256b64(`2|record.registered|${eventDigest1}|${payloadDigest2}`);
  writeFileSync(join(dir, "event-digest.json"), JSON.stringify({
    description: "Event chain digest vectors - payloadDigest = sha256(JSON.stringify(payload)); eventDigest = sha256(seq|type|prevOrEmpty|payloadDigest)",
    events: [
      { sequenceNumber: 1, eventType: "passport.created", previousEventDigest: null, payload: evPayload, payloadDigest: payloadDigest1, eventDigest: eventDigest1 },
      { sequenceNumber: 2, eventType: "record.registered", previousEventDigest: eventDigest1, payload: evPayload2, payloadDigest: payloadDigest2, eventDigest: eventDigest2 },
    ],
  }, null, 2));

  // Transfer envelope: fixed key/IV/plaintext -> deterministic AES-256-GCM.
  const keyBytes = Buffer.from("0123456789abcdef0123456789abcdef", "utf8"); // 32 bytes
  const iv = Buffer.from("fx-iv-012345", "utf8"); // 12 bytes
  const plain = Buffer.from("lc-transfer-v1 conformance vector payload", "utf8");
  const cipher = createCipheriv("aes-256-gcm", keyBytes, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  const envelope = { v: "lc-transfer-v1", iv: b64std(iv), data: b64std(Buffer.concat([ct, tag])) };
  writeFileSync(join(dir, "transfer-envelope.json"), JSON.stringify({
    description: "lc-transfer-v1 envelope vector - AES-256-GCM, 12-byte IV, ciphertext||tag in data (standard base64); the share-link #k= fragment carries the raw 32-byte key as JWK k (base64url); the stored blob is base64(JSON.stringify(envelope))",
    key: { kty: "oct", k: b64url(keyBytes), alg: "A256GCM" },
    envelope,
    plaintextBase64: b64std(plain),
  }, null, 2));
  console.log("vectors written");
}

rmSync(join(ROOT, "legacy-v1"), { recursive: true, force: true });
rmSync(join(ROOT, "basic"), { recursive: true, force: true });
await genLegacy();
await genBasic();
await genReceipts();
await genVectors();
console.log("all fixtures regenerated");
