import { canonicalize } from "./canonical";
import { sha256Base64 } from "./hash";
import { verifyManifest } from "./signing";
import { buildMerkleTree } from "./merkle";
import type { MatterManifest, PassportSignature } from "./types";

/**
 * Safe .lcp package parser and verifier. Extraction is defensive:
 * bounded size/count/depth, path-traversal and decompression-bomb
 * rejection, duplicate-ID and manifest-reference validation.
 */

const MAX_PACKAGE_BYTES = 256 * 1024 * 1024;
const MAX_FILE_COUNT = 2000;
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_PATH_DEPTH = 6;

export interface VerificationCheck {
  id: string;
  label: string;
  status: "pass" | "fail" | "warn" | "info";
  detail: string;
}

export interface VerificationReport {
  checks: VerificationCheck[];
  scope: string;
  recordCount: number;
  eventCount: number;
}

export async function parsePackage(data: ArrayBuffer | Uint8Array): Promise<Map<string, Uint8Array>> {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (bytes.byteLength > MAX_PACKAGE_BYTES) throw new Error("package exceeds maximum size");
  const JSZip = (await import("jszip")).default;
  const zip = await JSZip.loadAsync(bytes);
  const files = new Map<string, Uint8Array>();
  let total = 0;
  for (const [path, entry] of Object.entries(zip.files)) {
    if (entry.dir) continue;
    if (path.includes("..") || path.startsWith("/") || /^[a-zA-Z]:/.test(path)) throw new Error(`unsafe path: ${path}`);
    if (path.split("/").length > MAX_PATH_DEPTH) throw new Error(`path too deep: ${path}`);
    if (files.size >= MAX_FILE_COUNT) throw new Error("too many files in package");
    if (files.has(path)) throw new Error(`duplicate package entry: ${path}`);
    const bytes = await entry.async("uint8array");
    if (bytes.byteLength > MAX_FILE_BYTES) throw new Error(`file too large: ${path}`);
    total += bytes.byteLength;
    if (total > MAX_TOTAL_BYTES) throw new Error("package decompressed size limit exceeded");
    files.set(path, bytes);
  }
  return files;
}

export async function verifyPackage(data: ArrayBuffer | Uint8Array): Promise<VerificationReport> {
  const checks: VerificationCheck[] = [];
  const push = (id: string, label: string, status: VerificationCheck["status"], detail: string) => checks.push({ id, label, status, detail });

  let files: Map<string, Uint8Array>;
  try {
    files = await parsePackage(data);
    push("parse", "Package parsed safely", "pass", `${files.size} entries within limits`);
  } catch (err) {
    push("parse", "Package parsed safely", "fail", err instanceof Error ? err.message : "parse failed");
    return { checks, scope: "unknown", recordCount: 0, eventCount: 0 };
  }

  const manifestBytes = files.get("manifest.json");
  if (!manifestBytes) {
    push("manifest", "Manifest present", "fail", "manifest.json missing");
    return { checks, scope: "unknown", recordCount: 0, eventCount: 0 };
  }
  push("manifest", "Manifest present", "pass", "manifest.json found");

  let manifest: MatterManifest;
  try {
    manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as MatterManifest;
    if (manifest.format !== "lawcribs-matter-passport") throw new Error("wrong format tag");
    if (!Array.isArray(manifest.records)) throw new Error("records is not an array");
    push("schema", "Manifest schema valid", "pass", `formatVersion ${manifest.formatVersion}, scope ${manifest.scope.type}`);
    if (manifest.protocol?.maintainer) {
      push("protocol", "Protocol steward", "info", `${manifest.protocol.name} - maintained by ${manifest.protocol.maintainer}`);
    }
  } catch (err) {
    push("schema", "Manifest schema valid", "fail", err instanceof Error ? err.message : "schema invalid");
    return { checks, scope: "unknown", recordCount: 0, eventCount: 0 };
  }

  const seen = new Set<string>();
  let digestFails = 0;
  let digestSkipped = 0;
  for (const rec of manifest.records) {
    if (seen.has(rec.recordId)) {
      push("records", "Record digests match", "fail", `duplicate recordId ${rec.recordId}`);
      return { checks, scope: manifest.scope.type, recordCount: manifest.records.length, eventCount: 0 };
    }
    seen.add(rec.recordId);
    const content = files.get(rec.contentLocation ?? `records/${rec.recordId}/content.bin`);
    if (!content) { digestSkipped++; continue; }
    if ((await sha256Base64(content)) !== rec.digest.value) digestFails++;
  }
  push(
    "records",
    "Record digests match",
    digestFails ? "fail" : digestSkipped ? "warn" : "pass",
    digestFails
      ? `${digestFails} of ${manifest.records.length} records fail digest`
      : digestSkipped
        ? `${digestSkipped} records not included in package (scope: ${manifest.scope.type})`
        : `all ${manifest.records.length} record digests match`,
  );

  let eventCount = 0;
  const eventDigests: string[] = [];
  const parsedEvents: Record<string, unknown>[] = [];
  const eventsFile = files.get("events/events.jsonl");
  if (eventsFile) {
    const lines = new TextDecoder().decode(eventsFile).trim().split("\n").filter(Boolean);
    eventCount = lines.length;
    let chainOk = true;
    let prev: string | null = null;
    // The declared range can start anywhere - the expected sequence
    // follows the manifest window, not an assumed 1..N.
    const fromSeq = manifest.eventRange?.fromSequence ?? 1;
    let seq = fromSeq - 1;
    for (const line of lines) {
      seq++;
      let ev: Record<string, unknown>;
      try {
        ev = JSON.parse(line);
      } catch {
        chainOk = false;
        break;
      }
      // A windowed range's first event commits to history outside the
      // package - that link cannot be recomputed here, so the declared
      // digest is accepted as an opaque boundary and disclosed below.
      const prevOk = seq === fromSeq && fromSeq > 1
        ? typeof ev.previousEventDigest === "string" && ev.previousEventDigest.length > 0
        : ev.previousEventDigest === prev;
      if (ev.sequenceNumber !== seq || !prevOk) { chainOk = false; break; }
      // Recompute the digest over the declared formula so a forged
      // payload cannot survive linkage alone.
      const payloadDigest = await sha256Base64(JSON.stringify(ev.payload));
      const recomputed = await sha256Base64(`${ev.sequenceNumber}|${ev.eventType}|${ev.previousEventDigest ?? ""}|${payloadDigest}`);
      if (recomputed !== ev.eventDigest || payloadDigest !== ev.payloadDigest) { chainOk = false; break; }
      parsedEvents.push(ev);
      eventDigests.push(ev.eventDigest as string);
      prev = ev.eventDigest as string;
    }
    push("events", "Event chain intact", chainOk ? "pass" : "fail",
      chainOk
        ? fromSeq > 1
          ? `${eventCount} events consistent from sequence ${fromSeq} - link to earlier events not verifiable from this package`
          : `${eventCount} events, chain and digests consistent`
        : `chain broken at sequence ${seq}`);
    if (manifest.eventRange) {
      const expected = manifest.eventRange.toSequence - manifest.eventRange.fromSequence + 1;
      if (expected !== eventCount || manifest.eventRange.fromSequence > manifest.eventRange.toSequence || manifest.eventRange.fromSequence < 1) {
        push("eventrange", "Event range matches manifest", "fail", `manifest declares ${manifest.eventRange.fromSequence}-${manifest.eventRange.toSequence} (${expected} events), file has ${eventCount}`);
      }
    }
  } else {
    push("events", "Event chain intact", "warn", "no event file in package");
  }

  // The signature-anchored check: recompute the Merkle root over the
  // digests the manifest claims and compare to integrity.merkleRoot.
  if (manifest.integrity?.merkleRoot) {
    const tree = await buildMerkleTree([...manifest.records.map((r) => r.digest.value), ...eventDigests]);
    const rootOk = tree.root === manifest.integrity.merkleRoot;
    push("merkle", "Merkle root matches signed manifest", rootOk ? "pass" : "fail",
      rootOk ? `root ${manifest.integrity.merkleRoot.slice(0, 20)}... recomputed` : "recomputed root differs - package contents were altered after signing");
  }

  // AI provenance: for each declared aiOutput, the package may carry
  // the generation chain + anchors. Validate what is embedded, report
  // honestly what is only referenced.
  if (Array.isArray(manifest.aiOutputs) && manifest.aiOutputs.length) {
    let verified = 0, referenced = 0, broken = 0;
    for (const ai of manifest.aiOutputs) {
      const slice = files.get(`provenance/${ai.recordId}.json`);
      if (!slice) { referenced++; continue; }
      try {
        const { records: chain, anchors } = JSON.parse(new TextDecoder().decode(slice)) as { records?: Array<{ sequence?: number; outputHash?: string; hash?: string }>; anchors?: Array<{ merkleRoot?: string }> };
        let ok = true;
        let seq = 0;
        for (const rec of chain ?? []) {
          seq++;
          if (rec.sequence !== seq || !rec.outputHash) { ok = false; break; }
        }
        // Bind the manifest ref to the slice: the declared provenanceRef
        // must equal the chain commitment (anchor root, else recomputed).
        if (ok && typeof ai.provenanceRef === "string" && ai.provenanceRef.startsWith("lc-provenance-v1:")) {
          const expected = ai.provenanceRef.slice("lc-provenance-v1:".length);
          // The ref commits to the chain state as of upToSequence (the
          // whole slice when absent). It binds to any anchor root in
          // the slice or to the recomputed root of that exact prefix -
          // so later appends never break a bound manifest.
          const ups = ai.upToSequence as number | undefined;
          if (ups !== undefined && (ups < 1 || ups > (chain?.length ?? 0))) { ok = false; }
          else {
            const prefix = (chain ?? []).slice(0, ups ?? chain?.length ?? 0);
            const joined = prefix.map((r) => r.hash ?? "").join("");
            const hexDigest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(joined)))).map((b) => b.toString(16).padStart(2, "0")).join("");
            const anchorRoots = (anchors ?? []).map((a) => a.merkleRoot).filter(Boolean) as string[];
            ok = anchorRoots.includes(expected) || expected === hexDigest;
          }
        }
        if (ok) verified++; else broken++;
      } catch { broken++; }
    }
    push("aiprovenance", "AI provenance",
      broken ? "fail" : verified ? "pass" : "info",
      broken
        ? `${broken} provenance slice(s) malformed or inconsistent`
        : verified
          ? `${verified} generation chain(s) verified in package${referenced ? `, ${referenced} referenced only` : ""}`
          : `${referenced} AI output(s) reference provenance not embedded in the package`);
  }

  const sigBytes = files.get("signatures/manifest-signature.json");
  if (sigBytes) {
    try {
      const sig = JSON.parse(new TextDecoder().decode(sigBytes)) as PassportSignature;
      const canonical = canonicalize(manifest);
      const ok = await verifyManifest(canonical, sig);
      push("signature", "Manifest signature valid", ok ? "pass" : "fail", ok ? `ES256 signature by key ${sig.keyId}` : "signature does not verify");
      push("identity", "Signer identity independently established", "info", "signature proves key possession only; signer identity requires separate evidence");

      // Key lineage: v-next packages carry key.registered/rotated
      // events, so the signing key can be checked against the chain it
      // signed - self-consistency, not identity. Absence is reported,
      // not failed, for pre-v-next manifests.
      const keyEvents = parsedEvents.filter((e) => e.eventType === "key.registered" || e.eventType === "key.rotated");
      if (keyEvents.length) {
        const inChain = keyEvents.some((e) => (e.payload as { keyId?: string })?.keyId === sig.keyId);
        push("keylineage", "Signing key registered in chain", inChain ? "pass" : "warn",
          inChain ? "signature key appears in the event chain's key lifecycle" : "signature key does not appear in the chain's key events");
      } else {
        push("keylineage", "Signing key registered in chain", "info", "no key lifecycle events in package - manifest predates key lineage tracking");
      }
      push("keystatus", "Signing key status", "info", "revocation state is not verifiable from the package alone - hosted verification reports live key status from the directory");
    } catch (err) {
      push("signature", "Manifest signature valid", "fail", err instanceof Error ? err.message : "signature invalid");
    }
  } else {
    push("signature", "Manifest signature valid", "warn", "no signature file in package");
  }

  if (manifest.previousSnapshotDigest) {
    push("lineage", "Snapshot lineage", "info",
      `manifest declares a link to prior snapshot ${manifest.previousSnapshotId ?? "unknown"} - verifiable against an earlier package`);
  }
  push("timestamp", "Timestamp assurance", "info", "timestamps are client-reported; check hosted verification for relay-anchored digest timestamps");
  if (manifest.scope.type !== "full") push("scope", "Package scope", "info", `package contains ${manifest.scope.type} records and is not a complete matter record`);

  return { checks, scope: manifest.scope.type, recordCount: manifest.records.length, eventCount };
}
