# LawCribs Matter Passport Protocol v1.1.0
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


An open specification for portable, cryptographically verifiable matter records. Any implementation conforming to this document produces packages LawCribs and other verifiers can check.

## Compatibility policy

- Version fields (`formatVersion`, `schemaVersion`) use `major.minor.patch`. The `format` tag `lawcribs-matter-passport` is the only hard gate - a verifier MUST accept any `formatVersion` it does not recognize as long as the format tag matches and required fields are present.
- Changes within a major version are additive-only: new optional manifest fields, new event types, new check ids. Verifiers MUST ignore manifest fields they do not recognize (they remain covered by the signature and Merkle root because canonicalization and digesting run over the bytes as received).
- `1.0.0` packages remain fully verifiable; `fixtures/legacy-v1/` is a known-good 1.0.0 package proving it.
- Digest and signature formulas are normative and unchanged since v1 - see `CANONICALIZATION.md` and `fixtures/vectors/` for known-answer tests every implementation should pass.

## Format

A Matter Passport is delivered as a `.lcp` (LawCribs Passport Package) ZIP container (layout in `PACKAGE_FORMAT.md`) carrying:

- `manifest.json` - the canonical manifest (schema below)
- `signatures/manifest-signature.json` - the ES256 signature record
- `records/<recordId>/` - metadata + optional content bytes per record
- `events/events.jsonl` + `checkpoint.json` - the hash-chained event log
- `proofs/merkle-proofs/` - optional per-record inclusion proofs
- `verification/README.txt` - plain-language verification instructions

## Manifest schema (v1)

```json
{
  "format": "lawcribs-matter-passport",
  "formatVersion": "1.1.0",
  "schemaVersion": "1.1.0",
  "protocol": { "name": "LawCribs Matter Passport", "maintainer": "LawCribs", "specUrl": "https://lawcribs.com/matter-passport-spec/PROTOCOL.md" },
  "matterId": "opaque-id",
  "snapshotId": "opaque-id",
  "previousSnapshotId": "opaque-id (optional, v-next)",
  "previousSnapshotDigest": "b64url sha-256 of the prior canonical manifest (optional, v-next)",
  "createdAt": "RFC3339-UTC",
  "scope": { "type": "full | selected | partial | redacted" },
  "records": [{ "recordId", "recordType", "filename", "mediaType", "size", "digest": {"algorithm":"sha-256","encoding":"base64url","value":"..."}, "contentLocation", "parentRecordId?", "provenanceClass" }],
  "eventRange": { "fromSequence": 1, "toSequence": 24 },
  "integrity": { "canonicalization": "JCS-lite", "manifestDigestAlgorithm": "sha-256", "merkleRoot": "..." },
  "aiOutputs": [{ "recordId", "digest", "`provenanceRef` (a `lc-provenance-v1:`-prefixed chain commitment - the anchor Merkle root when one exists, else the recomputed root - never an internal id) bound to the chain state at `upToSequence` - the root of exactly that prefix, so later appends do not break the manifest", "providerRef?", "modelRef?", "reviewStatus", "editedAfterGeneration" }],
  "signatures": [{ "signatureId", "algorithm": "ES256", "keyId" }]
}
```

## Canonicalization ("JCS-lite")

RFC 8785 profile over the manifest object: keys sorted, UTF-8, JSON.stringify number semantics, no undefined. Duplicate keys MUST be rejected at parse time. The manifest digest is `SHA-256(canonical(manifest))` encoded base64url. The full normative definition - including the `JSON.stringify` (non-canonical) rule for event `payloadDigest`, digest formulas, and signature encoding - lives in `CANONICALIZATION.md`; `fixtures/vectors/` pins every formula with known-answer tests.

## Signature profile

- Algorithm: ES256 (ECDSA P-256 + SHA-256) over the canonical manifest bytes
- Signature envelope: `{ id, snapshotId, keyId, algorithm, payloadDigest, signatureValue, publicKeyJwk, timeAssuranceLevel, createdAt }`
- Signature value: raw IEEE-P1363 `r || s` (64 bytes), base64url, no padding - NOT DER. This matches WebCrypto `crypto.subtle.sign` output; DER-encoded signatures fail verification.

## Merkle proof profile

- Domain tag: `lc-pproof-v1`
- Leaf: `sha256(tag|leaf|<digest>)`; node: `sha256(tag|node|<left>|<right>)`
- Sorted leaves over record digests + event digests; odd leaves duplicate
- Root lives at `integrity.merkleRoot`; proofs as `{"leafIndex","siblings":[{"position","digest"}],"root"}`

## Verification (honest claims)

A conformant verifier reports per-check results, never a bare "verified":

- Package parsed safely (traversal, zip-bomb, duplicate entries, size/count/depth caps rejected)
- Manifest present + schema valid
- Record digests match (per-record; missing content is a scope warning, not a failure)
- Merkle root recomputed over record + event digests and compared to the signed `integrity.merkleRoot`
- Event chain intact - linkage plus recomputed `eventDigest` per event, within the declared `eventRange`. Partial ranges are supported: when `fromSequence > 1` the first event's `previousEventDigest` commits to history outside the package, so verifiers accept it as an opaque boundary (it must be a non-empty digest string) and disclose that the link to earlier events is not verifiable from this package alone. A windowed package whose first event claims genesis linkage (`previousEventDigest: null`) is inconsistent and fails.
- Manifest signature valid - proves key possession only
- Signer identity NOT independently established
- Timestamp is client-reported unless a trusted timestamp is attached
- Scope disclosure for selected/partial/redacted packages

## Transfer envelope

Packages move between workspaces as encrypted blobs: `{v:"lc-transfer-v1", iv, data}` = `AES-256-GCM(package)` under a fresh key delivered in the share URL `#k=` fragment. Relays store ciphertext + opaque metadata only - the token column holds the SHA-256 hash, never the plaintext token, and `recipient_ref` is never stored. `GET` serves the blob and claims a fetch slot atomically - a `max_fetches` cap (one-time link = 1) cannot be raced; only `revoked`/`expired` block fetches, since a leaked `declined` must not burn access. `PATCH` acknowledges `delivered`/`decrypted`/`accepted`/`declined` under strictly-forward transition rules (rank initiated<delivered<decrypted<terminal; the sole exception is `declined`->`accepted` reconsideration). `revoked` is a sender action on the owner-authed route only - the share token cannot revoke. Uploads, the status listing, and revocation require the workspace `x-workspace-owner-token`; token-gated routes are rate-limited via a shared DB-backed limiter.

### Recipient receipts

A LawCribs recipient MAY countersign its accept/decline acknowledgement with the workspace's ES256 passport signing key. Receipts form an append-only collection (`passport_transfer_receipts`) - a link acknowledged by several parties keeps every countersignature; the relay dedupes by `keyFingerprint`+`manifestDigest`. Each receipt is a self-contained object:

```json
{
  "payload": {
    "version": "lc-transfer-receipt-v1",
    "tokenHash": "<sha256-b64url(raw token)>",
    "snapshotId": "<snapshot id from manifest>",
    "manifestDigest": "<sha256-b64url(canonical manifest)>",
    "decision": "accepted | declined",
    "createdAt": "<client-reported ISO time>"
  },
  "algorithm": "ES256",
  "signatureValue": "<b64url ECDSA over canonical payload>",
  "publicKeyJwk": { "...": "P-256 public key" },
  "keyFingerprint": "<sha256-b64url of the public key JWK>"
}
```

The relay enforces only the bindings it can check - the receipt's `tokenHash` must equal the stored token hash and `decision` must equal the submitted status. Signature verification is the sender's job, not the relay's: the sender verifies ES256 over the canonical payload against the embedded `publicKeyJwk`, then checks `payload.tokenHash` equals the local `tokenHash` and `payload.manifestDigest` equals `sha256(canonical manifestJson)` of the exported snapshot. Only a receipt passing all checks lands on the transfer row and as a `transfer.receipt` event; a failed receipt is recorded as `receiptVerification: "failed"` on the ack event, so forgery attempts stay visible rather than silently dropped.

A verified receipt proves the holder of the recipient workspace's signing key acknowledged those exact package bytes for that transfer - stronger than a token-capability PATCH because it binds the ack to a key identity and to the content. It still does not prove legal identity, and timestamps remain client-reported. Receipts are optional by design: external recipients send plain acknowledgements and both states are reported distinctly.

### Snapshot lineage and key lifecycle

Snapshots chain: manifests carry `previousSnapshotId` + `previousSnapshotDigest` (the prior snapshot's canonical manifest digest), both inside the signed bytes. Anyone holding an earlier package can verify the lineage - a rewritten history is detectable rather than indistinguishable. Signing keys also live in the chain: `key.registered`/`key.rotated` events are emitted inside the signed `eventRange` before the manifest is computed, so a verifier can check the signature's `keyId` against the passport's own key lifecycle (self-consistency, not identity).

### Time assurance, revocation, and the key directory

Timestamps in packages are client-reported and labeled as such. Two optional relay services raise assurance without becoming trusted third parties:

- **Anchors** (`POST/GET /api/passport/anchors`): the earliest time the relay saw a manifest digest, keyed by digest only. Relay-reported - stronger than client-reported, weaker than a TSA.
- **Key directory** (`POST/GET /api/passport/directory`): workspaces publish signing-key status (`current`/`revoked`) under a server-recomputed fingerprint. Public keys only. Hosted verification reports `current`/`revoked`/`unknown`; offline verification reports that status is not checkable from the package alone.

Revocation is forward-looking: packages signed before a key was revoked still verify - `verify-at-signing-time` is the semantic, and reports must say so rather than implying retroactive invalidation.

Scope is self-asserted: a `full` manifest claims completeness at snapshot time but cannot prove no record was withheld. Verifiers report the claim, not the guarantee.

## License, trademark, and governance

- Specification text: **CC-BY-4.0**; reference code (conformance verifier, SDK modules, CLI): **MIT** - see `LICENSE.md`.
- "Matter Passport" is a LawCribs mark - see `TRADEMARK.md`. Implementing this protocol does not imply LawCribs endorsement or certification.
- Stewardship and the change process are described in `GOVERNANCE.md`; vulnerability reporting in `SECURITY.md`.
- All protocol artifacts are publicly downloadable under `/matter-passport-spec/` - spec, fixtures, `conformance/`, `sdk/`, and `tools/` directories.

## Import semantics

Recipients verify, then rebuild locally: record ids are remapped (derivative `parentRecordId` links follow the remap), original digests are preserved so integrity still verifies, contents re-encrypt under the recipient workspace key, provenance is `externally-attested`, the sender's event chain ships as a provenance record, and re-importing the same snapshot is refused.
