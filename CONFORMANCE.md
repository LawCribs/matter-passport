# Matter Passport Conformance Suite
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


External implementations certify against this checklist. Each item maps to a fixture in `fixtures/` (publicly served at `/matter-passport-spec/fixtures/`) and a unit test in `src/lib/passport/__tests__/`.

## Fixtures

- `fixtures/legacy-v1/` - a valid `formatVersion` 1.0.0 package; proves pre-v-next packages still verify.
- `fixtures/basic/snapshot-a/` + `snapshot-b/` - v-next packages; B chains to A via `previousSnapshotDigest` and rotates the signing key (`key.rotated`/`key.registered` events), exercising lineage and keylineage checks.
- `fixtures/receipts/` - signed `lc-transfer-receipt-v1` vectors: valid, valid-signature/wrong-binding, and payload-tampered.
- `fixtures/vectors/` - known-answer vectors for every digest formula (see `CANONICALIZATION.md`).

Fixture packages and expected reports are downloadable at `https://lawcribs.com/matter-passport-spec/fixtures/` and in this repository under `fixtures/`. Maintainers regenerate all fixtures with `node tools/generate-passport-fixtures.mjs fixtures` (in the LawCribs app repo the same script lives at `scripts/generate-passport-fixtures.mjs` with `docs/matter-passport/fixtures` as its default output). `src/lib/passport/__tests__/fixtures.test.ts` in the app fails if any fixture stops verifying or drifts from its `expected-report.json`.

## Required checks

1. Canonical determinism: canonicalizing the same manifest twice yields identical bytes; key order differences yield different digests.
2. Hash correctness: SHA-256 base64url digests match known vectors (empty, small text, binary, large).
3. Signature round-trip: a freshly signed manifest verifies; a tampered byte fails.
4. Event chain: sequence + previousEventDigest links validate; an inserted/removed/reordered event breaks the chain.
5. Merkle proofs: `verifyProof` accepts every leaf in a built tree and rejects foreign leaves, wrong roots, and odd-leaf edge cases.
6. Package round-trip: a built .lcp verifies; traversal (`../`), oversized entries, and duplicate recordIds are rejected.
7. Honest labels: reports distinguish digest match, signature validity, signer identity, timestamp assurance, and scope - never a single "verified" verdict.
8. Transfer envelope: AES-256-GCM blob + `#k=` fragment decrypts offline; ciphertext alone proves nothing about contents.
9. Receipt verification (v-next): `lc-transfer-receipt-v1` payloads verify ES256 over the canonical payload; tokenHash/manifestDigest/decision bindings are checked by the sender - a valid signature over the wrong digest still fails.
10. Key lineage (v-next): when `key.registered`/`key.rotated` events exist, the signature's `keyId` appears in them; absence is reported (pre-v-next manifest), never failed.
11. Transition rules (v-next): transfer statuses move strictly forward by rank; `declined`->`accepted` is the only reconsideration permitted, and `revoked` is never a token capability.

## Self-certification

Run your implementation against the fixtures, record the per-check results, and attest that all eleven checks pass. `lawcribs_conformance.py` (MIT, zero dependencies, Python 3.9+ stdlib only) is a reference implementation written from this spec - download it from `/matter-passport-spec/conformance/` and run it against the fixtures as the baseline self-check. Institutional adopters MAY submit results for listing as a conformant verifier.
