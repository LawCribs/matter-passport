# Conformance Fixtures

Maintained by LawCribs.

Fixture packages and vectors for cross-implementation testing (see CONFORMANCE.md and CANONICALIZATION.md).

## Layout

- `legacy-v1/` - a valid `formatVersion` 1.0.0 package; proves pre-v-next manifests still verify.
- `basic/snapshot-a/`, `basic/snapshot-b/` - v-next packages. B chains to A through `previousSnapshotDigest` and uses a rotated signing key, exercising the lineage and keylineage checks.
- `receipts/` - `lc-transfer-receipt-v1` vectors: a valid receipt, a valid signature over the wrong binding, and a payload tampered after signing.
- `vectors/` - known-answer vectors for canonicalization, Merkle proofs, event digests, and the transfer envelope.

Each package directory ships `passport.lcp` plus `manifest.json`, `manifest-signature.json`, and `expected-report.json` listing every check result a conformant verifier must produce.

## Regenerating

```sh
# matter-passport repository:
node tools/generate-passport-fixtures.mjs fixtures

# LawCribs application repository (default output docs/matter-passport/fixtures):
node scripts/generate-passport-fixtures.mjs
```

The generator replicates the reference formulas exactly (JCS-lite, base64url digests, `lc-pproof-v1` Merkle tags, ES256 in raw IEEE-P1363 format). In the LawCribs app, `src/lib/passport/__tests__/fixtures.test.ts` verifies every fixture against the app's own verifier and fails on any drift.

`conformance/lawcribs_conformance.py` is a zero-dependency Python verifier written from the spec - use it to check your own implementation against these fixtures.
