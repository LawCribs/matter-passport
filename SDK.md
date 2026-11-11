# Matter Passport SDK
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


## Standalone surface

These files carry zero app imports - copy them into any project and the
full verification path runs unmodified. They are publicly downloadable at
`/matter-passport-spec/sdk/` (canonical sources: `src/lib/passport/`):

| File | Provides |
|------|----------|
| `hash.ts` | `sha256Base64` (SHA-256, base64url) |
| `canonical.ts` | JCS-lite `canonicalize` + `manifestDigest` |
| `merkle.ts` | `buildMerkleTree` / `verifyProof` (lc-pproof-v1) |
| `signing.ts` | `verifyManifest` (ES256, embedded JWK) |
| `verify.ts` | `parsePackage` + `verifyPackage` (needs jszip) |
| `types.ts` | Manifest, signature, and entity types |

External implementations vendor those files (plus `types.ts`) and
call `verifyPackage(bytes)` - no workspace, storage, or LawCribs runtime
required. MIT licensed - see `LICENSE.md`. The reference CLI
`/matter-passport-spec/tools/verify-passport.mjs` exercises the
same formulas with zero dependencies beyond `jszip`.


TypeScript surface: `src/lib/passport/sdk.ts` re-exports the same primitives the app runs - canonicalization, Merkle proofs, manifest/package verification, and the domain types.

```ts
import { verifyPackage, verifyManifest, buildMerkleTree, verifyProof, canonicalize, sha256Base64 } from "@/lib/passport/sdk";
```

## Reference CLI

Download `tools/verify-passport.mjs` from `/matter-passport-spec/tools/` (needs `npm i jszip` alongside it):

```bash
node verify-passport.mjs path/to/matter-passport.lcp
```

Runs the same per-check verification as the app - package safety, manifest schema, record digests, event chain, Merkle root, ES256 signature (P1363), key lineage, key status, snapshot lineage, timestamp and scope labels - and exits nonzero on any FAIL. For the in-app report use `/verify-passport` (offline) or `POST /api/passport/verify` (manifest-only).

## Conformance

`/matter-passport-spec/fixtures/` ships known-good packages + expected reports for cross-implementation testing: `legacy-v1` (1.0.0), `basic/snapshot-a`+`b` (chained v-next with key rotation), `receipts/` (signed transfer receipts), and `vectors/` (canonicalization, Merkle, event-digest, and transfer-envelope known-answer tests - see `CANONICALIZATION.md`). A conformant implementation MUST reproduce the expected check results.

`/matter-passport-spec/conformance/lawcribs_conformance.py` is a zero-dependency Python reference implementation written from the spec alone - the baseline self-check for any third-party verifier (MIT licensed, canonical source `conformance/lawcribs_conformance.py`):

```bash
python lawcribs_conformance.py package path/to/package.lcp
python lawcribs_conformance.py vectors path/to/fixtures/vectors
python lawcribs_conformance.py receipt path/to/receipt.json
```
