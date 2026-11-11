# Developer Portal - Matter Passport
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


Entry point for external verifiers and integrators.

## Contents

- `PROTOCOL.md` - the full format, canonicalization, signature and Merkle profiles, plus the compatibility policy
- `PACKAGE_FORMAT.md` - the .lcp ZIP layout
- `CANONICALIZATION.md` - normative JCS-lite rules and every digest/signature formula
- `SDK.md` - the TypeScript SDK surface + reference CLI
- `CONFORMANCE.md` - the certification checklist + fixture pointers
- `KEY_MANAGEMENT.md` - workspace and organisation signing keys, directory publication
- `GOVERNANCE.md` - stewardship, the change process, and versioning rules
- `SECURITY.md` - vulnerability disclosure policy for protocol artifacts
- `TRADEMARK.md` - naming and usage guidelines for "Matter Passport" and `.lcp`
- `LICENSE.md` - dual licensing: spec text CC-BY-4.0, reference code MIT
- `V2-ROADMAP.md` - design-only plan for identity binding, trusted timestamping, and federation
- `fixtures/` - known-good packages and expected verification results: `legacy-v1` (1.0.0), `basic/snapshot-a`+`b` (chained v-next with key rotation), `receipts/`, `vectors/` (canonicalization/Merkle/event/envelope known-answer tests)

## Download the code

Everything below is public and MIT licensed - no LawCribs account or repository access required:

- `/matter-passport-spec/conformance/lawcribs_conformance.py` - zero-dependency Python reference verifier (+ `conformance/README.md`)
- `/matter-passport-spec/sdk/` - the standalone TypeScript verification modules (`hash.ts`, `canonical.ts`, `merkle.ts`, `signing.ts`, `verify.ts`, `types.ts`, `sdk.ts`)
- `/matter-passport-spec/tools/verify-passport.mjs` - reference Node CLI (needs `jszip`)
- `/matter-passport-spec/tools/generate-passport-fixtures.mjs` - fixture generator (maintainers)

Licensing: specification text is CC-BY-4.0, code is MIT - see `LICENSE.md`. "Matter Passport" is a LawCribs trademark - see `TRADEMARK.md`.

## Independent verifier

`conformance/lawcribs_conformance.py` is a zero-dependency Python implementation written from these documents alone - run it against the fixtures as your baseline self-check:

```sh
python lawcribs_conformance.py package fixtures/basic/snapshot-a/passport.lcp
python lawcribs_conformance.py vectors fixtures/vectors
python lawcribs_conformance.py receipt fixtures/receipts/receipt-accepted.json
```

(run from the directory containing the downloaded `lawcribs_conformance.py` and `fixtures/` - both under `/matter-passport-spec/`)

CI (`.github/workflows/passport-conformance.yml`) regenerates fixtures and runs this verifier plus the app's own suite on every passport change. `npm run conformance` runs the vectors locally; `tools/verify-passport.mjs <file.lcp>` is the reference Node CLI.

## API surface

- `POST /api/passport/verify` - manifest-only online verification, returns a shareable report
- `GET /api/passport/verify/[id]` - the stored report JSON
- `POST /api/passport/transfers` - relay an encrypted transfer blob
- `GET /api/passport/transfers/[token]` - token-gated blob delivery
- `PATCH /api/passport/transfers/[token]` - accept/decline
- `POST/GET /api/passport/anchors` - earliest relay sighting of a manifest digest (relay-reported time bound)
- `POST/GET /api/passport/directory` - public signing-key status directory

## Principles

- Verification reports per-check results - never a single "verified" verdict.
- Transfers stay zero-knowledge: ciphertext + opaque metadata on the relay.
- No matter content is ever required for online verification.
- Signatures are raw IEEE-P1363 `r || s` (64 bytes), base64url - never DER.
