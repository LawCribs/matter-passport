# Matter Passport

An open protocol for cryptographically verifiable legal matter records, maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.

A Matter Passport (`.lcp`) is a signed, tamper-evident package containing a matter's records, an append-only event chain, and a Merkle root anchored by an ES256 signature. Verification is deliberately honest: every check is reported individually, never collapsed into a single "verified" verdict.

This repository contains the specification, conformance fixtures, and reference tooling. No LawCribs account is required to implement, verify, or certify against the protocol.

## Repository layout

- `PROTOCOL.md` - the full format, canonicalization, signature and Merkle profiles, compatibility policy
- `PACKAGE_FORMAT.md` - the `.lcp` ZIP layout
- `CANONICALIZATION.md` - normative JCS-lite rules and every digest/signature formula
- `SDK.md` - the TypeScript SDK surface + reference CLI
- `CONFORMANCE.md` - the certification checklist
- `KEY_MANAGEMENT.md` - workspace and organisation signing keys, directory publication
- `GOVERNANCE.md` - stewardship, the change process, and versioning rules
- `SECURITY.md` - vulnerability disclosure policy
- `TRADEMARK.md` - naming and usage guidelines for "Matter Passport" and `.lcp`
- `V2-ROADMAP.md` - design-only plan for identity binding, trusted timestamping, and federation
- `conformance/` - zero-dependency Python reference verifier
- `sdk/` - standalone TypeScript verification modules
- `tools/` - reference Node CLI and fixture generator
- `fixtures/` - known-good packages and expected verification results

## Quickstart

Requires Node.js 20+ (for the tools) and Python 3 (for the independent verifier).

```sh
npm install
npm run fixtures   # regenerate fixtures/ from scratch
npm run verify -- fixtures/basic/snapshot-a/passport.lcp
```

Run the independent Python verifier against the committed fixtures:

```sh
python conformance/lawcribs_conformance.py package fixtures/basic/snapshot-a/passport.lcp
python conformance/lawcribs_conformance.py vectors fixtures/vectors
python conformance/lawcribs_conformance.py receipt fixtures/receipts/receipt-accepted.json
```

See `CONFORMANCE.md` for the full self-certification checklist.

## Hosted surfaces

LawCribs operates the canonical reference deployment:

- Styled spec docs: https://lawcribs.com/developers/passport/spec
- Raw spec mirror: https://lawcribs.com/matter-passport-spec/
- Public package verification: https://lawcribs.com/verify-passport
- Signing-key directory and digest anchors: see `PROTOCOL.md`

## License

Specification text is CC-BY-4.0; reference code is MIT. See `LICENSE.md`. The LawCribs name and marks are governed by `TRADEMARK.md`; LawCribs-operated services are not covered by the protocol license.
