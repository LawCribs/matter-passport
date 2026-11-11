# Matter Passport - Governance
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


This document describes who decides what, how the protocol changes, and what implementers can rely on. It is deliberately short - the normative rules live in `PROTOCOL.md`; this file describes the process around them.

## Stewardship

**LawCribs is the steward** of the Matter Passport protocol: maintainer of the specification, the fixture suite, the conformance checklist, the reference implementations, and the conformant-verifier directory. This stewardship is declared in-band - every manifest carries a signed `protocol` block naming LawCribs as maintainer, and verification reports surface it as a labeled check.

Stewardship means LawCribs operates the bootstrap infrastructure (relay, key directory, digest anchors, hosted verification) and publishes the conformance authority. It does not mean LawCribs controls the protocol - the compatibility policy below constrains what the steward may change unilaterally.

## Compatibility policy (summary)

The binding rules are in `PROTOCOL.md` "Compatibility policy". In brief:

- `major.minor.patch` versioning; the `format` tag `lawcribs-matter-passport` is the only hard gate.
- Within a major version, changes are **additive-only**: new optional fields, event types, check ids. Verifiers MUST ignore unknown fields (they remain signature- and Merkle-covered).
- A breaking change requires a new major version and a documented migration path. `1.0.0` packages remain verifiable indefinitely - `fixtures/legacy-v1/` proves it.

## How changes happen

1. **Proposal** - email info@lawcribs.com with subject `Matter Passport proposal`, or open an issue on the public repository when one exists. Proposals should state the problem, the smallest spec delta that solves it, and the trust-model impact.
2. **Design review** - LawCribs reviews for spec soundness and trust-model fit (the honest-labels rule is not negotiable: no change may collapse distinct assurance levels into a single verdict). Accepted proposals are drafted as spec changes.
3. **Publication** - a spec change ships with, at minimum: the doc update, fixture or vector additions where behavior is observable, a conformance-checklist update, and parity in `conformance/lawcribs_conformance.py`. This is already the rule the project follows for every passport change.
4. **Versioning** - additive changes bump minor (or patch for typo-level fixes); breaking changes bump major with a migration note in the changelog.

There is no formal RFC process yet. As external implementers appear, this document will be revised - the intent is a lightweight process, not a standards-body bureaucracy.

## Conformance authority

LawCribs maintains the checklist (`CONFORMANCE.md`) and the public directory of conformant verifiers (`/developers/passport/verifiers`). Implementations self-certify against the published fixtures and are listed after review. Infrastructure conformance (relays, directories) will extend the same model when federation ships - see `V2-ROADMAP.md`.

## Licensing and IP

- Specification text: **CC-BY-4.0** - see `LICENSE.md`.
- Reference code (conformance verifier, SDK modules, CLI): **MIT** - see `LICENSE.md`.
- Name and marks: LawCribs trademark - see `TRADEMARK.md`.
- **Open item**: a formal patent non-assertion covenant has not been published. The protocol uses only published royalty-free primitives. If your implementation requires patent assurance, raise it via the proposal channel - this is a known gap, not an oversight we are hiding.

## Neutral stewardship

Long-term, protocol credibility benefits from governance beyond any single company - a foundation or multi-stakeholder steering committee is the standard end-state (IETF, W3C, Apache models). LawCribs is not ready to cede stewardship while the ecosystem has zero external implementers; `V2-ROADMAP.md` sequences federation and governance maturation behind demonstrated demand. When that threshold is reached, the signed `protocol` block and this document are the artifacts a successor steward would inherit.
