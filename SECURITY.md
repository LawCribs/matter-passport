# Matter Passport - Security and Vulnerability Disclosure
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


This policy covers the **Matter Passport protocol artifacts**: the specification, the conformance verifier, the SDK modules, the reference CLI, the fixtures, and the `.lcp` package format. It does not replace LawCribs' general security contact for the hosted application - use the same channel and say which surface you are reporting.

## How to report

Email **info@lawcribs.com** with the subject line `Matter Passport Security`, or open a private vulnerability report via [GitHub Security Advisories](https://github.com/LawCribs/matter-passport/security/advisories/new) on the public protocol repository. Include:

- which artifact is affected (spec document, `lawcribs_conformance.py`, an `sdk/` module, `verify-passport.mjs`, a fixture, or the `.lcp` format itself),
- a description of the issue and its security impact,
- reproduction steps or a proof of concept,
- whether you believe the issue is exploitable today or is a spec-level ambiguity.

If your report contains sensitive detail, say so in the first line and we will arrange an encrypted channel before you send payloads.

## What we consider in scope

- Cryptographic flaws: signature, digest, canonicalization, Merkle, or envelope weaknesses that let forged or tampered packages verify.
- Parser differentials: inputs that verify differently across conformant implementations (the Python verifier exists precisely to catch these).
- Specification ambiguities with security consequences - e.g. unclear MUSTs that allow a dishonest implementation to claim stronger assurance than warranted.
- Fixture or vector integrity problems.
- Denial-of-service vectors in package parsing (zip bombs, pathological canonical inputs) that conformant verifiers must already reject.

## What is out of scope

- Issues in the LawCribs hosted application unrelated to the protocol artifacts (report them the same way - they are still welcome).
- The honest-label limits the spec already declares: signatures prove key possession not legal identity, timestamps are client-reported unless anchored, scope is self-asserted. These are documented design properties, not vulnerabilities - see `PROTOCOL.md` "Verification (honest claims)".
- Social engineering, physical access, and attacks requiring compromise of a user's device.

## Our commitments

- Acknowledge receipt within **72 hours**.
- Triage and give an initial severity assessment within **7 days** for confirmed in-scope reports.
- Coordinate disclosure: we aim to publish a fix or spec clarification before public details, defaulting to a **90-day** window. If a fix needs longer we will say so and keep you informed.
- Credit reporters in the changelog unless you prefer anonymity.

## Safe harbor

Good-faith security research against the published protocol artifacts and the public verification endpoints is welcome. We will not pursue legal action against researchers who stop at demonstrating the issue, do not access or modify data that is not theirs, and give us reasonable time to remediate before disclosure.

## For implementers

If you find that your implementation and ours disagree on a package, that is a conformance bug worth reporting even when it is not a security issue - file it the same way and mark it `interoperability` rather than `security` in the subject.
