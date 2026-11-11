# Matter Passport Protocol - V2 Roadmap (Design Only)
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*

This document scopes three planned protocol extensions: **identity binding**, **trusted timestamping (TSA)**, and **federation**. Nothing here is implemented; each section records the problem, candidate designs, trust-model impact, compatibility path, and open questions requiring a decision before code.

The v1.x trust model is the constraint every design must preserve: digests prove bytes, signatures prove key possession, timestamps are labeled by assurance level, scope is always disclosed, and no check ever collapses into an unconditional "verified" verdict. V2 features add *new labeled claims* - they never silently upgrade existing ones.

---

## 1. Identity binding

### Problem

A manifest signature proves the holder of a P-256 private key signed these bytes. It says nothing about whether that key belongs to "Chambers & Associates" or "Mallory". Today the only mitigations are self-asserted manifest fields (`clientName`, etc. - unsigned claims inside signed bytes, i.e. claims the signer makes about themselves) and the public key directory, which maps fingerprints to `current`/`revoked` status but not to any legal identity.

**Non-goals for this workstream**: no KYC or identity verification service, no certificate issuance, no merging of attestation claims into signature validity, and no retroactive reinterpretation of v1.x packages - a package signed before attestments existed keeps exactly the claims it was signed with.

**Schema deltas (sketch)**: a new `passport_key_attestations` relay table (`fingerprint`, `issuerType`, `issuerId`, `payloadJson`, `signatureJwk`, `status`, `createdAt`, `revokedAt`) - attestations live outside the `.lcp` package, keyed by the same fingerprint the directory already uses, so no manifest or package format change is required. Verifiers gain one new check id, `attestation`, emitted at `info` level with the issuer and assurance level in the detail string - never `pass`/`fail`, because an attestation is a claim, not a cryptographic fact.

### Candidate designs

**A. Attestation records in the key directory (recommended first step)**

Extend `passport_directory_keys` (or a sibling `passport_key_attestations` table) so any party can publish a signed statement about a key fingerprint:

```json
{
  "version": "lc-key-attestation-v1",
  "subjectFingerprint": "<sha256-b64url of {kty,crv,x,y}>",
  "issuer": { "type": "workspace" | "organisation" | "authority", "id": "opaque-id" },
  "claims": {
    "legalName": "string (optional)",
    "jurisdiction": "string (optional)",
    "roles": ["string"]
  },
  "assuranceLevel": "self-asserted" | "counter-signed" | "institutionally-verified",
  "createdAt": "RFC3339",
  "signature": "ES256 over canonical attestation payload, issuer's key"
}
```

Hosted verification reports attestation status alongside key status: `attested (self-asserted)`, `attested (counter-signed by N parties)`, `attested (institutionally-verified)`, or `unattested`. The label carries the assurance level - an attestation is always reported *as a claim by an issuer*, never merged into signature validity.

Why first: it reuses the directory, receipt, and verification plumbing already shipped; it is additive (old verifiers ignore the new check id); and it creates the data model that OIDC/X.509 options would populate later.

**B. OIDC/SAML organisational attestation**

A workspace proves control of an identity provider (e.g. a firm's Entra/Google Workspace domain) and the directory records `org-attested` status bound to the key fingerprint. Stronger than A for institutions, but requires IdP integration, token validation, and a decision about which claims to store (store references, not tokens).

**C. X.509 / PIV certificate binding**

Bind passport keys to hardware-backed or CA-issued certificates at registration. Highest assurance, highest friction - certificate lifecycle (expiry, revocation) becomes protocol surface. Deferred until institutional demand justifies it.

**D. Counter-signature chains**

Generalize recipient receipts: any party may countersign a manifest or key with their own key, building web-of-trust-style chains. The receipt format already exists; this extends it to manifests. Powerful but changes the verification UX - verifiers must decide how much chain to chase. Possible V2.1 item.

### Trust-model impact

None of these change what a signature proves. They add *attribution claims* with explicit assurance levels. The honest-label rule applies: a verifier MUST report `signer identity: key possession proven; attribution: <level> <issuer>` as separate facts.

### Open questions

- Who may publish attestations - anyone (like the directory today), or only counter-signed issuers?
- Does `institutionally-verified` require LawCribs review (like `conformant_verifiers`) or a defined external process?
- Attestation revocation semantics (supersede vs. revoke - the directory already handles status).
- Privacy: attestations bind public keys to names - is that opt-in per key?

---

## 2. Trusted timestamping (RFC 3161 TSA)

### Problem

All package timestamps are client-reported (honestly labeled) or relay-reported (anchors - earliest sighting of a digest, also honestly labeled). For litigation, "when was this signed" ideally comes from an independent time authority. `PassportSignature.timeAssuranceLevel` already anticipates `"third-party"`.

**Non-goals**: TSA does not replace anchors (they remain the zero-dependency baseline), is never mandatory, covers RFC 3161 only (no eIDAS qualified/qualified-electronic timestamps in v2.0), and archive timestamps (periodic re-timestamping for long-lived evidence) are deferred to V2.1.

**Schema deltas (sketch)**: the package gains an optional `timestamps/` directory - no manifest or signature format change, because the token binds to `manifestDigest`, which is already derived from signed content. Two token encodings under consideration: raw DER `.tsr` (smallest, but carries no provenance metadata) vs. a JSON envelope `{ "version": "lc-timestamp-v1", "tsa": "<url>", "requestedAt": "<rfc3339>", "token": "<base64-DER TimeStampResp>" }` (recommended - self-describing). `PassportSignature.timeAssuranceLevel` may be `"third-party"` only when a structurally valid token for that manifest digest is embedded; claiming it without one is a conformance violation. Verifier gains `timestamp` upgrade (labeled `pass`/`warn`/`info` by token state) and an optional `tsa-chain` check reported separately.

### Design

**Timestamp token attachment**

After signing a manifest (or on export), the producer optionally requests an RFC 3161 `TimeStampToken` over `manifestDigest` from a TSA and embeds it:

```text
matter-passport.lcp
  timestamps/
    <manifestDigest>.tsr     DER TimeStampResp (or a JSON-wrapped variant)
```

Verification additions:

- `timestamp` check upgrades from `info` to a labeled result: `pass (TSA: <CA name>, genTime <t>)`, `warn (TSA token malformed/expired)`, or stays `info (client-reported)` when absent.
- Optional cert-chain validation against a published TSA root list - reported separately (`tsa-chain: verified|unverified|not-checked`) since root programs differ.
- `timeAssuranceLevel` on the signature record may be set to `"third-party"` only when a valid token is embedded - producers MUST NOT claim it without one (conformance check).

**Anchor interplay**: relay anchors remain the zero-dependency baseline. A package can carry both; the report shows both labels. TSA does not replace anchors - it adds an independently auditable time source.

### Provider decision (deferred)

Candidates: free public TSAs (e.g. FreeTSA), commercial CAs (DigiCert etc.), or self-hosted (e.g. an OpenTimestamps-style aggregate). The protocol is provider-agnostic - the token is self-contained - but the docs should name at least one recommended provider and publish the accepted-root policy. Open question: does LawCribs operate a TSA endpoint (`/api/passport/tsa`) as a convenience, or only document third-party usage?

### Compatibility

Purely additive: `timestamps/` is a new optional directory; old verifiers ignore it, new verifiers treat its absence as today's behavior. No manifest or signature format change - the token binds to `manifestDigest`, which is already signed-content-derived.

### Open questions

- Token format: raw DER `.tsr` vs. a JSON envelope `{token: base64-DER, tsa: url, requestedAt}`? (JSON envelope recommended - carries provenance metadata.)
- Archive timestamps (periodic re-timestamping for long-lived evidence) - V2.1.
- Cost/latency: TSA request adds a network call to export; make it opt-in per snapshot or per workspace policy?

---

## 3. Federation

### Problem

Today LawCribs operates the only relay, directory, anchor service, and conformance authority. "Open protocol" currently means *open specification + open fixtures* - the infrastructure is single-operator. Federation addresses three separable concerns:

**A. Spec and fixture federation**

The spec is already portable (markdown mirror under `/matter-passport-spec/`). Formalize: spec releases get dated snapshots (`/matter-passport-spec/v1.1/`), a changelog, and a signed release manifest (LawCribs key signs the spec digest - stewardship, already declared in manifest `protocol` blocks). Other organizations can fork the spec for domain profiles (e.g. `format: "lawcribs-matter-passport"` + `profile: "e-discovery-v1"`) as long as core checks hold.

**B. Relay federation**

Multiple conformant relays hold transfer ciphertext and digest anchors. Design:

- Relay identity: each relay publishes a descriptor `{id, endpoints, operator, conformanceAttestation}` at a well-known location.
- Anchor federation: a manifest digest anchored on N independent relays yields N relay-reported timestamps - stronger than one (collusion resistance), still honestly labeled "relay-reported".
- Transfer portability: share links carry the relay origin; a recipient-facing resolver could try alternate relays for the same token hash (tokens are capability + hash, relay-agnostic in principle - the ciphertext blob is self-contained).
- Conformance: a relay conformance checklist (rate limiting, opaque storage, transition rules, no plaintext token storage) extends the existing verifier conformance model to infrastructure.

**C. Key-directory federation**

`.well-known/lawcribs-passport` (or `/.well-known/matter-passport`) publishing an org's signing keys and attestations, so identity resolution doesn't depend on LawCribs' directory. Hosted verification aggregates: local directory + well-known lookups, reporting each source separately.

**Non-goals**: LawCribs does not cede stewardship of the spec or the conformance authority in v2 - federation adds implementers and infrastructure operators, not competing spec editors. No mandatory relay federation (single-relay operation remains fully conformant), and no trust merging - every federated source is labeled with its origin and assurance level.

**Schema deltas (sketch)**:

- Well-known document at `https://<org>/.well-known/matter-passport`:
  ```json
  {
    "version": "lc-wellknown-v1",
    "keys": [{ "publicJwk": {}, "status": "current|revoked", "attestations": [] }],
    "spec": [{ "url": "...", "version": "1.1.0" }]
  }
  ```
  Content is public-key material and self-asserted claims only - the same data the directory already publishes, so federation exposes nothing new.
- Relay descriptor (published per relay, referenced by share links and anchor lookups): `{ "id", "operator", "endpoints": { "transfers", "anchors", "directory" }, "conformanceAttestation": "<ref>" }`.
- **Version negotiation**: no handshake exists or is needed - the `format` tag is the only hard gate and the compatibility policy in `PROTOCOL.md` (additive-only within a major version, unknown fields ignored but signature-covered) already defines negotiation. Federation inherits it unchanged; profiles (e.g. `profile: "e-discovery-v1"`) are the extension point for domain dialects.
- **Conformance-authority model**: LawCribs maintains the spec, fixture suite, and verifier directory - the same stewardship already declared in signed `protocol` blocks. Other organizations implement the spec and submit conformance results for listing, exactly as `CONFORMANCE.md` self-certification already describes. Infrastructure conformance (relays, directories) extends the same checklist model rather than creating a second authority.

### Trust-model impact

Federation multiplies *claims sources*, not trust: every relay/directory answer is labeled with its source and assurance level. The protocol's core insight - never collapse sources into one verdict - is exactly what makes federation honest rather than dangerous.

### Compatibility

All additive: well-known documents are new endpoints; relay federation is client-side resolution; spec versioning already supports profiles. No breaking change to `.lcp` or transfer envelopes.

### Open questions

- Governance: who maintains the conformance checklist and the conformant relay/verifier directories? (LawCribs as steward, with a published policy for additions - mirrors the trademark/stewardship docs already filed.)
- Relay discovery: how does a verifier find "all relays that saw this digest"? A federation index vs. gossip vs. sender-declared relay list in the manifest (adds a signed field - V2 manifest revision).
- Sybil/abuse: open relay publication invites spam anchors; rate limits and operator identity help but policy is needed.

---

## Suggested sequencing

1. **Attestation records (1A)** - smallest increment, reuses shipped plumbing, unblocks the "who is this key" question honestly.
2. **TSA tokens (2)** - independent of identity work; pick provider + envelope format, add `timestamps/` to package builder + verifier check.
3. **Well-known key directory (3C)** - enables identity binding without LawCribs dependency.
4. **Relay federation (3B)** - largest scope; needs the relay conformance checklist first.
5. **Spec federation (3A) + counter-signature chains (1D)** - governance-heavy, do once V2.1 demand is proven.

Each item ships with: spec doc update, fixture/vector additions, verifier check (honest label), conformance checklist update, and the Python reference verifier kept in parity.
