# LawCribs Passport Package Format (`.lcp`) - v1.1.0

`.lcp` = LawCribs Passport Package.
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


ZIP container. All JSON is UTF-8; the manifest is canonicalized (JCS profile: sorted keys, RFC 3339 UTC times, no undefined - full normative definition in `CANONICALIZATION.md`) before digesting/signing. Signatures are raw IEEE-P1363 `r || s`, base64url, never DER.

```text
matter-passport.lcp
  manifest.json                 canonical manifest (see schema)
  signatures/
    manifest-signature.json     { algorithm, keyId, publicKey, payloadDigest, signatureValue }
  records/
    <recordId>/
      metadata.json             record metadata + digest + provenance classification
      content.bin               original bytes (omitted in metadata-only/redacted packages)
  events/
    events.jsonl                append-only event chain (one JSON object per line)
    checkpoint.json             last event digest + sequence
  proofs/
    merkle-proofs/<recordId>.json  inclusion proofs when produced
  verification/
    README.txt                  plain-language verification instructions + limitations
```

## Manifest schema (v1.1, JCS-canonical)

```json
{
  "format": "lawcribs-matter-passport",
  "formatVersion": "1.1.0",
  "schemaVersion": "1.1.0",
  "protocol": { "name", "maintainer", "specUrl" },
  "matterId": "opaque-id",
  "matterTitle?": "string", "clientName?": "string", "matterNumber?": "string",
  "practiceArea?": "string", "court?": "string", "matterDescription?": "string",
  "clientEmail?": "string", "clientPhone?": "string", "clientCompany?": "string", "clientAddress?": "string",
  "snapshotId": "opaque-id",
  "previousSnapshotId": "opaque-id (optional, v-next)",
  "previousSnapshotDigest": "b64url sha-256 of the prior canonical manifest (optional, v-next)",
  "createdAt": "RFC3339-UTC",
  "scope": { "type": "full|selected|partial|redacted" },
  "records": [{ "recordId", "recordType", "filename", "mediaType", "size", "digest": {"algorithm":"sha-256","encoding":"base64url","value":"..."}, "contentLocation" }],
  "eventRange": { "fromSequence": 1, "toSequence": 24 },
  "integrity": { "canonicalization": "JCS-lite", "manifestDigestAlgorithm": "sha-256", "merkleRoot": "..." },
  "aiOutputs": [{ "recordId", "digest", "provenanceRef", "providerRef", "modelRef", "reviewStatus", "editedAfterGeneration" }],
  "signatures": [{ "signatureId", "algorithm": "ES256", "keyId" }]
}
```

Rules: scope is honest (a selected export never claims completeness); private keys never appear in the package; verification distinguishes digest match, signature validity, signer identity, and timestamp assurance separately.
