# Matter Passport Conformance Verifier

`lawcribs_conformance.py` is an independent implementation of the Matter Passport verification spec, written in Python from the published specification documents alone. It shares no code with the LawCribs application - the point is to prove the protocol is implementable by someone who only has the documents.

Zero dependencies: Python 3.9+ standard library only (`hashlib`, `zipfile`, `json`, `base64`, `struct`, `math`). It reimplements JCS-lite canonicalization (including JS `JSON.stringify` number formatting and UTF-16 key ordering), SHA-256 base64url digests, the `lc-pproof-v1` Merkle construction, the hash-chained event format, pure-Python ECDSA P-256 signature verification (raw IEEE-P1363 signatures, never DER), and AES-256-GCM for the transfer envelope.

Implementation notes:

- **JSON parsing is JS-faithful**: `js_loads` rejects `NaN`/`Infinity` literals (which `JSON.parse` rejects) and rounds integers beyond 2^53 to doubles exactly as JS does, so canonical bytes match the signer's `JSON.stringify` even on adversarial input.
- **ECDSA timing**: verification scalars (`u1 = z·s⁻¹`, `u2 = r·s⁻¹`) derive only from public values - the signature, message hash, and public key - so there is no secret for a timing channel to leak. Scalar multiplication still runs a fixed 256-bit iteration for hygiene.
- **Package paths** are matched literally against manifest `contentLocation` values and never extracted to disk, so traversal is impossible by construction. Path checks mirror `verify.ts`; exotic separators (e.g. backslashes, which JSZip mangles before the app verifier sees them) can produce a WARN rather than FAIL on both sides.

## Usage

```sh
# Verify a .lcp package (optionally diff against its expected-report.json)
python conformance/lawcribs_conformance.py package path/to/package.lcp
python conformance/lawcribs_conformance.py package path/to/package.lcp --expected path/to/fixture-dir

# Verify a signed transfer receipt (lc-transfer-receipt-v1)
python conformance/lawcribs_conformance.py receipt path/to/receipt.json

# Run all known-answer vectors (canonicalization, merkle, event digests, transfer envelope)
python conformance/lawcribs_conformance.py vectors path/to/fixtures/vectors
```

On Windows use `python`; on POSIX use `python3`. CI regenerates fixtures and runs this suite plus the package and receipt checks on every change.

## What a pass proves

- Package structure is safe (no traversal, zip bombs, duplicate entries, oversized payloads)
- Record digests, event chain, and Merkle root recompute correctly
- The ES256 manifest signature verifies against the embedded public JWK
- Key-lineage, snapshot-lineage, scope, timestamp, and protocol-steward checks report the same honest labels as the reference verifier

## What it does not prove

Same honest limits as every conformant verifier: signatures prove key possession not legal identity, timestamps are client-reported unless relay-anchored, scope is self-asserted, and receipt *bindings* (tokenHash/manifestDigest vs. the transfer you hold) must be compared by the caller - the tool prints them for exactly that purpose.

## Negative coverage

The vectors suite includes a tampered-GCM-tag rejection case. Ad-hoc negative tests (flip a manifest byte, alter a receipt payload after signing) correctly produce FAIL results - see git history / CONFORMANCE.md for the fixture set.
