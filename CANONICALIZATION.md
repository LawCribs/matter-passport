# Canonicalization ("JCS-lite") and Digest Formulas
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*

Every digest and signature in the Matter Passport protocol is computed over a canonical serialization. Implementations MUST reproduce these formulas byte-for-byte; `fixtures/vectors/` pins them with known-answer tests.

## JCS-lite canonicalization

A restricted profile of RFC 8785 (JSON Canonicalization Scheme) that covers the data shapes the protocol uses:

- Objects: member names sorted by UTF-16 code unit order (JavaScript `Object.keys().sort()` / `Array.prototype.sort()` semantics - NOT Unicode code-point order; they differ only for characters outside the BMP ordering edge cases, and the vectors pin the behavior).
- Arrays: order preserved; each element canonicalized recursively.
- Strings: `JSON.stringify` semantics - minimal escaping (`"`, `\`, and control characters U+0000-U+001F using `\b \f \n \r \t` or `\uXXXX`), all other characters emitted literally as UTF-8, including non-BMP characters and U+2028/U+2029.
- Numbers: `JSON.stringify` semantics (shortest round-trip representation; `-0` serializes as `0`; integers beyond 2^53 are already unsafe and MUST NOT appear).
- Literals: `null`, `true`, `false`.
- Output: UTF-8, no whitespace.
- `undefined` values are REJECTED at any depth (they have no JSON representation).
- Duplicate object keys are REJECTED at JSON parse time - a parser that silently keeps the last value produces different bytes than the signer intended.

The manifest digest is `SHA-256(canonical(manifest))`, base64url without padding. The signature is computed over the same canonical bytes.

## Digest and hash formulas

All digests are `SHA-256`, base64url without padding (`base64url` in Node, `base64` + strip `=` in browser `btoa` output).

| Value | Formula |
|---|---|
| Record/content digest | `sha256(fileBytes)` |
| `payloadDigest` (event) | `sha256(JSON.stringify(payload))` - **NOT canonicalized**: JS `JSON.stringify` with insertion-order keys and no whitespace |
| `eventDigest` | `sha256(`${seq}\|${eventType}\|${previousEventDigest ?? ""}\|${payloadDigest}`)` - genesis uses empty string for prev |
| Merkle leaf | `sha256("lc-pproof-v1\|leaf\|" + digest)` |
| Merkle node | `sha256("lc-pproof-v1\|node\|" + left + "\|" + right)` |
| `manifestDigest` | `sha256(canonical(manifest))` |
| `tokenHash` (transfer) | `sha256(rawTokenString)` - UTF-8 of the token text |
| `keyFingerprint` | `sha256(JSON.stringify({kty, crv, x, y}))` - fixed key order, NOT canonicalized (same output either way for this flat object) |
| Receipt signature input | `canonical(receipt.payload)` - JCS-lite, same as manifest |

## The `JSON.stringify` trap

`payloadDigest` deliberately uses plain `JSON.stringify`, not JCS-lite. Two consequences implementers miss:

1. Key order matters: `JSON.stringify({a:1,b:2})` and `JSON.stringify({b:2,a:1})` differ. Event payloads are hashed in the key order the producer emitted them; verifiers re-serialize the parsed payload and MUST preserve the order encountered in `events.jsonl` (JSON parsers that reorder object keys - e.g. sorting them - will compute wrong digests).
2. String escaping follows `JSON.stringify`, which differs subtly across languages (Python `json.dumps` needs `ensure_ascii=False` and `separators=(",", ":")` to match; it still differs on a few edge cases the vectors cover).

## Signature encoding

ES256 signatures are **raw IEEE-P1363 format**: the concatenation `r || s` of the two 32-byte big-endian integers (64 bytes total), base64url without padding. They are NOT DER-encoded ASN.1 sequences. This matches WebCrypto `crypto.subtle.sign` output. The historical fixture generator once emitted DER signatures - a package signed that way fails verification; `fixtures/vectors/` and the fixture regression test exist to prevent recurrence.

## Test vectors

`fixtures/vectors/` contains known-answer vectors for every formula above:

- `canonicalization.json` - inputs, expected canonical strings, expected digests (12 cases covering sorting, nesting, unicode, escapes, empty containers, number forms)
- `merkle.json` - sorted leaves, expected root, per-leaf proofs (exercises odd-leaf duplication)
- `event-digest.json` - two chained events with expected `payloadDigest`/`eventDigest` (genesis empty-prev and normal prev cases)
- `transfer-envelope.json` - fixed AES-256 key/IV/plaintext producing a deterministic `lc-transfer-v1` envelope; documents that `data` is `ciphertext || 16-byte GCM tag` in standard base64, `iv` is standard base64, and the `#k=` fragment carries the raw key as JWK `k` (base64url)
