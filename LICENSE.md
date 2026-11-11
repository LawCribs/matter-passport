# Matter Passport Protocol - License and IP
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


This directory contains two differently-licensed bodies of work. Read this before implementing, redistributing, or referencing either.

## Specification documents - CC-BY-4.0

All prose documentation in this directory (`PROTOCOL.md`, `PACKAGE_FORMAT.md`, `CANONICALIZATION.md`, `KEY_MANAGEMENT.md`, `SDK.md`, `CONFORMANCE.md`, `GOVERNANCE.md`, `SECURITY.md`, `TRADEMARK.md`, `DEVELOPER_PORTAL.md`, `V2-ROADMAP.md`, `REPOSITORY_AUDIT.md`, `fixtures/README.md`, and `LICENSE.md` itself) is licensed under **Creative Commons Attribution 4.0 International (CC-BY-4.0)**:

https://creativecommons.org/licenses/by/4.0/

You may share and adapt the specification provided you:

- give appropriate credit to LawCribs (a link to https://lawcribs.com suffices),
- link to the license, and
- indicate if you modified the text.

Normative formulas, check lists, and fixture data inside the documents are part of the specification and carry the same license.

## Reference code - MIT

All code published under this directory is licensed under the **MIT License**:

- `conformance/lawcribs_conformance.py` and `conformance/README.md` - the zero-dependency Python reference verifier
- `sdk/` - the standalone TypeScript verification modules (`hash.ts`, `canonical.ts`, `merkle.ts`, `signing.ts`, `verify.ts`, `types.ts`, `sdk.ts`)
- `tools/verify-passport.mjs` and `tools/generate-passport-fixtures.mjs` - the reference Node CLI and fixture generator

```
MIT License

Copyright (c) 2026 LawCribs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The MIT license applies to the code only. It does not license the specification text (CC-BY-4.0) and it does not grant any right to the LawCribs name or marks (see `TRADEMARK.md`).

## What the licenses do NOT cover

- **The LawCribs Matter Passport name, logo, and `.lcp` mark usage** - see `TRADEMARK.md`.
- **LawCribs-operated services** - the hosted relay, key directory, digest anchors, hosted verification endpoint, and conformance directory are services of LawCribs, not part of the protocol license. Implementing the protocol does not entitle you to operate under the lawcribs.com domain or imply LawCribs endorsement.
- **The LawCribs application** - the app that produces packages is proprietary. The protocol is open; the product is not.

## Patent posture

LawCribs makes no patent grant beyond what the licenses above permit, and no explicit patent non-assertion covenant has been published yet. The protocol is built entirely on published, royalty-free primitives (SHA-256, ECDSA P-256, AES-256-GCM, JCS/RFC 8785-style canonicalization, RFC 3161 is roadmap-only). A formal RF commitment is tracked as an open item in `GOVERNANCE.md`.
