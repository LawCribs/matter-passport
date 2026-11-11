# Matter Passport - Trademark and Naming Guidelines
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.1.0.*


"Matter Passport" is a LawCribs mark. A Nigerian trademark application for `LAWCRIBS MATTER PASSPORT` (Nice classes 9, 42, 45) is in preparation - see `docs/trademark/matter-passport-application.md` in the LawCribs repository. Until registration completes, these guidelines state our intended policy; they are not legal advice.

The open license on the specification (see `LICENSE.md`) covers the *text and code*. It does not grant rights to the *name*. Those are separate things, deliberately.

## What you MAY do

- State accurately that your product **implements**, **supports**, or is **compatible with** the Matter Passport protocol.
- Use "Matter Passport" descriptively to identify the format your software reads or writes, e.g. "exports Matter Passport packages".
- Claim conformance **only** if your implementation appears in the public conformant-verifier directory at `/developers/passport/verifiers` (or a successor listing). Self-certification without listing is not a conformance claim you may advertise.
- Use `.lcp` as the file extension for packages your software produces or consumes - the extension is part of the open format.

## What you MAY NOT do

- Name your product, company, or service "Matter Passport", "LawCribs Matter Passport", or anything confusingly similar.
- Use the LawCribs logo or trade dress, or imply that LawCribs endorses, certifies, sponsors, or is affiliated with your product.
- Claim "official", "certified", or "approved by LawCribs" status unless you hold a current listing in the conformant-verifier directory.
- Register domain names, app-store listings, or handles that incorporate the mark in a way that suggests official status.
- Present modified versions of the specification under the unqualified name "Matter Passport" - forked profiles must be clearly labeled as derivatives (the `format` tag plus a `profile` field is the mechanism; see `V2-ROADMAP.md`).

## Why this split

Protocols survive on implementer trust. A protected name lets users and courts distinguish "a package that verifies under the LawCribs Matter Passport protocol" from "a product calling itself a passport". The spec being open means anyone can implement it; the mark being protected means the ecosystem has one recognizable name for the thing being implemented.

## Questions

For trademark questions or nominative-use clarification, contact info@lawcribs.com.
