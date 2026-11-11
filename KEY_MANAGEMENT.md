# Matter Passport Key Management
> *An open protocol maintained by [LawCribs](https://lawcribs.com). Version 1.0.0.*


## Model

- One ES256 (ECDSA P-256) signing key per workspace, generated locally.
- The private key exists only encrypted under the workspace key (`privateKeyEncrypted` on the `passport_keys` row) - the server never sees it.
- The public key JWK + fingerprint ship in every package's signature record so offline verification works without key lookup.

## Status semantics

- `current` - used for new signatures.
- `revoked` - no longer signs; packages signed BEFORE revocation remain valid. Verification reports key status at signing time, not current status.

## Rotation

Rotation creates a new `current` key and marks the prior one `revoked`. Existing snapshots keep their original signature + embedded public key, so previously exported packages still verify.

## Revocation

Revoke on suspected compromise. Honest consequence: packages signed while the key was trusted still verify cryptographically - revocation signals distrust going forward, it does not retroactively invalidate signatures. Report this distinction in verification output.

## Key directory

Workspaces publish signing-key status (`current`/`revoked`) to `/api/passport/directory` on create, rotate, and revoke. Keys created before the directory existed publish lazily on next use - `ensurePassportKey` re-attempts publication until the relay accepts once, tracked by `directoryPublishedAt` on the key row. The relay stores public JWKs only, recomputes the fingerprint server-side, and serves status anonymously - a directory is only useful if anyone can consult it. Hosted verification reports `current`/`revoked`/`unknown`; offline verification reports status as not checkable.

## Organisation keys

`ensurePassportKey` accepts `ownerType: "organisation"`. Org keys live alongside workspace keys in the same lifecycle (register/rotate/revoke events, directory publication) and can sign snapshots via `createSnapshot`'s `signingKeyOwnerType` option.

## Org policy controls (enterprise)

Workspace config may require: snapshots signed before export, key rotation cadence, mandatory human review before transfers. See `PassportKeyManagement` component.
