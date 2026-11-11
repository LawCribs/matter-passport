# Matter Passport - Repository Audit

**Date:** 2026-11-02
**Purpose:** align the Matter Passport spec (`docs/LawCribs_Matter_Passport_Development_Plan.md`) with the actual codebase. The spec's PHP/CodeIgniter reference (section 5.1) is stale - this document records the real stack.

## Actual architecture

- **Client app**: Next.js 16 (App Router) + React 19 + TypeScript. Local-first: workspace data lives in IndexedDB via Dexie (`src/lib/db.ts`, `LawCribsDB`, currently version 40) encrypted with AES-256-GCM under a workspace key held in `sessionStorage`.
- **Server-side**: Next.js route handlers + Postgres via Drizzle (`src/lib/subscription/schema.ts`, `admin-app/src/lib/subscription/schema.ts` - duplicated, keep in sync). Postgres carries only metadata/relay data; workspace content arrives only as encrypted blobs.
- **Token-gated public flows**: invites, intake forms, client portal, careers - the relay pattern to reuse for transfers.

## Reused components

| Spec component | Existing implementation |
|---|---|
| SHA-256 file hashing | `crypto.subtle.digest` helpers; `evidenceItems.sha256Hash` + custody chain |
| Signature scheme | `signature-service.ts` - ECDSA P-256 keypairs, private keys encrypted under workspace key, public verify portal at `/verify` |
| Package export | jszip + `evidence-export-service.ts` bundle pattern |
| Transfer envelope | Client portal URL-fragment AES-256-GCM key model |
| Honest verify UI | `/verify` + `/arcade/verify` - per-check labels, never a bare green badge |
| Event chaining | Drafting provenance ledger - Merkle-chained records + HMAC anchor receipts |
| Public verify API | `/api/signature/verify`, `/api/arcade/certify` (HMAC pattern) |

## Data ownership mapping

- Passport domain rows: Dexie-local (encrypted, synced as blobs) - `passports`, `passportRecords`, `passportEvents`, `passportSnapshots`, `passportKeys`, `passportTransfers` (local ledger).
- Transfer delivery relay: Postgres `passport_transfers` - token hash, encrypted blob, scope/expiry/status metadata only.
- Online verification reports: Postgres `passport_verifications` - report JSON + reference only.
