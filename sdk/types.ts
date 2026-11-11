/** Matter Passport domain types - Dexie-local entities plus the
 *  canonical manifest shape the .lcp package carries. Opaque ids only;
 *  no client names, case numbers, or confidential data in identifiers. */

export interface MatterPassport {
  id: string;
  matterId: string;
  protocolVersion: string;
  status: "active" | "archived";
  createdBy: string;
  latestSnapshotId?: string;
  createdAt: string;
  updatedAt: string;
}

export type RecordType = "document" | "evidence" | "contract" | "signature" | "ai-output" | "draft" | "authority" | "note";
export type ProvenanceClass = "user-supplied" | "system-observed" | "externally-attested";
export type ContentMode = "embedded" | "encrypted" | "referenced" | "omitted";

export interface PassportRecord {
  id: string;
  passportId: string;
  recordType: RecordType;
  sourceModule?: string;
  sourceRecordId?: string;
  filename: string;
  mediaType: string;
  sizeBytes: number;
  digestAlgorithm: "sha-256";
  digestValue: string;
  storageReference?: string;
  contentMode: ContentMode;
  provenanceClass: ProvenanceClass;
  /** For derivative records: the parent record's id. */
  parentRecordId?: string;
  /** AI-output records: provenance ledger reference. */
  provenanceId?: string;
  status: "active" | "superseded";
  createdBy: string;
  createdAt: string;
}

export type EventType =
  | "passport.created" | "record.registered" | "record.updated_metadata" | "record.superseded"
  | "snapshot.created" | "snapshot.signed" | "snapshot.exported" | "verification.completed"
  | "access.granted" | "access.revoked"
  | "transfer.initiated" | "transfer.delivered" | "transfer.decrypted" | "transfer.accepted" | "transfer.declined" | "transfer.expired" | "transfer.revoked" | "transfer.receipt"
  | "key.registered" | "key.rotated" | "key.revoked"
  | "ai.output.registered" | "ai.output.reviewed";

export interface PassportEvent {
  id: string;
  passportId: string;
  sequenceNumber: number;
  eventType: EventType;
  actorId: string;
  actorType: "user" | "system" | "recipient" | "verifier";
  payload: Record<string, unknown>;
  payloadDigest: string;
  previousEventDigest: string | null;
  eventDigest: string;
  clientTime: string;
  serverReceivedAt?: string;
  signatureRef?: string;
  createdAt: string;
}

export interface PassportSnapshot {
  id: string;
  passportId: string;
  snapshotVersion: number;
  manifestDigest: string;
  canonicalizationMethod: string;
  signatureId: string;
  scopeType: "full" | "selected" | "partial" | "redacted";
  merkleRoot: string;
  /** Canonical manifest JSON - stored so the package can be rebuilt. */
  manifestJson: string;
  createdBy: string;
  createdAt: string;
}

export interface PassportSignature {
  id: string;
  snapshotId: string;
  keyId: string;
  algorithm: "ES256";
  payloadDigest: string;
  signatureValue: string;
  publicKeyJwk: JsonWebKey;
  timeAssuranceLevel: "client-reported" | "server" | "third-party" | "none";
  createdAt: string;
}

export type TransferStatus = "initiated" | "delivered" | "decrypted" | "accepted" | "declined" | "expired" | "revoked";

/** A signed recipient receipt proves the holder of the signing key
 *  acknowledged this exact package (manifestDigest) for this transfer
 *  (tokenHash). Stronger than the token-capability PATCH: it binds the
 *  ack to a workspace signing identity and to the received content. It
 *  still proves key possession, not legal identity - same honest limits
 *  as manifest signatures. */
export interface TransferReceiptPayload {
  version: "lc-transfer-receipt-v1";
  tokenHash: string;
  snapshotId: string;
  manifestDigest: string;
  decision: "accepted" | "declined";
  createdAt: string;
}

/** The receipt is self-contained: payload + signature + the public key,
 *  so any verifier checks it standalone with no key directory. */
export interface TransferReceipt {
  payload: TransferReceiptPayload;
  algorithm: "ES256";
  signatureValue: string;
  publicKeyJwk: JsonWebKey;
  keyFingerprint: string;
}

export interface PassportTransfer {
  id: string;
  passportId: string;
  snapshotId: string;
  /** URL-safe share token (hashed at rest on the relay, full value only in the share link). */
  tokenHash: string;
  recipientReference: string;
  scopeJson: string;
  deliveryMode: "encrypted-package" | "access-grant";
  status: TransferStatus;
  expiresAt?: string;
  createdAt: string;
  acceptedAt?: string;
  revokedAt?: string;
  /** Present only when the recipient countersigned and the sender
   *  verified the signature plus the manifest digest binding. */
  recipientReceipt?: TransferReceipt;
  /** All verified receipts - a link can be acknowledged by more than
   *  one party. recipientReceipt mirrors the first for compatibility. */
  recipientReceipts?: TransferReceipt[];
  /** Relay access audit: how many times the blob was fetched. */
  fetchCount?: number;
  /** Sender-set fetch cap (one-time link = 1). */
  maxFetches?: number;
}

export interface PassportKey {
  id: string;
  ownerType: "workspace" | "organisation";
  ownerId: string;
  algorithm: "ES256";
  publicKeyJwk: JsonWebKey;
  fingerprint: string;
  status: "current" | "revoked";
  validFrom: string;
  revokedAt?: string;
  /** Set once the relay directory accepts this key's status - keys
   *  created before the directory existed publish lazily on next use. */
  directoryPublishedAt?: string;
  directoryStatus?: "current" | "revoked";
  createdAt: string;
}

/** Digest representation used across manifest + records. */
export interface Digest {
  algorithm: "sha-256";
  encoding: "base64url";
  value: string;
}

export interface ManifestRecord {
  recordId: string;
  recordType: RecordType;
  filename: string;
  mediaType: string;
  size: number;
  digest: Digest;
  contentLocation?: string;
  parentRecordId?: string;
  provenanceClass: ProvenanceClass;
}

export interface ManifestAiOutput {
  recordId: string;
  digest: Digest;
  provenanceRef: string;
  providerRef?: string;
  modelRef?: string;
  reviewStatus: "reviewed" | "pending" | "unreviewed";
  editedAfterGeneration: boolean;
  /** Chain length at snapshot time - provenanceRef binds to the
   *  root of exactly this prefix, so later appends do not break the
   *  manifest. */
  upToSequence?: number;
}

export interface MatterManifest {
  format: "lawcribs-matter-passport";
  formatVersion: string;
  schemaVersion: string;
  /** Protocol stewardship - who publishes the spec this manifest
   *  follows. Inside the signed bytes, so the claim is unforgeable. */
  protocol?: { name: string; maintainer: string; specUrl: string; };
  matterId: string;
  /** Matter title at snapshot time - inside the signed bytes so the
   *  recipient sees the real name, not a placeholder. */
  matterTitle?: string;
  /** Client name at snapshot time. */
  clientName?: string;
  clientEmail?: string;
  clientPhone?: string;
  clientCompany?: string;
  clientAddress?: string;
  matterNumber?: string;
  practiceArea?: string;
  court?: string;
  matterDescription?: string;
  snapshotId: string;
  /** Lineage: the manifest digest of the previous snapshot on this
   *  passport. Inside the signed bytes - anyone holding an earlier
   *  package can check the chain of snapshots, so a rewritten history
   *  is detectable rather than indistinguishable. */
  previousSnapshotId?: string;
  previousSnapshotDigest?: string;
  createdAt: string;
  scope: { type: "full" | "selected" | "partial" | "redacted"; description?: string };
  records: ManifestRecord[];
  eventRange: { fromSequence: number; toSequence: number };
  integrity: {
    canonicalization: string;
    manifestDigestAlgorithm: string;
    merkleRoot: string;
  };
  aiOutputs?: ManifestAiOutput[];
  signatures: Array<{ signatureId: string; algorithm: "ES256"; keyId: string }>;
}
