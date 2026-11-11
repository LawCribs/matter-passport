/** Public SDK surface for the Matter Passport protocol. External
 *  verifiers and integrations import from this file - it re-exports
 *  the same code the app runs so conformance stays honest. */

export { canonicalize, manifestDigest } from "./canonical";
export { buildMerkleTree, verifyProof } from "./merkle";
export { sha256Base64 } from "./hash";
export { verifyPackage } from "./verify";
export type { VerificationCheck, VerificationReport } from "./verify";
export { verifyManifest } from "./signing";
export type {
  MatterManifest, ManifestRecord, ManifestAiOutput, Digest,
  PassportSignature, MatterPassport, PassportRecord, PassportEvent,
  PassportSnapshot, PassportTransfer, PassportKey,
} from "./types";
