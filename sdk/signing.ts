import type { PassportSignature } from "./types";

/** ES256 manifest signature verification. Pure - key storage and
 *  signing live in crypto.ts because they need the workspace; this
 *  side needs only the public key embedded in the signature record. */

const ECDSA_ALG = { name: "ECDSA", namedCurve: "P-256" };
const ECDSA_VERIFY = { name: "ECDSA", hash: "SHA-256" };

/** Verify a manifest signature against the embedded public key. */
export async function verifyManifest(manifestCanonical: string, sig: Pick<PassportSignature, "signatureValue" | "publicKeyJwk" | "algorithm">): Promise<boolean> {
  try {
    if (sig.algorithm && sig.algorithm !== "ES256") return false;
    const key = await crypto.subtle.importKey("jwk", sig.publicKeyJwk, ECDSA_ALG, false, ["verify"]);
    const b64 = sig.signatureValue.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const sigBytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    return crypto.subtle.verify(ECDSA_VERIFY, key, sigBytes, new TextEncoder().encode(manifestCanonical));
  } catch {
    return false;
  }
}
