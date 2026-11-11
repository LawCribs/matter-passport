/** SHA-256 helpers for the Matter Passport. Pure - no workspace,
 *  storage, or app imports, so external verifiers can vendor this
 *  file as part of the standalone reference surface. */

/** SHA-256 of bytes or UTF-8 text, base64url-encoded (no padding). */
export async function sha256Base64(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
