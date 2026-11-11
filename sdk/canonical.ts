import { sha256Base64 } from "./hash";

/**
 * Canonical serialization for the manifest - a JCS-profile ("JCS-lite")
 * following RFC 8785 rules that matter for our data shapes: sorted
 * object keys, UTF-8, RFC 3339 UTC timestamps, undefined rejected,
 * JSON.stringify number semantics (deterministic for our integer sizes).
 * Duplicate keys are rejected at parse/validation boundaries.
 */

export function canonicalize(value: unknown): string {
  if (value === undefined) throw new Error("canonicalize: undefined values are not allowed");
  return JSON.stringify(sortValue(value));
}

function sortValue(v: unknown): unknown {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(sortValue);
  const obj = v as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) {
    const item = obj[k];
    if (item === undefined) throw new Error(`canonicalize: undefined at key "${k}"`);
    out[k] = sortValue(item);
  }
  return out;
}

export async function manifestDigest(manifest: unknown): Promise<string> {
  return sha256Base64(canonicalize(manifest));
}
