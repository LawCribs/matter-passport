import { sha256Base64 } from "./hash";

/**
 * Merkle inclusion proofs over record+event digests. Sorted leaves,
 * SHA-256 pair hashing, odd-leaf duplication, domain-separated with
 * the "lc-pproof-v1" tag so passport proofs can't collide with other
 * trees in the codebase.
 */

const TAG = "lc-pproof-v1";

const leafHash = (leaf: string) => sha256Base64(`${TAG}|leaf|${leaf}`);
const nodeHash = (left: string, right: string) => sha256Base64(`${TAG}|node|${left}|${right}`);

export interface MerkleProof {
  leafIndex: number;
  siblings: Array<{ position: "left" | "right"; digest: string }>;
  root: string;
}

export interface MerkleTree {
  root: string;
  leaves: string[];
  proof(leafIndex: number): Promise<MerkleProof>;
}

export async function buildMerkleTree(items: string[]): Promise<MerkleTree> {
  const leaves = [...items].sort();
  const leafHashes = await Promise.all(leaves.map(leafHash));
  const levels: string[][] = [leafHashes];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1];
    const next: string[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      next.push(await nodeHash(cur[i], cur[i + 1] ?? cur[i]));
    }
    levels.push(next);
  }
  const root = leafHashes.length === 0 ? "" : levels[levels.length - 1][0];

  return {
    root,
    leaves,
    async proof(leafIndex: number): Promise<MerkleProof> {
      const siblings: MerkleProof["siblings"] = [];
      let idx = leafIndex;
      for (let level = 0; level < levels.length - 1; level++) {
        const row = levels[level];
        const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
        if (sib < row.length) {
          siblings.push({ position: idx % 2 === 0 ? "right" : "left", digest: row[sib] });
        } else {
          siblings.push({ position: idx % 2 === 0 ? "right" : "left", digest: row[idx] });
        }
        idx = Math.floor(idx / 2);
      }
      return { leafIndex, siblings, root };
    },
  };
}

export async function verifyProof(leaf: string, proof: MerkleProof): Promise<boolean> {
  let cur = await leafHash(leaf);
  for (const s of proof.siblings) {
    cur = s.position === "left" ? await nodeHash(s.digest, cur) : await nodeHash(cur, s.digest);
  }
  return cur === proof.root;
}
