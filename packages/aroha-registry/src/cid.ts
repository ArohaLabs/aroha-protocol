// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Compute a real IPFS CIDv0 (base58btc, dag-pb/UnixFS) for a manifest —
 * production use, by a publisher building the `manifestCID` field for
 * `POST /v1/agents` (M6). Matches, byte for byte, the encoding
 * `apps/registry-server`'s `cid-verify.ts` decodes and verifies on the read
 * path (fetchCapabilityIds's raw-block verification), and mirrors
 * `apps/registry-server/src/test-utils/cid-builder.ts`, which builds the
 * same CIDs for that Worker's own tests. The two are intentionally not
 * shared code — registry-server's version is test-only scaffolding and
 * pinned by its own tests; this one is the production path a real client
 * uses when publishing.
 *
 * Note: computing a CID is not the same as pinning content durably on IPFS
 * so a third party can later fetch it — that needs a real pinning service
 * (Pinata, web3.storage, ...), which is separate, credentialed
 * infrastructure this package intentionally does not assume access to. A
 * manifest whose content is never actually pinned anywhere still produces a
 * structurally valid `manifestCID`; the registry's own capability-derivation
 * step already degrades gracefully to an empty capability list when the
 * content isn't fetchable (see fetchCapabilityIds's doc comment) rather than
 * blocking registration on it.
 */

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeVarint(n: number): number[] {
  const bytes: number[] = [];
  while (n > 127) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n & 0x7f);
  return bytes;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) {
    out.set(a, pos);
    pos += a.length;
  }
  return out;
}

function pbVarint(fieldNum: number, value: number): Uint8Array {
  return new Uint8Array([...encodeVarint((fieldNum << 3) | 0), ...encodeVarint(value)]);
}

function pbBytes(fieldNum: number, data: Uint8Array): Uint8Array {
  return new Uint8Array([...encodeVarint((fieldNum << 3) | 2), ...encodeVarint(data.length), ...data]);
}

function makeUnixFSFile(content: Uint8Array): Uint8Array {
  return concat(
    pbVarint(1, 2), // Type = File (2)
    pbBytes(2, content),
    pbVarint(3, content.length),
  );
}

function makeDagPBNode(data: Uint8Array): Uint8Array {
  return pbBytes(1, data);
}

function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let result = "";
  while (n > 0n) {
    result = BASE58_ALPHABET[Number(n % 58n)] + result;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    result = "1" + result;
  }
  return result;
}

export interface CidResult {
  cid: string;
  /** The raw IPLD block — what a pinning service needs to actually store. */
  block: Uint8Array;
}

/** Build a real CIDv0 for arbitrary content bytes. */
export async function buildCIDv0Bytes(content: Uint8Array): Promise<CidResult> {
  const block = makeDagPBNode(makeUnixFSFile(content));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", block));
  const cid = base58Encode(new Uint8Array([0x12, 0x20, ...hash]));
  return { cid, block };
}

/** Build a real CIDv0 for a JSON manifest object. */
export async function buildCIDv0(manifest: object): Promise<CidResult> {
  return buildCIDv0Bytes(new TextEncoder().encode(JSON.stringify(manifest)));
}
