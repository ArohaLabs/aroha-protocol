/**
 * Helpers for constructing real IPFS CIDs and raw IPLD blocks in tests.
 * These are the encoding inverses of the decoders in cid-verify.ts.
 */

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

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

// Protobuf varint field (wire type 0)
function pbVarint(fieldNum: number, value: number): Uint8Array {
  return new Uint8Array([...encodeVarint((fieldNum << 3) | 0), ...encodeVarint(value)]);
}

// Protobuf length-delimited field (wire type 2)
function pbBytes(fieldNum: number, data: Uint8Array): Uint8Array {
  return new Uint8Array([
    ...encodeVarint((fieldNum << 3) | 2),
    ...encodeVarint(data.length),
    ...data,
  ]);
}

// UnixFS Data protobuf for a simple file (Type=File, Data, filesize)
function makeUnixFSFile(content: Uint8Array): Uint8Array {
  return concat(
    pbVarint(1, 2), // Type = File (2)
    pbBytes(2, content), // Data
    pbVarint(3, content.length), // filesize
  );
}

// dag-pb PBNode with only a Data field (no Links — single-chunk file)
function makeDagPBNode(data: Uint8Array): Uint8Array {
  return pbBytes(1, data);
}

function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let result = "";
  while (n > 0n) {
    result = BASE58[Number(n % 58n)] + result;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    result = "1" + result;
  }
  return result;
}

function base32Encode(bytes: Uint8Array): string {
  let result = "",
    buf = 0,
    bits = 0;
  for (const b of bytes) {
    buf = (buf << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32[(buf >> bits) & 0x1f];
    }
  }
  if (bits > 0) result += BASE32[(buf << (5 - bits)) & 0x1f];
  return result;
}

/**
 * Build a real CIDv0 (base58btc, dag-pb/UnixFS) for a JSON manifest.
 * The returned `block` is the raw IPLD block — what a gateway returns for
 * `Accept: application/vnd.ipld.raw`.
 */
export async function buildCIDv0(
  manifest: object,
): Promise<{ cid: string; block: Uint8Array }> {
  return buildCIDv0Bytes(new TextEncoder().encode(JSON.stringify(manifest)));
}

/**
 * Like buildCIDv0 but accepts raw content bytes — useful for testing non-JSON content.
 */
export async function buildCIDv0Bytes(
  content: Uint8Array,
): Promise<{ cid: string; block: Uint8Array }> {
  const block = makeDagPBNode(makeUnixFSFile(content));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", block));
  const cid = base58Encode(new Uint8Array([0x12, 0x20, ...hash]));
  return { cid, block };
}

/**
 * Build a CIDv1 with the raw codec (0x55), where the block IS the content bytes.
 * Used to verify the non-dag-pb path in cid-verify.ts.
 */
export async function buildCIDv1Raw(
  manifest: object,
): Promise<{ cid: string; block: Uint8Array }> {
  const block = new TextEncoder().encode(JSON.stringify(manifest));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", block));
  // CIDv1 bytes: version(1) + codec(0x55) + multihash(0x12 0x20 hash)
  const cidBytes = new Uint8Array([
    ...encodeVarint(1),
    ...encodeVarint(0x55),
    0x12,
    0x20,
    ...hash,
  ]);
  const cid = "b" + base32Encode(cidBytes);
  return { cid, block };
}
