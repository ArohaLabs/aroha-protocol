/**
 * Minimal IPFS CID verification — no external dependencies.
 *
 * Supports CIDv0 (base58btc, dag-pb) and CIDv1 (base32 lowercase, any codec).
 * Uses Web Crypto API (crypto.subtle) available in both Node.js 22+ and Workers.
 *
 * When a gateway supports `Accept: application/vnd.ipld.raw`, it returns the raw
 * IPLD block bytes. We SHA-256 those bytes and compare against the multihash
 * embedded in the CID — a mismatch means the gateway returned tampered content.
 */

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

function base58Decode(s: string): Uint8Array {
  const bytes: number[] = [0];
  for (const ch of s) {
    let carry = BASE58.indexOf(ch);
    if (carry < 0) throw new Error("invalid base58");
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const ch of s) {
    if (ch !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

function base32Decode(s: string): Uint8Array {
  const out: number[] = [];
  let buf = 0,
    bits = 0;
  for (const ch of s) {
    const idx = BASE32.indexOf(ch.toLowerCase());
    if (idx < 0) continue; // skip padding and unknown chars
    buf = (buf << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// Reads a protobuf varint from buf starting at pos. Returns [value, newPos].
// Uses 32-bit arithmetic — sufficient for tags, lengths, and small codec values.
function readVarint(buf: Uint8Array, pos: number): [number, number] {
  let result = 0,
    shift = 0;
  while (pos < buf.length) {
    const b = buf[pos++];
    result |= (b & 0x7f) << shift;
    shift += 7;
    if (!(b & 0x80)) return [result >>> 0, pos];
  }
  return [result >>> 0, pos];
}

// Minimal protobuf decoder — returns length-delimited (wire 2) fields by field number.
// Wire type 0 (varint) and fixed-width fields are consumed but discarded.
function decodeProtobuf(buf: Uint8Array): Map<number, Uint8Array> {
  const out = new Map<number, Uint8Array>();
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p1] = readVarint(buf, pos);
    if (!tag) break;
    pos = p1;
    const wire = tag & 7;
    if (wire === 0) {
      [, pos] = readVarint(buf, pos);
    } else if (wire === 2) {
      const [len, p2] = readVarint(buf, pos);
      pos = p2;
      out.set(tag >>> 3, buf.slice(pos, pos + len));
      pos += len;
    } else if (wire === 1) {
      pos += 8; // 64-bit fixed — skip
    } else if (wire === 5) {
      pos += 4; // 32-bit fixed — skip
    } else {
      break; // unknown wire type — stop parsing
    }
  }
  return out;
}

// Extracts the file content bytes from a raw IPLD block, based on the multicodec.
//   dag-pb (0x70): PBNode.Data (field 1) = UnixFS bytes; UnixFSData.Data (field 2) = content
//   raw (0x55) or dag-json (0x0129): block IS the content bytes
function extractFromBlock(codec: number, block: Uint8Array): Uint8Array | null {
  if (codec === 0x55 || codec === 0x0129) return block;
  if (codec === 0x70 || codec === 0) {
    // dag-pb (explicit 0x70 for CIDv1, or 0 as implicit for CIDv0)
    const node = decodeProtobuf(block);
    const unixfsBytes = node.get(1); // PBNode.Data
    if (!unixfsBytes) return null;
    const unixfsData = decodeProtobuf(unixfsBytes);
    return unixfsData.get(2) ?? null; // UnixFSData.Data
  }
  return null;
}

function parseCID(cid: string): { hashCode: number; digest: Uint8Array; codec: number } | null {
  try {
    let raw: Uint8Array;
    let codec: number;
    let mhStart: number;

    if (cid.startsWith("Qm")) {
      // CIDv0: base58btc(multihash) — implicitly dag-pb, SHA-256
      raw = base58Decode(cid);
      codec = 0; // dag-pb implied
      mhStart = 0;
    } else if (cid.startsWith("b")) {
      // CIDv1: b<base32lower>(version + codec + multihash)
      raw = base32Decode(cid.slice(1));
      const [ver, p1] = readVarint(raw, 0);
      if (ver !== 1) return null;
      const [c, p2] = readVarint(raw, p1);
      codec = c;
      mhStart = p2;
    } else {
      return null; // unsupported multibase
    }

    const [hashCode, p1] = readVarint(raw, mhStart);
    const [len, p2] = readVarint(raw, p1);
    return { hashCode, digest: raw.slice(p2, p2 + len), codec };
  } catch {
    return null;
  }
}

export type BlockVerifyResult =
  | { ok: true; manifest: unknown }
  | { ok: false; tampered: boolean };

/**
 * Verify a raw IPLD block against its CID and extract the JSON manifest.
 *
 * Returns:
 *   { ok: true, manifest }        — SHA-256 verified; manifest parsed
 *   { ok: false, tampered: true } — hash mismatch; gateway returned tampered data
 *   { ok: false, tampered: false} — CID format unsupported or content not decodable
 */
export async function verifyBlock(
  cid: string,
  block: Uint8Array,
): Promise<BlockVerifyResult> {
  const parsed = parseCID(cid);
  if (!parsed || parsed.hashCode !== 0x12 /* SHA-256 */) {
    return { ok: false, tampered: false };
  }

  const actual = new Uint8Array(await crypto.subtle.digest("SHA-256", block));
  const expected = parsed.digest;
  if (
    expected.length !== actual.length ||
    !expected.every((b, i) => b === actual[i])
  ) {
    return { ok: false, tampered: true };
  }

  const contentBytes = extractFromBlock(parsed.codec, block);
  if (!contentBytes) return { ok: false, tampered: false };

  try {
    return { ok: true, manifest: JSON.parse(new TextDecoder().decode(contentBytes)) };
  } catch {
    return { ok: false, tampered: false };
  }
}
