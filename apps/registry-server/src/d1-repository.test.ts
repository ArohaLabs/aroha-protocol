import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { D1Repository } from "./d1-repository.js";
import {
  openDb,
  NONCE_SCHEMA,
  ROTATE_KEY_SCHEMA,
} from "./test-utils/sqlite-d1.js";

// Cast needed because SqliteD1 implements the D1 method subset used by D1Repository.
// D1Database globals are available from @cloudflare/workers-types.
function makeRepo(schema: string) {
  const { db, adapter } = openDb(schema);
  return { db, repo: new D1Repository(adapter as unknown as D1Database) };
}

// ─── consumeRotationNonce ─────────────────────────────────────────────────────

describe("D1Repository.consumeRotationNonce — nonce replay prevention", () => {
  it("first consumption returns true (row inserted)", async () => {
    const { repo } = makeRepo(NONCE_SCHEMA);
    const ok = await repo.consumeRotationNonce("nonce-1", "did-hash-1", Date.now() + 60_000);
    expect(ok).toBe(true);
  });

  it("replaying the same nonce returns false — INSERT OR IGNORE is a no-op (changes === 0)", async () => {
    const { repo } = makeRepo(NONCE_SCHEMA);
    const expiresAt = Date.now() + 60_000;

    const first = await repo.consumeRotationNonce("replay-nonce", "did-1", expiresAt);
    const replay = await repo.consumeRotationNonce("replay-nonce", "did-1", expiresAt);

    expect(first).toBe(true);
    expect(replay).toBe(false); // second INSERT OR IGNORE → changes === 0
  });

  it("different nonces for the same DID both succeed", async () => {
    const { repo } = makeRepo(NONCE_SCHEMA);
    const expiresAt = Date.now() + 60_000;

    const r1 = await repo.consumeRotationNonce("nonce-A", "did-1", expiresAt);
    const r2 = await repo.consumeRotationNonce("nonce-B", "did-1", expiresAt);

    expect(r1).toBe(true);
    expect(r2).toBe(true);
  });

  it("expired nonce (expiresAt in the past) is rejected without inserting a row", async () => {
    const { db, repo } = makeRepo(NONCE_SCHEMA);

    // expiresAt already in the past — should return false without writing
    const ok = await repo.consumeRotationNonce("past-nonce", "did-1", Date.now() - 1_000);
    expect(ok).toBe(false);

    // Table must be empty — no phantom row was inserted
    const rows = db.prepare("SELECT nonce FROM rotation_nonces").all();
    expect(rows).toHaveLength(0);
  });

  it("nonce PRIMARY KEY is global — same nonce for a different DID still collides", async () => {
    // rotation_nonces.nonce is TEXT PRIMARY KEY (not a composite key).
    // A nonce is globally unique across all DIDs — prevents cross-DID replay.
    const { repo } = makeRepo(NONCE_SCHEMA);
    const expiresAt = Date.now() + 60_000;

    const r1 = await repo.consumeRotationNonce("shared-nonce", "did-1", expiresAt);
    const r2 = await repo.consumeRotationNonce("shared-nonce", "did-2", expiresAt);

    expect(r1).toBe(true);
    expect(r2).toBe(false); // PK collision → INSERT OR IGNORE no-op
  });
});

// ─── pruneExpiredRotationNonces ───────────────────────────────────────────────

describe("D1Repository.pruneExpiredRotationNonces", () => {
  it("deletes expired nonces and leaves fresh ones intact", async () => {
    const { db, repo } = makeRepo(NONCE_SCHEMA);

    await repo.consumeRotationNonce("stale-nonce", "did-1", Date.now() - 1_000);
    await repo.consumeRotationNonce("fresh-nonce", "did-1", Date.now() + 60_000);

    await repo.pruneExpiredRotationNonces();

    const rows = db.prepare("SELECT nonce FROM rotation_nonces").all() as { nonce: string }[];
    const nonces = rows.map((r) => r.nonce);

    expect(nonces).toContain("fresh-nonce");
    expect(nonces).not.toContain("stale-nonce");
  });

  it("is a no-op when there are no expired nonces", async () => {
    const { db, repo } = makeRepo(NONCE_SCHEMA);
    await repo.consumeRotationNonce("fresh-only", "did-1", Date.now() + 60_000);

    await repo.pruneExpiredRotationNonces(); // should not throw

    const rows = db.prepare("SELECT nonce FROM rotation_nonces").all();
    expect(rows).toHaveLength(1);
  });
});

// ─── rotateKey ────────────────────────────────────────────────────────────────

describe("D1Repository.rotateKey", () => {
  const NOW = Date.now();

  function insertAgent(db: DatabaseSync, didHash: string, pubKey: string) {
    db.prepare(
      `INSERT INTO agent_records
         (did_hash, did, owner_key_hash, public_key_b64, registered_at, last_updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(didHash, `did:aroha:${didHash}`, "owner-hash", pubKey, NOW, NOW);
  }

  it("returns new keyVersion and archives the old public key", async () => {
    const { db, repo } = makeRepo(ROTATE_KEY_SCHEMA);
    insertAgent(db, "did-h1", "old-pub-key-b64");

    const result = await repo.rotateKey("did-h1", "new-pub-key-b64", 1);

    expect(result).not.toBeNull();
    expect(result!.keyVersion).toBe(2);

    const agent = db
      .prepare("SELECT public_key_b64, key_version FROM agent_records WHERE did_hash = ?")
      .get("did-h1") as { public_key_b64: string; key_version: number };
    expect(agent.public_key_b64).toBe("new-pub-key-b64");
    expect(agent.key_version).toBe(2);

    const revoked = db
      .prepare("SELECT public_key_b64, key_version FROM revoked_keys WHERE did_hash = ?")
      .all("did-h1") as { public_key_b64: string; key_version: number }[];
    expect(revoked).toHaveLength(1);
    expect(revoked[0].public_key_b64).toBe("old-pub-key-b64");
    expect(revoked[0].key_version).toBe(1);
  });

  it("returns null for an unknown or inactive DID", async () => {
    const { repo } = makeRepo(ROTATE_KEY_SCHEMA);
    const result = await repo.rotateKey("no-such-did", "any-key", 1);
    expect(result).toBeNull();
  });

  // Two rotations verified against the same current key (same version):
  // exactly one lands, the other is a conflict, and the old key is archived
  // once — not twice with the second rotation silently overwriting the first.
  it("refuses a rotation whose expected version is stale (concurrent rotation)", async () => {
    const { db, repo } = makeRepo(ROTATE_KEY_SCHEMA);
    insertAgent(db, "did-h3", "key-v1");

    const [a, b] = await Promise.all([
      repo.rotateKey("did-h3", "key-a", 1),
      repo.rotateKey("did-h3", "key-b", 1),
    ]);
    expect([a, b].filter((r) => r === "conflict")).toHaveLength(1);
    expect([a, b].filter((r) => typeof r === "object" && r?.keyVersion === 2)).toHaveLength(1);

    const archived = db.prepare("SELECT COUNT(*) AS n FROM revoked_keys WHERE did_hash = ?").get("did-h3") as { n: number };
    expect(archived.n).toBe(1);
  });

  it("increments keyVersion on each successive rotation", async () => {
    const { db, repo } = makeRepo(ROTATE_KEY_SCHEMA);
    insertAgent(db, "did-h2", "key-v1");

    await repo.rotateKey("did-h2", "key-v2", 1);
    const r = await repo.rotateKey("did-h2", "key-v3", 2);

    expect(r).toEqual({ keyVersion: 3 });

    const revoked = db
      .prepare("SELECT key_version FROM revoked_keys WHERE did_hash = ? ORDER BY key_version")
      .all("did-h2") as { key_version: number }[];
    expect(revoked.map((r) => r.key_version)).toEqual([1, 2]);
  });
});
