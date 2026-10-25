// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — File-backed NonceStore
 *
 * WHY this exists: the default `MapNonceStore` lives in process memory, so
 * every restart (deploy, crash, autoscaler recycle) forgets every nonce it
 * has seen. Any envelope captured before the restart whose `expires` is
 * still in the future can then be replayed and will be accepted exactly
 * once more. `validateEnvelope` now caps the lifetime of an envelope
 * (`maxTtlMs`, default 5 minutes) which bounds that window, but it does not
 * close it. A single-instance deployment closes it by persisting nonces to
 * local disk with this store; a multi-instance deployment needs a shared
 * store (e.g. Redis `SET key NX PXAT expiry`) behind the same `NonceStore`
 * interface.
 *
 * Format: append-only JSON Lines, one `{"k": <key>, "e": <expiryMs>}` per
 * accepted nonce. On construction the file is replayed into memory (expired
 * and malformed lines — e.g. a torn final line after a crash — are
 * skipped). `evictExpired()` (called periodically by NonceRegistry) drops
 * expired entries from memory and, once enough have expired, compacts the
 * file by writing the live set to a temp file and renaming it over the
 * original, so the file does not grow without bound.
 *
 * Durability: each accepted nonce is written with a synchronous append
 * BEFORE `setIfAbsent` resolves `true`, so a nonce is never reported fresh
 * without being on disk as far as the OS is concerned (survives a process
 * crash). Pass `{ fsync: true }` to also flush to stable storage on every
 * write (survives power loss, costs a disk flush per message).
 *
 * Permissions: the file is created 0600 (owner-only). A nonce list is not
 * a secret, but it is a record of who this agent talked to and when, and a
 * world-writable copy could be truncated to reopen the window it closes.
 *
 * One process per file: the in-memory map is the source of truth for the
 * duplicate check, so two processes appending to the same file would not
 * see each other's nonces. Use a shared store for multi-instance setups.
 *
 * Node.js only (uses `fs`); deliberately NOT re-exported from the
 * `@aroha-sdk/core/messages` subpath so that subpath stays free of Node
 * built-ins. Import it from the package root.
 */

import {
  appendFileSync,
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "fs";
import { dirname } from "path";
import type { NonceStore } from "./nonce.js";

export interface FileNonceStoreOptions {
  /** fsync after every append (default false — see module comment). */
  fsync?: boolean;
  /**
   * Compact the file once at least this many expired lines have been
   * evicted since the last compaction. Default 1000.
   */
  compactAfterEvictions?: number;
}

export class FileNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();
  private readonly fsync: boolean;
  private readonly compactAfter: number;
  private evictedSinceCompaction = 0;

  constructor(private readonly filePath: string, options: FileNonceStoreOptions = {}) {
    this.fsync = options.fsync ?? false;
    this.compactAfter = options.compactAfterEvictions ?? 1000;
    mkdirSync(dirname(filePath), { recursive: true });
    this.load();
  }

  private load(): void {
    if (!existsSync(this.filePath)) return;
    // `mode` only applies when a file is created, so a store file left by an
    // older version (or a different umask) keeps whatever it had. Tighten it
    // once here. A no-op on Windows, where POSIX modes are not enforced.
    chmodSync(this.filePath, 0o600);
    const now = Date.now();
    const text = readFileSync(this.filePath, "utf8");
    let stale = 0;
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line) as { k?: unknown; e?: unknown };
        if (typeof rec.k !== "string" || typeof rec.e !== "number") { stale++; continue; }
        if (rec.e < now) { stale++; continue; }
        const prev = this.seen.get(rec.k);
        if (prev === undefined || rec.e > prev) this.seen.set(rec.k, rec.e);
      } catch {
        // Torn/garbled line (e.g. crash mid-append) — skip it. The nonce it
        // may have recorded belongs to a request whose response was never
        // completed, so the worst case is one re-acceptance of that message.
        stale++;
      }
    }
    this.evictedSinceCompaction = stale;
    if (stale >= this.compactAfter) this.compact();
  }

  private append(key: string, expiryMs: number): void {
    const line = JSON.stringify({ k: key, e: expiryMs }) + "\n";
    if (!this.fsync) {
      appendFileSync(this.filePath, line, { encoding: "utf8", mode: 0o600 });
      return;
    }
    const fd = openSync(this.filePath, "a", 0o600);
    try {
      appendFileSync(fd, line, "utf8");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  private compact(): void {
    const tmp = `${this.filePath}.${process.pid}.tmp`;
    const body = [...this.seen].map(([k, e]) => JSON.stringify({ k, e })).join("\n");
    // The temp file replaces the store by rename, so it must be created
    // owner-only too — otherwise the first compaction widens the store to the
    // umask default. A leftover tmp from a crashed run is tightened before use.
    writeFileSync(tmp, body ? body + "\n" : "", { encoding: "utf8", mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, this.filePath);
    this.evictedSinceCompaction = 0;
  }

  async setIfAbsent(nonce: string, expiryMs: number): Promise<boolean> {
    const existing = this.seen.get(nonce);
    if (existing !== undefined && existing >= Date.now()) return false;
    // Persist first: if the write throws, the nonce is NOT reported fresh,
    // and the caller rejects the message (fail closed).
    this.append(nonce, expiryMs);
    this.seen.set(nonce, expiryMs);
    return true;
  }

  async evictExpired(): Promise<void> {
    const now = Date.now();
    for (const [nonce, expiryMs] of this.seen) {
      if (expiryMs < now) {
        this.seen.delete(nonce);
        this.evictedSinceCompaction++;
      }
    }
    if (this.evictedSinceCompaction >= this.compactAfter) this.compact();
  }

  get size(): number { return this.seen.size; }
}
