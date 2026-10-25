// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Manifest Cache — eliminates repeated IPFS fetches for known agent manifests.
 *
 * IPFS is content-addressed: a CID uniquely and permanently identifies content.
 * If the content changes, the CID changes. Therefore manifests can be cached
 * indefinitely by CID — the cache is always correct as long as the CID matches.
 *
 * This wraps the ArohaIpfsClient and is a drop-in replacement.
 *
 * Performance impact:
 *   IPFS fetch: 200–800ms (p50)
 *   Cache hit:  <1ms
 *   For a 10-agent saga: eliminates 10 serial IPFS lookups (~2–8s → <10ms)
 */

import { type CapabilityManifest } from "./types.js";

// ─── Interface ────────────────────────────────────────────────────────────────

/** Minimal interface for the IPFS client — satisfied by ArohaIpfsClient. */
export interface IIpfsClient {
  fetchManifest(cid: string): Promise<CapabilityManifest>;
}

export interface ManifestCacheConfig {
  /**
   * Maximum number of manifests to hold in memory.
   * LRU eviction when exceeded. Default: 500
   */
  maxSize?: number;
}

interface CacheEntry {
  manifest: CapabilityManifest;
  lastUsed: number;
}

// ─── Cache ────────────────────────────────────────────────────────────────────

export class ManifestCache implements IIpfsClient {
  private readonly maxSize: number;
  private readonly cache = new Map<string, CacheEntry>();
  private hits = 0;
  private misses = 0;

  constructor(
    private readonly ipfs: IIpfsClient,
    config: ManifestCacheConfig = {}
  ) {
    this.maxSize = config.maxSize ?? 500;
  }

  async fetchManifest(cid: string): Promise<CapabilityManifest> {
    const entry = this.cache.get(cid);
    if (entry) {
      entry.lastUsed = Date.now();
      this.hits++;
      return entry.manifest;
    }

    this.misses++;
    const manifest = await this.ipfs.fetchManifest(cid);

    if (this.cache.size >= this.maxSize) this.evictLru();
    this.cache.set(cid, { manifest, lastUsed: Date.now() });

    return manifest;
  }

  /**
   * Pre-populate the cache (e.g. at startup from a local manifest store).
   * Useful for known trusted agents to avoid cold-start IPFS latency.
   */
  preload(cid: string, manifest: CapabilityManifest): void {
    if (this.cache.size >= this.maxSize) this.evictLru();
    this.cache.set(cid, { manifest, lastUsed: Date.now() });
  }

  /** Remove a manifest from cache (e.g. after the agent re-registers with a new CID). */
  invalidate(cid: string): void {
    this.cache.delete(cid);
  }

  get stats(): { size: number; hits: number; misses: number; hitRate: string } {
    const total = this.hits + this.misses;
    return {
      size: this.cache.size,
      hits: this.hits,
      misses: this.misses,
      hitRate: total === 0 ? "0%" : `${Math.round((this.hits / total) * 100)}%`,
    };
  }

  private evictLru(): void {
    let oldest: [string, CacheEntry] | null = null;
    for (const entry of this.cache.entries()) {
      if (!oldest || entry[1].lastUsed < oldest[1].lastUsed) oldest = entry;
    }
    if (oldest) this.cache.delete(oldest[0]);
  }
}
