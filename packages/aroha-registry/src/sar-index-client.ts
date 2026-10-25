// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Federated SAR index client (design spec §7.3, §7.4).
 *
 * An index is a plain HTTP store — POST to publish, GET to query. It is
 * deliberately untrusted: this client verifies every record itself before
 * returning it, so a malicious or merely broken index can omit results but
 * cannot forge one. Callers are expected to configure several index URLs
 * (the registry being "one index among many, not the index" — spec §7.4);
 * publishing and querying both fan out across all of them and tolerate any
 * subset failing.
 */

import { verifySar, verifySarWithResolver, type SignedAgentRecord } from "./sar.js";

export interface PublishResult {
  indexUrl: string;
  ok: boolean;
  error?: string;
}

/** Publish a SAR to every given index. Failures are per-index, not fatal to the others. */
export async function publishSar(indexUrls: string[], sar: SignedAgentRecord): Promise<PublishResult[]> {
  return Promise.all(
    indexUrls.map(async (indexUrl): Promise<PublishResult> => {
      try {
        const res = await fetch(`${indexUrl.replace(/\/$/, "")}/v1/sar`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(sar),
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          return { indexUrl, ok: false, error: `${res.status}: ${text}` };
        }
        return { indexUrl, ok: true };
      } catch (err) {
        return { indexUrl, ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    }),
  );
}

export interface QueryOptions {
  capability?: string;
  did?: string;
  /**
   * Resolves keys for namespaced (non-content-addressed) DIDs. Content-
   * addressed DIDs never need this — they verify offline regardless.
   * Records whose DID needs a resolver are silently dropped if omitted,
   * same as any other record that fails verification.
   */
  resolvePublicKey?: (did: string) => Promise<Uint8Array | null> | Uint8Array | null;
}

/**
 * Query every given index and return the union of records that pass
 * verification, newest per DID. Un-verifiable or duplicate-but-older
 * records are dropped, not surfaced as errors — an unreachable or
 * malicious index is expected, ordinary federation behavior, not a fault
 * this function's caller needs to handle specially.
 */
export async function querySar(indexUrls: string[], opts: QueryOptions = {}): Promise<SignedAgentRecord[]> {
  const params = new URLSearchParams();
  if (opts.capability) params.set("capability", opts.capability);
  if (opts.did) params.set("did", opts.did);
  const qs = params.toString() ? `?${params}` : "";

  const perIndex = await Promise.allSettled(
    indexUrls.map(async (indexUrl) => {
      const res = await fetch(`${indexUrl.replace(/\/$/, "")}/v1/sar${qs}`);
      if (!res.ok) return [] as unknown[];
      const body = (await res.json()) as { records?: unknown[] };
      return body.records ?? [];
    }),
  );

  const candidates = perIndex.flatMap((r) => (r.status === "fulfilled" ? r.value : []));

  const verified = new Map<string, SignedAgentRecord>();
  for (const candidate of candidates) {
    const result = opts.resolvePublicKey
      ? await verifySarWithResolver(candidate, opts.resolvePublicKey)
      : await verifySar(candidate);
    if (!result.valid) continue;

    const existing = verified.get(result.sar.did);
    if (!existing || existing.issuedAt < result.sar.issuedAt) {
      verified.set(result.sar.did, result.sar);
    }
  }

  return [...verified.values()];
}
