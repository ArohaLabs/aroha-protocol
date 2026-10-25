// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Where the registry fetches a manifest by CID, in order.
 *
 * Every gateway here is either Aroha-operated or explicitly configured — no
 * third-party gateway is consulted silently:
 *
 *   1. Pinata's API gateway, ONLY when PINATA_JWT is set (a secret the
 *      operator chose to provision). Content the SDK just pinned is there
 *      immediately, without public-gateway propagation delay.
 *   2. IPFS_GATEWAY — the Aroha-operated gateway (wrangler.toml [vars]);
 *      @aroha-sdk/core's AROHA_DEFAULT_IPFS_GATEWAY when unset.
 *   3. IPFS_FALLBACK_GATEWAYS — optional comma-separated list, declared in
 *      wrangler.toml so the fallback is visible and removable.
 *
 * Whichever gateway answers, the caller only accepts a raw block whose
 * SHA-256 matches the CID, so a gateway can withhold content but cannot
 * substitute it.
 */

import { AROHA_DEFAULT_IPFS_GATEWAY } from "@aroha-sdk/core/endpoints";

/** Pinata's authenticated gateway — used only with PINATA_JWT. */
export const PINATA_API_GATEWAY = "https://gateway.pinata.cloud/ipfs";

export interface GatewayEnv {
  IPFS_GATEWAY?: string;
  IPFS_FALLBACK_GATEWAYS?: string;
  PINATA_JWT?: string;
}

export interface GatewayAttempt {
  label: string;
  url: string;
  headers?: Record<string, string>;
}

function trimSlash(u: string): string {
  return u.trim().replace(/\/+$/, "");
}

/** Ordered fetch attempts for `cid` (see module comment). */
export function manifestGatewayAttempts(cid: string, env: GatewayEnv): GatewayAttempt[] {
  const attempts: GatewayAttempt[] = [];
  if (env.PINATA_JWT) {
    attempts.push({
      label: "pinata-direct",
      url: `${PINATA_API_GATEWAY}/${cid}`,
      headers: { Authorization: `Bearer ${env.PINATA_JWT}` },
    });
  }
  const primary = trimSlash(env.IPFS_GATEWAY?.trim() || AROHA_DEFAULT_IPFS_GATEWAY);
  attempts.push({ label: "ipfs-gateway", url: `${primary}/${cid}` });
  for (const g of (env.IPFS_FALLBACK_GATEWAYS ?? "").split(",")) {
    const base = trimSlash(g);
    if (!base || base === primary) continue;
    let host: string;
    try {
      const u = new URL(base);
      if (u.protocol !== "https:") throw new Error("not https");
      host = u.host;
    } catch {
      console.warn(`[ipfs] ignoring IPFS_FALLBACK_GATEWAYS entry that is not an https URL: ${base}`);
      continue;
    }
    attempts.push({ label: `fallback:${host}`, url: `${base}/${cid}` });
  }
  return attempts;
}
