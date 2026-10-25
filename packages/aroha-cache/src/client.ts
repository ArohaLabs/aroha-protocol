// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * CachingArohaClient — client-side semantic caching.
 *
 * Intercepts ArohaRequest sends, returning cached ArohaResponse bodies when
 * a matching response exists. Cache misses fall through to the real network
 * and the response is stored for future callers.
 *
 * Only ArohaRequest messages are cached — saga protocol messages (Reserve,
 * Commit, Cancel) always go through to ensure correctness.
 */

import {
  ArohaClient,
  type ArohaEnvelope,
  type SendOptions,
  type ArohaRequestBody,
  type ArohaResponseBody,
} from "@aroha-sdk/core";
import { type ISemanticCache, type CacheEntry, cacheKey, InMemorySemanticCache } from "./cache.js";

// ─── TTL configuration ────────────────────────────────────────────────────────

export interface CacheTtlConfig {
  /** Default TTL in milliseconds (default: 5 minutes) */
  defaultTtlMs?: number;
  /** Per-capability TTL overrides */
  perCapability?: Record<string, number>;
}

function ttlForCapability(config: CacheTtlConfig, capability: string): number {
  return config.perCapability?.[capability] ?? config.defaultTtlMs ?? 5 * 60 * 1000;
}

// ─── CachingArohaClient ────────────────────────────────────────────────────────

export class CachingArohaClient extends ArohaClient {
  private readonly cache: ISemanticCache;
  private readonly ttl: CacheTtlConfig;

  constructor(opts: { cache?: ISemanticCache; ttl?: CacheTtlConfig } = {}) {
    super();
    this.cache = opts.cache ?? new InMemorySemanticCache();
    this.ttl = opts.ttl ?? {};
  }

  override async send(
    endpoint: string,
    envelope: ArohaEnvelope,
    opts: SendOptions = {}
  ): Promise<ArohaEnvelope | null> {
    // Only cache ArohaRequest — never cache saga protocol messages
    if (envelope.type !== "ArohaRequest") {
      return super.send(endpoint, envelope, opts);
    }

    const body = envelope.body as ArohaRequestBody;
    const key = cacheKey(body.capability, body.params);
    const cached = await this.cache.get(key);

    if (cached) {
      // Synthesize a ArohaResponse from the cached entry
      return {
        ...envelope,
        id: `urn:uuid:cache-${key.slice(0, 8)}`,
        type: "ArohaResponse",
        from: envelope.to,
        to: envelope.from,
        body: {
          capability: body.capability,
          result: cached.result,
        } satisfies ArohaResponseBody,
        // No proof on cache-synthesized responses — the original was verified when stored
        proof: undefined,
      } as ArohaEnvelope;
    }

    const response = await super.send(endpoint, envelope, opts);

    if (response?.type === "ArohaResponse") {
      const respBody = response.body as ArohaResponseBody;
      const ttlMs = ttlForCapability(this.ttl, body.capability);
      const now = new Date();
      const entry: CacheEntry = {
        capability: body.capability,
        params: body.params,
        result: respBody.result,
        cachedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
        hitCount: 0,
      };
      await this.cache.set(key, entry);
    }

    return response;
  }

  /** Access the underlying cache for stats and manual invalidation. */
  get semanticCache(): ISemanticCache {
    return this.cache;
  }
}

// ─── Server-side handler wrapper ──────────────────────────────────────────────

import { type MessageHandler } from "@aroha-sdk/core";
import { buildEnvelope } from "@aroha-sdk/core";

export interface CachedHandlerOptions {
  cache: ISemanticCache;
  ttl?: CacheTtlConfig;
  /** DID and private key of the server agent — needed to sign cache responses. */
  agentDID: string;
  agentPrivateKey: Uint8Array;
}

/**
 * Wrap a ArohaServer message handler with caching.
 * Cache hits are returned as signed ArohaResponse envelopes without calling
 * the underlying handler — eliminating LLM inference for repeated lookups.
 *
 * Usage:
 *   const server = new ArohaServer({
 *     onMessage: withCaching(myHandler, {
 *       cache: new InMemorySemanticCache(),
 *       agentDID, agentPrivateKey,
 *     }),
 *   });
 */
export function withCaching(
  handler: MessageHandler,
  opts: CachedHandlerOptions
): MessageHandler {
  const ttl = opts.ttl ?? {};

  return async (envelope, respond, stream) => {
    if (envelope.type !== "ArohaRequest") {
      return handler(envelope, respond, stream);
    }

    const body = envelope.body as ArohaRequestBody;
    const key = cacheKey(body.capability, body.params);
    const cached = await opts.cache.get(key);

    if (cached) {
      const responseBody: ArohaResponseBody = {
        capability: body.capability,
        result: cached.result,
      };
      const reply = await buildEnvelope(
        "ArohaResponse",
        opts.agentDID,
        envelope.from,
        responseBody,
        envelope.correlationId,
        opts.agentPrivateKey
      );
      respond(reply);
      return;
    }

    // Cache miss — call real handler, intercept response to cache it
    const captured: { reply: ArohaEnvelope | null } = { reply: null };
    const interceptingRespond = (reply: ArohaEnvelope) => {
      captured.reply = reply;
      respond(reply);
    };

    await handler(envelope, interceptingRespond, stream);

    const interceptedReply = captured.reply;
    if (interceptedReply !== null && interceptedReply.type === "ArohaResponse") {
      const respBody = interceptedReply.body as ArohaResponseBody;
      const ttlMs = ttlForCapability(ttl, body.capability);
      const now = new Date();
      await opts.cache.set(key, {
        capability: body.capability,
        params: body.params,
        result: respBody.result,
        cachedAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
        hitCount: 0,
      });
    }
  };
}
