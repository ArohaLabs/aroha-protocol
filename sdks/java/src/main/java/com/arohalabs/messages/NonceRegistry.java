// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.messages;

import com.arohalabs.util.IsoTime;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Aroha Layer 3 — Nonce Registry (Replay Attack Prevention)
 *
 * Keeps a record of seen nonces until their associated message expires.
 * Thread-safe for concurrent server use.
 *
 * <p>Keys passed by {@link ArohaEnvelope#validate} are sender-scoped
 * ({@code <fromDID>:<nonce>}) and are recorded only AFTER the envelope's
 * signature verified, so unauthenticated traffic cannot fill the store or
 * pre-burn a nonce.
 *
 * <p>The default store is in-process and forgotten on restart; pass a
 * persistent or shared {@link NonceStore} for multi-instance deployments.
 */
public final class NonceRegistry {

    /** Pluggable deduplication backend (TS {@code NonceStore}). */
    public interface NonceStore {
        /**
         * Record {@code key} until {@code expiryMs} (epoch ms). True if it was
         * absent (fresh), false if already recorded (replay). Must be atomic.
         */
        boolean setIfAbsent(String key, long expiryMs);

        /** Drop entries whose expiry has passed. */
        void evictExpired();

        /** Number of tracked entries, or -1 if unknown. */
        default int size() { return -1; }
    }

    /** Default in-process store. */
    public static final class MapNonceStore implements NonceStore {
        private final Map<String, Long> seen = new ConcurrentHashMap<>();

        @Override
        public boolean setIfAbsent(String key, long expiryMs) {
            return seen.putIfAbsent(key, expiryMs) == null;
        }

        @Override
        public void evictExpired() {
            long now = System.currentTimeMillis();
            seen.values().removeIf(exp -> exp < now);
        }

        @Override
        public int size() { return seen.size(); }
    }

    private final NonceStore store;

    public NonceRegistry() {
        this(new MapNonceStore());
    }

    public NonceRegistry(NonceStore store) {
        this.store = store;
    }

    /**
     * Checks whether a nonce is fresh (not yet seen) and records it.
     *
     * @param nonce     the nonce key (sender-scoped when called by the validator)
     * @param expiresAt ISO-8601 instant until which the nonce must be remembered
     * @return true if fresh (accept), false if already known or already
     *         expired / unparseable (reject)
     */
    public boolean check(String nonce, String expiresAt) {
        store.evictExpired();
        Long expiry = IsoTime.parseMillis(expiresAt);
        if (expiry == null || System.currentTimeMillis() > expiry) {
            return false;
        }
        return store.setIfAbsent(nonce, expiry);
    }

    /** Returns the number of currently tracked nonces (-1 if the store cannot say). */
    public int size() {
        store.evictExpired();
        return store.size();
    }
}
