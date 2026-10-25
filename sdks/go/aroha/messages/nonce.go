// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package messages

import (
	"sync"
	"time"
)

// NonceStore is a pluggable nonce deduplication backend (TS NonceStore).
//
// The default MapNonceStore is in-process and forgotten on restart. A
// multi-instance deployment needs a shared store (e.g. Redis SET NX PXAT).
// Keys passed by Validate are sender-scoped ("<fromDID>:<nonce>") and are
// recorded only AFTER the envelope's signature verified.
type NonceStore interface {
	// SetIfAbsent records key until expiry and reports whether it was fresh.
	SetIfAbsent(key string, expiry time.Time) (bool, error)
	// EvictExpired drops entries whose expiry has passed.
	EvictExpired() error
}

// MapNonceStore is the default in-process NonceStore. Safe for concurrent use.
type MapNonceStore struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	lastEvict time.Time
	now       func() time.Time
}

// NewMapNonceStore returns an empty store.
func NewMapNonceStore() *MapNonceStore {
	return &MapNonceStore{seen: map[string]time.Time{}, now: time.Now}
}

// SetIfAbsent implements NonceStore. An entry whose expiry has passed counts
// as absent. Expired entries are swept at most once a second, so a call is
// O(1) amortised instead of O(n).
func (s *MapNonceStore) SetIfAbsent(key string, expiry time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if now.Sub(s.lastEvict) > time.Second {
		s.evictLocked(now)
	}
	if exp, ok := s.seen[key]; ok && !now.After(exp) {
		return false, nil
	}
	s.seen[key] = expiry
	return true, nil
}

// EvictExpired implements NonceStore.
func (s *MapNonceStore) EvictExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictLocked(s.now())
	return nil
}

// Len returns the number of tracked entries (expired ones included until swept).
func (s *MapNonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func (s *MapNonceStore) evictLocked(now time.Time) {
	for k, exp := range s.seen {
		if now.After(exp) {
			delete(s.seen, k)
		}
	}
	s.lastEvict = now
}

// NonceRegistry tracks seen nonces to prevent replay. Safe for concurrent use.
type NonceRegistry struct {
	store NonceStore
}

// NewNonceRegistry returns a registry backed by an in-process MapNonceStore.
func NewNonceRegistry() *NonceRegistry {
	return &NonceRegistry{store: NewMapNonceStore()}
}

// NewNonceRegistryWithStore returns a registry backed by store (e.g. a
// shared store for multi-instance deployments).
func NewNonceRegistryWithStore(store NonceStore) *NonceRegistry {
	return &NonceRegistry{store: store}
}

// CheckKey records key until expiry and reports whether it was fresh.
// Validate calls it with the sender-scoped key "<from>:<nonce>".
func (r *NonceRegistry) CheckKey(key string, expiry time.Time) (bool, error) {
	return r.store.SetIfAbsent(key, expiry)
}

// Check returns true if nonce is fresh (not yet seen and not expired).
// Returns false if it was already registered, the message has expired, or
// expiresAt is not an RFC 3339 timestamp. Note Validate does NOT use this
// global namespace; it scopes nonces per sender via CheckKey.
func (r *NonceRegistry) Check(nonce, expiresAt string) bool {
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || time.Now().After(expiry) {
		return false
	}
	ok, err := r.store.SetIfAbsent(nonce, expiry)
	return err == nil && ok
}

// Size returns the number of tracked nonces after evicting expired ones.
// It reports 0 for stores other than MapNonceStore.
func (r *NonceRegistry) Size() int {
	_ = r.store.EvictExpired()
	if m, ok := r.store.(*MapNonceStore); ok {
		return m.Len()
	}
	return 0
}
