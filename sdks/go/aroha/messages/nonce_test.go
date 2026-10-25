// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package messages_test

import (
	"sync"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
)

func TestNonceRegistry_Check(t *testing.T) {
	r := messages.NewNonceRegistry()
	exp := time.Now().Add(time.Minute).UTC().Format("2006-01-02T15:04:05.000Z")
	if !r.Check("n1", exp) {
		t.Fatal("fresh nonce rejected")
	}
	if r.Check("n1", exp) {
		t.Fatal("replayed nonce accepted")
	}
	if !r.Check("n2", exp) {
		t.Fatal("second nonce rejected")
	}
	if r.Size() != 2 {
		t.Errorf("size = %d", r.Size())
	}
	if r.Check("n3", time.Now().Add(-time.Second).UTC().Format(time.RFC3339)) {
		t.Error("expired message accepted")
	}
	if r.Check("n4", "garbage") {
		t.Error("unparseable expiry accepted")
	}
}

func TestMapNonceStore_ExpiredEntriesAreAbsent(t *testing.T) {
	s := messages.NewMapNonceStore()
	past := time.Now().Add(-time.Second)
	if ok, _ := s.SetIfAbsent("k", past); !ok {
		t.Fatal("first insert")
	}
	if ok, _ := s.SetIfAbsent("k", time.Now().Add(time.Minute)); !ok {
		t.Fatal("an expired entry must not block a new one")
	}
	if ok, _ := s.SetIfAbsent("k", time.Now().Add(time.Minute)); ok {
		t.Fatal("live entry ignored")
	}
	_ = s.EvictExpired()
	if s.Len() != 1 {
		t.Errorf("len = %d", s.Len())
	}
}

func TestNonceRegistry_Concurrent(t *testing.T) {
	r := messages.NewNonceRegistry()
	exp := time.Now().Add(time.Minute)
	var wg sync.WaitGroup
	var mu sync.Mutex
	fresh := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := r.CheckKey("same", exp); ok {
				mu.Lock()
				fresh++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if fresh != 1 {
		t.Errorf("%d goroutines saw the nonce as fresh, want 1", fresh)
	}
}

type countingStore struct{ calls int }

func (c *countingStore) SetIfAbsent(string, time.Time) (bool, error) { c.calls++; return true, nil }
func (c *countingStore) EvictExpired() error                         { return nil }

func TestNonceRegistry_CustomStore(t *testing.T) {
	cs := &countingStore{}
	r := messages.NewNonceRegistryWithStore(cs)
	_, _ = r.CheckKey("a", time.Now().Add(time.Minute))
	if cs.calls != 1 {
		t.Errorf("custom store not used")
	}
}
