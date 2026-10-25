// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package orchestrator_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/orchestrator"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"
)

// ── CSN ──────────────────────────────────────────────────────────────────────

func schema(required []string, props map[string]string) map[string]any {
	p := map[string]any{}
	for k, typ := range props {
		p[k] = map[string]any{"type": typ}
	}
	return map[string]any{"type": "object", "properties": p, "required": required}
}

func TestSchemaCompatibilityScore(t *testing.T) {
	desired := schema([]string{"origin", "dest"}, map[string]string{"origin": "string", "dest": "string"})
	if s := orchestrator.SchemaCompatibilityScore(desired, desired); s != 1 {
		t.Errorf("identical schemas scored %v", s)
	}
	numeric := schema([]string{"n"}, map[string]string{"n": "integer"})
	if s := orchestrator.SchemaCompatibilityScore(numeric, schema(nil, map[string]string{"n": "number"})); s != 0.7 {
		t.Errorf("integer vs number scored %v, want 0.7", s)
	}
	if s := orchestrator.SchemaCompatibilityScore(desired, schema(nil, map[string]string{"x": "string"})); s != 0 {
		t.Errorf("disjoint schemas scored %v", s)
	}
	if s := orchestrator.SchemaCompatibilityScore(map[string]any{}, desired); s != 1 {
		t.Errorf("empty desired schema scored %v", s)
	}
	// Required fields weigh more than optional ones.
	mixed := schema([]string{"a"}, map[string]string{"a": "string", "b": "string"})
	onlyA := orchestrator.SchemaCompatibilityScore(mixed, schema(nil, map[string]string{"a": "string"}))
	onlyB := orchestrator.SchemaCompatibilityScore(mixed, schema(nil, map[string]string{"b": "string"}))
	if onlyA <= onlyB {
		t.Errorf("required match %v should outscore optional match %v", onlyA, onlyB)
	}
}

func TestSchemaHash_KeyOrderIndependentAndJSCompatible(t *testing.T) {
	a := map[string]any{"b": 1, "a": map[string]any{"y": "<", "x": 2}}
	var b map[string]any
	_ = json.Unmarshal([]byte(`{"a":{"x":2,"y":"<"},"b":1}`), &b)
	if orchestrator.SchemaHash(a) != orchestrator.SchemaHash(b) {
		t.Error("hash depends on key order or number representation")
	}
	// sha256 of the JS string {"a":{"x":2,"y":"<"},"b":1}
	if h := orchestrator.SchemaHash(a); h != "f81ae74b5f0d28be6fbcec679802a39093b16df9b7df777440ca6c3c0f8c9736" {
		t.Errorf("hash %s", h)
	}
}

func TestCapabilityRegistry(t *testing.T) {
	r := orchestrator.NewCapabilityRegistry()
	r.Register(&orchestrator.CapabilityEntry{Name: "flights", InputSchema: schema([]string{"origin"}, map[string]string{"origin": "string", "date": "string"})})
	r.Register(&orchestrator.CapabilityEntry{Name: "hotels", InputSchema: schema([]string{"city"}, map[string]string{"city": "string"})})

	m := r.FindByInputSchema(schema([]string{"origin"}, map[string]string{"origin": "string"}))
	if m == nil || m.Entry.Name != "flights" || !m.Confident {
		t.Fatalf("best match = %+v", m)
	}
	if got := r.FindCandidates(schema([]string{"city"}, map[string]string{"city": "string"}), 0.5); len(got) != 1 || got[0].Entry.Name != "hotels" {
		t.Errorf("candidates = %+v", got)
	}
	if r.Get("hotels") == nil || len(r.List()) != 2 {
		t.Error("Get/List")
	}
}

func TestDiscoveryCache(t *testing.T) {
	c := orchestrator.NewDiscoveryCache()
	c.Put("did:aroha:p", "h1", "flights", nil, "structural", 0.9)
	c.Put("did:aroha:p", "h2", "hotels", nil, "structural", 0.9)
	if e := c.Get("did:aroha:p", "h1"); e == nil || e.CapabilityName != "flights" || e.HitCount != 1 {
		t.Fatalf("Get = %+v", e)
	}
	c.Invalidate("did:aroha:p", "flights")
	if c.Get("did:aroha:p", "h1") != nil || c.Get("did:aroha:p", "h2") == nil {
		t.Error("Invalidate by capability")
	}
	c.Invalidate("did:aroha:p", "")
	if c.Get("did:aroha:p", "h2") != nil {
		t.Error("Invalidate all")
	}
}

// ── Saga ─────────────────────────────────────────────────────────────────────

type fakeAgent struct {
	mu        sync.Mutex
	failOn    string // message type to answer with ArohaError
	received  []string
	publicKey ed25519.PublicKey
	did       string
	nonces    *messages.NonceRegistry
}

func (a *fakeAgent) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var env map[string]any
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if err := messages.Validate(env, a.publicKey, a.did, a.nonces); err != nil {
			t.Errorf("agent %s rejected envelope: %v", a.did, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		typ, _ := env["type"].(string)
		a.mu.Lock()
		a.received = append(a.received, typ)
		a.mu.Unlock()

		resp := map[string]any{"type": typ + "Ack", "body": map[string]any{}}
		switch {
		case typ == a.failOn:
			resp = map[string]any{"type": messages.TypeError, "body": map[string]any{"code": "Aroha_RESERVATION_FAILED", "message": "no seats"}}
		case typ == messages.TypeReserve:
			resp["body"] = map[string]any{"reservationToken": "tok-" + a.did, "expiresAt": "2099-01-01T00:00:00.000Z"}
		case typ == messages.TypeCommit:
			resp["body"] = map[string]any{"result": map[string]any{"confirmation": "C-" + a.did}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func (a *fakeAgent) got() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.received...)
}

func sagaSetup(t *testing.T, failOn map[int]string) (*orchestrator.SagaEngine, []*fakeAgent, []*orchestrator.SagaStep) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const orch = "did:aroha:orchestrator"
	engine := orchestrator.NewSagaEngine(transport.NewArohaClient(), orch, orch+"#key-1", priv)
	var agents []*fakeAgent
	var steps []*orchestrator.SagaStep
	for i := 0; i < 2; i++ {
		a := &fakeAgent{failOn: failOn[i], publicKey: pub, did: []string{"did:aroha:air", "did:aroha:hotel"}[i], nonces: messages.NewNonceRegistry()}
		srv := httptest.NewServer(a.handler(t))
		t.Cleanup(srv.Close)
		agents = append(agents, a)
		steps = append(steps, &orchestrator.SagaStep{AgentDID: a.did, AgentEndpoint: srv.URL, Capability: "book"})
	}
	return engine, agents, steps
}

func TestSaga_Success(t *testing.T) {
	engine, agents, steps := sagaSetup(t, nil)
	res, err := engine.Execute(steps)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success || len(res.Results) != 2 {
		t.Fatalf("result = %+v", res)
	}
	if res.Results[0]["confirmation"] != "C-did:aroha:air" {
		t.Errorf("commit result = %v", res.Results[0])
	}
	for _, a := range agents {
		if got := a.got(); len(got) != 2 || got[0] != messages.TypeReserve || got[1] != messages.TypeCommit {
			t.Errorf("%s received %v", a.did, got)
		}
	}
}

func TestSaga_ReserveFailureCompensates(t *testing.T) {
	engine, agents, steps := sagaSetup(t, map[int]string{1: messages.TypeReserve})
	res, err := engine.Execute(steps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Success || len(res.Failures) != 1 || res.Failures[0]["reason"] != "no seats" {
		t.Fatalf("result = %+v", res)
	}
	if got := agents[0].got(); len(got) != 2 || got[1] != messages.TypeCancel {
		t.Errorf("reserved participant must be cancelled, received %v", got)
	}
	if steps[0].State != orchestrator.StateCancelled || steps[1].State != orchestrator.StateFailed {
		t.Errorf("states = %s, %s", steps[0].State, steps[1].State)
	}
}

func TestSaga_CommitFailureCompensates(t *testing.T) {
	engine, agents, steps := sagaSetup(t, map[int]string{1: messages.TypeCommit})
	res, err := engine.Execute(steps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Success {
		t.Fatal("saga succeeded despite a commit failure")
	}
	if got := agents[0].got(); len(got) != 3 || got[2] != messages.TypeCancel {
		t.Errorf("committed participant must be compensated, received %v", got)
	}
}
