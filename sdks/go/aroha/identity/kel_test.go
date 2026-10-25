// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
)

// ── Test-only log builders (the SDK side is read-only) ──────────────────────

const now = "2026-10-07T00:00:00.000Z"

func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
}

func randKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// roundTrip turns a Go-built event into the JSON data model a verifier receives.
func roundTrip(t *testing.T, ev map[string]any) identity.KelEvent {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jcs.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func sign(t *testing.T, ev map[string]any, k ed25519.PrivateKey) identity.KelEvent {
	t.Helper()
	ev = roundTrip(t, ev)
	msg, err := jcs.Canonicalize(ev)
	if err != nil {
		t.Fatal(err)
	}
	ev["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, msg))
	return ev
}

type ident struct {
	did       string
	cur, next ed25519.PrivateKey
	kel       []identity.KelEvent
}

func incept(t *testing.T, kind string, cur, next ed25519.PrivateKey, controller string) *ident {
	t.Helper()
	ev := map[string]any{
		"v": 1, "type": "inception", "kind": kind,
		"keys":          []string{identity.ToMultibase(pub(cur))},
		"nextKeyDigest": identity.KeyDigest(pub(next)),
		"createdAt":     now,
	}
	if controller != "" {
		ev["controller"] = controller
	}
	inc := sign(t, ev, cur)
	did, err := identity.DIDFromInception(inc)
	if err != nil {
		t.Fatal(err)
	}
	return &ident{did: did, cur: cur, next: next, kel: []identity.KelEvent{inc}}
}

func position(t *testing.T, kel []identity.KelEvent) (int, string) {
	t.Helper()
	d, err := identity.EventDigest(kel[len(kel)-1])
	if err != nil {
		t.Fatal(err)
	}
	return len(kel), d
}

func rotate(t *testing.T, id *ident, newNext ed25519.PrivateKey) *ident {
	t.Helper()
	seq, prior := position(t, id.kel)
	ev := sign(t, map[string]any{
		"v": 1, "type": "rotate", "did": id.did, "seq": seq, "prior": prior, "at": now,
		"keys":          []string{identity.ToMultibase(pub(id.next))},
		"nextKeyDigest": identity.KeyDigest(pub(newNext)),
	}, id.next)
	kel := append(append([]identity.KelEvent{}, id.kel...), ev)
	return &ident{did: id.did, cur: id.next, next: newNext, kel: kel}
}

func anchor(t *testing.T, person *ident, sealDID string, sealSeq int, sealDigest string) *ident {
	t.Helper()
	seq, prior := position(t, person.kel)
	ev := sign(t, map[string]any{
		"v": 1, "type": "anchor", "did": person.did, "seq": seq, "prior": prior, "at": now,
		"seals": []map[string]any{{"did": sealDID, "seq": sealSeq, "digest": sealDigest}},
	}, person.cur)
	out := *person
	out.kel = append(append([]identity.KelEvent{}, person.kel...), ev)
	return &out
}

func revokeAgent(t *testing.T, person *ident, agent *ident) (*ident, []identity.KelEvent) {
	t.Helper()
	seq, prior := position(t, agent.kel)
	ev := roundTrip(t, map[string]any{
		"v": 1, "type": "revoke", "did": agent.did, "seq": seq, "prior": prior, "at": now, "auth": "controller",
	})
	d, _ := identity.EventDigest(ev)
	p := anchor(t, person, agent.did, seq, d)
	return p, append(append([]identity.KelEvent{}, agent.kel...), ev)
}

func recoverAgent(t *testing.T, person *ident, agent *ident, newCur, newNext ed25519.PrivateKey) (*ident, []identity.KelEvent) {
	t.Helper()
	seq, prior := position(t, agent.kel)
	ev := roundTrip(t, map[string]any{
		"v": 1, "type": "recover", "did": agent.did, "seq": seq, "prior": prior, "at": now, "auth": "controller",
		"keys":          []string{identity.ToMultibase(pub(newCur))},
		"nextKeyDigest": identity.KeyDigest(pub(newNext)),
	})
	d, _ := identity.EventDigest(ev)
	p := anchor(t, person, agent.did, seq, d)
	return p, append(append([]identity.KelEvent{}, agent.kel...), ev)
}

func code(err error) identity.KelErrorCode {
	var ke *identity.KelError
	if errors.As(err, &ke) {
		return ke.Code
	}
	return ""
}

// ── L0-KEL-01: the fixed-seed vector from the TypeScript conformance suite ──

func TestKel_FixedSeedVector(t *testing.T) {
	id := incept(t, "person", seedKey(1), seedKey(2), "")
	body := map[string]any{}
	for k, v := range id.kel[0] {
		if k != "sig" {
			body[k] = v
		}
	}
	got := string(jcs.MustCanonicalize(body))
	want := `{"createdAt":"2026-10-07T00:00:00.000Z","keys":["zAKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"],` +
		`"kind":"person","nextKeyDigest":"E89dkqqjMw9HTi1pqHbANSNwioHuMhmpTCXapTmfUr1EW","type":"inception","v":1}`
	if got != want {
		t.Fatalf("canonical inception\n got  %s\n want %s", got, want)
	}
	if id.did != "did:aroha:EFLYfS6RfFTTMNdhSybB52jJ4KCTLsNXC4ZuBECvceFKZ" {
		t.Errorf("did = %s", id.did)
	}
	if sig := id.kel[0]["sig"]; sig != "a-jO6pXYXMBFY3nEhbzzz20MlJ81pxy17L42BgphDMw8ogNyKOeLD_Rg5yMhtv22Rf6kt8d4kpW0VWrdt3TjCw" {
		t.Errorf("sig = %v", sig)
	}
	rotated := rotate(t, id, seedKey(3))
	if d, _ := identity.EventDigest(rotated.kel[1]); d != "ED3cVEYDPescYcT6jaD4swqCa3PyGvTDUxhhahnYVFTrr" {
		t.Errorf("rotate digest = %s", d)
	}
	st, err := identity.VerifyKel(id.did, rotated.kel, identity.VerifyKelOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(st.CurrentKey, pub(seedKey(2))) || st.Sequence != 1 {
		t.Errorf("state after rotation: key=%x seq=%d", st.CurrentKey, st.Sequence)
	}
	if keys, _ := identity.KeysAtSequence(st, 0); keys[0] != identity.ToMultibase(pub(seedKey(1))) {
		t.Errorf("KeysAtSequence(0) = %v", keys)
	}
}

func TestKel_ParseKelRoundTrip(t *testing.T) {
	id := rotate(t, incept(t, "person", seedKey(1), seedKey(2), ""), seedKey(3))
	raw, _ := json.Marshal(id.kel)
	parsed, err := identity.ParseKel(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.VerifyKel(id.did, parsed, identity.VerifyKelOptions{}); err != nil {
		t.Fatal(err)
	}
}

// L0-KEL-02
func TestKel_InceptionOnlyVerifies(t *testing.T) {
	id := incept(t, "agent", randKey(t), randKey(t), "")
	st, err := identity.VerifyKel(id.did, id.kel, identity.VerifyKelOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(st.CurrentKey, pub(id.cur)) {
		t.Error("current key mismatch")
	}
}

// L0-KEL-03
func TestKel_RotationMustBeSignedByNextKey(t *testing.T) {
	id := incept(t, "agent", seedKey(4), seedKey(5), "")
	honest := rotate(t, id, randKey(t)).kel[1]
	forged := map[string]any{}
	for k, v := range honest {
		if k != "sig" {
			forged[k] = v
		}
	}
	forged = sign(t, forged, id.cur) // signed by the CURRENT key
	if _, err := identity.VerifyKel(id.did, []identity.KelEvent{id.kel[0], forged}, identity.VerifyKelOptions{}); code(err) != identity.KelInvalid {
		t.Errorf("forged rotation: err = %v", err)
	}
	if _, err := identity.VerifyKel(id.did, []identity.KelEvent{id.kel[0], honest}, identity.VerifyKelOptions{}); err != nil {
		t.Errorf("honest rotation: %v", err)
	}
}

func TestKel_TamperedInceptionRejected(t *testing.T) {
	id := incept(t, "person", randKey(t), randKey(t), "")
	tampered := map[string]any{}
	for k, v := range id.kel[0] {
		tampered[k] = v
	}
	tampered["kind"] = "agent"
	if _, err := identity.VerifyKel(id.did, []identity.KelEvent{tampered}, identity.VerifyKelOptions{}); code(err) != identity.KelInvalid {
		t.Errorf("err = %v", err)
	}
	if _, err := identity.VerifyKel("did:aroha:Echo", id.kel, identity.VerifyKelOptions{}); code(err) != identity.KelInvalid {
		t.Errorf("named DID: err = %v", err)
	}
}

// L0-KEL-04
func TestKel_ControllerEventsNeedSeal(t *testing.T) {
	person := incept(t, "person", randKey(t), randKey(t), "")
	agent := incept(t, "agent", randKey(t), randKey(t), person.did)
	p2, agentKel := revokeAgent(t, person, agent)

	st, err := identity.VerifyKel(agent.did, agentKel, identity.VerifyKelOptions{
		ResolveControllerKel: identity.KelSourceFromLogs(p2.kel),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Revoked || st.CurrentKey != nil {
		t.Error("expected revoked agent")
	}
	if _, err := identity.VerifyKel(agent.did, agentKel, identity.VerifyKelOptions{}); code(err) != identity.KelControllerUnavailable {
		t.Errorf("without controller: err = %v", err)
	}
	// The controller log WITHOUT the anchor: the revoke is unauthorised junk.
	if _, err := identity.VerifyKel(agent.did, agentKel, identity.VerifyKelOptions{
		ResolveControllerKel: identity.KelSourceFromLogs(person.kel),
	}); code(err) != identity.KelInvalid {
		t.Errorf("unanchored revoke: err = %v", err)
	}
	// The agent log WITHOUT the revoke, against a controller that sealed it: stale.
	if _, err := identity.VerifyKel(agent.did, agent.kel, identity.VerifyKelOptions{
		ResolveControllerKel: identity.KelSourceFromLogs(p2.kel),
	}); code(err) != identity.KelStale {
		t.Errorf("stale agent log: err = %v", err)
	}
}

func TestKel_RecoverAndKelKeyResolver(t *testing.T) {
	person := incept(t, "person", randKey(t), randKey(t), "")
	agent := incept(t, "agent", randKey(t), randKey(t), person.did)
	newCur, newNext := randKey(t), randKey(t)
	p2, agentKel := recoverAgent(t, person, agent, newCur, newNext)

	resolve := identity.KelKeyResolver(identity.KelSourceFromLogs(p2.kel, agentKel), identity.ResolveKelStateOptions{RequireController: true})
	if got := resolve(agent.did); !bytes.Equal(got, pub(newCur)) {
		t.Errorf("resolved %x, want recovered key", got)
	}
	if resolve("did:aroha:zFVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z") != nil {
		t.Error("non-E DID must resolve to nil")
	}
	// Person revokes itself with its next key: its agents' keys stop resolving.
	seq, prior := position(t, p2.kel)
	selfRevoke := sign(t, map[string]any{
		"v": 1, "type": "revoke", "did": p2.did, "seq": seq, "prior": prior, "at": now,
		"auth": "next-key", "revealedKey": identity.ToMultibase(pub(p2.next)),
	}, p2.next)
	pRevoked := append(append([]identity.KelEvent{}, p2.kel...), selfRevoke)
	resolve2 := identity.KelKeyResolver(identity.KelSourceFromLogs(pRevoked, agentKel), identity.ResolveKelStateOptions{RequireController: true})
	if resolve2(agent.did) != nil {
		t.Error("agent of a revoked controller must not resolve")
	}
}

func TestKel_AgentSealVsSignature(t *testing.T) {
	person := incept(t, "person", randKey(t), randKey(t), "")
	agent := incept(t, "agent", randKey(t), randKey(t), person.did)
	seq, prior := position(t, agent.kel)
	signedRecover := sign(t, map[string]any{
		"v": 1, "type": "recover", "did": agent.did, "seq": seq, "prior": prior, "at": now, "auth": "controller",
		"keys": []string{identity.ToMultibase(pub(randKey(t)))}, "nextKeyDigest": identity.KeyDigest(pub(randKey(t))),
	}, agent.cur)
	_, err := identity.VerifyKel(agent.did, append(agent.kel, signedRecover), identity.VerifyKelOptions{
		ResolveControllerKel: identity.KelSourceFromLogs(person.kel),
	})
	if code(err) != identity.KelInvalid {
		t.Errorf("a signed recover must be invalid, got %v", err)
	}
}

// L0-KEL-05 / L0-KEL-06
func TestKel_AcceptKelDuplicityAndStale(t *testing.T) {
	id := incept(t, "person", randKey(t), randKey(t), "")
	store := identity.NewInMemoryKelStore()
	if _, err := identity.AcceptKel(id.did, rotate(t, id, randKey(t)).kel, store, identity.AcceptKelOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.AcceptKel(id.did, id.kel, store, identity.AcceptKelOptions{}); code(err) != identity.KelStale {
		t.Errorf("shorter log: err = %v", err)
	}
	if st, err := identity.AcceptKel(id.did, id.kel, store, identity.AcceptKelOptions{UseStored: true}); err != nil || st.Sequence != 1 {
		t.Errorf("use-stored: st=%v err=%v", st, err)
	}
	if _, err := identity.AcceptKel(id.did, rotate(t, id, randKey(t)).kel, store, identity.AcceptKelOptions{}); code(err) != identity.KelDuplicity {
		t.Errorf("fork: err = %v", err)
	}
	if _, err := identity.AcceptKel(id.did, id.kel, store, identity.AcceptKelOptions{UseStored: true}); code(err) != identity.KelDuplicity {
		t.Errorf("after alarm: err = %v", err)
	}
}

func TestKel_IsInceptionDID(t *testing.T) {
	for did, want := range map[string]bool{
		"did:aroha:EFLYfS6RfFTTMNdhSybB52jJ4KCTLsNXC4ZuBECvceFKZ": true,
		"did:aroha:Echo": false,
		"did:aroha:zFVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z": false,
		"did:other:EFLYfS6RfFTTMNdhSybB52jJ4KCTLsNXC4ZuBECvceFKZ": false,
	} {
		if got := identity.IsInceptionDID(did); got != want {
			t.Errorf("%s: got %v", did, got)
		}
	}
}
