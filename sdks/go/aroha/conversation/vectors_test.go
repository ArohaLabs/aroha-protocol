// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package conversation_test

// spec-public/vectors/conversation-v1.json — the file the TypeScript
// reference generated and the Python verifiers also consume: every signing
// payload byte for byte, every valid object accepted, every invalid one
// refused.

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/conversation"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/crypto"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/receipts"
)

type vectors struct {
	raw map[string]any
}

func load(t *testing.T) *vectors {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "spec-public", "vectors", "conversation-v1.json")
	if env := os.Getenv("AROHA_CONVERSATION_VECTORS"); env != "" {
		path = env
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("conversation vectors not available: %v", err)
	}
	v, err := jcs.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return &vectors{raw: v.(map[string]any)}
}

func (v *vectors) get(path ...string) any {
	var cur any = v.raw
	for _, p := range path {
		cur = cur.(map[string]any)[p]
	}
	return cur
}

func (v *vectors) str(path ...string) string { return v.get(path...).(string) }

func (v *vectors) invalid(path ...string) []map[string]any {
	var out []map[string]any
	for _, e := range v.get(path...).([]any) {
		out = append(out, e.(map[string]any))
	}
	return out
}

func (v *vectors) resolver() conversation.KeyResolver {
	logs := map[string][]identity.KelEvent{}
	for did, evs := range v.get("kels").(map[string]any) {
		for _, e := range evs.([]any) {
			logs[did] = append(logs[did], e.(map[string]any))
		}
	}
	source := func(did string) ([]identity.KelEvent, error) { return logs[did], nil }
	return conversation.WithContentAddressedAgents(conversation.KelResolver(source))
}

func (v *vectors) room(t *testing.T) *conversation.Room {
	t.Helper()
	r, err := conversation.VerifyRoom(v.get("room", "value"), v.resolver())
	if err != nil {
		t.Fatal(err)
	}
	return &r.Value
}

func TestVectors_Disclosure(t *testing.T) {
	v := load(t)
	d, err := messages.ValidateDisclosure(v.get("disclosure", "value"), "")
	if err != nil {
		t.Fatal(err)
	}
	if !d.AIGenerated || d.PrincipalKind != messages.PrincipalPerson {
		t.Fatalf("%+v", d)
	}
}

func TestVectors_Room(t *testing.T) {
	v := load(t)
	got, err := conversation.SigningBytes(v.get("room", "value"))
	if err != nil || string(got) != v.str("room", "expectedSigningPayload") {
		t.Fatalf("signing payload differs (%v)\n got %s", err, got)
	}
	r, err := conversation.VerifyRoom(v.get("room", "value"), v.resolver())
	if err != nil {
		t.Fatal(err)
	}
	if r.Signer.Kind != conversation.KindPerson || r.Value.Epoch != 2 || len(r.Value.Members) != 3 {
		t.Fatalf("verified room: %+v", r)
	}
	for _, bad := range v.invalid("room", "invalid") {
		if _, err := conversation.VerifyRoom(bad["value"], v.resolver()); err == nil {
			t.Errorf("%s: accepted", bad["name"])
		} else {
			t.Logf("%s: %v", bad["name"], err)
		}
	}
}

func TestVectors_Consent(t *testing.T) {
	v := load(t)
	room := v.room(t)
	for _, k := range []string{"given", "withdrawn"} {
		c := v.get("consent", k, "value")
		for i, want := range v.get("consent", k, "expectedEventSigningPayloads").([]any) {
			got, err := conversation.ConsentEventSigningBytes(c, i)
			if err != nil || string(got) != want.(string) {
				t.Fatalf("%s event %d payload differs (%v)\n got %s\nwant %s", k, i, err, got, want)
			}
		}
		r, err := conversation.VerifyConsent(c, v.resolver(), room)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		var got []string
		for p := range conversation.EffectiveConsent(&r.Value) {
			got = append(got, p)
		}
		sort.Strings(got)
		var want []string
		for _, p := range v.get("consent", k, "effectivePurposes").([]any) {
			want = append(want, p.(string))
		}
		if len(got) != len(want) {
			t.Fatalf("%s: effective %v, want %v", k, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: effective %v, want %v", k, got, want)
			}
		}
	}
	// A non-subject (withdrawal) event cannot be checked without the room.
	if _, err := conversation.VerifyConsent(v.get("consent", "withdrawn", "value"), v.resolver(), nil); err == nil {
		t.Fatal("withdrawal by a member accepted without the room record")
	}
	for _, bad := range v.invalid("consent", "invalid") {
		if _, err := conversation.VerifyConsent(bad["value"], v.resolver(), room); err == nil {
			t.Errorf("%s: accepted", bad["name"])
		} else {
			t.Logf("%s: %v", bad["name"], err)
		}
	}
}

func TestVectors_TurnAndSpeakerKind(t *testing.T) {
	v := load(t)
	room := v.room(t)
	turn := v.get("turn", "value")
	if h := conversation.TurnContentHash(v.str("turn", "value", "content")); h != v.str("turn", "expectedContentHash") {
		t.Fatalf("content hash %s", h)
	}
	got, err := conversation.TurnSigningBytes(turn)
	if err != nil || string(got) != v.str("turn", "expectedSigningPayload") {
		t.Fatalf("turn payload differs (%v)\n got %s", err, got)
	}
	r, err := conversation.VerifyTurn(turn, v.resolver(), room)
	if err != nil {
		t.Fatal(err)
	}
	if r.Signer.Kind != v.str("turn", "expectedSpeakerKind") {
		t.Fatalf("speaker kind %s", r.Signer.Kind)
	}
	for _, bad := range v.invalid("turn", "invalid") {
		if _, err := conversation.VerifyTurn(bad["value"], v.resolver(), room); err == nil {
			t.Errorf("%s: accepted", bad["name"])
		} else {
			t.Logf("%s: %v", bad["name"], err)
		}
	}
}

func receiptKey(did string) (ed25519.PublicKey, error) {
	return identity.ResolveContentAddressedKey(did), nil
}

func TestVectors_Receipts(t *testing.T) {
	v := load(t)
	for _, k := range []string{"v1", "v2Executed", "v2Denied"} {
		got, err := receipts.SigningBytes(v.get("receipts", k, "value"))
		if err != nil || string(got) != v.str("receipts", k, "expectedSigningPayload") {
			t.Fatalf("%s payload differs (%v)", k, err)
		}
		if _, err := receipts.Verify(v.get("receipts", k, "value"), receiptKey); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	r, _ := receipts.Verify(v.get("receipts", "v2Executed", "value"), receiptKey)
	if h, _ := receipts.HashPresentedContent(v.get("receipts", "v2Executed", "presentedContent")); h != v.str("receipts", "v2Executed", "expectedPresentedHash") {
		t.Fatalf("presented hash %s", h)
	}
	if p := receipts.VerifyPresentedHash(r, v.get("receipts", "v2Executed", "presentedContent")); p != "" {
		t.Fatal(p)
	}
	if p := receipts.VerifyPresentedHash(r, v.get("receipts", "v2Executed", "mismatchedPresentedContent")); p == "" {
		t.Fatal("mismatched presented content accepted")
	}
	for _, bad := range v.invalid("receipts", "invalid") {
		if _, err := receipts.Verify(bad["value"], receiptKey); err == nil {
			t.Errorf("%s: accepted", bad["name"])
		}
	}
}

func TestVectors_EnvelopeWithDisclosure(t *testing.T) {
	v := load(t)
	env := v.get("envelopeWithDisclosure", "value").(map[string]any)
	unsigned := map[string]any{}
	for k, x := range env {
		if k != "proof" {
			unsigned[k] = x
		}
	}
	got, err := crypto.Canonicalize(unsigned)
	if err != nil || string(got) != v.str("envelopeWithDisclosure", "expectedSigningPayload") {
		t.Fatalf("envelope payload differs (%v)\n got %s", err, got)
	}
	from := env["from"].(string)
	created, _ := time.Parse(time.RFC3339Nano, env["created"].(string))
	err = messages.Validate(env, identity.ResolveContentAddressedKey(from), env["to"].(string), messages.NewNonceRegistry(),
		messages.ValidateOptions{Now: created.Add(time.Second)})
	if err != nil {
		t.Fatalf("disclosure-bearing envelope rejected: %v", err)
	}

	// A disclosure in another agent's name is refused even though the
	// envelope signature (which covers it) verifies.
	other := map[string]any{}
	for k, x := range env {
		other[k] = x
	}
	d := map[string]any{}
	for k, x := range env["disclosure"].(map[string]any) {
		d[k] = x
	}
	d["agentDid"] = "did:aroha:zSomeoneElse"
	other["disclosure"] = d
	if err := messages.Validate(other, identity.ResolveContentAddressedKey(from), env["to"].(string), messages.NewNonceRegistry(),
		messages.ValidateOptions{Now: created.Add(time.Second)}); err == nil {
		t.Fatal("disclosure naming another agent accepted")
	}
}
