// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package messages_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
)

func TestDisclosure_Validate(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{"v": 1.0, "agentDid": "did:aroha:a", "principalDid": "did:aroha:p",
			"principalKind": "person", "purpose": "assistant", "hop": 0.0, "aiGenerated": true}
	}
	if _, err := messages.ValidateDisclosure(good(), "did:aroha:a"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mod  func(map[string]any)
		want string
	}{
		"version":       {func(d map[string]any) { d["v"] = 2.0 }, "unsupported disclosure version 2"},
		"empty purpose": {func(d map[string]any) { d["purpose"] = "" }, "purpose must be a non-empty string"},
		"not a DID":     {func(d map[string]any) { d["principalDid"] = "alice" }, "must be DIDs"},
		"long purpose":  {func(d map[string]any) { d["purpose"] = strings.Repeat("x", 513) }, "purpose exceeds 512"},
		"kind":          {func(d map[string]any) { d["principalKind"] = "robot" }, "principalKind"},
		"hop":           {func(d map[string]any) { d["hop"] = 1.5 }, "hop must be a non-negative integer"},
		"ai":            {func(d map[string]any) { d["aiGenerated"] = false }, "aiGenerated must be true"},
		"unknown":       {func(d map[string]any) { d["extra"] = 1.0 }, `unknown field "extra"`},
		"other agent":   {func(d map[string]any) { d["agentDid"] = "did:aroha:b" }, "not the sender did:aroha:a"},
	}
	for name, c := range cases {
		d := good()
		c.mod(d)
		if _, err := messages.ValidateDisclosure(d, "did:aroha:a"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

func TestDisclosure_EnvelopeRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	from := identity.DIDFromPublicKey(pub)
	d, err := messages.BuildDisclosure(messages.DisclosureInput{AgentDID: from, PrincipalDID: "did:aroha:person",
		PrincipalKind: messages.PrincipalPerson, Purpose: "books tables"})
	if err != nil {
		t.Fatal(err)
	}
	env, err := messages.BuildWithOptions("ArohaRequest", from, "did:aroha:to", nil, "c", priv, messages.BuildOptions{Disclosure: d})
	if err != nil {
		t.Fatal(err)
	}
	if err := messages.Validate(wire(t, env), pub, "did:aroha:to", messages.NewNonceRegistry()); err != nil {
		t.Fatal(err)
	}
	d.AgentDID = "did:aroha:someone-else"
	if _, err := messages.BuildWithOptions("ArohaRequest", from, "did:aroha:to", nil, "c", priv, messages.BuildOptions{Disclosure: d}); err == nil {
		t.Fatal("built an envelope disclosing in another agent's name")
	}
}
