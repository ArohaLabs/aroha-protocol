// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package identity_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
)

func TestMultibase_RoundTripAndLeadingZeros(t *testing.T) {
	cases := [][]byte{
		{}, {0}, {0, 0}, {0, 0, 1}, {1}, {0xff, 0xff}, bytes.Repeat([]byte{0}, 32),
		append([]byte{0}, bytes.Repeat([]byte{0xab}, 31)...),
	}
	for _, c := range cases {
		mb := identity.ToMultibase(c)
		got, err := identity.FromMultibase(mb)
		if err != nil || !bytes.Equal(got, c) {
			t.Errorf("%x -> %s -> %x (%v)", c, mb, got, err)
		}
	}
	if mb := identity.ToMultibase([]byte{0, 0}); mb != "z11" {
		t.Errorf("two zero bytes encode as %s, want z11", mb)
	}
	if _, err := identity.FromMultibase("z0OIl"); err == nil {
		t.Error("expected an error for non-base58 characters")
	}
	if _, err := identity.FromMultibase("f00"); err == nil {
		t.Error("expected an error for a non-z multibase prefix")
	}
}

// Keys and DIDs from packages/aroha-credentials/test-vectors/mandate-v2.json
// (RFC 8032 section 7.1 test keys).
func TestContentAddressedDID(t *testing.T) {
	pub, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	const did = "did:aroha:zFVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z"
	if got := identity.DIDFromPublicKey(pub); got != did {
		t.Errorf("DIDFromPublicKey = %s", got)
	}
	if got := identity.ResolveContentAddressedKey(did); !bytes.Equal(got, pub) {
		t.Errorf("ResolveContentAddressedKey = %x", got)
	}
	if !identity.IsContentAddressedDID(did) {
		t.Error("IsContentAddressedDID = false")
	}
	for _, named := range []string{"did:aroha:zoo", "did:aroha:zebra", "did:aroha:my-agent", "did:web:x"} {
		if identity.ResolveContentAddressedKey(named) != nil || identity.IsContentAddressedDID(named) {
			t.Errorf("%s must not resolve as content-addressed", named)
		}
	}
}

func TestGenerateAndExtract(t *testing.T) {
	id, err := identity.Generate("test-agent", "https://agent.example")
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.ExtractPublicKey(id.DIDDocument)
	if err != nil || !bytes.Equal(key, id.PublicKey) {
		t.Fatalf("ExtractPublicKey: %x %v", key, err)
	}
	// The same document after a JSON round-trip (arrays become []any).
	raw, _ := json.Marshal(id.DIDDocument)
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	key, err = identity.ExtractPublicKey(decoded)
	if err != nil || !bytes.Equal(key, id.PublicKey) {
		t.Fatalf("ExtractPublicKey(decoded): %x %v", key, err)
	}
	ep, err := identity.ExtractEndpoint(decoded)
	if err != nil || ep != "https://agent.example" {
		t.Fatalf("ExtractEndpoint: %q %v", ep, err)
	}
}
