// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package crypto_test

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/crypto"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
)

// The TypeScript envelope canonical form is JSON.stringify(sortKeysDeep(v)):
// integer-like keys first, numerically. The expected bytes are what the
// Python SDK's canonicalize_message produces (itself checked live against
// @aroha-sdk/core in sdks/aroha-py/tests/test_cross_language.py); the Java
// SDK pins the same string.
const intKeyMessage = `{"type":"ArohaRequest","body":{"params":{"10":"ten","9":"nine","2":"two","01":"zero-one","b":1,"a":[{"3":1,"x":2}],"4294967295":"max"}},"proof":{"x":1}}`
const intKeyCanonical = `{"body":{"params":{"2":"two","9":"nine","10":"ten","01":"zero-one","4294967295":"max","a":[{"3":1,"x":2}],"b":1}},"type":"ArohaRequest"}`

func TestCanonicalize_IntegerLikeKeysFollowJavaScriptOrder(t *testing.T) {
	var msg map[string]any
	if err := json.Unmarshal([]byte(intKeyMessage), &msg); err != nil {
		t.Fatal(err)
	}
	delete(msg, "proof")
	got, err := crypto.Canonicalize(msg)
	if err != nil || string(got) != intKeyCanonical {
		t.Fatalf("got %s %v", got, err)
	}
	// JCS proper (mandates, KELs) keeps plain UTF-16 order.
	if j, _ := jcs.Canonicalize(map[string]any{"10": 1, "9": 2}); string(j) != `{"10":1,"9":2}` {
		t.Fatalf("JCS changed: %s", j)
	}
	// Sign/verify round trip over the new bytes.
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := crypto.SignMessage(msg, priv, "did:aroha:x#key-1"); err != nil {
		t.Fatal(err)
	}
	if ok, err := crypto.VerifyMessageSignature(msg, pub); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	for k, want := range map[string]bool{"0": true, "10": true, "4294967294": true, "4294967295": false, "01": false, "-1": false, "1.5": false, "": false} {
		if jcs.IsArrayIndex(k) != want {
			t.Errorf("IsArrayIndex(%q) != %v", k, want)
		}
	}
}
