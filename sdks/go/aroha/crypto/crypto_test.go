// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package crypto_test

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/crypto"
)

// Bytes JavaScript produces for JSON.stringify(sortKeysDeep(msg)): sorted
// keys, no HTML escaping, ECMAScript numbers.
func TestCanonicalize_MatchesJavaScript(t *testing.T) {
	msg := map[string]any{
		"z": "<a href='x'>&</a> ",
		"a": []any{1e21, 1e-7, 0.1, 100.0, -0.0},
		"m": map[string]any{"b": true, "a": nil},
	}
	got, err := crypto.Canonicalize(msg)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":[1e+21,1e-7,0.1,100,0],\"m\":{\"a\":null,\"b\":true},\"z\":\"<a href='x'>&</a> \"}"
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := map[string]any{"type": "ArohaRequest", "body": map[string]any{"q": "<&>"}}
	if err := crypto.SignMessage(msg, priv, "did:aroha:a#key-1"); err != nil {
		t.Fatal(err)
	}
	// After a JSON round-trip (what a receiver sees).
	raw, _ := json.Marshal(msg)
	var received map[string]any
	_ = json.Unmarshal(raw, &received)
	ok, err := crypto.VerifyMessageSignature(received, pub)
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	received["body"] = map[string]any{"q": "changed"}
	if ok, _ := crypto.VerifyMessageSignature(received, pub); ok {
		t.Fatal("tampered message verified")
	}
	if ok, _ := crypto.VerifyMessageSignature(received, pub[:5]); ok {
		t.Fatal("short key verified")
	}
	delete(received, "proof")
	if _, err := crypto.VerifyMessageSignature(received, pub); err == nil {
		t.Fatal("missing proof not reported")
	}
}

func TestEncryptDecryptBody(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"card": "4111", "amount": 42.5}
	enc, err := crypto.EncryptBody(body, priv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	dec, err := crypto.DecryptBody(enc, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dec, body) {
		t.Errorf("got %v", dec)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := crypto.DecryptBody(enc, other); err == nil {
		t.Error("decrypted with the wrong key")
	}
}
