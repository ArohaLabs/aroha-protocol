// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package crypto_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/crypto"
)

// Produced by aroha-core encryptBody (TypeScript, @noble/curves 1.9.7) for a
// recipient whose Ed25519 seed is 32 bytes of 0x09. The Python SDK carries
// the same vector (sdks/aroha-py/tests/test_encryption.py).
var tsEncrypted = map[string]any{
	"alg":        "ECDH-ES+A256GCM",
	"epk":        "ESD8db8bcWQ5_DcFzwqysk_v-SZyCXaZviTNmYdcW20",
	"iv":         "ZZ40t9ssVRW__bVe",
	"ciphertext": "3nnruPHitEvAbmbgl1GCSpIrPYtWXlq_Mhn3tTkID-gtFliNP2c18XVGDgdvKb8GVJuDmXkHJWwqdSLYXu_pOtGTIgDeuA",
	"tag":        "EC7kYlJ2VIwUA0SGHBj0Bg",
}

func seed9() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)) }

func TestEncryption_TypeScriptVectorDecrypts(t *testing.T) {
	priv := seed9()
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618" {
		t.Fatalf("seed mismatch: %s", got)
	}
	out, err := crypto.DecryptBodyWithEd25519(tsEncrypted, priv)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"amount": 10.5, "note": "héllo 😀",
		"nested": map[string]any{"2": true, "10": []any{1.0, 2.25}}}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %#v", out)
	}
}

func TestEncryption_Ed25519ConversionAgrees(t *testing.T) {
	for _, s := range [][]byte{bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{255}, 32), make([]byte, 32)} {
		priv := ed25519.NewKeyFromSeed(s)
		xpriv, err := crypto.Ed25519PrivateKeyToX25519(priv)
		if err != nil {
			t.Fatal(err)
		}
		xpub, err := crypto.Ed25519PublicKeyToX25519(priv.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		if !xpriv.PublicKey().Equal(xpub) {
			t.Fatalf("conversion mismatch for seed %x", s)
		}
	}
}

func TestEncryption_Ed25519RoundTrip(t *testing.T) {
	priv := seed9()
	enc, err := crypto.EncryptBodyForEd25519(map[string]any{"k": "v"}, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != 5 || enc["alg"] != "ECDH-ES+A256GCM" {
		t.Fatalf("wire shape: %v", enc)
	}
	out, err := crypto.DecryptBodyWithEd25519(enc, priv)
	if err != nil || out["k"] != "v" {
		t.Fatalf("%v %v", out, err)
	}
	enc["alg"] = "A256GCM"
	if _, err := crypto.DecryptBodyWithEd25519(enc, priv); err == nil {
		t.Fatal("unsupported alg accepted")
	}
}
