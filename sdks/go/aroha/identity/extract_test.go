// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
)

func keyPair(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// rotatedDoc: primary key `cur` rotated from `old`, trustAfter = t0 + 24h.
func rotatedDoc(old, cur, device ed25519.PublicKey, t0 time.Time) map[string]any {
	return map[string]any{
		"id": "did:aroha:named",
		"verificationMethod": []any{
			map[string]any{"id": "did:aroha:named#key-1", "publicKeyMultibase": identity.ToMultibase(cur)},
			map[string]any{"id": "#key-2", "publicKeyMultibase": identity.ToMultibase(device)},
		},
		"keyHistory": []any{map[string]any{
			"rotatedAt":      t0.UTC().Format(time.RFC3339),
			"trustAfter":     t0.Add(24 * time.Hour).UTC().Format(time.RFC3339),
			"predecessorKey": identity.ToMultibase(old),
		}},
	}
}

func TestExtractPublicKeyFor_CoolDownRevocationAndRecovery(t *testing.T) {
	old, cur, device := keyPair(t), keyPair(t), keyPair(t)
	t0 := time.Now()
	doc := rotatedDoc(old, cur, device, t0)

	got, err := identity.ExtractPublicKeyFor(doc, "", t0.Add(time.Hour))
	if err != nil || !bytes.Equal(got, old) {
		t.Fatalf("during cool-down want predecessor: %v", err)
	}
	if got, _ := identity.ExtractPublicKeyFor(doc, "#key-1", t0.Add(25*time.Hour)); !bytes.Equal(got, cur) {
		t.Fatal("after cool-down want current")
	}
	if got, _ := identity.ExtractPublicKeyFor(doc, "did:aroha:named#key-2", t0.Add(time.Hour)); !bytes.Equal(got, device) {
		t.Fatal("device keys are not subject to rotation cool-down")
	}
	if _, err := identity.ExtractPublicKeyFor(doc, "#key-9", t0); err == nil {
		t.Fatal("unknown method accepted")
	}

	// Controller recovery that installed the current key, after the rotation.
	doc["controllerRecoveries"] = []any{map[string]any{
		"newKeyMultibase": identity.ToMultibase(cur), "recoveredAt": t0.Add(time.Minute).UTC().Format(time.RFC3339),
	}}
	if got, _ := identity.ExtractPublicKeyFor(doc, "", t0.Add(time.Hour)); !bytes.Equal(got, cur) {
		t.Fatal("controller-installed key should skip the cool-down")
	}
	delete(doc, "controllerRecoveries")

	// Revoked predecessor during cool-down: nothing trusted.
	doc["revokedKeys"] = []any{map[string]any{"keyMultibase": identity.ToMultibase(old), "revokedAt": "2026-01-01T00:00:00Z", "reason": "lost"}}
	if _, err := identity.ExtractPublicKeyFor(doc, "", t0.Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "no key is trusted") {
		t.Fatalf("revoked predecessor: %v", err)
	}
	// Revoked current key after cool-down; revoked device key.
	doc["revokedKeys"] = []any{
		map[string]any{"keyMultibase": identity.ToMultibase(cur), "revokedAt": "2026-01-01T00:00:00Z", "reason": "lost"},
		map[string]any{"keyMultibase": identity.ToMultibase(device), "revokedAt": "2026-01-01T00:00:00Z", "reason": "lost"},
	}
	if _, err := identity.ExtractPublicKeyFor(doc, "", t0.Add(25*time.Hour)); err == nil || !strings.Contains(err.Error(), "was revoked") {
		t.Fatalf("revoked current: %v", err)
	}
	if _, err := identity.ExtractPublicKeyFor(doc, "#key-2", t0); err == nil {
		t.Fatal("revoked device key accepted")
	}
	// ExtractPublicKey applies the same rules to the primary key.
	delete(doc, "keyHistory")
	if _, err := identity.ExtractPublicKey(doc); err == nil {
		t.Fatal("ExtractPublicKey ignored revocation")
	}
}
