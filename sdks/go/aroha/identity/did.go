// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package identity implements Aroha Layer 1 — Decentralized Identity.
//
// Generates DID documents and Ed25519 key pairs conforming to:
//   - W3C DID Core 1.0
//   - Ed25519VerificationKey2020
//   - Multibase base58btc encoding (z prefix)
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"time"
)

// Base58 alphabet (Bitcoin/IPFS alphabet used by multibase btc58).
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// AgentIdentity holds everything a Aroha agent needs to identify itself.
type AgentIdentity struct {
	DID         string
	KeyID       string
	DIDDocument map[string]any
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
}

// Generate creates a new Aroha AgentIdentity.
//
//   - agentID:  unique identifier suffix, e.g. "expedia-flights-v2"
//   - endpoint: HTTPS endpoint of the agent's Aroha service
func Generate(agentID, endpoint string) (*AgentIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	did := "did:aroha:" + agentID
	keyID := did + "#key-1"
	publicKeyMultibase := ToMultibase(pub)
	doc := buildDocument(did, keyID, publicKeyMultibase, endpoint)

	return &AgentIdentity{
		DID:         did,
		KeyID:       keyID,
		DIDDocument: doc,
		PrivateKey:  priv,
		PublicKey:   pub,
	}, nil
}

func buildDocument(did, keyID, publicKeyMultibase, endpoint string) map[string]any {
	return map[string]any{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		"id": did,
		"verificationMethod": []map[string]any{
			{
				"id":                 keyID,
				"type":               "Ed25519VerificationKey2020",
				"controller":         did,
				"publicKeyMultibase": publicKeyMultibase,
			},
		},
		"authentication": []string{keyID},
		"service": []map[string]any{
			{
				"id":              did + "#aroha",
				"type":            "ArohaEndpoint",
				"serviceEndpoint": endpoint,
			},
		},
	}
}

// ExtractPublicKey returns the key that should verify a signature from the
// document's PRIMARY verification method right now. It accepts both documents
// built by Generate and documents decoded from JSON (where arrays are []any).
// See ExtractPublicKeyFor for the rules applied.
func ExtractPublicKey(doc map[string]any) (ed25519.PublicKey, error) {
	return ExtractPublicKeyFor(doc, "", time.Now())
}

// ExtractPublicKeyFor is a port of aroha-core extractPublicKey: the key that
// should verify a signature naming verificationMethodID ("" = the primary
// method) at time now.
//
//   - A key listed in revokedKeys is refused.
//   - For the primary method, while a keyHistory rotation is inside its
//     cool-down (trustAfter in the future, or unparseable), the PREDECESSOR
//     key is returned — unless the latest controllerRecoveries entry
//     installed the current key and is at least as recent as the latest
//     rotation. If that predecessor was revoked, no key is trusted.
//   - Non-primary (device) methods are subject to revocation only.
//
// The document's authenticity is the caller's responsibility.
func ExtractPublicKeyFor(doc map[string]any, verificationMethodID string, now time.Time) (ed25519.PublicKey, error) {
	methods := objectList(doc["verificationMethod"])
	if len(methods) == 0 {
		return nil, fmt.Errorf("DID %v has no verification methods", doc["id"])
	}
	vm, err := selectVerificationMethod(doc, methods, verificationMethodID)
	if err != nil {
		return nil, err
	}
	isPrimary := vm == 0
	mb, _ := methods[vm]["publicKeyMultibase"].(string)
	history := objectList(doc["keyHistory"])

	candidate := mb
	if isPrimary && len(history) > 0 && !controllerInstalled(doc, history, mb) {
		nowMs := now.UnixMilli()
		for _, rotation := range history {
			ta, err := ParseISOTime(stringOf(rotation["trustAfter"]))
			if err == nil && nowMs >= ta.UnixMilli() {
				break // Date NaN compares false, so an unparseable trustAfter keeps walking back
			}
			candidate = stringOf(rotation["predecessorKey"])
		}
		if candidate != mb {
			if r := revokedRecord(doc, candidate); r != nil {
				return nil, fmt.Errorf("DID %v key rotation cool-down active until %v and the predecessor key was revoked at %v (%v) — "+
					"no key is trusted until the cool-down ends or the controller recovers the DID",
					doc["id"], history[0]["trustAfter"], r["revokedAt"], r["reason"])
			}
		}
	}
	if r := revokedRecord(doc, candidate); r != nil {
		short := candidate
		if len(short) > 12 {
			short = short[:12]
		}
		return nil, fmt.Errorf("DID %v key %s... was revoked at %v: %v", doc["id"], short, r["revokedAt"], r["reason"])
	}
	key, err := FromMultibase(candidate)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("verificationMethod key is %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	return key, nil
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

// selectVerificationMethod returns the index of the method a proof names
// (port of selectVerificationMethod).
func selectVerificationMethod(doc map[string]any, methods []map[string]any, vmID string) (int, error) {
	if vmID == "" {
		return 0, nil
	}
	id := stringOf(doc["id"])
	absolute := vmID
	if strings.HasPrefix(vmID, "#") {
		absolute = id + vmID
	}
	for i, m := range methods {
		mid := stringOf(m["id"])
		if mid == absolute || (strings.HasPrefix(mid, "#") && id+mid == absolute) {
			return i, nil
		}
	}
	if absolute == id+"#key-1" {
		return 0, nil
	}
	return 0, fmt.Errorf("DID %s has no verification method %s", id, vmID)
}

func revokedRecord(doc map[string]any, keyMultibase string) map[string]any {
	for _, r := range objectList(doc["revokedKeys"]) {
		if stringOf(r["keyMultibase"]) == keyMultibase {
			return r
		}
	}
	return nil
}

// controllerInstalled: the latest controller recovery installed exactly
// keyMultibase and is at least as recent as the latest rotation.
func controllerInstalled(doc map[string]any, history []map[string]any, keyMultibase string) bool {
	recs := objectList(doc["controllerRecoveries"])
	if len(recs) == 0 || stringOf(recs[0]["newKeyMultibase"]) != keyMultibase {
		return false
	}
	if len(history) == 0 {
		return true
	}
	rec, e1 := ParseISOTime(stringOf(recs[0]["recoveredAt"]))
	rot, e2 := ParseISOTime(stringOf(history[0]["rotatedAt"]))
	return e1 == nil && e2 == nil && rec.UnixMilli() >= rot.UnixMilli()
}

// ExtractEndpoint extracts the Aroha service endpoint from a DID Document:
// the first service of type ArohaEndpoint.
func ExtractEndpoint(doc map[string]any) (string, error) {
	for _, svc := range objectList(doc["service"]) {
		if t, _ := svc["type"].(string); t == "ArohaEndpoint" {
			ep, _ := svc["serviceEndpoint"].(string)
			return ep, nil
		}
	}
	return "", fmt.Errorf("no ArohaEndpoint service in DID Document")
}

func objectList(v any) []map[string]any {
	switch x := v.(type) {
	case []map[string]any:
		return x
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// DIDPrefix is the method prefix shared by every did:aroha: form.
const DIDPrefix = "did:aroha:"

// DIDFromPublicKey returns the content-addressed DID for an Ed25519 public
// key: did:aroha:z<base58btc(publicKey)>. Matches @aroha-sdk/core generateDid.
func DIDFromPublicKey(publicKey []byte) string {
	return DIDPrefix + ToMultibase(publicKey)
}

// ResolveContentAddressedKey returns the public key a content-addressed DID
// (did:aroha:z<base58btc(32-byte key)>) commits to, or nil for any other DID.
// The DID IS the key, so nothing outside the string can influence the answer.
// The re-encode check keeps a named DID that merely starts with "z" and uses
// only base58 letters (e.g. did:aroha:zoo) from decoding to a garbage key.
func ResolveContentAddressedKey(did string) ed25519.PublicKey {
	if !strings.HasPrefix(did, DIDPrefix+"z") {
		return nil
	}
	key, err := FromMultibase(did[len(DIDPrefix):])
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil
	}
	if DIDFromPublicKey(key) != did {
		return nil
	}
	return key
}

// IsContentAddressedDID reports whether did is the self-certifying
// did:aroha:z<base58btc(32-byte key)> form.
func IsContentAddressedDID(did string) bool {
	if !strings.HasPrefix(did, DIDPrefix) {
		return false
	}
	suffix := did[len(DIDPrefix):]
	if !strings.HasPrefix(suffix, "z") || strings.ContainsAny(suffix, ".:") {
		return false
	}
	key, err := FromMultibase(suffix)
	return err == nil && len(key) == 32
}

// ── Multibase (base58btc) ─────────────────────────────────────────────────────

// ToMultibase encodes raw bytes as multibase base58btc (z prefix).
func ToMultibase(b []byte) string {
	return "z" + encodeBase58(b)
}

// FromMultibase decodes a multibase base58btc string (z prefix) to raw bytes.
func FromMultibase(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "z") {
		return nil, fmt.Errorf("only base58btc (z-prefix) multibase is supported")
	}
	return decodeBase58(s[1:])
}

func encodeBase58(input []byte) string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	// Little-endian base-58 digits of the big-endian number in input[zeros:].
	digits := make([]byte, 0, len(input)*138/100+1)
	for _, b := range input[zeros:] {
		carry := int(b)
		for i := range digits {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	var sb strings.Builder
	sb.Grow(zeros + len(digits))
	for i := 0; i < zeros; i++ {
		sb.WriteByte('1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		sb.WriteByte(base58Alphabet[digits[i]])
	}
	return sb.String()
}

// decodeBase58 is the textbook algorithm, matching @aroha-sdk/core: each
// leading '1' is one leading zero byte, and the rest is a big-endian base-58
// number emitted in exactly as many bytes as it needs. It round-trips every
// byte string encodeBase58 produces.
func decodeBase58(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	// Little-endian base-256 bytes of the number.
	var num []byte
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(base58Alphabet, s[i])
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character: %q", s[i])
		}
		carry := idx
		for j := range num {
			carry += int(num[j]) * 58
			num[j] = byte(carry & 0xFF)
			carry >>= 8
		}
		for carry > 0 {
			num = append(num, byte(carry&0xFF))
			carry >>= 8
		}
	}
	out := make([]byte, zeros+len(num))
	for i, b := range num {
		out[len(out)-1-i] = b
	}
	return out, nil
}
