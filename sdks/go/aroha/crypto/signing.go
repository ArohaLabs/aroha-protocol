// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package crypto implements Aroha Layer 1/3 cryptographic primitives.
//
// Signing: Ed25519 sign / verify over canonical JSON.
// Encryption: ECDH-ES + AES-256-GCM for sensitive body fields (see encryption.go).
package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
)

// Proof is the Aroha Ed25519Signature2020 proof block.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// SignMessage adds an Ed25519Signature2020 proof to the given message map.
//
// The proof covers the canonical form (see Canonicalize) of the message with
// the "proof" field excluded.
func SignMessage(message map[string]any, privateKey ed25519.PrivateKey, verificationMethodID string) error {
	delete(message, "proof")

	canonical, err := Canonicalize(message)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}

	sig := ed25519.Sign(privateKey, canonical)
	proofValue := base64.RawURLEncoding.EncodeToString(sig)

	message["proof"] = map[string]any{
		"created":            time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"proofPurpose":       "authentication",
		"proofValue":         proofValue,
		"type":               "Ed25519Signature2020",
		"verificationMethod": verificationMethodID,
	}
	return nil
}

// VerifyMessageSignature verifies the Ed25519Signature2020 proof on a message map.
func VerifyMessageSignature(message map[string]any, publicKey ed25519.PublicKey) (bool, error) {
	proofRaw, ok := message["proof"]
	if !ok {
		return false, fmt.Errorf("no proof in message")
	}

	// Extract proof fields
	proofMap, ok := proofRaw.(map[string]any)
	if !ok {
		return false, fmt.Errorf("proof is not a map")
	}
	proofValue, _ := proofMap["proofValue"].(string)
	if proofValue == "" {
		return false, fmt.Errorf("missing proofValue")
	}

	// Canonicalize without proof
	withoutProof := make(map[string]any, len(message))
	for k, v := range message {
		if k != "proof" {
			withoutProof[k] = v
		}
	}
	canonical, err := Canonicalize(withoutProof)
	if err != nil {
		return false, fmt.Errorf("canonicalize: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(proofValue, "="))
	if err != nil {
		return false, fmt.Errorf("decode proofValue: %w", err)
	}
	if len(sig) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return false, nil
	}

	return ed25519.Verify(publicKey, canonical, sig), nil
}

// Canonicalize returns the canonical bytes Aroha envelope signatures
// cover: a byte-exact port of the TypeScript JSON.stringify(sortKeysDeep(v))
// (see jcs.StringifySorted). It differs from RFC 8785 JCS only in key order —
// integer-like ("array index") keys come first in numeric order, as
// JavaScript enumerates them — so a body such as {"10":1,"9":2} signs the
// same bytes in every SDK. encoding/json is NOT used for the output: it
// escapes <, >, &, U+2028 and U+2029, which JavaScript does not.
func Canonicalize(v any) ([]byte, error) {
	return jcs.StringifySorted(v)
}
