// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// EncryptBody encrypts a JSON-serializable body map using ECDH-ES + AES-256-GCM.
//
// Returns a map with fields: alg, epk, iv, ciphertext, tag.
// The recipient's X25519 public key is used for key agreement.
func EncryptBody(plaintext map[string]any, recipientPub *ecdh.PublicKey) (map[string]any, error) {
	// Generate ephemeral X25519 key pair
	curve := ecdh.X25519()
	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// ECDH key agreement
	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive 256-bit AES key via SHA-256
	h := sha256.Sum256(sharedSecret)
	aesKey := h[:]

	// Marshal plaintext
	plaintextBytes, err := json.Marshal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("marshal plaintext: %w", err)
	}

	// AES-256-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}
	iv := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generate IV: %w", err)
	}
	// Seal appends the GCM tag to ciphertext
	ciphertextWithTag := gcm.Seal(nil, iv, plaintextBytes, nil)
	tagOffset := len(ciphertextWithTag) - gcm.Overhead()
	ciphertext := ciphertextWithTag[:tagOffset]
	tag := ciphertextWithTag[tagOffset:]

	b64 := base64.RawURLEncoding
	return map[string]any{
		"alg":        "ECDH-ES+A256GCM",
		"epk":        b64.EncodeToString(ephemeralPriv.PublicKey().Bytes()),
		"iv":         b64.EncodeToString(iv),
		"ciphertext": b64.EncodeToString(ciphertext),
		"tag":        b64.EncodeToString(tag),
	}, nil
}

// DecryptBody decrypts an encrypted body map produced by EncryptBody.
func DecryptBody(encrypted map[string]any, recipientPriv *ecdh.PrivateKey) (map[string]any, error) {
	b64 := base64.RawURLEncoding
	if alg, _ := encrypted["alg"].(string); alg != "ECDH-ES+A256GCM" {
		return nil, fmt.Errorf("unsupported encrypted body alg %q; expected ECDH-ES+A256GCM", alg)
	}

	decode := func(key string) ([]byte, error) {
		s, _ := encrypted[key].(string)
		if s == "" {
			return nil, fmt.Errorf("missing field: %s", key)
		}
		return b64.DecodeString(s)
	}

	epkBytes, err := decode("epk")
	if err != nil {
		return nil, err
	}
	iv, err := decode("iv")
	if err != nil {
		return nil, err
	}
	ciphertext, err := decode("ciphertext")
	if err != nil {
		return nil, err
	}
	tag, err := decode("tag")
	if err != nil {
		return nil, err
	}

	// Reconstruct ephemeral public key
	curve := ecdh.X25519()
	epk, err := curve.NewPublicKey(epkBytes)
	if err != nil {
		return nil, fmt.Errorf("parse EPK: %w", err)
	}

	// ECDH key agreement
	sharedSecret, err := recipientPriv.ECDH(epk)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive AES key
	h := sha256.Sum256(sharedSecret)
	aesKey := h[:]

	// AES-256-GCM decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new GCM: %w", err)
	}

	// Reassemble ciphertext + tag
	ciphertextWithTag := append(ciphertext, tag...)
	plaintextBytes, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM decrypt: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(plaintextBytes, &result); err != nil {
		return nil, fmt.Errorf("unmarshal plaintext: %w", err)
	}
	return result, nil
}
