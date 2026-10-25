// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// The TypeScript SDK (aroha-core encryptBody / decryptBody) takes the
// recipient's Ed25519 keys and converts them to X25519 the way
// @noble/curves does. These helpers do the same so a body encrypted by one
// SDK decrypts in the other.

var p25519 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// Ed25519PublicKeyToX25519 maps an Ed25519 public key to its X25519 form via
// the birational map u = (1 + y) / (1 - y) mod p (edwardsToMontgomeryPub).
func Ed25519PublicKeyToX25519(pub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("Ed25519 public key must be 32 bytes")
	}
	le := make([]byte, 32)
	copy(le, pub)
	le[31] &= 0x7f // drop the x sign bit
	y := new(big.Int).SetBytes(reverse(le))
	if y.Cmp(p25519) >= 0 {
		return nil, errors.New("Ed25519 public key is not canonical")
	}
	one := big.NewInt(1)
	den := new(big.Int).Mod(new(big.Int).Sub(one, y), p25519)
	if den.Sign() == 0 {
		return nil, errors.New("Ed25519 public key has no X25519 equivalent")
	}
	num := new(big.Int).Add(one, y)
	u := new(big.Int).Mod(new(big.Int).Mul(num, new(big.Int).ModInverse(den, p25519)), p25519)
	ub := u.FillBytes(make([]byte, 32))
	key, err := ecdh.X25519().NewPublicKey(reverse(ub))
	if err != nil {
		return nil, fmt.Errorf("X25519 public key: %w", err)
	}
	return key, nil
}

// Ed25519PrivateKeyToX25519 maps an Ed25519 private key to the matching
// X25519 private key: the first 32 bytes of SHA-512(seed), clamped
// (edwardsToMontgomeryPriv).
func Ed25519PrivateKeyToX25519(priv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("Ed25519 private key must be 64 bytes (seed || public key)")
	}
	h := sha512.Sum512(priv.Seed())
	s := h[:32]
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return ecdh.X25519().NewPrivateKey(s)
}

// EncryptBodyForEd25519 is EncryptBody for a recipient identified by its
// Ed25519 public key — the form aroha-core's encryptBody takes.
func EncryptBodyForEd25519(plaintext map[string]any, recipient ed25519.PublicKey) (map[string]any, error) {
	x, err := Ed25519PublicKeyToX25519(recipient)
	if err != nil {
		return nil, err
	}
	return EncryptBody(plaintext, x)
}

// DecryptBodyWithEd25519 is DecryptBody with the recipient's Ed25519 private
// key — the form aroha-core's decryptBody takes.
func DecryptBodyWithEd25519(encrypted map[string]any, recipient ed25519.PrivateKey) (map[string]any, error) {
	x, err := Ed25519PrivateKeyToX25519(recipient)
	if err != nil {
		return nil, err
	}
	return DecryptBody(encrypted, x)
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
