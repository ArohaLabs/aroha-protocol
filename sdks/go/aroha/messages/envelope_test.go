// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package messages_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/crypto"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
)

const (
	alice = "did:aroha:alice"
	bob   = "did:aroha:bob"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// wire simulates transmission: JSON out, JSON in.
func wire(t *testing.T, env map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func code(err error) messages.ErrorCode {
	var ve *messages.ValidationError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}

func build(t *testing.T, priv ed25519.PrivateKey, body map[string]any) map[string]any {
	t.Helper()
	env, err := messages.BuildDefault(messages.TypeRequest, alice, bob, body, messages.NewCorrelationID(), priv, alice+"#key-1")
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestBuild_Shape(t *testing.T) {
	_, priv := keys(t)
	env := build(t, priv, map[string]any{"q": "x"})
	for _, f := range []string{"@context", "id", "type", "from", "to", "created", "expires", "nonce", "correlationId", "body", "proof"} {
		if _, ok := env[f]; !ok {
			t.Errorf("missing %s", f)
		}
	}
	if n := env["nonce"].(string); len(n) != 64 {
		t.Errorf("nonce %q: want 32 bytes hex", n)
	}
	if !strings.HasPrefix(env["id"].(string), "urn:uuid:") || !strings.HasPrefix(env["correlationId"].(string), "saga-") {
		t.Errorf("id/correlationId = %v / %v", env["id"], env["correlationId"])
	}
	for _, f := range []string{"created", "expires"} {
		if _, err := time.Parse("2006-01-02T15:04:05.000Z", env[f].(string)); err != nil {
			t.Errorf("%s not in toISOString format: %v", f, env[f])
		}
	}
}

func TestBuild_TTLCeiling(t *testing.T) {
	_, priv := keys(t)
	if _, err := messages.Build(messages.TypeRequest, alice, bob, nil, "c", priv, "", time.Hour); err == nil {
		t.Fatal("Build accepted a TTL above the receiver maximum")
	}
	if _, err := messages.Build(messages.TypeRequest, alice, bob, nil, "c", priv, "", 0); err == nil {
		t.Fatal("Build accepted a zero TTL")
	}
	env, err := messages.BuildWithOptions(messages.TypeRequest, alice, bob, nil, "c", priv,
		messages.BuildOptions{TTL: time.Hour, AllowLongTTL: true})
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := messages.Validate(wire(t, env), pub, bob, messages.NewNonceRegistry()); code(err) != messages.ErrInvalidParams {
		t.Errorf("default receiver accepted a 1h envelope: %v", err)
	}
	if err := messages.Validate(wire(t, env), pub, bob, messages.NewNonceRegistry(),
		messages.ValidateOptions{MaxTTL: time.Hour}); err != nil {
		t.Errorf("receiver configured for 1h rejected it: %v", err)
	}
}

func TestBuild_ExtrasCannotOverrideReservedFields(t *testing.T) {
	_, priv := keys(t)
	for _, f := range []string{"expires", "from", "nonce", "proof"} {
		if _, err := messages.Build(messages.TypeRequest, alice, bob, nil, "c", priv, "", time.Minute, map[string]any{f: "x"}); err == nil {
			t.Errorf("extra %q accepted", f)
		}
	}
	env, err := messages.Build(messages.TypeRequest, alice, bob, nil, "c", priv, "", time.Minute, map[string]any{"traceparent": "00-abc"})
	if err != nil || env["traceparent"] != "00-abc" {
		t.Fatalf("traceparent extra: %v %v", env["traceparent"], err)
	}
}

func TestValidate_RoundTrip(t *testing.T) {
	pub, priv := keys(t)
	reg := messages.NewNonceRegistry()
	env := wire(t, build(t, priv, map[string]any{"html": "<b>&</b>", "n": 1e21, "f": 0.1}))
	if err := messages.Validate(env, pub, bob, reg); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	if err := messages.Validate(env, pub, bob, reg); code(err) != messages.ErrReplayDetected {
		t.Fatalf("replay: %v", err)
	}
}

func TestValidate_Order(t *testing.T) {
	pub, priv := keys(t)
	otherPub, _ := keys(t)

	// Recipient is checked first, before anything else.
	if err := messages.Validate(wire(t, build(t, priv, nil)), otherPub, "did:aroha:carol", messages.NewNonceRegistry()); code(err) != messages.ErrUnauthorized {
		t.Errorf("recipient: %v", err)
	}

	// A forged envelope must not burn the real sender's nonce.
	reg := messages.NewNonceRegistry()
	real := wire(t, build(t, priv, nil))
	forged := wire(t, build(t, priv, nil))
	forged["nonce"] = real["nonce"]
	forged["body"] = map[string]any{"tampered": true}
	if err := messages.Validate(forged, pub, bob, reg); code(err) != messages.ErrInvalidSignature {
		t.Fatalf("forged: %v", err)
	}
	if err := messages.Validate(real, pub, bob, reg); err != nil {
		t.Fatalf("real envelope rejected after a forged one carried its nonce: %v", err)
	}

	// Wrong key.
	if err := messages.Validate(wire(t, build(t, priv, nil)), otherPub, bob, messages.NewNonceRegistry()); code(err) != messages.ErrInvalidSignature {
		t.Errorf("wrong key: %v", err)
	}
}

func TestValidate_PerSenderNonces(t *testing.T) {
	alicePub, alicePriv := keys(t)
	carolPub, carolPriv := keys(t)
	reg := messages.NewNonceRegistry()
	a := wire(t, build(t, alicePriv, nil))
	c, err := messages.BuildDefault(messages.TypeRequest, "did:aroha:carol", bob, nil, "c", carolPriv, "did:aroha:carol#key-1")
	if err != nil {
		t.Fatal(err)
	}
	// Same nonce from a different sender: re-sign carol's envelope with alice's nonce.
	delete(c, "proof")
	c["nonce"] = a["nonce"]
	if err := crypto.SignMessage(c, carolPriv, "did:aroha:carol#key-1"); err != nil {
		t.Fatal(err)
	}
	if err := messages.Validate(a, alicePub, bob, reg); err != nil {
		t.Fatal(err)
	}
	if err := messages.Validate(wire(t, c), carolPub, bob, reg); err != nil {
		t.Fatalf("a nonce collision across senders must not count as replay: %v", err)
	}
}

func TestValidate_Timestamps(t *testing.T) {
	pub, priv := keys(t)
	env := wire(t, build(t, priv, nil))
	later := time.Now().Add(10 * time.Minute)
	if err := messages.Validate(env, pub, bob, messages.NewNonceRegistry(), messages.ValidateOptions{Now: later}); code(err) != messages.ErrExpiredMessage {
		t.Errorf("expired: %v", err)
	}
	if err := messages.Validate(env, pub, bob, messages.NewNonceRegistry(), messages.ValidateOptions{Now: later, ClockTolerance: 6 * time.Minute}); err != nil {
		t.Errorf("within tolerance: %v", err)
	}
	earlier := time.Now().Add(-time.Minute)
	if err := messages.Validate(env, pub, bob, messages.NewNonceRegistry(), messages.ValidateOptions{Now: earlier}); code(err) != messages.ErrInvalidParams {
		t.Errorf("created in the future: %v", err)
	}
	if err := messages.Validate(env, pub, bob, messages.NewNonceRegistry(), messages.ValidateOptions{ClockTolerance: -1}); err == nil {
		t.Error("negative tolerance accepted")
	}
	bad := wire(t, build(t, priv, nil))
	bad["expires"] = "not a date"
	if err := messages.Validate(bad, pub, bob, messages.NewNonceRegistry()); code(err) != messages.ErrInvalidParams {
		t.Errorf("malformed expires: %v", err)
	}
	noNonce := wire(t, build(t, priv, nil))
	delete(noNonce, "nonce")
	if err := messages.Validate(noNonce, pub, bob, messages.NewNonceRegistry()); code(err) != messages.ErrInvalidParams {
		t.Errorf("missing nonce: %v", err)
	}
}

func TestValidate_ProofKeyMustBelongToFrom(t *testing.T) {
	pub, priv := keys(t)
	env, err := messages.BuildDefault(messages.TypeRequest, alice, bob, nil, "c", priv, "did:aroha:mallory#key-1")
	if err != nil {
		t.Fatal(err)
	}
	err = messages.Validate(wire(t, env), pub, bob, messages.NewNonceRegistry())
	if code(err) != messages.ErrInvalidSignature || !strings.Contains(err.Error(), "different DID") {
		t.Errorf("foreign proof key: %v", err)
	}
	rel, err := messages.BuildDefault(messages.TypeRequest, alice, bob, nil, "c", priv, "#key-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := messages.Validate(wire(t, rel), pub, bob, messages.NewNonceRegistry()); err != nil {
		t.Errorf("relative verification method: %v", err)
	}
}

func TestValidate_SkipSignatureStillRecordsNonce(t *testing.T) {
	_, priv := keys(t)
	reg := messages.NewNonceRegistry()
	env := wire(t, build(t, priv, nil))
	ack := messages.ValidateOptions{SkipSignature: true, AcknowledgeUnauthenticated: true}
	if err := messages.Validate(env, nil, bob, reg, ack); err != nil {
		t.Fatal(err)
	}
	if err := messages.Validate(env, nil, bob, reg, ack); code(err) != messages.ErrReplayDetected {
		t.Errorf("replay in skip mode: %v", err)
	}
}

func TestValidate_SkipSignatureNeedsAcknowledgementOrDevEnv(t *testing.T) {
	_, priv := keys(t)
	env := wire(t, build(t, priv, nil))
	skip := messages.ValidateOptions{SkipSignature: true}
	t.Setenv(messages.DevModeEnv, "")
	err := messages.Validate(env, nil, bob, messages.NewNonceRegistry(), skip)
	if !errors.Is(err, messages.ErrDevModeNotPermitted) || !strings.Contains(err.Error(), "AROHA_DEV_MODE=1") {
		t.Fatalf("SkipSignature without acknowledgement must be refused: %v", err)
	}
	t.Setenv(messages.DevModeEnv, "true") // only "1" opts in
	if err := messages.Validate(env, nil, bob, messages.NewNonceRegistry(), skip); !errors.Is(err, messages.ErrDevModeNotPermitted) {
		t.Fatalf("got %v", err)
	}
	t.Setenv(messages.DevModeEnv, "1")
	if err := messages.Validate(env, nil, bob, messages.NewNonceRegistry(), skip); err != nil {
		t.Fatalf("dev env should permit SkipSignature: %v", err)
	}
}

func TestValidate_NonceLengthCap(t *testing.T) {
	pub, priv := keys(t)
	for _, tc := range []struct {
		n  int
		ok bool
	}{{128, true}, {129, false}} {
		env := build(t, priv, nil)
		env["nonce"] = strings.Repeat("a", tc.n)
		if err := crypto.SignMessage(env, priv, alice+"#key-1"); err != nil {
			t.Fatal(err)
		}
		err := messages.Validate(wire(t, env), pub, bob, messages.NewNonceRegistry())
		if tc.ok && err != nil {
			t.Fatalf("%d-char nonce rejected: %v", tc.n, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "Nonce too long (max 128 characters)")) {
			t.Fatalf("%d-char nonce: %v", tc.n, err)
		}
	}
}

func TestTypesAndErrorCodes(t *testing.T) {
	if len(messages.MessageTypes) != 19 {
		t.Errorf("%d message types, want 19", len(messages.MessageTypes))
	}
	if !messages.IsMessageType("ArohaDisputeResolution") || messages.IsMessageType("ArohaNope") {
		t.Error("IsMessageType")
	}
	if len(messages.ErrorCodes) != 35 {
		t.Errorf("%d error codes, want 35 (34 Aroha_* + CSN_NO_STRUCTURAL_MATCH)", len(messages.ErrorCodes))
	}
	seen := map[messages.ErrorCode]bool{}
	for _, c := range messages.ErrorCodes {
		if seen[c] {
			t.Errorf("duplicate %s", c)
		}
		seen[c] = true
	}
	if messages.ErrorDocsURL(messages.ErrCommitDisputed) != "https://aroha-labs.com/docs/errors#Aroha_COMMIT_DISPUTED" {
		t.Error("ErrorDocsURL")
	}
}
