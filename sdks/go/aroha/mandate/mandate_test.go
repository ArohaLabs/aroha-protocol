// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package mandate_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/mandate"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func ptr[T any](v T) *T { return &v }

var base = mandate.SpendingConstraints{
	SpendLimitUSD:                500.0,
	SessionLimitUSD:              ptr(200.0),
	RequireHumanApprovalAboveUSD: ptr(100.0),
	AllowedMerchants:             []string{"merchant-a", "merchant-b", "merchant-c"},
}

// ── IssueIntent ───────────────────────────────────────────────────────────────

func TestIssueIntent_Fields(t *testing.T) {
	_, priv := mustKey(t)
	m, err := mandate.IssueIntent("did:aroha:grantor", "did:aroha:grantee", base, priv, time.Hour)
	if err != nil {
		t.Fatalf("IssueIntent: %v", err)
	}
	if m.Mandate.MandateTier != mandate.TierIntent {
		t.Errorf("tier = %q, want %q", m.Mandate.MandateTier, mandate.TierIntent)
	}
	if m.Mandate.Grantor != "did:aroha:grantor" {
		t.Errorf("grantor = %q", m.Mandate.Grantor)
	}
	if m.Mandate.Grantee != "did:aroha:grantee" {
		t.Errorf("grantee = %q", m.Mandate.Grantee)
	}
	if m.Mandate.ParentMandateID != nil {
		t.Errorf("parentMandateID should be nil for root mandate")
	}
	if m.Mandate.MandateID == "" {
		t.Error("mandateId is empty")
	}
	if m.Token == "" {
		t.Error("token is empty")
	}
}

// ── Verify ────────────────────────────────────────────────────────────────────

func TestVerify_Valid(t *testing.T) {
	pub, priv := mustKey(t)
	m, err := mandate.IssueIntent("did:aroha:g", "did:aroha:e", base, priv, time.Hour)
	if err != nil {
		t.Fatalf("IssueIntent: %v", err)
	}
	got, err := mandate.Verify(m.Token, pub, "did:aroha:e")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.MandateID != m.Mandate.MandateID {
		t.Errorf("mandateId mismatch")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv := mustKey(t)
	otherPub, _ := mustKey(t)
	m, _ := mandate.IssueIntent("did:aroha:g", "did:aroha:e", base, priv, time.Hour)
	_, err := mandate.Verify(m.Token, otherPub, "")
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
}

func TestVerify_Expired(t *testing.T) {
	pub, priv := mustKey(t)
	m, _ := mandate.IssueIntent("did:aroha:g", "did:aroha:e", base, priv, -time.Second)
	_, err := mandate.Verify(m.Token, pub, "")
	if err == nil {
		t.Fatal("expected expired error, got nil")
	}
}

func TestVerify_GranteeMismatch(t *testing.T) {
	pub, priv := mustKey(t)
	m, _ := mandate.IssueIntent("did:aroha:g", "did:aroha:e", base, priv, time.Hour)
	_, err := mandate.Verify(m.Token, pub, "did:aroha:other")
	if err == nil {
		t.Fatal("expected grantee mismatch error, got nil")
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	pub, _ := mustKey(t)
	_, err := mandate.Verify("not-valid-base64url!!!", pub, "")
	if err == nil {
		t.Fatal("expected error for malformed token, got nil")
	}
}

// ── assertNarrowing via AttenuateToCart ───────────────────────────────────────

func TestAttenuateToCart_Valid(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:user", "did:aroha:agent", base, priv, time.Hour)
	narrow := mandate.SpendingConstraints{
		SpendLimitUSD:                100.0,
		SessionLimitUSD:              ptr(50.0),
		RequireHumanApprovalAboveUSD: ptr(50.0),
		AllowedMerchants:             []string{"merchant-a"},
	}
	cart, err := mandate.AttenuateToCart(parent, "did:aroha:provider", narrow, priv, nil)
	if err != nil {
		t.Fatalf("AttenuateToCart: %v", err)
	}
	if cart.Mandate.MandateTier != mandate.TierCart {
		t.Errorf("tier = %q, want cart", cart.Mandate.MandateTier)
	}
}

func TestAttenuateToCart_RejectsSpendWidening(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:u", "did:aroha:a", base, priv, time.Hour)
	_, err := mandate.AttenuateToCart(parent, "did:aroha:p",
		mandate.SpendingConstraints{SpendLimitUSD: 9999.0}, priv, nil)
	if err == nil {
		t.Fatal("expected error for spendLimitUsd widening")
	}
}

func TestAttenuateToCart_RejectsSessionWidening(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:u", "did:aroha:a", base, priv, time.Hour)
	_, err := mandate.AttenuateToCart(parent, "did:aroha:p",
		mandate.SpendingConstraints{SpendLimitUSD: 100.0, SessionLimitUSD: ptr(9999.0)}, priv, nil)
	if err == nil {
		t.Fatal("expected error for sessionLimitUsd widening")
	}
}

func TestAttenuateToCart_RejectsApprovalThresholdWidening(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:u", "did:aroha:a", base, priv, time.Hour)
	_, err := mandate.AttenuateToCart(parent, "did:aroha:p",
		mandate.SpendingConstraints{
			SpendLimitUSD:                100.0,
			RequireHumanApprovalAboveUSD: ptr(9999.0),
		}, priv, nil)
	if err == nil {
		t.Fatal("expected error for approvalThreshold widening")
	}
}

func TestAttenuateToCart_RejectsUnlistedMerchant(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:u", "did:aroha:a", base, priv, time.Hour)
	_, err := mandate.AttenuateToCart(parent, "did:aroha:p",
		mandate.SpendingConstraints{
			SpendLimitUSD:    100.0,
			AllowedMerchants: []string{"merchant-a", "merchant-unknown"},
		}, priv, nil)
	if err == nil {
		t.Fatal("expected error for merchant not in parent list")
	}
}

func TestAttenuateToCart_RejectsEmptyMerchantsWhenParentRestricts(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:u", "did:aroha:a", base, priv, time.Hour)
	_, err := mandate.AttenuateToCart(parent, "did:aroha:p",
		mandate.SpendingConstraints{SpendLimitUSD: 100.0, AllowedMerchants: []string{}},
		priv, nil)
	if err == nil {
		t.Fatal("expected error for empty child merchants when parent restricts")
	}
}

func TestAttenuateToCart_RejectsNoMerchantsWhenParentRestricts(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:u", "did:aroha:a", base, priv, time.Hour)
	_, err := mandate.AttenuateToCart(parent, "did:aroha:p",
		mandate.SpendingConstraints{SpendLimitUSD: 100.0}, // no AllowedMerchants
		priv, nil)
	if err == nil {
		t.Fatal("expected error for missing child merchants when parent restricts")
	}
}

// ── Full chain ────────────────────────────────────────────────────────────────

func TestFullChain_IntentCartPayment(t *testing.T) {
	// v2 tokens carry their ancestry, and Verify checks it: each grantor's key
	// must be resolvable, so the chain uses content-addressed DIDs.
	_, userKey := mustKey(t)
	agentPub, agentKey := mustKey(t)
	providerPub, providerKey := mustKey(t)
	user := identity.DIDFromPublicKey(userKey.Public().(ed25519.PublicKey))
	agent := identity.DIDFromPublicKey(agentPub)
	provider := identity.DIDFromPublicKey(providerPub)

	intent, err := mandate.IssueIntent(user, agent, base, userKey, time.Hour)
	if err != nil {
		t.Fatalf("IssueIntent: %v", err)
	}

	cart, err := mandate.AttenuateToCart(intent, provider,
		mandate.SpendingConstraints{
			SpendLimitUSD:    100.0,
			AllowedMerchants: []string{"merchant-a"},
		}, agentKey, nil)
	if err != nil {
		t.Fatalf("AttenuateToCart: %v", err)
	}

	payment, err := mandate.AttenuateToPayment(cart, "did:aroha:processor",
		mandate.SpendingConstraints{
			SpendLimitUSD:    42.0,
			AllowedMerchants: []string{"merchant-a"},
		}, providerKey, nil)
	if err != nil {
		t.Fatalf("AttenuateToPayment: %v", err)
	}

	if payment.Mandate.MandateTier != mandate.TierPayment {
		t.Errorf("tier = %q, want payment", payment.Mandate.MandateTier)
	}
	if *payment.Mandate.ParentMandateID != cart.Mandate.MandateID {
		t.Errorf("parentMandateId mismatch")
	}
	if payment.Mandate.Constraints.SpendLimitUSD != 42.0 {
		t.Errorf("spendLimitUsd = %v, want 42", payment.Mandate.Constraints.SpendLimitUSD)
	}
	if len(payment.Chain) != 2 || payment.Chain[0].Mandate.MandateID != intent.Mandate.MandateID {
		t.Fatalf("payment chain = %+v", payment.Chain)
	}

	got, err := mandate.Verify(payment.Token, providerPub, "did:aroha:processor")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.MandateID != payment.Mandate.MandateID {
		t.Errorf("mandateId mismatch after verify")
	}

	r := mandate.VerifyMandateChain(payment.Token, nil, mandate.ChainOptions{
		CheckOptions:    mandate.CheckOptions{ExpectedRoot: user},
		ExpectedGrantee: "did:aroha:processor",
	})
	if !r.Valid || !r.ChainVerified || r.RootGrantor != user || len(r.Chain) != 3 {
		t.Fatalf("VerifyMandateChain: %+v", r)
	}
}

// A child that leaves the approval threshold out used to drop it; it now
// inherits the parent's value.
func TestAttenuateToCart_InheritsOmittedApprovalThreshold(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:u", "did:aroha:a", base, priv, time.Hour)
	cart, err := mandate.AttenuateToCart(parent, "did:aroha:p",
		mandate.SpendingConstraints{SpendLimitUSD: 100.0, AllowedMerchants: []string{"merchant-a"}}, priv, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := cart.Mandate.Constraints.RequireHumanApprovalAboveUSD
	if got == nil || *got != 100.0 {
		t.Fatalf("approval threshold = %v, want inherited 100", got)
	}
	if s := cart.Mandate.Constraints.SessionLimitUSD; s == nil || *s != 200.0 {
		t.Fatalf("session limit = %v, want inherited 200", s)
	}
}

func TestAttenuateToCart_RejectsCurrencyChange(t *testing.T) {
	_, priv := mustKey(t)
	parent, _ := mandate.IssueIntent("did:aroha:u", "did:aroha:a", base, priv, time.Hour)
	_, err := mandate.AttenuateToCart(parent, "did:aroha:p",
		mandate.SpendingConstraints{SpendLimitUSD: 100.0, Currency: "EUR",
			AllowedMerchants: []string{"merchant-a"}}, priv, nil)
	if err == nil {
		t.Fatal("expected error for currency change")
	}
}
