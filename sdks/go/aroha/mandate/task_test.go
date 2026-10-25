// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package mandate_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/mandate"
)

func taskParty(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return identity.DIDFromPublicKey(priv.Public().(ed25519.PublicKey)), priv
}

func f64(v float64) *float64 { return &v }

func rootTask(t *testing.T, humanDID string, humanKey ed25519.PrivateKey, agentDID string) *mandate.SignedTaskMandate {
	t.Helper()
	sm, err := mandate.IssueTaskMandate(humanDID, agentDID,
		[]string{"search", "send-email", "export"},
		mandate.TaskConstraints{
			ActionLimits: map[string]float64{"send-email": 2},
			ComputeLimit: &mandate.ComputeLimit{LLMTokens: f64(1000)},
			DataAccess:   map[string]mandate.DataAccessLevel{"email": mandate.DataAccessReadWrite},
			HumanGates:   []string{"send-email"},
			RoomID:       "room-1",
			OnBehalfOf:   "did:aroha:guest",
		},
		humanKey, time.Hour, mandate.TaskIssueOptions{Blocked: []string{"export"}})
	if err != nil {
		t.Fatal(err)
	}
	return sm
}

func TestTask_IssueVerifyRoundTrip(t *testing.T) {
	human, humanKey := taskParty(t)
	agent, _ := taskParty(t)
	sm := rootTask(t, human, humanKey, agent)
	if sm.V != 2 || sm.Mandate.MandateType != mandate.TaskTypeTask || sm.Mandate.MandateTier != mandate.TaskTierIntent {
		t.Fatalf("unexpected mandate: %+v", sm.Mandate)
	}
	r := mandate.VerifyTaskMandate(sm.Token, humanKey.Public().(ed25519.PublicKey), agent, mandate.TaskVerifyOptions{})
	if !r.Valid {
		t.Fatal(r.Reason)
	}
	if r.Mandate.TaskConstraints.RoomID != "room-1" || r.Mandate.Blocked[0] != "export" {
		t.Fatalf("decoded mandate lost fields: %+v", r.Mandate)
	}
	// The token is {v, mandate, signature} in that order.
	tok, _ := base64.RawURLEncoding.DecodeString(sm.Token)
	if !strings.HasPrefix(string(tok), `{"v":2,"mandate":{"mandateType":"task","mandateTier":"intent","allowed":[`) {
		t.Fatalf("token layout: %s", tok)
	}
}

func TestTask_HybridWhenSpendingConstraintsSet(t *testing.T) {
	human, humanKey := taskParty(t)
	agent, _ := taskParty(t)
	sm, err := mandate.IssueTaskMandate(human, agent, []string{"buy"}, mandate.TaskConstraints{}, humanKey, 0,
		mandate.TaskIssueOptions{SpendingConstraints: &mandate.SpendingConstraints{SpendLimitUSD: 50}})
	if err != nil {
		t.Fatal(err)
	}
	if sm.Mandate.MandateType != mandate.TaskTypeHybrid {
		t.Fatalf("mandateType = %s", sm.Mandate.MandateType)
	}
	exp, _ := time.Parse(time.RFC3339Nano, sm.Mandate.ExpiresAt)
	if d := time.Until(exp); d < 59*time.Minute || d > time.Hour {
		t.Fatalf("ttl 0 should default to an hour, got %s", d)
	}
}

func TestTask_IssueRefusesMalformedConstraints(t *testing.T) {
	human, humanKey := taskParty(t)
	_, err := mandate.IssueTaskMandate(human, "did:aroha:x", []string{"a"},
		mandate.TaskConstraints{ActionLimits: map[string]float64{"a": -1}}, humanKey, 0, mandate.TaskIssueOptions{})
	if err == nil || !strings.Contains(err.Error(), "actionLimits") {
		t.Fatalf("want an actionLimits error, got %v", err)
	}
}

func TestTask_AttenuateInheritsAndNarrows(t *testing.T) {
	human, humanKey := taskParty(t)
	agent, agentKey := taskParty(t)
	sub, _ := taskParty(t)
	root := rootTask(t, human, humanKey, agent)

	child, err := mandate.AttenuateTaskMandate(root, sub, []string{"send-email"},
		mandate.TaskConstraints{
			ActionLimits: map[string]float64{"send-email": 1},
			ComputeLimit: &mandate.ComputeLimit{LLMTokens: f64(500)},
			DataAccess:   map[string]mandate.DataAccessLevel{"email": mandate.DataAccessWrite},
			HumanGates:   []string{"send-email"},
		},
		agentKey, 10*time.Minute, mandate.TaskAttenuateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c := child.Mandate
	if c.Grantor != agent || c.Grantee != sub || *c.ParentMandateID != root.Mandate.MandateID || c.MandateTier != mandate.TaskTierCart {
		t.Fatalf("linkage: %+v", c)
	}
	// Room / member binding and the blocked list are inherited.
	if c.TaskConstraints.RoomID != "room-1" || c.TaskConstraints.OnBehalfOf != "did:aroha:guest" || len(c.Blocked) != 1 {
		t.Fatalf("inheritance: %+v", c)
	}
	exp, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if time.Until(exp) > 10*time.Minute {
		t.Fatalf("ttl not applied: %s", c.ExpiresAt)
	}
	if err := mandate.CheckTaskNarrowingMandates(&root.Mandate, &c); err != nil {
		t.Fatalf("the verifier-side rule refuses what attenuation produced: %v", err)
	}
	if r := mandate.VerifyTaskMandate(child.Token, agentKey.Public().(ed25519.PublicKey), sub, mandate.TaskVerifyOptions{}); !r.Valid {
		t.Fatal(r.Reason)
	}

	// A grandchild is an execution mandate and never outlives its parent.
	grand, err := mandate.AttenuateTaskMandate(child, "did:aroha:x", []string{"send-email"}, c.TaskConstraints, ed25519KeyOf(t), 0, mandate.TaskAttenuateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if grand.Mandate.MandateTier != mandate.TaskTierExecution || grand.Mandate.ExpiresAt != c.ExpiresAt {
		t.Fatalf("grandchild: %+v", grand.Mandate)
	}
}

func ed25519KeyOf(t *testing.T) ed25519.PrivateKey {
	_, k := taskParty(t)
	return k
}

func TestTask_AttenuateRefusesWidening(t *testing.T) {
	human, humanKey := taskParty(t)
	agent, agentKey := taskParty(t)
	root := rootTask(t, human, humanKey, agent)
	base := func() mandate.TaskConstraints {
		return mandate.TaskConstraints{
			ActionLimits: map[string]float64{"send-email": 2},
			ComputeLimit: &mandate.ComputeLimit{LLMTokens: f64(1000)},
			DataAccess:   map[string]mandate.DataAccessLevel{"email": mandate.DataAccessRead},
			HumanGates:   []string{"send-email"},
		}
	}
	cases := map[string]struct {
		allowed []string
		tc      func(mandate.TaskConstraints) mandate.TaskConstraints
		want    string
	}{
		"new capability":   {[]string{"search", "post"}, func(c mandate.TaskConstraints) mandate.TaskConstraints { return c }, `"post" which is not in parent's allowed`},
		"limit omitted":    {[]string{"send-email"}, func(c mandate.TaskConstraints) mandate.TaskConstraints { c.ActionLimits = nil; return c }, "but child omits it"},
		"limit raised":     {[]string{"send-email"}, func(c mandate.TaskConstraints) mandate.TaskConstraints { c.ActionLimits["send-email"] = 3; return c }, "exceeds parent (2)"},
		"compute dropped":  {[]string{"send-email"}, func(c mandate.TaskConstraints) mandate.TaskConstraints { c.ComputeLimit = nil; return c }, "computeLimit.llmTokens"},
		"data map dropped": {[]string{"send-email"}, func(c mandate.TaskConstraints) mandate.TaskConstraints { c.DataAccess = nil; return c }, "restricts dataAccess"},
		"human gate gone":  {[]string{"send-email"}, func(c mandate.TaskConstraints) mandate.TaskConstraints { c.HumanGates = nil; return c }, "human gate"},
		"other room":       {[]string{"send-email"}, func(c mandate.TaskConstraints) mandate.TaskConstraints { c.RoomID = "room-2"; return c }, "roomId"},
		"other member":     {[]string{"send-email"}, func(c mandate.TaskConstraints) mandate.TaskConstraints { c.OnBehalfOf = "did:aroha:x"; return c }, "onBehalfOf"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := mandate.AttenuateTaskMandate(root, "did:aroha:sub", tc.allowed, tc.tc(base()), agentKey, 0, mandate.TaskAttenuateOptions{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	// Dropping the parent's blocked list through options is impossible: it is merged.
	child, err := mandate.AttenuateTaskMandate(root, "did:aroha:sub", []string{"send-email"}, base(), agentKey, 0,
		mandate.TaskAttenuateOptions{Blocked: []string{"search"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(child.Mandate.Blocked, ","); got != "export,search" {
		t.Fatalf("blocked = %s", got)
	}
}

func TestTask_VerifyRejects(t *testing.T) {
	human, humanKey := taskParty(t)
	agent, _ := taskParty(t)
	sm := rootTask(t, human, humanKey, agent)
	pub := humanKey.Public().(ed25519.PublicKey)
	now := time.Now()

	// Tamper: widen allowed after signing.
	tok, _ := base64.RawURLEncoding.DecodeString(sm.Token)
	var obj map[string]any
	_ = json.Unmarshal(tok, &obj)
	obj["mandate"].(map[string]any)["allowed"] = []any{"search", "send-email", "export", "delete-everything"}
	tampered, _ := json.Marshal(obj)

	checks := []struct {
		name, token, grantee string
		opts                 mandate.TaskVerifyOptions
		key                  ed25519.PublicKey
		want                 string
	}{
		{"tampered", base64.RawURLEncoding.EncodeToString(tampered), "", mandate.TaskVerifyOptions{}, pub, "Invalid signature"},
		{"wrong key", sm.Token, "", mandate.TaskVerifyOptions{}, ed25519KeyOf(t).Public().(ed25519.PublicKey), "Invalid signature"},
		{"expired", sm.Token, "", mandate.TaskVerifyOptions{Now: now.Add(2 * time.Hour)}, pub, "Task mandate expired"},
		{"future", sm.Token, "", mandate.TaskVerifyOptions{Now: now.Add(-time.Minute)}, pub, "is in the future"},
		{"grantee", sm.Token, "did:aroha:someone-else", mandate.TaskVerifyOptions{}, pub, "Grantee mismatch"},
		{"revoked", sm.Token, "", mandate.TaskVerifyOptions{IsRevoked: func(id, g string) (bool, error) { return id == sm.Mandate.MandateID && g == human, nil }}, pub, "has been revoked"},
		{"revocation outage fails closed", sm.Token, "", mandate.TaskVerifyOptions{IsRevoked: func(string, string) (bool, error) { return false, errors.New("down") }}, pub, "Revocation check failed"},
		{"garbage", "!!!", "", mandate.TaskVerifyOptions{}, pub, "Malformed token"},
		{"empty", "", "", mandate.TaskVerifyOptions{}, pub, "Malformed token"},
		{"number", base64.RawURLEncoding.EncodeToString([]byte("42")), "", mandate.TaskVerifyOptions{}, pub, "Malformed token"},
		{"no mandate", base64.RawURLEncoding.EncodeToString([]byte(`{"v":2,"signature":"x"}`)), "", mandate.TaskVerifyOptions{}, pub, "mandate is not an object"},
		{"short key", sm.Token, "", mandate.TaskVerifyOptions{}, pub[:8], "Invalid signature"},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			r := mandate.VerifyTaskMandate(c.token, c.key, c.grantee, c.opts)
			if r.Valid || !strings.Contains(r.Reason, c.want) {
				t.Fatalf("got valid=%v reason=%q, want %q", r.Valid, r.Reason, c.want)
			}
		})
	}
}

func TestTask_DecodeTokenThenAttenuate(t *testing.T) {
	human, humanKey := taskParty(t)
	agent, agentKey := taskParty(t)
	root := rootTask(t, human, humanKey, agent)
	received, err := mandate.DecodeTaskToken(root.Token)
	if err != nil {
		t.Fatal(err)
	}
	child, err := mandate.AttenuateTaskMandate(received, "did:aroha:sub", []string{"search"}, mandate.TaskConstraints{
		ComputeLimit: &mandate.ComputeLimit{LLMTokens: f64(100)},
		DataAccess:   map[string]mandate.DataAccessLevel{}, // no access to anything: narrower than the parent's map
	}, agentKey, 0, mandate.TaskAttenuateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := base64.RawURLEncoding.DecodeString(child.Token)
	if !strings.Contains(string(tok), `"dataAccess":{}`) {
		t.Fatalf("an empty dataAccess map must stay on the wire: %s", tok)
	}
	if child.Mandate.TaskConstraints.DataAccess == nil {
		t.Fatal("empty dataAccess decoded as nil")
	}
	if v := mandate.CheckTaskDataAccess(&child.Mandate.TaskConstraints, map[string]mandate.DataAccessLevel{"email": mandate.DataAccessRead}); v == nil {
		t.Fatal("an empty grant map must refuse every resource")
	}
}

func TestTask_Enforce(t *testing.T) {
	human, humanKey := taskParty(t)
	agent, _ := taskParty(t)
	sm := rootTask(t, human, humanKey, agent)
	pub := humanKey.Public().(ed25519.PublicKey)
	ok := mandate.TaskActionRequest{RequestedCapability: "search", RoomID: "room-1", OnBehalfOf: "did:aroha:guest"}

	if _, err := mandate.EnforceTaskConstraints(sm.Token, pub, mandate.EnforceTaskOptions{TaskActionRequest: ok, ExpectedGrantee: agent}); err != nil {
		t.Fatal(err)
	}
	code := func(err error) string {
		var v *mandate.TaskConstraintViolation
		if !errors.As(err, &v) {
			t.Fatalf("not a TaskConstraintViolation: %v", err)
		}
		return v.Code
	}
	cases := map[string]struct {
		mod  func(r mandate.TaskActionRequest) mandate.TaskActionRequest
		want string
	}{
		"blocked": {func(r mandate.TaskActionRequest) mandate.TaskActionRequest {
			r.RequestedCapability = "export"
			return r
		}, mandate.TaskViolationCapabilityNotPermitted},
		"not allowed": {func(r mandate.TaskActionRequest) mandate.TaskActionRequest { r.RequestedCapability = "pay"; return r }, mandate.TaskViolationCapabilityNotPermitted},
		"gate": {func(r mandate.TaskActionRequest) mandate.TaskActionRequest {
			r.RequestedCapability = "send-email"
			return r
		}, mandate.TaskViolationHumanGateRequired},
		"over limit": {func(r mandate.TaskActionRequest) mandate.TaskActionRequest {
			r.RequestedCapability, r.HumanApproved, r.CurrentActionCounts = "send-email", true, map[string]float64{"send-email": 2}
			return r
		}, mandate.TaskViolationActionLimitExceeded},
		"compute": {func(r mandate.TaskActionRequest) mandate.TaskActionRequest {
			r.CurrentCompute = &mandate.ComputeUsage{LLMTokens: 1000}
			return r
		}, mandate.TaskViolationComputeLimitExceeded},
		"data": {func(r mandate.TaskActionRequest) mandate.TaskActionRequest {
			r.DataAccess = map[string]mandate.DataAccessLevel{"files": mandate.DataAccessRead}
			return r
		}, mandate.TaskViolationDataAccess},
		"room": {func(r mandate.TaskActionRequest) mandate.TaskActionRequest { r.RoomID = ""; return r }, mandate.TaskViolationContextMismatch},
		"member": {func(r mandate.TaskActionRequest) mandate.TaskActionRequest {
			r.OnBehalfOf = "did:aroha:other"
			return r
		}, mandate.TaskViolationContextMismatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := mandate.EnforceTaskConstraints(sm.Token, pub, mandate.EnforceTaskOptions{TaskActionRequest: c.mod(ok)})
			if got := code(err); got != c.want {
				t.Fatalf("code = %s, want %s (%v)", got, c.want, err)
			}
		})
	}
	_, err := mandate.EnforceTaskConstraints(sm.Token, pub, mandate.EnforceTaskOptions{TaskActionRequest: ok, ExpectedGrantee: "did:aroha:nope"})
	if code(err) != mandate.TaskViolationMandateInvalid {
		t.Fatalf("grantee mismatch: %v", err)
	}
}

func TestTask_ReversibleOnly(t *testing.T) {
	human, humanKey := taskParty(t)
	sm, err := mandate.IssueTaskMandate(human, "did:aroha:a", []string{"draft", "send"},
		mandate.TaskConstraints{ReversibleOnly: true}, humanKey, 0, mandate.TaskIssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for rev, allowed := range map[string]bool{"full": true, "semi": true, "irreversible": false, "": false} {
		v := mandate.CheckTaskConstraints(&sm.Mandate, mandate.TaskActionRequest{RequestedCapability: "draft", CapabilityReversibility: rev})
		if (v == nil) != allowed {
			t.Fatalf("reversibility %q: allowed=%v, violation %v", rev, allowed, v)
		}
	}
}

// A task-mandate signature does not verify as a spending mandate, and a
// spending mandate's signature does not verify as a task mandate.
func TestTask_DomainSeparatedFromSpendingMandates(t *testing.T) {
	human, humanKey := taskParty(t)
	agent, _ := taskParty(t)
	spend, err := mandate.IssueIntent(human, agent, mandate.SpendingConstraints{SpendLimitUSD: 10}, humanKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r := mandate.VerifyTaskMandate(spend.Token, humanKey.Public().(ed25519.PublicKey), "", mandate.TaskVerifyOptions{}); r.Valid {
		t.Fatal("a spending token verified as a task mandate")
	}
	task := rootTask(t, human, humanKey, agent)
	if _, err := mandate.Verify(task.Token, humanKey.Public().(ed25519.PublicKey), ""); err == nil {
		t.Fatal("a task token verified as a spending mandate")
	}
}
