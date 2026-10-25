// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

//go:build integration

// Cross-language task-mandate checks against the TypeScript reference, live:
// tokens issued and attenuated by @aroha-sdk/credentials are verified,
// narrowing-checked and enforced in Go, and the reverse.
//
//	AROHA_CREDENTIALS_DIR=<path to a built packages/aroha-credentials> \
//	  go test -tags integration -run CrossLanguageTask ./aroha/mandate/
//
// Shares credentialsEntry / runNode / seedParty with
// crosslang_integration_test.go; skips the same way when node or the built
// package is missing.

package mandate_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/mandate"
)

func tamperTaskToken(t *testing.T, token string, mutate func(m map[string]any)) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	mutate(obj["mandate"].(map[string]any))
	out, _ := json.Marshal(obj)
	return base64.RawURLEncoding.EncodeToString(out)
}

// TypeScript issues and attenuates; Go verifies, rejects tampered, widened,
// expired and over-limit cases, then attenuates further for TypeScript.
func TestCrossLanguageTask_TSIssuedVerifiesInGo(t *testing.T) {
	entry := credentialsEntry(t)
	human, humanKey, humanSeed := seedParty(t)
	agent, agentKey, agentSeed := seedParty(t)
	provider, providerKey, providerSeed := seedParty(t)

	out := runNode(t, `
const c = await import(process.env.ENTRY);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const root = await c.issueTaskMandate(process.env.HUMAN, process.env.AGENT,
  ["search", "send-email", "export"],
  { actionLimits: { "send-email": 3, search: 20 }, computeLimit: { llmTokens: 10000, webRequests: 50 },
    dataAccess: { email: "read-write", drafts: "write" }, humanGates: ["send-email"], outputHandling: "user-only",
    roomId: "room-<&>", onBehalfOf: process.env.PROVIDER, maxDelegationDepth: 2 },
  hex(process.env.HUMAN_SEED), 3600000, { blocked: ["export"] });
const child = await c.attenuateTaskMandate(root, process.env.PROVIDER, ["send-email"],
  { actionLimits: { "send-email": 1 }, computeLimit: { llmTokens: 1000, webRequests: 5 },
    dataAccess: { email: "write" }, humanGates: ["send-email"], outputHandling: "internal-only" },
  hex(process.env.AGENT_SEED));
// A dishonest delegator skips attenuateTaskMandate and signs a widened child itself.
const widened = await c.issueTaskMandate(process.env.AGENT, process.env.PROVIDER, ["send-email", "search"],
  { actionLimits: { "send-email": 30, search: 20 }, computeLimit: { llmTokens: 1000, webRequests: 5 },
    dataAccess: { email: "read-write" }, humanGates: ["send-email"], outputHandling: "internal-only",
    roomId: "room-<&>", onBehalfOf: process.env.PROVIDER },
  hex(process.env.AGENT_SEED), 600000, { blocked: ["export"], parentMandateId: root.mandate.mandateId, tier: "cart" });
process.stdout.write(JSON.stringify({ root: root.token, child: child.token, widened: widened.token }));
`, map[string]string{"ENTRY": entry, "HUMAN": human, "AGENT": agent, "PROVIDER": provider,
		"HUMAN_SEED": humanSeed, "AGENT_SEED": agentSeed})
	var toks struct{ Root, Child, Widened string }
	if err := json.Unmarshal([]byte(out), &toks); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	humanPub := humanKey.Public().(ed25519.PublicKey)
	agentPub := agentKey.Public().(ed25519.PublicKey)

	root := mandate.VerifyTaskMandate(toks.Root, humanPub, agent, mandate.TaskVerifyOptions{})
	if !root.Valid {
		t.Fatalf("TS root rejected by Go: %s", root.Reason)
	}
	child := mandate.VerifyTaskMandate(toks.Child, agentPub, provider, mandate.TaskVerifyOptions{})
	if !child.Valid {
		t.Fatalf("TS child rejected by Go: %s", child.Reason)
	}
	if child.Mandate.TaskConstraints.RoomID != "room-<&>" || child.Mandate.MandateTier != mandate.TaskTierCart {
		t.Fatalf("TS child decoded as %+v", child.Mandate)
	}
	if err := mandate.CheckTaskNarrowingMandates(root.Mandate, child.Mandate); err != nil {
		t.Fatalf("Go narrowing refuses TS attenuation: %v", err)
	}

	// Widened: the signature is genuine, the narrowing rule is what refuses it.
	widened := mandate.VerifyTaskMandate(toks.Widened, agentPub, provider, mandate.TaskVerifyOptions{})
	if !widened.Valid {
		t.Fatalf("widened token should verify as a single link: %s", widened.Reason)
	}
	if err := mandate.CheckTaskNarrowingMandates(root.Mandate, widened.Mandate); err == nil ||
		!strings.Contains(err.Error(), `child actionLimits["send-email"] (30) exceeds parent (3)`) {
		t.Fatalf("widened child not refused: %v", err)
	}

	// Tampered after signing.
	tampered := tamperTaskToken(t, toks.Child, func(m map[string]any) {
		m["taskConstraints"].(map[string]any)["actionLimits"] = map[string]any{"send-email": 100}
	})
	if r := mandate.VerifyTaskMandate(tampered, agentPub, "", mandate.TaskVerifyOptions{}); r.Valid || r.Reason != "Invalid signature" {
		t.Fatalf("tampered TS token: %+v", r)
	}
	// Expired.
	if r := mandate.VerifyTaskMandate(toks.Child, agentPub, "", mandate.TaskVerifyOptions{Now: time.Now().Add(2 * time.Hour)}); r.Valid || r.Reason != "Task mandate expired" {
		t.Fatalf("expired TS token: %+v", r)
	}
	// Over limit, and the room binding.
	req := mandate.TaskActionRequest{RequestedCapability: "send-email", HumanApproved: true, RoomID: "room-<&>", OnBehalfOf: provider}
	if _, err := mandate.EnforceTaskConstraints(toks.Child, agentPub, mandate.EnforceTaskOptions{TaskActionRequest: req, ExpectedGrantee: provider}); err != nil {
		t.Fatalf("within-limit request refused: %v", err)
	}
	req.CurrentActionCounts = map[string]float64{"send-email": 1}
	var v *mandate.TaskConstraintViolation
	if _, err := mandate.EnforceTaskConstraints(toks.Child, agentPub, mandate.EnforceTaskOptions{TaskActionRequest: req}); !errors.As(err, &v) || v.Code != mandate.TaskViolationActionLimitExceeded {
		t.Fatalf("over-limit: %v", err)
	}

	// Go attenuates the TS child; TS verifies the grandchild and its narrowing.
	parent, err := mandate.DecodeTaskToken(toks.Child)
	if err != nil {
		t.Fatal(err)
	}
	grand, err := mandate.AttenuateTaskMandate(parent, "did:aroha:executor", []string{"send-email"}, mandate.TaskConstraints{
		ActionLimits: map[string]float64{"send-email": 1},
		ComputeLimit: &mandate.ComputeLimit{LLMTokens: f64(100), WebRequests: f64(1)},
		DataAccess:   map[string]mandate.DataAccessLevel{"email": mandate.DataAccessWrite},
		HumanGates:   []string{"send-email"}, OutputHandling: mandate.OutputInternalOnly,
	}, providerKey, 5*time.Minute, mandate.TaskAttenuateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	verdict := runNode(t, `
const c = await import(process.env.ENTRY);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const parent = await c.verifyTaskMandate(process.env.PARENT, hex(process.env.AGENT_PUB));
const r = await c.verifyTaskMandate(process.env.TOKEN, hex(process.env.PROVIDER_PUB), "did:aroha:executor");
const narrowing = r.valid ? c.checkTaskNarrowing(parent.mandate, r.mandate) : "unverified";
process.stdout.write(JSON.stringify({ valid: r.valid, reason: r.reason ?? null, narrowing, tier: r.mandate?.mandateTier }));
`, map[string]string{"ENTRY": entry, "PARENT": toks.Child, "TOKEN": grand.Token,
		"AGENT_PUB": hexKey(agentPub), "PROVIDER_PUB": hexKey(providerKey.Public().(ed25519.PublicKey)), "PROVIDER_SEED": providerSeed})
	if !strings.Contains(verdict, `"valid":true`) || !strings.Contains(verdict, `"narrowing":null`) || !strings.Contains(verdict, `"tier":"execution"`) {
		t.Fatalf("Go grandchild rejected by TS: %s", verdict)
	}
}

func hexKey(k ed25519.PublicKey) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(k))
	for _, b := range k {
		out = append(out, digits[b>>4], digits[b&15])
	}
	return string(out)
}

// Go issues and attenuates; TypeScript verifies, narrowing-checks and
// enforces, and rejects tampered, widened, expired and over-limit cases.
func TestCrossLanguageTask_GoIssuedVerifiesInTS(t *testing.T) {
	entry := credentialsEntry(t)
	human, humanKey, _ := seedParty(t)
	agent, agentKey, _ := seedParty(t)
	provider, _, _ := seedParty(t)

	root, err := mandate.IssueTaskMandate(human, agent, []string{"search", "send-email"}, mandate.TaskConstraints{
		ActionLimits:   map[string]float64{"send-email": 2},
		ComputeLimit:   &mandate.ComputeLimit{LLMTokens: f64(5000), ExecutionTimeMs: f64(60000)},
		DataAccess:     map[string]mandate.DataAccessLevel{"email": mandate.DataAccessReadWrite, "calendar": mandate.DataAccessRead},
		HumanGates:     []string{"send-email"},
		ReversibleOnly: true,
		RoomID:         "room-1", OnBehalfOf: provider,
	}, humanKey, time.Hour, mandate.TaskIssueOptions{
		SpendingConstraints: &mandate.SpendingConstraints{SpendLimitUSD: 42.07, AllowedMerchants: []string{"did:aroha:m-<&>"}},
		Invariants:          &mandate.MandateInvariants{Payee: []string{"did:aroha:m-<&>"}, Parameters: map[string]any{"dest": "JFK", "n": 2, "rt": true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	child, err := mandate.AttenuateTaskMandate(root, provider, []string{"send-email"}, mandate.TaskConstraints{
		ActionLimits:   map[string]float64{"send-email": 1},
		ComputeLimit:   &mandate.ComputeLimit{LLMTokens: f64(500), ExecutionTimeMs: f64(1000)},
		DataAccess:     map[string]mandate.DataAccessLevel{"email": mandate.DataAccessWrite},
		HumanGates:     []string{"send-email"},
		ReversibleOnly: true,
	}, agentKey, 0, mandate.TaskAttenuateOptions{
		SpendingConstraints: &mandate.SpendingConstraints{SpendLimitUSD: 10, AllowedMerchants: []string{"did:aroha:m-<&>"}},
		Invariants:          &mandate.MandateInvariants{Payee: []string{"did:aroha:m-<&>"}, Parameters: map[string]any{"dest": "JFK", "n": 2, "rt": true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A dishonest Go delegator signs a widened child directly: its spend
	// limit exceeds the parent's.
	widened, err := mandate.IssueTaskMandate(agent, provider, []string{"send-email", "search"}, mandate.TaskConstraints{
		ActionLimits: map[string]float64{"send-email": 1},
		ComputeLimit: &mandate.ComputeLimit{LLMTokens: f64(500), ExecutionTimeMs: f64(1000)},
		DataAccess:   map[string]mandate.DataAccessLevel{"email": mandate.DataAccessWrite},
		HumanGates:   []string{"send-email"}, ReversibleOnly: true, RoomID: "room-1", OnBehalfOf: provider,
	}, agentKey, 10*time.Minute, mandate.TaskIssueOptions{
		SpendingConstraints: &mandate.SpendingConstraints{SpendLimitUSD: 900, AllowedMerchants: []string{"did:aroha:m-<&>"}},
		Invariants:          &mandate.MandateInvariants{Payee: []string{"did:aroha:m-<&>"}, Parameters: map[string]any{"dest": "JFK", "n": 2, "rt": true}},
		ParentMandateID:     root.Mandate.MandateID, Tier: mandate.TaskTierCart,
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := tamperTaskToken(t, child.Token, func(m map[string]any) { m["allowed"] = []any{"send-email", "search"} })

	verdict := runNode(t, `
const c = await import(process.env.ENTRY);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const human = hex(process.env.HUMAN_PUB), agent = hex(process.env.AGENT_PUB);
const root = await c.verifyTaskMandate(process.env.ROOT, human, process.env.AGENT);
const child = await c.verifyTaskMandate(process.env.CHILD, agent, process.env.PROVIDER);
const widened = await c.verifyTaskMandate(process.env.WIDENED, agent, process.env.PROVIDER);
const tampered = await c.verifyTaskMandate(process.env.TAMPERED, agent);
const expired = await c.verifyTaskMandate(process.env.CHILD, agent, undefined, { now: Date.now() + 7200000 });
const enforce = async (counts) => {
  try {
    await c.enforceTaskConstraints(process.env.CHILD, agent, { expectedGrantee: process.env.PROVIDER,
      requestedCapability: "send-email", humanApproved: true, capabilityReversibility: "semi",
      roomId: "room-1", onBehalfOf: process.env.PROVIDER, currentActionCounts: counts, dataAccess: { email: "write" } });
    return "ok";
  } catch (e) { return e.code ?? String(e); }
};
process.stdout.write(JSON.stringify({
  root: root.valid, rootType: root.mandate?.mandateType, child: child.valid, childReason: child.reason ?? null,
  childNarrowing: c.checkTaskNarrowing(root.mandate, child.mandate),
  widenedSig: widened.valid, widenedNarrowing: c.checkTaskNarrowing(root.mandate, widened.mandate),
  tampered: tampered.reason ?? "valid", expired: expired.reason ?? "valid",
  withinLimit: await enforce({ "send-email": 0 }), overLimit: await enforce({ "send-email": 1 }),
}));
`, map[string]string{"ENTRY": entry, "ROOT": root.Token, "CHILD": child.Token, "WIDENED": widened.Token, "TAMPERED": tampered,
		"HUMAN_PUB": hexKey(humanKey.Public().(ed25519.PublicKey)), "AGENT_PUB": hexKey(agentKey.Public().(ed25519.PublicKey)),
		"AGENT": agent, "PROVIDER": provider})
	var v struct {
		Root             bool    `json:"root"`
		RootType         string  `json:"rootType"`
		Child            bool    `json:"child"`
		ChildReason      *string `json:"childReason"`
		ChildNarrowing   *string `json:"childNarrowing"`
		WidenedSig       bool    `json:"widenedSig"`
		WidenedNarrowing *string `json:"widenedNarrowing"`
		Tampered         string  `json:"tampered"`
		Expired          string  `json:"expired"`
		WithinLimit      string  `json:"withinLimit"`
		OverLimit        string  `json:"overLimit"`
	}
	if err := json.Unmarshal([]byte(verdict), &v); err != nil {
		t.Fatalf("%v: %s", err, verdict)
	}
	t.Logf("TS verdicts on Go tokens: %s", verdict)
	switch {
	case !v.Root || v.RootType != "hybrid":
		t.Fatalf("Go root rejected by TS: %s", verdict)
	case !v.Child || v.ChildNarrowing != nil:
		t.Fatalf("Go child rejected by TS: %s", verdict)
	case !v.WidenedSig || v.WidenedNarrowing == nil || !strings.Contains(*v.WidenedNarrowing, "child spendLimitUsd (900) exceeds parent (42.07)"):
		t.Fatalf("Go widened child not refused by TS narrowing: %s", verdict)
	case v.Tampered != "Invalid signature":
		t.Fatalf("tampered Go token: %s", verdict)
	case v.Expired != "Task mandate expired":
		t.Fatalf("expired Go token: %s", verdict)
	case v.WithinLimit != "ok" || v.OverLimit != mandate.TaskViolationActionLimitExceeded:
		t.Fatalf("TS enforcement of Go token: %s", verdict)
	}
}
