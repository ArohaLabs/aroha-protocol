// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

//go:build integration

// Cross-language mandate checks against the TypeScript reference.
//
//	go test -tags integration ./aroha/mandate/
//
// Needs node on PATH and a built @aroha-sdk/credentials (dist/ plus its
// node_modules). The package is looked up at $AROHA_CREDENTIALS_DIR, else
// ../../packages/aroha-credentials relative to the Go module. Skips when
// either is missing.

package mandate_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/mandate"
)

func credentialsEntry(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	dir := os.Getenv("AROHA_CREDENTIALS_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "..", "packages", "aroha-credentials")
	}
	entry, err := filepath.Abs(filepath.Join(dir, "dist", "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(entry); err != nil {
		t.Skipf("@aroha-sdk/credentials is not built at %s", entry)
	}
	return (&url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(strings.TrimPrefix(entry, "/"))}).String()
}

func runNode(t *testing.T, script string, env map[string]string) string {
	t.Helper()
	cmd := exec.Command("node", "--input-type=module", "-e", script)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// stdout only: the reference writes advisories (e.g. "ran without
	// isRevoked") to stderr, and they must not be parsed as the result.
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s%s", err, out, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

func seedParty(t *testing.T) (string, ed25519.PrivateKey, string) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return identity.DIDFromPublicKey(priv.Public().(ed25519.PublicKey)), priv, hex.EncodeToString(priv.Seed())
}

// TS issues intent → cart; Go verifies the chain and attenuates further.
func TestCrossLanguage_TSIssuedTokenVerifiesInGo(t *testing.T) {
	entry := credentialsEntry(t)
	human, _, humanSeed := seedParty(t)
	agent, _, agentSeed := seedParty(t)
	provider, providerKey, _ := seedParty(t)

	token := runNode(t, `
const c = await import(process.env.ENTRY);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const intent = await c.issueIntentMandate(process.env.HUMAN, process.env.AGENT,
  { spendLimitUsd: 500, sessionLimitUsd: 200.5, requireHumanApprovalAboveUsd: 100,
    allowedMerchants: ["did:aroha:m-<&>"], validUntil: "2099-01-01T00:00:00.000Z" },
  hex(process.env.HUMAN_SEED), 3600000);
const cart = await c.attenuateToCart(intent, process.env.PROVIDER,
  { spendLimitUsd: 42.07, allowedMerchants: ["did:aroha:m-<&>"] }, hex(process.env.AGENT_SEED));
process.stdout.write(cart.token);
`, map[string]string{"ENTRY": entry, "HUMAN": human, "AGENT": agent, "PROVIDER": provider,
		"HUMAN_SEED": humanSeed, "AGENT_SEED": agentSeed})

	r := mandate.VerifyMandateChain(token, nil, mandate.ChainOptions{
		CheckOptions: mandate.CheckOptions{ExpectedRoot: human}, ExpectedGrantee: provider,
	})
	if !r.Valid || len(r.Chain) != 2 {
		t.Fatalf("TS token rejected by Go: %+v", r)
	}
	if r.Mandate.IssuedAt == "" || r.Mandate.Constraints.SessionLimitUSD == nil || *r.Mandate.Constraints.SessionLimitUSD != 200.5 {
		t.Errorf("leaf = %+v", r.Mandate)
	}

	parent, err := mandate.DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	payment, err := mandate.AttenuateToPayment(parent, "did:aroha:m-<&>",
		mandate.SpendingConstraints{SpendLimitUSD: 10, AllowedMerchants: []string{"did:aroha:m-<&>"}}, providerKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	// …and TS verifies the Go-extended chain.
	verdict := runNode(t, `
const c = await import(process.env.ENTRY);
const r = await c.verifyMandateChain(process.env.TOKEN, undefined, { expectedRoot: process.env.HUMAN });
process.stdout.write(JSON.stringify({ valid: r.valid, reason: r.reason ?? null, links: r.chain ? r.chain.length : 0 }));
`, map[string]string{"ENTRY": entry, "TOKEN": payment.Token, "HUMAN": human})
	var v struct {
		Valid  bool    `json:"valid"`
		Reason *string `json:"reason"`
		Links  int     `json:"links"`
	}
	if err := json.Unmarshal([]byte(verdict), &v); err != nil {
		t.Fatalf("%v: %s", err, verdict)
	}
	if !v.Valid || v.Links != 3 {
		t.Fatalf("Go-extended token rejected by TS: %s", verdict)
	}
}

// Go issues a chain; TS verifies it.
func TestCrossLanguage_GoIssuedTokenVerifiesInTS(t *testing.T) {
	entry := credentialsEntry(t)
	human, humanKey, _ := seedParty(t)
	agent, agentKey, _ := seedParty(t)
	cat := "travel"
	intent, err := mandate.IssueIntent(human, agent, mandate.SpendingConstraints{
		SpendLimitUSD: 1e21, RequireHumanApprovalAboveUSD: ptr(0.1), MerchantCategory: &cat,
		ValidFrom: time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05.000Z"),
	}, humanKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cart, err := mandate.AttenuateToCart(intent, "did:aroha:shop",
		mandate.SpendingConstraints{SpendLimitUSD: 1e-7, MerchantCategory: &cat}, agentKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	verdict := runNode(t, `
const c = await import(process.env.ENTRY);
const r = await c.verifyMandateChain(process.env.TOKEN, undefined, { expectedRoot: process.env.HUMAN, expectedGrantee: "did:aroha:shop" });
process.stdout.write(JSON.stringify({ valid: r.valid, reason: r.reason ?? null }));
`, map[string]string{"ENTRY": entry, "TOKEN": cart.Token, "HUMAN": human})
	if !strings.Contains(verdict, `"valid":true`) {
		t.Fatalf("Go token rejected by TS: %s", verdict)
	}
}
