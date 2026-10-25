// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package mandate

import "testing"

// A task mandate must never pass as a spending mandate, whatever else it
// carries: the tiers overlap and a v1 task signature covers the same bytes.
func TestCheckMandateShapeRefusesTaskMandates(t *testing.T) {
	body := map[string]any{
		"mandateTier": "intent",
		"constraints": map[string]any{"spendLimitUsd": 100.0},
		"grantor":     "did:aroha:zA",
		"grantee":     "did:aroha:zB",
		"mandateId":   "m1",
		"issuedAt":    "2026-01-01T00:00:00.000Z",
		"expiresAt":   "2027-01-01T00:00:00.000Z",
	}
	const want = "mandateType present: this is a task mandate, not a spending mandate"
	if got := checkMandateShape(body); got == want {
		t.Fatalf("a spending body without mandateType was refused as a task mandate")
	}
	for _, typ := range []string{"task", "hybrid"} {
		withType := map[string]any{"mandateType": typ}
		for k, v := range body {
			withType[k] = v
		}
		if got := checkMandateShape(withType); got != want {
			t.Fatalf("mandateType %q: got %q, want %q", typ, got, want)
		}
	}
}
