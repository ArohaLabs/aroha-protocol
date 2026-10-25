// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package mandate_test

// Task mandates against vectors the TypeScript reference generated:
//   - packages/aroha-credentials/test-vectors/task-mandate-v2.json
//     (scripts/gen-task-mandate-vectors.ts): signing payloads, signatures,
//     and the verdict, reason and code of verifyTaskMandate,
//     checkTaskNarrowing and checkTaskConstraints on every case;
//   - spec-public/vectors/conversation-v1.json "taskMandateV2": a guest grant
//     whose token Go must reproduce byte for byte.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/mandate"
)

type taskVectorFile struct {
	Keys map[string]struct {
		PrivateKeyHex string `json:"privateKeyHex"`
		PublicKeyHex  string `json:"publicKeyHex"`
		DID           string `json:"did"`
	} `json:"keys"`
	Mandates []struct {
		Name                   string          `json:"name"`
		Signer                 string          `json:"signer"`
		Mandate                json.RawMessage `json:"mandate"`
		ExpectedSigningPayload string          `json:"expectedSigningPayload"`
		ExpectedSignature      string          `json:"expectedSignature"`
		Token                  string          `json:"token"`
	} `json:"mandates"`
	Tokens []struct {
		Name            string `json:"name"`
		Token           string `json:"token"`
		Signer          string `json:"signer"`
		Now             string `json:"now"`
		ExpectedGrantee string `json:"expectedGrantee"`
		Valid           bool   `json:"valid"`
		Reason          string `json:"reason"`
	} `json:"tokens"`
	Narrowing []struct {
		Name   string          `json:"name"`
		Parent string          `json:"parent"`
		Child  json.RawMessage `json:"child"`
		Valid  bool            `json:"valid"`
		Reason string          `json:"reason"`
	} `json:"narrowing"`
	Requests []struct {
		Name    string          `json:"name"`
		Mandate string          `json:"mandate"`
		Request json.RawMessage `json:"request"`
		Allowed bool            `json:"allowed"`
		Code    string          `json:"code"`
		Reason  string          `json:"reason"`
	} `json:"requests"`
}

func loadTaskVectors(t *testing.T) *taskVectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "packages", "aroha-credentials", "test-vectors", "task-mandate-v2.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("task-mandate vectors not available: %v", err)
	}
	var v taskVectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func (v *taskVectorFile) privateKey(t *testing.T, name string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(v.Keys[name].PrivateKeyHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("key %s: bad seed", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func (v *taskVectorFile) body(t *testing.T, name string) mandate.TaskMandate {
	t.Helper()
	for _, m := range v.Mandates {
		if m.Name == name {
			var tm mandate.TaskMandate
			if err := json.Unmarshal(m.Mandate, &tm); err != nil {
				t.Fatal(err)
			}
			return tm
		}
	}
	t.Fatalf("no mandate %q", name)
	return mandate.TaskMandate{}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// sameDataModel reports whether two JSON texts decode to the same value.
func sameDataModel(t *testing.T, a, b []byte) bool {
	t.Helper()
	va, err := jcs.Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	vb, err := jcs.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(va, vb)
}

func decodeToken(t *testing.T, token string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTaskVectors_SigningPayloadsAndSignatures(t *testing.T) {
	v := loadTaskVectors(t)
	for _, mv := range v.Mandates {
		t.Run(mv.Name, func(t *testing.T) {
			raw, err := jcs.Parse(mv.Mandate)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := mandate.TaskMandateSigningPayloadV2(raw)
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) != mv.ExpectedSigningPayload {
				t.Fatalf("signing payload differs\n got %s\nwant %s", payload, mv.ExpectedSigningPayload)
			}
			// The same payload from the typed struct (what Go signs at issuance).
			body := v.body(t, mv.Name)
			typed, err := mandate.TaskMandateSigningPayloadV2(body)
			if err != nil || string(typed) != mv.ExpectedSigningPayload {
				t.Fatalf("typed payload differs: %v\n got %s", err, typed)
			}

			// Go issuance of the same body reproduces the signature, and a
			// token with the same content.
			var ttl time.Duration
			opts := mandate.TaskIssueOptions{
				Blocked:             body.Blocked,
				SpendingConstraints: body.SpendingConstraints,
				Tier:                body.MandateTier,
				Invariants:          body.Invariants,
				IssuedAt:            mustTime(t, body.IssuedAt),
				ExpiresAt:           mustTime(t, body.ExpiresAt),
				MandateID:           body.MandateID,
			}
			if body.ParentMandateID != nil {
				opts.ParentMandateID = *body.ParentMandateID
			}
			sm, err := mandate.IssueTaskMandate(body.Grantor, body.Grantee, body.Allowed, body.TaskConstraints,
				v.privateKey(t, mv.Signer), ttl, opts)
			if err != nil {
				t.Fatal(err)
			}
			if sm.Signature != mv.ExpectedSignature {
				t.Fatalf("signature differs\n got %s\nwant %s", sm.Signature, mv.ExpectedSignature)
			}
			if !sameDataModel(t, decodeToken(t, sm.Token), decodeToken(t, mv.Token)) {
				t.Fatalf("Go token content differs from the TypeScript token")
			}
		})
	}
}

func TestTaskVectors_TokenVerdicts(t *testing.T) {
	v := loadTaskVectors(t)
	for _, tv := range v.Tokens {
		t.Run(tv.Name, func(t *testing.T) {
			pub := v.privateKey(t, tv.Signer).Public().(ed25519.PublicKey)
			r := mandate.VerifyTaskMandate(tv.Token, pub, tv.ExpectedGrantee, mandate.TaskVerifyOptions{Now: mustTime(t, tv.Now)})
			if r.Valid != tv.Valid {
				t.Fatalf("valid = %v (%s), TypeScript says %v (%s)", r.Valid, r.Reason, tv.Valid, tv.Reason)
			}
			if r.Reason != tv.Reason {
				t.Fatalf("reason\n got %q\nwant %q", r.Reason, tv.Reason)
			}
		})
	}
}

type narrowingChildJSON struct {
	Allowed             []string                     `json:"allowed"`
	Blocked             []string                     `json:"blocked"`
	TaskConstraints     mandate.TaskConstraints      `json:"taskConstraints"`
	SpendingConstraints *mandate.SpendingConstraints `json:"spendingConstraints"`
	Invariants          *mandate.MandateInvariants   `json:"invariants"`
	ExpiresAt           string                       `json:"expiresAt"`
}

func TestTaskVectors_Narrowing(t *testing.T) {
	v := loadTaskVectors(t)
	for _, nv := range v.Narrowing {
		t.Run(nv.Name, func(t *testing.T) {
			parent := v.body(t, nv.Parent)
			var c narrowingChildJSON
			if err := json.Unmarshal(nv.Child, &c); err != nil {
				t.Fatal(err)
			}
			err := mandate.CheckTaskNarrowing(&parent, mandate.TaskNarrowingChild{
				Allowed: c.Allowed, Blocked: c.Blocked, TaskConstraints: c.TaskConstraints,
				SpendingConstraints: c.SpendingConstraints, Invariants: c.Invariants, ExpiresAt: c.ExpiresAt,
			})
			if (err == nil) != nv.Valid {
				t.Fatalf("narrowing ok = %v (%v), TypeScript says %v (%s)", err == nil, err, nv.Valid, nv.Reason)
			}
			if err != nil && err.Error() != nv.Reason {
				t.Fatalf("reason\n got %q\nwant %q", err.Error(), nv.Reason)
			}
		})
	}
}

type requestJSON struct {
	RequestedCapability string             `json:"requestedCapability"`
	CurrentActionCounts map[string]float64 `json:"currentActionCounts"`
	CurrentCompute      *struct {
		LLMTokens   float64 `json:"llmTokens"`
		WebRequests float64 `json:"webRequests"`
		WallClockMs float64 `json:"wallClockMs"`
	} `json:"currentCompute"`
	CapabilityReversibility string                             `json:"capabilityReversibility"`
	DataAccess              map[string]mandate.DataAccessLevel `json:"dataAccess"`
	HumanApproved           bool                               `json:"humanApproved"`
	RoomID                  string                             `json:"roomId"`
	OnBehalfOf              string                             `json:"onBehalfOf"`
}

func (r requestJSON) toRequest() mandate.TaskActionRequest {
	req := mandate.TaskActionRequest{
		RequestedCapability:     r.RequestedCapability,
		CurrentActionCounts:     r.CurrentActionCounts,
		CapabilityReversibility: r.CapabilityReversibility,
		DataAccess:              r.DataAccess,
		HumanApproved:           r.HumanApproved,
		RoomID:                  r.RoomID,
		OnBehalfOf:              r.OnBehalfOf,
	}
	if r.CurrentCompute != nil {
		req.CurrentCompute = &mandate.ComputeUsage{
			LLMTokens: r.CurrentCompute.LLMTokens, WebRequests: r.CurrentCompute.WebRequests, WallClockMs: r.CurrentCompute.WallClockMs,
		}
	}
	return req
}

func TestTaskVectors_Requests(t *testing.T) {
	v := loadTaskVectors(t)
	for _, rv := range v.Requests {
		t.Run(rv.Name, func(t *testing.T) {
			m := v.body(t, rv.Mandate)
			var r requestJSON
			if err := json.Unmarshal(rv.Request, &r); err != nil {
				t.Fatal(err)
			}
			viol := mandate.CheckTaskConstraints(&m, r.toRequest())
			if (viol == nil) != rv.Allowed {
				t.Fatalf("allowed = %v (%v), TypeScript says %v (%s)", viol == nil, viol, rv.Allowed, rv.Reason)
			}
			if viol != nil && (viol.Code != rv.Code || viol.Message != rv.Reason) {
				t.Fatalf("violation\n got %s %q\nwant %s %q", viol.Code, viol.Message, rv.Code, rv.Reason)
			}
		})
	}
}

// The token Go issues for the conversation profile's guest grant is the
// TypeScript token, byte for byte.
func TestTaskVectors_ConversationGuestGrantToken(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "spec-public", "vectors", "conversation-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("conversation vectors not available: %v", err)
	}
	var f struct {
		Keys map[string]struct {
			PrivateKeyHex string `json:"privateKeyHex"`
		} `json:"keys"`
		Task struct {
			Mandate                json.RawMessage `json:"mandate"`
			ExpectedSigningPayload string          `json:"expectedSigningPayload"`
			Signature              string          `json:"signature"`
			Token                  string          `json:"token"`
			Requests               []struct {
				Request json.RawMessage `json:"request"`
				Allowed bool            `json:"allowed"`
				Code    string          `json:"code"`
			} `json:"requests"`
		} `json:"taskMandateV2"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(f.Keys["host"].PrivateKeyHex)
	host := ed25519.NewKeyFromSeed(seed)
	var body mandate.TaskMandate
	if err := json.Unmarshal(f.Task.Mandate, &body); err != nil {
		t.Fatal(err)
	}
	sm, err := mandate.IssueTaskMandate(body.Grantor, body.Grantee, body.Allowed, body.TaskConstraints, host, 0, mandate.TaskIssueOptions{
		IssuedAt: mustTime(t, body.IssuedAt), ExpiresAt: mustTime(t, body.ExpiresAt), MandateID: body.MandateID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sm.Signature != f.Task.Signature {
		t.Fatalf("signature differs: %s", sm.Signature)
	}
	if sm.Token != f.Task.Token {
		t.Fatalf("token differs\n got %s\nwant %s", decodeToken(t, sm.Token), decodeToken(t, f.Task.Token))
	}
	payload, _ := mandate.TaskMandateSigningPayloadV2(sm.Mandate)
	if !bytes.Equal(payload, []byte(f.Task.ExpectedSigningPayload)) {
		t.Fatalf("payload differs: %s", payload)
	}

	r := mandate.VerifyTaskMandate(f.Task.Token, host.Public().(ed25519.PublicKey), body.Grantee,
		mandate.TaskVerifyOptions{Now: mustTime(t, body.IssuedAt).Add(time.Minute)})
	if !r.Valid {
		t.Fatalf("vector token rejected: %s", r.Reason)
	}
	for i, rq := range f.Task.Requests {
		var req requestJSON
		if err := json.Unmarshal(rq.Request, &req); err != nil {
			t.Fatal(err)
		}
		viol := mandate.CheckTaskConstraints(r.Mandate, req.toRequest())
		if (viol == nil) != rq.Allowed || (viol != nil && viol.Code != rq.Code) {
			t.Fatalf("request %d: got %v, want allowed=%v code=%s", i, viol, rq.Allowed, rq.Code)
		}
	}
}
