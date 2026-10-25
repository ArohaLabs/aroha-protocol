// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package orchestrator implements Aroha Layer 4 — Orchestration Primitives.
//
// SagaEngine: atomic multi-step transactions (reserve → commit → compensate).
// AgentSelector: fan-out, scoring, and ranking of candidate agents.
package orchestrator

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"
	"github.com/google/uuid"
)

// SagaState represents a saga step's lifecycle state.
type SagaState string

const (
	StatePending   SagaState = "PENDING"
	StateReserved  SagaState = "RESERVED"
	StateCommitted SagaState = "COMMITTED"
	StateCancelled SagaState = "CANCELLED"
	StateFailed    SagaState = "FAILED"
)

// SagaStep is one participant in a saga.
type SagaStep struct {
	AgentDID       string
	AgentEndpoint  string
	Capability     string
	Params         map[string]any
	HoldDurationMs int

	// Set by the engine
	StepID               int
	State                SagaState
	ReservationToken     string
	ReservationExpiresAt string
	CommitResult         map[string]any
	Error                string
}

// SagaResult is returned from SagaEngine.Execute.
type SagaResult struct {
	Success  bool
	SagaID   string
	Results  map[int]map[string]any
	Failures []map[string]any
}

// SagaEngine executes atomic multi-agent transactions.
//
//	Phase 1 — RESERVE: all participants in parallel
//	Phase 2 — COMMIT:  all participants sequentially (only if all reserved)
//	Phase 3 — COMPENSATE: LIFO ArohaCancel on any failure
type SagaEngine struct {
	client            *transport.ArohaClient
	orchestratorDID   string
	orchestratorKeyID string
	privateKey        ed25519.PrivateKey
}

// NewSagaEngine creates a SagaEngine.
func NewSagaEngine(
	client *transport.ArohaClient,
	orchestratorDID, orchestratorKeyID string,
	privateKey ed25519.PrivateKey,
) *SagaEngine {
	return &SagaEngine{
		client:            client,
		orchestratorDID:   orchestratorDID,
		orchestratorKeyID: orchestratorKeyID,
		privateKey:        privateKey,
	}
}

// Execute runs a saga across the given participants.
func (e *SagaEngine) Execute(participants []*SagaStep) (*SagaResult, error) {
	sagaID := "saga-" + uuid.New().String()
	correlationID := messages.NewCorrelationID()

	for i, step := range participants {
		step.StepID = i
		if step.HoldDurationMs == 0 {
			step.HoldDurationMs = 300_000
		}
	}

	// ── Phase 1: RESERVE (parallel) ───────────────────────────────────────────
	var wg sync.WaitGroup
	for _, step := range participants {
		wg.Add(1)
		go func(s *SagaStep) {
			defer wg.Done()
			e.reserve(s, correlationID)
		}(step)
	}
	wg.Wait()

	allReserved := true
	for _, s := range participants {
		if s.State != StateReserved {
			allReserved = false
			break
		}
	}

	if !allReserved {
		e.compensate(participants, correlationID)
		failures := collectFailures(participants)
		return &SagaResult{Success: false, SagaID: sagaID, Failures: failures}, nil
	}

	// ── Phase 2: COMMIT (sequential) ──────────────────────────────────────────
	for _, step := range participants {
		ack, err := e.commit(step, correlationID)
		if err != nil {
			step.State = StateFailed
			step.Error = err.Error()
			e.compensate(participants, correlationID)
			return &SagaResult{
				Success:  false,
				SagaID:   sagaID,
				Failures: []map[string]any{{"stepId": step.StepID, "reason": step.Error}},
			}, nil
		}
		step.State = StateCommitted
		if result, ok := ack["result"].(map[string]any); ok {
			step.CommitResult = result
		}
	}

	results := make(map[int]map[string]any, len(participants))
	for _, s := range participants {
		if s.CommitResult != nil {
			results[s.StepID] = s.CommitResult
		} else {
			results[s.StepID] = map[string]any{}
		}
	}
	return &SagaResult{Success: true, SagaID: sagaID, Results: results}, nil
}

// ── Phase Implementations ─────────────────────────────────────────────────────

func (e *SagaEngine) reserve(step *SagaStep, correlationID string) {
	body := map[string]any{
		"capability":     step.Capability,
		"params":         step.Params,
		"holdDurationMs": step.HoldDurationMs,
	}
	env, err := messages.BuildDefault(
		messages.TypeReserve, e.orchestratorDID, step.AgentDID,
		body, correlationID, e.privateKey, e.orchestratorKeyID)
	if err != nil {
		step.State = StateFailed
		step.Error = "build envelope: " + err.Error()
		return
	}

	resp, err := e.client.Send(step.AgentEndpoint, env)
	if err != nil {
		step.State = StateFailed
		step.Error = err.Error()
		return
	}
	if resp == nil {
		step.State = StateFailed
		step.Error = "no response from " + step.AgentDID
		return
	}
	if msgType, _ := resp["type"].(string); msgType == messages.TypeError {
		b, _ := resp["body"].(map[string]any)
		step.State = StateFailed
		step.Error, _ = b["message"].(string)
		return
	}

	respBody, _ := resp["body"].(map[string]any)
	step.ReservationToken, _ = respBody["reservationToken"].(string)
	step.ReservationExpiresAt, _ = respBody["expiresAt"].(string)
	step.State = StateReserved
}

func (e *SagaEngine) commit(step *SagaStep, correlationID string) (map[string]any, error) {
	env, err := messages.BuildDefault(
		messages.TypeCommit, e.orchestratorDID, step.AgentDID,
		map[string]any{"reservationToken": step.ReservationToken},
		correlationID, e.privateKey, e.orchestratorKeyID)
	if err != nil {
		return nil, fmt.Errorf("build envelope: %w", err)
	}
	resp, err := e.client.Send(step.AgentEndpoint, env)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("no response from %s", step.AgentDID)
	}
	if msgType, _ := resp["type"].(string); msgType == messages.TypeError {
		b, _ := resp["body"].(map[string]any)
		msg, _ := b["message"].(string)
		return nil, fmt.Errorf("%s", msg)
	}
	body, _ := resp["body"].(map[string]any)
	return body, nil
}

func (e *SagaEngine) compensate(steps []*SagaStep, correlationID string) {
	// LIFO order
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		if s.State != StateReserved && s.State != StateCommitted {
			continue
		}
		env, err := messages.BuildDefault(
			messages.TypeCancel, e.orchestratorDID, s.AgentDID,
			map[string]any{
				"reservationToken": s.ReservationToken,
				"reason":           "Saga compensation — rolling back",
			},
			correlationID, e.privateKey, e.orchestratorKeyID)
		if err != nil {
			continue
		}
		e.client.Send(s.AgentEndpoint, env) //nolint:errcheck
		s.State = StateCancelled
	}
}

func collectFailures(steps []*SagaStep) []map[string]any {
	var out []map[string]any
	for _, s := range steps {
		if s.State == StateFailed {
			reason := s.Error
			if reason == "" {
				reason = "reserve failed"
			}
			out = append(out, map[string]any{"stepId": s.StepID, "reason": reason})
		}
	}
	return out
}
