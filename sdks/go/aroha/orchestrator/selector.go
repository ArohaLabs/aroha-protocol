// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"
)

// DefaultWeights are the standard 5-dimension scoring weights.
var DefaultWeights = map[string]float64{
	"price":        0.35,
	"reputation":   0.30,
	"latency":      0.15,
	"preference":   0.15,
	"availability": 0.05,
}

// AgentOffer holds a candidate's response and computed score.
type AgentOffer struct {
	AgentDID      string
	AgentEndpoint string
	Response      map[string]any
	Price         *float64 // nil if agent did not report a price
	LatencyMs     float64
	Score         float64
}

// SelectionResult is returned from AgentSelector.Select.
type SelectionResult struct {
	Winner *AgentOffer
	Ranked []*AgentOffer
}

// AgentSelector fans out ArohaRequests, collects responses, and returns a ranked list.
type AgentSelector struct {
	client            *transport.ArohaClient
	orchestratorDID   string
	orchestratorKeyID string
	privateKey        ed25519.PrivateKey
}

// NewAgentSelector creates an AgentSelector.
func NewAgentSelector(
	client *transport.ArohaClient,
	orchestratorDID, orchestratorKeyID string,
	privateKey ed25519.PrivateKey,
) *AgentSelector {
	return &AgentSelector{
		client:            client,
		orchestratorDID:   orchestratorDID,
		orchestratorKeyID: orchestratorKeyID,
		privateKey:        privateKey,
	}
}

// SelectOptions controls the fan-out behaviour.
type SelectOptions struct {
	Weights          map[string]float64 // nil → DefaultWeights
	PreferenceScores map[string]float64 // per-DID 0-1 boost; nil → 0.5 for all
	BlockedAgents    []string
	FanOutTimeout    time.Duration // default 5s
}

// Select fans out to all eligible candidates and returns the winner.
//
// candidates must be a list of maps with at least "did", "endpoint";
// optionally "reputation" (int, 0–10000, default 5000).
func (s *AgentSelector) Select(
	capability string,
	params map[string]any,
	candidates []map[string]any,
	opts *SelectOptions,
) (*SelectionResult, error) {
	if opts == nil {
		opts = &SelectOptions{}
	}
	w := DefaultWeights
	if opts.Weights != nil {
		w = opts.Weights
	}
	pref := opts.PreferenceScores
	if pref == nil {
		pref = map[string]float64{}
	}
	timeout := opts.FanOutTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	blocked := make(map[string]bool, len(opts.BlockedAgents))
	for _, d := range opts.BlockedAgents {
		blocked[d] = true
	}

	var eligible []map[string]any
	for _, c := range candidates {
		if did, _ := c["did"].(string); !blocked[did] {
			eligible = append(eligible, c)
		}
	}
	if len(eligible) == 0 {
		return nil, fmt.Errorf("no eligible agents for capability: %s", capability)
	}

	correlationID := messages.NewCorrelationID()

	// Fan-out in parallel
	type result struct {
		offer *AgentOffer
	}
	resultCh := make(chan result, len(eligible))
	var wg sync.WaitGroup
	for _, agent := range eligible {
		wg.Add(1)
		go func(a map[string]any) {
			defer wg.Done()
			offer := s.sendRequest(a, capability, params, correlationID, timeout)
			resultCh <- result{offer}
		}(agent)
	}
	wg.Wait()
	close(resultCh)

	var offers []*AgentOffer
	for r := range resultCh {
		if r.offer != nil {
			offers = append(offers, r.offer)
		}
	}
	if len(offers) == 0 {
		return nil, fmt.Errorf("no agents responded for capability: %s", capability)
	}

	scored := s.scoreOffers(offers, eligible, w, pref)
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})
	return &SelectionResult{Winner: scored[0], Ranked: scored}, nil
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (s *AgentSelector) sendRequest(
	agent map[string]any,
	capability string,
	params map[string]any,
	correlationID string,
	timeout time.Duration,
) *AgentOffer {
	did, _ := agent["did"].(string)
	endpoint, _ := agent["endpoint"].(string)

	env, err := messages.BuildDefault(
		messages.TypeRequest, s.orchestratorDID, did,
		map[string]any{"capability": capability, "params": params},
		correlationID, s.privateKey, s.orchestratorKeyID)
	if err != nil {
		return nil
	}

	start := time.Now()
	resp, err := s.client.SendWithTimeout(endpoint, env, timeout)
	if err != nil || resp == nil {
		return nil
	}
	if msgType, _ := resp["type"].(string); msgType == messages.TypeError {
		return nil
	}
	latencyMs := float64(time.Since(start).Milliseconds())

	body, _ := resp["body"].(map[string]any)
	bodyResult, _ := body["result"].(map[string]any)

	var price *float64
	for _, key := range []string{"price", "totalPrice"} {
		if v, ok := bodyResult[key]; ok {
			if f := toFloat64(v); f != nil {
				price = f
				break
			}
		}
	}

	return &AgentOffer{
		AgentDID:      did,
		AgentEndpoint: endpoint,
		Response:      resp,
		Price:         price,
		LatencyMs:     latencyMs,
	}
}

func (s *AgentSelector) scoreOffers(
	offers []*AgentOffer,
	candidates []map[string]any,
	w map[string]float64,
	pref map[string]float64,
) []*AgentOffer {
	var prices []float64
	for _, o := range offers {
		if o.Price != nil {
			prices = append(prices, *o.Price)
		}
	}
	minPrice, maxPrice := minMax(prices)

	var latencies []float64
	for _, o := range offers {
		latencies = append(latencies, o.LatencyMs)
	}
	minLat, maxLat := minMax(latencies)

	repByDID := make(map[string]float64, len(candidates))
	for _, c := range candidates {
		did, _ := c["did"].(string)
		rep := 5000.0
		if r := toFloat64(c["reputation"]); r != nil {
			rep = *r
		}
		repByDID[did] = rep
	}

	for _, o := range offers {
		priceScore := 1.0
		if o.Price != nil {
			priceScore = norm(maxPrice-*o.Price, 0, maxPrice-minPrice)
		}
		rep := repByDID[o.AgentDID] / 10_000.0
		latScore := norm(maxLat-o.LatencyMs, 0, maxLat-minLat)
		prefScore := 0.5
		if ps, ok := pref[o.AgentDID]; ok {
			prefScore = ps
		}

		o.Score = priceScore*w["price"] +
			rep*w["reputation"] +
			latScore*w["latency"] +
			prefScore*w["preference"] +
			1.0*w["availability"]
	}
	return offers
}

func norm(v, lo, hi float64) float64 {
	if hi == lo {
		return 1.0
	}
	return (v - lo) / (hi - lo)
}

func minMax(vals []float64) (min, max float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	min, max = vals[0], vals[0]
	for _, v := range vals[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return
}

func toFloat64(v any) *float64 {
	switch n := v.(type) {
	case float64:
		return &n
	case float32:
		f := float64(n)
		return &f
	case int:
		f := float64(n)
		return &f
	case int64:
		f := float64(n)
		return &f
	}
	return nil
}
