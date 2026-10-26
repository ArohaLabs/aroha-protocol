// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package reputation implements the Aroha Bayesian Beta reputation model (v1.1).
//
// 12-signal model with Thompson Sampling for Multi-Armed Bandit agent selection.
//
// References:
//
//	Jøsang & Ismail (2002) "The Beta Reputation System" BLED Conf.
//	Agrawal & Goyal (2012) "Analysis of Thompson Sampling for MAB" COLT.
//	Lai & Robbins (1985) "Asymptotically efficient adaptive allocation rules".
package reputation

import (
	"encoding/json"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// ── Constants ──────────────────────────────────────────────────────────────────

const (
	jeffreysPrior        = 0.5
	successHalfLifeDays  = 180.0
	failureHalfLifeDays  = 60.0
	rhrHalfLifeDays      = 30.0
	dormancyHalfLifeDays = 365.0

	muBaseline = 2.0
	muRHR      = 2.0
	muDSL      = 2.0
	muFSS      = 1.5
	muPAS      = 2.5
	muRRS      = 1.2
)

// ── Data structures ────────────────────────────────────────────────────────────

// SignalPair holds the Beta(α,β) posterior for a single binary signal.
type SignalPair struct {
	Alpha       float64 `json:"alpha"`
	Beta        float64 `json:"beta"`
	N           int     `json:"n"`
	LastUpdated string  `json:"lastUpdated"` // ISO8601
}

// WelfordStats accumulates a running mean/variance (Welford algorithm).
type WelfordStats struct {
	N           int     `json:"n"`
	Mean        float64 `json:"mean"`
	M2          float64 `json:"m2"`
	LastUpdated string  `json:"lastUpdated"`
}

// CompositeWeights defines the per-signal contribution to the composite score.
type CompositeWeights struct {
	Baseline float64
	RHR      float64
	PCR      float64
	DSL      float64
	CLS      float64
	SAS      float64
	FSS      float64
	PAS      float64
	RSS      float64
	RRS      float64
	CS       float64
	PPS      float64
}

// DefaultWeights are the Aroha v1.1 composite weights (sum = 1.00).
var DefaultWeights = CompositeWeights{
	Baseline: 0.18,
	RHR:      0.18,
	PCR:      0.10,
	DSL:      0.08,
	CLS:      0.07,
	SAS:      0.05,
	FSS:      0.10,
	PAS:      0.08,
	RSS:      0.06,
	RRS:      0.04,
	CS:       0.04,
	PPS:      0.02,
}

// ReputationState holds the full 12-signal model for one (agent, domain) pair.
type ReputationState struct {
	AgentDID          string       `json:"agentDID"`
	Domain            string       `json:"domain"`
	Baseline          SignalPair   `json:"baseline"`
	RHR               SignalPair   `json:"rhr"`
	PCR               SignalPair   `json:"pcr"`
	DSL               SignalPair   `json:"dsl"`
	CLS               SignalPair   `json:"cls"`
	SAS               SignalPair   `json:"sas"`
	FSS               SignalPair   `json:"fss"`
	PAS               SignalPair   `json:"pas"`
	RSS               SignalPair   `json:"rss"`
	RRS               SignalPair   `json:"rrs"`
	CS                WelfordStats `json:"cs"`
	PPS               SignalPair   `json:"pps"`
	CreatedAt         string       `json:"createdAt"`
	TotalInteractions int          `json:"totalInteractions"`
	CompositeScore    float64      `json:"compositeScore"`
}

// EventType is the type field of a ReputationEvent.
type EventType string

const (
	EventSagaComplete       EventType = "saga_complete"
	EventProtocolViolation  EventType = "protocol_violation"
	EventCancellation       EventType = "cancellation"
	EventSatisfactionSignal EventType = "satisfaction_signal"
	EventFailureSpeed       EventType = "failure_speed"
	EventPriceDeviation     EventType = "price_deviation"
	EventReservationAttempt EventType = "reservation_attempt"
	EventRetryTriggered     EventType = "retry_triggered"
	EventQualityObserved    EventType = "quality_observed"
	EventPeerEndorsement    EventType = "peer_endorsement"
)

// ReputationEvent carries the data for a single reputation update.
type ReputationEvent struct {
	Type      EventType `json:"type"`
	SagaID    string    `json:"sagaId"`
	AgentDID  string    `json:"agentDID"`
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`
	// saga_complete
	Success       *bool    `json:"success,omitempty"`
	LatencyMs     *float64 `json:"latencyMs,omitempty"`
	SLADurationMs *float64 `json:"slaDurationMs,omitempty"`
	// failure_speed
	FailureFastMs *float64 `json:"failureFastMs,omitempty"`
	// price_deviation
	QuotedPrice *float64 `json:"quotedPrice,omitempty"`
	ActualPrice *float64 `json:"actualPrice,omitempty"`
	// reservation_attempt
	ReservationAccepted *bool `json:"reservationAccepted,omitempty"`
	// retry_triggered
	RetryCount *int `json:"retryCount,omitempty"`
	// quality_observed / satisfaction_signal
	QualityScore *float64 `json:"qualityScore,omitempty"`
	// peer_endorsement
	EndorserScore *float64 `json:"endorserScore,omitempty"`
}

// ── Signal update functions ────────────────────────────────────────────────────

func newSignalPair() SignalPair {
	return SignalPair{Alpha: jeffreysPrior, Beta: jeffreysPrior, N: 0, LastUpdated: nowISO()}
}

func newWelford() WelfordStats {
	return WelfordStats{LastUpdated: nowISO()}
}

func decaySignal(p SignalPair, now time.Time) SignalPair {
	last, err := time.Parse(time.RFC3339Nano, p.LastUpdated)
	if err != nil {
		return p
	}
	days := now.Sub(last).Hours() / 24
	if days <= 0 {
		return p
	}
	ls := math.Log(2) / successHalfLifeDays
	lf := math.Log(2) / failureHalfLifeDays
	return SignalPair{
		Alpha:       math.Max(jeffreysPrior, jeffreysPrior+(p.Alpha-jeffreysPrior)*math.Exp(-ls*days)),
		Beta:        math.Max(jeffreysPrior, jeffreysPrior+(p.Beta-jeffreysPrior)*math.Exp(-lf*days)),
		N:           p.N,
		LastUpdated: now.Format(time.RFC3339Nano),
	}
}

func dormancyShrink(p SignalPair, now time.Time) SignalPair {
	last, err := time.Parse(time.RFC3339Nano, p.LastUpdated)
	if err != nil {
		return p
	}
	days := now.Sub(last).Hours() / 24
	if days <= dormancyHalfLifeDays {
		return p
	}
	ld := math.Log(2) / dormancyHalfLifeDays
	factor := math.Exp(-ld * (days - dormancyHalfLifeDays))
	return SignalPair{
		Alpha:       jeffreysPrior + (p.Alpha-jeffreysPrior)*factor,
		Beta:        jeffreysPrior + (p.Beta-jeffreysPrior)*factor,
		N:           p.N,
		LastUpdated: p.LastUpdated,
	}
}

func addAlpha(p SignalPair, v float64, now time.Time) SignalPair {
	return SignalPair{Alpha: p.Alpha + v, Beta: p.Beta, N: p.N + 1, LastUpdated: now.Format(time.RFC3339Nano)}
}

func addBeta(p SignalPair, v float64, now time.Time) SignalPair {
	return SignalPair{Alpha: p.Alpha, Beta: p.Beta + v, N: p.N + 1, LastUpdated: now.Format(time.RFC3339Nano)}
}

func updateBaseline(p SignalPair, success bool, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if success {
		return addAlpha(d, 1, now)
	}
	return addBeta(d, muBaseline, now)
}

func updateRHR(p SignalPair, success bool, now time.Time) SignalPair {
	last, _ := time.Parse(time.RFC3339Nano, p.LastUpdated)
	days := now.Sub(last).Hours() / 24
	lam := math.Log(2) / rhrHalfLifeDays
	da := math.Max(jeffreysPrior, jeffreysPrior+(p.Alpha-jeffreysPrior)*math.Exp(-lam*days))
	db := math.Max(jeffreysPrior, jeffreysPrior+(p.Beta-jeffreysPrior)*math.Exp(-lam*days))
	if success {
		return SignalPair{Alpha: da + 1, Beta: db, N: p.N + 1, LastUpdated: now.Format(time.RFC3339Nano)}
	}
	return SignalPair{Alpha: da, Beta: db + muRHR, N: p.N + 1, LastUpdated: now.Format(time.RFC3339Nano)}
}

func updatePCR(p SignalPair, compliant bool, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if compliant {
		return addAlpha(d, 1, now)
	}
	return addBeta(d, 3.0, now)
}

func updateDSL(p SignalPair, metSLA bool, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if metSLA {
		return addAlpha(d, 1, now)
	}
	return addBeta(d, muDSL, now)
}

func updateCLS(p SignalPair, cancelled bool, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if cancelled {
		return addBeta(d, 2.5, now)
	}
	return addAlpha(d, 1, now)
}

func updateSAS(p SignalPair, outcome string, now time.Time) SignalPair {
	d := decaySignal(p, now)
	switch outcome {
	case "satisfied":
		return addAlpha(d, 1, now)
	case "dissatisfied":
		return addBeta(d, 1.5, now)
	default:
		return SignalPair{Alpha: d.Alpha, Beta: d.Beta, N: d.N, LastUpdated: now.Format(time.RFC3339Nano)}
	}
}

func updateFSS(p SignalPair, failureMs, slaMs float64, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if failureMs <= slaMs*0.10 {
		return addAlpha(d, 1, now)
	}
	return addBeta(d, muFSS, now)
}

func updatePAS(p SignalPair, quoted, actual float64, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if quoted <= 0 {
		return d
	}
	deviation := math.Abs(actual-quoted) / quoted
	if deviation <= 0.02 {
		return addAlpha(d, 1, now)
	}
	return addBeta(d, muPAS, now)
}

func updateRSS(p SignalPair, accepted bool, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if accepted {
		return addAlpha(d, 1, now)
	}
	return addBeta(d, 1.0, now)
}

func updateRRS(p SignalPair, retryCount int, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if retryCount > 0 {
		return addBeta(d, muRRS*float64(retryCount), now)
	}
	return addAlpha(d, 1, now)
}

func updateCS(s WelfordStats, quality float64, now time.Time) WelfordStats {
	n := s.N + 1
	delta := quality - s.Mean
	mean := s.Mean + delta/float64(n)
	delta2 := quality - mean
	m2 := s.M2 + delta*delta2
	return WelfordStats{N: n, Mean: mean, M2: m2, LastUpdated: now.Format(time.RFC3339Nano)}
}

func updatePPS(p SignalPair, endorserScore float64, now time.Time) SignalPair {
	d := decaySignal(p, now)
	if endorserScore < 0.8 {
		return d
	}
	return SignalPair{Alpha: d.Alpha + endorserScore, Beta: d.Beta, N: d.N + 1, LastUpdated: now.Format(time.RFC3339Nano)}
}

// ── Score helpers ──────────────────────────────────────────────────────────────

func betaMean(p SignalPair) float64 {
	return p.Alpha / (p.Alpha + p.Beta)
}

func csScore(s WelfordStats) float64 {
	if s.N < 2 {
		return s.Mean
	}
	v := s.M2 / float64(s.N-1)
	return s.Mean / (1.0 + math.Sqrt(v))
}

func computeComposite(state *ReputationState, w CompositeWeights) float64 {
	return betaMean(state.Baseline)*w.Baseline +
		betaMean(state.RHR)*w.RHR +
		betaMean(state.PCR)*w.PCR +
		betaMean(state.DSL)*w.DSL +
		betaMean(state.CLS)*w.CLS +
		betaMean(state.SAS)*w.SAS +
		betaMean(state.FSS)*w.FSS +
		betaMean(state.PAS)*w.PAS +
		betaMean(state.RSS)*w.RSS +
		betaMean(state.RRS)*w.RRS +
		csScore(state.CS)*w.CS +
		betaMean(state.PPS)*w.PPS
}

// WilsonLowerBound returns the 95% Wilson-score lower bound.
func WilsonLowerBound(p SignalPair) float64 {
	z := 1.96
	n := p.Alpha + p.Beta - 1.0
	if n <= 0 {
		return 0
	}
	pHat := (p.Alpha - jeffreysPrior) / n
	denom := 1 + (z*z)/n
	centre := pHat + (z*z)/(2*n)
	spread := z * math.Sqrt((pHat*(1-pHat)+(z*z)/(4*n))/n)
	v := (centre - spread) / denom
	if v < 0 {
		return 0
	}
	return v
}

// ── Thompson Sampling ─────────────────────────────────────────────────────────

// SampleBeta draws θ ~ Beta(α,β) using Go's math/rand.
func SampleBeta(alpha, beta float64) float64 {
	ga := sampleGamma(alpha)
	gb := sampleGamma(beta)
	return ga / (ga + gb)
}

func sampleGamma(shape float64) float64 {
	if shape < 1 {
		return sampleGamma(1+shape) * math.Pow(rand.Float64(), 1/shape)
	}
	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9*d)
	for {
		x := randNorm()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := rand.Float64()
		if u < 1-0.0331*(x*x)*(x*x) {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

func randNorm() float64 {
	u := 1 - rand.Float64()
	v := rand.Float64()
	return math.Sqrt(-2*math.Log(u)) * math.Cos(2*math.Pi*v)
}

// ── Engine ─────────────────────────────────────────────────────────────────────

// Engine is the in-memory Bayesian reputation engine.
type Engine struct {
	mu      sync.RWMutex
	store   map[string]*ReputationState
	weights CompositeWeights
}

// New creates an Engine with the default composite weights.
func New(weights *CompositeWeights) *Engine {
	w := DefaultWeights
	if weights != nil {
		w = *weights
	}
	return &Engine{store: make(map[string]*ReputationState), weights: w}
}

func (e *Engine) key(agentDID, domain string) string {
	return agentDID + "::" + domain
}

func (e *Engine) getOrCreate(agentDID, domain string) *ReputationState {
	k := e.key(agentDID, domain)
	if s, ok := e.store[k]; ok {
		return s
	}
	now := nowISO()
	s := &ReputationState{
		AgentDID:       agentDID,
		Domain:         domain,
		Baseline:       newSignalPair(),
		RHR:            newSignalPair(),
		PCR:            newSignalPair(),
		DSL:            newSignalPair(),
		CLS:            newSignalPair(),
		SAS:            newSignalPair(),
		FSS:            newSignalPair(),
		PAS:            newSignalPair(),
		RSS:            newSignalPair(),
		RRS:            newSignalPair(),
		CS:             newWelford(),
		PPS:            newSignalPair(),
		CreatedAt:      now,
		CompositeScore: 0.5,
	}
	e.store[k] = s
	return s
}

// RecordEvent processes a ReputationEvent and updates the model.
func (e *Engine) RecordEvent(ev ReputationEvent) {
	if ev.Domain == "" {
		ev.Domain = "general"
	}
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	s := e.getOrCreate(ev.AgentDID, ev.Domain)

	switch ev.Type {
	case EventSagaComplete:
		ok := ev.Success != nil && *ev.Success
		s.Baseline = updateBaseline(s.Baseline, ok, now)
		s.RHR = updateRHR(s.RHR, ok, now)
		if ev.LatencyMs != nil && ev.SLADurationMs != nil {
			s.DSL = updateDSL(s.DSL, *ev.LatencyMs <= *ev.SLADurationMs, now)
		}
	case EventProtocolViolation:
		s.PCR = updatePCR(s.PCR, false, now)
	case EventCancellation:
		s.CLS = updateCLS(s.CLS, true, now)
	case EventSatisfactionSignal:
		if ev.QualityScore != nil {
			outcome := "neutral"
			if *ev.QualityScore >= 0.7 {
				outcome = "satisfied"
			} else if *ev.QualityScore <= 0.3 {
				outcome = "dissatisfied"
			}
			s.SAS = updateSAS(s.SAS, outcome, now)
		}
	case EventFailureSpeed:
		if ev.FailureFastMs != nil && ev.SLADurationMs != nil {
			s.FSS = updateFSS(s.FSS, *ev.FailureFastMs, *ev.SLADurationMs, now)
		}
	case EventPriceDeviation:
		if ev.QuotedPrice != nil && ev.ActualPrice != nil {
			s.PAS = updatePAS(s.PAS, *ev.QuotedPrice, *ev.ActualPrice, now)
		}
	case EventReservationAttempt:
		accepted := ev.ReservationAccepted != nil && *ev.ReservationAccepted
		s.RSS = updateRSS(s.RSS, accepted, now)
	case EventRetryTriggered:
		count := 1
		if ev.RetryCount != nil {
			count = *ev.RetryCount
		}
		s.RRS = updateRRS(s.RRS, count, now)
	case EventQualityObserved:
		if ev.QualityScore != nil {
			s.CS = updateCS(s.CS, *ev.QualityScore, now)
		}
	case EventPeerEndorsement:
		if ev.EndorserScore != nil {
			s.PPS = updatePPS(s.PPS, *ev.EndorserScore, now)
		}
	}

	s.TotalInteractions++
	s.CompositeScore = computeComposite(s, e.weights)
}

// CompositeScore returns the current composite score (0–1) for an agent+domain.
// Returns 0.5 (uninformed prior) if no data is available.
func (e *Engine) CompositeScore(agentDID, domain string) float64 {
	if domain == "" {
		domain = "general"
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	s, ok := e.store[e.key(agentDID, domain)]
	if !ok {
		return 0.5
	}
	return computeComposite(s, e.weights)
}

// ThompsonCandidate holds a candidate with its Thompson sample.
type ThompsonCandidate struct {
	AgentDID      string
	ThompsonScore float64
	Mean          float64
	LowerBound    float64
	Extra         map[string]any
}

// ThompsonSelect samples θ ~ Beta(α,β) per candidate and returns them sorted
// by sample descending (winner first).
func (e *Engine) ThompsonSelect(candidates []map[string]any, domain string, riskGated bool) []ThompsonCandidate {
	if domain == "" {
		domain = "general"
	}
	now := time.Now().UTC()

	e.mu.Lock()
	defer e.mu.Unlock()

	results := make([]ThompsonCandidate, 0, len(candidates))
	for _, c := range candidates {
		did, _ := c["agentDID"].(string)
		if did == "" {
			did, _ = c["agent_did"].(string)
		}
		s := e.getOrCreate(did, domain)
		applyDormancy(s, now)
		composite := computeComposite(s, e.weights)
		n := s.Baseline.Alpha + s.Baseline.Beta
		alphaC := math.Max(0.5, composite*n)
		betaC := math.Max(0.5, (1-composite)*n)
		ts := SampleBeta(alphaC, betaC)
		lb := WilsonLowerBound(s.Baseline)
		extra := make(map[string]any, len(c))
		for k, v := range c {
			extra[k] = v
		}
		results = append(results, ThompsonCandidate{
			AgentDID: did, ThompsonScore: ts, Mean: composite, LowerBound: lb, Extra: extra,
		})
	}

	if riskGated {
		filtered := results[:0]
		for _, r := range results {
			if r.LowerBound >= 0.1 {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) > 0 {
			results = filtered
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].ThompsonScore > results[j].ThompsonScore })
	return results
}

func applyDormancy(s *ReputationState, now time.Time) {
	s.Baseline = dormancyShrink(s.Baseline, now)
	s.RHR = dormancyShrink(s.RHR, now)
	s.PCR = dormancyShrink(s.PCR, now)
	s.DSL = dormancyShrink(s.DSL, now)
	s.CLS = dormancyShrink(s.CLS, now)
	s.SAS = dormancyShrink(s.SAS, now)
	s.FSS = dormancyShrink(s.FSS, now)
	s.PAS = dormancyShrink(s.PAS, now)
	s.RSS = dormancyShrink(s.RSS, now)
	s.RRS = dormancyShrink(s.RRS, now)
	s.PPS = dormancyShrink(s.PPS, now)
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// MarshalJSON implements json.Marshaler for ReputationState.
func (s ReputationState) MarshalJSON() ([]byte, error) {
	type Alias ReputationState
	return json.Marshal(Alias(s))
}
