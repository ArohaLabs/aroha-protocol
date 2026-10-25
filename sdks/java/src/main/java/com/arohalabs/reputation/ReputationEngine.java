// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.reputation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Aroha Bayesian Beta Reputation Engine (v1.1).
 *
 * <p>11-signal model with Thompson Sampling for Multi-Armed Bandit agent selection.
 *
 * <p>References:
 * <ul>
 *   <li>Jøsang &amp; Ismail (2002) "The Beta Reputation System" BLED Conf.</li>
 *   <li>Agrawal &amp; Goyal (2012) "Analysis of Thompson Sampling for MAB" COLT.</li>
 *   <li>Lai &amp; Robbins (1985) "Asymptotically efficient adaptive allocation rules".</li>
 * </ul>
 */
public class ReputationEngine {

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final double JEFFREYS_PRIOR         = 0.5;
    private static final double SUCCESS_HALF_LIFE_DAYS = 180.0;
    private static final double FAILURE_HALF_LIFE_DAYS = 60.0;
    private static final double RHR_HALF_LIFE_DAYS     = 30.0;
    private static final double DORMANCY_HALF_LIFE     = 365.0;
    private static final double MU_BASELINE = 2.0;
    private static final double MU_RHR      = 2.0;
    private static final double MU_DSL      = 2.0;
    private static final double MU_FSS      = 1.5;
    private static final double MU_PAS      = 2.5;
    private static final double MU_RRS      = 1.2;

    // ── Nested types ──────────────────────────────────────────────────────────

    public record SignalPair(double alpha, double beta, int n, String lastUpdated) {
        public static SignalPair fresh() {
            return new SignalPair(JEFFREYS_PRIOR, JEFFREYS_PRIOR, 0, Instant.now().toString());
        }
        public double mean() { return alpha / (alpha + beta); }
    }

    public record WelfordStats(int n, double mean, double m2, String lastUpdated) {
        public static WelfordStats fresh() {
            return new WelfordStats(0, 0.0, 0.0, Instant.now().toString());
        }
        public double score() {
            if (n < 2) return mean;
            double variance = m2 / (n - 1);
            return mean / (1.0 + Math.sqrt(variance));
        }
    }

    public record CompositeWeights(
        double baseline, double rhr, double pcr, double dsl,
        double cls,      double sas, double fss, double pas,
        double rss,      double rrs, double cs,  double pps
    ) {
        public static CompositeWeights defaults() {
            return new CompositeWeights(0.18, 0.18, 0.10, 0.08,
                                        0.07, 0.05, 0.10, 0.08,
                                        0.06, 0.04, 0.04, 0.02);
        }
    }

    public static class ReputationState {
        public String agentDID;
        public String domain;
        public SignalPair  baseline, rhr, pcr, dsl, cls, sas, fss, pas, rss, rrs, pps;
        public WelfordStats cs;
        public int totalInteractions;
        public double compositeScore = 0.5;

        public ReputationState(String agentDID, String domain) {
            this.agentDID = agentDID;
            this.domain   = domain;
            this.baseline = SignalPair.fresh(); this.rhr = SignalPair.fresh();
            this.pcr = SignalPair.fresh();      this.dsl = SignalPair.fresh();
            this.cls = SignalPair.fresh();      this.sas = SignalPair.fresh();
            this.fss = SignalPair.fresh();      this.pas = SignalPair.fresh();
            this.rss = SignalPair.fresh();      this.rrs = SignalPair.fresh();
            this.pps = SignalPair.fresh();      this.cs  = WelfordStats.fresh();
        }
    }

    public record ReputationEvent(
        String type, String sagaId, String agentDID, String domain,
        Instant timestamp,
        Boolean success, Double latencyMs, Double slaDurationMs,
        Double failureFastMs, Double quotedPrice, Double actualPrice,
        Boolean reservationAccepted, Integer retryCount,
        Double qualityScore, Double endorserScore
    ) {
        public static Builder builder(String type, String sagaId, String agentDID) {
            return new Builder(type, sagaId, agentDID);
        }

        public static class Builder {
            private final String type, sagaId, agentDID;
            private String domain = "general";
            private Instant timestamp = Instant.now();
            private Boolean success; private Double latencyMs, slaDurationMs;
            private Double failureFastMs, quotedPrice, actualPrice;
            private Boolean reservationAccepted; private Integer retryCount;
            private Double qualityScore, endorserScore;

            Builder(String type, String sagaId, String agentDID) {
                this.type = type; this.sagaId = sagaId; this.agentDID = agentDID;
            }
            public Builder domain(String v)              { domain = v; return this; }
            public Builder success(boolean v)            { success = v; return this; }
            public Builder latencyMs(double v)           { latencyMs = v; return this; }
            public Builder slaDurationMs(double v)       { slaDurationMs = v; return this; }
            public Builder failureFastMs(double v)       { failureFastMs = v; return this; }
            public Builder quotedPrice(double v)         { quotedPrice = v; return this; }
            public Builder actualPrice(double v)         { actualPrice = v; return this; }
            public Builder reservationAccepted(boolean v){ reservationAccepted = v; return this; }
            public Builder retryCount(int v)             { retryCount = v; return this; }
            public Builder qualityScore(double v)        { qualityScore = v; return this; }
            public Builder endorserScore(double v)       { endorserScore = v; return this; }
            public ReputationEvent build() {
                return new ReputationEvent(type, sagaId, agentDID, domain, timestamp,
                    success, latencyMs, slaDurationMs, failureFastMs, quotedPrice, actualPrice,
                    reservationAccepted, retryCount, qualityScore, endorserScore);
            }
        }
    }

    public record ThompsonCandidate(String agentDID, double thompsonScore, double mean, double lowerBound,
                                    Map<String, Object> extra) {}

    // ── Engine state ──────────────────────────────────────────────────────────

    private final ConcurrentHashMap<String, ReputationState> store = new ConcurrentHashMap<>();
    private final CompositeWeights weights;
    private final Random rng = new Random();

    public ReputationEngine() { this(CompositeWeights.defaults()); }
    public ReputationEngine(CompositeWeights weights) { this.weights = weights; }

    // ── Public API ────────────────────────────────────────────────────────────

    public synchronized void recordEvent(ReputationEvent ev) {
        String domain = ev.domain() != null ? ev.domain() : "general";
        Instant now = ev.timestamp() != null ? ev.timestamp() : Instant.now();
        ReputationState s = getOrCreate(ev.agentDID(), domain);

        switch (ev.type()) {
            case "saga_complete" -> {
                boolean ok = ev.success() != null && ev.success();
                s.baseline = updateBaseline(s.baseline, ok, now);
                s.rhr      = updateRHR(s.rhr, ok, now);
                if (ev.latencyMs() != null && ev.slaDurationMs() != null) {
                    s.dsl = updateDSL(s.dsl, ev.latencyMs() <= ev.slaDurationMs(), now);
                }
            }
            case "protocol_violation"  -> s.pcr = updatePCR(s.pcr, false, now);
            case "cancellation"        -> s.cls = updateCLS(s.cls, true, now);
            case "satisfaction_signal" -> {
                if (ev.qualityScore() != null) {
                    String outcome = ev.qualityScore() >= 0.7 ? "satisfied" :
                                     ev.qualityScore() <= 0.3 ? "dissatisfied" : "neutral";
                    s.sas = updateSAS(s.sas, outcome, now);
                }
            }
            case "failure_speed" -> {
                if (ev.failureFastMs() != null && ev.slaDurationMs() != null)
                    s.fss = updateFSS(s.fss, ev.failureFastMs(), ev.slaDurationMs(), now);
            }
            case "price_deviation" -> {
                if (ev.quotedPrice() != null && ev.actualPrice() != null)
                    s.pas = updatePAS(s.pas, ev.quotedPrice(), ev.actualPrice(), now);
            }
            case "reservation_attempt" ->
                s.rss = updateRSS(s.rss, ev.reservationAccepted() != null && ev.reservationAccepted(), now);
            case "retry_triggered" ->
                s.rrs = updateRRS(s.rrs, ev.retryCount() != null ? ev.retryCount() : 1, now);
            case "quality_observed" -> {
                if (ev.qualityScore() != null) s.cs = updateCS(s.cs, ev.qualityScore(), now);
            }
            case "peer_endorsement" -> {
                if (ev.endorserScore() != null) s.pps = updatePPS(s.pps, ev.endorserScore(), now);
            }
        }

        s.totalInteractions++;
        s.compositeScore = computeComposite(s, weights);
    }

    public double compositeScore(String agentDID, String domain) {
        if (domain == null) domain = "general";
        ReputationState s = store.get(key(agentDID, domain));
        if (s == null) return 0.5;
        return computeComposite(s, weights);
    }

    public List<ThompsonCandidate> thompsonSelect(
        List<Map<String, Object>> candidates, String domain, boolean riskGated
    ) {
        if (domain == null) domain = "general";
        Instant now = Instant.now();
        List<ThompsonCandidate> results = new ArrayList<>(candidates.size());

        synchronized (this) {
            for (var c : candidates) {
                String did = (String) c.getOrDefault("agentDID", c.get("agent_did"));
                if (did == null) continue;
                ReputationState s = getOrCreate(did, domain);
                applyDormancy(s, now);
                double composite = computeComposite(s, weights);
                double n = s.baseline.alpha() + s.baseline.beta();
                double alphaC = Math.max(0.5, composite * n);
                double betaC  = Math.max(0.5, (1 - composite) * n);
                double ts = sampleBeta(alphaC, betaC);
                double lb = wilsonLowerBound(s.baseline);
                results.add(new ThompsonCandidate(did, ts, composite, lb, new HashMap<>(c)));
            }
        }

        if (riskGated) {
            var filtered = results.stream().filter(r -> r.lowerBound() >= 0.1).toList();
            if (!filtered.isEmpty()) {
                var sorted = new ArrayList<>(filtered);
                sorted.sort((a, b) -> Double.compare(b.thompsonScore(), a.thompsonScore()));
                return sorted;
            }
        }

        results.sort((a, b) -> Double.compare(b.thompsonScore(), a.thompsonScore()));
        return results;
    }

    // ── Signal updaters ───────────────────────────────────────────────────────

    private SignalPair decay(SignalPair p, Instant now) {
        double days = daysBetween(p.lastUpdated(), now);
        if (days <= 0) return p;
        double ls = Math.log(2) / SUCCESS_HALF_LIFE_DAYS;
        double lf = Math.log(2) / FAILURE_HALF_LIFE_DAYS;
        return new SignalPair(
            Math.max(JEFFREYS_PRIOR, JEFFREYS_PRIOR + (p.alpha() - JEFFREYS_PRIOR) * Math.exp(-ls * days)),
            Math.max(JEFFREYS_PRIOR, JEFFREYS_PRIOR + (p.beta()  - JEFFREYS_PRIOR) * Math.exp(-lf * days)),
            p.n(), now.toString()
        );
    }

    private SignalPair dormancyShrink(SignalPair p, Instant now) {
        double days = daysBetween(p.lastUpdated(), now);
        if (days <= DORMANCY_HALF_LIFE) return p;
        double ld = Math.log(2) / DORMANCY_HALF_LIFE;
        double f = Math.exp(-ld * (days - DORMANCY_HALF_LIFE));
        return new SignalPair(
            JEFFREYS_PRIOR + (p.alpha() - JEFFREYS_PRIOR) * f,
            JEFFREYS_PRIOR + (p.beta()  - JEFFREYS_PRIOR) * f,
            p.n(), p.lastUpdated()
        );
    }

    private SignalPair updateBaseline(SignalPair p, boolean ok, Instant now) {
        var d = decay(p, now);
        return ok ? addA(d, 1, now) : addB(d, MU_BASELINE, now);
    }

    private SignalPair updateRHR(SignalPair p, boolean ok, Instant now) {
        double days = daysBetween(p.lastUpdated(), now);
        double lam = Math.log(2) / RHR_HALF_LIFE_DAYS;
        double da = Math.max(JEFFREYS_PRIOR, JEFFREYS_PRIOR + (p.alpha() - JEFFREYS_PRIOR) * Math.exp(-lam * days));
        double db = Math.max(JEFFREYS_PRIOR, JEFFREYS_PRIOR + (p.beta()  - JEFFREYS_PRIOR) * Math.exp(-lam * days));
        return ok ? new SignalPair(da + 1, db, p.n() + 1, now.toString())
                  : new SignalPair(da, db + MU_RHR, p.n() + 1, now.toString());
    }

    private SignalPair updatePCR(SignalPair p, boolean ok, Instant now)  { var d=decay(p,now); return ok?addA(d,1,now):addB(d,3.0,now); }
    private SignalPair updateDSL(SignalPair p, boolean ok, Instant now)  { var d=decay(p,now); return ok?addA(d,1,now):addB(d,MU_DSL,now); }
    private SignalPair updateCLS(SignalPair p, boolean c,  Instant now)  { var d=decay(p,now); return c?addB(d,2.5,now):addA(d,1,now); }
    private SignalPair updateFSS(SignalPair p, double fMs, double sMs, Instant now) {
        var d=decay(p,now); return fMs<=sMs*0.10?addA(d,1,now):addB(d,MU_FSS,now);
    }
    private SignalPair updatePAS(SignalPair p, double q, double a, Instant now) {
        var d=decay(p,now); if(q<=0) return d;
        return Math.abs(a-q)/q<=0.02?addA(d,1,now):addB(d,MU_PAS,now);
    }
    private SignalPair updateRSS(SignalPair p, boolean acc, Instant now) { var d=decay(p,now); return acc?addA(d,1,now):addB(d,1.0,now); }
    private SignalPair updateRRS(SignalPair p, int cnt, Instant now)     { var d=decay(p,now); return cnt>0?addB(d,MU_RRS*cnt,now):addA(d,1,now); }
    private SignalPair updatePPS(SignalPair p, double es, Instant now)   { var d=decay(p,now); return es<0.8?d:new SignalPair(d.alpha()+es,d.beta(),d.n()+1,now.toString()); }

    private SignalPair updateSAS(SignalPair p, String outcome, Instant now) {
        var d = decay(p, now);
        return switch (outcome) {
            case "satisfied"    -> addA(d, 1, now);
            case "dissatisfied" -> addB(d, 1.5, now);
            default -> new SignalPair(d.alpha(), d.beta(), d.n(), now.toString());
        };
    }

    private WelfordStats updateCS(WelfordStats s, double q, Instant now) {
        int n = s.n() + 1;
        double delta = q - s.mean();
        double mean = s.mean() + delta / n;
        double m2 = s.m2() + delta * (q - mean);
        return new WelfordStats(n, mean, m2, now.toString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SignalPair addA(SignalPair p, double v, Instant now) {
        return new SignalPair(p.alpha() + v, p.beta(), p.n() + 1, now.toString());
    }
    private SignalPair addB(SignalPair p, double v, Instant now) {
        return new SignalPair(p.alpha(), p.beta() + v, p.n() + 1, now.toString());
    }

    private double computeComposite(ReputationState s, CompositeWeights w) {
        return s.baseline.mean()*w.baseline() + s.rhr.mean()*w.rhr() +
               s.pcr.mean()*w.pcr()           + s.dsl.mean()*w.dsl() +
               s.cls.mean()*w.cls()           + s.sas.mean()*w.sas() +
               s.fss.mean()*w.fss()           + s.pas.mean()*w.pas() +
               s.rss.mean()*w.rss()           + s.rrs.mean()*w.rrs() +
               s.cs.score()*w.cs()            + s.pps.mean()*w.pps();
    }

    private double wilsonLowerBound(SignalPair p) {
        double z = 1.96, n = p.alpha() + p.beta() - 1.0;
        if (n <= 0) return 0;
        double pHat = (p.alpha() - JEFFREYS_PRIOR) / n;
        double denom = 1 + (z*z)/n;
        double centre = pHat + (z*z)/(2*n);
        double spread = z * Math.sqrt((pHat*(1-pHat) + (z*z)/(4*n))/n);
        return Math.max(0, (centre - spread) / denom);
    }

    private double sampleBeta(double alpha, double beta) {
        double ga = sampleGamma(alpha), gb = sampleGamma(beta);
        return ga / (ga + gb);
    }

    private double sampleGamma(double shape) {
        if (shape < 1) return sampleGamma(1 + shape) * Math.pow(rng.nextDouble(), 1.0 / shape);
        double d = shape - 1.0/3, c = 1.0/Math.sqrt(9*d);
        while (true) {
            double x = randNorm(), v = 1 + c * x;
            if (v <= 0) continue;
            v = v*v*v;
            double u = rng.nextDouble();
            if (u < 1 - 0.0331*(x*x)*(x*x)) return d*v;
            if (Math.log(u) < 0.5*x*x + d*(1 - v + Math.log(v))) return d*v;
        }
    }

    private double randNorm() {
        double u = 1 - rng.nextDouble(), v = rng.nextDouble();
        return Math.sqrt(-2*Math.log(u)) * Math.cos(2*Math.PI*v);
    }

    private void applyDormancy(ReputationState s, Instant now) {
        s.baseline = dormancyShrink(s.baseline, now); s.rhr = dormancyShrink(s.rhr, now);
        s.pcr = dormancyShrink(s.pcr, now);           s.dsl = dormancyShrink(s.dsl, now);
        s.cls = dormancyShrink(s.cls, now);           s.sas = dormancyShrink(s.sas, now);
        s.fss = dormancyShrink(s.fss, now);           s.pas = dormancyShrink(s.pas, now);
        s.rss = dormancyShrink(s.rss, now);           s.rrs = dormancyShrink(s.rrs, now);
        s.pps = dormancyShrink(s.pps, now);
    }

    private ReputationState getOrCreate(String agentDID, String domain) {
        return store.computeIfAbsent(key(agentDID, domain), k -> new ReputationState(agentDID, domain));
    }

    private String key(String agentDID, String domain) { return agentDID + "::" + domain; }

    private double daysBetween(String iso, Instant now) {
        try {
            return ChronoUnit.MILLIS.between(Instant.parse(iso), now) / 86_400_000.0;
        } catch (Exception e) { return 0; }
    }
}
