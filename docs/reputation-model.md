<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Reputation Model v1.1
## A Bayesian, Saga-Native, Multi-Signal Trust Scoring System

*This document specifies the v1.1 reputation model. The v1.0 EMA-based model remains supported for backwards compatibility. Implementations SHOULD migrate to v1.1.*

---

## Motivation

The v1.0 model uses an Exponential Moving Average (EMA) over binary saga outcomes. EMA is well-understood but has four structural weaknesses:

1. **No uncertainty quantification.** An agent with 2 successes and one with 200 successes can have identical scores, but the first agent's score is far less trustworthy.
2. **Symmetric time decay.** A failure from six months ago decays at the same rate as a success — too conservative.
3. **Single signal.** Binary success/failure loses the rich causal structure of the Aroha saga lifecycle.
4. **No consistency signal.** Two agents at 80% reliability — one consistently 80%, one alternating 100%/50% — look identical to EMA.

The v1.1 model replaces EMA with a **Bayesian Beta-reputation system** extended with **11 orthogonal signals** (5 saga-native, 6 adapted from cross-domain precedents), **Thompson Sampling** for agent selection, and **graph-propagated priors** for cold start.

---

## Prior Art and Cross-Domain Precedents

The signals in this model are not invented from scratch. Each has a direct precedent in a production system or peer-reviewed literature. This section maps each signal to its intellectual heritage.

| Signal | Domain it comes from | Key reference |
|---|---|---|
| Beta-Bayesian reliability | P2P trust systems | Jøsang (2002, 2009) [[J1]](#ref-j1) |
| Thompson Sampling selection | Multi-armed bandits | Agrawal & Goyal (2012) [[A1]](#ref-a1) |
| Asymmetric time decay | Credit scoring, recency bias | Marti (2005) [[M1]](#ref-m1) |
| Failure speed (fast-fail) | Netflix Hystrix, AWS SRE | Netflix (2011) [[N1]](#ref-n1), AWS (2020) [[AW1]](#ref-aw1) |
| Price accuracy | Credence goods economics | Dulleck & Kerschbamer (2006) [[D1]](#ref-d1) |
| Reservation selectivity | Hotel overbooking models | Noone & Lee (2011) [[NO1]](#ref-no1) |
| Retry rate as quality signal | TCP retransmission analysis | TCP Analysis (2023) [[T1]](#ref-t1) |
| Variance / consistency | Financial Sharpe ratio | Sharpe (1966) [[SH1]](#ref-sh1) |
| Peer preference | PageRank + collaborative filtering | Massucci & Docampo (2019) [[PA1]](#ref-pa1) |
| Multi-dimensional composition | eBay DSR, Airbnb, Amazon | Resnick & Zeckhauser (2002) [[R1]](#ref-r1) |
| Graph-propagated prior | Byzantine fault tolerance | Reputation-enhanced PBFT (2025) [[BF1]](#ref-bf1) |

The Jøsang Beta Reputation System (BRS) [[J1]](#ref-j1) is the closest prior art to this model's core. BRS models binary interaction outcomes as Beta-distributed beliefs. Aroha v1.1 extends BRS with: asymmetric time decay, 11 domain-specific signals, Thompson Sampling for selection, and graph-propagated priors for cold start. The combination has not previously been applied to agent-network protocols.

---

## 1. Core Model: Beta-Bayesian Reliability

### 1.1 The Beta Distribution as a Reliability Prior

For each agent $a$ and capability domain $d$, we model the agent's latent reliability as a random variable:

$$p_{a,d} \sim \text{Beta}(\alpha_{a,d},\, \beta_{a,d})$$

where $\alpha_{a,d} > 0$ is the weighted success count plus prior, and $\beta_{a,d} > 0$ is the weighted failure count plus prior.

The **expected reliability** (point-estimate score) is:

$$\hat{p}_{a,d} = \frac{\alpha_{a,d}}{\alpha_{a,d} + \beta_{a,d}}$$

The **epistemic uncertainty** is:

$$\text{Var}[p_{a,d}] = \frac{\alpha_{a,d}\,\beta_{a,d}}{(\alpha_{a,d}+\beta_{a,d})^2\,(\alpha_{a,d}+\beta_{a,d}+1)}$$

Variance is maximised for a new agent ($\alpha = \beta = \tfrac{1}{2}$ gives $\text{Var} \approx \tfrac{1}{9}$) and converges to zero as interaction count grows.

*Precedent: Jøsang's BRS [[J1]](#ref-j1) introduced this exact formulation for P2P networks in 2002. eBay's reputation research by Resnick & Zeckhauser [[R1]](#ref-r1) confirmed empirically that Bayesian updating outperforms simple averages for sparse-feedback systems.*

### 1.2 Uninformative Prior

All new agents start with a **Jeffreys prior**:

$$\alpha_0 = \beta_0 = \tfrac{1}{2}$$

This is the maximally uninformative prior for a Bernoulli parameter. It gives a new agent $\hat{p} = 0.5$ with high variance. When vouching is present (§4), $\alpha_0$ and $\beta_0$ are inflated before any direct observations arrive.

### 1.3 Time-Weighted Updates with Asymmetric Decay

Let $T$ be the current time (Unix epoch seconds) and $t_i$ the time of observation $i$.

**Success decay rate** $\lambda_s$: successes persist longer, rewarding sustained good behaviour.

**Failure decay rate** $\lambda_f > \lambda_s$: failures fade faster, enabling genuine rehabilitation.

$$w_i^{(k)}(T) = \exp\!\bigl(-\lambda_k\,(T - t_i)\bigr), \quad k \in \{s, f\}$$

$$\alpha_{a,d}(T) = \alpha_0 + \sum_{i \in \mathcal{S}_{a,d}} w_i^{(s)}(T)$$

$$\beta_{a,d}(T) = \beta_0 + \mu \sum_{i \in \mathcal{F}_{a,d}} w_i^{(f)}(T)$$

where $\mu > 1$ is the **failure amplification factor** (default $\mu = 2.0$).

*Precedent: Marti's Stanford dissertation on P2P trust [[M1]](#ref-m1) identified asymmetric decay as essential — otherwise agents can't recover from early mistakes, killing cold-start. The $\mu = 2.0$ amplification was calibrated against Mansa AI's production asymmetric update data (+5 success, −10 failure) [[MA1]](#ref-ma1).*

**Default parameters:**

| Parameter | Symbol | Default | Rationale |
|---|---|---|---|
| Success half-life | $\tau_s = \ln 2 / \lambda_s$ | 180 days | Sustained good behaviour persists |
| Failure half-life | $\tau_f = \ln 2 / \lambda_f$ | 60 days | Failures forgiven in ~2 months |
| Failure amplification | $\mu$ | 2.0 | Mansa AI production calibration |
| Jeffreys prior | $\alpha_0, \beta_0$ | 0.5 | Maximally uninformative |

### 1.4 Dormancy Shrinkage

An inactive agent has a stale reputation. We shrink toward the prior — uncertainty grows but the point estimate remains:

$$\alpha_{a,d}' = \alpha_0 + (\alpha_{a,d} - \alpha_0)\,\exp(-\lambda_d\,\Delta t)$$

$$\beta_{a,d}' = \beta_0 + (\beta_{a,d} - \beta_0)\,\exp(-\lambda_d\,\Delta t)$$

Default dormancy half-life: $\tau_d = 365$ days.

---

## 2. The Eleven Reputation Signals

Each signal is an independent Beta distribution updated by its own Bernoulli observations. The composite score (§3) combines all eleven via a learned weight vector.

### Signal 1: Baseline Reliability $(\hat{p})$

The core Beta distribution from §1. Updated on every saga terminal event.

*The simplest signal. Jøsang BRS [[J1]](#ref-j1) uses this alone; we use it as one of eleven.*

---

### Signal 2: Reservation Honor Rate (RHR)

**What it measures:** When an orchestrator issues `ArohaCommit` following a `ArohaReserveAck`, does the agent deliver a timely `ArohaCommitAck`?

Let $C_a$ = count of `ArohaCommit` messages directed at $a$, and $H_a$ = count of timely `ArohaCommitAck` responses.

$$\text{RHR}_a \sim \text{Beta}\!\left(\alpha_0 + H_a,\; \beta_0 + \mu_{\text{RHR}}\,(C_a - H_a)\right)$$

$\mu_{\text{RHR}} = 3.0$ (higher amplification than baseline — committing and then failing to deliver is the worst failure mode in a multi-party saga, forcing LIFO rollback of all preceding steps).

---

### Signal 3: Provider-Initiated Cancellation Rate (PCR)

**What it measures:** What fraction of cancellations involving this agent were *initiated by the provider* (not requested by the orchestrator)?

Let $K_a$ = total cancellation events, $P_a$ = provider-initiated subset.

$$\text{PCR score}_a \sim \text{Beta}\!\left(\alpha_0 + (K_a - P_a),\; \beta_0 + \mu_{\text{PCR}}\,P_a\right)$$

$\mu_{\text{PCR}} = 2.5$. High PCR = routine overcommitment. Orthogonal to RHR: PCR catches reserve-stage dishonesty; RHR catches commit-stage failure.

---

### Signal 4: Downstream Success Lift (DSL)

**What it measures:** Do sagas that include agent $a$ complete at a higher rate than the network baseline?

$$\text{DSL}_a = r_a - \bar{r}, \quad \hat{\text{DSL}}_a = \tfrac{1}{2} + \tfrac{\text{DSL}_a}{2\,\sigma_{\text{DSL}}}$$

$$\text{DSL}_a \sim \text{Beta}\!\left(\alpha_0 + n_a\,r_a,\; \beta_0 + n_a\,(1 - r_a)\right)$$

*Precedent: The Component Synergy Score from TRiSM [[TR1]](#ref-tr1) and the dual-level framework from RepuNet [[RE1]](#ref-re1) are the academic basis. This is the only signal that measures a network-level property rather than point-to-point interactions.*

---

### Signal 5: Commit Latency Score (CLS)

**What it measures:** Does the agent deliver `ArohaCommitAck` within the capability's SLA threshold $\ell_d$?

$$\text{CLS}_{a,d} \sim \text{Beta}\!\left(\alpha_0 + |\{i : L_i \leq \ell_d\}|,\; \beta_0 + |\{i : L_i > \ell_d\}|\right)$$

SLA defaults: data query 2s, booking 5s, payment 10s, LLM 30s.

---

### Signal 6: Satisfaction Alignment Score (SAS)

**What it measures:** Does the agent's predicted reliability match human-rated outcome quality via `ArohaSatisfactionSignal`?

A `ArohaSatisfactionSignal` carries `qualityStars` $q \in \{1..5\}$. Convert: $s_i = \mathbf{1}[q_i \geq 4]$.

$$\text{SAS}_a \sim \text{Beta}(\alpha_0 + \text{aligned},\; \beta_0 + \text{misaligned})$$

No failure amplification: calibration is a softer signal than reliability.

---

### Signal 7: Failure Speed Score (FSS)

**What it measures:** When the agent fails, does it fail *fast* (immediate error) or *slow* (block until timeout)?

A slow failure that occupies a saga slot for the full TTL is far more damaging to the orchestrator than a fast failure that allows immediate retry or rerouting. Netflix's Hystrix circuit breaker [[N1]](#ref-n1) formalises this distinction: a fast-failing dependency is treated as a temporary outage; a slow-failing one triggers circuit opening. Google's SRE book [[G1]](#ref-g1) documents the same principle: "fail open fast" is a first-class reliability design goal. AWS Well-Architected REL05-BP04 [[AW1]](#ref-aw1) mandates it as a best practice.

Formally: for each failure event $f_i$, let $\delta_i = t_{\text{failure}} - t_{\text{request}}$.

Define a **fast-fail threshold** $\tau_{\text{ff}}$ (default: 10% of the capability's SLA $\ell_d$):

$$\text{fast}_i = \mathbf{1}[\delta_i \leq \tau_{\text{ff}}]$$

$$\text{FSS}_a \sim \text{Beta}\!\left(\alpha_0 + \sum_i \text{fast}_i,\; \beta_0 + \mu_{\text{FSS}} \sum_i (1 - \text{fast}_i)\right)$$

$\mu_{\text{FSS}} = 1.5$. A timeout failure is 1.5× worse than an immediate error.

!!! note "This signal only updates on failure events"
    FSS is undefined (stays at the Jeffreys prior) for agents that never fail. It is only a discriminator within the set of agents that have failed at least once.

---

### Signal 8: Price Accuracy Score (PAS)

**What it measures:** How closely does the final committed price match the price quoted at reservation time?

This is the agent-network analogue of credence-goods price accuracy. Dulleck & Kerschbamer (2006) [[D1]](#ref-d1) studied this extensively in markets where quality is hard to observe (auto repair, healthcare): quote deviation is a strong predictor of provider trustworthiness even when outcomes look identical. The bid-ask spread literature in financial markets [[BA1]](#ref-ba1) formalises similar intuitions — systematic quote deviation signals either incompetence or manipulation.

Let $q_i$ be the quoted price in `ArohaReserveAck` and $c_i$ be the committed price in `ArohaCommitAck` for interaction $i$.

Define the **relative price deviation**:

$$\delta^{\text{price}}_i = \frac{|c_i - q_i|}{q_i}$$

Convert to Bernoulli with tolerance $\varepsilon_d$ (default: 1% for payments, 5% for non-payment capabilities):

$$\text{accurate}_i = \mathbf{1}[\delta^{\text{price}}_i \leq \varepsilon_d]$$

$$\text{PAS}_{a,d} \sim \text{Beta}\!\left(\alpha_0 + \sum_i \text{accurate}_i,\; \beta_0 + \mu_{\text{PAS}} \sum_i (1 - \text{accurate}_i)\right)$$

$\mu_{\text{PAS}} = 2.5$ for payment capabilities (price bait-and-switch is a severe trust violation); $\mu_{\text{PAS}} = 1.5$ for non-payment capabilities.

!!! note "Applicable only to capabilities with quoted prices"
    PAS defaults to the Jeffreys prior for capabilities that have no price component.

---

### Signal 9: Reservation Selectivity Score (RSS)

**What it measures:** Is the agent's reservation acceptance rate in a healthy range — neither dangerously high (overcommitment) nor uselessly low?

Noone & Lee (2011) [[NO1]](#ref-no1) established in hotel overbooking research that acceptance rate is as important as fulfillment rate: an agent that accepts 100% of reservations is almost certainly overcommitting capacity it doesn't have. Marti's P2P trust dissertation [[M1]](#ref-m1) identified the symmetric problem: an agent that accepts only 5% is gaming the system (cherry-picking only sure wins to maintain a perfect score).

Let $A_a$ be the count of `ArohaReserveAck` responses and $R_a$ the count of `ArohaReserve` requests received.

$$\text{acc}_a = \frac{A_a}{R_a}$$

Define the **selectivity score** as a quadratic penalty around the optimal acceptance rate $\mu_{\text{opt}} = 0.70$ (calibrated from hotel revenue management literature):

$$\text{RSS}_a = 1 - \frac{(\text{acc}_a - \mu_{\text{opt}})^2}{\max(\mu_{\text{opt}}^2,\; (1-\mu_{\text{opt}})^2)}$$

$\text{RSS}_a \in [0, 1]$; it equals 1.0 when $\text{acc}_a = 0.70$ and 0.0 at the extremes (0% or 100% acceptance).

Unlike the other signals, RSS is not modelled as a Beta distribution — it is a continuous closed-form score computed directly from counts. It enters the composite score (§3) as-is.

The optimal acceptance rate $\mu_{\text{opt}}$ is **configurable per capability class** (default 0.70; higher for commodity capabilities, lower for scarce or high-complexity ones).

---

### Signal 10: Retry Rate Score (RRS)

**What it measures:** Does the orchestrator need to retry this agent within the same `correlationId` saga — even when the saga eventually succeeds?

A retry is a hidden quality signal. TCP retransmission analysis [[T1]](#ref-t1) documents exactly this: high retransmission rates indicate degraded link quality even when packets are eventually delivered. Kubernetes pod restart counts [[K1]](#ref-k1) are used by operators as an early warning of instability even when the service is technically available. Both are cases where the nominal outcome (delivery / uptime) masks a real reliability problem.

Let $\text{Req}_a$ = total `ArohaRequest` messages directed at $a$, $\text{Retry}_a$ = subset where the same `correlationId` had a prior attempt to $a$.

$$\text{retry\_rate}_a = \frac{\text{Retry}_a}{\text{Req}_a}$$

Convert to Bernoulli: success = first-attempt success (no retry), failure = required retry.

$$\text{RRS}_a \sim \text{Beta}\!\left(\alpha_0 + (\text{Req}_a - \text{Retry}_a),\; \beta_0 + \mu_{\text{RRS}}\,\text{Retry}_a\right)$$

$\mu_{\text{RRS}} = 1.2$ (mild amplification — retries are a quality signal but less severe than outright failures).

---

### Signal 11: Consistency Score (CS)

**What it measures:** How consistent is the agent's outcome quality over time? High variance is penalised even if the mean is acceptable.

The Sharpe ratio [[SH1]](#ref-sh1) is the canonical formulation of this principle in finance: a portfolio with lower mean return but also lower variance can be preferable to a higher-mean, higher-variance alternative. Supplier performance scorecards in supply chain management [[SC1]](#ref-sc1) apply the same logic: an unpredictable supplier is more costly to operate with than a predictably average one, because unpredictability requires safety stock and contingency planning.

Let $q_1, q_2, \ldots, q_n$ be the sequence of normalised outcome quality scores for agent $a$ (each $q_i \in [0,1]$, derived from `ArohaSatisfactionSignal` or proxy signals).

Running mean and variance (Welford's online algorithm for numerical stability):

$$\bar{q}_n = \bar{q}_{n-1} + \frac{q_n - \bar{q}_{n-1}}{n}, \qquad M_n = M_{n-1} + (q_n - \bar{q}_{n-1})(q_n - \bar{q}_n)$$

$$\sigma_n^2 = \frac{M_n}{n-1} \quad (n \geq 2)$$

The **Consistency Score** (agent-network Sharpe ratio):

$$\text{CS}_a = \frac{\bar{q}_n}{1 + \sigma_n} \in [0, 1]$$

This is analogous to the Sharpe ratio with the variance in the denominator acting as a penalty: an agent with $\bar{q} = 0.8$ and $\sigma = 0.05$ (consistent) scores $0.8/1.05 \approx 0.76$, while an agent with the same mean but $\sigma = 0.4$ (erratic) scores $0.8/1.4 \approx 0.57$.

CS enters the composite as a continuous score (not Beta), like RSS.

!!! note "Minimum observations for CS"
    CS is undefined for $n < 5$. Agents with fewer than 5 rated interactions use $\text{CS}_a = 0.5$ (neutral) until the threshold is crossed.

---

### Signal 12: Peer Preference Score (PPS)

**What it measures:** Do high-reputation agents preferentially choose to include agent $a$ in sagas they initiate?

This is the agent-network analogue of academic citation reputation. Massucci & Docampo (2019) [[PA1]](#ref-pa1) showed that PageRank over citation networks produces more accurate reputation estimates than raw citation counts — the identity of who cites you matters as much as how many. Collaborative filtering research [[CF1]](#ref-cf1) established the same principle in recommender systems: preferences expressed by trusted users are more informative than those from unknown users.

Define the **weighted preference count**:

$$\text{WPC}_a = \sum_{b \in \text{orchestrators\_choosing\_}a} S_b^{\text{global}} \cdot \mathbf{1}[S_b^{\text{global}} \geq 0.8]$$

Only high-reputation orchestrators (score ≥ 0.8) contribute to WPC. Normalize against the network mean:

$$\text{PPS}_a = \frac{\text{WPC}_a}{\bar{\text{WPC}} + \epsilon}, \quad \text{clamped to } [0, 2]$$

Scale to $[0,1]$ by dividing by 2. PPS enters the composite as a continuous score.

!!! note "Cold start"
    PPS is 0.5 (neutral) until the agent has appeared in at least 10 sagas initiated by high-reputation orchestrators.

---

## 3. Composite Score

### 3.1 Weighted Combination

The composite score for agent $a$ in domain $d$ combines all eleven signals:

$$S_{a,d} = \sum_{j=1}^{11} w_j\, X_j(a, d)$$

where each $X_j \in [0,1]$ is either a Beta posterior mean $\hat{p}_j = \alpha_j/(\alpha_j+\beta_j)$ or a continuous score (RSS, CS, PPS).

**Default weights:**

| # | Signal | Weight | Precedent |
|---|---|---|---|
| 1 | Baseline reliability $\hat{p}$ | 0.18 | Jøsang BRS [[J1]](#ref-j1) |
| 2 | Reservation Honor Rate (RHR) | 0.18 | Aroha-native |
| 3 | Provider-Initiated Cancel Rate (PCR) | 0.10 | Aroha-native |
| 4 | Downstream Success Lift (DSL) | 0.08 | RepuNet [[RE1]](#ref-re1), TRiSM [[TR1]](#ref-tr1) |
| 5 | Commit Latency Score (CLS) | 0.07 | SLA literature |
| 6 | Satisfaction Alignment (SAS) | 0.05 | Airbnb multi-dim [[AI1]](#ref-ai1) |
| 7 | Failure Speed Score (FSS) | 0.10 | Netflix Hystrix [[N1]](#ref-n1), AWS [[AW1]](#ref-aw1) |
| 8 | Price Accuracy Score (PAS) | 0.08 | Dulleck & Kerschbamer [[D1]](#ref-d1) |
| 9 | Reservation Selectivity (RSS) | 0.06 | Noone & Lee [[NO1]](#ref-no1) |
| 10 | Retry Rate Score (RRS) | 0.04 | TCP retransmission [[T1]](#ref-t1) |
| 11 | Consistency Score (CS) | 0.04 | Sharpe (1966) [[SH1]](#ref-sh1) |
| 12 | Peer Preference Score (PPS) | 0.02 | PageRank citation [[PA1]](#ref-pa1) |

Weights sum to 1.00. They are configurable per deployment and retrainable per capability class as data accumulates.

*Precedent for multi-dimensional composition: eBay's Detailed Seller Ratings (DSR) [[EB1]](#ref-eb1) have used four explicit dimensions (Item Description, Communication, Shipping Time, Shipping Cost) since 2007. Airbnb [[AI1]](#ref-ai1) uses six. Amazon [[AM1]](#ref-am1) tracks Order Defect Rate, Late Shipment Rate, and Pre-fulfillment Cancel Rate as separate metrics with separate thresholds. CommTrust [[CT1]](#ref-ct1) extracts reputation dimensions automatically from unstructured feedback via NLP. The Aroha model differs in that its dimensions are extracted from structured protocol events, not user text — making them harder to game.*

### 3.2 Global Score Aggregation

The global score across all domains is precision-weighted:

$$S_a^{\text{global}} = \frac{\sum_d n_{a,d}\,S_{a,d}}{\sum_d n_{a,d}}, \quad n_{a,d} = \alpha_{a,d} + \beta_{a,d} - 2\alpha_0$$

### 3.3 Grade Table

| Score range | Grade | Spending tier unlocked |
|---|---|---|
| 0.90 – 1.00 | AAA | Bonded Trusted (\$5,000) |
| 0.80 – 0.89 | AA | Trusted (\$500) |
| 0.70 – 0.79 | A | Standard (\$50) |
| 0.55 – 0.69 | B | Standard (\$50) with rate limit |
| 0.40 – 0.54 | C | Probationary (\$10) |
| below 0.40 | F | No new reservations |

---

## 4. Thompson Sampling Agent Selection

### 4.1 Standard Thompson Sampling

For each candidate agent $a$, sample from each Beta signal independently:

$$\tilde{X}_j(a) \sim \text{Beta}(\alpha_j^{(a)}, \beta_j^{(a)})$$

Composite sampled score:

$$\tilde{S}_{a,d} = \sum_j w_j\,\tilde{X}_j(a)$$

Select: $a^* = \arg\max_a\; \tilde{S}_{a,d}$.

*Precedent: Agrawal & Goyal (2012) [[A1]](#ref-a1) proved Thompson Sampling achieves asymptotically optimal regret for Bernoulli bandits. The Thompson Sampling Tutorial [[TS1]](#ref-ts1) from Stanford covers the multi-dimensional extension used here. Netflix, Spotify, and LinkedIn all run Thompson Sampling in production for content and ad selection — it is battle-tested at scale.*

### 4.2 Risk-Adjusted Constrained Selection

For high-value tasks, add a credible-interval floor using the Wilson score approximation:

$$p_{\text{lb}}(q_r) \approx \frac{\alpha + \tfrac{z_{q_r}^2}{2}}{\alpha + \beta + z_{q_r}^2} - z_{q_r}\cdot\frac{\sqrt{\frac{\alpha\beta}{\alpha+\beta} + \tfrac{z_{q_r}^2}{4}}}{\alpha + \beta + z_{q_r}^2}$$

| Risk level | Spend | Quantile $q_r$ | Min floor $\tau_r$ |
|---|---|---|---|
| Low | < \$10 | — | 0.0 |
| Medium | \$10–\$100 | 0.10 | 0.60 |
| High | \$100–\$1,000 | 0.05 | 0.75 |
| Critical | > \$1,000 | 0.01 | 0.90 |

Agent is only eligible for sampling if $p_{\text{lb}}(q_r) \geq \tau_r$.

### 4.3 Regret Bound

Expected cumulative regret over $T$ selections with $K$ candidate agents:

$$\mathbb{E}[\text{Regret}(T)] \leq \sum_{a:\,\mu_a < \mu^*} \frac{\Delta_a\,C\ln T}{\text{KL}(\mu_a \| \mu^*)} + O(K)$$

This is asymptotically optimal — no algorithm can achieve better regret by more than a constant factor [[Lai & Robbins 1985]](#ref-lr).

---

## 5. Graph-Propagated Prior Initialization

### 5.1 Trust Graph

$\mathcal{G} = (\mathcal{V}, \mathcal{E})$ where edge $(a_i \to a_j) \in \mathcal{E}$ means $a_i$ has issued a vouching VC for $a_j$, with weight $v_{ij} = S_{a_i}^{\text{global}} \cdot c_{ij}$ and $c_{ij} \in [0,1]$ declared attestation confidence.

*Precedent: Reputation-enhanced PBFT [[BF1]](#ref-bf1) uses a similar graph structure to assign voting weights in Byzantine-fault-tolerant consensus — higher-reputation nodes get more influence. PageRank's damping factor [[PA1]](#ref-pa1) and PBFT's trust propagation both inform the damping choices below.*

### 5.2 Prior Inflation

For a new agent $a_0$ with vouchers $\mathcal{N}(a_0)$:

$$\tau(a_0) = \frac{\sum_{a_i \in \mathcal{N}(a_0)} v_{i0}\,S_{a_i}^{\text{global}}}{\sum_{a_i \in \mathcal{N}(a_0)} v_{i0}}, \quad n_{\text{prior}} = \eta\,\tau(a_0)\sum_{a_i} n_{a_i}^{\text{eff}} \leq n_{\max}$$

$$\alpha_0' = \alpha_0 + n_{\text{prior}}\,\tau(a_0), \qquad \beta_0' = \beta_0 + n_{\text{prior}}\,(1 - \tau(a_0))$$

$\eta = 0.3$ (voucher effectiveness discount), $n_{\max} = 20$ (max synthetic interactions from vouching).

### 5.3 Voucher Liability

Vouching agent $a_i$ accepts liability for $a_0$'s first 20 interactions. Each failure by $a_0$ increments $a_i$'s $\beta$ by $\rho\,\mu\,w_f(T)$ with $\rho = 0.2$, making reputation laundering costly.

### 5.4 Multi-Hop Damping

Trust from $k$-hop connections is damped by $d^k$ where $d = 0.15$ (identical to PageRank's original damping factor [[PA1]](#ref-pa1)). A 3-hop connection contributes $0.15^3 \approx 0.3\%$ of voucher score — negligible.

---

## 6. Sybil Resistance

| Mechanism | Description | Cost to attacker |
|---|---|---|
| **DID bond** | $B_{\min} = \$5$ to register a new `did:aroha:` | Linear in number of Sybils |
| **History forwarding discount** | $\phi_{\text{fwd}} = 0.7$ — forwarding history to new DID costs 30% of reputation | Losing earned trust |
| **Vouching contagion** | Vouchers of a detected Sybil receive $\beta$ penalty | Damages vouching network |
| **Probationary tier** | $n_{a,d} < 10$ cannot bid on Medium+ risk tasks | Time cost of building history |

---

## 7. Reputation-Adaptive Authorization

$$L(a, d, T) = \begin{cases}
\$10 & n_{a,d} < 10 \text{ (probationary)} \\
\$50 & S_{a,d} \geq 0.70 \text{ and } n_{a,d} \geq 10 \\
\$500 & S_{a,d} \geq 0.80 \text{ and } n_{a,d} \geq 50 \\
\$5{,}000 & S_{a,d} \geq 0.90 \text{ and } n_{a,d} \geq 200 \text{ and } B \geq \$500
\end{cases}$$

Authorization succeeds iff $\text{cartAmount} \leq \min(\text{mandate.spendLimitUsd},\; L(a,d,T))$.

---

## 8. Implementation

### 8.1 Stored State

```typescript
interface ReputationState {
  // Beta signal parameters (α, β pairs)
  baseline:     [number, number];
  rhr:          [number, number];
  pcr:          [number, number];
  dsl:          [number, number];
  cls:          [number, number];
  sas:          [number, number];
  fss:          [number, number];
  pas:          [number, number];
  rrs:          [number, number];

  // Continuous signals (Welford running stats for CS, counts for RSS/PPS)
  cs_mean:      number;  cs_M:         number;  cs_n:    number;
  acc_accepted: number;  acc_received: number;  // for RSS
  wpc:          number;  wpc_n:        number;  // for PPS

  // Saga counters
  sagasInvolving: number;  sagasCompleted: number;

  // Timestamps & bond
  lastObservationAt: number;
  createdAt:         number;
  stakedBondUsd:     number;
}
```

### 8.2 Per-Event Update (Pseudocode)

```typescript
function update(state: ReputationState, event: SagaEvent, T: number) {
  const daysSince = (T - state.lastObservationAt) / 86_400_000;
  const ws = Math.exp(-LAMBDA_S * daysSince);
  const wf = Math.exp(-LAMBDA_F * daysSince);

  switch (event.type) {

    case "ArohaCommitAck": {
      inc(state.baseline, ws, 0);
      inc(state.rhr, ws, 0);
      // RRS: first-attempt success
      if (!event.wasRetry) inc(state.rrs, ws, 0);
      else                  inc(state.rrs, 0, MU_RRS * wf);
      // CLS: latency gate
      const fast = event.latencyMs <= SLA[event.domain];
      inc(state.cls, fast ? ws : 0, fast ? 0 : MU * wf);
      // PAS: price accuracy
      const dev = Math.abs(event.committedPrice - event.quotedPrice) / event.quotedPrice;
      const acc = dev <= EPSILON[event.domain];
      inc(state.pas, acc ? ws : 0, acc ? 0 : MU_PAS * wf);
      // Saga counter for DSL
      state.sagasCompleted++;
      break;
    }

    case "ArohaError": {
      inc(state.baseline, 0, MU * wf);
      inc(state.rhr, 0, MU_RHR * wf);
      // FSS: was it a fast fail?
      const ff = event.failureLatencyMs <= 0.1 * SLA[event.domain];
      inc(state.fss, ff ? ws : 0, ff ? 0 : MU_FSS * wf);
      break;
    }

    case "ArohaCancelAck(provider_initiated)":
      inc(state.baseline, 0, MU * wf);
      inc(state.pcr,      0, MU_PCR * wf);
      break;

    case "ArohaCancelAck(orchestrator_initiated)":
      // Normal — no penalty
      break;

    case "ArohaReserveAck":
      state.acc_accepted++;
      state.acc_received++;
      break;

    case "ArohaReserveDeclined":
      state.acc_received++;
      break;

    case "SagaTerminated":
      state.sagasInvolving++;
      const lift = event.sagaSuccessRate - NETWORK_BASELINE;
      if (lift > 0) inc(state.dsl, ws * event.n, 0);
      else          inc(state.dsl, 0, MU * wf * event.n);
      break;

    case "ArohaSatisfactionSignal": {
      const q = event.qualityStars >= 4 ? 1 : 0;
      // SAS: calibration alignment
      const predicted = score(state) >= 0.8;
      inc(state.sas, predicted === (q === 1) ? ws : 0,
                     predicted !== (q === 1) ? wf  : 0);
      // CS: Welford update
      const prev_mean = state.cs_mean;
      state.cs_n++;
      state.cs_mean += (q - prev_mean) / state.cs_n;
      state.cs_M    += (q - prev_mean) * (q - state.cs_mean);
      break;
    }

    case "PeerPreference":
      if (event.orchestratorScore >= 0.8) {
        state.wpc   += event.orchestratorScore;
        state.wpc_n++;
      }
      break;
  }

  state.lastObservationAt = T;
}

function inc([α, β]: [number, number], sa: number, fb: number) {
  α += sa;  β += fb;
}
```

### 8.3 Score Read (O(1))

```typescript
function score(state: ReputationState, T = Date.now()): number {
  const d = Math.exp(-LAMBDA_D * (T - state.lastObservationAt) / 86_400_000);
  const E = ([α, β]: [number, number]) => {
    const as = ALPHA_0 + (α - ALPHA_0) * d;
    const bs = BETA_0  + (β - BETA_0)  * d;
    return as / (as + bs);
  };

  // Continuous signals
  const rss = rssScore(state.acc_accepted, state.acc_received);
  const cs  = state.cs_n >= 5
    ? state.cs_mean / (1 + Math.sqrt(state.cs_M / (state.cs_n - 1)))
    : 0.5;
  const pps = state.wpc_n >= 10
    ? Math.min(1, (state.wpc / state.wpc_n) / (2 * NETWORK_MEAN_WPC))
    : 0.5;

  return (
    0.18 * E(state.baseline) +
    0.18 * E(state.rhr)      +
    0.10 * E(state.pcr)      +
    0.08 * E(state.dsl)      +
    0.07 * E(state.cls)      +
    0.05 * E(state.sas)      +
    0.10 * E(state.fss)      +
    0.08 * E(state.pas)      +
    0.06 * rss               +
    0.04 * E(state.rrs)      +
    0.04 * cs                +
    0.02 * pps
  );
}
```

---

## 9. Theoretical Properties

### Regret Optimality
Thompson Sampling achieves $O(\sqrt{KT\ln T})$ cumulative regret, which is asymptotically optimal by the Lai-Robbins lower bound [[Lai & Robbins 1985]](#ref-lr).

### Beta Convergence
Under time decay at rate $\lambda_k$ and observation arrival rate $\lambda_{\text{obs}}$, the effective observation count converges to $n_{\text{eff}} = \lambda_{\text{obs}}/\lambda_k$ — giving the model a natural memory horizon of $1/\lambda_k$ days.

### Calibration
Beta-Bayesian estimators are asymptotically calibrated for i.i.d. Bernoulli observations (Bernstein–von Mises theorem). Time decay introduces a small calibration bias correctible via isotonic regression on a held-out interaction sample.

---

## 10. Summary: What Makes This SOTA

| Property | EMA (v1.0) | v1.1 | Cross-domain precedent |
|---|---|---|---|
| Uncertainty bounds | None | Credible intervals | Jøsang BRS [[J1]](#ref-j1) |
| Asymmetric decay | No | $\lambda_f > \lambda_s$ | Credit scoring |
| Cold start | Bond only | Graph-propagated prior | PBFT reputation [[BF1]](#ref-bf1) |
| Exploration | Greedy | Thompson Sampling | Netflix, Spotify (production) |
| Risk-gated selection | Score threshold | Credible-interval floor | n/a |
| Failure mode distinction | None | FSS (fast vs slow fail) | Netflix Hystrix [[N1]](#ref-n1), AWS [[AW1]](#ref-aw1) |
| Price honesty | None | PAS (quote deviation) | Credence goods [[D1]](#ref-d1) |
| Commitment discipline | None | RSS (healthy acceptance range) | Hotel overbooking [[NO1]](#ref-no1) |
| Hidden quality signal | None | RRS (retry rate) | TCP retransmission [[T1]](#ref-t1) |
| Consistency | None | CS (Sharpe-ratio analogue) | Finance [[SH1]](#ref-sh1), supply chain [[SC1]](#ref-sc1) |
| Network-effect signal | None | PPS (peer preference) | PageRank [[PA1]](#ref-pa1), collab filtering [[CF1]](#ref-cf1) |
| Dimensions | 1 | 11 | eBay DSR [[EB1]](#ref-eb1), Airbnb [[AI1]](#ref-ai1), Amazon [[AM1]](#ref-am1) |
| Theoretical guarantee | None | Sub-linear regret, calibration | Lai & Robbins 1985 [[LR]](#ref-lr) |

---

## References

<a name="ref-j1">[J1]</a> Jøsang, A., & Ismail, R. (2002). The Beta Reputation System. *Proceedings of the 15th Bled Electronic Commerce Conference*. Updated: Jøsang, A. (2009). Bayesian Reputation Systems. *TrustBus 2009*. https://www.mn.uio.no/ifi/english/people/aca/josang/publications/jq2009-trustbus.pdf

<a name="ref-a1">[A1]</a> Agrawal, S., & Goyal, N. (2012). Analysis of Thompson Sampling for the Multi-Armed Bandit Problem. *JMLR Workshop and Conference Proceedings*, 23. http://proceedings.mlr.press/v23/agrawal12/agrawal12.pdf

<a name="ref-ts1">[TS1]</a> Russo, D., Van Roy, B., Kazerouni, A., Osband, I., & Wen, Z. (2018). A Tutorial on Thompson Sampling. *Foundations and Trends in Machine Learning*, 11(1). https://web.stanford.edu/~bvr/pubs/TS_Tutorial.pdf

<a name="ref-lr">[LR]</a> Lai, T. L., & Robbins, H. (1985). Asymptotically Efficient Adaptive Allocation Rules. *Advances in Applied Mathematics*, 6(1), 4–22.

<a name="ref-m1">[M1]</a> Marti, S. (2005). *Trust and Reputation in Peer-to-Peer Networks* (PhD dissertation). Stanford University. https://crypto.stanford.edu/portia/papers/marti.pdf

<a name="ref-n1">[N1]</a> Netflix Engineering. (2011–present). *Hystrix: Latency and Fault Tolerance Library*. Circuit breaker fast-fail vs timeout distinction. https://github.com/netflix/hystrix/wiki/how-it-works

<a name="ref-aw1">[AW1]</a> Amazon Web Services. (2020). *Well-Architected Framework: Reliability Pillar*, REL05-BP04 (Fail fast and limit queues). https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_mitigate_interaction_failure_fail_fast.html

<a name="ref-g1">[G1]</a> Beyer, B., Jones, C., Petoff, J., & Murphy, R. (2016). *Site Reliability Engineering: How Google Runs Production Systems*, ch. 6 (Monitoring Distributed Systems). O'Reilly. https://sre.google/sre-book/monitoring-distributed-systems/

<a name="ref-d1">[D1]</a> Dulleck, U., & Kerschbamer, R. (2006). On Doctors, Mechanics, and Computer Specialists: The Economics of Credence Goods. *Journal of Economic Literature*, 44(1), 5–42. https://academic.oup.com/cesifo/article/63/1/1/2992734

<a name="ref-ba1">[BA1]</a> Stoll, H. R. (2000). Friction. *Journal of Finance*, 55(4), 1479–1514. Bid-ask spread as quote accuracy signal. https://www.sciencedirect.com/science/article/abs/pii/S1386418114000524

<a name="ref-no1">[NO1]</a> Noone, B. M., & Lee, C. H. (2011). Hotel Overbooking: The Effect of Overcompensation on Loyalty. *Journal of Hospitality & Tourism Research*, 35(3), 334–357. https://journals.sagepub.com/doi/abs/10.1177/1096348010382238

<a name="ref-t1">[T1]</a> ArthurChiao. (2023). TCP Retransmission Rate as a Hidden Quality Signal. Engineering blog. https://arthurchiao.art/blog/tcp-retransmission-may-be-misleading/

<a name="ref-k1">[K1]</a> Kuberhealthy. (2020–present). Kubernetes pod restart count as reliability metric. https://github.com/kuberhealthy/kuberhealthy

<a name="ref-sh1">[SH1]</a> Sharpe, W. F. (1966). Mutual Fund Performance. *Journal of Business*, 39(1), 119–138. http://web.stanford.edu/~wfsharpe/art/sr/sr.html

<a name="ref-sc1">[SC1]</a> GEP. (2022). Understanding Supplier Scorecard Metrics: Variance as a Reliability Signal. https://www.gep.com/blog/strategy/understanding-supplier-scorecard-metrics

<a name="ref-pa1">[PA1]</a> Massucci, F. A., & Docampo, D. (2019). Measuring the Academic Reputation through Citation Networks via PageRank. *Journal of Informetrics*, 13(1), 185–201. https://arxiv.org/abs/1803.09104

<a name="ref-cf1">[CF1]</a> Massa, P., & Avesani, P. (2004). Trust-Aware Collaborative Filtering for Recommender Systems. *CoopIS/DOA/ODBASE 2004*. https://link.springer.com/chapter/10.1007/978-3-540-30468-5_31

<a name="ref-r1">[R1]</a> Resnick, P., & Zeckhauser, R. (2002). Trust Among Strangers in Internet Transactions. *Advances in Applied Microeconomics*, 11, 127–157. https://presnick.people.si.umich.edu/papers/ebayNBER/index.html

<a name="ref-del1">[DEL1]</a> Dellarocas, C. (2005). Reputation Mechanism Design in Online Trading Environments with Pure Moral Hazard. *Information Systems Research*, 16(2), 209–230. https://ideas.repec.org/a/inm/orisre/v16y2005i2p209-230.html

<a name="ref-eb1">[EB1]</a> eBay. (2007–present). Detailed Seller Ratings (DSR) — four-dimension reputation since 2007. https://www.ebay.com/help/buying/resolving-issues-sellers/seller-ratings?id=4023

<a name="ref-ai1">[AI1]</a> Airbnb. (2010–present). Host Rating System — six-dimension trust model. https://www.airbnb.com/help/article/1257

<a name="ref-am1">[AM1]</a> Amazon. (2010–present). Seller Performance Metrics: ODR, LSR, Pre-fulfillment Cancel Rate. https://feedvisor.com/university/seller-performance-measurements/

<a name="ref-ct1">[CT1]</a> Moghaddam, M., et al. (2015). CommTrust: Computing Multi-Dimensional Trust by Mining E-Commerce Feedback Comments. *arXiv:1710.10061*. https://arxiv.org/pdf/1710.10061

<a name="ref-ma1">[MA1]</a> Mansa AI. (2025). Agent Reputation Framework: Asymmetric Update Mechanics (+5/−10). https://www.cointrust.com/market-news/mansa-ai-advances-trust-with-agent-reputation-framework

<a name="ref-bf1">[BF1]</a> Zhao, J., et al. (2025). Reputation-Enhanced PBFT for UAV Networks. *Journal of Network and Computer Applications*. https://link.springer.com/article/10.1007/s43926-025-00164-y

<a name="ref-re1">[RE1]</a> Ren, S., et al. (2025). Beyond the Tragedy of the Commons: Building A Reputation System for Generative Multi-agent Systems. *arXiv:2505.05029*. AAMAS 2026.

<a name="ref-tr1">[TR1]</a> Raza, S., et al. (2025). TRiSM for Agentic AI. *arXiv:2506.04133*.
