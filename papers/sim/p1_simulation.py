# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0
#
# Simulation for Paper 1 — "Asymmetric Temporal Decay in Bayesian Reputation
# Systems for Open Multi-Agent AI Networks".
#
# Implements the evaluation protocol of §Evaluation exactly:
#   population   n = 200 agents: 60% stable, 25% degrading, 15% recovering
#   observations 5 Bernoulli trials / agent / day, success prob q_i(t)
#   signals      s1 (success, w=1.00) and s2 (failure, w=1.20), Table `signals`
#   update       decay operator D_{tau_s,tau_f} (Def. `decay`, half-life form)
#                followed by the additive Bayesian update (the deployed
#                signals path: alpha += w1*k, beta += w2*(m-k))
#   prior        Jeffreys alpha0 = beta0 = 0.5
#   score        posterior mean q_hat = alpha / (alpha + beta), threshold 0.70
#   horizon      365 days, R = 1000 independent runs
#
# Methods compared:
#   no-decay     tau_s = tau_f = infinity
#   symmetric    tau_s = tau_f = 90 days
#   aroharep     tau_s = 180, tau_f = 60 days
#
# Metrics (§Metrics):
#   T_det   days from quality drop until q_hat < 0.70 (degrading agents);
#           undetected-by-horizon agents are censored at (365 - T_drop) and
#           the censoring rate is reported
#   FPR     fraction of recovering agents with q_hat < 0.70 at any time
#           more than 14 days after recovery
#   RQ@10   mean true quality of the top-10 agents by Thompson sampling
#           (one Beta draw per agent), averaged over weekly evaluations
#           from day 30
#
# Usage:  python p1_simulation.py [--runs 1000] [--seed 7] [--rho-sweep]

import argparse
import json
import time

import numpy as np

ALPHA0 = BETA0 = 0.5
W_SUCCESS, W_FAILURE = 1.00, 1.20
TRIALS_PER_DAY = 5
DAYS = 365
THRESHOLD = 0.70
N_AGENTS = 200
N_STABLE, N_DEGRADING, N_RECOVERING = 120, 50, 30  # 60% / 25% / 15%

METHODS = {
    "no-decay":  (np.inf, np.inf),
    "symmetric": (90.0, 90.0),
    "aroharep":  (180.0, 60.0),
}


def simulate_run(rng: np.random.Generator, methods=METHODS):
    """One 365-day run. Returns per-method metric contributions."""
    # ── True quality trajectories ──────────────────────────────────────────
    q = np.empty((DAYS, N_AGENTS))

    q_stable = rng.uniform(0.7, 1.0, N_STABLE)
    q[:, :N_STABLE] = q_stable

    d0, d1 = N_STABLE, N_STABLE + N_DEGRADING
    q_hi = rng.uniform(0.8, 1.0, N_DEGRADING)
    q_lo = rng.uniform(0.0, 0.2, N_DEGRADING)
    t_drop = rng.uniform(30, 180, N_DEGRADING)
    days_col = np.arange(DAYS)[:, None]
    q[:, d0:d1] = np.where(days_col < t_drop[None, :], q_hi[None, :], q_lo[None, :])

    r0 = d1
    q_lo_r = rng.uniform(0.0, 0.3, N_RECOVERING)
    q_hi_r = rng.uniform(0.8, 1.0, N_RECOVERING)
    t_rec = rng.uniform(30, 90, N_RECOVERING)
    q[:, r0:] = np.where(days_col < t_rec[None, :], q_lo_r[None, :], q_hi_r[None, :])

    # ── Shared observations across methods (paired comparison) ────────────
    successes = rng.binomial(TRIALS_PER_DAY, q)          # (DAYS, N)
    failures = TRIALS_PER_DAY - successes

    out = {}
    for name, (tau_s, tau_f) in methods.items():
        ds = 0.0 if np.isinf(tau_s) else np.log(2.0) / tau_s
        df = 0.0 if np.isinf(tau_f) else np.log(2.0) / tau_f
        decay_s, decay_f = np.exp(-ds), np.exp(-df)      # per-day factors

        alpha = np.full(N_AGENTS, ALPHA0)
        beta = np.full(N_AGENTS, BETA0)

        qhat = np.empty((DAYS, N_AGENTS))
        rq_samples = []

        for t in range(DAYS):
            # Decay excess over the prior (Def. `decay`), then additive update
            alpha = ALPHA0 + (alpha - ALPHA0) * decay_s
            beta = BETA0 + (beta - BETA0) * decay_f
            alpha = alpha + W_SUCCESS * successes[t]
            beta = beta + W_FAILURE * failures[t]
            qhat[t] = alpha / (alpha + beta)

            # Weekly Thompson-sampling evaluation from day 30
            if t >= 30 and (t - 30) % 7 == 0:
                draws = rng.beta(alpha, beta)
                top10 = np.argpartition(draws, -10)[-10:]
                rq_samples.append(q[t, top10].mean())

        # ── T_det over degrading agents ────────────────────────────────────
        det_times, censored = [], 0
        for j in range(N_DEGRADING):
            a = d0 + j
            start = int(np.ceil(t_drop[j]))
            below = np.nonzero(qhat[start:, a] < THRESHOLD)[0]
            if below.size:
                det_times.append(float(below[0]))
            else:
                det_times.append(float(DAYS - start))
                censored += 1

        # ── FPR over recovering agents ─────────────────────────────────────
        # Fraction of post-grace agent-days on which a recovered agent is
        # still blocked (q_hat < threshold), 14-day grace after recovery.
        blocked_days, total_days = 0, 0
        for j in range(N_RECOVERING):
            a = r0 + j
            start = int(np.ceil(t_rec[j] + 14))
            if start < DAYS:
                window = qhat[start:, a]
                blocked_days += int(np.sum(window < THRESHOLD))
                total_days += window.size

        out[name] = {
            "t_det_mean": float(np.mean(det_times)),
            "censored": censored,
            "n_degrading": N_DEGRADING,
            "fp": blocked_days,
            "n_recovering": total_days,
            "rq10": float(np.mean(rq_samples)),
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--rho-sweep", action="store_true",
                    help="additionally sweep rho = tau_s/tau_f with tau_f = 60")
    args = ap.parse_args()

    methods = dict(METHODS)
    if args.rho_sweep:
        for rho in (1.0, 1.5, 2.0, 3.0, 4.0, 5.0):
            methods[f"rho={rho}"] = (60.0 * rho, 60.0)

    rng = np.random.default_rng(args.seed)
    agg = {m: {"t": [], "fp": 0, "nrec": 0, "cens": 0, "ndeg": 0, "rq": []}
           for m in methods}

    t0 = time.time()
    for r in range(args.runs):
        res = simulate_run(rng, methods)
        for m, v in res.items():
            agg[m]["t"].append(v["t_det_mean"])
            agg[m]["fp"] += v["fp"]
            agg[m]["nrec"] += v["n_recovering"]
            agg[m]["cens"] += v["censored"]
            agg[m]["ndeg"] += v["n_degrading"]
            agg[m]["rq"].append(v["rq10"])
        if (r + 1) % 100 == 0:
            print(f"  run {r + 1}/{args.runs}  ({time.time() - t0:.0f}s)")

    print(f"\n{'Method':<14} {'T_det (days)':>16} {'cens%':>7} "
          f"{'FPR%':>7} {'RQ@10':>8}")
    results = {}
    for m in methods:
        t_mean = float(np.mean(agg[m]["t"]))
        t_std = float(np.std(agg[m]["t"]))
        fpr = 100.0 * agg[m]["fp"] / agg[m]["nrec"]
        cens = 100.0 * agg[m]["cens"] / agg[m]["ndeg"]
        rq = float(np.mean(agg[m]["rq"]))
        results[m] = {"t_det_mean": round(t_mean, 1), "t_det_std": round(t_std, 1),
                      "censored_pct": round(cens, 1), "fpr_pct": round(fpr, 1),
                      "rq10": round(rq, 3)}
        print(f"{m:<14} {t_mean:>10.1f} ± {t_std:<4.1f} {cens:>6.1f} "
              f"{fpr:>7.1f} {rq:>8.3f}")

    with open("p1_results.json", "w") as f:
        json.dump({"runs": args.runs, "seed": args.seed, "results": results}, f, indent=2)
    print(f"\nwritten p1_results.json  ({time.time() - t0:.0f}s total)")


if __name__ == "__main__":
    main()
