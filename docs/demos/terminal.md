<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Terminal Demo

`npm run demo:vc` runs two live scenarios back-to-back in the terminal (~35 seconds).
No blockchain, no IPFS, no API keys required.

> The saga, settlement and on-chain parts of these demos use optional extensions, not the core protocol ([extensions document](../spec/extensions.md), [positioning](../positioning.md)). For the core mandate flow, run `npm run demo:mandate` (no network, no server).

## Prerequisites

```bash
npm install && npm run build
```

Optionally set `ANTHROPIC_API_KEY` to stream real Claude reasoning.

## Run

```bash
npm run demo:vc
# or with real LLM:
ANTHROPIC_API_KEY=sk-ant-... npm run demo:vc
```

---

## Scenario 1 — Travel Saga

PersonalAgent books a Tokyo trip atomically across FlightAgent and HotelAgent.

```
▶  Scenario 1: Travel Saga
   PersonalAgent → decomposeIntent("Book a round trip Tokyo June 1–7")
   [AI thinking] Intent decomposition: book-flight + book-hotel

   PersonalAgent → FlightAgent  ArohaRequest (search-flights)
   FlightAgent  → PersonalAgent ArohaResponse { FL1: ¥82,000, FL2: ¥67,000 }

   PersonalAgent → HotelAgent   ArohaRequest (search-hotels)
   HotelAgent   → PersonalAgent ArohaResponse { Shinjuku Grand ¥24,000/night, ... }

   [AI thinking] Selecting FL2 (cheaper, 1 stop) + Shinjuku Grand (central location)

   ── Saga Phase 1: Reserve ──────────────────────────────
   PersonalAgent → FlightAgent  ArohaReserve (book-flight FL2, hold 5 min)
   PersonalAgent → HotelAgent   ArohaReserve (book-hotel Shinjuku Grand, hold 5 min)
   FlightAgent  → PersonalAgent ArohaReserveAck { token: RES-A1B2 }
   HotelAgent   → PersonalAgent ArohaReserveAck { token: RES-C3D4 }

   ── Saga Phase 2: Commit ──────────────────────────────
   PersonalAgent → FlightAgent  ArohaCommit { token: RES-A1B2 }
   PersonalAgent → HotelAgent   ArohaCommit { token: RES-C3D4 }
   FlightAgent  → PersonalAgent ArohaCommitAck { pnr: PNR829341 }
   HotelAgent   → PersonalAgent ArohaCommitAck { ref: HTL-292847 }

   [AI thinking] Trip confirmed. Generating summary...

   ✓  TRIP CONFIRMED
      Flight:  NH834 Tokyo-LHR → NRT, June 1 | PNR: PNR829341
      Hotel:   Shinjuku Grand, Jun 1–7 (6 nights) | Ref: HTL-292847
      Total:   ¥211,000 (~$1,410)
```

**What this proves:**

- Multi-party atomic saga across independent agents
- LLM drives every decision (intent → selection → summary)
- Rollback would trigger if either commit failed

---

## Scenario 2 — Hedge Fund Analyst (MCP data wedge)

HedgeFundAgent pays $0.20 to TwitterScraperMCP for real-time BTC sentiment.

```
▶  Scenario 2: Hedge Fund Analyst × MCP data wedge
   HedgeFundAgent → decomposeIntent("Generate Q2 BTC outlook report")
   [AI thinking] Need: real-time sentiment + on-chain activity

   HedgeFundAgent → TwitterScraperMCP ArohaRequest
   {
     "capability": "sentiment-score",
     "params": { "ticker": "BTC", "window": "1h" },
     "payment": { "amount": 0.20, "currency": "USD" }
   }
   → MCP tool call: aroha_sentiment_score({ ticker: "BTC", window: "1h" })
   ← { score: 0.73, signal: "BULLISH", confidence: 0.91, sampleSize: 12847 }

   TwitterScraperMCP → HedgeFundAgent ArohaResponse { sentiment data }

   [AI thinking] Synthesising Q2 outlook...

   ── Q2 BTC OUTLOOK REPORT ────────────────────────────
   Sentiment Score: 0.73 (BULLISH, 91% confidence)
   Sample: 12,847 Twitter/X posts, past 1 hour

   Key signals:
   • ETF inflows remain strong (~$420M daily average)
   • Network hash rate at ATH — miner confidence high
   • Social sentiment diverging positively from 30-day MA

   Q2 Price Target: $115,000–$135,000
   Risk: Fed pivot delay, regulatory clarity pending

   Payment settled: $0.20 → did:aroha:twitter-scraper-mcp
   ────────────────────────────────────────────────────
```

**What this proves:**

- Micro-payments between agents (invisible to application code)
- MCP bridge — any MCP server is instantly a Aroha provider
- Machine-to-machine data commerce at sub-dollar granularity

---

## Enabling real Claude reasoning

With `ANTHROPIC_API_KEY` set, the three `[AI thinking]` panels stream real Claude
reasoning to the terminal. Without a key, the demo uses realistic pre-written text
and still demonstrates the full protocol correctly.

```bash
ANTHROPIC_API_KEY=sk-ant-api03-... npm run demo:vc
```

The model used is `claude-sonnet-4-6` (configurable in `scripts/demo-vc-terminal.mjs`).
