# Cerberus — Zero-Trust Access Control for Decentralized APIs

**Team Sentinel** | InnovaHack Chapter-1 | Domain 2: Cybersecurity (PS 2)

> "Just like Cerberus guards the gates with multiple heads, our system guards
> microservices with 5 layers of defense — each watching a different angle."

## Problem
Traditional perimeter firewalls can't police internal lateral API traffic. An
attacker who compromises one edge microservice can move laterally across the
internal network, scraping backend databases via unsecured APIs — before any
manual response happens.

## Solution
A lightweight zero-trust service mesh proxy that enforces cryptographic-style
identity + contextual policy checks on every inter-service request, with 5
integrated layers:

1. **Trust Decay + Blast Radius Prediction** — trust scores drain like a
   battery; on compromise, weighted BFS over the call-graph predicts which
   services are at risk *next*, before the attacker reaches them.
2. **Honeytoken Trap Network** — decoy endpoints no legit service ever calls;
   any touch = 100% confirmed malicious, auto-quarantine.
3. **Behavioral Fingerprint Verification** — rolling payload-size baseline
   per service, z-score deviation catches stolen-but-valid-token attacks.
4. **Self-Healing Micro-Segmentation** — compromised services are
   auto-quarantined (traffic blocked) for a cooldown, then auto-healed to a
   cautious trust level — no human intervention needed.
5. **Risk-Adaptive Rate Limiting** — sliding-window rate limit tied to live
   trust score, throttles suspicious behavior gradually.
6. **Ask Cerberus (Lyzr agent)** — natural-language SOC-analyst panel on the
   dashboard. The core decision engine above stays pure rule-based math;
   this is a read-only explainer layer on top, powered by a Lyzr agent, that
   answers questions like "why was OrderService quarantined?" using the live
   trust/event-log state as context.

## AI / Data-Science Upgrade Layer (`ml_layer.py`)
Added on top of the original 6 rule-based layers — **additive/advisory**,
the core decision path (`/proxy/request`) stays pure auditable rule-based
math; these layers enrich it with learned predictions and explanations:

7. **Learned Blast-Radius Predictor** — a `RandomForestRegressor`
   (scikit-learn) trained on Monte-Carlo–simulated propagation episodes
   over the call graph, replacing the fixed `0.7**hop` decay formula.
   Retrains itself as real incidents accumulate (`record_incident`).
   Compare it live against the original rule-based formula: both are
   returned side-by-side in `/simulate/attack` (`blast_radius` vs
   `ml_blast_radius`).
8. **ML Behavioral Anomaly Model** — a per-service `IsolationForest` over
   `[payload_size, hour_of_day, seconds_since_last_call]`, catching
   stolen-but-valid-token attacks that deviate in *cadence*, not just
   payload size (the original z-score check only looked at payload size).
9. **Synthetic Adversarial Traffic Generator** — `POST /simulate/synthetic_attack`
   fires a generated burst of varied attack patterns (lateral probes,
   credential replay, bulk scrapes, honeytoken scans) through the real
   proxy pipeline — good for demos ("AI attacks, AI defends") and
   stress-testing without hand-scripting each request.
10. **Explainable Quarantine Decisions** — every block/quarantine now
    carries a feature-attribution breakdown (SHAP over the
    IsolationForest where enough history exists, falling back to a
    manual normalized breakdown of the rule-based components). See
    `GET /explain/{service}` or the `explanation` field on any blocked
    `/proxy/request` response.
11. **Extractive Log Summarizer** — `GET /summary` gives a rolling,
    frequency-based digest of recent activity with zero configuration
    (no LLM/API key needed) — a fast always-on companion to the
    Lyzr-powered "Ask Cerberus" chat panel, which does need
    `LYZR_API_KEY`/`LYZR_AGENT_ID` configured.

## Dashboard Extras
12. **System Health Score card** — glanceable ring score (avg trust +
    demonstrated-defense bonus) plus raw metrics (avg trust, attacks
    defended, requests blocked, honeytoken hits).
13. **Compare Mode toggle** — flip the ML behavioral layer on/off live
    (`POST /toggle/ml_layer?enabled=false`) and replay the same attack to
    show judges the difference the AI layer makes.
14. **Export Incident Report** — downloads a full JSON snapshot
    (`GET /export/report`): live state, full event log, honeytoken hits,
    and the extractive digest — handy for post-demo review.

## Tech Stack
- **Backend:** Python, FastAPI, in-memory state, WebSocket live push,
  asyncio background loops (trust decay, quarantine watchdog)
- **AI/ML:** scikit-learn (RandomForest, IsolationForest), SHAP, NumPy —
  see `ml_layer.py`
- **Frontend:** Single-file `dashboard.html` — vanilla JS + SVG graph,
  live trust bars, rate-limit/fingerprint/quarantine panels, event log

## Run Locally
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Then open `dashboard.html` in a browser.

### Enable "Ask Cerberus" (optional, Lyzr agent)
Create an agent in [Lyzr Studio](https://studio.lyzr.ai) with a system prompt
like: *"You are a SOC analyst assistant for a zero-trust service mesh. You'll
get a live state snapshot + question — answer citing specific services and
trust scores."* Then run with your credentials set:
```bash
LYZR_API_KEY=your_key LYZR_AGENT_ID=your_agent_id uvicorn main:app --reload --port 8000
```
Without these set, the panel shows a friendly "not configured yet" message
instead of erroring.

## Demo Topology
5 services — OrderService, PaymentService, InventoryService, BankGateway,
UserDBService — with a defined legitimate call graph. Use the dashboard
controls to simulate attacks, honeytoken probes, and normal traffic.

## Team
Malavika · Soham
