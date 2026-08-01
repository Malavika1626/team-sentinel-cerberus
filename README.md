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

## Tech Stack
- **Backend:** Python, FastAPI, in-memory state, WebSocket live push,
  asyncio background loops (trust decay, quarantine watchdog)
- **Frontend:** Single-file `dashboard.html` — vanilla JS + SVG graph,
  live trust bars, rate-limit/fingerprint/quarantine panels, event log

## Run Locally
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Then open `dashboard.html` in a browser.

## Demo Topology
5 services — OrderService, PaymentService, InventoryService, BankGateway,
UserDBService — with a defined legitimate call graph. Use the dashboard
controls to simulate attacks, honeytoken probes, and normal traffic.

## Team
Malavika · Soham
