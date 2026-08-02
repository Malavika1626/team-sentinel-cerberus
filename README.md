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
6. **Ask Cerberus (Lyzr agent #1)** — natural-language SOC-analyst panel on
   the dashboard. The core decision engine above stays pure rule-based math;
   this is a read-only explainer layer on top, powered by a Lyzr agent, that
   answers questions like "why was OrderService quarantined?" using the live
   trust/event-log state as context.
6b. **Cerberus Narrator (Lyzr agent #2)** — a second, independent Lyzr agent
   with a different job: it writes the executive-summary paragraph of the
   downloadable incident PDF report, one-shot (state in, prose out), no
   chat session. Falls back to a rule-based digest summary if unconfigured.

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
    and the extractive digest — handy for post-demo review. Also
    available as a one-page **PDF report** (`GET /export/report_pdf`),
    a more presentable artifact for judges or a submission packet.
15. **MITRE ATT&CK tagging** — every synthetic attack pattern (lateral
    probe, credential replay, bulk scrape, honeytoken scan) and every
    simulated compromise is tagged with a real ATT&CK technique ID,
    name, and tactic (`ml_blast_radius`/`/simulate/*` responses,
    `MITRE_ATTACK_MAP` in `main.py`). Best-effort educational mapping,
    not an official MITRE-certified classification.
16. **Seed Demo Traffic** — `POST /seed_demo` fires a batch of benign,
    realistic requests across the real call graph so the dashboard isn't
    sitting at a cold, empty state (no trust history, no behavioral
    baselines) for the first 10-15 seconds in front of judges.
17. **Incident Replay** — `GET /history` returns a scrubbable timeline of
    trust/quarantine snapshots recorded continuously (every decay tick)
    plus at key moments (compromise, quarantine, honeytoken hit,
    auto-heal), with labels on the notable events. The dashboard's
    "Incident Replay" panel lets you drag a slider back through an
    attack after the fact instead of only ever seeing the live moment.

## More Lyzr Agents
Four more independent, optional Lyzr agents on top of "Ask Cerberus" and
"Cerberus Narrator" — same pattern (own env var, own graceful fallback,
never blocks the core rule-based engine):

18. **Threat Hunter** (`GET /threat_hunt`) — proactive, not question-driven:
    reads the live snapshot and flags what a SOC analyst should look at
    right now (trust drops, repeated blocks, honeytoken activity). Falls
    back to a rule-based heuristic summary if unconfigured.
19. **Remediation Advisor** (`POST /advise/{service}`) — one-shot, same
    state-in/prose-out shape as the Narrator, but per-service: writes a
    short actionable remediation playbook (3-5 steps) for one service's
    current incident.
20. **Policy Tuning Agent** (`GET /policy_review`) — reads the current
    rule-based thresholds (trust decay rate, rate-limit window, quarantine
    cooldown) plus recent traffic stats and suggests tuning. Advisory only —
    never mutates config itself.
21. **Forensics Q&A** (`POST /forensics`) — a chat agent like Ask Cerberus,
    but scoped to the *historical* incident-replay timeline + full event
    log instead of only the live moment, for after-the-fact root-cause
    questions. Own session store, own agent id.

```bash
LYZR_HUNTER_AGENT_ID=your_hunter_agent_id \
LYZR_ADVISOR_AGENT_ID=your_advisor_agent_id \
LYZR_POLICY_AGENT_ID=your_policy_agent_id \
LYZR_FORENSICS_AGENT_ID=your_forensics_agent_id \
uvicorn main:app --reload --port 8000
```
Each is independent — set any subset alongside `LYZR_API_KEY`. Unset ones
just fall back to their rule-based/informational message; nothing errors.

## Tech Stack
- **Backend:** Python, FastAPI, in-memory state, WebSocket live push,
  asyncio background loops (trust decay, quarantine watchdog)
- **AI/ML:** scikit-learn (RandomForest, IsolationForest), SHAP, NumPy —
  see `ml_layer.py`
- **Frontend:** Single-file `dashboard.html` — vanilla JS + SVG graph,
  live trust bars, rate-limit/fingerprint/quarantine panels, event log
- **Reporting:** reportlab (PDF incident reports)
- **Tests:** pytest + FastAPI TestClient — `tests/test_core.py` covers
  the rule-based decision engine, attack simulation/quarantine, MITRE
  tagging, replay history, seed_demo, exports, and Lyzr degradation.
  Run with `pytest -v` from the project root.

## Run Locally
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Then open `dashboard.html` in a browser.

### Run the test suite
```bash
pip install -r requirements.txt   # includes pytest + httpx
pytest -v
```

### Enable Lyzr Agents (six independent agents, six jobs)
Cerberus uses **six separate Lyzr Studio agents**, each optional and each
degrading gracefully on its own if unset — the core zero-trust engine
(`/proxy/request`) never depends on any of them being configured:

**1. "Ask Cerberus" (Trust Guardian)** — interactive SOC Q&A panel on the
dashboard (`POST /analyze`). Create an agent in
[Lyzr Studio](https://studio.lyzr.ai) with a system prompt like: *"You are a
SOC analyst assistant for a zero-trust service mesh. You'll get a live state
snapshot + question — answer citing specific services and trust scores."*

**2. "Cerberus Narrator" (Report Sentinel)** — writes the AI-generated
executive summary paragraph of the incident PDF report
(`GET /export/report_pdf`). System prompt like: *"You are writing the
executive summary for a zero-trust security incident report. Given a state
snapshot, write 3-5 plain prose sentences a SOC lead could paste into a
post-mortem — no headers, no bullet points."* One-shot (no chat, no
session) — state in, prose out.

**3. "Threat Hunter" (Mesh Guardian)** — proactive live-state scan
(`GET /threat_hunt`), no question needed. System prompt like: *"You are a
proactive threat hunter for a zero-trust service mesh. Given the live
snapshot, flag anything a SOC analyst should look at right now — unusual
trust drops, repeated blocks, honeytoken activity."*

**4. "Remediation Advisor" (Playbook Guardian)** — one-shot remediation
playbook for a single service (`POST /advise/{service}`). System prompt
like: *"You are a SOC remediation advisor. Given the incident context for
one service, write a short, actionable playbook (3-5 concrete steps)."*

**5. "Policy Tuning Agent" (Threshold Tuner)** — advisory threshold-tuning
suggestions (`GET /policy_review`), read-only — never changes config
itself. System prompt like: *"You are a security policy tuning advisor.
Given current thresholds and recent traffic, suggest whether any should be
tuned, and why."*

**6. "Chronos Forensics Engine" (Forensics Q&A)** — chat agent over the
*historical* incident-replay timeline (`POST /forensics`), for after-the-fact
root-cause questions. System prompt like: *"You are a forensics analyst.
You'll get a historical incident timeline + question — answer with root
cause, citing specific events."*

Run with all six sets of credentials (each is independent — set any subset
alongside `LYZR_API_KEY`; unset ones just fall back to their
rule-based/informational message instead of erroring):
```bash
LYZR_API_KEY=your_key \
LYZR_USER_ID=your_lyzr_account_email \
LYZR_AGENT_ID=your_trust_guardian_agent_id \
LYZR_NARRATOR_AGENT_ID=your_report_sentinel_agent_id \
LYZR_HUNTER_AGENT_ID=your_mesh_guardian_agent_id \
LYZR_ADVISOR_AGENT_ID=your_playbook_guardian_agent_id \
LYZR_POLICY_AGENT_ID=your_threshold_tuner_agent_id \
LYZR_FORENSICS_AGENT_ID=your_chronos_forensics_agent_id \
uvicorn main:app --reload --port 8000
```
Or set them in a local `.env` file (picked up automatically by
`load_dotenv()` — no manual `$env:`/export needed).

## Demo Topology
5 services — OrderService, PaymentService, InventoryService, BankGateway,
UserDBService — with a defined legitimate call graph. Use the dashboard
controls to simulate attacks, honeytoken probes, and normal traffic.

## Team
Malavika · Dhanush Karthikeyan
