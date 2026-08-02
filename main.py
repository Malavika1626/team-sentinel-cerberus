"""
Cerberus — Zero-Trust Access Control with Blast Radius Prediction
--------------------------------------------------------------------
Core innovation beyond standard zero-trust proxies:
  1. Trust Decay      -> trust score drains over time like a battery,
                          forcing periodic re-verification (shrinks attacker window)
  2. Blast Radius      -> predicts which services WOULD be compromised next,
                          BEFORE the attacker actually reaches them (graph propagation)
  3. Explainable Block -> every allow/block decision returns a human-readable reason

Run:  uvicorn main:app --reload --port 8000
"""

import os
import time
import math
import random
import asyncio
import statistics
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse
from pydantic import BaseModel

from ml_layer import (
    BlastRadiusPredictor,
    BehavioralAnomalyModel,
    SyntheticAttackGenerator,
    QuarantineExplainer,
    LogSummarizer,
)

# ---------------------------------------------------------------------------
# LYZR AGENT CONFIG — two independent agents, two independent jobs:
#   1. LYZR_AGENT_ID          -> "Ask Cerberus"   interactive SOC Q&A panel
#   2. LYZR_NARRATOR_AGENT_ID -> "Cerberus Narrator" autonomous report writer
#      (writes the executive-summary paragraph of the incident PDF — no
#      chat, no back-and-forth, just: state in, prose out)
# Both are optional/env-driven; each degrades independently and doesn't
# block the other or the core rule-based engine.
# ---------------------------------------------------------------------------
load_dotenv()  # picks up a local .env file if present, no-op otherwise

LYZR_API_KEY = os.environ.get("LYZR_API_KEY", "")
LYZR_AGENT_ID = os.environ.get("LYZR_AGENT_ID", "")
LYZR_NARRATOR_AGENT_ID = os.environ.get("LYZR_NARRATOR_AGENT_ID", "")
# ---------------------------------------------------------------------------
# 4 more independent Lyzr agents, each optional / each degrades on its own:
#   3. LYZR_HUNTER_AGENT_ID    -> "Threat Hunter"        proactive scan (no question needed)
#   4. LYZR_ADVISOR_AGENT_ID   -> "Remediation Advisor"   one-shot playbook for one service
#   5. LYZR_POLICY_AGENT_ID    -> "Policy Tuning Agent"   one-shot threshold-tuning advisory
#   6. LYZR_FORENSICS_AGENT_ID -> "Forensics Q&A"         chat over the *historical* replay
#                                  timeline (distinct from Ask-Cerberus, which only sees live state)
# ---------------------------------------------------------------------------
LYZR_HUNTER_AGENT_ID = os.environ.get("LYZR_HUNTER_AGENT_ID", "")
LYZR_ADVISOR_AGENT_ID = os.environ.get("LYZR_ADVISOR_AGENT_ID", "")
LYZR_POLICY_AGENT_ID = os.environ.get("LYZR_POLICY_AGENT_ID", "")
LYZR_FORENSICS_AGENT_ID = os.environ.get("LYZR_FORENSICS_AGENT_ID", "")
# Lyzr Studio ties usage/rate-limits to a user_id tied to your account —
# use the same email you signed up with (shown in Lyzr's own example curl
# on the Deploy tab), not an arbitrary string, or calls get 403'd.
LYZR_USER_ID = os.environ.get("LYZR_USER_ID", "cerberus_dashboard")
LYZR_CHAT_URL = "https://agent-prod.studio.lyzr.ai/v3/inference/chat/"
_lyzr_sessions: Dict[str, str] = {}  # per-browser-tab session_id, keyed by a client token
_forensics_sessions: Dict[str, str] = {}  # separate session store — own agent, own continuity


def _lyzr_call(agent_id: str, message: str, session_id: Optional[str] = None) -> Optional[str]:
    """Shared low-level Lyzr Studio caller used by the 4 newer agents below.
    Blocking (sync) — callers must run it via asyncio.to_thread. Returns
    None on any missing-config/network/parsing failure so every caller can
    fall back to a rule-based message without the core engine ever depending
    on Lyzr being up."""
    if not LYZR_API_KEY or not agent_id:
        return None
    try:
        resp = requests.post(
            LYZR_CHAT_URL,
            headers={"accept": "application/json", "Content-Type": "application/json", "x-api-key": LYZR_API_KEY},
            json={
                "user_id": LYZR_USER_ID,
                "agent_id": agent_id,
                "session_id": session_id or str(uuid.uuid4()),
                "message": message,
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("response") or data.get("agent_response")
    except Exception:
        return None

app = FastAPI(title="Cerberus")


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def serve_dashboard():
    """Serves the dashboard UI at the root URL so the deployed backend link
    alone (e.g. for hackathon submission) opens the live dashboard instead
    of a bare 404 — dashboard.html sits next to main.py in the repo root.
    Accepts both GET (browsers) and HEAD (uptime monitors like UptimeRobot,
    which probe with HEAD and would otherwise get a 405)."""
    return FileResponse("dashboard.html", media_type="text/html")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# 1. SERVICE TOPOLOGY  (normal, legitimate call graph — who talks to whom)
# ---------------------------------------------------------------------------
# Each edge = (caller -> callee): weight = how "normal" this call pattern is (0-1)
NORMAL_GRAPH: Dict[str, Dict[str, float]] = {
    "OrderService":   {"PaymentService": 0.95, "InventoryService": 0.9},
    "PaymentService": {"BankGateway": 0.9},
    "InventoryService": {"UserDBService": 0.2},   # rare, low-weight legit edge
    "UserDBService":  {},
    "BankGateway":    {},
}

ALL_SERVICES = list(NORMAL_GRAPH.keys())

# ---------------------------------------------------------------------------
# 1b. HONEYTOKENS  (decoy services — NO legitimate service should ever call these)
# ---------------------------------------------------------------------------
# Any request that targets one of these is, by definition, malicious —
# a legit service was never told these exist, so touching them = 100% signal.
HONEYTOKEN_SERVICES = {"AdminBackdoor_DB", "LegacyPaymentVault", "InternalHR_Records"}

honeytoken_hits: List[dict] = []

# ---------------------------------------------------------------------------
# 1c2. MITRE ATT&CK MAPPING
#      Ties our synthetic attack patterns to real-world ATT&CK techniques so
#      the demo isn't just "block/allow" — it's grounded in recognized
#      attacker tradecraft. Best-effort educational mapping, not an official
#      MITRE-certified classification.
# ---------------------------------------------------------------------------
MITRE_ATTACK_MAP = {
    "lateral_probe": {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "credential_replay": {"id": "T1550", "name": "Use Alternate Authentication Material", "tactic": "Defense Evasion / Lateral Movement"},
    "bulk_scrape": {"id": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    "honeytoken_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "compromise": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access / Persistence"},
}


def mitre_for(pattern: str) -> Optional[dict]:
    return MITRE_ATTACK_MAP.get(pattern)


# ---------------------------------------------------------------------------
# 1c. AI / DATA-SCIENCE UPGRADE LAYER  (see ml_layer.py)
#     Additive/advisory — the core rule-based decision path is untouched;
#     these enrich it with learned predictions + explanations.
# ---------------------------------------------------------------------------
blast_radius_model = BlastRadiusPredictor(NORMAL_GRAPH)
behavioral_ml_model = BehavioralAnomalyModel()
synthetic_attack_generator = SyntheticAttackGenerator(NORMAL_GRAPH, list(HONEYTOKEN_SERVICES))
quarantine_explainer = QuarantineExplainer(behavioral_ml_model)
log_summarizer = LogSummarizer()

# "Compare Mode" — lets the demo toggle the ML behavioral layer on/off so you
# can show judges the exact same attack with and without the AI upgrade.
ml_layer_enabled = True

# ---------------------------------------------------------------------------
# 2. TRUST STATE  (the "battery" — decays continuously, recharges on verify)
# ---------------------------------------------------------------------------
@dataclass
class ServiceTrust:
    name: str
    score: float = 100.0          # 0-100, battery-style
    compromised: bool = False
    last_verified: float = field(default_factory=time.time)
    quarantined: bool = False
    quarantined_until: float = 0.0

    def decay(self, dt: float):
        # exponential decay -> trust drains faster the longer it goes unverified
        decay_rate = 0.15  # % per second
        self.score = max(0.0, self.score - decay_rate * dt)

    def recharge(self, amount: float = 25.0):
        self.score = min(100.0, self.score + amount)
        self.last_verified = time.time()


trust_state: Dict[str, ServiceTrust] = {s: ServiceTrust(s) for s in ALL_SERVICES}

event_log: deque = deque(maxlen=200)
connected_sockets: List[WebSocket] = []

# ---------------------------------------------------------------------------
# 2a2. INCIDENT REPLAY HISTORY
#      Lightweight snapshots of every service's trust/quarantine state over
#      time, so the dashboard can scrub back through an incident after the
#      fact instead of only ever showing the live moment.
# ---------------------------------------------------------------------------
STATE_HISTORY_MAXLEN = 400
state_history: deque = deque(maxlen=STATE_HISTORY_MAXLEN)


def record_history_snapshot(label: str = ""):
    """Appends a snapshot for the replay timeline. Called every decay tick
    for a continuous baseline, plus at key moments (compromise, quarantine,
    honeytoken hit, auto-heal, seed) with a label so the replay UI can mark
    notable events distinctly from the ambient continuous trace."""
    state_history.append({
        "t": round(time.time(), 2),
        "label": label,
        "services": {
            name: {"score": round(s.score, 1), "compromised": s.compromised, "quarantined": s.quarantined}
            for name, s in trust_state.items()
        },
    })


# ---------------------------------------------------------------------------
# 2b. QUARANTINE COOLDOWN (feature 4: self-healing micro-segmentation)
# ---------------------------------------------------------------------------
QUARANTINE_COOLDOWN_SECONDS = 20.0
QUARANTINE_RECOVERY_TRUST = 50.0

# ---------------------------------------------------------------------------
# 2c. BEHAVIORAL FINGERPRINT baseline (feature 3)
# ---------------------------------------------------------------------------
BASELINE_WINDOW = 30
payload_baselines: Dict[str, deque] = {s: deque(maxlen=BASELINE_WINDOW) for s in ALL_SERVICES}

# ---------------------------------------------------------------------------
# 2d. RISK-ADAPTIVE RATE LIMITING state (feature 5)
# ---------------------------------------------------------------------------
RATE_WINDOW_SECONDS = 10.0
request_timestamps: Dict[str, deque] = {s: deque() for s in ALL_SERVICES}


def log_event(kind: str, message: str, extra: Optional[dict] = None):
    entry = {
        "ts": round(time.time(), 2),
        "kind": kind,       # "allow" | "block" | "info" | "attack"
        "message": message,
        **(extra or {}),
    }
    event_log.append(entry)
    return entry


# ---------------------------------------------------------------------------
# 3. TRUST DECAY LOOP  (background task — the "battery drains" over time)
# ---------------------------------------------------------------------------
async def decay_loop():
    last = time.time()
    while True:
        await asyncio.sleep(1)
        now = time.time()
        dt = now - last
        last = now
        for svc in trust_state.values():
            if not svc.compromised:
                svc.decay(dt)
        record_history_snapshot()
        await broadcast_state()


def quarantine_service(name: str, reason: str, cooldown: float = QUARANTINE_COOLDOWN_SECONDS):
    """Isolate a service: block all its outbound traffic for `cooldown` seconds."""
    svc = trust_state.get(name)
    if not svc:
        return
    svc.quarantined = True
    svc.quarantined_until = time.time() + cooldown
    log_event(
        "attack",
        f"🔒 {name} QUARANTINED for {int(cooldown)}s — {reason}",
        {"service": name, "quarantined_until": svc.quarantined_until},
    )
    record_history_snapshot(f"{name} quarantined — {reason}")


async def quarantine_watchdog():
    """Background loop: auto-lifts quarantine after cooldown, restores cautious mid-trust."""
    while True:
        await asyncio.sleep(1)
        now = time.time()
        changed = False
        for svc in trust_state.values():
            if svc.quarantined and now >= svc.quarantined_until:
                svc.quarantined = False
                svc.compromised = False
                svc.score = QUARANTINE_RECOVERY_TRUST
                svc.last_verified = now
                log_event(
                    "info",
                    f"♻ {svc.name} auto-healed — quarantine lifted, trust restored to {QUARANTINE_RECOVERY_TRUST:.0f} (cautious mid-level)",
                    {"service": svc.name},
                )
                changed = True
        if changed:
            record_history_snapshot("auto-healed after cooldown")
            await broadcast_state()


async def broadcast_state():
    if not connected_sockets:
        return
    payload = build_state_payload()
    dead = []
    for ws in connected_sockets:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for d in dead:
        connected_sockets.remove(d)


def build_state_payload():
    now = time.time()
    services_payload = {}
    for name, s in trust_state.items():
        q = request_timestamps.get(name, deque())
        # count only requests still inside the sliding window, without mutating state
        active_count = sum(1 for ts in q if now - ts <= RATE_WINDOW_SECONDS)
        baseline = payload_baselines.get(name, deque())
        services_payload[name] = {
            "score": round(s.score, 1),
            "compromised": s.compromised,
            "quarantined": s.quarantined,
            "quarantine_remaining": round(max(0.0, s.quarantined_until - now), 1) if s.quarantined else 0,
            "rate_limit": {
                "count": active_count,
                "limit": get_rate_limit_for_trust(s.score),
                "window_seconds": RATE_WINDOW_SECONDS,
            },
            "fingerprint": {
                "sample_count": len(baseline),
                "baseline_ready": len(baseline) >= 5,
                "avg_payload": round(statistics.mean(baseline), 0) if baseline else None,
            },
        }
    return {
        "type": "state",
        "services": services_payload,
        "edges": [
            {"from": src, "to": dst, "weight": w}
            for src, targets in NORMAL_GRAPH.items()
            for dst, w in targets.items()
        ],
        "log": list(event_log)[-30:],
        "honeytokens": list(HONEYTOKEN_SERVICES),
        "honeytoken_hit_count": len(honeytoken_hits),
        "ml_layer_enabled": ml_layer_enabled,
        "lyzr_configured": bool(LYZR_API_KEY and LYZR_AGENT_ID),
        "lyzr_narrator_configured": bool(LYZR_API_KEY and LYZR_NARRATOR_AGENT_ID),
        "lyzr_hunter_configured": bool(LYZR_API_KEY and LYZR_HUNTER_AGENT_ID),
        "lyzr_advisor_configured": bool(LYZR_API_KEY and LYZR_ADVISOR_AGENT_ID),
        "lyzr_policy_configured": bool(LYZR_API_KEY and LYZR_POLICY_AGENT_ID),
        "lyzr_forensics_configured": bool(LYZR_API_KEY and LYZR_FORENSICS_AGENT_ID),
    }


@app.on_event("startup")
async def startup():
    asyncio.create_task(decay_loop())
    asyncio.create_task(quarantine_watchdog())


# ---------------------------------------------------------------------------
# 4. CONTEXTUAL ANOMALY SCORING  (time / pattern / payload heuristics)
# ---------------------------------------------------------------------------
def context_anomaly_score(caller: str, callee: str, payload_size: int, hour: int) -> float:
    """Returns 0 (totally normal) -> 1 (highly anomalous)."""
    score = 0.0
    reasons = []

    # 1. Is this even a known/legit edge?
    legit_weight = NORMAL_GRAPH.get(caller, {}).get(callee)
    if legit_weight is None:
        score += 0.6
        reasons.append(f"no known trust relationship {caller}->{callee}")
    elif legit_weight < 0.3:
        score += 0.25
        reasons.append(f"rare edge (baseline weight {legit_weight})")

    # 2. Odd hour (outside 6am-10pm "business" simulation window)
    if hour < 6 or hour > 22:
        score += 0.2
        reasons.append(f"off-hours request ({hour}:00)")

    # 3. Payload size anomaly (large scrape-like payloads)
    if payload_size > 5000:
        score += 0.25
        reasons.append(f"unusually large payload ({payload_size} bytes)")

    return min(1.0, score), reasons


# ---------------------------------------------------------------------------
# 4b. BEHAVIORAL FINGERPRINT VERIFICATION  (feature 3 — payload z-score baseline)
# ---------------------------------------------------------------------------
def behavioral_deviation_score(caller: str, payload_size: int):
    """
    Compares payload_size against the caller's rolling baseline (last 30 allowed
    calls) using a z-score. Catches stolen-but-valid-token attacks where identity
    checks pass but behavior doesn't match the service's normal fingerprint.
    Returns (extra_anomaly_score 0-1, human-readable reason or None).
    """
    baseline = payload_baselines.get(caller)
    if baseline is None or len(baseline) < 5:
        return 0.0, None  # not enough history yet to judge deviation

    mean = statistics.mean(baseline)
    stdev = statistics.pstdev(baseline) or 1.0  # avoid divide-by-zero for flat baselines
    z = (payload_size - mean) / stdev

    if abs(z) > 3:
        return 0.35, f"payload fingerprint deviation z={z:.1f} (baseline avg {mean:.0f}B) — severe"
    elif abs(z) > 2:
        return 0.2, f"payload fingerprint deviation z={z:.1f} (baseline avg {mean:.0f}B)"
    return 0.0, None


def record_baseline(caller: str, payload_size: int):
    """Only ALLOWED calls feed the baseline, so poisoning the fingerprint is harder."""
    if caller in payload_baselines:
        payload_baselines[caller].append(payload_size)


# ---------------------------------------------------------------------------
# 4c. RISK-ADAPTIVE RATE LIMITING  (feature 5 — sliding window tied to trust)
# ---------------------------------------------------------------------------
def get_rate_limit_for_trust(trust_score: float) -> int:
    if trust_score >= 80:
        return 20
    elif trust_score >= 50:
        return 10
    elif trust_score >= 20:
        return 3
    else:
        return 1


def check_rate_limit(caller: str, trust_score: float):
    """
    Sliding 10s window. Limit shrinks as trust drops, so bulk-scraping behavior
    gets throttled gradually instead of only reacting after full compromise.
    Returns (allowed: bool, current_count: int, limit: int).
    """
    now = time.time()
    q = request_timestamps.setdefault(caller, deque())
    while q and now - q[0] > RATE_WINDOW_SECONDS:
        q.popleft()

    limit = get_rate_limit_for_trust(trust_score)
    allowed = len(q) < limit
    if allowed:
        q.append(now)
    return allowed, len(q), limit


# ---------------------------------------------------------------------------
# 5. BLAST RADIUS PREDICTION  (graph propagation from a compromised node)
# ---------------------------------------------------------------------------
def predict_blast_radius(compromised: str, max_hops: int = 2) -> List[dict]:
    """
    BFS outward from the compromised service through the legitimate call graph.
    Risk decays with hop distance and edge weight -- this is what lets us
    warn 'these N services are likely next' BEFORE the attacker gets there.
    """
    visited = {compromised: 1.0}
    frontier = [(compromised, 1.0, 0)]
    results = []

    while frontier:
        node, risk, hop = frontier.pop(0)
        if hop >= max_hops:
            continue
        for neighbor, weight in NORMAL_GRAPH.get(node, {}).items():
            propagated_risk = risk * weight * (0.7 ** hop)  # decay per hop
            if neighbor not in visited or propagated_risk > visited[neighbor]:
                visited[neighbor] = propagated_risk
                frontier.append((neighbor, propagated_risk, hop + 1))
                results.append({
                    "service": neighbor,
                    "predicted_risk": round(propagated_risk * 100, 1),
                    "hops_away": hop + 1,
                    "via": node,
                })
    return sorted(results, key=lambda r: -r["predicted_risk"])


# ---------------------------------------------------------------------------
# 6. API MODELS
# ---------------------------------------------------------------------------
class ProxyRequest(BaseModel):
    caller: str
    callee: str
    payload_size: int = 200
    hour: Optional[int] = None


class AttackSimRequest(BaseModel):
    compromised_service: str


# ---------------------------------------------------------------------------
# 7. CORE ENDPOINT — every inter-service call passes through here
# ---------------------------------------------------------------------------
@app.post("/proxy/request")
async def proxy_request(req: ProxyRequest):
    """
    Every inter-service call passes through here. Checked in strict priority
    order: quarantine -> honeytoken -> context anomaly -> behavioral fingerprint
    -> rate limit -> final trust-threshold decision.
    """
    caller = trust_state.get(req.caller)

    # --- LAYER 1: QUARANTINE CHECK (feature 4 — highest priority, no ambiguity) ---
    if caller and caller.quarantined:
        remaining = max(0, round(caller.quarantined_until - time.time(), 1))
        reason = f"{req.caller} is QUARANTINED — all outbound traffic blocked ({remaining}s remaining in cooldown)"
        log_event(
            "block",
            f"{req.caller} -> {req.callee}: BLOCK (quarantined)",
            {"caller": req.caller, "callee": req.callee, "reason": reason},
        )
        await broadcast_state()
        return {"decision": "block", "reason": reason, "anomaly_score": 1.0, "trust": 0, "quarantine_remaining": remaining}

    # --- LAYER 2: HONEYTOKEN CHECK (zero ambiguity signal) ---
    if req.callee in HONEYTOKEN_SERVICES:
        hit = {
            "ts": time.time(),
            "attacker": req.caller,
            "honeytoken": req.callee,
        }
        honeytoken_hits.append(hit)
        # touching a honeytoken instantly zeroes the caller's trust and quarantines it —
        # no legit service would ever know this endpoint exists
        if caller:
            caller.score = 0
            caller.compromised = True
            quarantine_service(req.caller, f"honeytoken '{req.callee}' triggered")
        log_event(
            "attack",
            f"🍯 HONEYTOKEN TRIGGERED: {req.caller} touched decoy '{req.callee}' — 100% confirmed malicious",
            {"caller": req.caller, "callee": req.callee, "reason": "honeytoken access — no legitimate service is aware this endpoint exists"},
        )
        record_history_snapshot(f"{req.caller} honeytoken hit")
        await broadcast_state()
        return {
            "decision": "block",
            "reason": f"HONEYTOKEN TRIGGERED — {req.caller} accessed decoy service '{req.callee}'. Confidence: 100% malicious. Auto-quarantined.",
            "anomaly_score": 1.0,
            "trust": 0,
            "mitre": mitre_for("honeytoken_scan"),
        }

    callee = trust_state.get(req.callee)
    if not caller or not callee:
        return {"decision": "block", "reason": "unknown service"}

    # --- LAYER 3: CONTEXTUAL ANOMALY SCORING ---
    hour = req.hour if req.hour is not None else time.localtime().tm_hour
    anomaly, reasons = context_anomaly_score(req.caller, req.callee, req.payload_size, hour)
    context_anomaly_base = anomaly  # preserved for the explainability breakdown (layer 4d)

    # --- LAYER 4: BEHAVIORAL FINGERPRINT VERIFICATION ---
    behavior_extra, behavior_reason = behavioral_deviation_score(req.caller, req.payload_size)
    if behavior_reason:
        anomaly = min(1.0, anomaly + behavior_extra)
        reasons.append(behavior_reason)

    # --- LAYER 4b: ML BEHAVIORAL ANOMALY MODEL (multi-feature IsolationForest) ---
    # Additive to the single-feature z-score above: catches deviations in
    # calling cadence / time-of-day, not just payload size.
    # Skipped entirely when Compare Mode has the AI layer switched off, so the
    # same attack can be replayed rule-based-only vs AI-enabled for a demo.
    ml_extra, ml_reason = (0.0, None)
    if ml_layer_enabled:
        ml_extra, ml_reason = behavioral_ml_model.score(req.caller, req.payload_size, hour, time.time())
    if ml_reason:
        anomaly = min(1.0, anomaly + ml_extra)
        reasons.append(ml_reason)

    # --- LAYER 5: RISK-ADAPTIVE RATE LIMITING ---
    rl_allowed, rl_count, rl_limit = check_rate_limit(req.caller, caller.score)
    if not rl_allowed:
        reason = f"Blocked: rate limit exceeded ({rl_count}/{rl_limit} req in {int(RATE_WINDOW_SECONDS)}s window at trust {caller.score:.0f})"
        if caller.score < 20:
            quarantine_service(req.caller, "sustained rate-limit violations at critically low trust")
        log_event(
            "block",
            f"{req.caller} -> {req.callee}: BLOCK (rate limited)",
            {"caller": req.caller, "callee": req.callee, "reason": reason},
        )
        await broadcast_state()
        return {"decision": "block", "reason": reason, "anomaly_score": anomaly, "trust": round(caller.score, 1),
                "rate_limit": {"count": rl_count, "limit": rl_limit}}

    # --- LAYER 6: FINAL TRUST-THRESHOLD DECISION ---
    effective_trust = caller.score * (1 - anomaly)

    if caller.compromised:
        decision = "block"
        reason = f"{req.caller} is flagged compromised — all outbound traffic blocked"
    elif effective_trust < 40:
        decision = "block"
        reason = "Blocked: trust score too low (" + f"{effective_trust:.1f}" + ") — " + "; ".join(reasons or ["battery depleted, re-auth required"])
    else:
        decision = "allow"
        caller.recharge(10)  # successful legit call recharges trust slightly
        record_baseline(req.caller, req.payload_size)  # only allowed calls feed the fingerprint
        behavioral_ml_model.observe(req.caller, req.payload_size, hour, time.time())  # feed ML profile
        reason = f"Allowed: trust {effective_trust:.1f}/100, anomaly {anomaly:.2f}"

    # Self-healing micro-segmentation: trust collapsing below critical threshold => quarantine
    if decision == "block" and caller.score <= 20 and not caller.quarantined:
        quarantine_service(req.caller, f"trust collapsed to {caller.score:.0f} (below critical threshold)")

    # --- LAYER 4d: EXPLAINABLE AI — feature-attribution breakdown for this decision ---
    explanation = None
    if decision == "block":
        components = {
            "unknown_or_rare_edge_and_context": max(0.0, context_anomaly_base - behavior_extra - ml_extra),
            "behavioral_zscore_deviation": behavior_extra,
            "ml_behavioral_model": ml_extra,
            "trust_deficit": max(0.0, (40 - effective_trust) / 40),
        }
        explanation = quarantine_explainer.explain(req.caller, components)
        blast_radius_model.record_incident(req.caller, retrain=False)  # feeds the learned predictor

    log_event(
        decision,
        f"{req.caller} -> {req.callee}: {decision.upper()}",
        {"caller": req.caller, "callee": req.callee, "reason": reason, "anomaly": round(anomaly, 2),
         "explanation": explanation},
    )
    await broadcast_state()
    return {
        "decision": decision,
        "reason": reason,
        "anomaly_score": anomaly,
        "trust": round(effective_trust, 1),
        "rate_limit": {"count": rl_count, "limit": rl_limit},
        "behavioral_flag": behavior_reason,
        "ml_behavioral_flag": ml_reason,
        "explanation": explanation,
    }


@app.post("/verify/{service}")
async def verify_service(service: str):
    """Manual re-authentication -> recharges the trust battery."""
    svc = trust_state.get(service)
    if not svc:
        return {"error": "unknown service"}
    svc.recharge(100)
    svc.compromised = False
    svc.quarantined = False
    svc.quarantined_until = 0.0
    log_event("info", f"{service} re-verified — trust recharged to 100")
    await broadcast_state()
    return {"service": service, "score": svc.score}


@app.post("/simulate/attack")
async def simulate_attack(req: AttackSimRequest):
    """
    Marks a service as compromised, then predicts blast radius BEFORE
    the attacker actually issues any lateral-movement requests.
    """
    svc = trust_state.get(req.compromised_service)
    if not svc:
        return {"error": "unknown service"}

    svc.compromised = True
    svc.score = min(svc.score, 20)  # compromise tanks trust immediately
    quarantine_service(req.compromised_service, "attack simulation confirmed compromise")

    radius = predict_blast_radius(req.compromised_service)             # rule-based (formula)
    ml_radius = blast_radius_model.predict(req.compromised_service)    # learned (RandomForest)
    blast_radius_model.record_incident(req.compromised_service)        # feeds + retrains the model

    log_event(
        "attack",
        f"⚠ {req.compromised_service} COMPROMISED — predicted blast radius: "
        + ", ".join(r["service"] for r in radius) if radius else f"⚠ {req.compromised_service} COMPROMISED — no reachable neighbors",
        {"blast_radius": radius, "ml_blast_radius": ml_radius, "mitre": mitre_for("compromise")},
    )
    record_history_snapshot(f"{req.compromised_service} compromised")
    await broadcast_state()

    # Now actually attempt lateral movement calls to prove the block works
    lateral_results = []
    for r in radius:
        result = await proxy_request(ProxyRequest(
            caller=req.compromised_service,
            callee=r["service"],
            payload_size=8000,   # scrape-like payload
            hour=3,              # off hours
        ))
        lateral_results.append({"target": r["service"], **result})

    return {
        "compromised": req.compromised_service,
        "blast_radius": radius,
        "ml_blast_radius": ml_radius,
        "lateral_movement_attempts": lateral_results,
        "mitre": mitre_for("compromise"),
    }


@app.post("/simulate/honeytoken_probe")
async def simulate_honeytoken_probe(req: AttackSimRequest):
    """
    Demo endpoint: an already-compromised service tries to scan/discover
    internal endpoints and stumbles onto a honeytoken. Shows the trap
    working in isolation (separate from the full blast-radius attack demo).
    """
    decoy = random.choice(list(HONEYTOKEN_SERVICES))
    result = await proxy_request(ProxyRequest(
        caller=req.compromised_service,
        callee=decoy,
        payload_size=1500,
        hour=3,
    ))
    return {"probed_honeytoken": decoy, "mitre": mitre_for("honeytoken_scan"), **result}


@app.post("/simulate/synthetic_attack")
async def simulate_synthetic_attack(size: int = 6, seed_service: Optional[str] = None):
    """
    Fires a generated burst of adversarial traffic (varied patterns —
    lateral probes, credential replay, bulk scrapes, honeytoken scans)
    through the real /proxy/request pipeline, so you can watch Cerberus's
    rule-based + ML layers react live. Useful for demos ("AI attacks,
    AI defends") and stress-testing without hand-scripting each request.
    """
    burst = synthetic_attack_generator.generate_burst(size=size, seed_service=seed_service)
    results = []
    for item in burst:
        result = await proxy_request(ProxyRequest(
            caller=item["caller"],
            callee=item["callee"],
            payload_size=item["payload_size"],
            hour=item["hour"],
        ))
        results.append({**item, "mitre": mitre_for(item["pattern"]), **result})
    blocked = sum(1 for r in results if r["decision"] == "block")
    return {
        "burst_size": size,
        "blocked": blocked,
        "allowed": size - blocked,
        "requests": results,
    }


@app.get("/summary")
async def summary():
    """
    Lightweight extractive summary of recent activity — no LLM/API key
    needed, always available. Complements (doesn't replace) the Lyzr-powered
    'Ask Cerberus' chat panel, which needs LYZR_API_KEY configured.
    """
    return log_summarizer.summarize_with_stats(list(event_log), len(honeytoken_hits))


@app.get("/explain/{service}")
async def explain_service(service: str):
    """Standalone explainability query for a service's current risk profile
    (independent of a specific proxy call) — used by the dashboard's
    'why?' button next to any service."""
    svc = trust_state.get(service)
    if not svc:
        return {"error": "unknown service"}
    components = {
        "trust_deficit": max(0.0, (40 - svc.score) / 40),
        "quarantined": 1.0 if svc.quarantined else 0.0,
        "compromised": 1.0 if svc.compromised else 0.0,
    }
    return quarantine_explainer.explain(service, components)


@app.post("/toggle/ml_layer")
async def toggle_ml_layer(enabled: bool = True):
    """Compare Mode switch — turn the ML behavioral layer on/off so the same
    attack can be demoed rule-based-only vs AI-enabled."""
    global ml_layer_enabled
    ml_layer_enabled = enabled
    log_event("info", f"⚙ Compare Mode — AI behavioral layer {'ENABLED' if enabled else 'DISABLED'}")
    await broadcast_state()
    return {"ml_layer_enabled": ml_layer_enabled}


@app.get("/export/report")
async def export_report():
    """Downloadable incident report — full state snapshot, event log, and
    honeytoken hits, for post-demo review or attaching to a submission."""
    now = time.time()
    digest = log_summarizer.summarize_with_stats(list(event_log), len(honeytoken_hits))
    narrative = await asyncio.to_thread(_call_lyzr_narrator, build_soc_context())
    return {
        "generated_at": now,
        "system": "Cerberus — Zero-Trust Access Control for Decentralized APIs",
        "ml_layer_enabled": ml_layer_enabled,
        "services": build_state_payload()["services"],
        "full_event_log": list(event_log),
        "honeytoken_hits": honeytoken_hits,
        "digest": digest,
        # AI-written executive summary (Cerberus Narrator, 2nd Lyzr agent) —
        # falls back to the rule-based digest summary when not configured.
        "executive_summary": narrative or digest.get("summary", "No activity recorded."),
        "executive_summary_ai_generated": bool(narrative),
    }


def _call_lyzr_narrator(context: str) -> Optional[str]:
    """
    'Cerberus Narrator' — second, independent Lyzr agent. Given the raw
    incident state, writes a 3-5 sentence executive-summary paragraph for
    the PDF report (the kind a SOC lead would paste into a post-mortem).
    Distinct job from 'Ask Cerberus': no chat, no session, no follow-up
    question — one-shot state-in / prose-out. Returns None (caller falls
    back to the rule-based digest) if not configured or on any failure —
    the report must always generate, LLM or not.
    """
    if not LYZR_API_KEY or not LYZR_NARRATOR_AGENT_ID:
        return None
    prompt = (
        "You are writing the executive summary for a zero-trust security "
        "incident report. Given the state snapshot below, write 3-5 plain "
        "prose sentences (no headers, no bullet points) a SOC lead could "
        "paste directly into a post-mortem: what happened, which services "
        "were affected, and the overall severity.\n\n" + context
    )
    try:
        resp = requests.post(
            LYZR_CHAT_URL,
            headers={"accept": "application/json", "Content-Type": "application/json", "x-api-key": LYZR_API_KEY},
            json={
                "user_id": LYZR_USER_ID,
                "agent_id": LYZR_NARRATOR_AGENT_ID,
                "session_id": str(uuid.uuid4()),  # one-shot — no continuity needed
                "message": prompt,
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("response") or data.get("agent_response")
    except Exception:
        return None  # report generation must never fail because the LLM did


def _build_pdf_report(narrative: Optional[str] = None) -> bytes:
    """Renders the same data as /export/report as a one-page-friendly PDF —
    handier than raw JSON to hand to judges or attach to a submission.
    `narrative`, if given, is the Cerberus Narrator's AI-written executive
    summary; otherwise the rule-based digest summary is used instead."""
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CerberusTitle", parent=styles["Title"], textColor=colors.HexColor("#4b2aad"))
    header_style = ParagraphStyle("CerberusHeader", parent=styles["Heading2"], textColor=colors.HexColor("#241640"),
                                   spaceBefore=12)

    def styled_table(data):
        t = Table(data, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#241640")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2effa")]),
        ]))
        return t

    story = [
        Paragraph("Cerberus — Incident Report", title_style),
        Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]),
        Spacer(1, 14),
        Paragraph("Service Trust Snapshot", header_style),
    ]

    payload = build_state_payload()
    table_data = [["Service", "Trust", "Compromised", "Quarantined"]]
    for name, s in payload["services"].items():
        table_data.append([name, f"{s['score']}", "yes" if s["compromised"] else "no", "yes" if s["quarantined"] else "no"])
    story.append(styled_table(table_data))

    digest = log_summarizer.summarize_with_stats(list(event_log), len(honeytoken_hits))
    summary_header = "Executive Summary (AI-generated — Cerberus Narrator / Lyzr)" if narrative else "Activity Digest"
    story.append(Paragraph(summary_header, header_style))
    story.append(Paragraph(narrative or digest.get("summary", "No activity recorded."), styles["Normal"]))
    counts = digest.get("event_counts", {})
    if counts:
        story.append(Spacer(1, 8))
        story.append(styled_table([["Event Type", "Count"]] + [[k, str(v)] for k, v in counts.items()]))

    story.append(Paragraph(f"Honeytoken Hits ({len(honeytoken_hits)})", header_style))
    if honeytoken_hits:
        hdata = [["Time", "Attacker", "Honeytoken"]]
        for h in honeytoken_hits[-20:]:
            hdata.append([datetime.fromtimestamp(h["ts"]).strftime("%H:%M:%S"), h["attacker"], h["honeytoken"]])
        story.append(styled_table(hdata))
    else:
        story.append(Paragraph("No honeytoken hits recorded.", styles["Normal"]))

    story.append(Paragraph("Recent Event Log (last 30)", header_style))
    log_style = ParagraphStyle("LogLine", parent=styles["Normal"], fontSize=8, leading=11)
    for e in list(event_log)[-30:]:
        ts = datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
        safe_message = e["message"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        story.append(Paragraph(f"[{ts}] {safe_message}", log_style))

    doc.build(story)
    return buf.getvalue()


@app.get("/export/report_pdf")
async def export_report_pdf():
    """Same incident report as /export/report, rendered as a downloadable
    PDF — a more presentable artifact for judges or a submission packet.
    Executive summary is written live by the Cerberus Narrator (2nd Lyzr
    agent) when configured, else falls back to the rule-based digest."""
    narrative = await asyncio.to_thread(_call_lyzr_narrator, build_soc_context())
    pdf_bytes = _build_pdf_report(narrative)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cerberus_incident_report_{int(time.time())}.pdf"},
    )


@app.post("/seed_demo")
async def seed_demo(count: int = 24):
    """
    Fires a batch of benign, realistic traffic across the real legitimate
    call graph. Without this, the dashboard starts at a cold, empty state —
    no trust history, no behavioral-fingerprint baselines — which looks flat
    for the first 10-15 seconds in front of judges. Call this once right
    after opening the dashboard, before running any attack demos.
    """
    fired = 0
    for _ in range(count):
        caller = random.choice(list(NORMAL_GRAPH.keys()))
        callees = NORMAL_GRAPH.get(caller, {})
        if not callees:
            continue
        callee = random.choices(list(callees.keys()), weights=list(callees.values()), k=1)[0]
        payload = max(50, int(random.gauss(320, 70)))   # realistic small payload, occasional wobble
        hour = random.choice([9, 10, 11, 13, 14, 15, 16])  # business hours
        await proxy_request(ProxyRequest(caller=caller, callee=callee, payload_size=payload, hour=hour))
        fired += 1
    record_history_snapshot("seed demo traffic fired")
    log_event("info", f"🌱 Seed demo — fired {fired} benign requests to warm up trust/baselines")
    await broadcast_state()
    return {"seeded": True, "requests_fired": fired}


@app.get("/history")
async def get_history(limit: int = 200):
    """Incident Replay timeline — a series of past trust/quarantine snapshots
    the dashboard can scrub back through after an attack, instead of only
    ever showing the live moment."""
    data = list(state_history)[-limit:]
    return {"history": data, "count": len(data)}


@app.post("/reset")
async def reset():
    for s in trust_state.values():
        s.score = 100.0
        s.compromised = False
        s.quarantined = False
        s.quarantined_until = 0.0
    for baseline in payload_baselines.values():
        baseline.clear()
    for q in request_timestamps.values():
        q.clear()
    event_log.clear()
    honeytoken_hits.clear()
    state_history.clear()
    behavioral_ml_model.history.clear()
    behavioral_ml_model.models.clear()
    behavioral_ml_model.last_call_ts.clear()
    blast_radius_model.compromise_history.clear()
    global ml_layer_enabled
    ml_layer_enabled = True
    log_event("info", "System reset — all services re-verified (ML profiles cleared)")
    await broadcast_state()
    return {"status": "reset"}


@app.get("/state")
async def get_state():
    return build_state_payload()


# ---------------------------------------------------------------------------
# 8. ASK-CERBERUS  (Lyzr agent layer — SOC-analyst explainer over live state)
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    question: str
    client_id: Optional[str] = None  # browser tab id, keeps chat session continuity


def build_soc_context() -> str:
    """Summarizes current Cerberus state into plain text for the LLM to reason over."""
    lines = ["CERBERUS LIVE STATE SNAPSHOT", "=" * 30]
    for name, s in trust_state.items():
        status = "QUARANTINED" if s.quarantined else ("COMPROMISED" if s.compromised else "OK")
        lines.append(f"- {name}: trust={s.score:.1f}/100, status={status}")
    lines.append("\nRECENT EVENTS (latest last):")
    for e in list(event_log)[-15:]:
        lines.append(f"[{e['kind'].upper()}] {e['message']}")
    if honeytoken_hits:
        lines.append(f"\nHoneytoken hits so far: {len(honeytoken_hits)}")
    return "\n".join(lines)


@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    """
    'Ask Cerberus' — lets a SOC analyst ask natural-language questions about
    what's happening right now. Cerberus's own decision engine stays pure
    rule-based math (see /proxy/request); this is a read-only explainer layer
    on top, powered by a Lyzr agent, with the live event log/trust state as context.
    """
    if not LYZR_API_KEY or not LYZR_AGENT_ID:
        return {
            "answer": (
                "Ask-Cerberus isn't configured yet — set LYZR_API_KEY and "
                "LYZR_AGENT_ID environment variables (create the agent in "
                "Lyzr Studio first, with a system prompt like: 'You are a SOC "
                "analyst assistant. You'll be given a live zero-trust mesh "
                "snapshot; answer questions about what happened and why, "
                "citing specific services and trust scores.')."
            ),
            "configured": False,
        }

    client_id = req.client_id or "default"
    session_id = _lyzr_sessions.setdefault(client_id, str(uuid.uuid4()))

    context = build_soc_context()
    message = f"{context}\n\nANALYST QUESTION: {req.question}"

    def _call_lyzr():
        resp = requests.post(
            LYZR_CHAT_URL,
            headers={"accept": "application/json", "Content-Type": "application/json", "x-api-key": LYZR_API_KEY},
            json={
                "user_id": LYZR_USER_ID,
                "agent_id": LYZR_AGENT_ID,
                "session_id": session_id,
                "message": message,
            },
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json()

    try:
        # requests is blocking (sync) — run it in a worker thread so it doesn't
        # freeze the asyncio event loop (WS broadcasts, decay loop, other
        # requests) for every connected client while we wait on Lyzr.
        data = await asyncio.to_thread(_call_lyzr)
        answer = data.get("response") or data.get("agent_response") or str(data)
        return {"answer": answer, "configured": True}
    except requests.exceptions.Timeout:
        return {
            "answer": "Ask-Cerberus timed out waiting on the Lyzr agent. Try again in a moment.",
            "configured": True,
            "error": True,
        }
    except requests.exceptions.RequestException as exc:
        return {
            "answer": f"Couldn't reach the Lyzr agent: {exc}",
            "configured": True,
            "error": True,
        }
    except Exception as exc:
        return {"answer": f"Ask-Cerberus hit an unexpected error: {exc}", "configured": True, "error": True}


# ---------------------------------------------------------------------------
# 9. THREAT HUNTER  (Lyzr agent #3) — proactive scan, no question needed.
#    Unlike Ask-Cerberus (only answers when asked), this one looks at the
#    live snapshot on demand and flags what it would raise to a SOC analyst.
# ---------------------------------------------------------------------------
def build_hunt_context() -> str:
    lines = ["CERBERUS THREAT-HUNT SNAPSHOT", "=" * 30, "Services:"]
    for name, s in trust_state.items():
        status = "QUARANTINED" if s.quarantined else ("COMPROMISED" if s.compromised else "OK")
        lines.append(f"- {name}: trust={s.score:.1f}/100, status={status}")
    flagged = [e for e in list(event_log)[-40:] if e["kind"] in ("attack", "block")]
    lines.append(f"\nRecent suspicious/blocked events ({len(flagged)} in last 40):")
    for e in flagged[-15:]:
        lines.append(f"[{e['kind'].upper()}] {e['message']}")
    lines.append(f"\nHoneytoken hits so far: {len(honeytoken_hits)}")
    return "\n".join(lines)


def _rule_based_hunt_fallback() -> str:
    low_trust = [n for n, s in trust_state.items() if s.score < 40 and not s.quarantined]
    quarantined = [n for n, s in trust_state.items() if s.quarantined]
    bits = []
    if quarantined:
        bits.append(f"{len(quarantined)} service(s) currently quarantined: {', '.join(quarantined)}.")
    if low_trust:
        bits.append(f"{len(low_trust)} service(s) trending low on trust: {', '.join(low_trust)}.")
    if honeytoken_hits:
        bits.append(f"{len(honeytoken_hits)} honeytoken hit(s) recorded — confirmed malicious activity.")
    return " ".join(bits) if bits else "No anomalies standing out right now — system looks nominal."


@app.get("/threat_hunt")
async def threat_hunt():
    """
    Threat Hunter — proactive read of the live state. Call any time (dashboard
    button or poll) instead of asking a specific question. Read-only, same
    graceful-degradation pattern as the other Lyzr agents.
    """
    context = build_hunt_context()
    if not LYZR_API_KEY or not LYZR_HUNTER_AGENT_ID:
        return {"finding": _rule_based_hunt_fallback(), "configured": False}
    prompt = (
        "You are a proactive threat hunter for a zero-trust service mesh. "
        "Given the live snapshot below, without being asked a specific "
        "question, flag anything a SOC analyst should look at right now — "
        "unusual trust drops, repeated blocks, honeytoken activity, or "
        "services trending toward compromise. If nothing stands out, say so "
        "briefly. Keep it to 2-4 sentences.\n\n" + context
    )
    answer = await asyncio.to_thread(_lyzr_call, LYZR_HUNTER_AGENT_ID, prompt)
    if answer is None:
        return {"finding": _rule_based_hunt_fallback(), "configured": True, "error": True}
    return {"finding": answer, "configured": True}


# ---------------------------------------------------------------------------
# 10. REMEDIATION ADVISOR  (Lyzr agent #4) — one-shot, state-in/prose-out,
#     same shape as Cerberus Narrator but a different job: a short actionable
#     playbook for one specific service's current incident.
# ---------------------------------------------------------------------------
def build_advisor_context(service: str) -> Optional[str]:
    svc = trust_state.get(service)
    if not svc:
        return None
    lines = [f"CERBERUS REMEDIATION REQUEST — {service}", "=" * 30]
    lines.append(f"Trust score: {svc.score:.1f}/100")
    lines.append(f"Status: {'QUARANTINED' if svc.quarantined else ('COMPROMISED' if svc.compromised else 'OK')}")
    svc_events = [e for e in list(event_log) if e.get("service") == service or service in e["message"]][-15:]
    lines.append("\nRecent related events:")
    for e in svc_events:
        lines.append(f"[{e['kind'].upper()}] {e['message']}")
    explanation = quarantine_explainer.explain(service, {
        "trust_deficit": max(0.0, (40 - svc.score) / 40),
        "quarantined": 1.0 if svc.quarantined else 0.0,
        "compromised": 1.0 if svc.compromised else 0.0,
    })
    lines.append(f"\nExplainability breakdown: {explanation}")
    return "\n".join(lines)


def _rule_based_advisor_fallback(service: str) -> str:
    svc = trust_state.get(service)
    if not svc:
        return "Unknown service."
    if svc.quarantined:
        return (f"{service} is quarantined. Standard playbook: rotate its credentials/tokens, "
                f"audit recent outbound calls for lateral movement, patch the entry vector, "
                f"and keep it quarantined until root cause is confirmed before manual re-verify.")
    if svc.score < 50:
        return f"{service}'s trust is low ({svc.score:.0f}/100). Re-verify identity and watch closely; no quarantine needed yet."
    return f"{service} looks healthy (trust {svc.score:.0f}/100). No remediation needed."


@app.post("/advise/{service}")
async def advise(service: str):
    """
    Remediation Advisor — given one service's current incident context,
    writes a short remediation playbook a SOC analyst could action right
    now. Core engine untouched — this is advisory text only.
    """
    context = build_advisor_context(service)
    if context is None:
        return {"error": "unknown service"}
    if not LYZR_API_KEY or not LYZR_ADVISOR_AGENT_ID:
        return {"advice": _rule_based_advisor_fallback(service), "configured": False}
    prompt = (
        "You are a SOC remediation advisor for a zero-trust service mesh. "
        "Given the incident context below for one service, write a short, "
        "actionable remediation playbook (3-5 concrete steps) a SOC analyst "
        "could execute right now. Be specific, no generic security advice.\n\n" + context
    )
    answer = await asyncio.to_thread(_lyzr_call, LYZR_ADVISOR_AGENT_ID, prompt)
    if answer is None:
        return {"advice": _rule_based_advisor_fallback(service), "configured": True, "error": True}
    return {"advice": answer, "configured": True}


# ---------------------------------------------------------------------------
# 11. POLICY TUNING AGENT  (Lyzr agent #5) — one-shot advisory layer over the
#     rule-based thresholds. Never changes config itself — the core decision
#     path stays pure rule-based math — it only reads current constants +
#     recent traffic and suggests tuning, same additive spirit as ml_layer.py.
# ---------------------------------------------------------------------------
def build_policy_context() -> str:
    lines = ["CERBERUS POLICY REVIEW SNAPSHOT", "=" * 30]
    lines.append("Trust decay rate: 0.15 pts/sec")
    lines.append(f"Quarantine cooldown: {QUARANTINE_COOLDOWN_SECONDS}s, recovery trust: {QUARANTINE_RECOVERY_TRUST}")
    lines.append(f"Rate-limit window: {RATE_WINDOW_SECONDS}s")
    lines.append(f"Behavioral baseline window: {BASELINE_WINDOW} samples")
    lines.append(f"Honeytoken hits total: {len(honeytoken_hits)}")
    counts: Dict[str, int] = {}
    for e in event_log:
        counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    lines.append(f"\nEvent counts in current log window: {counts}")
    quarantine_count = sum(1 for s in trust_state.values() if s.quarantined)
    lines.append(f"Currently quarantined services: {quarantine_count}/{len(trust_state)}")
    return "\n".join(lines)


def _rule_based_policy_fallback() -> str:
    return ("Rule-based check: thresholds look within normal demo ranges. Configure "
            "LYZR_POLICY_AGENT_ID for AI-driven tuning suggestions based on live traffic.")


@app.get("/policy_review")
async def policy_review():
    """
    Policy Tuning Agent — advisory layer over the rule-based thresholds
    (decay rate, rate-limit window, quarantine cooldown). Read-only
    suggestion text; nothing here mutates config automatically.
    """
    context = build_policy_context()
    if not LYZR_API_KEY or not LYZR_POLICY_AGENT_ID:
        return {"suggestion": _rule_based_policy_fallback(), "configured": False}
    prompt = (
        "You are a security policy tuning advisor for a zero-trust service "
        "mesh. Given the current threshold config and recent traffic stats "
        "below, suggest whether any thresholds (trust decay rate, rate "
        "limit window, quarantine cooldown) should be tuned, and why. Be "
        "concise, 2-4 sentences, concrete numbers not vague advice.\n\n" + context
    )
    answer = await asyncio.to_thread(_lyzr_call, LYZR_POLICY_AGENT_ID, prompt)
    if answer is None:
        return {"suggestion": _rule_based_policy_fallback(), "configured": True, "error": True}
    return {"suggestion": answer, "configured": True}


# ---------------------------------------------------------------------------
# 12. FORENSICS Q&A  (Lyzr agent #6) — chat, own session store, but sees the
#     *historical* incident-replay timeline instead of only the live state —
#     for after-the-fact root-cause questions ("what actually triggered the
#     OrderService quarantine earlier?"). Distinct job from Ask-Cerberus.
# ---------------------------------------------------------------------------
class ForensicsRequest(BaseModel):
    question: str
    client_id: Optional[str] = None


def build_forensics_context() -> str:
    lines = ["CERBERUS INCIDENT REPLAY TIMELINE", "=" * 30]
    labeled = [snap for snap in list(state_history)[-200:] if snap["label"]]
    for snap in labeled[-30:]:
        lines.append(f"t={snap['t']}: {snap['label']}")
    lines.append("\nFull event log (most recent 60):")
    for e in list(event_log)[-60:]:
        lines.append(f"[{e['kind'].upper()}] {e['message']}")
    return "\n".join(lines)


@app.post("/forensics")
async def forensics(req: ForensicsRequest):
    """
    Forensics Q&A — root-cause analysis over the historical replay timeline
    and full event log, not just the current moment. Own session store, own
    agent id — degrades independently of every other agent.
    """
    if not LYZR_API_KEY or not LYZR_FORENSICS_AGENT_ID:
        return {
            "answer": (
                "Forensics Q&A isn't configured yet — set LYZR_FORENSICS_AGENT_ID "
                "(and LYZR_API_KEY) to enable historical root-cause analysis over "
                "the incident replay timeline."
            ),
            "configured": False,
        }
    client_id = req.client_id or "default"
    session_id = _forensics_sessions.setdefault(client_id, str(uuid.uuid4()))
    context = build_forensics_context()
    message = f"{context}\n\nFORENSICS QUESTION: {req.question}"
    answer = await asyncio.to_thread(_lyzr_call, LYZR_FORENSICS_AGENT_ID, message, session_id)
    if answer is None:
        return {"answer": "Couldn't reach the Forensics agent. Try again in a moment.", "configured": True, "error": True}
    return {"answer": answer, "configured": True}


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_sockets.append(websocket)
    await websocket.send_json(build_state_payload())
    try:
        while True:
            await websocket.receive_text()  # keep-alive; client doesn't need to send real data
    except WebSocketDisconnect:
        if websocket in connected_sockets:
            connected_sockets.remove(websocket)
