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
from typing import Dict, List, Optional

import requests
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ml_layer import (
    BlastRadiusPredictor,
    BehavioralAnomalyModel,
    SyntheticAttackGenerator,
    QuarantineExplainer,
    LogSummarizer,
)

# ---------------------------------------------------------------------------
# LYZR AGENT CONFIG  (Ask-Cerberus SOC analyst panel — set via env vars)
# ---------------------------------------------------------------------------
LYZR_API_KEY = os.environ.get("LYZR_API_KEY", "")
LYZR_AGENT_ID = os.environ.get("LYZR_AGENT_ID", "")
LYZR_CHAT_URL = "https://agent-prod.studio.lyzr.ai/v3/inference/chat/"
_lyzr_sessions: Dict[str, str] = {}  # per-browser-tab session_id, keyed by a client token

app = FastAPI(title="Cerberus")

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
        await broadcast_state()
        return {
            "decision": "block",
            "reason": f"HONEYTOKEN TRIGGERED — {req.caller} accessed decoy service '{req.callee}'. Confidence: 100% malicious. Auto-quarantined.",
            "anomaly_score": 1.0,
            "trust": 0,
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
        {"blast_radius": radius, "ml_blast_radius": ml_radius},
    )
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
    return {"probed_honeytoken": decoy, **result}


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
        results.append({**item, **result})
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
    return {
        "generated_at": now,
        "system": "Cerberus — Zero-Trust Access Control for Decentralized APIs",
        "ml_layer_enabled": ml_layer_enabled,
        "services": build_state_payload()["services"],
        "full_event_log": list(event_log),
        "honeytoken_hits": honeytoken_hits,
        "digest": log_summarizer.summarize_with_stats(list(event_log), len(honeytoken_hits)),
    }


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

    try:
        resp = requests.post(
            LYZR_CHAT_URL,
            headers={"accept": "application/json", "Content-Type": "application/json", "x-api-key": LYZR_API_KEY},
            json={
                "user_id": "cerberus_dashboard",
                "agent_id": LYZR_AGENT_ID,
                "session_id": session_id,
                "message": message,
            },
            timeout=20,
        )
        data = resp.json()
        answer = data.get("response") or data.get("agent_response") or str(data)
        return {"answer": answer, "configured": True}
    except Exception as exc:
        return {"answer": f"Lyzr agent call failed: {exc}", "configured": True, "error": True}


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
