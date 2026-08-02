"""
ml_layer.py — Cerberus AI / Data-Science Upgrade Layer
--------------------------------------------------------------------------
Adds 5 ML-driven features on top of the existing rule-based Cerberus core,
without touching the core decision path in main.py (it stays pure,
auditable rule-based math — these are additive/advisory layers):

  1. BlastRadiusPredictor   — learned regressor replacing the hand-tuned
                               0.7**hop decay formula for "who's next".
  2. BehavioralAnomalyModel — per-service IsolationForest replacing the
                               single-feature z-score fingerprint check.
  3. SyntheticAttackGenerator — generates varied adversarial traffic
                               patterns for stress-testing / demos.
  4. QuarantineExplainer    — SHAP-based (falls back to manual) feature
                               attribution for every block/quarantine call.
  5. LogSummarizer          — lightweight extractive NLP summarizer for
                               the event log; works with zero API keys,
                               separate from the Lyzr "Ask Cerberus" chat.

All models are intentionally small and CPU-only (no GPU/torch dependency)
so this runs anywhere `pip install -r requirements.txt` runs.
"""

import random
import re
import statistics
from collections import Counter, deque
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import RandomForestRegressor, IsolationForest

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


# ===========================================================================
# 1. LEARNED BLAST-RADIUS RISK PREDICTOR
# ===========================================================================
class BlastRadiusPredictor:
    """
    Predicts propagation risk to each reachable service after a compromise,
    using a trained RandomForestRegressor instead of a fixed formula.

    Features per (candidate) node during BFS expansion:
        hop_distance         - hops from the compromised node
        edge_weight          - legitimacy weight of the incoming edge
        path_weight_product  - product of edge weights along the path
        in_degree            - how many services normally call this node
        out_degree           - how many services this node normally calls
        historical_incidents - times this service was compromised before

    Bootstrapped via Monte-Carlo simulated propagation episodes over the
    known topology (standard technique when no real incident history exists
    yet) — as real incidents happen, `record_incident` feeds back into
    retraining so the model sharpens over time.
    """

    def __init__(self, graph: Dict[str, Dict[str, float]]):
        self.graph = graph
        self.reverse_graph = self._build_reverse(graph)
        self.compromise_history: Counter = Counter()
        self.model = RandomForestRegressor(n_estimators=120, max_depth=5, random_state=42)
        self._fitted = False
        self._train_on_synthetic_episodes()

    def _build_reverse(self, graph):
        rev = {n: 0 for n in graph}
        for src, edges in graph.items():
            for dst in edges:
                rev[dst] = rev.get(dst, 0) + 1
        return rev

    def _node_features(self, node: str, hop: int, edge_weight: float, path_weight: float) -> List[float]:
        return [
            hop,
            edge_weight,
            path_weight,
            self.reverse_graph.get(node, 0),
            len(self.graph.get(node, {})),
            self.compromise_history.get(node, 0),
        ]

    def _simulate_episode(self, start: str) -> List[Tuple[List[float], float]]:
        """One Monte-Carlo propagation episode: randomly decide, at each hop,
        whether the compromise actually spreads (weighted by edge trust),
        producing (features, did_it_spread) training pairs."""
        samples = []
        frontier = [(start, 0, 1.0, 1.0)]
        seen = {start}
        while frontier:
            node, hop, edge_w, path_w = frontier.pop(0)
            if hop >= 3:
                continue
            for neighbor, w in self.graph.get(node, {}).items():
                spread_prob = w * (0.75 ** hop) * random.uniform(0.8, 1.2)
                spread_prob = min(1.0, max(0.0, spread_prob))
                spread = 1.0 if random.random() < spread_prob else 0.0
                feats = self._node_features(neighbor, hop + 1, w, path_w * w)
                samples.append((feats, spread))
                if neighbor not in seen and spread:
                    seen.add(neighbor)
                    frontier.append((neighbor, hop + 1, w, path_w * w))
        return samples

    def _train_on_synthetic_episodes(self, n_episodes: int = 500):
        X, y = [], []
        nodes = list(self.graph.keys())
        for _ in range(n_episodes):
            start = random.choice(nodes)
            for feats, label in self._simulate_episode(start):
                X.append(feats)
                y.append(label)
        if len(X) < 10:
            self._fitted = False
            return
        self.model.fit(np.array(X), np.array(y))
        self._fitted = True

    def record_incident(self, service: str, retrain: bool = True):
        """Feed a real (or simulated-demo) incident back into the model."""
        self.compromise_history[service] += 1
        if retrain:
            self._train_on_synthetic_episodes(n_episodes=150)  # lighter refresh

    def predict(self, compromised: str, max_hops: int = 2) -> List[dict]:
        if not self._fitted:
            return []
        visited = {compromised: 1.0}
        frontier = [(compromised, 0.0, 1.0, 0)]
        results = []
        while frontier:
            node, edge_w, path_w, hop = frontier.pop(0)
            if hop >= max_hops:
                continue
            for neighbor, w in self.graph.get(node, {}).items():
                feats = np.array([self._node_features(neighbor, hop + 1, w, path_w * w)])
                risk = float(self.model.predict(feats)[0])
                risk = min(1.0, max(0.0, risk))
                if neighbor not in visited or risk > visited[neighbor]:
                    visited[neighbor] = risk
                    frontier.append((neighbor, w, path_w * w, hop + 1))
                    results.append({
                        "service": neighbor,
                        "predicted_risk": round(risk * 100, 1),
                        "hops_away": hop + 1,
                        "via": node,
                        "model": "random_forest",
                    })
        return sorted(results, key=lambda r: -r["predicted_risk"])


# ===========================================================================
# 2. ML BEHAVIORAL ANOMALY MODEL  (replaces single-feature payload z-score)
# ===========================================================================
class BehavioralAnomalyModel:
    """
    Per-service IsolationForest over a small feature vector of each request:
        [payload_size, hour_of_day, seconds_since_last_call]
    Catches multi-dimensional stolen-but-valid-token behavior that a single
    z-score on payload size alone would miss (e.g. right payload size, but
    calling at a wildly different hour / cadence than usual).
    """

    MIN_SAMPLES = 8

    def __init__(self):
        self.history: Dict[str, deque] = {}
        self.models: Dict[str, IsolationForest] = {}
        self.last_call_ts: Dict[str, float] = {}

    def _features(self, payload_size: int, hour: int, gap: float) -> List[float]:
        return [payload_size, hour, gap]

    def observe(self, service: str, payload_size: int, hour: int, now: float):
        """Record an ALLOWED call and refit the model if enough samples exist."""
        gap = now - self.last_call_ts.get(service, now)
        self.last_call_ts[service] = now
        buf = self.history.setdefault(service, deque(maxlen=60))
        buf.append(self._features(payload_size, hour, gap))
        if len(buf) >= self.MIN_SAMPLES:
            X = np.array(buf)
            forest = IsolationForest(n_estimators=60, contamination=0.15, random_state=42)
            forest.fit(X)
            self.models[service] = forest

    def score(self, service: str, payload_size: int, hour: int, now: float) -> Tuple[float, Optional[str]]:
        """Returns (extra_anomaly 0-1, reason) for the CURRENT call, without
        mutating history (candidate calls shouldn't poison the baseline)."""
        model = self.models.get(service)
        if model is None:
            return 0.0, None
        gap = now - self.last_call_ts.get(service, now)
        x = np.array([self._features(payload_size, hour, gap)])
        raw = model.decision_function(x)[0]  # >0 normal, <0 anomalous
        pred = model.predict(x)[0]            # 1 normal, -1 anomaly
        if pred == -1:
            severity = min(1.0, abs(raw) * 2.5)
            return round(0.2 + 0.3 * severity, 3), (
                f"ML behavioral model flags this call as an outlier "
                f"(isolation score {raw:.2f}) vs {service}'s learned multi-feature profile"
            )
        return 0.0, None


# ===========================================================================
# 3. SYNTHETIC ADVERSARIAL TRAFFIC GENERATOR
# ===========================================================================
class SyntheticAttackGenerator:
    """
    Generates varied adversarial request sequences for stress-testing /
    live demos, by perturbing the normal-traffic distribution rather than
    hand-scripting a single fixed attack: random target selection biased
    toward rare/no-trust edges, randomized off-hour timestamps, and payload
    sizes sampled from a heavy-tailed (scrape-like) distribution.
    """

    PATTERNS = ["lateral_probe", "credential_replay", "bulk_scrape", "honeytoken_scan"]

    def __init__(self, graph: Dict[str, Dict[str, float]], honeytokens: List[str]):
        self.graph = graph
        self.services = list(graph.keys())
        self.honeytokens = honeytokens

    def _sample_payload(self) -> int:
        # heavy-tailed: mostly small, occasionally huge (scrape-like)
        return int(np.random.pareto(1.5) * 800 + 150)

    def generate_burst(self, size: int = 6, seed_service: Optional[str] = None) -> List[dict]:
        caller = seed_service or random.choice(self.services)
        burst = []
        for _ in range(size):
            pattern = random.choice(self.PATTERNS)
            if pattern == "honeytoken_scan" and self.honeytokens:
                callee = random.choice(self.honeytokens)
            else:
                # bias toward edges that DON'T exist in the normal graph (lateral movement)
                candidates = [s for s in self.services if s != caller]
                legit = set(self.graph.get(caller, {}).keys())
                weird = [c for c in candidates if c not in legit]
                callee = random.choice(weird or candidates)
            burst.append({
                "pattern": pattern,
                "caller": caller,
                "callee": callee,
                "payload_size": self._sample_payload(),
                "hour": random.choice([1, 2, 3, 4, 23]),  # off-hours bias
            })
        return burst


# ===========================================================================
# 4. EXPLAINABLE QUARANTINE DECISIONS  (SHAP where possible, manual fallback)
# ===========================================================================
class QuarantineExplainer:
    """
    Produces a human-readable feature-attribution breakdown for a decision:
      - if a fitted IsolationForest exists for the service, uses SHAP's
        TreeExplainer / KernelExplainer-free approximation via
        `shap.Explainer` over the isolation-forest decision function
      - otherwise falls back to a manual normalized breakdown of the
        rule-based anomaly components already computed by main.py
    Either way the output shape is the same, so the frontend doesn't care
    which path produced it.
    """

    def __init__(self, behavioral_model: BehavioralAnomalyModel):
        self.behavioral_model = behavioral_model

    def explain(self, service: str, components: Dict[str, float]) -> dict:
        """
        `components` = named rule-based anomaly contributions already
        computed in main.py, e.g.
          {"unknown_edge": 0.6, "off_hours": 0.2, "large_payload": 0.25,
           "behavioral_ml": 0.35, "rate_limit_pressure": 0.1}
        """
        total = sum(components.values()) or 1e-9
        breakdown = [
            {"factor": k, "contribution_pct": round(v / total * 100, 1), "raw": round(v, 3)}
            for k, v in components.items() if v > 0
        ]
        breakdown.sort(key=lambda r: -r["contribution_pct"])

        method = "manual_normalized"
        model = self.behavioral_model.models.get(service)
        if SHAP_AVAILABLE and model is not None and len(self.behavioral_model.history.get(service, [])) >= 8:
            try:
                X = np.array(self.behavioral_model.history[service])
                explainer = shap.Explainer(model.decision_function, X)
                shap_values = explainer(X[-1:])
                feature_names = ["payload_size", "hour_of_day", "seconds_since_last_call"]
                shap_contrib = {
                    feature_names[i]: float(shap_values.values[0][i])
                    for i in range(len(feature_names))
                }
                method = "shap_isolationforest"
                breakdown.append({"factor": "shap_detail", "contribution_pct": None, "raw": shap_contrib})
            except Exception:
                pass  # SHAP is a bonus explanation layer; manual breakdown already covers it

        return {"service": service, "method": method, "breakdown": breakdown}


# ===========================================================================
# 5. LIGHTWEIGHT EXTRACTIVE LOG SUMMARIZER  (no LLM / API key required)
# ===========================================================================
class LogSummarizer:
    """
    Frequency-based extractive summarizer (classic TextRank-lite approach,
    pure Python + regex — no NLTK data download needed, so it works fully
    offline). Distinct from the "Ask Cerberus" Lyzr chat: this runs
    continuously with zero configuration and produces a rolling digest.
    """

    STOPWORDS = {
        "the", "a", "an", "to", "for", "of", "in", "on", "at", "and", "is",
        "was", "were", "with", "this", "that", "it", "its", "as", "by", "be",
    }

    def _tokenize_words(self, text: str) -> List[str]:
        return [w for w in re.findall(r"[a-zA-Z]+", text.lower()) if w not in self.STOPWORDS]

    def summarize(self, log_entries: List[dict], max_sentences: int = 3) -> str:
        if not log_entries:
            return "No recent activity to summarize."

        sentences = [e["message"] for e in log_entries]
        word_freq = Counter()
        for s in sentences:
            word_freq.update(self._tokenize_words(s))

        if not word_freq:
            return " ".join(sentences[-max_sentences:])

        max_freq = max(word_freq.values())
        for w in word_freq:
            word_freq[w] /= max_freq

        scored = []
        for i, s in enumerate(sentences):
            words = self._tokenize_words(s)
            score = sum(word_freq.get(w, 0) for w in words) / (len(words) or 1)
            # recency bonus so the summary favors what just happened
            recency_bonus = (i / len(sentences)) * 0.3
            scored.append((score + recency_bonus, i, s))

        # prefer variety: skip a sentence if we've already picked a near-duplicate
        # (same caller/callee/decision repeated many times shouldn't crowd out
        # the one or two lines that actually matter, e.g. an attack/block)
        picked, seen_norm = [], set()
        for score, i, s in sorted(scored, key=lambda t: -t[0]):
            norm = re.sub(r"\d+", "", s.lower())  # ignore numeric noise (timestamps, scores)
            if norm in seen_norm:
                continue
            seen_norm.add(norm)
            picked.append((score, i, s))
            if len(picked) >= max_sentences:
                break
        top_in_order = [s for _, _, s in sorted(picked, key=lambda t: t[1])]
        return " ".join(top_in_order)

    def summarize_with_stats(self, log_entries: List[dict], honeytoken_hits: int) -> dict:
        kinds = Counter(e["kind"] for e in log_entries)
        return {
            "summary": self.summarize(log_entries),
            "event_counts": dict(kinds),
            "honeytoken_hits": honeytoken_hits,
            "total_events_considered": len(log_entries),
        }
