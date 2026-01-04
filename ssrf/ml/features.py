"""
Lightweight confidence scoring for SSRF findings.

ML is used only to adjust confidence; existence is determined by signals
and callbacks. No external dependencies are required.
"""
from typing import List, Dict


def _compute_score(finding: Dict) -> float:
    signals = finding.get("signals", []) or []
    signal_count = len(signals)
    callback = "callback_received" in signals
    ingestion_scores = finding.get("ingestion_vector_scores", {}) or {}
    max_ingestion = max(ingestion_scores.values()) if ingestion_scores else 0.0
    endpoint_class = finding.get("endpoint_class", "generic")

    score = 0.3
    if callback:
        score += 0.5
    score += min(signal_count * 0.1, 0.3)
    score += min(max_ingestion * 0.2, 0.2)

    if endpoint_class in {"fetch", "callback", "webhook"}:
        score += 0.05

    # Cross-signal correlation boosts
    if "redirect_followed" in signals and "timeout_variance" in signals:
        score += 0.1
    if "worker_fetch_inference" in signals:
        score += 0.05

    return min(score, 1.0)


def _label(score: float) -> str:
    if score >= 0.75:
        return "HIGH"
    if score >= 0.5:
        return "MEDIUM"
    return "LOW"


def score_confidence(findings: List[Dict]) -> List[Dict]:
    scored = []
    for f in findings:
        s = _compute_score(f)
        item = dict(f)
        item["confidence"] = _label(s)
        item["anomaly_score"] = round(s, 3)
        scored.append(item)
    return scored


__all__ = ["score_confidence"]
