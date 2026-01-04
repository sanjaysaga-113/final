"""
SSRF capability detection (blind / out-of-band).

This module sends strictly controlled HTTP(S) payloads to attacker-owned
endpoints and correlates UUID-tagged callbacks. No internal probing,
port scanning, or metadata access is performed.
"""
import time
import urllib.parse
from typing import Dict, List, Any, Optional

from bsqli.core.http_client import HttpClient
from bsqli.core.response_analyzer import measure_request_time, is_time_significant
from bsqli.core.logger import get_logger
from .payload_engine import SSRFPayloadEngine
from ssrf.ml.features import score_confidence

SSRF_LIKELY_PARAMS = {
    "url", "uri", "link", "redirect", "next", "callback", "webhook", "fetch", "target"
}

logger = get_logger("ssrf_detector")


class SSRFDetector:
    def __init__(self, listener_url: str, timeout: int = 10, wait_time: int = 20, expanded_enabled: bool = True):
        self.listener_url = listener_url
        self.client = HttpClient(timeout=timeout)
        self.engine = SSRFPayloadEngine(listener_url)
        self.wait_time = wait_time
        self.expanded_enabled = expanded_enabled
        self.injections: Dict[str, Dict[str, Any]] = {}
        self.negative_evidence: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _param_replace(self, url: str, param: str, new_value: str) -> str:
        p = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        qs[param] = [new_value]
        new_q = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

    def _classify_endpoint(self, url: str) -> str:
        path = urllib.parse.urlparse(url).path.lower()
        if any(k in path for k in ["auth", "login", "signin"]):
            return "auth"
        if any(k in path for k in ["search", "query", "filter"]):
            return "search"
        if any(k in path for k in ["fetch", "proxy", "callback", "webhook", "hook"]):
            return "fetch"
        if any(k in path for k in ["log", "analytics", "event"]):
            return "analytics"
        if any(k in path for k in ["upload", "file", "image", "media"]):
            return "upload"
        return "generic"

    def _identify_ssrf_params(self, url: str) -> List[str]:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)
        return [p for p in qs.keys() if p.lower() in SSRF_LIKELY_PARAMS]

    def update_ingestion_vector_scores(self, recon_report: Dict[str, Any]) -> Dict[str, float]:
        """Convert recon ingestion flags into calibrated scores."""
        if recon_report.get("ingestion_vector_scores"):
            return dict(recon_report.get("ingestion_vector_scores", {}))

        scores: Dict[str, float] = {}
        accepted = set(recon_report.get("ingestion_vectors", []))
        async_behavior = recon_report.get("async_behavior", False)
        header_accept = recon_report.get("evidence", {}).get("headers_accepted", [])

        for vector in ["query", "form", "json"]:
            if vector in accepted:
                base = 0.9 if vector == "query" else 0.7
                if async_behavior:
                    base += 0.05
                scores[vector] = round(min(base, 0.95), 2)
        if header_accept:
            scores["header"] = 0.8
        if async_behavior and not scores:
            scores["async_only"] = 0.5

        # Downrank vectors tied to negative evidence
        for kind, count in self.negative_evidence.items():
            if count >= 2:
                scores[kind] = max(0.1, scores.get(kind, 0.3) * 0.5)
        return scores

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------
    def run_oob_detection(self, url: str, recon_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Send OOB SSRF payloads and record injection metadata."""
        baseline_time, baseline_resp = measure_request_time(self.client.get, url)
        endpoint_class = recon_report.get("endpoint_class") or self._classify_endpoint(url)
        ingestion_scores = self.update_ingestion_vector_scores(recon_report)
        async_behavior = recon_report.get("async_behavior", False)
        params = self._identify_ssrf_params(url)
        if not params:
            return []

        payloads = self.engine.build_payloads()
        injections: List[Dict[str, Any]] = []
        decision_prefix = f"active_recon: blind_capable={recon_report.get('blind_capable', False)}"

        for param in params:
            for payload in payloads:
                injected_url = self._param_replace(url, param, payload["url"])
                injected_time, resp = measure_request_time(self.client.get, injected_url)

                signals = self.analyze_behavioral_signals(
                    baseline_time=baseline_time,
                    injected_time=injected_time,
                    response=resp,
                    payload_kind=payload["kind"],
                    control=payload.get("control", False),
                )

                record = {
                    "uuid": payload["uuid"],
                    "url": url,
                    "parameter": param,
                    "payload": payload["url"],
                    "payload_kind": payload["kind"],
                    "detection_tier": payload["tier"],
                    "signals": signals,
                    "ingestion_vector_scores": ingestion_scores,
                    "endpoint_class": endpoint_class,
                    "async_behavior": async_behavior,
                    "baseline_time": baseline_time,
                    "injected_time": injected_time,
                    "status_code": getattr(resp, "status_code", None),
                    "redirects": getattr(resp, "history", []),
                    "decision_trace": [decision_prefix],
                    "detection_type": "BLIND_SSRF",
                    "callback_time": None,
                }

                for sig in signals:
                    record["decision_trace"].append(f"ssrf: {sig}")

                self.injections[payload["uuid"].lower()] = record
                injections.append(record)

                if payload.get("control") and not signals:
                    self.negative_evidence[payload["kind"]] = self.negative_evidence.get(payload["kind"], 0) + 1

        # Allow callbacks to arrive
        if injections:
            time.sleep(self.wait_time)
        return injections

    def analyze_behavioral_signals(
        self,
        baseline_time: float,
        injected_time: float,
        response: Any,
        payload_kind: str,
        control: bool = False,
    ) -> List[str]:
        signals: List[str] = []

        # Timing variance (expected slower for unreachable)
        if is_time_significant(baseline_time, injected_time, threshold=2.5):
            signals.append("timeout_variance")

        # Redirect chain following
        if response is not None and getattr(response, "history", None):
            try:
                history_hosts = {urllib.parse.urlparse(r.url).netloc for r in response.history if getattr(r, "url", None)}
                final_host = urllib.parse.urlparse(getattr(response, "url", "")).netloc
                if history_hosts and final_host not in history_hosts:
                    signals.append("redirect_followed")
            except Exception:
                pass

        # Error-class differences
        if response is not None:
            status = getattr(response, "status_code", 0)
            if status in {301, 302, 307, 308}:
                signals.append("redirect_signal")
            elif status in {400, 404, 408, 500, 504} and not control:
                signals.append("error_difference")

        if payload_kind == "unreachable_probe" and "timeout_variance" in signals:
            signals.append("worker_fetch_inference")

        return signals

    def correlate_callbacks(self, callbacks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for cb in callbacks:
            uuid = cb.get("uuid", "").lower()
            if not uuid:
                continue
            inj = self.injections.get(uuid)
            if not inj:
                continue
            inj_copy = dict(inj)
            inj_copy["detection_tier"] = "OOB"
            inj_copy["signals"] = list(set(inj_copy.get("signals", [])) | {"callback_received"})
            inj_copy["callback_time"] = cb.get("timestamp")
            inj_copy["decision_trace"].append("ssrf: callback_received")
            findings.append(inj_copy)
        return findings

    def run_expanded_detection(self, injections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.expanded_enabled:
            return []
        expanded: List[Dict[str, Any]] = []
        for inj in injections:
            if "callback_received" in inj.get("signals", []):
                continue
            if len(inj.get("signals", [])) >= 2:
                inj_copy = dict(inj)
                inj_copy["detection_tier"] = "EXPANDED"
                inj_copy["decision_trace"].append("ssrf: behavioral_signals")
                expanded.append(inj_copy)
        return expanded

    def generate_ssrf_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not findings:
            return {"findings": []}
        scored = score_confidence(findings)
        output_dir = "ssrf/output"
        json_path = f"{output_dir}/findings.json"
        txt_path = f"{output_dir}/findings.txt"

        import os
        import json
        os.makedirs(output_dir, exist_ok=True)
        with open(json_path, "w") as f:
            json.dump(scored, f, indent=2)

        with open(txt_path, "w") as f:
            for item in scored:
                f.write(f"URL: {item['url']}\n")
                f.write(f"Param: {item['parameter']} | Tier: {item['detection_tier']} | Confidence: {item.get('confidence')}\n")
                f.write(f"Signals: {', '.join(item.get('signals', []))}\n")
                f.write(f"Decision trace: {item.get('decision_trace', [])}\n")
                f.write("-" * 60 + "\n")

        return {"findings": scored, "json_path": json_path, "txt_path": txt_path}


__all__ = [
    "SSRFDetector",
]
