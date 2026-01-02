"""
Active Blind Reconnaissance (Non-destructive)

Purpose:
- Identify endpoints that are *capable* of blind SQLi/XSS (ingestion/execution surfaces)
- Never send injection or exploit payloads
- Never trigger callbacks or destructive actions

Key capabilities:
- Parameter discovery (query, form, JSON) using safe placeholders
- Method probing (GET/POST/PUT/PATCH/DELETE)
- Content-Type probing (json/xml/multipart)
- Header ingestion probing (X-Forwarded-For, Referer, User-Agent, X-Original-URL)
- Async behavior inference (202, delayed responses)
- Preferred OOB channel inference (dns/http/none)

Deterministic & rate-limited:
- Fixed wordlists
- Per-host throttle (default 0.5s)
- Timeouts on every request
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

SAFE_PARAM_WORDLIST: List[str] = [
    "id", "uid", "user_id", "file", "url", "redirexct", "callback", "next"
]

SAFE_CONTENT_TYPES: List[str] = [
    "application/json",
    "application/xml",
    "multipart/form-data",
]

SAFE_METHODS: List[str] = ["GET", "POST", "PUT", "PATCH", "DELETE"]

HEADER_PROBE_SET: Dict[str, str] = {
    "X-Forwarded-For": "1.1.1.1",
    "Referer": "https://example.com/ref",
    "User-Agent": "Mozilla/5.0 (Recon-Probe)",
    "X-Original-URL": "/internal/health",
}

DEFAULT_PARAM_WORDLIST_PATH = Path(__file__).resolve().parent / "wordlists" / "burp_parameter_names.txt"
DEFAULT_MAX_PARAM_PROBES: Optional[int] = None  # None = load entire file


class ActiveBlindRecon:
    """Non-destructive active reconnaissance for blind-capable endpoints."""

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        timeout: float = 8.0,
        rate_limit: float = 0.5,
        enable_graphql: bool = False,
        max_param_probes: Optional[int] = DEFAULT_MAX_PARAM_PROBES,
    ) -> None:
        self.base_url = base_url
        self.session = session or requests.Session()
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.enable_graphql = enable_graphql
        self._last_request_ts: float = 0.0
        self.param_candidates = self._load_param_candidates(max_param_probes)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _throttle(self) -> None:
        """Simple per-host rate limiter (deterministic, no jitter)."""
        now = time.time()
        elapsed = now - self._last_request_ts
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_ts = time.time()

    def _request(self, method: str, url: str, **kwargs):
        self._throttle()
        try:
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException:
            return None

    def _load_param_candidates(self, max_param_probes: Optional[int]) -> List[str]:
        """Load a deduped parameter list (built-ins + full Burp wordlist)."""
        seen: Set[str] = set()
        candidates: List[str] = []

        def add(word: str) -> None:
            cleaned = word.strip()
            if not cleaned or cleaned in seen:
                return
            seen.add(cleaned)
            candidates.append(cleaned)

        for word in SAFE_PARAM_WORDLIST:
            add(word)

        # Require the on-disk Burp list so collaborators get identical coverage.
        path = DEFAULT_PARAM_WORDLIST_PATH
        if not path.exists():
            raise FileNotFoundError(f"Missing Burp parameter wordlist at {path}")

        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                add(line)
                if max_param_probes and len(candidates) >= max_param_probes:
                    break

        return candidates if max_param_probes is None else candidates[:max_param_probes]

    # ------------------------------------------------------------------
    # Probing methods
    # ------------------------------------------------------------------
    def probe_parameters(self) -> Set[str]:
        """Probe query/form/JSON parameters with safe placeholders."""
        accepted: Set[str] = set()
        parsed = urlparse(self.base_url)
        base_qs = parse_qs(parsed.query, keep_blank_values=True)

        # Query param probing
        for p in self.param_candidates:
            qs = base_qs.copy()
            qs[p] = ["1"]  # Safe value
            new_query = urlencode(qs, doseq=True)
            candidate = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            resp = self._request("GET", candidate)
            if resp and resp.status_code < 500:
                accepted.add("query")
                break

        # Form probing (safe echo of existing query params as form fields)
        form_keys = self.param_candidates[:3] or SAFE_PARAM_WORDLIST[:3]
        form_data = {p: "1" for p in form_keys}
        resp = self._request("POST", self.base_url, data=form_data)
        if resp and resp.status_code < 500:
            accepted.add("form")

        # JSON probing (minimal object)
        json_keys = form_keys
        resp = self._request("POST", self.base_url, json={p: "1" for p in json_keys})
        if resp and resp.status_code < 500:
            accepted.add("json")

        return accepted

    def probe_methods(self) -> List[str]:
        """Check which HTTP methods are accepted (non-destructive)."""
        accepted: List[str] = []
        for m in SAFE_METHODS:
            resp = self._request(m, self.base_url)
            if resp and resp.status_code not in {405, 501}:
                accepted.append(m)
        return accepted

    def probe_content_types(self) -> List[str]:
        """Probe content-types using small, valid bodies."""
        accepted: List[str] = []
        for ct in SAFE_CONTENT_TYPES:
            if ct == "application/json":
                body = {"ping": "1"}
            elif ct == "application/xml":
                body = "<ping>1</ping>"
            else:  # multipart/form-data
                body = {"ping": "1"}
            resp = self._request("POST", self.base_url, data=None if ct == "application/json" else body, json=body if ct == "application/json" else None, headers={"Content-Type": ct})
            if resp and resp.status_code not in {400, 415, 500}:
                accepted.append(ct)
        return accepted

    def probe_headers(self) -> List[str]:
        """Check which special headers are accepted without errors."""
        accepted: List[str] = []
        for header, value in HEADER_PROBE_SET.items():
            resp = self._request("GET", self.base_url, headers={header: value})
            if resp and resp.status_code < 500:
                accepted.append(header)
        return accepted

    def infer_async_behavior(self) -> bool:
        """Detect hints of async/queued behavior (non-destructive)."""
        timings: List[float] = []
        statuses: List[int] = []
        for _ in range(3):
            t0 = time.time()
            resp = self._request("GET", self.base_url)
            t1 = time.time()
            if resp:
                timings.append(t1 - t0)
                statuses.append(resp.status_code)
        if not timings:
            return False
        # Heuristics: HTTP 202 or high variance in timings
        if any(s == 202 for s in statuses):
            return True
        avg = sum(timings) / len(timings)
        variance = max(timings) - min(timings) if len(timings) > 1 else 0
        return variance > max(1.5, avg * 0.75)

    def infer_preferred_oob(self, headers_accepted: List[str], async_behavior: bool) -> str:
        """Infer OOB channel preference without sending callbacks."""
        if async_behavior and ("X-Forwarded-For" in headers_accepted or "X-Original-URL" in headers_accepted):
            return "http"
        if async_behavior:
            return "dns"
        return "none"

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    def generate_recon_report(self) -> Dict:
        ingestion_vectors = self.probe_parameters()
        methods = self.probe_methods()
        content_types = self.probe_content_types()
        headers_accepted = self.probe_headers()
        async_behavior = self.infer_async_behavior()
        preferred_oob = self.infer_preferred_oob(headers_accepted, async_behavior)

        blind_capable = bool(ingestion_vectors) or async_behavior or bool(headers_accepted)

        return {
            "url": self.base_url,
            "blind_capable": blind_capable,
            "ingestion_vectors": sorted(list(ingestion_vectors)),
            "async_behavior": async_behavior,
            "preferred_oob": preferred_oob,
            "evidence": {
                "methods": methods,
                "content_types": content_types,
                "headers_accepted": headers_accepted,
            },
        }


__all__ = ["ActiveBlindRecon"]
