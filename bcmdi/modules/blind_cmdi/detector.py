"""
Blind CMDi Detection Module

Core detection logic for blind command injection vulnerabilities.

Features:
- Time-based detection (OS-aware payloads, linear latency scaling)
- Baseline capture & comparison (3 samples for jitter tolerance)
- False positive reduction (multi-probe verification, control payloads)
- ML feature extraction for anomaly detection
- OS fingerprinting (passive, from headers and payload behavior)
- WAF evasion via payload obfuscation

Detection Workflow:
1. Capture baseline response times (3 samples)
2. Calculate jitter tolerance (std dev of baseline)
3. Inject time-based payloads with chaining separators
4. Measure response latency deltas
5. Verify linear time increase (3 → 5 → 7 seconds)
6. Compare against control payloads (false positive elimination)
7. Extract ML features and persist to feature store
"""

import urllib.parse
import time
import statistics
from typing import Dict, Any, List, Optional, Tuple
import sys
import os

# Import from shared core
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from bsqli.core.http_client import HttpClient
from bsqli.core.response_analyzer import measure_request_time
from bsqli.core.logger import get_logger
from bsqli.ml.anomaly_stub import persist_feature_vector, prepare_feature_vector

from .payloads import (
    linux_time_payloads, windows_time_payloads, chain_separators,
    obfuscation_variants, get_control_payloads, PAYLOAD_CLASS_INDEX
)

logger = get_logger("cmdi_detector")

# Configuration
BASELINE_SAMPLES = 3  # Number of baseline samples to capture
MIN_CONFIRMATIONS = 2  # Minimum successful time-based proofs required
TIME_JITTER_TOLERANCE = 1.5  # Baseline std dev multiplier (1.5x = 50% variance tolerated)
LATENCY_THRESHOLD = 2.5  # Minimum delta (seconds) to consider significant


class OSFingerprinter:
    """Passive OS detection based on response behavior and headers."""
    
    @staticmethod
    def infer_from_headers(headers: dict) -> Optional[str]:
        """Infer OS from HTTP response headers."""
        if not headers:
            return None
        
        server = (headers.get("server") or "").lower()
        
        # Windows-specific servers
        if any(x in server for x in ["iis", "windows"]):
            return "windows"
        
        # Linux-specific servers (Apache, Nginx usually on Linux)
        if any(x in server for x in ["apache", "nginx", "linux"]):
            return "linux"
        
        return None
    
    @staticmethod
    def infer_from_url(url: str) -> Optional[str]:
        """Infer OS from URL path patterns."""
        path = urllib.parse.urlparse(url).path.lower()
        
        # Windows paths
        if any(x in path for x in [".asp", ".aspx", ".php", "windows", "system32"]):
            if any(x in path for x in [".asp", ".aspx"]):
                return "windows"
        
        # Linux paths
        if any(x in path for x in ["/usr/", "/var/", "/home/", "/tmp/", ".sh"]):
            return "linux"
        
        return None


class BlindCMDiDetector:
    """
    Main detector for blind command injection vulnerabilities.
    """
    
    def __init__(self, timeout: int = 10):
        """
        Initialize detector.
        
        Args:
            timeout: HTTP request timeout in seconds
        """
        self.client = HttpClient(timeout=timeout)
        self.timeout = timeout
        self.os_hint = None  # Will be inferred
    
    def _measure_baseline(self, url: str, headers: Dict[str, str] = None,
                          cookies: Dict[str, str] = None) -> Tuple[List[float], float]:
        """
        Capture baseline response times (3 samples).
        
        Returns:
            (list of baseline times, jitter tolerance threshold)
        """
        baseline_times = []
        headers = headers or {}
        cookies = cookies or {}
        
        logger.debug(f"[CMDi] Capturing baseline ({BASELINE_SAMPLES} samples)...")
        
        for i in range(BASELINE_SAMPLES):
            try:
                t, resp = measure_request_time(self.client.get, url, headers=headers, cookies=cookies)
                baseline_times.append(t)
                logger.debug(f"  Sample {i+1}: {t:.3f}s")
            except Exception as e:
                logger.debug(f"  Sample {i+1} failed: {e}")
                return [], float('inf')
        
        if not baseline_times or len(baseline_times) < BASELINE_SAMPLES:
            logger.warning("[CMDi] Failed to capture sufficient baseline samples")
            return [], float('inf')
        
        # Calculate jitter tolerance (standard deviation)
        jitter = statistics.stdev(baseline_times)
        jitter_tolerance = jitter * TIME_JITTER_TOLERANCE
        
        avg_baseline = statistics.mean(baseline_times)
        logger.info(f"[CMDi] Baseline: avg={avg_baseline:.3f}s, jitter={jitter:.3f}s, tolerance={jitter_tolerance:.3f}s")
        
        return baseline_times, jitter_tolerance
    
    def _param_replace_get(self, url: str, param: str, new_value: str) -> str:
        """Replace a query parameter value in URL."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [new_value]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                        parsed.params, new_query, parsed.fragment))
    
    def _inject_payload(self, url: str, param: str, payload: str,
                        separator: str = ";") -> str:
        """
        Inject a command injection payload into a parameter.
        
        Args:
            url: Target URL
            param: Parameter name
            payload: Command to inject
            separator: Chaining separator (e.g., ";", "&&", "|")
        
        Returns:
            URL with injected payload
        """
        # Get original parameter value (if exists)
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        original_value = qs.get(param, [""])[0]
        
        # Inject with separator
        injected_value = original_value + separator + payload
        
        return self._param_replace_get(url, param, injected_value)
    
    def _select_os_payloads(self) -> List[Dict]:
        """
        Select OS-appropriate time-based payloads.
        
        Returns list of payload dicts with 'payload' and 'delay' keys.
        """
        # Try to infer OS from context
        if self.os_hint and "windows" in self.os_hint.lower():
            logger.info("[CMDi] Using Windows payloads")
            return windows_time_payloads()
        elif self.os_hint and "linux" in self.os_hint.lower():
            logger.info("[CMDi] Using Linux payloads")
            return linux_time_payloads()
        else:
            # Default to Linux (more common in web apps)
            logger.info("[CMDi] OS unknown, defaulting to Linux payloads")
            return linux_time_payloads()
    
    def _test_time_based(self, url: str, param: str, baseline_times: List[float],
                         jitter_tolerance: float, headers: Dict[str, str] = None,
                         cookies: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Test for time-based CMDi vulnerability.
        
        Injects sleep payloads (3/5/7 seconds) and verifies linear latency scaling.
        
        Returns:
            Result dict with 'evidence', 'details', 'confidence'
        """
        headers = headers or {}
        cookies = cookies or {}
        result = {
            "type": "time_based",
            "evidence": False,
            "confirmations": [],
            "details": {},
            "confidence": "LOW"
        }
        
        if not baseline_times:
            return result
        
        avg_baseline = statistics.mean(baseline_times)
        
        # Select OS-appropriate payloads
        payloads = self._select_os_payloads()
        time_payloads = [p for p in payloads if p["variant"] != "control"]
        
        # Test each separator strategy
        separators = chain_separators()
        
        for separator_info in separators:
            separator = separator_info["sep"]
            logger.debug(f"[CMDi] Testing separator: {separator_info['description']}")
            
            # Collect timing results for this separator
            timings = {}
            
            # Test time-based payloads (3, 5, 7 seconds)
            for payload_info in time_payloads:
                if payload_info["variant"] == "control":
                    continue
                
                payload = payload_info["payload"]
                expected_delay = payload_info["delay"]
                
                # Inject payload
                injected_url = self._inject_payload(url, param, payload, separator)
                
                try:
                    logger.debug(f"  Testing payload: {payload} (expect {expected_delay}s delay)")
                    injected_time, resp = measure_request_time(
                        self.client.get, injected_url, headers=headers, cookies=cookies
                    )
                    
                    # Store timing result
                    if expected_delay not in timings:
                        timings[expected_delay] = []
                    timings[expected_delay].append(injected_time)
                    
                    logger.debug(f"    Response time: {injected_time:.3f}s")
                    
                except Exception as e:
                    logger.debug(f"    Request failed: {e}")
                    continue
            
            # Analyze timings for linear scaling
            if len(timings) < 2:
                continue
            
            # Sort by expected delay
            sorted_delays = sorted(timings.keys())
            
            # Check for linear time increase
            # Example: 3s → 5s → 7s
            is_linear = True
            deltas = []
            
            for i in range(len(sorted_delays) - 1):
                delay1 = sorted_delays[i]
                delay2 = sorted_delays[i + 1]
                
                time1 = statistics.mean(timings[delay1])
                time2 = statistics.mean(timings[delay2])
                
                delta = time2 - time1
                expected_delta = delay2 - delay1
                deltas.append(delta)
                
                # Allow ±1.5s tolerance for network jitter
                tolerance = max(expected_delta * 0.3, jitter_tolerance * 2)
                
                if abs(delta - expected_delta) > tolerance:
                    logger.debug(f"    Delta mismatch: expected ~{expected_delta}s, got {delta:.3f}s")
                    is_linear = False
                    break
                else:
                    logger.debug(f"    Delta match: {delta:.3f}s ≈ {expected_delta}s (tolerance: ±{tolerance:.3f}s)")
            
            if is_linear and len(timings) >= 2:
                confirmation = {
                    "separator": separator,
                    "timings": {str(k): statistics.mean(v) for k, v in timings.items()},
                    "linear_scaling": True,
                    "deltas": deltas
                }
                result["confirmations"].append(confirmation)
                logger.info(f"[CMDi] ✓ Time-based confirmation: {separator}")
        
        # Evaluate evidence
        if len(result["confirmations"]) >= MIN_CONFIRMATIONS:
            result["evidence"] = True
            result["confidence"] = "HIGH"
            logger.info(f"[CMDi] ✓ HIGH confidence: {len(result['confirmations'])} confirmations")
        elif len(result["confirmations"]) == 1:
            result["confidence"] = "MEDIUM"
            logger.info(f"[CMDi] ~ MEDIUM confidence: {len(result['confirmations'])} confirmation")
        else:
            result["confidence"] = "LOW"
            logger.debug(f"[CMDi] ✗ LOW confidence: {len(result['confirmations'])} confirmations")
        
        result["details"] = {
            "baseline_avg": avg_baseline,
            "confirmations_count": len(result["confirmations"]),
            "threshold": MIN_CONFIRMATIONS
        }
        
        return result
    
    def _test_control_payloads(self, url: str, param: str, headers: Dict[str, str] = None,
                               cookies: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Test control payloads (should NOT sleep or behave like injections).
        
        Used to eliminate false positives.
        
        Returns:
            Result dict with pass/fail status
        """
        headers = headers or {}
        cookies = cookies or {}
        
        logger.debug("[CMDi] Testing control payloads (false positive check)...")
        
        control_payloads = get_control_payloads(os_type=self.os_hint or "linux")
        
        for control_payload in control_payloads:
            try:
                injected_url = self._inject_payload(url, param, control_payload, separator=";")
                control_time, resp = measure_request_time(
                    self.client.get, injected_url, headers=headers, cookies=cookies
                )
                
                logger.debug(f"  Control payload '{control_payload}': {control_time:.3f}s")
                
                # Control payloads should NOT introduce delays
                if control_time > (LATENCY_THRESHOLD + 1.0):
                    logger.warning(f"  ⚠ Control payload introduced unexpected delay: {control_time:.3f}s")
                    return {"passed": False, "reason": "control_delay", "time": control_time}
            
            except Exception as e:
                logger.debug(f"  Control payload error: {e}")
        
        return {"passed": True}
    
    def detect_query_param(self, url: str, param: str, headers: Dict[str, str] = None,
                          cookies: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Detect CMDi in query parameter (GET request).
        
        Args:
            url: Target URL
            param: Parameter name to test
            headers: HTTP headers (optional)
            cookies: Cookies (optional)
        
        Returns:
            Result dict with findings
        """
        headers = headers or {}
        cookies = cookies or {}
        
        logger.info(f"[CMDi] Detecting query param: {param}")
        
        # Infer OS from URL/headers
        inferred_os = OSFingerprinter.infer_from_headers(headers) or \
                      OSFingerprinter.infer_from_url(url)
        if inferred_os:
            self.os_hint = inferred_os
            logger.info(f"[CMDi] Inferred OS: {inferred_os}")
        
        # Measure baseline
        baseline_times, jitter_tolerance = self._measure_baseline(url, headers, cookies)
        if not baseline_times:
            logger.warning(f"[CMDi] Baseline measurement failed for {param}")
            return {"evidence": False, "confidence": "LOW", "error": "baseline_failed"}
        
        # Test time-based injection
        result = self._test_time_based(url, param, baseline_times, jitter_tolerance, headers, cookies)
        
        # Run control payload test (false positive check)
        if result["evidence"]:
            control_result = self._test_control_payloads(url, param, headers, cookies)
            if not control_result["passed"]:
                logger.warning(f"[CMDi] Control test failed - likely false positive")
                result["evidence"] = False
                result["confidence"] = "LOW"
                result["details"]["control_failure"] = control_result["reason"]
        
        # Extract ML features
        if result["evidence"]:
            self._extract_and_persist_features(url, param, result, headers, cookies)
        
        return result
    
    def _extract_and_persist_features(self, url: str, param: str, result: Dict[str, Any],
                                      headers: Dict[str, str] = None,
                                      cookies: Dict[str, str] = None):
        """
        Extract ML features from successful detection and persist to feature store.
        """
        headers = headers or {}
        cookies = cookies or {}
        
        try:
            # Get sample injected response for feature extraction
            if result["confirmations"]:
                # Use first confirmation's payload for feature extraction
                first_sep = result["confirmations"][0]["separator"]
                payload = self._select_os_payloads()[0]["payload"]  # Use first sleep payload
                
                injected_url = self._inject_payload(url, param, payload, first_sep)
                _, resp = measure_request_time(self.client.get, injected_url, headers=headers, cookies=cookies)
                
                response_body = resp.text if resp else ""
                
                # Build feature vector
                feature_vector = prepare_feature_vector(
                    url=url,
                    parameter=param,
                    injection_type="command_injection",
                    payload=payload,
                    baseline_time=statistics.mean(result["details"].get("baseline_times", [0])),
                    injected_time=result["confirmations"][0]["timings"].get("5", 0),
                    content_length=len(response_body),
                    status_code=resp.status_code if resp else None,
                    response_body=response_body
                )
                
                # Persist to feature store
                persist_feature_vector(feature_vector)
                logger.debug("[CMDi] Feature vector persisted")
        
        except Exception as e:
            logger.debug(f"[CMDi] Feature extraction error: {e}")
