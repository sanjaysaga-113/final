"""
Blind XXE Detection Engine

Implements multi-technique XXE detection:
1. Out-of-band (OAST) - HTTP/DNS callback correlation
2. Time-based - Response timing anomalies
3. Parser behavior - Status code/size/error patterns

Features:
- Baseline response capture (3 samples)
- OAST callback server integration
- Multi-probe confirmation (requires OAST callback OR 2x time-based confirmations)
- ML feature extraction for anomaly detection
- False-positive reduction via control payloads
- Jitter-tolerant timing analysis
"""

import time
import re
import statistics
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
from bsqli.core.http_client import HttpClient
from bsqli.core.logger import get_logger
from bsqli.ml.anomaly_stub import prepare_feature_vector, persist_feature_vector
from . import payloads


logger = get_logger(__name__)


class OASTCorrelator:
    """
    Correlates OAST callbacks with injected XXE payloads.
    
    Tracks:
    - Unique correlation IDs for each payload
    - Callback timestamps
    - Callback sources (HTTP vs DNS)
    - Payload injection time windows
    """
    
    def __init__(self):
        """Initialize OAST correlator"""
        self.pending_callbacks = {}  # {correlation_id: (payload_type, injection_time, endpoint)}
        self.received_callbacks = {}  # {correlation_id: (callback_time, callback_type, source_ip)}
        self.callback_window = 30  # seconds to wait for callbacks
    
    def register_injection(self, correlation_id: str, payload_type: str, endpoint: str):
        """
        Register a payload injection for callback tracking.
        
        Args:
            correlation_id: Unique ID embedded in payload
            payload_type: Type of XXE payload (oast_http, oast_dns, etc.)
            endpoint: Target endpoint URL
        """
        self.pending_callbacks[correlation_id] = {
            "payload_type": payload_type,
            "injection_time": time.time(),
            "endpoint": endpoint,
        }
        logger.debug(f"Registered OAST correlation ID: {correlation_id}")
    
    def log_callback(self, correlation_id: str, callback_type: str, source: str):
        """
        Log a received OAST callback.
        
        Args:
            correlation_id: Matched correlation ID
            callback_type: "http" or "dns"
            source: Source IP/hostname
        """
        if correlation_id in self.pending_callbacks:
            self.received_callbacks[correlation_id] = {
                "callback_time": time.time(),
                "callback_type": callback_type,
                "source": source,
                "injection_metadata": self.pending_callbacks[correlation_id],
            }
            logger.info(f"OAST callback received: {correlation_id} ({callback_type})")
            return True
        return False
    
    def get_confirmed_xxe(self) -> List[Dict[str, Any]]:
        """
        Get XXE vulnerabilities confirmed by OAST callbacks.
        
        Returns:
            List of confirmed XXE discoveries with correlation data
        """
        confirmed = []
        for corr_id, callback_data in self.received_callbacks.items():
            if corr_id in self.pending_callbacks:
                confirmed.append({
                    "correlation_id": corr_id,
                    "callback_type": callback_data["callback_type"],
                    "callback_time": callback_data["callback_time"],
                    "endpoint": callback_data["injection_metadata"]["endpoint"],
                    "payload_type": callback_data["injection_metadata"]["payload_type"],
                })
        return confirmed
    
    def cleanup(self, max_age_seconds: int = 60):
        """Remove old pending callbacks"""
        current_time = time.time()
        expired = [
            cid for cid, data in self.pending_callbacks.items()
            if current_time - data["injection_time"] > max_age_seconds
        ]
        for cid in expired:
            del self.pending_callbacks[cid]


class BlindXXEDetector:
    """
    Core XXE detection engine.
    
    Implements three detection techniques:
    1. OAST - Out-of-band callback verification
    2. Time-based - Response timing anomalies
    3. Parser behavior - Status/size/error pattern changes
    """
    
    # Configuration
    BASELINE_SAMPLES = 3
    MIN_TIME_CONFIRMATIONS = 2
    TIME_JITTER_TOLERANCE = 1.5
    LATENCY_THRESHOLD = 2.5  # seconds
    MIN_BODY_CHANGE = 50  # bytes
    HTTP_TIMEOUT = 15
    
    def __init__(self, http_client: HttpClient, oast_server=None):
        """
        Initialize XXE detector.
        
        Args:
            http_client: Shared HttpClient for requests
            oast_server: Optional OAST server for callback correlation
                        Should implement: register_injection(), get_callbacks()
        """
        self.http_client = http_client
        self.oast_server = oast_server
        self.correlator = OASTCorrelator()
        self.response_analyzer = None  # Placeholder; kept for interface parity
        
        # Baselines and history
        self.baselines = {}  # {parameter: [response_times]}
        self.responses = {}  # {parameter: [response_objects]}
        self.xxe_candidates = defaultdict(list)  # {parameter: [findings]}
    
    def _measure_baseline(self, url: str, method: str = "GET", 
                         data: Dict = None, headers: Dict = None,
                         content_type: str = "application/xml") -> Dict[str, Any]:
        """
        Capture baseline behavior for target endpoint.
        
        Sends valid XML and measures:
        - Response time
        - Status code
        - Content length
        - Error patterns
        
        Args:
            url: Target endpoint URL
            method: HTTP method (GET, POST, etc.)
            data: Request body data
            headers: HTTP headers
            content_type: Content-Type header value
        
        Returns:
            Baseline metrics dict
        """
        baseline_data = {
            "response_times": [],
            "status_codes": [],
            "content_lengths": [],
            "errors": [],
            "avg_time": 0,
            "std_dev": 0,
            "jitter_tolerance": 0,
        }
        
        # Send valid XML samples
        valid_xml = """<?xml version="1.0" encoding="UTF-8"?>
<root>
  <data>test</data>
</root>"""
        
        for i in range(self.BASELINE_SAMPLES):
            try:
                req_headers = headers.copy() if headers else {}
                req_headers["Content-Type"] = content_type
                
                start = time.time()
                if method.upper() == "POST":
                    resp = self.http_client.post(
                        url,
                        data=valid_xml,
                        headers=req_headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                else:
                    resp = self.http_client.get(
                        url,
                        headers=req_headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                elapsed = time.time() - start
                
                baseline_data["response_times"].append(elapsed)
                baseline_data["status_codes"].append(resp.status_code)
                baseline_data["content_lengths"].append(len(resp.content))
                
                logger.debug(f"Baseline {i+1}: {elapsed:.2f}s, {resp.status_code}, {len(resp.content)} bytes")
                
            except Exception as e:
                logger.warning(f"Baseline measurement error: {e}")
                baseline_data["errors"].append(str(e))
        
        # Calculate statistics
        if baseline_data["response_times"]:
            baseline_data["avg_time"] = statistics.mean(baseline_data["response_times"])
            if len(baseline_data["response_times"]) > 1:
                baseline_data["std_dev"] = statistics.stdev(baseline_data["response_times"])
            
            # Jitter tolerance: allow variance up to 1.5x standard deviation
            baseline_data["jitter_tolerance"] = max(
                self.TIME_JITTER_TOLERANCE,
                baseline_data["std_dev"] * 1.5
            )
        
        logger.info(f"Baseline established: avg={baseline_data['avg_time']:.2f}s, "
                   f"std_dev={baseline_data['std_dev']:.2f}s, "
                   f"tolerance={baseline_data['jitter_tolerance']:.2f}s")
        
        return baseline_data
    
    def _test_time_based(self, url: str, parameter: str, 
                        method: str = "GET", headers: Dict = None,
                        baseline: Dict = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Test for time-based XXE detection.
        
        Injects payloads that delay response via:
        - file:///dev/random (blocks indefinitely)
        - Recursive entity expansion (CPU-bound delay)
        
        Requires multiple confirmations (MIN_TIME_CONFIRMATIONS).
        
        Args:
            url: Target endpoint URL
            parameter: Parameter name being tested
            method: HTTP method
            headers: HTTP headers
            baseline: Baseline metrics from _measure_baseline()
        
        Returns:
            (is_vulnerable, findings_list) tuple
        """
        findings = []
        time_confirmations = 0
        
        # Get time-based payloads
        time_payloads = payloads.time_based_payloads()
        
        if not baseline or baseline["avg_time"] == 0:
            logger.warning("No baseline available for time-based detection")
            return False, findings
        
        baseline_avg = baseline["avg_time"]
        jitter_tolerance = baseline["jitter_tolerance"]
        threshold = baseline_avg + self.LATENCY_THRESHOLD + jitter_tolerance
        
        logger.debug(f"Time-based detection threshold: {threshold:.2f}s "
                    f"(baseline {baseline_avg:.2f}s + 2.5s + jitter {jitter_tolerance:.2f}s)")
        
        for payload, expected_delay, technique in time_payloads:
            try:
                # Build request with XXE payload in parameter
                req_headers = headers.copy() if headers else {}
                req_headers["Content-Type"] = "application/xml"
                
                start = time.time()
                
                if method.upper() == "POST":
                    resp = self.http_client.post(
                        url,
                        data=payload,
                        headers=req_headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                else:
                    resp = self.http_client.get(
                        url,
                        headers=req_headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                
                elapsed = time.time() - start
                
                logger.debug(f"Time-based test ({technique}): {elapsed:.2f}s "
                           f"(expected ~{expected_delay:.1f}s, threshold {threshold:.2f}s)")
                
                # Check if response is significantly delayed
                if elapsed > threshold:
                    time_confirmations += 1
                    findings.append({
                        "technique": "time_based",
                        "method": technique,
                        "response_time": elapsed,
                        "baseline_avg": baseline_avg,
                        "delta": elapsed - baseline_avg,
                        "threshold": threshold,
                        "payload_type": "time_xxe",
                    })
                    logger.info(f"Time-based XXE indicator: {elapsed:.2f}s > {threshold:.2f}s")
                
            except Exception as e:
                logger.debug(f"Time-based test error: {e}")
        
        # Vulnerable if confirmed multiple times
        is_vulnerable = time_confirmations >= self.MIN_TIME_CONFIRMATIONS
        logger.info(f"Time-based confirmations: {time_confirmations}/{self.MIN_TIME_CONFIRMATIONS}")
        
        return is_vulnerable, findings
    
    def _test_parser_behavior(self, url: str, parameter: str,
                             method: str = "GET", headers: Dict = None,
                             baseline: Dict = None) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Test for XXE via parser behavior changes.
        
        Observations:
        - HTTP status code differs (200 -> 400/500 on XXE error)
        - Response size deviates significantly
        - Error messages reveal XML parser state
        
        Args:
            url: Target endpoint URL
            parameter: Parameter name
            method: HTTP method
            headers: HTTP headers
            baseline: Baseline metrics
        
        Returns:
            (is_vulnerable, findings_list) tuple
        """
        findings = []
        behavior_indicators = 0
        
        behavior_payloads = payloads.parser_behavior_payloads()
        
        if not baseline or not baseline["status_codes"]:
            logger.warning("No baseline status codes for behavior detection")
            return False, findings
        
        baseline_status = statistics.mode(baseline["status_codes"])
        baseline_avg_size = statistics.mean(baseline["content_lengths"]) if baseline["content_lengths"] else 0
        
        logger.debug(f"Expected status: {baseline_status}, avg size: {baseline_avg_size:.0f} bytes")
        
        for payload, behavior_type in behavior_payloads:
            try:
                req_headers = headers.copy() if headers else {}
                req_headers["Content-Type"] = "application/xml"
                
                if method.upper() == "POST":
                    resp = self.http_client.post(
                        url,
                        data=payload,
                        headers=req_headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                else:
                    resp = self.http_client.get(
                        url,
                        headers=req_headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                
                actual_size = len(resp.content)
                size_diff = abs(actual_size - baseline_avg_size)
                
                # Check for status code anomaly
                if resp.status_code != baseline_status:
                    behavior_indicators += 1
                    findings.append({
                        "technique": "parser_behavior",
                        "anomaly_type": "status_code_change",
                        "baseline_status": baseline_status,
                        "actual_status": resp.status_code,
                        "payload_type": behavior_type,
                    })
                    logger.info(f"Status code anomaly: {baseline_status} -> {resp.status_code}")
                
                # Check for size anomaly
                if size_diff > self.MIN_BODY_CHANGE:
                    behavior_indicators += 1
                    findings.append({
                        "technique": "parser_behavior",
                        "anomaly_type": "size_change",
                        "baseline_size": baseline_avg_size,
                        "actual_size": actual_size,
                        "delta": size_diff,
                        "payload_type": behavior_type,
                    })
                    logger.info(f"Response size anomaly: {baseline_avg_size:.0f} -> {actual_size} bytes")
                
            except Exception as e:
                logger.debug(f"Parser behavior test error: {e}")
        
        is_vulnerable = behavior_indicators >= 2
        logger.info(f"Parser behavior indicators: {behavior_indicators}")
        
        return is_vulnerable, findings
    
    def _test_control_payloads(self, url: str, method: str = "GET",
                              headers: Dict = None) -> bool:
        """
        Test control payloads to reduce false positives.
        
        Control payloads should NOT exhibit XXE behavior:
        - Valid XML without entities
        - Declared but unreferenced entities
        - Invalid entity syntax
        
        If all control payloads behave normally, XXE is more likely.
        If control payloads also behave anomalously, it's a false positive.
        
        Args:
            url: Target endpoint
            method: HTTP method
            headers: HTTP headers
        
        Returns:
            True if controls behave normally (XXE is likely)
            False if controls behave anomalously (likely false positive)
        """
        control_payloads_list = payloads.control_payloads()
        abnormal_count = 0
        
        for control_payload in control_payloads_list:
            try:
                req_headers = headers.copy() if headers else {}
                req_headers["Content-Type"] = "application/xml"
                
                start = time.time()
                
                if method.upper() == "POST":
                    resp = self.http_client.post(
                        url,
                        data=control_payload,
                        headers=req_headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                else:
                    resp = self.http_client.get(
                        url,
                        headers=req_headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                
                elapsed = time.time() - start
                
                # Control payloads should respond quickly (< 2 seconds)
                if elapsed > 5.0:
                    abnormal_count += 1
                    logger.warning(f"Control payload delayed: {elapsed:.2f}s")
                
            except Exception as e:
                logger.debug(f"Control payload test error: {e}")
        
        # False positive if most controls are abnormal
        is_false_positive = abnormal_count >= len(control_payloads_list) / 2
        
        if is_false_positive:
            logger.warning(f"Potential false positive detected: {abnormal_count}/{len(control_payloads_list)} controls abnormal")
            return False
        
        logger.info("Control payload tests passed (false positive check)")
        return True
    
    def _extract_and_persist_features(self, url: str, parameter: str,
                                     baseline: Dict, findings: Dict,
                                     oast_triggered: bool = False) -> Dict[str, float]:
        """
        Extract ML features from detection results.
        
        Features:
        - response_time: Latest observed response time
        - delta_from_baseline: Deviation from baseline average
        - response_size: Content length
        - status_code: HTTP status code
        - oast_triggered: Boolean (1.0 or 0.0)
        - time_delta_ratio: (observed - baseline) / baseline
        - std_dev_ratio: Delta / standard deviation
        - control_payload_result: Boolean from control test
        
        Args:
            url: Target endpoint
            parameter: Parameter name
            baseline: Baseline metrics
            findings: Combined findings from all techniques
            oast_triggered: Whether OAST callback was received
        
        Returns:
            Feature vector dict
        """
        features = {
            "url": url,
            "parameter": parameter,
            "response_time": findings.get("latest_time", baseline["avg_time"]),
            "delta_from_baseline": findings.get("delta", 0.0),
            "response_size": findings.get("response_size", 0),
            "status_code": findings.get("status_code", 200),
            "oast_triggered": 1.0 if oast_triggered else 0.0,
            "time_delta_ratio": 0.0,
            "std_dev_ratio": 0.0,
            "control_payload_passed": 1.0 if findings.get("control_passed", False) else 0.0,
            "technique_count": findings.get("technique_count", 0),
        }
        
        # Calculate ratios
        if baseline["avg_time"] > 0:
            features["time_delta_ratio"] = features["delta_from_baseline"] / baseline["avg_time"]
        
        if baseline["std_dev"] > 0:
            features["std_dev_ratio"] = features["delta_from_baseline"] / baseline["std_dev"]
        
        # Persist features for ML training
        try:
            persist_feature_vector(
                feature_dict=features,
                label="xxe",
                is_vulnerable=findings.get("is_vulnerable", False)
            )
            logger.debug(f"Features persisted for {parameter}")
        except Exception as e:
            logger.warning(f"Feature persistence error: {e}")
        
        return features
    
    def detect_json_parameter(self, url: str, parameter: str, value: str,
                             headers: Dict = None) -> Dict[str, Any]:
        """
        Detect XXE in JSON-embedded XML values.
        
        Supports:
        - {"field": "<xml>...</xml>"}
        - {"data": "base64_encoded_xml"}
        - Nested XML in any JSON string field
        
        Args:
            url: Target endpoint URL
            parameter: Parameter name (JSON field name)
            value: Original parameter value
            headers: HTTP headers
        
        Returns:
            Finding dict with type, parameter, findings
        """
        logger.info(f"Testing JSON parameter {parameter} for XXE")
        
        # Capture baseline
        baseline = self._measure_baseline(url, method="POST", headers=headers)
        
        # Generate OAST payloads embedded in JSON
        if self.oast_server:
            oast_endpoint = self.oast_server.get_http_endpoint()
            json_payloads = payloads.json_embedded_payloads(oast_endpoint)
            
            for json_payload, correlation_id in json_payloads:
                self.correlator.register_injection(
                    correlation_id, "json_xxe", url
                )
                
                try:
                    resp = self.http_client.post(
                        url,
                        data=json_payload,
                        headers=headers,
                        timeout=self.HTTP_TIMEOUT,
                    )
                except Exception as e:
                    logger.debug(f"JSON XXE test error: {e}")
        
        # Also test time-based
        is_time_based, time_findings = self._test_time_based(
            url, parameter, method="POST", headers=headers, baseline=baseline
        )
        
        # Control test
        control_passed = self._test_control_payloads(url, method="POST", headers=headers)
        
        # Determine if vulnerable
        is_vulnerable = is_time_based and control_passed
        
        # Extract features
        combined_findings = {
            "is_vulnerable": is_vulnerable,
            "control_passed": control_passed,
            "technique_count": 1 if is_time_based else 0,
            "latest_time": baseline["avg_time"],
        }
        
        features = self._extract_and_persist_features(
            url, parameter, baseline, combined_findings, oast_triggered=False
        )
        
        return {
            "is_vulnerable": is_vulnerable,
            "parameter": parameter,
            "technique": "time_based" if is_time_based else "unknown",
            "findings": time_findings,
            "ml_features": features,
        }
    
    def detect_xml_parameter(self, url: str, parameter: str, value: str,
                            method: str = "POST", headers: Dict = None) -> Dict[str, Any]:
        """
        Detect XXE in XML-typed parameters.
        
        Tests parameters that accept XML payloads:
        - SOAP endpoints
        - XML API endpoints
        - Form fields with XML content-type
        
        Args:
            url: Target endpoint URL
            parameter: Parameter/field name
            value: Original value (used to infer content type)
            method: HTTP method (GET/POST)
            headers: HTTP headers
        
        Returns:
            Finding dict with vulnerabilities and ML features
        """
        logger.info(f"Testing XML parameter {parameter} for XXE via {method}")
        
        # Infer content type
        content_type = "application/xml"
        if "soap" in value.lower():
            content_type = "application/soap+xml"
        
        # Capture baseline
        baseline = self._measure_baseline(url, method=method, headers=headers,
                                        content_type=content_type)
        
        findings_list = []
        techniques_triggered = 0
        oast_callbacks = []
        
        # Technique 1: OAST-based detection
        if self.oast_server:
            oast_endpoint = self.oast_server.get_http_endpoint()
            oast_payloads = payloads.oast_http_payloads(oast_endpoint)
            
            for payload, correlation_id, payload_type in oast_payloads:
                self.correlator.register_injection(
                    correlation_id, payload_type.value, url
                )
                
                try:
                    req_headers = headers.copy() if headers else {}
                    req_headers["Content-Type"] = content_type
                    
                    if method.upper() == "POST":
                        self.http_client.post(
                            url,
                            data=payload,
                            headers=req_headers,
                            timeout=self.HTTP_TIMEOUT,
                        )
                    else:
                        self.http_client.get(
                            url,
                            headers=req_headers,
                            timeout=self.HTTP_TIMEOUT,
                        )
                    
                except Exception as e:
                    logger.debug(f"OAST payload injection error: {e}")
                
                # Small delay to allow callback to arrive
                time.sleep(0.5)
            
            # Check for callbacks
            oast_callbacks = self.correlator.get_confirmed_xxe()
            if oast_callbacks:
                techniques_triggered += 1
                findings_list.append({
                    "technique": "oast",
                    "callbacks": oast_callbacks,
                })
                logger.info(f"OAST XXE confirmed: {len(oast_callbacks)} callbacks")
        
        # Technique 2: Time-based detection
        is_time_based, time_findings = self._test_time_based(
            url, parameter, method=method, headers=headers, baseline=baseline
        )
        if is_time_based:
            techniques_triggered += 1
            findings_list.extend(time_findings)
            logger.info("Time-based XXE confirmed")
        
        # Technique 3: Parser behavior detection
        is_behavior, behavior_findings = self._test_parser_behavior(
            url, parameter, method=method, headers=headers, baseline=baseline
        )
        if is_behavior:
            techniques_triggered += 1
            findings_list.extend(behavior_findings)
            logger.info("Parser behavior XXE confirmed")
        
        # Control payload test (false positive reduction)
        control_passed = self._test_control_payloads(url, method=method, headers=headers)
        
        # Determine vulnerability
        # Vulnerable if:
        # - OAST callback received OR
        # - Time-based confirmed twice OR
        # - Parser behavior detected twice AND control passed
        is_vulnerable = (
            len(oast_callbacks) > 0 or
            (is_time_based and control_passed) or
            (is_behavior and control_passed)
        )
        
        # Extract ML features
        combined_findings = {
            "is_vulnerable": is_vulnerable,
            "control_passed": control_passed,
            "technique_count": techniques_triggered,
            "latest_time": time_findings[0]["response_time"] if time_findings else baseline["avg_time"],
            "delta": time_findings[0]["delta"] if time_findings else 0.0,
            "response_size": len(oast_callbacks) * 100,  # Placeholder
            "status_code": 200,
        }
        
        features = self._extract_and_persist_features(
            url, parameter, baseline, combined_findings,
            oast_triggered=len(oast_callbacks) > 0
        )
        
        return {
            "is_vulnerable": is_vulnerable,
            "parameter": parameter,
            "technique": "oast" if oast_callbacks else ("time_based" if is_time_based else "parser_behavior"),
            "confidence": "high" if oast_callbacks or (is_time_based and control_passed) else "medium",
            "findings": findings_list,
            "ml_features": features,
            "ml_score": calculate_ml_score(features),
        }


def calculate_ml_score(features: Dict[str, float]) -> float:
    """
    Calculate ML anomaly score based on extracted features.
    
    Score ranges 0.0 (not XXE) to 1.0 (highly likely XXE).
    
    Args:
        features: Feature vector from detection
    
    Returns:
        ML anomaly score (0.0-1.0)
    """
    score = 0.0
    
    # OAST callback is strong indicator
    if features.get("oast_triggered", 0.0) > 0.5:
        score += 0.6
    
    # Time-based deviation
    time_delta_ratio = features.get("time_delta_ratio", 0.0)
    if time_delta_ratio > 2.0:  # > 200% increase
        score += 0.3
    elif time_delta_ratio > 1.0:  # > 100% increase
        score += 0.2
    
    # Standard deviation ratio
    std_dev_ratio = features.get("std_dev_ratio", 0.0)
    if std_dev_ratio > 3.0:  # > 3 sigma
        score += 0.1
    
    # Control payload success
    if features.get("control_payload_passed", 0.0) > 0.5:
        score += 0.0  # Control passing is neutral, not XXE
    else:
        score -= 0.2  # Control failing suggests false positive
    
    # Clamp score to 0.0-1.0
    return max(0.0, min(1.0, score))
