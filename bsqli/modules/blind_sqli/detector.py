import urllib.parse
from typing import Dict, Any
from ...core.http_client import HttpClient
from ...core.response_analyzer import measure_request_time, content_similarity, is_time_significant
from .payload_engine import generate_payloads
from ...core.logger import get_logger
from .payloads import boolean_payloads

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
                    if conf == "HIGH":
                        break
            except Exception as e:
                logger.debug("Time detection error: %s", e)
                continue
        return results
