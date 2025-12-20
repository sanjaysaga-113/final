from .detector import BlindSQLiDetector
from urllib.parse import parse_qs, urlparse
from ...core.logger import get_logger

logger = get_logger("sqli_module")

class BlindSQLiModule:
    def __init__(self, timeout=10):
        self.detector = BlindSQLiDetector(timeout=timeout)

    def _flatten_form(self, data: dict) -> dict:
        # parse_qs returns lists; convert to first value to align with detector expectations
        flattened = {}
        for k, v in data.items():
            if isinstance(v, list):
                flattened[k] = v[0] if v else ""
            else:
                flattened[k] = v
        return flattened

    def scan_url(self, url: str, headers: dict = None, cookies: dict = None) -> list:
        findings = []
        try:
            qs = parse_qs(urlparse(url).query)
            for param in qs.keys():
                b = self.detector.detect_boolean(url, param, headers=headers, cookies=cookies)
                if b.get("evidence"):
                    findings.append({
                        "url": url, "parameter": param, "injection": "boolean",
                        "details": b
                    })
                t = self.detector.detect_time(url, param, headers=headers, cookies=cookies)
                if t.get("evidence"):
                    findings.append({
                        "url": url, "parameter": param, "injection": "time",
                        "details": t
                    })
        except Exception as e:
            logger.debug("scan_url error: %s", e)
        return findings

    def scan_form(self, url: str, form_data: dict, headers: dict = None, cookies: dict = None) -> list:
        findings = []
        data = self._flatten_form(form_data)
        try:
            for param in data.keys():
                b = self.detector.detect_boolean_form(url, param, data, headers=headers, cookies=cookies)
                if b.get("evidence"):
                    findings.append({
                        "url": url, "parameter": param, "injection": "boolean-form",
                        "details": b
                    })
                t = self.detector.detect_time_form(url, param, data, headers=headers, cookies=cookies)
                if t.get("evidence"):
                    findings.append({
                        "url": url, "parameter": param, "injection": "time-form",
                        "details": t
                    })
        except Exception as e:
            logger.debug("scan_form error: %s", e)
        return findings

    def scan_cookies(self, url: str, cookies: dict, headers: dict = None) -> list:
        findings = []
        if not cookies:
            return findings
        try:
            for cname in cookies.keys():
                b = self.detector.detect_boolean_cookie(url, cname, cookies, headers=headers)
                if b.get("evidence"):
                    findings.append({
                        "url": url, "parameter": cname, "injection": "boolean-cookie",
                        "details": b
                    })
                t = self.detector.detect_time_cookie(url, cname, cookies, headers=headers)
                if t.get("evidence"):
                    findings.append({
                        "url": url, "parameter": cname, "injection": "time-cookie",
                        "details": t
                    })
        except Exception as e:
            logger.debug("scan_cookies error: %s", e)
        return findings

    def scan_raw_request(self, raw: dict) -> list:
        findings = []
        if not raw:
            return findings
        method = raw.get("method", "").upper()
        url = raw.get("url")
        headers = raw.get("headers") or {}
        cookies = raw.get("cookies") or {}
        body = raw.get("body") or ""
        content_type = (raw.get("content_type") or "").lower()

        if not url:
            return findings

        # Always scan query parameters if present
        findings.extend(self.scan_url(url, headers=headers, cookies=cookies))
        findings.extend(self.scan_cookies(url, cookies, headers=headers))

        # Form scanning for urlencoded bodies
        if method == "POST" and "application/x-www-form-urlencoded" in content_type:
            form_dict = parse_qs(body, keep_blank_values=True)
            findings.extend(self.scan_form(url, form_dict, headers=headers, cookies=cookies))
        return findings
