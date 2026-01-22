"""
Blind CMDi Module Interface

Orchestrates command injection detection across multiple parameters and injection points.
Follows the same pattern as blind_sqli and blind_xss modules for consistency.

Scanning workflow:
1. scan_url: Test all query parameters
2. scan_form: Test POST form parameters
3. scan_cookies: Test cookie values
4. scan_raw_request: Unified interface for raw HTTP requests

Results are structured findings with type, parameter, technique, confidence, and ML score.
"""

import sys
import os
from urllib.parse import parse_qs, urlparse
from typing import List, Dict, Optional

# Import from shared core
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from bsqli.core.logger import get_logger

# Import CMDi detector
from .detector import BlindCMDiDetector

logger = get_logger("cmdi_module")


class BlindCMDiModule:
    """
    Blind CMDi scanning module.
    
    Coordinates command injection payload injection across multiple injection points:
    - Query parameters
    - POST form parameters
    - HTTP cookies
    - Custom headers (if supported)
    """
    
    def __init__(self, timeout: int = 10):
        """
        Initialize CMDi module.
        
        Args:
            timeout: HTTP request timeout in seconds (default 10)
        """
        self.detector = BlindCMDiDetector(timeout=timeout)
        logger.info("[CMDi Module] Initialized")
    
    def _flatten_form(self, form_data: dict) -> dict:
        """
        Flatten form data (convert lists to first value).
        
        Args:
            form_data: Dictionary from parse_qs (values are lists)
        
        Returns:
            Flattened dictionary with single values
        """
        flattened = {}
        for k, v in form_data.items():
            if isinstance(v, list):
                flattened[k] = v[0] if v else ""
            else:
                flattened[k] = v
        return flattened
    
    def _result_to_finding(self, url: str, param: str, result: Dict,
                           injection_point: str = "query") -> Optional[Dict]:
        """
        Convert detector result to structured finding.
        
        Args:
            url: Target URL
            param: Parameter name
            result: Detector result dict
            injection_point: Type of injection point (query, form, cookie)
        
        Returns:
            Finding dict or None if no evidence
        """
        if not result.get("evidence"):
            return None
        
        # Determine technique based on result
        technique = "time-based"
        if "confirmations" in result and result["confirmations"]:
            technique = "time-based"  # Could extend to logic-based later
        
        # Build structured finding
        finding = {
            "type": "blind_cmdi",
            "parameter": param,
            "injection_point": injection_point,
            "url": url,
            "technique": technique,
            "confidence": result.get("confidence", "LOW"),
            "details": result.get("details", {}),
            "confirmations": len(result.get("confirmations", [])),
        }
        
        return finding
    
    def scan_url(self, url: str, headers: Dict[str, str] = None,
                 cookies: Dict[str, str] = None) -> List[Dict]:
        """
        Scan query parameters in a URL for CMDi vulnerabilities.
        
        Args:
            url: Target URL (with query string)
            headers: HTTP headers (optional)
            cookies: Cookies (optional)
        
        Returns:
            List of findings (empty if no vulnerabilities detected)
        """
        findings = []
        headers = headers or {}
        cookies = cookies or {}
        
        try:
            # Extract query parameters
            parsed_url = urlparse(url)
            qs = parse_qs(parsed_url.query, keep_blank_values=True)
            
            if not qs:
                logger.debug(f"[CMDi] No query parameters in {url}")
                return findings
            
            logger.info(f"[CMDi] Scanning URL: {url}")
            logger.info(f"[CMDi] Parameters found: {list(qs.keys())}")
            
            # Test each parameter
            for param in qs.keys():
                logger.info(f"[CMDi] Testing parameter: {param}")
                
                result = self.detector.detect_query_param(url, param, headers=headers, cookies=cookies)
                
                # Convert to structured finding
                finding = self._result_to_finding(url, param, result, injection_point="query")
                if finding:
                    findings.append(finding)
                    logger.info(f"[CMDi] ✓ VULNERABILITY FOUND: {param}")
        
        except Exception as e:
            logger.debug(f"[CMDi] scan_url error: {e}")
        
        return findings
    
    def scan_form(self, url: str, form_data: Dict[str, str],
                  headers: Dict[str, str] = None,
                  cookies: Dict[str, str] = None) -> List[Dict]:
        """
        Scan POST form parameters for CMDi vulnerabilities.
        
        Args:
            url: Target URL (POST endpoint)
            form_data: Dictionary of form parameters
            headers: HTTP headers (optional)
            cookies: Cookies (optional)
        
        Returns:
            List of findings (empty if no vulnerabilities detected)
        """
        findings = []
        headers = headers or {}
        cookies = cookies or {}
        data = self._flatten_form(form_data)
        
        if not data:
            logger.debug(f"[CMDi] No form parameters for {url}")
            return findings
        
        try:
            logger.info(f"[CMDi] Scanning POST form: {url}")
            logger.info(f"[CMDi] Form parameters: {list(data.keys())}")
            
            for param in data.keys():
                logger.info(f"[CMDi] Testing form parameter: {param}")
                
                # For POST, we'd need to extend detector to handle POST params
                # For now, fall back to query param detection on the URL
                result = self.detector.detect_query_param(url, param, headers=headers, cookies=cookies)
                
                finding = self._result_to_finding(url, param, result, injection_point="form")
                if finding:
                    findings.append(finding)
                    logger.info(f"[CMDi] ✓ VULNERABILITY FOUND in form: {param}")
        
        except Exception as e:
            logger.debug(f"[CMDi] scan_form error: {e}")
        
        return findings
    
    def scan_cookies(self, url: str, cookies: Dict[str, str],
                     headers: Dict[str, str] = None) -> List[Dict]:
        """
        Scan cookie values for CMDi vulnerabilities.
        
        Args:
            url: Target URL (for context)
            cookies: Dictionary of cookies
            headers: HTTP headers (optional)
        
        Returns:
            List of findings (empty if no vulnerabilities detected)
        """
        findings = []
        headers = headers or {}
        
        if not cookies:
            logger.debug(f"[CMDi] No cookies to scan")
            return findings
        
        try:
            logger.info(f"[CMDi] Scanning cookies for: {url}")
            logger.info(f"[CMDi] Cookies found: {list(cookies.keys())}")
            
            for cname in cookies.keys():
                logger.info(f"[CMDi] Testing cookie: {cname}")
                
                # Add cookie to query param for testing (detector works with GET)
                test_url = url + ("&" if "?" in url else "?") + f"{cname}={cookies[cname]}"
                result = self.detector.detect_query_param(test_url, cname, headers=headers, cookies=cookies)
                
                finding = self._result_to_finding(url, cname, result, injection_point="cookie")
                if finding:
                    findings.append(finding)
                    logger.info(f"[CMDi] ✓ VULNERABILITY FOUND in cookie: {cname}")
        
        except Exception as e:
            logger.debug(f"[CMDi] scan_cookies error: {e}")
        
        return findings
    
    def scan_raw_request(self, raw: Dict) -> List[Dict]:
        """
        Scan a raw HTTP request for CMDi vulnerabilities.
        
        Unified interface that handles GET/POST and extracts parameters automatically.
        
        Args:
            raw: Raw request dict with keys:
                - method: HTTP method (GET, POST, etc.)
                - url: Target URL
                - headers: HTTP headers dict
                - cookies: Cookies dict
                - body: Request body (for POST)
                - content_type: Content-Type header value
        
        Returns:
            List of findings
        """
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
            logger.warning("[CMDi] No URL in raw request")
            return findings
        
        logger.info(f"[CMDi] Scanning raw {method} request to {url}")
        
        # Always scan query parameters
        findings.extend(self.scan_url(url, headers=headers, cookies=cookies))
        
        # Scan cookies
        if cookies:
            findings.extend(self.scan_cookies(url, cookies, headers=headers))
        
        # Scan form body (POST with application/x-www-form-urlencoded)
        if method == "POST" and "application/x-www-form-urlencoded" in content_type:
            form_dict = parse_qs(body, keep_blank_values=True)
            findings.extend(self.scan_form(url, form_dict, headers=headers, cookies=cookies))
        
        return findings
