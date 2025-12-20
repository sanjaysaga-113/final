"""
Blind XSS Module Interface

Follows the same pattern as blind_sqli/sqli_module.py for consistency.
Orchestrates detection across multiple parameters and injection points.
"""
import sys
import os
from urllib.parse import parse_qs, urlparse
from typing import List, Dict

# Import from existing BSQLI core
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from bsqli.core.logger import get_logger

# Import BXSS detector
from .detector import BlindXSSDetector

logger = get_logger("bxss_module")


class BlindXSSModule:
    """
    Blind XSS scanning module.
    
    Coordinates payload injection across multiple injection points:
    - Query parameters
    - POST parameters
    - HTTP headers
    - JSON body
    """
    
    def __init__(self, listener_url: str, timeout: int = 10, wait_time: int = 5):
        """
        Args:
            listener_url: OOB callback server URL
            timeout: HTTP request timeout
            wait_time: Seconds to wait after injection
        """
        self.detector = BlindXSSDetector(listener_url, timeout, wait_time)
        self.listener_url = listener_url
    
    def scan_url(self, url: str) -> List[Dict]:
        """
        Scan a single URL for Blind XSS vulnerabilities.
        
        Tests all query parameters and common headers.
        Returns injection metadata (actual findings determined by correlation).
        """
        injections = []
        
        try:
            # Test query parameters
            qs = parse_qs(urlparse(url).query)
            logger.info(f"[BXSS] URL: {url} | params: {list(qs.keys())}")
            for param in qs.keys():
                logger.info(f"[BXSS] Scanning parameter: {param}")
                param_injections = self.detector.detect_query_param(url, param)
                injections.extend(param_injections)
            
            # Test common headers (if no parameters found)
            if not qs:
                logger.info(f"[BXSS] No parameters found, testing headers")
                for header in ["User-Agent", "Referer", "X-Forwarded-For"]:
                    header_injections = self.detector.detect_header(url, header)
                    injections.extend(header_injections)
        
        except Exception as e:
            logger.debug(f"scan_url error: {e}")
        
        return injections
    
    def scan_post_form(self, url: str, form_data: Dict[str, str]) -> List[Dict]:
        """
        Scan POST form parameters for Blind XSS.
        
        Args:
            url: Target URL
            form_data: Dictionary of form parameters
        """
        injections = []
        
        try:
            for param in form_data.keys():
                logger.info(f"[BXSS] Scanning POST parameter: {param}")
                param_injections = self.detector.detect_post_param(url, param, form_data)
                injections.extend(param_injections)
        
        except Exception as e:
            logger.debug(f"scan_post_form error: {e}")
        
        return injections
    
    def scan_json_endpoint(self, url: str, json_template: Dict) -> List[Dict]:
        """
        Scan JSON API endpoint for Blind XSS.
        
        Args:
            url: Target API URL
            json_template: JSON structure to test
        """
        injections = []
        
        try:
            # Flatten JSON to find testable parameters
            params = self._flatten_json(json_template)
            
            for param_path in params:
                logger.info(f"[BXSS] Scanning JSON parameter: {param_path}")
                param_injections = self.detector.detect_json_param(url, param_path, json_template)
                injections.extend(param_injections)
        
        except Exception as e:
            logger.debug(f"scan_json_endpoint error: {e}")
        
        return injections
    
    def _flatten_json(self, obj: Dict, prefix: str = "") -> List[str]:
        """
        Flatten nested JSON to get parameter paths.
        
        Example: {"user": {"name": "test"}} -> ["user.name"]
        """
        paths = []
        
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                paths.extend(self._flatten_json(value, path))
            else:
                paths.append(path)
        
        return paths
