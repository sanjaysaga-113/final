"""
Blind SSRF Module Interface

Orchestrates SSRF detection across multiple parameters.
Follows the same pattern as blind_sqli/blind_xss modules.
"""

import sys
import os
from urllib.parse import parse_qs, urlparse
from typing import List, Dict, Optional
import time

# Import from core
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from bsqli.core.logger import get_logger

# Import SSRF detector
from .detector import BlindSSRFDetector

# Import correlation module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
try:
    from oob.correlation import CallbackCorrelator
except ImportError:
    CallbackCorrelator = None
    print("[WARNING] CallbackCorrelator not available - callbacks won't be verified")

logger = get_logger("bssrf_module")


class BlindSSRFModule:
    """
    Blind SSRF scanning module.
    
    Coordinates payload injection across parameters.
    Confirms findings via OOB callbacks (DNS/HTTP).
    """
    
    def __init__(self, listener_url: str, timeout: int = 10, wait_time: int = 5, 
                 use_advanced: bool = False, verify_callbacks: bool = True,
                 callback_api_url: Optional[str] = None):
        """
        Args:
            listener_url: OOB callback server URL (e.g., http://attacker.com)
            timeout: HTTP request timeout
            wait_time: Seconds to wait after injection for callback
            use_advanced: Enable advanced payloads (internal services, gopher, file, encoding)
            verify_callbacks: Enable automatic callback verification
            callback_api_url: Callback server API URL (if different from listener_url)
        """
        self.detector = BlindSSRFDetector(listener_url, timeout, wait_time, use_advanced)
        self.listener_url = listener_url
        self.wait_time = wait_time
        self.use_advanced = use_advanced
        self.verify_callbacks = verify_callbacks
        
        # Initialize correlator with SQLite backend (production-grade)
        if verify_callbacks and CallbackCorrelator:
            # Use SQLite-backed correlation (persistent, replay protection)
            self.correlator = CallbackCorrelator(callback_source="sqlite", api_url=callback_api_url)
            logger.info("Using SQLite-backed callback verification (production-grade)")
        else:
            self.correlator = None
            if verify_callbacks:
                logger.warning("Callback verification disabled - CallbackCorrelator not available")
    
    def scan_url(self, url: str) -> List[Dict]:
        """
        Scan a single URL for Blind SSRF vulnerabilities.
        
        Tests all query parameters that look like URL/link parameters.
        Returns injection metadata (findings confirmed by callbacks later).
        """
        injections = []
        
        try:
            # Extract query parameters
            qs = parse_qs(urlparse(url).query)
            logger.info(f"[SSRF] URL: {url} | params: {list(qs.keys())}")
            
            # Test each parameter
            for param in qs.keys():
                logger.info(f"[SSRF] Scanning parameter: {param}")
                param_injections = self.detector.detect_query_param(url, param)
                injections.extend(param_injections)
        
        except Exception as e:
            logger.debug(f"[SSRF] scan_url error: {e}")
        
        return injections
    
    def scan_post_form(self, url: str, form_data: Dict[str, str]) -> List[Dict]:
        """
        Scan POST form parameters for Blind SSRF.
        
        Args:
            url: Target URL
            form_data: POST parameter dictionary
        
        Returns:
            List of injection metadata
        """
        injections = []
        
        try:
            logger.info(f"[SSRF] POST URL: {url} | params: {list(form_data.keys())}")
            
            for param in form_data.keys():
                logger.info(f"[SSRF] Scanning POST param: {param}")
                param_injections = self.detector.detect_post_param(url, param, form_data)
                injections.extend(param_injections)
        
        except Exception as e:
            logger.debug(f"[SSRF] scan_post_form error: {e}")
        
        return injections
    
    def get_all_injections(self) -> Dict:
        """
        Return all injections made so far.
        Useful for manual correlation with callbacks.
        """
        return self.detector.get_injections()
    
    def wait_for_callbacks(self, timeout: int = None):
        """
        Wait for OOB callbacks to arrive.
        
        In production, this would query the callback server.
        For now, just sleep.
        """
        wait = timeout or self.wait_time
        logger.info(f"[SSRF] Waiting {wait}s for OOB callbacks...")
        time.sleep(wait)
        logger.info(f"[SSRF] Callback wait complete")
    
    def verify_findings(self, injections: List[Dict]) -> Dict:
        """
        Verify injections by correlating with received callbacks.
        
        Args:
            injections: List of injection metadata from scanning
            
        Returns:
            Dict with 'confirmed' and 'unconfirmed' findings
        """
        if not self.verify_callbacks or not self.correlator:
            logger.warning("Callback verification not enabled - marking all as unconfirmed")
            return {
                'total_injections': len(injections),
                'confirmed': [],
                'unconfirmed': injections,
                'confirmed_count': 0,
                'unconfirmed_count': len(injections)
            }
        
        logger.info(f"Verifying {len(injections)} injections with callback correlation")
        
        # Check callback server health
        if hasattr(self.correlator, 'check_callback_server_health'):
            healthy = self.correlator.check_callback_server_health()
            if not healthy:
                logger.warning("Callback server may not be reachable")
        
        # Correlate injections with callbacks
        results = self.correlator.correlate_injections(injections, self.wait_time)
        
        logger.info(f"Verification complete: {results['confirmed_count']} confirmed SSRF vulnerabilities")
        
        return results
    
    def scan_and_verify(self, url: str) -> Dict:
        """
        Scan URL and automatically verify findings.
        
        Args:
            url: Target URL to scan
            
        Returns:
            Dict with confirmed and unconfirmed findings
        """
        # Perform scanning
        injections = self.scan_url(url)
        
        if not injections:
            logger.info("No SSRF-vulnerable parameters found")
            return {
                'total_injections': 0,
                'confirmed': [],
                'unconfirmed': [],
                'confirmed_count': 0,
                'unconfirmed_count': 0
            }
        
        logger.info(f"Made {len(injections)} SSRF injections, now verifying...")
        
        # Verify with callbacks
        results = self.verify_findings(injections)
        
        return results
    
    def check_callback_received(self, uuid: str) -> bool:
        """
        Check if a callback was received for a given UUID.
        
        Args:
            uuid: UUID of the injection to check
            
        Returns:
            True if callback was received, False otherwise
        """
        if not self.correlator:
            # Try to check directly via callback server API
            try:
                import requests
                api_url = f"{self.callback_api_url}/api/check/{uuid}"
                response = requests.get(api_url, timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    return data.get('received', False) or len(data.get('callbacks', [])) > 0
            except Exception as e:
                logger.debug(f"Failed to check callback for {uuid}: {e}")
                return False
        else:
            # Use correlator's check_uuid method
            callback_data = self.correlator.check_uuid(uuid)
            return callback_data is not None
        
        return False
