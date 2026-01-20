"""
Blind SSRF Detector

Injects SSRF payloads into parameters and tracks OOB callbacks.
Confirms SSRF only when callback is received.
"""

import sys
import os
from typing import List, Dict, Optional
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
import time
import requests
from datetime import datetime

# Import SSRF payloads
from .payloads import SSRFPayloadEngine

# Import logger from core
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
try:
    from bsqli.core.logger import get_logger
except:
    import logging
    logging.basicConfig(level=logging.DEBUG)
    get_logger = logging.getLogger

logger = get_logger("bssrf_detector")


class BlindSSRFDetector:
    """
    Detects blind SSRF by injecting payloads and waiting for OOB callbacks.
    """
    
    def __init__(self, listener_url: str, timeout: int = 10, wait_time: int = 5, use_advanced: bool = False):
        """
        Args:
            listener_url: OOB callback server base URL
            timeout: HTTP request timeout
            wait_time: Seconds to wait after injection before checking callbacks
            use_advanced: Enable advanced payloads (internal services, gopher, file, encoding)
        """
        self.listener_url = listener_url
        self.timeout = timeout
        self.wait_time = wait_time
        self.use_advanced = use_advanced
        self.payload_engine = SSRFPayloadEngine(listener_url)
        self.injections_made = {}  # Track injections: uuid -> metadata
    
    def detect_query_param(self, url: str, param_name: str) -> List[Dict]:
        """
        Test a query parameter for SSRF vulnerability.
        
        Returns:
            List of injection metadata (findings confirmed by callbacks later)
        """
        findings = []
        
        # Skip non-SSRF parameters
        if not self.payload_engine.is_ssrf_parameter(param_name):
            logger.debug(f"[SSRF] Skipping non-SSRF param: {param_name}")
            return findings
        
        logger.info(f"[SSRF] Testing query param: {param_name} on {url}")
        
        # Generate callback ID
        callback_id = self.payload_engine.generate_callback_id()
        
        # Get all payload types
        payloads = self.payload_engine.get_all_payloads(callback_id)
        
        # Add advanced payloads if enabled
        if self.use_advanced:
            advanced = self.payload_engine.get_advanced_payloads(callback_id)
            for category, payload_list in advanced.items():
                # Add first few payloads from each category
                for i, payload in enumerate(payload_list[:3]):  # Limit to 3 per category
                    payloads[f"{category}_{i}"] = payload
            
            # Add encoded variations
            encoded = self.payload_engine.get_encoded_variations(callback_id)
            for enc_type, enc_list in encoded.items():
                for i, payload in enumerate(enc_list[:2]):  # Limit to 2 per type
                    payloads[f"{enc_type}_{i}"] = payload
        
        # Inject each payload type
        for payload_type, payload_url in payloads.items():
            try:
                # Parse URL and inject payload into parameter
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param_name] = [payload_url]
                
                # Rebuild URL
                new_query = urlencode(qs, doseq=True)
                injected_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                logger.debug(f"[SSRF] Injecting {payload_type}: {injected_url[:100]}")
                
                # Make the request
                response = requests.get(injected_url, timeout=self.timeout)
                
                # Record injection
                injection_metadata = {
                    "uuid": callback_id,
                    "url": url,
                    "parameter": param_name,
                    "payload_type": payload_type,
                    "payload": payload_url,
                    "timestamp": datetime.utcnow().isoformat(),
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "confirmed": False  # Will be set by correlation
                }
                
                self.injections_made[callback_id] = injection_metadata
                findings.append(injection_metadata)
                
                logger.info(f"[SSRF] Injected {payload_type} | Status: {response.status_code}")
                
            except requests.exceptions.Timeout:
                logger.debug(f"[SSRF] Timeout on {payload_type}")
            except Exception as e:
                logger.debug(f"[SSRF] Error on {payload_type}: {e}")
        
        return findings
    
    def detect_post_param(self, url: str, param_name: str, form_data: Dict[str, str]) -> List[Dict]:
        """
        Test a POST parameter for SSRF vulnerability.
        """
        findings = []
        
        if not self.payload_engine.is_ssrf_parameter(param_name):
            return findings
        
        logger.info(f"[SSRF] Testing POST param: {param_name} on {url}")
        
        callback_id = self.payload_engine.generate_callback_id()
        payloads = self.payload_engine.get_all_payloads(callback_id)
        
        # Add advanced payloads if enabled
        if self.use_advanced:
            advanced = self.payload_engine.get_advanced_payloads(callback_id)
            for category, payload_list in advanced.items():
                for i, payload in enumerate(payload_list[:3]):
                    payloads[f"{category}_{i}"] = payload
            
            encoded = self.payload_engine.get_encoded_variations(callback_id)
            for enc_type, enc_list in encoded.items():
                for i, payload in enumerate(enc_list[:2]):
                    payloads[f"{enc_type}_{i}"] = payload
        
        for payload_type, payload_url in payloads.items():
            try:
                # Inject into form data
                test_data = form_data.copy()
                test_data[param_name] = payload_url
                
                logger.debug(f"[SSRF] POST injecting {payload_type}")
                
                response = requests.post(url, data=test_data, timeout=self.timeout)
                
                injection_metadata = {
                    "uuid": callback_id,
                    "url": url,
                    "parameter": param_name,
                    "method": "POST",
                    "payload_type": payload_type,
                    "payload": payload_url,
                    "timestamp": datetime.utcnow().isoformat(),
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "confirmed": False
                }
                
                self.injections_made[callback_id] = injection_metadata
                findings.append(injection_metadata)
                
            except Exception as e:
                logger.debug(f"[SSRF] POST error: {e}")
        
        return findings
    
    def get_injections(self) -> Dict:
        """Return all injections made."""
        return self.injections_made.copy()
