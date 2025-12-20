"""
Blind XSS Detector

Black-box methodology: Inject payloads and wait for OOB callbacks.
NO response body inspection - detection relies ONLY on callback correlation.

Reuses existing HttpClient from bsqli.core for consistency.
"""
import urllib.parse
from typing import Dict, Any, List, Optional
import time
import sys
import os
from colorama import Fore, Style

# Import from existing BSQLI core (reuse infrastructure)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from bsqli.core.http_client import HttpClient
from bsqli.core.logger import get_logger

# Import BXSS-specific modules
from bxss.modules.blind_xss import payloads as payload_module
from bxss.oob.correlation import record_injection
import uuid as uuid_lib


logger = get_logger("bxss_detector")


class BlindXSSDetector:
    """
    Blind XSS detector using OOB callback methodology.
    
    Detection workflow:
    1. Generate UUID-tagged payloads
    2. Inject into parameters/headers
    3. Record injection metadata
    4. Wait for OOB callback (handled by callback_server)
    5. Correlation happens externally via correlation.py
    """
    
    def __init__(self, listener_url: str, timeout: int = 10, wait_time: int = 5):
        """
        Args:
            listener_url: Callback server URL (e.g., http://attacker.com:5000)
            timeout: HTTP request timeout
            wait_time: Seconds to wait after injection (for immediate callbacks)
        """
        self.client = HttpClient(timeout=timeout)
        self.listener_url = listener_url
        self.wait_time = wait_time
    
    def _param_replace(self, url: str, param: str, new_value: str) -> str:
        """Replace parameter value in URL."""
        p = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        qs[param] = [new_value]
        new_q = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))
    
    def detect_query_param(self, url: str, param: str) -> List[Dict[str, str]]:
        """
        Inject XSS payloads into a query parameter.
        
        Returns list of injection metadata (for later correlation).
        """
        logger.info(f"{Fore.CYAN}[QUERY] {param}{Style.RESET_ALL} on {url}")
        
        # Get raw payload templates (without substitution)
        from bxss.modules.blind_xss import payloads as payload_templates
        all_templates = payload_templates.get_all_payloads()
        template_list = all_templates['script'] + all_templates['event'] + all_templates['bypass']
        
        injections = []
        
        for template in template_list:
            payload_uuid = str(uuid_lib.uuid4())
            
            try:
                # Substitute placeholders with this payload's UUID
                payload = payload_templates.substitute_placeholders(template, self.listener_url, payload_uuid)
                
                # Inject payload into parameter
                test_url = self._param_replace(url, param, payload)
                
                logger.debug(
                    "  [BXSS] Injecting | uuid=%s | context=query_param\n"
                    "           original_url=%s\n"
                    "           test_url=%s",
                    payload_uuid,
                    url,
                    test_url,
                )
                
                # Record injection BEFORE sending request
                record_injection(payload_uuid, url, param, payload)
                
                # Send request (no need to inspect response)
                resp = self.client.get(test_url)
                status = getattr(resp, "status_code", None)
                clen = len(getattr(resp, "text", "")) if resp is not None else 0
                logger.debug(
                    "  [BXSS] Request sent | status=%s | body_len=%s",
                    status,
                    clen,
                )
                
                injections.append({
                    "uuid": payload_uuid,
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "context": "query_param",
                    "request_url": test_url,
                    "status_code": status,
                    "response_length": clen,
                })
                
            except Exception as e:
                logger.debug(f"  [BXSS] Injection failed: {e}")
                continue
        
        # Wait for immediate callbacks
        if injections:
            logger.debug(f"  [BXSS] Waiting {self.wait_time}s for callbacks...")
            time.sleep(self.wait_time)
        
        return injections
    
    def detect_post_param(self, url: str, param: str, base_data: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Inject XSS payloads into a POST parameter.
        
        Args:
            url: Target URL
            param: Parameter to inject
            base_data: Base form data (other parameters)
        """
        logger.info(f"[BXSS] Testing POST parameter: {param} on {url}")
        
        # Get raw payload templates
        from bxss.modules.blind_xss import payloads as payload_templates
        all_templates = payload_templates.get_all_payloads()
        template_list = all_templates['script'] + all_templates['event'] + all_templates['bypass'] + all_templates['exfil']
        
        injections = []
        
        for template in template_list:
            payload_uuid = str(uuid_lib.uuid4())
            
            try:
                # Substitute placeholders with this payload's UUID
                payload = payload_templates.substitute_placeholders(template, self.listener_url, payload_uuid)
                
                # Build POST data with injected payload
                post_data = base_data.copy()
                post_data[param] = payload
                
                logger.debug(
                    "  [BXSS] Injecting | uuid=%s | context=post_param\n"
                    "           url=%s\n"
                    "           param=%s",
                    payload_uuid,
                    url,
                    param,
                )
                
                # Record injection
                record_injection(payload_uuid, url, f"POST:{param}", payload)
                
                # Send POST request
                resp = self.client.session.post(url, data=post_data, timeout=self.client.timeout)
                status = getattr(resp, "status_code", None)
                clen = len(getattr(resp, "text", "")) if resp is not None else 0
                logger.debug("  [BXSS] POST sent | status=%s | body_len=%s", status, clen)
                
                injections.append({
                    "uuid": payload_uuid,
                    "url": url,
                    "parameter": f"POST:{param}",
                    "payload": payload,
                    "context": "post_param",
                    "status_code": status,
                    "response_length": clen,
                })
                
            except Exception as e:
                logger.debug(f"  [BXSS] POST injection failed: {e}")
                continue
        
        if injections:
            time.sleep(self.wait_time)
        
        return injections
    
    def detect_header(self, url: str, header_name: str) -> List[Dict[str, str]]:
        """
        Inject XSS payloads into HTTP header.
        
        Common targets: User-Agent, Referer, X-Forwarded-For, etc.
        """
        logger.info(f"[BXSS] Testing header: {header_name} on {url}")
        
        # Get raw payload templates
        from bxss.modules.blind_xss import payloads as payload_templates
        all_templates = payload_templates.get_all_payloads()
        template_list = all_templates['header'] + all_templates['script']
        
        injections = []
        
        for template in template_list:
            payload_uuid = str(uuid_lib.uuid4())
            
            try:
                # Substitute placeholders with this payload's UUID
                payload = payload_templates.substitute_placeholders(template, self.listener_url, payload_uuid)
                
                headers = {header_name: payload}
                
                logger.debug(
                    "  [BXSS] Injecting | uuid=%s | context=header | header=%s\n"
                    "           url=%s",
                    payload_uuid,
                    header_name,
                    url,
                )
                
                # Record injection
                record_injection(payload_uuid, url, f"HEADER:{header_name}", payload)
                
                # Send request with custom header
                resp = self.client.get(url, headers=headers)
                status = getattr(resp, "status_code", None)
                clen = len(getattr(resp, "text", "")) if resp is not None else 0
                logger.debug("  [BXSS] Header request sent | status=%s | body_len=%s", status, clen)
                
                injections.append({
                    "uuid": payload_uuid,
                    "url": url,
                    "parameter": f"HEADER:{header_name}",
                    "payload": payload,
                    "context": "header",
                    "headers_used": {header_name: "<payload>"},
                    "status_code": status,
                    "response_length": clen,
                })
                
            except Exception as e:
                logger.debug(f"  [BXSS] Header injection failed: {e}")
                continue
        
        if injections:
            time.sleep(self.wait_time)
        
        return injections
    
    def detect_json_param(self, url: str, param_path: str, base_json: Dict) -> List[Dict[str, str]]:
        """
        Inject XSS payloads into JSON request body.
        
        Args:
            url: Target URL
            param_path: JSON parameter path (e.g., 'user.name')
            base_json: Base JSON structure
        """
        logger.info(f"[BXSS] Testing JSON parameter: {param_path} on {url}")
        
        # Get raw payload templates
        from bxss.modules.blind_xss import payloads as payload_templates
        all_templates = payload_templates.get_all_payloads()
        template_list = all_templates['json'] + all_templates['script']
        
        injections = []
        
        for template in template_list:
            payload_uuid = str(uuid_lib.uuid4())
            
            try:
                # Substitute placeholders with this payload's UUID
                payload = payload_templates.substitute_placeholders(template, self.listener_url, payload_uuid)
                
                # Clone base JSON and inject payload
                import copy
                json_data = copy.deepcopy(base_json)
                
                # Simple nested key support (e.g., 'user.name' -> json_data['user']['name'])
                keys = param_path.split('.')
                target = json_data
                for key in keys[:-1]:
                    target = target.setdefault(key, {})
                target[keys[-1]] = payload
                
                logger.debug(
                    "  [BXSS] Injecting | uuid=%s | context=json_body | path=%s\n"
                    "           url=%s",
                    payload_uuid,
                    param_path,
                    url,
                )
                
                # Record injection
                record_injection(payload_uuid, url, f"JSON:{param_path}", payload)
                
                # Send JSON POST
                resp = self.client.session.post(url, json=json_data, timeout=self.client.timeout)
                status = getattr(resp, "status_code", None)
                clen = len(getattr(resp, "text", "")) if resp is not None else 0
                logger.debug("  [BXSS] JSON POST sent | status=%s | body_len=%s", status, clen)
                
                injections.append({
                    "uuid": payload_uuid,
                    "url": url,
                    "parameter": f"JSON:{param_path}",
                    "payload": payload,
                    "context": "json_body",
                    "status_code": status,
                    "response_length": clen,
                })
                
            except Exception as e:
                logger.debug(f"  [BXSS] JSON injection failed: {e}")
                continue
        
        if injections:
            time.sleep(self.wait_time)
        
        return injections
