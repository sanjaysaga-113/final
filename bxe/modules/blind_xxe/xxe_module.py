"""
Blind XXE Module - High-Level Scanner Interface

Provides a unified API for XXE detection across:
- XML-based endpoints
- SOAP web services
- JSON with embedded XML
- File upload endpoints accepting XML
- RESTful APIs with XML request bodies

Integrates seamlessly with the scanner:
- Uses shared HttpClient
- Returns structured findings
- Supports async scanning
- Includes error handling and timeouts
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from bsqli.core.http_client import HttpClient
from bsqli.core.logger import get_logger
from .detector import BlindXXEDetector
from . import payloads


logger = get_logger(__name__)


class BlindXXEModule:
    """
    High-level XXE scanner interface.
    
    Provides methods to scan:
    - XML-typed request bodies
    - JSON parameters containing XML
    - SOAP endpoints
    - File uploads
    
    Example usage:
        module = BlindXXEModule(timeout=15)
        findings = module.scan_xml_body(
            url="http://target.com/api/parse",
            body='<?xml version="1.0"?><root><data>test</data></root>',
            content_type="application/xml"
        )
        if findings.get("is_vulnerable"):
            print(f"XXE found: {findings['technique']}")
    """
    
    def __init__(self, timeout: int = 15, oast_server=None):
        """
        Initialize XXE scanner.
        
        Args:
            timeout: HTTP request timeout in seconds
            oast_server: Optional OAST server for callback correlation
                        Should implement get_http_endpoint() and get_dns_domain()
        """
        # Use shared HttpClient without custom args to match existing signature
        self.http_client = HttpClient(timeout=timeout)
        self.detector = BlindXXEDetector(self.http_client, oast_server)
        self.timeout = timeout
        self.oast_server = oast_server
        self.findings = []
    
    def scan_xml_body(self, url: str, body: str = None, method: str = "POST",
                     content_type: str = "application/xml",
                     headers: Dict = None) -> Dict[str, Any]:
        """
        Scan XML-typed request body for XXE vulnerabilities.
        
        Targets endpoints that accept XML:
        - Application/xml
        - Application/soap+xml
        - Text/xml
        
        Args:
            url: Target endpoint URL
            body: Original XML body (optional, used for baseline)
            method: HTTP method (POST, PUT, PATCH)
            content_type: Content-Type header value
            headers: Additional HTTP headers
        
        Returns:
            Finding dict with:
            - is_vulnerable: Boolean
            - technique: Detection method used
            - confidence: High/Medium/Low
            - findings: Detailed findings list
            - ml_score: Anomaly score 0.0-1.0
        """
        logger.info(f"Scanning {url} for blind XXE (XML body)")
        
        try:
            # Build headers
            req_headers = headers or {}
            req_headers["Content-Type"] = content_type
            req_headers["User-Agent"] = self.http_client.get_random_user_agent()
            
            # Perform detection
            result = self.detector.detect_xml_parameter(
                url=url,
                parameter="xml_body",
                value=body or "<xml/>",
                method=method,
                headers=req_headers
            )
            
            # Format as finding
            finding = self._result_to_finding(
                result=result,
                endpoint=url,
                parameter="xml_body",
                method=method
            )
            
            self.findings.append(finding)
            return finding
            
        except Exception as e:
            logger.error(f"XXE scan error: {e}", exc_info=True)
            return {
                "is_vulnerable": False,
                "error": str(e),
                "endpoint": url,
            }
    
    def scan_json_parameter(self, url: str, parameter: str, value: str = None,
                           method: str = "POST", headers: Dict = None) -> Dict[str, Any]:
        """
        Scan JSON parameter for embedded XML/XXE.
        
        Targets JSON APIs where XML can be embedded:
        - {"data": "<xml>...</xml>"}
        - {"config": "<?xml...?>"}
        - {"document": "base64_xml"}
        
        Args:
            url: Target endpoint URL
            parameter: JSON parameter name
            value: Original parameter value
            method: HTTP method
            headers: Additional HTTP headers
        
        Returns:
            Finding dict with vulnerability info
        """
        logger.info(f"Scanning {url} parameter '{parameter}' for embedded XXE")
        
        try:
            req_headers = headers or {}
            req_headers["Content-Type"] = "application/json"
            
            result = self.detector.detect_json_parameter(
                url=url,
                parameter=parameter,
                value=value or "<xml/>",
                headers=req_headers
            )
            
            finding = self._result_to_finding(
                result=result,
                endpoint=url,
                parameter=parameter,
                method=method
            )
            
            self.findings.append(finding)
            return finding
            
        except Exception as e:
            logger.error(f"JSON XXE scan error: {e}")
            return {
                "is_vulnerable": False,
                "error": str(e),
                "endpoint": url,
            }
    
    def scan_soap_endpoint(self, url: str, service_name: str = None,
                          method: str = "POST", headers: Dict = None) -> Dict[str, Any]:
        """
        Scan SOAP web service for XXE vulnerabilities.
        
        SOAP endpoints are XML-based and commonly vulnerable to XXE
        due to XML parser configurations.
        
        Args:
            url: SOAP endpoint URL
            service_name: Optional SOAP service name (for reporting)
            method: HTTP method (usually POST)
            headers: Additional HTTP headers
        
        Returns:
            Finding dict with SOAP XXE status
        """
        logger.info(f"Scanning SOAP endpoint {url} for XXE")
        
        try:
            req_headers = headers or {}
            req_headers["Content-Type"] = "application/soap+xml"
            req_headers["SOAPAction"] = ""
            
            # Generate SOAP payloads
            if self.oast_server:
                oast_endpoint = self.oast_server.get_http_endpoint()
                soap_payloads = payloads.soap_xxe_payloads(oast_endpoint)
                
                for soap_payload in soap_payloads:
                    try:
                        resp = self.http_client.post(
                            url,
                            data=soap_payload,
                            headers=req_headers,
                            timeout=self.timeout
                        )
                        logger.debug(f"SOAP XXE payload response: {resp.status_code}")
                    except Exception as e:
                        logger.debug(f"SOAP payload error: {e}")
            
            # Use detector
            result = self.detector.detect_xml_parameter(
                url=url,
                parameter="soap_body",
                value="<soap:Envelope/>",
                method=method,
                headers=req_headers
            )
            
            finding = self._result_to_finding(
                result=result,
                endpoint=url,
                parameter="soap_body",
                method=method
            )
            
            self.findings.append(finding)
            return finding
            
        except Exception as e:
            logger.error(f"SOAP XXE scan error: {e}")
            return {
                "is_vulnerable": False,
                "error": str(e),
                "endpoint": url,
            }
    
    def scan_file_upload(self, url: str, file_param: str = "file",
                        headers: Dict = None) -> Dict[str, Any]:
        """
        Scan file upload endpoint for XXE vulnerabilities.
        
        File uploads accepting XML/SVG/PDF files may be vulnerable:
        - XML uploads
        - SVG uploads (XML-based)
        - Office documents (.docx, .xlsx are XML-based)
        
        Args:
            url: Upload endpoint URL
            file_param: File parameter name
            headers: Additional HTTP headers
        
        Returns:
            Finding dict with upload XXE status
        """
        logger.info(f"Scanning file upload {url} for XXE")
        
        try:
            req_headers = headers or {}
            
            # Generate SVG XXE payloads
            if self.oast_server:
                oast_endpoint = self.oast_server.get_http_endpoint()
                svg_payloads = payloads.svg_xxe_payloads(oast_endpoint)
                
                for svg_payload in svg_payloads:
                    try:
                        files = {
                            file_param: ("test.svg", svg_payload, "image/svg+xml")
                        }
                        resp = self.http_client.post(
                            url,
                            files=files,
                            headers=req_headers,
                            timeout=self.timeout
                        )
                        logger.debug(f"SVG upload response: {resp.status_code}")
                    except Exception as e:
                        logger.debug(f"SVG upload error: {e}")
            
            # Generate regular XML payloads
            xml_payloads = payloads.oast_http_payloads(
                self.oast_server.get_http_endpoint() if self.oast_server else "http://callback"
            )
            
            for xml_payload, correlation_id, payload_type in xml_payloads:
                try:
                    files = {
                        file_param: ("test.xml", xml_payload, "application/xml")
                    }
                    resp = self.http_client.post(
                        url,
                        files=files,
                        headers=req_headers,
                        timeout=self.timeout
                    )
                    logger.debug(f"XML upload response: {resp.status_code}")
                except Exception as e:
                    logger.debug(f"XML upload error: {e}")
            
            finding = {
                "is_vulnerable": False,
                "endpoint": url,
                "parameter": file_param,
                "technique": "file_upload",
                "confidence": "low",
                "findings": [],
                "note": "File upload XXE detection requires callback confirmation"
            }
            
            self.findings.append(finding)
            return finding
            
        except Exception as e:
            logger.error(f"File upload XXE scan error: {e}")
            return {
                "is_vulnerable": False,
                "error": str(e),
                "endpoint": url,
            }
    
    def scan_raw_request(self, raw_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan XXE using raw HTTP request dict.
        
        Unified interface accepting:
        {
            "method": "POST",
            "url": "http://target.com/api",
            "headers": {...},
            "body": "<?xml...?>",
            "content_type": "application/xml"
        }
        
        Args:
            raw_request: Raw HTTP request dict
        
        Returns:
            Finding dict
        """
        url = raw_request.get("url")
        method = raw_request.get("method", "POST")
        body = raw_request.get("body", "")
        headers = raw_request.get("headers", {})
        content_type = raw_request.get("content_type", "application/xml")
        
        logger.info(f"Scanning raw request {method} {url}")
        
        # Determine endpoint type and scan accordingly
        if "soap" in content_type.lower():
            return self.scan_soap_endpoint(url, method=method, headers=headers)
        elif "json" in content_type.lower():
            # Extract parameters from JSON body
            import json
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    # Scan each parameter
                    results = []
                    for key, value in data.items():
                        if isinstance(value, str) and ("<" in value or "<?xml" in value):
                            result = self.scan_json_parameter(
                                url, key, value, method=method, headers=headers
                            )
                            results.append(result)
                    return results[0] if results else {"is_vulnerable": False}
            except:
                pass
        
        # Default to XML body scan
        return self.scan_xml_body(url, body=body, method=method,
                                 content_type=content_type, headers=headers)
    
    def scan_url(self, url: str, method: str = "POST", headers: Dict = None,
                 body: str = None, **kwargs) -> List[Dict[str, Any]]:
        """
        Generic URL scan method for integration with scanner.

        Detects XXE injection points in the target URL by:
        1. Extracting URL parameters
        2. Testing JSON parameters (if content-type is JSON)
        3. Testing XML body (if content-type is XML or SOAP)
        4. Probing for XXE-vulnerable fields

        Args:
            url: Target URL to scan
            method: HTTP method (GET, POST, PUT, etc.)
            headers: Optional HTTP headers dict
            body: Optional request body
            **kwargs: Additional arguments (ignored)

        Returns:
            List of finding dicts (compatible with scanner output format)
        """
        findings = []

        # Scan the URL by testing XML body if it's a POST request
        result = self.scan_xml_body(
            url=url,
            body=body,
            method=method,
            headers=headers
        )

        # Convert result to finding if vulnerable
        if result.get("is_vulnerable"):
            findings.append(result)

        # Also try JSON parameters if we found vulnerable endpoints
        if "?" in url and "=" in url:
            # Extract parameters from URL
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Test first parameter for XXE
            if params:
                param_name = list(params.keys())[0]
                json_result = self.scan_json_parameter(
                    url=url,
                    parameter=param_name,
                    value='<![CDATA[<root/>]]>'
                )
                if json_result.get("is_vulnerable"):
                    findings.append(json_result)

        return findings

    def get_findings(self) -> List[Dict[str, Any]]:
        """
        Get all findings from scans performed.
        
        Returns:
            List of finding dicts
        """
        return self.findings
    
    def _result_to_finding(self, result: Dict, endpoint: str, parameter: str,
                          method: str = "POST") -> Dict[str, Any]:
        """
        Convert detector result to scanner finding format.
        
        Args:
            result: Result dict from detector
            endpoint: Target endpoint URL
            parameter: Parameter/field name
            method: HTTP method
        
        Returns:
            Structured finding dict
        """
        finding = {
            "type": "blind_xxe",
            "endpoint": endpoint,
            "parameter": parameter,
            "method": method,
            "is_vulnerable": result.get("is_vulnerable", False),
            "technique": result.get("technique", "unknown"),
            "confidence": result.get("confidence", "low"),
            "payload": "XXE injection in XML/SOAP/JSON",
            "findings": result.get("findings", []),
            "ml_score": result.get("ml_score", 0.0),
            "ml_features": result.get("ml_features", {}),
        }
        
        return finding


def determine_xxe_confidence(findings: List[Dict], ml_score: float) -> str:
    """
    Determine confidence level based on findings and ML score.
    
    Confidence levels:
    - HIGH: OAST callback confirmed OR multiple techniques confirmed
    - MEDIUM: Time-based or parser behavior confirmed
    - LOW: Single anomaly or ML score < 0.5
    
    Args:
        findings: List of findings from all techniques
        ml_score: ML anomaly score (0.0-1.0)
    
    Returns:
        Confidence level string
    """
    technique_count = len(set(f.get("technique") for f in findings if f.get("technique")))
    
    has_oast = any(f.get("technique") == "oast" for f in findings)
    has_time_based = any(f.get("technique") == "time_based" for f in findings)
    has_behavior = any(f.get("technique") == "parser_behavior" for f in findings)
    
    if has_oast:
        return "high"
    elif technique_count >= 2:
        return "high"
    elif has_time_based or has_behavior:
        if ml_score > 0.6:
            return "high"
        elif ml_score > 0.3:
            return "medium"
    
    return "low" if ml_score < 0.5 else "medium"
