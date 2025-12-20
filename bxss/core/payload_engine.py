"""
XSS Payload Engine

Generates Blind XSS payloads with UUID injection for correlation.
Reuses payload templates from modules/blind_xss/payloads.py.
"""
import uuid
from typing import List, Dict, Optional
from ..modules.blind_xss.payloads import (
    get_script_payloads,
    get_event_handler_payloads,
    get_bypass_payloads,
    get_json_payloads,
    get_header_payloads,
    get_exfil_payloads,
    get_all_payloads,
)


def generate_uuid() -> str:
    """
    Generate a unique UUID for payload tracking.
    """
    return str(uuid.uuid4())


def inject_uuid_and_listener(payload_template: str, listener_url: str, payload_uuid: str) -> str:
    """
    Inject UUID and listener URL into payload template.
    
    Templates must contain {UUID} and {LISTENER} placeholders.
    """
    # Remove trailing slash from listener
    listener_url = listener_url.rstrip('/')
    
    # Extract host:port from listener URL (remove http://)
    listener_host = listener_url.replace('http://', '').replace('https://', '')
    
    return payload_template.format(UUID=payload_uuid, LISTENER=listener_host)


def generate_payloads(
    listener_url: str,
    payload_types: Optional[List[str]] = None,
    max_per_type: int = 5
) -> List[Dict[str, str]]:
    """
    Generate XSS payloads with UUID and listener URL injected.
    
    Args:
        listener_url: Callback server URL (e.g., http://attacker.com:5000)
        payload_types: List of payload categories to use (default: all)
        max_per_type: Maximum payloads per category
    
    Returns:
        List of payload dictionaries with:
          - uuid: Unique identifier for correlation
          - payload: Injected XSS payload
          - type: Payload category
          - template: Original template
    """
    if payload_types is None:
        payload_types = ["script", "event", "bypass", "json", "header", "exfil"]
    
    all_payloads_dict = get_all_payloads()
    generated = []
    
    for ptype in payload_types:
        if ptype not in all_payloads_dict:
            continue
        
        templates = all_payloads_dict[ptype][:max_per_type]
        
        for template in templates:
            payload_uuid = generate_uuid()
            injected_payload = inject_uuid_and_listener(template, listener_url, payload_uuid)
            
            generated.append({
                "uuid": payload_uuid,
                "payload": injected_payload,
                "type": ptype,
                "template": template,
            })
    
    return generated


def generate_payload_single(listener_url: str, template: str) -> Dict[str, str]:
    """
    Generate a single payload from a template.
    """
    payload_uuid = generate_uuid()
    injected_payload = inject_uuid_and_listener(template, listener_url, payload_uuid)
    
    return {
        "uuid": payload_uuid,
        "payload": injected_payload,
        "template": template,
    }


def get_payload_for_context(context: str, listener_url: str) -> List[Dict[str, str]]:
    """
    Get payloads optimized for specific injection context.
    
    Contexts:
        - query_param: URL query parameters
        - post_param: POST form parameters
        - json_body: JSON request body
        - header: HTTP headers (User-Agent, Referer, etc.)
    """
    if context == "query_param":
        # Use URL-safe payloads
        types = ["script", "event", "bypass"]
    elif context == "post_param":
        # Use all payload types
        types = ["script", "event", "bypass", "exfil"]
    elif context == "json_body":
        # Use JSON-safe payloads
        types = ["json", "script"]
    elif context == "header":
        # Use header-specific payloads
        types = ["header", "script"]
    else:
        types = ["script", "event"]
    
    return generate_payloads(listener_url, payload_types=types, max_per_type=3)
