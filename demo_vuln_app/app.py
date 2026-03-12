from flask import Flask, request, jsonify, render_template_string
import sqlite3
import threading
import time
import re
import os
import json
from datetime import datetime
from urllib.parse import urlparse
import requests

app = Flask(__name__)


# --- In-memory DB setup (intentionally naive) ---

def get_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return conn


DB = get_db()
DB.executescript(
    """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT
    );
    INSERT INTO users (name) VALUES ('alice'), ('bob'), ('charlie');
    """
)


# --- Helpers ---
COMMENTS = []  # naive in-memory store
EVENTS = []
EVENT_LOCK = threading.Lock()
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
EVENTS_FILE = os.path.join(OUTPUT_DIR, "events.jsonl")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


def record_event(module: str, endpoint: str, parameter: str = None, vulnerable: bool = None, **details):
    event = {
        "timestamp": _now_iso(),
        "module": module,
        "endpoint": endpoint,
        "parameter": parameter,
        "vulnerable": vulnerable,
    }
    event.update(details)
    with EVENT_LOCK:
        EVENTS.append(event)
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def _is_private_host(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return True
    private_markers = [
        "localhost", "127.", "10.", "192.168.", "169.254.", "::1",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.2",
    ]
    return any(host.startswith(marker) or marker in host for marker in private_markers)


BENCHMARK_ROUTE_PAIRS = [
    {
        "module": "sqli",
        "param": "name",
        "vulnerable_path": "/search",
        "safe_path": "/sqli/search_safe",
        "vulnerable_sample": "/search?name=test",
        "safe_sample": "/sqli/search_safe?name=test",
        "methods": ["GET"],
    },
    {
        "module": "bxss",
        "param": "text",
        "vulnerable_path": "/comment",
        "safe_path": "/xss/comment_safe",
        "vulnerable_sample": "/comment?text=hello",
        "safe_sample": "/xss/comment_safe?text=hello",
        "methods": ["GET"],
    },
    {
        "module": "ssrf",
        "param": "url",
        "vulnerable_path": "/fetch_image",
        "safe_path": "/ssrf/fetch_safe",
        "vulnerable_sample": "/fetch_image?url=http://example.com",
        "safe_sample": "/ssrf/fetch_safe?url=http://example.com",
        "methods": ["GET"],
    },
    {
        "module": "ssrf",
        "param": "callback",
        "vulnerable_path": "/webhook",
        "safe_path": "/ssrf/webhook_safe",
        "vulnerable_sample": "/webhook?callback=http://example.com",
        "safe_sample": "/ssrf/webhook_safe?callback=http://example.com",
        "methods": ["GET"],
    },
    {
        "module": "ssrf",
        "param": "file",
        "vulnerable_path": "/fetch_file",
        "safe_path": "/ssrf/file_safe",
        "vulnerable_sample": "/fetch_file?file=http://example.com",
        "safe_sample": "/ssrf/file_safe?file=http://example.com",
        "methods": ["GET"],
    },
    {
        "module": "cmdi",
        "param": "host",
        "vulnerable_path": "/ping",
        "safe_path": "/cmdi/ping_safe",
        "vulnerable_sample": "/ping?host=127.0.0.1",
        "safe_sample": "/cmdi/ping_safe?host=127.0.0.1",
        "methods": ["GET"],
    },
    {
        "module": "cmdi",
        "param": "domain",
        "vulnerable_path": "/dns",
        "safe_path": "/cmdi/dns_safe",
        "vulnerable_sample": "/dns?domain=example.com",
        "safe_sample": "/cmdi/dns_safe?domain=example.com",
        "methods": ["GET"],
    },
    {
        "module": "cmdi",
        "param": "cmd",
        "vulnerable_path": "/process",
        "safe_path": "/cmdi/process_safe",
        "vulnerable_sample": "/process?cmd=ls",
        "safe_sample": "/cmdi/process_safe?cmd=ls",
        "methods": ["GET"],
    },
    {
        "module": "xxe",
        "param": "xml_body",
        "vulnerable_path": "/api/parse",
        "safe_path": "/xxe/parse_safe",
        "vulnerable_sample": "/api/parse",
        "safe_sample": "/xxe/parse_safe",
        "methods": ["POST"],
    },
    {
        "module": "xxe",
        "param": "soap_body",
        "vulnerable_path": "/soap",
        "safe_path": "/xxe/soap_safe",
        "vulnerable_sample": "/soap",
        "safe_sample": "/xxe/soap_safe",
        "methods": ["POST"],
    },
    {
        "module": "xxe",
        "param": "file",
        "vulnerable_path": "/upload",
        "safe_path": "/xxe/upload_safe",
        "vulnerable_sample": "/upload",
        "safe_sample": "/xxe/upload_safe",
        "methods": ["POST"],
    },
]

# 22 base targets + (19 aliases * 2) = 60 total targets.
ALIAS_REPLICA_COUNT = {
    "/search": 2,
    "/comment": 2,
    "/fetch_image": 2,
    "/webhook": 2,
    "/fetch_file": 2,
    "/ping": 2,
    "/dns": 2,
    "/process": 2,
    "/api/parse": 1,
    "/soap": 1,
    "/upload": 1,
}


def _alias_path(path: str, index: int, kind: str) -> str:
    normalized = path.strip("/").replace("/", "_")
    return f"/bench/{kind}/{normalized}_{index}"


def _build_ground_truth_targets(base: str):
    targets = []
    for pair in BENCHMARK_ROUTE_PAIRS:
        targets.append(
            {
                "module": pair["module"],
                "url": f"{base}{pair['vulnerable_sample']}",
                "parameter": pair["param"],
                "vulnerable": True,
            }
        )
        targets.append(
            {
                "module": pair["module"],
                "url": f"{base}{pair['safe_sample']}",
                "parameter": pair["param"],
                "vulnerable": False,
            }
        )

        replicas = ALIAS_REPLICA_COUNT.get(pair["vulnerable_path"], 0)
        for idx in range(1, replicas + 1):
            vuln_alias = _alias_path(pair["vulnerable_path"], idx, "v")
            safe_alias = _alias_path(pair["safe_path"], idx, "s")
            targets.append(
                {
                    "module": pair["module"],
                    "url": f"{base}{vuln_alias}",
                    "parameter": pair["param"],
                    "vulnerable": True,
                }
            )
            targets.append(
                {
                    "module": pair["module"],
                    "url": f"{base}{safe_alias}",
                    "parameter": pair["param"],
                    "vulnerable": False,
                }
            )
    return targets


def _ground_truth(host_url: str):
    base = host_url.rstrip("/")
    return {
        "dataset": "ShadowProbeEvalBench-2026",
        "generated_at": _now_iso(),
        "targets": _build_ground_truth_targets(base),
    }


def simulate_admin_visit_and_trigger_oob(comment_text: str):
    """Simulate an admin reading stored content and executing injected callbacks.

    For demo purposes, we parse the comment text for callback-like URLs and
    call them server-side to trigger the OOB callback server.
    """
    # Extract all potential UUIDs (36-char hex with hyphens or 32-char hex)
    # UUIDs typically: 8-4-4-4-12 (36 chars) or compact 32 chars
    uuid_patterns = [
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',  # standard UUID
        r'[0-9a-fA-F]{32}',  # compact UUID
    ]
    
    uuids_found = set()
    for pattern in uuid_patterns:
        uuids_found.update(re.findall(pattern, comment_text))
    
    # Also try to extract host from the payload
    host_match = re.search(r'https?://([^/\s"\']+)', comment_text)
    default_host = None
    if host_match:
        default_host = host_match.group(1)
    
    print(f"[ADMIN] Parsing stored comment for callbacks: {len(uuids_found)} UUIDs found")
    if default_host:
        print(f"[ADMIN] Extracted listener host: {default_host}")
    
    # For each UUID found, try to trigger the callback
    for uuid in uuids_found:
        # Try different callback formats
        callback_urls = []
        
        if default_host:
            # Try with /x.js?id=UUID
            callback_urls.append(f"http://{default_host}/x.js?id={uuid}")
            # Try with /c/UUID  
            callback_urls.append(f"http://{default_host}/c/{uuid}")
            # Try with /?id=UUID
            callback_urls.append(f"http://{default_host}/?id={uuid}")
        
        # Try localhost:5000 as fallback
        callback_urls.extend([
            f"http://127.0.0.1:5000/x.js?id={uuid}",
            f"http://127.0.0.1:5000/c/{uuid}",
            f"http://127.0.0.1:5000/?id={uuid}",
            f"http://localhost:5000/x.js?id={uuid}",
            f"http://localhost:5000/c/{uuid}",
            f"http://localhost:5000/?id={uuid}",
        ])
        
        for url in callback_urls:
            try:
                print(f"[ADMIN] Triggering callback: {url}")
                resp = requests.get(url, timeout=5)
                print(f"[ADMIN] Callback response: {resp.status_code}")
            except Exception as e:
                print(f"[ADMIN] Callback failed: {e}")
                continue


@app.route("/")
def index():
    return render_template_string(
        """
        <h2>Vulnerable Demo App</h2>
        <p>For local demo only. Do NOT expose publicly.</p>
        <h3>SQL Injection (Time-Based)</h3>
        <ul>
          <li><a href="/search?name=alice">/search?name=alice</a> — SQL query with unsafe string concatenation</li>
        </ul>
        <h3>Cross-Site Scripting (Blind XSS)</h3>
        <ul>
          <li><a href="/comment?text=hello">/comment?text=hello</a> — Stores comments and reflects unsanitized</li>
          <li><a href="/comments">/comments</a> — List stored comments</li>
        </ul>
        <h3>Server-Side Request Forgery (SSRF)</h3>
        <ul>
          <li><a href="/fetch_image?url=http://google.com">/fetch_image?url=...</a> — SSRF via image URL parameter</li>
          <li><a href="/webhook?callback=http://localhost:8080">/webhook?callback=...</a> — SSRF via webhook callback parameter</li>
          <li><a href="/fetch_file?file=http://localhost:8000">/fetch_file?file=...</a> — SSRF via file fetch parameter</li>
        </ul>
        <h3>Command Injection (Blind CMDi)</h3>
        <ul>
          <li><a href="/ping?host=127.0.0.1">/ping?host=127.0.0.1</a> — Blind CMDi via ping (time-based)</li>
          <li><a href="/dns?domain=example.com">/dns?domain=example.com</a> — Blind CMDi via nslookup (time-based)</li>
          <li><a href="/process?cmd=ls">/process?cmd=ls</a> — Blind CMDi via OS command (time-based)</li>
        </ul>
        <h3>XML External Entity (Blind XXE)</h3>
        <ul>
          <li><a href="/api/parse">/api/parse</a> (POST with XML body) — XXE via XML parsing (time-based, OAST-ready)</li>
          <li><a href="/soap">/soap</a> (POST with SOAP) — XXE via SOAP endpoint (XML-based)</li>
          <li><a href="/upload">/upload</a> (POST file upload) — XXE via SVG/XML file upload</li>
        </ul>
        <p>
          Time-based simulation: if payloads contain patterns like
          <code>WAITFOR DELAY '00:00:5'</code>, <code>SLEEP(5)</code>, or <code>sleep 5</code>, 
          the server will sleep accordingly.
        </p>
        <p>
          XXE simulation: if payloads contain DOCTYPE/ENTITY declarations, the server simulates XML parsing.
        </p>
        """
    )


@app.route("/_shadowprobe/ground-truth", methods=["GET"])
def shadowprobe_ground_truth():
    return jsonify(_ground_truth(request.host_url))


@app.route("/_shadowprobe/events", methods=["GET"])
def shadowprobe_events():
    module = request.args.get("module")
    with EVENT_LOCK:
        data = list(EVENTS)
    if module:
        data = [e for e in data if e.get("module") == module]
    return jsonify({"count": len(data), "events": data[-500:]})


@app.route("/_shadowprobe/reset", methods=["POST"])
def shadowprobe_reset():
    with EVENT_LOCK:
        EVENTS.clear()
        COMMENTS.clear()
    if os.path.exists(EVENTS_FILE):
        os.remove(EVENTS_FILE)
    return jsonify({"ok": True, "message": "benchmark state reset"})


@app.route("/search")
def search():
    name = request.args.get("name", "")

    # DEMO-ONLY: simulate time-based delays for common payloads
    try:
        m = re.search(r"WAITFOR\s+DELAY\s+'00:00:(\d+)'", name, re.IGNORECASE)
        if m:
            time.sleep(int(m.group(1)))
        m = re.search(r"SLEEP\((\d+)\)", name, re.IGNORECASE)
        if m:
            time.sleep(int(m.group(1)))
    except Exception:
        pass

    # Intentionally vulnerable query (UNSAFE!)
    sql = f"SELECT id, name FROM users WHERE name = '{name}'"
    try:
        rows = DB.execute(sql).fetchall()
        data = [{"id": r["id"], "name": r["name"]} for r in rows]
        record_event("sqli", "/search", parameter="name", vulnerable=True, payload=name, row_count=len(data))
        return jsonify({
            "query": sql,
            "count": len(data),
            "rows": data
        })
    except Exception as e:
        record_event("sqli", "/search", parameter="name", vulnerable=True, payload=name, error=str(e))
        return jsonify({"error": str(e), "query": sql}), 400


@app.route("/sqli/search_safe")
def search_safe():
    name = request.args.get("name", "")
    rows = DB.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()
    data = [{"id": r["id"], "name": r["name"]} for r in rows]
    record_event("sqli", "/sqli/search_safe", parameter="name", vulnerable=False, payload=name, row_count=len(data))
    return jsonify({"safe": True, "count": len(data), "rows": data})


@app.route("/comment")
def comment():
    text = request.args.get("text", "")
    # Intentionally store unsanitized content
    COMMENTS.append(text)
    record_event("bxss", "/comment", parameter="text", vulnerable=True, payload=text)

    # Simulate admin visit and callback trigger asynchronously
    threading.Thread(target=simulate_admin_visit_and_trigger_oob, args=(text,), daemon=True).start()

    # Reflect unsanitized content
    tpl = """
    <h3>Comment Stored</h3>
    <p>Below is your comment (unsanitized):</p>
    <div style="border:1px solid #ccc;padding:10px;margin:10px 0;">{{ text|safe }}</div>
    <p><a href="/comments">View all comments</a></p>
    """
    return render_template_string(tpl, text=text)


@app.route("/xss/comment_safe")
def comment_safe():
    text = request.args.get("text", "")
    COMMENTS.append(text)
    record_event("bxss", "/xss/comment_safe", parameter="text", vulnerable=False, payload=text)
    tpl = """
    <h3>Comment Stored (safe)</h3>
    <div style="border:1px solid #ccc;padding:10px;margin:10px 0;">{{ text }}</div>
    <p><a href="/comments">View all comments</a></p>
    """
    return render_template_string(tpl, text=text)


@app.route("/comments")
def list_comments():
    items = "".join(f"<li>{c}</li>" for c in COMMENTS)
    return render_template_string(
        f"""
        <h3>Stored Comments (unsanitized)</h3>
        <ul>{items}</ul>
        <p><a href="/">Home</a></p>
        """
    )


# ============================================
# SSRF Vulnerable Endpoints (for BSSRF demo)
# ============================================

@app.route("/fetch_image")
def fetch_image():
    """
    SSRF vulnerability: fetches an image from user-supplied URL.
    Vulnerable parameter: 'url'
    """
    url = request.args.get("url", "")
    
    if not url:
        return jsonify({
            "error": "Missing 'url' parameter",
            "example": "/fetch_image?url=http://example.com/image.jpg"
        })
    
    print(f"[SSRF] fetch_image endpoint received URL: {url}")
    record_event("ssrf", "/fetch_image", parameter="url", vulnerable=True, target=url)
    
    try:
        # VULNERABLE: directly fetch from user-supplied URL without validation
        response = requests.get(url, timeout=5)
        print(f"[SSRF] Fetched from {url}: status={response.status_code}")
        
        # Simulate storing the fetched image metadata
        return jsonify({
            "status": "success",
            "url": url,
            "status_code": response.status_code,
            "content_length": len(response.content),
            "message": "Image fetched and would be stored (vulnerable to SSRF)"
        })
    except requests.exceptions.Timeout:
        print(f"[SSRF] Timeout fetching {url}")
        return jsonify({
            "status": "timeout",
            "url": url,
            "message": "Request timed out (possible SSRF to slow/blocked endpoint)"
        }), 504
    except Exception as e:
        print(f"[SSRF] Error fetching {url}: {e}")
        return jsonify({
            "status": "error",
            "url": url,
            "error": str(e)
        }), 400


@app.route("/ssrf/fetch_safe")
def fetch_image_safe():
    url = request.args.get("url", "")
    record_event("ssrf", "/ssrf/fetch_safe", parameter="url", vulnerable=False, target=url)
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"status": "blocked", "reason": "scheme_not_allowed"}), 403
    if _is_private_host(url):
        return jsonify({"status": "blocked", "reason": "private_host_blocked"}), 403
    return jsonify({"status": "accepted", "safe": True, "url": url})


@app.route("/webhook")
def webhook():
    """
    SSRF vulnerability: registers a webhook callback URL.
    Vulnerable parameter: 'callback'
    
    Simulates a service that will make requests to the callback URL.
    """
    callback = request.args.get("callback", "")
    event = request.args.get("event", "user.created")
    
    if not callback:
        return jsonify({
            "error": "Missing 'callback' parameter",
            "example": "/webhook?callback=http://attacker.com/hook&event=user.created"
        })
    
    print(f"[SSRF] webhook endpoint received callback: {callback}")
    record_event("ssrf", "/webhook", parameter="callback", vulnerable=True, target=callback)
    
    try:
        # VULNERABLE: server will make requests to user-supplied callback
        # Simulate the server making a callback request
        print(f"[SSRF] Simulating webhook trigger to {callback}")
        response = requests.post(callback, 
                                json={"event": event, "timestamp": time.time()},
                                timeout=5)
        print(f"[SSRF] Callback response: {response.status_code}")
        
        return jsonify({
            "status": "registered",
            "callback": callback,
            "event": event,
            "callback_status": response.status_code,
            "message": "Webhook registered and would be triggered (vulnerable to SSRF)"
        })
    except requests.exceptions.Timeout:
        print(f"[SSRF] Webhook timeout to {callback}")
        return jsonify({
            "status": "timeout",
            "callback": callback,
            "message": "Webhook callback timed out (possible SSRF)"
        }), 504
    except Exception as e:
        print(f"[SSRF] Webhook error: {e}")
        return jsonify({
            "status": "error",
            "callback": callback,
            "error": str(e)
        }), 400


@app.route("/ssrf/webhook_safe")
def webhook_safe():
    callback = request.args.get("callback", "")
    record_event("ssrf", "/ssrf/webhook_safe", parameter="callback", vulnerable=False, target=callback)
    if not callback:
        return jsonify({"error": "Missing 'callback' parameter"}), 400
    if _is_private_host(callback):
        return jsonify({"status": "blocked", "reason": "private_host_blocked"}), 403
    return jsonify({"status": "registered_safe", "safe": True, "callback": callback})


@app.route("/fetch_file")
def fetch_file():
    """
    SSRF vulnerability: fetches content from a user-supplied file URL.
    Vulnerable parameter: 'file'
    
    Could be used to access internal services, metadata endpoints, etc.
    """
    file_url = request.args.get("file", "")
    
    if not file_url:
        return jsonify({
            "error": "Missing 'file' parameter",
            "example": "/fetch_file?file=http://internal-server:8080/admin"
        })
    
    print(f"[SSRF] fetch_file endpoint received: {file_url}")
    record_event("ssrf", "/fetch_file", parameter="file", vulnerable=True, target=file_url)
    
    try:
        # VULNERABLE: fetch file from user-supplied URL
        response = requests.get(file_url, timeout=5)
        print(f"[SSRF] Fetched file from {file_url}: status={response.status_code}")
        
        # Would parse and process the file
        return jsonify({
            "status": "success",
            "file_url": file_url,
            "status_code": response.status_code,
            "content_length": len(response.content),
            "message": "File fetched and processed (vulnerable to SSRF)"
        })
    except requests.exceptions.Timeout:
        print(f"[SSRF] File fetch timeout from {file_url}")
        return jsonify({
            "status": "timeout",
            "file_url": file_url,
            "message": "File fetch timed out (possible SSRF)"
        }), 504
    except Exception as e:
        print(f"[SSRF] File fetch error: {e}")
        return jsonify({
            "status": "error",
            "file_url": file_url,
            "error": str(e)
        }), 400


@app.route("/ssrf/file_safe")
def fetch_file_safe():
    file_url = request.args.get("file", "")
    record_event("ssrf", "/ssrf/file_safe", parameter="file", vulnerable=False, target=file_url)
    if not file_url:
        return jsonify({"error": "Missing 'file' parameter"}), 400
    if not (file_url.startswith("http://") or file_url.startswith("https://")):
        return jsonify({"status": "blocked", "reason": "scheme_not_allowed"}), 403
    if _is_private_host(file_url):
        return jsonify({"status": "blocked", "reason": "private_host_blocked"}), 403
    return jsonify({"status": "accepted", "safe": True, "file": file_url})


# ============================================
# Blind CMDi Vulnerable Endpoints (for BCMDI demo)
# ============================================

@app.route("/ping")
def ping():
    """
    Blind CMDi vulnerability: pings a host with user-supplied hostname.
    Vulnerable parameter: 'host'
    
    Demonstrates time-based blind command injection detection.
    Payloads like "127.0.0.1; sleep 5" will cause delays.
    """
    host = request.args.get("host", "127.0.0.1")
    record_event("cmdi", "/ping", parameter="host", vulnerable=True, payload=host)
    
    # DEMO-ONLY: simulate time-based CMDi delays
    # Parse for sleep/timeout commands injected via separator
    try:
        # Handle various injection payloads
        # sleep 3, sleep 5, sleep 7 (Linux)
        m = re.search(r"sleep\s+(\d+)", host, re.IGNORECASE)
        if m:
            delay = int(m.group(1))
            print(f"[CMDi] ping endpoint: detected sleep command, sleeping {delay}s")
            time.sleep(delay)
        
        # timeout /t N (Windows)
        m = re.search(r"timeout\s+/t\s+(\d+)", host, re.IGNORECASE)
        if m:
            delay = int(m.group(1))
            print(f"[CMDi] ping endpoint: detected timeout command, sleeping {delay}s")
            time.sleep(delay)
        
        # ping -n N (Windows/Linux)
        m = re.search(r"ping\s+-n\s+(\d+)", host, re.IGNORECASE)
        if m:
            count = int(m.group(1))
            # Approximate delay: N-1 seconds (N ping packets)
            delay = max(0, count - 1)
            if delay > 0:
                print(f"[CMDi] ping endpoint: detected ping -n, sleeping {delay}s")
                time.sleep(delay)
    except Exception as e:
        print(f"[CMDi] ping endpoint: error parsing delay: {e}")
    
    # Simulate ping command (return success regardless)
    print(f"[CMDi] ping endpoint: host={host}")
    
    return jsonify({
        "status": "success",
        "host": host,
        "message": "Host pinged successfully (vulnerable to blind CMDi)"
    })


@app.route("/cmdi/ping_safe")
def ping_safe():
    host = request.args.get("host", "127.0.0.1")
    record_event("cmdi", "/cmdi/ping_safe", parameter="host", vulnerable=False, payload=host)
    return jsonify({"status": "success", "safe": True, "host": host, "delay_simulated": 0})


@app.route("/dns")
def dns():
    """
    Blind CMDi vulnerability: performs DNS lookup on user-supplied domain.
    Vulnerable parameter: 'domain'
    
    Demonstrates time-based blind command injection detection.
    Payloads like "example.com; sleep 5" will cause delays.
    """
    domain = request.args.get("domain", "example.com")
    record_event("cmdi", "/dns", parameter="domain", vulnerable=True, payload=domain)
    
    # DEMO-ONLY: simulate time-based CMDi delays
    try:
        # Parse for sleep/timeout commands
        m = re.search(r"sleep\s+(\d+)", domain, re.IGNORECASE)
        if m:
            delay = int(m.group(1))
            print(f"[CMDi] dns endpoint: detected sleep command, sleeping {delay}s")
            time.sleep(delay)
        
        m = re.search(r"timeout\s+/t\s+(\d+)", domain, re.IGNORECASE)
        if m:
            delay = int(m.group(1))
            print(f"[CMDi] dns endpoint: detected timeout command, sleeping {delay}s")
            time.sleep(delay)
        
        m = re.search(r"ping\s+-n\s+(\d+)", domain, re.IGNORECASE)
        if m:
            count = int(m.group(1))
            delay = max(0, count - 1)
            if delay > 0:
                print(f"[CMDi] dns endpoint: detected ping -n, sleeping {delay}s")
                time.sleep(delay)
    except Exception as e:
        print(f"[CMDi] dns endpoint: error parsing delay: {e}")
    
    # Simulate DNS lookup (return fake results)
    print(f"[CMDi] dns endpoint: domain={domain}")
    
    return jsonify({
        "status": "success",
        "domain": domain,
        "ip_addresses": ["192.168.1.1"],
        "message": "DNS lookup completed (vulnerable to blind CMDi)"
    })


@app.route("/cmdi/dns_safe")
def dns_safe():
    domain = request.args.get("domain", "example.com")
    record_event("cmdi", "/cmdi/dns_safe", parameter="domain", vulnerable=False, payload=domain)
    return jsonify({"status": "success", "safe": True, "domain": domain, "ip_addresses": ["192.168.1.1"]})


@app.route("/process")
def process():
    """
    Blind CMDi vulnerability: processes a command parameter.
    Vulnerable parameter: 'cmd'
    
    Demonstrates time-based blind command injection detection.
    Payloads like "ls; sleep 5" will cause delays.
    """
    cmd = request.args.get("cmd", "ls")
    record_event("cmdi", "/process", parameter="cmd", vulnerable=True, payload=cmd)
    
    # DEMO-ONLY: simulate time-based CMDi delays
    try:
        # Parse for sleep/timeout commands
        m = re.search(r"sleep\s+(\d+)", cmd, re.IGNORECASE)
        if m:
            delay = int(m.group(1))
            print(f"[CMDi] process endpoint: detected sleep command, sleeping {delay}s")
            time.sleep(delay)
        
        m = re.search(r"timeout\s+/t\s+(\d+)", cmd, re.IGNORECASE)
        if m:
            delay = int(m.group(1))
            print(f"[CMDi] process endpoint: detected timeout command, sleeping {delay}s")
            time.sleep(delay)
        
        m = re.search(r"ping\s+-n\s+(\d+)", cmd, re.IGNORECASE)
        if m:
            count = int(m.group(1))
            delay = max(0, count - 1)
            if delay > 0:
                print(f"[CMDi] process endpoint: detected ping -n, sleeping {delay}s")
                time.sleep(delay)
    except Exception as e:
        print(f"[CMDi] process endpoint: error parsing delay: {e}")
    
    # Simulate command execution (return fake results)
    print(f"[CMDi] process endpoint: cmd={cmd}")
    
    return jsonify({
        "status": "success",
        "command": cmd,
        "output_lines": 5,
        "message": "Command executed (vulnerable to blind CMDi)"
    })


@app.route("/cmdi/process_safe")
def process_safe():
    cmd = request.args.get("cmd", "ls")
    record_event("cmdi", "/cmdi/process_safe", parameter="cmd", vulnerable=False, payload=cmd)
    return jsonify({"status": "success", "safe": True, "command": cmd, "output_lines": 5})


# ============================================
# Blind XXE Vulnerable Endpoints (for BXE demo)
# ============================================

@app.route("/api/parse", methods=["POST"])
def parse_xml():
    """
    Blind XXE vulnerability: parses XML request body without XXE protection.
    Vulnerable parameter: XML body content
    
    Demonstrates time-based XXE detection via:
    - file:///dev/random (blocks parser)
    - Recursive entity expansion (CPU-bound delay)
    - Delayed network endpoints
    
    Also demonstrates parser behavior changes (status code, size).
    """
    xml_data = request.data.decode('utf-8', errors='ignore') if request.data else ""
    record_event("xxe", "/api/parse", parameter="xml_body", vulnerable=True, body_length=len(xml_data))
    
    print(f"[XXE] parse_xml endpoint received: {len(xml_data)} bytes")
    
    # DEMO-ONLY: simulate XXE delays
    # Check for XXE payload indicators
    try:
        # Detect /dev/random reference (should block)
        if "/dev/random" in xml_data:
            print("[XXE] parse_xml: detected /dev/random, simulating 3s block")
            time.sleep(3)
        
        # Detect recursive entity expansion (Billion Laughs)
        if "&lol" in xml_data.lower() and "entity" in xml_data.lower():
            # Count entity references
            entity_count = xml_data.count("&lol")
            # Approximate delay based on nesting
            if entity_count > 5:
                print(f"[XXE] parse_xml: detected recursive entities ({entity_count}), simulating 2s CPU delay")
                time.sleep(2)
        
        # Detect external entity with delay endpoint
        if "SYSTEM" in xml_data and "http" in xml_data:
            print("[XXE] parse_xml: detected external entity reference")
            # Simulate parser attempting to fetch remote resource
            time.sleep(0.5)
        
        # Check for control payloads (should not delay)
        is_control = (
            ("<?xml" in xml_data and "DOCTYPE" not in xml_data) or
            ("<root>" in xml_data and "ENTITY" not in xml_data)
        )
        
        if is_control:
            print("[XXE] parse_xml: control payload detected (should not delay)")
    
    except Exception as e:
        print(f"[XXE] parse_xml: error parsing delays: {e}")
    
    # Simulate XML parsing
    try:
        # In real scenario, this would parse the XML
        # For demo, just check for well-formedness
        if "<?xml" not in xml_data and "<" in xml_data:
            # Bare XML tag, probably OK
            pass
        
        return jsonify({
            "status": "parsed",
            "size": len(xml_data),
            "message": "XML parsed successfully (vulnerable to blind XXE)",
            "timestamp": time.time()
        }), 200
    
    except Exception as e:
        print(f"[XXE] parse_xml: parsing error: {e}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "message": "XML parsing failed"
        }), 400


@app.route("/xxe/parse_safe", methods=["POST"])
def parse_xml_safe():
    xml_data = request.data.decode('utf-8', errors='ignore') if request.data else ""
    has_dangerous = ("DOCTYPE" in xml_data.upper()) or ("ENTITY" in xml_data.upper())
    record_event("xxe", "/xxe/parse_safe", parameter="xml_body", vulnerable=False, body_length=len(xml_data), blocked=has_dangerous)
    if has_dangerous:
        return jsonify({"status": "blocked", "reason": "doctype_or_entity_rejected"}), 400
    return jsonify({"status": "parsed", "safe": True, "size": len(xml_data)}), 200


@app.route("/soap", methods=["POST"])
def soap_endpoint():
    """
    Blind XXE vulnerability: SOAP web service endpoint.
    Vulnerable parameter: SOAP envelope (XML body)
    
    SOAP is XML-based and often processed without XXE protection.
    """
    soap_data = request.data.decode('utf-8', errors='ignore') if request.data else ""
    record_event("xxe", "/soap", parameter="soap_body", vulnerable=True, body_length=len(soap_data))
    
    print(f"[XXE] soap endpoint received: {len(soap_data)} bytes")
    
    # DEMO-ONLY: simulate XXE delays in SOAP parsing
    try:
        # Check for SOAP envelope with XXE
        if "soap:Envelope" in soap_data and "DOCTYPE" in soap_data:
            print("[XXE] soap: SOAP with DOCTYPE detected")
            
            # Detect XXE payload
            if "/dev/random" in soap_data:
                print("[XXE] soap: /dev/random detected, sleeping 3s")
                time.sleep(3)
            
            if "&lol" in soap_data.lower():
                print("[XXE] soap: recursive entity detected, sleeping 2s")
                time.sleep(2)
    
    except Exception as e:
        print(f"[XXE] soap: error: {e}")
    
    # Return SOAP-like response
    try:
        if "soap:Envelope" in soap_data:
            return jsonify({
                "status": "success",
                "message": "SOAP request processed (vulnerable to blind XXE)",
                "size": len(soap_data)
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": "Invalid SOAP envelope"
            }), 400
    
    except Exception as e:
        print(f"[XXE] soap: response error: {e}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 400


@app.route("/xxe/soap_safe", methods=["POST"])
def soap_endpoint_safe():
    soap_data = request.data.decode('utf-8', errors='ignore') if request.data else ""
    has_dangerous = ("DOCTYPE" in soap_data.upper()) or ("ENTITY" in soap_data.upper())
    record_event("xxe", "/xxe/soap_safe", parameter="soap_body", vulnerable=False, body_length=len(soap_data), blocked=has_dangerous)
    if has_dangerous:
        return jsonify({"status": "blocked", "reason": "doctype_or_entity_rejected"}), 400
    return jsonify({"status": "success", "safe": True, "size": len(soap_data)}), 200


@app.route("/upload", methods=["POST"])
def upload_file():
    """
    Blind XXE vulnerability: file upload endpoint accepting XML/SVG files.
    Vulnerable parameter: file content
    
    Files are processed (parsed) without XXE protection.
    Common file types:
    - SVG (XML-based images)
    - XML documents
    - Office documents (.docx, .xlsx are ZIP+XML)
    """
    
    if 'file' not in request.files:
        return jsonify({
            "error": "No file provided",
            "example": "POST multipart file with .svg or .xml extension"
        }), 400
    
    file = request.files['file']
    filename = file.filename or "upload.xml"
    
    try:
        file_content = file.read().decode('utf-8', errors='ignore')
        print(f"[XXE] upload endpoint: {filename} ({len(file_content)} bytes)")
        record_event("xxe", "/upload", parameter="file", vulnerable=True, filename=filename, body_length=len(file_content))
    except Exception as e:
        print(f"[XXE] upload endpoint: error reading file: {e}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 400
    
    # DEMO-ONLY: simulate XXE delays on file upload
    try:
        # SVG or XML upload
        if filename.endswith(('.svg', '.xml', '.docx', '.xlsx')):
            
            # Detect XXE in uploaded file
            if "/dev/random" in file_content:
                print("[XXE] upload: /dev/random in SVG/XML, sleeping 3s")
                time.sleep(3)
            
            if "&lol" in file_content.lower() and "DOCTYPE" in file_content:
                print("[XXE] upload: recursive entity in upload, sleeping 2s")
                time.sleep(2)
            
            if "DOCTYPE" in file_content and "ENTITY" in file_content:
                print("[XXE] upload: XXE payload detected")
                if "SYSTEM" in file_content:
                    time.sleep(0.5)
    
    except Exception as e:
        print(f"[XXE] upload: error: {e}")
    
    # Simulate file processing
    try:
        return jsonify({
            "status": "success",
            "filename": filename,
            "size": len(file_content),
            "message": "File uploaded and processed (vulnerable to blind XXE)"
        }), 200
    
    except Exception as e:
        print(f"[XXE] upload: processing error: {e}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 400


@app.route("/xxe/upload_safe", methods=["POST"])
def upload_file_safe():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    filename = file.filename or "upload.xml"
    try:
        file_content = file.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    has_dangerous = ("DOCTYPE" in file_content.upper()) or ("ENTITY" in file_content.upper())
    record_event("xxe", "/xxe/upload_safe", parameter="file", vulnerable=False, filename=filename, body_length=len(file_content), blocked=has_dangerous)
    if has_dangerous:
        return jsonify({"status": "blocked", "reason": "doctype_or_entity_rejected"}), 400
    return jsonify({"status": "success", "safe": True, "filename": filename, "size": len(file_content)}), 200


def _register_benchmark_alias_routes():
    route_handlers = {
        "/search": search,
        "/sqli/search_safe": search_safe,
        "/comment": comment,
        "/xss/comment_safe": comment_safe,
        "/fetch_image": fetch_image,
        "/ssrf/fetch_safe": fetch_image_safe,
        "/webhook": webhook,
        "/ssrf/webhook_safe": webhook_safe,
        "/fetch_file": fetch_file,
        "/ssrf/file_safe": fetch_file_safe,
        "/ping": ping,
        "/cmdi/ping_safe": ping_safe,
        "/dns": dns,
        "/cmdi/dns_safe": dns_safe,
        "/process": process,
        "/cmdi/process_safe": process_safe,
        "/api/parse": parse_xml,
        "/xxe/parse_safe": parse_xml_safe,
        "/soap": soap_endpoint,
        "/xxe/soap_safe": soap_endpoint_safe,
        "/upload": upload_file,
        "/xxe/upload_safe": upload_file_safe,
    }

    for pair in BENCHMARK_ROUTE_PAIRS:
        replicas = ALIAS_REPLICA_COUNT.get(pair["vulnerable_path"], 0)
        methods = pair.get("methods", ["GET"])
        vuln_handler = route_handlers[pair["vulnerable_path"]]
        safe_handler = route_handlers[pair["safe_path"]]
        for idx in range(1, replicas + 1):
            vuln_alias = _alias_path(pair["vulnerable_path"], idx, "v")
            safe_alias = _alias_path(pair["safe_path"], idx, "s")
            app.add_url_rule(
                vuln_alias,
                endpoint=f"bench_v_{pair['module']}_{idx}_{pair['vulnerable_path'].strip('/').replace('/', '_')}",
                view_func=vuln_handler,
                methods=methods,
            )
            app.add_url_rule(
                safe_alias,
                endpoint=f"bench_s_{pair['module']}_{idx}_{pair['safe_path'].strip('/').replace('/', '_')}",
                view_func=safe_handler,
                methods=methods,
            )


_register_benchmark_alias_routes()


def run(host: str = "127.0.0.1", port: int = 8000):
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Vulnerable Demo App (Flask)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run(args.host, args.port)
