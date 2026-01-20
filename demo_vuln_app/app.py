from flask import Flask, request, jsonify, render_template_string
import sqlite3
import threading
import time
import re
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
        <ul>
          <li><a href="/search?name=alice">/search?name=alice</a> — SQL query with unsafe string concatenation</li>
          <li><a href="/comment?text=hello">/comment?text=hello</a> — Stores comments and reflects unsanitized</li>
          <li><a href="/comments">/comments</a> — List stored comments</li>
          <li><a href="/fetch_image?url=http://google.com">/fetch_image?url=...</a> — SSRF via image URL parameter</li>
          <li><a href="/webhook?callback=http://localhost:8080">/webhook?callback=...</a> — SSRF via webhook callback parameter</li>
          <li><a href="/fetch_file?file=http://localhost:8000">/fetch_file?file=...</a> — SSRF via file fetch parameter</li>
        </ul>
        <p>
          Time-based simulation: if the <code>name</code> parameter contains patterns like
          <code>WAITFOR DELAY '00:00:5'</code> or <code>SLEEP(5)</code>, the server will sleep accordingly.
        </p>
        """
    )


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
        return jsonify({
            "query": sql,
            "count": len(data),
            "rows": data
        })
    except Exception as e:
        return jsonify({"error": str(e), "query": sql}), 400


@app.route("/comment")
def comment():
    text = request.args.get("text", "")
    # Intentionally store unsanitized content
    COMMENTS.append(text)

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


def run(host: str = "127.0.0.1", port: int = 8000):
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Vulnerable Demo App (Flask)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run(args.host, args.port)
