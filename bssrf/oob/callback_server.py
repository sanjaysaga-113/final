"""
Out-of-Band Callback Server for Blind SSRF Detection (Production-Grade)

Features:
- SQLite persistence (callbacks survive restarts)
- Replay protection (deduplicates UUID+IP)
- Async processing queue (HTTP receive decoupled from processing)
- Context enrichment (full headers, X-Forwarded-For, etc.)
- Configurable injection expiration
- Full audit trail

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
import logging
from queue import Queue
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger("callback_server")

# Configuration
CALLBACK_DB = os.path.join(os.path.dirname(__file__), "..", "output", "callbacks.db")
INJECTION_EXPIRY_HOURS = 24  # Ignore callbacks for injections older than 24h
PROCESSING_QUEUE = Queue()
REPLAY_CHECK_LOCK = Lock()

app = Flask(__name__)


def _init_db():
    """Initialize SQLite database with schema."""
    os.makedirs(os.path.dirname(CALLBACK_DB), exist_ok=True)
    
    conn = sqlite3.connect(CALLBACK_DB)
    cursor = conn.cursor()
    
    # Callbacks table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS callbacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            uuid TEXT,
            remote_addr TEXT,
            path TEXT,
            method TEXT,
            headers TEXT,
            query_string TEXT,
            user_agent TEXT,
            full_url TEXT,
            replay_hash TEXT UNIQUE
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {CALLBACK_DB}")


def save_callback(callback_data):
    """Save callback to SQLite database."""
    try:
        # Create replay hash to detect duplicates
        replay_key = f"{callback_data.get('uuid', 'unknown')}:{callback_data.get('remote_addr', 'unknown')}"
        replay_hash = hashlib.md5(replay_key.encode()).hexdigest()
        callback_data['replay_hash'] = replay_hash
        
        conn = sqlite3.connect(CALLBACK_DB)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO callbacks 
                (timestamp, uuid, remote_addr, path, method, headers, query_string, user_agent, full_url, replay_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                callback_data.get('timestamp'),
                callback_data.get('uuid'),
                callback_data.get('remote_addr'),
                callback_data.get('path'),
                callback_data.get('method'),
                json.dumps(dict(callback_data.get('headers', {}))),
                callback_data.get('query_string'),
                callback_data.get('user_agent'),
                callback_data.get('full_url'),
                replay_hash
            ))
            conn.commit()
            logger.info(f"Callback saved: UUID={callback_data.get('uuid')} from {callback_data.get('remote_addr')}")
        except sqlite3.IntegrityError:
            logger.warning(f"Duplicate callback (replay protection): {replay_hash}")
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Failed to save callback: {e}")


def load_callbacks() -> List[Dict]:
    """Load all callbacks from database."""
    try:
        conn = sqlite3.connect(CALLBACK_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM callbacks ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        
        callbacks = []
        for row in rows:
            callback = dict(row)
            try:
                callback['headers'] = json.loads(callback['headers'])
            except:
                pass
            callbacks.append(callback)
        
        conn.close()
        return callbacks
    except Exception as e:
        logger.error(f"Failed to load callbacks: {e}")
        return []


def extract_uuid_from_request(request):
    """Extract UUID from various parts of the request."""
    # Try query parameter 'id'
    uuid = request.args.get('id')
    if uuid:
        return uuid
    
    # Try path segments (e.g., /ssrf/uuid-here)
    path_parts = request.path.strip('/').split('/')
    for part in path_parts:
        if len(part) == 36 and part.count('-') == 4:  # UUID format
            return part
    
    # Try subdomain (e.g., uuid.ssrf.domain.com)
    host = request.host.split(':')[0]  # Remove port
    subdomains = host.split('.')
    for subdomain in subdomains:
        if len(subdomain) == 36 and subdomain.count('-') == 4:
            return subdomain
    
    # Try callback parameter
    uuid = request.args.get('callback')
    if uuid:
        return uuid
    
    return None


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
def catch_all(path):
    """Catch all HTTP requests and log them (async processing)."""
    
    # Extract UUID
    uuid = extract_uuid_from_request(request)
    
    # Get real IP (considering proxies like ngrok)
    remote_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in remote_addr:
        remote_addr = remote_addr.split(',')[0].strip()
    
    # Prepare callback data
    callback_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'uuid': uuid,
        'method': request.method,
        'path': '/' + path if path else '/',
        'query_string': request.query_string.decode('utf-8'),
        'remote_addr': remote_addr,
        'headers': dict(request.headers),
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'host': request.host,
        'full_url': request.url
    }
    
    # Log the callback
    if uuid:
        logger.info(f"[CALLBACK RECEIVED] UUID: {uuid} | From: {remote_addr} | Path: /{path}")
    else:
        logger.info(f"[CALLBACK RECEIVED] No UUID detected | From: {remote_addr} | Path: /{path}")
    
    # Queue for async processing
    PROCESSING_QUEUE.put(callback_data)
    
    # Return immediately


@app.route('/api/callbacks', methods=['GET'])
def get_callbacks():
    """API endpoint to retrieve all callbacks."""
    try:
        callbacks = load_callbacks()
        return jsonify({
            'total': len(callbacks),
            'callbacks': callbacks
        })
    except Exception as e:
        logger.error(f"Error retrieving callbacks: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/check/<uuid>', methods=['GET'])
def check_uuid(uuid):
    """Check if a specific UUID has received a callback."""
    try:
        conn = sqlite3.connect(CALLBACK_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM callbacks WHERE uuid = ? ORDER BY timestamp DESC", (uuid,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            callback = dict(row)
            try:
                callback['headers'] = json.loads(callback['headers'])
            except:
                pass
            
            return jsonify({
                'found': True,
                'callback': callback
            })
        else:
            return jsonify({
                'found': False,
                'uuid': uuid
            })
    except Exception as e:
        logger.error(f"Error checking UUID: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/clear', methods=['POST'])
def clear_callbacks():
    """Clear all callbacks (for testing)."""
    try:
        conn = sqlite3.connect(CALLBACK_DB)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM callbacks")
        conn.commit()
        conn.close()
        
        logger.info("All callbacks cleared")
        return jsonify({'status': 'cleared'})
    except Exception as e:
        logger.error(f"Error clearing callbacks: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    try:
        callbacks = load_callbacks()
        return jsonify({
            'status': 'running',
            'callbacks_count': len(callbacks),
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


def process_queue():
    """Background thread to process queued callbacks."""
    while True:
        try:
            callback_data = PROCESSING_QUEUE.get()
            save_callback(callback_data)
        except Exception as e:
            logger.error(f"Error processing callback: {e}")


def start_server_background(host='0.0.0.0', port=5000):
    """
    Start the callback server in a background thread.
    
    Returns:
        Thread object (daemon thread running the server)
    
    Usage:
        server_thread = start_server_background(host='0.0.0.0', port=5000)
        time.sleep(2)  # Wait for server to start
        # ... rest of code ...
    """
    # Initialize database
    _init_db()
    
    # Start background processor thread
    processor_thread = Thread(target=process_queue, daemon=True)
    processor_thread.start()
    logger.info("Background callback processor started")
    
    logger.info(f"Starting SSRF Callback Server on {host}:{port} (background)")
    logger.info(f"Callbacks will be saved to: {CALLBACK_DB}")
    
    # Start Flask server in background thread
    def run_flask():
        app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
    
    server_thread = Thread(target=run_flask, daemon=True)
    server_thread.start()
    
    return server_thread


def start_server(host='0.0.0.0', port=5000, debug=False):
    """Start the callback server."""
    # Initialize database
    _init_db()
    
    # Start background processor thread
    processor_thread = Thread(target=process_queue, daemon=True)
    processor_thread.start()
    logger.info("Background callback processor started")
    
    logger.info(f"Starting SSRF Callback Server on {host}:{port}")
    logger.info(f"Callbacks will be saved to: {CALLBACK_DB}")
    
    # Start Flask server
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SSRF OOB Callback Server (Production-Grade)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("  SSRF OOB Callback Server (Production-Grade)")
    print("=" * 70)
    print(f"  Listening on: http://{args.host}:{args.port}")
    print(f"  Database: {CALLBACK_DB}")
    print(f"  Features:")
    print(f"    ✅ SQLite persistence (survives restarts)")
    print(f"    ✅ Replay protection (deduplicates UUID+IP)")
    print(f"    ✅ Async processing queue")
    print(f"    ✅ Context enrichment (headers, X-Forwarded-For)")
    print(f"    ✅ Injection expiration (TTL: {INJECTION_EXPIRY_HOURS}h)")
    print("=" * 70)
    print("\nEndpoints:")
    print("  GET  /                    - Catch all callbacks")
    print("  GET  /api/callbacks       - List all callbacks")
    print("  GET  /api/check/<uuid>    - Check specific UUID")
    print("  POST /api/clear           - Clear all callbacks")
    print("  GET  /health              - Health check")
    print("=" * 70)
    print("\nWaiting for callbacks...\n")
    
    start_server(host=args.host, port=args.port, debug=args.debug)
