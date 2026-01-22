#!/usr/bin/env python3
"""
Black-Box Web Vulnerability Scanner - Frontend Application
Production-quality Flask-based dashboard with real-time output streaming

Author: Security Research Team
Date: January 2026
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from werkzeug.utils import secure_filename

from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from scanner_bridge import ScannerBridge


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Application configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload
    UPLOAD_FOLDER = Path(__file__).parent / 'uploads'
    LOGS_FOLDER = Path(__file__).parent / 'logs'
    ALLOWED_EXTENSIONS = {'txt'}
    
    # WebSocket configuration
    SOCKETIO_ASYNC_MODE = 'threading'
    SOCKETIO_CORS_ALLOWED_ORIGINS = "*"  # Restrict in production


# ============================================================================
# APPLICATION INITIALIZATION
# ============================================================================

app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS for development (restrict in production)
CORS(app)

# Initialize SocketIO for real-time communication
socketio = SocketIO(
    app,
    async_mode=Config.SOCKETIO_ASYNC_MODE,
    cors_allowed_origins=Config.SOCKETIO_CORS_ALLOWED_ORIGINS,
    logger=True,
    engineio_logger=False
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Ensure required directories exist
Config.UPLOAD_FOLDER.mkdir(exist_ok=True)
Config.LOGS_FOLDER.mkdir(exist_ok=True)

# Scanner bridge instance
scanner_bridge = ScannerBridge(socketio, logger)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def allowed_file(filename: str) -> bool:
    """Check if uploaded file has allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def validate_url(url: str) -> bool:
    """Validate URL format"""
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_scan_request(data: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Validate incoming scan request payload
    
    Returns:
        (is_valid, error_message)
    """
    # Check input type
    if 'input_type' not in data or data['input_type'] not in ['url', 'file']:
        return False, "Invalid input type. Must be 'url' or 'file'"
    
    # Validate target
    if not data.get('target'):
        return False, "Target is required"
    
    # If URL input, validate URL format
    if data['input_type'] == 'url' and not validate_url(data['target']):
        return False, "Invalid URL format"
    
    # Validate recon settings
    if 'recon' not in data:
        return False, "Recon flag is required"
    
    if data.get('recon') and 'recon_mode' not in data:
        return False, "Recon mode is required when recon is enabled"
    
    if data.get('recon') and data['recon_mode'] not in ['passive', 'active']:
        return False, "Invalid recon mode. Must be 'passive' or 'active'"
    
    # Validate modules
    if 'modules' not in data or not data['modules']:
        return False, "At least one scan module must be selected"
    
    valid_modules = ['bxss', 'bsqli', 'bssrf', 'bcmdi', 'bxxe']
    if not all(m in valid_modules for m in data['modules']):
        return False, f"Invalid modules. Allowed: {', '.join(valid_modules)}"
    
    # Validate callback URL if XSS module is selected
    if 'bxss' in data.get('modules', []):
        if 'callback_url' not in data or not data['callback_url']:
            return False, "Callback URL is required for Blind XSS module"
        if not validate_url(data['callback_url']):
            return False, "Invalid callback URL format"
    
    return True, None


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    """Render main dashboard"""
    return render_template('dashboard.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """
    Initiate a new vulnerability scan
    
    Expected JSON payload:
    {
        "input_type": "url" | "file",
        "target": "value",
        "recon": true | false,
        "recon_mode": "passive" | "active",  # Required if recon=true
        "modules": ["bxss", "bsqli", ...]
    }
    """
    try:
        # Parse request data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            # Parse modules from comma-separated string if needed
            if 'modules' in data and isinstance(data['modules'], str):
                data['modules'] = [m.strip() for m in data['modules'].split(',')]
            # Convert boolean strings
            data['recon'] = data.get('recon', '').lower() == 'true'
        
        # Validate request
        is_valid, error_msg = validate_scan_request(data)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': error_msg
            }), 400
        
        # Handle file upload if input_type is 'file'
        if data['input_type'] == 'file':
            if 'file' not in request.files:
                return jsonify({
                    'success': False,
                    'error': 'No file uploaded'
                }), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'success': False,
                    'error': 'No file selected'
                }), 400
            
            if not allowed_file(file.filename):
                return jsonify({
                    'success': False,
                    'error': 'Invalid file type. Only .txt files allowed'
                }), 400
            
            # Save uploaded file
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = Config.UPLOAD_FOLDER / filename
            file.save(filepath)
            
            # Update target to filepath
            data['target'] = str(filepath)
        
        # Check if scanner is already running
        if scanner_bridge.is_running():
            return jsonify({
                'success': False,
                'error': 'A scan is already in progress'
            }), 409
        
        # Start scan in background
        scan_id = scanner_bridge.start_scan(data)
        
        logger.info(f"Scan initiated: {scan_id}")
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Get current scan status"""
    try:
        status = scanner_bridge.get_status()
        return jsonify(status), 200
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    """Stop the current scan"""
    try:
        scanner_bridge.stop_scan()
        return jsonify({
            'success': True,
            'message': 'Scan stopped successfully'
        }), 200
    except Exception as e:
        logger.error(f"Error stopping scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/results/<scan_id>', methods=['GET'])
def get_results(scan_id):
    """Retrieve scan results"""
    try:
        results = scanner_bridge.get_results(scan_id)
        if results is None:
            return jsonify({
                'success': False,
                'error': 'Results not found'
            }), 404
        
        return jsonify({
            'success': True,
            'results': results
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving results: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/report/download/<scan_id>/<format>', methods=['GET'])
def download_report(scan_id, format):
    """
    Download scan report in specified format
    
    Args:
        scan_id: Unique scan identifier
        format: 'json' or 'txt'
    """
    try:
        if format not in ['json', 'txt']:
            return jsonify({
                'success': False,
                'error': 'Invalid format. Use json or txt'
            }), 400
        
        report_path = scanner_bridge.generate_report(scan_id, format)
        
        if not report_path or not os.path.exists(report_path):
            return jsonify({
                'success': False,
                'error': 'Report not found'
            }), 404
        
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f'scan_report_{scan_id}.{format}'
        )
        
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# ============================================================================
# WEBSOCKET HANDLERS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connection_response', {
        'status': 'connected',
        'message': 'WebSocket connection established'
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")


@socketio.on('subscribe_logs')
def handle_subscribe():
    """Client subscribes to real-time log updates"""
    logger.info(f"Client subscribed to logs: {request.sid}")
    emit('subscription_confirmed', {
        'message': 'Subscribed to real-time logs'
    })


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Resource not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Run with SocketIO
    logger.info("Starting Black-Box Vulnerability Scanner Frontend")
    logger.info(f"Upload folder: {Config.UPLOAD_FOLDER}")
    logger.info(f"Logs folder: {Config.LOGS_FOLDER}")
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True  # For development only
    )
