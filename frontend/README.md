# Black-Box Web Vulnerability Scanner - Frontend

Production-quality Flask-based web dashboard for the Black-Box Web Vulnerability Scanner Final Year Project.

## 📁 Directory Structure

```
frontend/
├── app.py                  # Main Flask application with routes & WebSocket
├── scanner_bridge.py       # Backend scanner integration module
├── requirements.txt        # Python dependencies
├── templates/
│   └── dashboard.html      # Single-page dashboard UI
├── static/
│   ├── css/
│   │   └── style.css      # Professional styling
│   └── js/
│       └── app.js         # WebSocket & UI logic
├── uploads/               # User-uploaded target files
└── logs/                  # Scan reports and logs
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd frontend
pip install -r requirements.txt
```

### 2. Run the Application

**Development Mode** (with auto-reload):
```bash
python app.py
```

**Production Mode**:
```bash
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
```

### 3. Access Dashboard

Open your browser and navigate to:
```
http://localhost:5000
```

## 🎯 Features

### ✅ Target Input
- **Single URL Input**: Test individual endpoints
- **File Upload**: Upload `.txt` file with multiple URLs (one per line)
- Automatic validation

### ✅ Reconnaissance Control
- **Checkbox**: Enable/Disable recon explicitly
- **Radio Options**:
  - Passive Recon Only (non-intrusive)
  - Passive + Active Recon (includes crawling)
- When disabled, scanner skips recon and tests provided targets directly

### ✅ Module Selection
- Blind XSS (OOB callbacks)
- Blind SQL Injection (time-based)
- Blind SSRF
- Command Injection
- XXE
- At least one module required

### ✅ Real-Time Output
- Terminal-style display (black background, monospace font)
- WebSocket-powered live streaming
- Timestamped log entries
- Color-coded by severity (INFO, SUCCESS, WARNING, ERROR)
- Auto-scroll with manual lock option
- Clear logs button

### ✅ Results Display
- Structured table with:
  - Vulnerability type
  - Target URL
  - Parameter name
  - Status (CONFIRMED/POTENTIAL)
  - Evidence (callback URL, delay time, etc.)
- Download reports:
  - JSON format (structured data)
  - TXT format (human-readable)

### ✅ Scan Control
- Start/Stop buttons
- Form disabling during scan
- Status indicator with real-time updates
- Reset functionality

## 🔧 Technical Architecture

### Backend (Flask)

**app.py** - Main application:
- Route handlers (`/`, `/api/scan/start`, `/api/scan/status`, etc.)
- WebSocket event handlers
- Input validation
- File upload management
- Error handling

**scanner_bridge.py** - Scanner integration:
- Subprocess management
- Real-time output streaming via WebSocket
- Result aggregation from module outputs
- Report generation
- Scan lifecycle management

### Frontend

**dashboard.html** - Single-page UI:
- Semantic HTML5
- Responsive design
- Accessibility considerations

**style.css** - Professional styling:
- CSS Grid layout
- Dark theme optimized for security tools
- Terminal aesthetics
- Mobile-responsive

**app.js** - Client-side logic:
- WebSocket connection management
- Form validation
- Real-time log rendering
- Results table generation
- Download functionality

## 🔌 Backend Integration

The frontend integrates with your existing scanner via `scanner_bridge.py`, which:

1. **Builds scanner command** based on user configuration:
   ```python
   python main.py --url <target> --xss --sqli --recon-passive
   ```

2. **Spawns subprocess** with proper environment

3. **Streams stdout/stderr** to WebSocket clients in real-time

4. **Aggregates results** from module output directories:
   - `bxss/output/findings*.json`
   - `bsqli/output/findings*.json`
   - `bssrf/output/findings*.json`
   - `bcmdi/output/findings*.json`
   - `bxe/output/findings*.json`

5. **Generates reports** in JSON and TXT formats

### Expected Backend Modifications

To fully integrate with the frontend, your `main.py` should support:

```python
# Command-line arguments
--url <single_url>          # Single URL target
--file <path_to_file>       # File with multiple URLs
--no-recon                  # Skip recon entirely
--recon-passive             # Passive recon only
--recon-active              # Passive + active recon
--xss                       # Enable Blind XSS module
--sqli                      # Enable Blind SQLi module
--ssrf                      # Enable Blind SSRF module
--cmdi                      # Enable Command Injection module
--xxe                       # Enable XXE module
```

Example integration in `main.py`:

```python
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--url', help='Single target URL')
parser.add_argument('--file', help='File with target URLs')
parser.add_argument('--no-recon', action='store_true', help='Disable recon')
parser.add_argument('--recon-passive', action='store_true', help='Passive recon')
parser.add_argument('--recon-active', action='store_true', help='Active recon')
parser.add_argument('--xss', action='store_true', help='Blind XSS')
parser.add_argument('--sqli', action='store_true', help='Blind SQLi')
parser.add_argument('--ssrf', action='store_true', help='Blind SSRF')
parser.add_argument('--cmdi', action='store_true', help='Command Injection')
parser.add_argument('--xxe', action='store_true', help='XXE')

args = parser.parse_args()

# Handle recon logic
if args.no_recon:
    # Skip all recon
    pass
elif args.recon_passive:
    # Run passive recon
    run_passive_recon()
elif args.recon_active:
    # Run both passive and active recon
    run_passive_recon()
    run_active_recon()

# Execute selected modules
if args.xss:
    run_bxss_module()
if args.sqli:
    run_bsqli_module()
# ... etc
```

## 🔒 Security Considerations

### Input Validation
- URL format validation
- File type restrictions (`.txt` only)
- File size limits (16MB max)
- Module selection validation

### File Upload Security
- Secure filename handling (`werkzeug.secure_filename`)
- Timestamped filenames to prevent overwrites
- Isolated upload directory

### Process Isolation
- Scanner runs in separate subprocess
- No shell command injection vulnerabilities
- Proper process termination handling

### CORS & Authentication
- CORS currently set to `*` for development
- **Production**: Restrict to specific origins
- **TODO**: Add authentication (JWT, session-based, etc.)

## 📊 API Endpoints

### `GET /`
Returns the main dashboard HTML

### `POST /api/scan/start`
Start a new scan

**Request (JSON)**:
```json
{
  "input_type": "url",
  "target": "https://example.com/page?param=value",
  "recon": true,
  "recon_mode": "passive",
  "modules": ["bxss", "bsqli", "bssrf"]
}
```

**Request (FormData for file upload)**:
```
input_type: file
file: <File>
recon: true
recon_mode: active
modules: bxss,bsqli
```

**Response**:
```json
{
  "success": true,
  "scan_id": "scan_20260122_143025_a1b2c3d4",
  "message": "Scan started successfully"
}
```

### `GET /api/scan/status`
Get current scan status

**Response**:
```json
{
  "scan_id": "scan_20260122_143025_a1b2c3d4",
  "running": true,
  "status": "running"
}
```

### `POST /api/scan/stop`
Stop current scan

### `GET /api/results/<scan_id>`
Retrieve scan results

**Response**:
```json
{
  "success": true,
  "results": {
    "config": {...},
    "status": "completed",
    "findings": [
      {
        "module": "bxss",
        "url": "https://example.com/comment",
        "parameter": "text",
        "status": "CONFIRMED",
        "evidence": "http://callback.server/xss_abc123"
      }
    ]
  }
}
```

### `GET /api/report/download/<scan_id>/<format>`
Download report (format: `json` or `txt`)

## 🌐 WebSocket Events

### Client → Server

**`connect`**: Initial connection
**`subscribe_logs`**: Subscribe to log stream

### Server → Client

**`connection_response`**: Connection confirmation
**`subscription_confirmed`**: Subscription confirmation
**`scan_log`**: Real-time log entry
```json
{
  "scan_id": "scan_...",
  "timestamp": "14:30:25",
  "level": "INFO",
  "message": "Starting Blind XSS module"
}
```

**`scan_status`**: Status update
```json
{
  "scan_id": "scan_...",
  "status": "completed"
}
```

## 🐛 Troubleshooting

### WebSocket Connection Issues
- Ensure Flask-SocketIO is properly installed
- Check firewall settings
- Try polling transport: `io({ transports: ['polling'] })`

### Scan Not Starting
- Check backend `main.py` exists in parent directory
- Verify Python executable path
- Check module output directories exist

### No Results Displayed
- Verify modules write to `*/output/findings*.json`
- Check JSON format validity
- Review terminal logs for errors

### File Upload Fails
- Check file extension (must be `.txt`)
- Verify file size (<16MB)
- Ensure `uploads/` directory is writable

## 📝 TODO / Future Enhancements

- [ ] User authentication system
- [ ] Multi-user support with session isolation
- [ ] Scan history with database storage
- [ ] Advanced filters for results table
- [ ] Export to PDF/HTML reports
- [ ] Scan scheduling/automation
- [ ] Email notifications on completion
- [ ] API rate limiting
- [ ] Comprehensive logging

## 👥 Credits

**Final Year Project**  
Black-Box Web Vulnerability Scanner  
© 2026

## 📄 License

Educational/Academic Use Only
