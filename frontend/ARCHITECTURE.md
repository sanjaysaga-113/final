# System Architecture
## Black-Box Web Vulnerability Scanner Frontend

```
┌─────────────────────────────────────────────────────────────────────┐
│                          USER BROWSER                                │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     Dashboard (HTML/CSS/JS)                   │  │
│  │                                                                │  │
│  │  ┌────────────────┐  ┌──────────────┐  ┌──────────────────┐ │  │
│  │  │ Configuration  │  │   Terminal   │  │     Results      │ │  │
│  │  │     Panel      │  │    Output    │  │      Table       │ │  │
│  │  │                │  │              │  │                  │ │  │
│  │  │ • URL/File     │  │ • Real-time  │  │ • Findings       │ │  │
│  │  │ • Recon        │  │ • Timestamped│  │ • Evidence       │ │  │
│  │  │ • Modules      │  │ • Color-coded│  │ • Downloads      │ │  │
│  │  └────────────────┘  └──────────────┘  └──────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│                    ↕ HTTP/HTTPS + WebSocket                          │
└───────────────────────────────────────────────────────────────────────┘
                                  ↕
┌─────────────────────────────────────────────────────────────────────┐
│                        FLASK APPLICATION                             │
│                          (app.py)                                    │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      REST API Routes                          │  │
│  │                                                                │  │
│  │  GET  /                    → Dashboard HTML                   │  │
│  │  POST /api/scan/start      → Initialize scan                  │  │
│  │  GET  /api/scan/status     → Get scan state                   │  │
│  │  POST /api/scan/stop       → Terminate scan                   │  │
│  │  GET  /api/results/<id>    → Retrieve findings                │  │
│  │  GET  /api/report/<id>     → Download report                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   WebSocket Handlers                          │  │
│  │                                                                │  │
│  │  connect           → Client connection                        │  │
│  │  subscribe_logs    → Register for log stream                  │  │
│  │  scan_log          → Broadcast log entry                      │  │
│  │  scan_status       → Broadcast status update                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                       │
│                              ↕                                        │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    SCANNER BRIDGE                             │  │
│  │                  (scanner_bridge.py)                          │  │
│  │                                                                │  │
│  │  • Process management                                         │  │
│  │  • Command builder                                            │  │
│  │  • Real-time streaming                                        │  │
│  │  • Result aggregation                                         │  │
│  │  • Report generation                                          │  │
│  └──────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
                                  ↕
                          subprocess.Popen()
                                  ↕
┌─────────────────────────────────────────────────────────────────────┐
│                     BACKEND SCANNER (main.py)                        │
│                                                                       │
│  Command: python main.py --url <target> --xss --sqli --recon-passive│
│                                                                       │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │   Recon Module   │  │  Vulnerability   │  │  Result Output   │  │
│  │                  │  │     Modules      │  │                  │  │
│  │ • Passive recon  │  │ • Blind XSS      │  │ • JSON files     │  │
│  │ • Active recon   │  │ • Blind SQLi     │  │ • Structured     │  │
│  │ • URL discovery  │  │ • Blind SSRF     │  │ • Timestamped    │  │
│  │                  │  │ • Command Inj    │  │                  │  │
│  │                  │  │ • XXE            │  │                  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                       │
│                  stdout/stderr → Scanner Bridge                      │
│                                                                       │
│  Output Directories:                                                 │
│    • bxss/output/findings*.json                                      │
│    • bsqli/output/findings*.json                                     │
│    • bssrf/output/findings*.json                                     │
│    • bcmdi/output/findings*.json                                     │
│    • bxe/output/findings*.json                                       │
└───────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════
DATA FLOW: COMPLETE SCAN LIFECYCLE
═══════════════════════════════════════════════════════════════════════

1. USER ACTION
   └─> Browser: User fills form and clicks "Start Scan"

2. FRONTEND VALIDATION
   └─> JavaScript validates input
       └─> Checks: URL format, file upload, module selection

3. HTTP REQUEST
   └─> POST /api/scan/start with JSON payload:
       {
         "input_type": "url",
         "target": "https://example.com",
         "recon": true,
         "recon_mode": "passive",
         "modules": ["bxss", "bsqli"]
       }

4. FLASK ROUTE HANDLER
   └─> app.py receives request
       └─> Validates payload
       └─> Calls scanner_bridge.start_scan()

5. SCANNER BRIDGE
   └─> Builds command:
       "python main.py --url https://example.com --xss --sqli --recon-passive"
   └─> Spawns subprocess
   └─> Captures stdout/stderr

6. REAL-TIME STREAMING
   └─> Scanner outputs: "[INFO] Starting Blind XSS module"
   └─> Scanner Bridge receives line
   └─> Emits via WebSocket: scan_log event
   └─> Browser receives and displays in terminal

7. BACKEND EXECUTION
   └─> main.py parses arguments
   └─> Runs selected modules
   └─> Writes findings to output directories
   └─> Prints progress to stdout

8. RESULT AGGREGATION
   └─> Scan completes
   └─> Scanner Bridge reads JSON files from:
       • bxss/output/findings*.json
       • bsqli/output/findings*.json
   └─> Aggregates all findings

9. STATUS UPDATE
   └─> WebSocket emit: scan_status = "completed"
   └─> Frontend calls GET /api/results/<scan_id>

10. RESULTS DISPLAY
    └─> Flask returns aggregated findings
    └─> JavaScript builds results table
    └─> User sees vulnerabilities in UI

11. REPORT DOWNLOAD
    └─> User clicks "Download JSON"
    └─> GET /api/report/download/<scan_id>/json
    └─> Scanner Bridge generates report
    └─> Browser downloads file


═══════════════════════════════════════════════════════════════════════
WEBSOCKET MESSAGE FLOW
═══════════════════════════════════════════════════════════════════════

Client → Server:
  • connect               (initial WebSocket handshake)
  • subscribe_logs        (register for log stream)

Server → Client:
  • connection_response   (confirm connection)
  • subscription_confirmed (confirm subscription)
  • scan_log              (real-time log entry)
    {
      "scan_id": "scan_...",
      "timestamp": "14:30:25",
      "level": "INFO",
      "message": "Starting module..."
    }
  • scan_status           (status update)
    {
      "scan_id": "scan_...",
      "status": "running|completed|failed"
    }


═══════════════════════════════════════════════════════════════════════
FILE SYSTEM LAYOUT
═══════════════════════════════════════════════════════════════════════

final year project/
├── main.py                      ← Backend scanner entry point
│
├── bxss/
│   └── output/
│       └── findings*.json       ← XSS results
│
├── bsqli/
│   └── output/
│       └── findings*.json       ← SQLi results
│
├── bssrf/
│   └── output/
│       └── findings*.json       ← SSRF results
│
├── bcmdi/
│   └── output/
│       └── findings*.json       ← CMDi results
│
├── bxe/
│   └── output/
│       └── findings*.json       ← XXE results
│
└── frontend/                    ← Flask web application
    ├── app.py                   ← Main Flask app
    ├── scanner_bridge.py        ← Backend integration
    ├── requirements.txt
    │
    ├── templates/
    │   └── dashboard.html       ← Single-page UI
    │
    ├── static/
    │   ├── css/
    │   │   └── style.css        ← Professional styling
    │   └── js/
    │       └── app.js           ← WebSocket client
    │
    ├── uploads/                 ← User-uploaded target files
    └── logs/                    ← Scan reports


═══════════════════════════════════════════════════════════════════════
TECHNOLOGY STACK
═══════════════════════════════════════════════════════════════════════

Backend:
  • Python 3.10+
  • Flask 3.0.0              (Web framework)
  • Flask-SocketIO 5.3.5     (WebSocket support)
  • Flask-CORS 4.0.0         (Cross-origin requests)
  • Gunicorn 21.2.0          (Production server)
  • Eventlet 0.33.3          (Async workers)

Frontend:
  • HTML5                    (Semantic markup)
  • CSS3 Grid                (Layout system)
  • Vanilla JavaScript       (No frameworks)
  • Socket.IO Client 4.5.4   (WebSocket library)

Integration:
  • subprocess module        (Process management)
  • JSON                     (Data interchange)
  • argparse                 (CLI argument parsing)


═══════════════════════════════════════════════════════════════════════
SECURITY ARCHITECTURE
═══════════════════════════════════════════════════════════════════════

Input Validation:
  ┌──────────────┐
  │ User Input   │
  └──────┬───────┘
         │
         ├─> URL validation (regex)
         ├─> File type check (.txt only)
         ├─> File size limit (16MB)
         ├─> Module validation (whitelist)
         └─> Filename sanitization
         │
         ↓
  ┌──────────────┐
  │ Validated    │
  └──────────────┘

Process Isolation:
  Flask App (user context)
    └─> subprocess.Popen(...)
        └─> Scanner Process (isolated)
            └─> No shell=True
            └─> Explicit command array
            └─> Timeout enforcement

File Security:
  • secure_filename() for uploads
  • Restricted upload directory
  • No executable permissions
  • Automatic cleanup (optional)

Web Security:
  • CSRF protection (Flask built-in)
  • XSS prevention (Jinja2 auto-escape)
  • CORS configuration
  • HTTPS support (via reverse proxy)
