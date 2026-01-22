# Demo Vulnerable App Updates - Blind CMDi Support

## Summary

The demo vulnerable app (`demo_vuln_app/app.py`) has been updated to include **Blind Command Injection (CMDi) vulnerable endpoints** for testing the new BCMDI module.

---

## Changes Made

### 1. Updated Home Page (`/`)
Added organized sections for each vulnerability type:
- SQL Injection (BSQLi)
- Blind XSS (BXSS)
- SSRF
- **NEW: Command Injection (CMDi)**

### 2. New CMDi Vulnerable Endpoints

#### `/ping?host=...`
- **Vulnerability**: Blind command injection in ping command
- **Parameter**: `host`
- **Payload Example**: `127.0.0.1; sleep 5`
- **Simulates**: Time-based delays when `sleep`, `timeout`, or `ping` commands are injected
- **Use Case**: Test CMDi detection via ping/network utilities

#### `/dns?domain=...`
- **Vulnerability**: Blind command injection in DNS lookup
- **Parameter**: `domain`
- **Payload Example**: `example.com; sleep 5`
- **Simulates**: Time-based delays when `sleep`, `timeout`, or `ping` commands are injected
- **Use Case**: Test CMDi detection via DNS commands

#### `/process?cmd=...`
- **Vulnerability**: Blind command injection in process parameter
- **Parameter**: `cmd`
- **Payload Example**: `ls; sleep 5`
- **Simulates**: Time-based delays when `sleep`, `timeout`, or `ping` commands are injected
- **Use Case**: Test CMDi detection via generic OS commands

### 3. Time-Based Delay Simulation

All three endpoints detect and simulate delays for injected commands:

```python
# Linux-style delays
- sleep 3, sleep 5, sleep 7

# Windows-style delays
- timeout /t 3, timeout /t 5, timeout /t 7
- ping -n 4, ping -n 6, ping -n 8 (approx 3, 5, 7 seconds)
```

### 4. New Files

#### `demo_vuln_app/urls_cmdi.txt`
Provides test URLs for CMDi scanning:
```
http://127.0.0.1:8000/ping?host=127.0.0.1
http://127.0.0.1:8000/dns?domain=example.com
http://127.0.0.1:8000/process?cmd=ls
```

#### `test_cmdi_against_demo_app.py`
Complete test harness that:
1. Starts the CMDi module
2. Scans each vulnerable endpoint
3. Collects and displays findings
4. Saves results to JSON
5. Provides status and timing information

---

## Testing the CMDi Module

### Quick Start

**Terminal 1: Start the demo app**
```bash
python demo_vuln_app/app.py --port 8000
```

**Terminal 2: Run CMDi tests**
```bash
python test_cmdi_against_demo_app.py
```

**Expected Output:**
```
[1/3] Testing: Ping Endpoint (time-based CMDi)
    URL: http://127.0.0.1:8000/ping?host=127.0.0.1
    Scanning (this may take 1-2 minutes)...
    ✓ Found 1 vulnerability(ies)!
      - Parameter: host
        Technique: time-based
        Confidence: HIGH
        Confirmations: 2

[2/3] Testing: DNS Endpoint (time-based CMDi)
    ...
    ✓ Found 1 vulnerability(ies)!

[3/3] Testing: Process Endpoint (time-based CMDi)
    ...
    ✓ Found 1 vulnerability(ies)!

Summary: Found 3 vulnerabilities
✓ Results saved to: bcmdi/output/findings_cmdi_demo.json
```

### Manual Testing

Test individual endpoints with curl:

```bash
# Normal request (no injection)
curl "http://127.0.0.1:8000/ping?host=127.0.0.1"

# Time-based injection (should delay ~3 seconds)
curl "http://127.0.0.1:8000/ping?host=127.0.0.1;sleep%203"

# Time-based injection with &&
curl "http://127.0.0.1:8000/ping?host=127.0.0.1%20%26%26%20sleep%205"
```

---

## How It Works

### Delay Simulation

Each endpoint parses the parameter for injected commands:

```python
# Example from /ping endpoint
host = request.args.get("host", "127.0.0.1")

# Check for sleep command
m = re.search(r"sleep\s+(\d+)", host, re.IGNORECASE)
if m:
    delay = int(m.group(1))
    time.sleep(delay)  # Actually sleep for N seconds

# Return success (simulating successful command execution)
return jsonify({"status": "success", "host": host})
```

### Detection Workflow

1. **BCMDI module sends payload**: `host=127.0.0.1;sleep 3`
2. **Demo app parses parameter**: Detects `sleep 3`
3. **Demo app delays response**: Sleeps for 3 seconds
4. **BCMDI module measures latency**: Delta from baseline = ~3 seconds
5. **BCMDI module confirms**: This is command injection (HIGH confidence)

---

## Integration with BCMDI Module

The endpoints are designed to work seamlessly with the CMDi module:

### Parameter Detection
- Each endpoint has exactly ONE vulnerable parameter
- Clear, obvious injection points (no encoding/obfuscation)
- Suitable for testing time-based detection

### Payload Compatibility
- Supports all BCMDI payload types:
  - `; sleep N` (semicolon separator)
  - `&& sleep N` (AND operator)
  - `|| sleep N` (OR operator)
  - `| sleep N` (pipe)
  - Newline separators

### Time-Based Simulation
- Responds to both Linux and Windows payloads
- Accurate timing (sleeps exactly as specified)
- No false positives (control payloads don't delay)

---

## Notes

- **DEMO ONLY**: This app is intentionally vulnerable. Do NOT expose publicly.
- **LOCAL TESTING**: Run only on `127.0.0.1:8000` for development.
- **TIME OVERHEAD**: Each CMDi scan takes 1-2 minutes per endpoint (3 × 3 payloads at delays).
- **ACCURATE TIMING**: Uses Python's `time.sleep()` for precise delays.
- **MULTI-SEPARATOR TESTING**: Each endpoint tests all separation strategies.

---

## Files Modified/Added

```
demo_vuln_app/
├── app.py                (UPDATED: Added 3 CMDi endpoints)
├── README.md             (UPDATED: New CMDi section)
└── urls_cmdi.txt         (NEW: Test URLs for CMDi)

Root project:
└── test_cmdi_against_demo_app.py  (NEW: CMDi test harness)
```

---

## Expected Test Results

Running `test_cmdi_against_demo_app.py` should produce:

1. **3 vulnerabilities found** (one per endpoint)
2. **HIGH confidence** for all (≥2 separator proofs)
3. **Results saved** to `bcmdi/output/findings_cmdi_demo.json`
4. **Features saved** to `bcmdi/output/features.csv` (ML training data)

---

## Next Steps

After successful testing against the demo app:

1. **Review Results**: Check `bcmdi/output/findings_cmdi_demo.json`
2. **Verify Confidence**: Ensure all findings show HIGH confidence
3. **Check Features**: Review `bcmdi/output/features.csv` for ML integration
4. **Integrate into Scanner**: Add to `main.py` (see INTEGRATION_EXAMPLES.md)
5. **Deploy to Production**: Follow deployment checklist

---

## Troubleshooting

### "Connection refused" error
- Ensure demo app is running: `python demo_vuln_app/app.py --port 8000`
- Check port 8000 is not in use: `lsof -i :8000`

### "Timeout" during scan
- Normal - CMDi testing takes time (baseline + multiple payloads)
- Allow 1-2 minutes per endpoint
- Total test duration: ~5-10 minutes

### "No vulnerabilities found"
- Check demo app is receiving requests (check app logs)
- Verify network connectivity to `127.0.0.1:8000`
- Ensure BCMDI module timeout is sufficient (15s+ recommended)

### "False positives/negatives"
- Adjust detector parameters in `bcmdi/modules/blind_cmdi/detector.py`:
  - `BASELINE_SAMPLES = 3` (increase for noisier networks)
  - `MIN_CONFIRMATIONS = 2` (increase for stricter detection)
  - `TIME_JITTER_TOLERANCE = 1.5` (increase for noisy networks)
