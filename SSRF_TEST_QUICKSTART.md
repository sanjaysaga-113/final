# Quick SSRF Testing on Demo App - Quick Start

## TL;DR - 3 Steps

### Step 1: Start Demo App
```bash
cd demo_vuln_app
python app.py --port 8000 &
cd ..
sleep 3
```

### Step 2: Run SSRF Scan
```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2
```

### Step 3: View Results
```bash
cat bssrf/output/findings_ssrf.json
```

---

## Automated Script (Recommended)

```bash
chmod +x test_ssrf_demo.sh
./test_ssrf_demo.sh
```

This script will:
- ✅ Start demo app
- ✅ Run SSRF scan
- ✅ Show results
- ✅ Clean up automatically

---

## Manual Step-by-Step

### Terminal 1: Start Demo App
```bash
cd demo_vuln_app
python app.py --port 8000
# Wait for: Running on http://0.0.0.0:8000
```

### Terminal 2: Verify App is Running
```bash
curl http://127.0.0.1:8000/
# Should return HTML or JSON response
```

### Terminal 3: Run Scan
```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2

# Output:
# [INFO] Starting OOB callback server...
# [SUCCESS] Callback server started
# [INFO] Scanning for SSRF...
# [SUCCESS] Results saved to bssrf/output/findings_ssrf.json
```

---

## Test Targets

The demo app has **3 SSRF-vulnerable endpoints**:

| Endpoint | Parameter | Expected |
|----------|-----------|----------|
| `/fetch_image` | `url` | Fetches external URLs → VULNERABLE |
| `/webhook` | `callback` | Registers callbacks → VULNERABLE |
| `/fetch_file` | `file` | Reads file URLs → VULNERABLE |

All should be detected with **100% confidence**.

---

## Check Results

### View Findings
```bash
cat bssrf/output/findings_ssrf.json | jq .
```

### View Callbacks
```bash
curl http://127.0.0.1:5000/api/callbacks | jq .
```

### View Raw Output
```bash
cat bssrf/output/findings_ssrf.txt
```

---

## Troubleshooting

### Port 8000 Already in Use
```bash
# Find and kill existing process
lsof -i :8000
kill -9 <PID>

# Or use different port
python demo_vuln_app/app.py --port 8001 &
# Update urls_ssrf.txt to use 8001
```

### Port 5000 Already in Use
```bash
# Use different port for callback
python main.py --scan bssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:6000 \
  --wait 30 \
  --threads 2
```

### No Findings Detected
```bash
# Check demo app is running
curl http://127.0.0.1:8000/fetch_image?url=http://example.com/test.jpg

# Check callback server logs
curl http://127.0.0.1:5000/api/callbacks

# Check scanner output
cat bssrf/output/findings_ssrf.txt
```

---

## Advanced Options

### With Advanced Payloads
```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --advanced
```

### With Recon First
```bash
python main.py --recon -u http://127.0.0.1:8000 \
  --scan ssrf \
  --listener http://127.0.0.1:5000 \
  --wait 30
```

### With More Threads
```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 5
```

---

## Expected Results

```json
{
  "total_vulnerabilities": 3,
  "vulnerabilities": [
    {
      "url": "http://127.0.0.1:8000/fetch_image?url=",
      "parameter": "url",
      "confidence": "100%",
      "vulnerability_type": "SSRF"
    },
    {
      "url": "http://127.0.0.1:8000/webhook?callback=",
      "parameter": "callback",
      "confidence": "100%",
      "vulnerability_type": "SSRF"
    },
    {
      "url": "http://127.0.0.1:8000/fetch_file?file=",
      "parameter": "file",
      "confidence": "100%",
      "vulnerability_type": "SSRF"
    }
  ]
}
```

---

## Files Reference

- **Test URLs:** `demo_vuln_app/urls_ssrf.txt`
- **Demo App:** `demo_vuln_app/app.py`
- **Test Script:** `test_ssrf_demo.sh`
- **Findings:** `bssrf/output/findings_ssrf.json`
- **Callbacks:** `bssrf/output/callbacks.json`

---

**For detailed guide:** See `SSRF_TESTING_GUIDE.md`
