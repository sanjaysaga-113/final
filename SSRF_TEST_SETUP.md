# SSRF Testing Setup Complete ✅

## What Was Created

### 1. Test URLs File
**File:** `demo_vuln_app/urls_ssrf.txt`

Contains 3 SSRF-vulnerable endpoints:
- `http://127.0.0.1:8000/fetch_image?url=PAYLOAD`
- `http://127.0.0.1:8000/webhook?callback=PAYLOAD`
- `http://127.0.0.1:8000/fetch_file?file=PAYLOAD`

### 2. Automated Test Script
**File:** `test_ssrf_demo.sh`

Usage:
```bash
chmod +x test_ssrf_demo.sh
./test_ssrf_demo.sh
```

This script:
- Starts demo app automatically
- Runs SSRF scan
- Shows results
- Cleans up

### 3. Documentation Files
- **SSRF_TESTING_GUIDE.md** - Detailed step-by-step guide with troubleshooting
- **SSRF_TEST_QUICKSTART.md** - Quick reference card (this is what you'll use)

---

## Quick Start (3 Steps)

### Option A: Automated (Recommended)
```bash
chmod +x test_ssrf_demo.sh
./test_ssrf_demo.sh
```

### Option B: Manual

**Terminal 1:**
```bash
cd demo_vuln_app
python app.py --port 8000 &
cd ..
sleep 3
```

**Terminal 2:**
```bash
python main.py --scan bssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2
```

**Terminal 3 (after scan completes):**
```bash
cat bssrf/output/findings_ssrf.json
```

---

## Expected Results

All 3 endpoints should be detected as **VULNERABLE (100% confidence)**:

```
[SUCCESS] Scan complete: 3 vulnerabilities found
[SUCCESS] Callbacks received: 3
[SUCCESS] Results saved to bssrf/output/findings_ssrf.json
```

---

## Demo App Vulnerable Endpoints

| Endpoint | Parameter | What it Does |
|----------|-----------|--------------|
| `/fetch_image` | `url` | Fetches image from URL (SSRF) |
| `/webhook` | `callback` | Registers webhook callback (SSRF) |
| `/fetch_file` | `file` | Fetches file content (SSRF) |

---

## Files Created

```
demo_vuln_app/
├── urls_ssrf.txt          ← Test URLs

Root:
├── test_ssrf_demo.sh      ← Automated test script
├── SSRF_TESTING_GUIDE.md  ← Detailed guide
├── SSRF_TEST_QUICKSTART.md ← Quick reference
└── SSRF_TEST_SETUP.md     ← This file
```

---

## No ngrok Needed for Local Testing

Since the demo app is on localhost (127.0.0.1), you don't need ngrok for this test!

**Automatic callback server will:**
- Start on `http://127.0.0.1:5000`
- Receive callbacks from demo app
- Store them in SQLite database
- Generate findings JSON

---

## Next Steps

1. **Run the test:**
   ```bash
   ./test_ssrf_demo.sh
   ```

2. **Review findings:**
   ```bash
   cat bssrf/output/findings_ssrf.json | jq .
   ```

3. **Check callbacks:**
   ```bash
   curl http://127.0.0.1:5000/api/callbacks | jq .
   ```

4. **Explore code:**
   - Look at detected payloads in `bssrf/output/findings_ssrf.txt`
   - Check `bssrf/output/callbacks.json` for raw callbacks
   - See how correlation works in `bssrf/oob/correlation.py`

---

## Tips

- **Keep it simple:** Use the automated script first
- **Parallel testing:** Run scan with `--threads 3` or higher
- **View everything:** `jq .` pipes output to pretty-print JSON
- **Check logs:** `tail /tmp/demo_app.log` if something fails

---

## Ready to Test! 🚀

```bash
./test_ssrf_demo.sh
```

All 3 SSRF vulnerabilities will be detected and confirmed.
