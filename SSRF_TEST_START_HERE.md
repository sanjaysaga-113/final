# SSRF Testing - Complete Setup ✅

## Everything is Ready!

I've created all the files and setup needed to test the SSRF module on the demo vulnerable app.

---

## 🚀 How to Test SSRF (3 Options)

### Option 1: One-Command Automated Test (EASIEST)
```bash
chmod +x test_ssrf_demo.sh && ./test_ssrf_demo.sh
```

This will:
1. Start demo vulnerable app
2. Run SSRF scan
3. Show results
4. Clean up automatically

**Expected output:**
```
[SUCCESS] Scan complete: 3 vulnerabilities found
[SUCCESS] Callbacks received: 3
```

---

### Option 2: Manual Testing (More Control)

**Terminal 1 - Start Demo App:**
```bash
cd demo_vuln_app
python app.py --port 8000 &
cd ..
sleep 3
```

**Terminal 2 - Verify App:**
```bash
curl http://127.0.0.1:8000/fetch_image?url=http://example.com/test.jpg
# Should return: {"status":"success",...}
```

**Terminal 3 - Run Scan:**
```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2
```

**View Results:**
```bash
cat bssrf/output/findings_ssrf.json | jq .
```

---

### Option 3: Advanced Testing

**With Recon:**
```bash
python main.py --recon -u http://127.0.0.1:8000 \
  --scan ssrf \
  --listener http://127.0.0.1:5000 \
  --wait 30
```

**With Advanced Payloads:**
```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --advanced
```

---

## 📋 Files Created

| File | Purpose |
|------|---------|
| `demo_vuln_app/urls_ssrf.txt` | Test URLs with 3 vulnerable endpoints |
| `test_ssrf_demo.sh` | Automated test script |
| `SSRF_TEST_QUICKSTART.md` | Quick reference card |
| `SSRF_TESTING_GUIDE.md` | Detailed step-by-step guide |
| `SSRF_TEST_SETUP.md` | This setup summary |

---

## 🎯 What Will Be Detected

The demo app has **3 SSRF vulnerabilities** that will be detected:

```
1. /fetch_image?url=PAYLOAD
   └─ Status: VULNERABLE (100%)
   └─ Action: Fetches external URLs

2. /webhook?callback=PAYLOAD
   └─ Status: VULNERABLE (100%)
   └─ Action: Registers webhook callbacks

3. /fetch_file?file=PAYLOAD
   └─ Status: VULNERABLE (100%)
   └─ Action: Reads file URLs
```

All 3 will be found and confirmed via OOB callbacks.

---

## 📊 Expected Results

**Console Output:**
```
[INFO] Starting BSSRF scan...
[INFO] Starting OOB callback server...
[SUCCESS] Callback server started
[INFO] Scanning 3 endpoints
[*] Testing: http://127.0.0.1:8000/fetch_image?url=
  [+] Injection point detected
  [+] Callback received!
  [+] Confidence: 100%
[SUCCESS] Scan complete: 3 vulnerabilities found
[SUCCESS] Results saved to bssrf/output/findings_ssrf.json
```

**JSON Output:**
```json
{
  "total_vulnerabilities": 3,
  "vulnerabilities": [
    {
      "url": "http://127.0.0.1:8000/fetch_image?url=",
      "parameter": "url",
      "confidence": 100,
      "vulnerability_type": "SSRF"
    },
    ...
  ]
}
```

---

## ✅ No Extra Setup Needed!

- ✅ Demo URLs file already created
- ✅ Test script ready to run
- ✅ No ngrok needed (local testing)
- ✅ Automatic callback server
- ✅ All dependencies installed

---

## 📍 Locations of Results

After running the scan, find results here:

```
bssrf/output/
├── findings_ssrf.json      ← Machine-readable results
├── findings_ssrf.txt       ← Human-readable results
└── callbacks.json          ← Raw callbacks received
```

View with:
```bash
cat bssrf/output/findings_ssrf.json | jq .
```

---

## 🔧 Troubleshooting

### Port Already in Use
```bash
# Check what's using port 8000
lsof -i :8000
kill -9 <PID>
```

### App Won't Start
```bash
# Check logs
cat /tmp/demo_app.log

# Try different port
python demo_vuln_app/app.py --port 8001 &
# Update urls_ssrf.txt to use 8001
```

### No Results Found
```bash
# Verify app is responding
curl http://127.0.0.1:8000/

# Check callback server is running
curl http://127.0.0.1:5000/api/callbacks
```

---

## 🎓 What You'll Learn

By running this test, you'll see:
1. How SSRF payloads are injected
2. How OOB callback server works
3. How callbacks are correlated with injections
4. How confidence scores are calculated
5. How findings are stored in JSON/TXT

---

## 🚀 READY TO TEST!

**Just run:**
```bash
chmod +x test_ssrf_demo.sh
./test_ssrf_demo.sh
```

**Or manually:**
```bash
cd demo_vuln_app && python app.py --port 8000 & && cd .. && sleep 3
python main.py --scan ssrf -f demo_vuln_app/urls_ssrf.txt --listener http://127.0.0.1:5000 --wait 30 --threads 2
```

---

## 📚 Documentation

For detailed guides, see:
- `SSRF_TEST_QUICKSTART.md` - Quick reference
- `SSRF_TESTING_GUIDE.md` - Complete guide with examples
- `README.md` - General project documentation
