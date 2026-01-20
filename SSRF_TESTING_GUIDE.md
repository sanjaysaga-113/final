# Testing SSRF Module on Demo Vulnerable App

## Step 1: Create SSRF Test URLs File

Create `demo_vuln_app/urls_ssrf.txt` with the vulnerable SSRF endpoints:

```
http://127.0.0.1:8000/fetch_image?url=PAYLOAD
http://127.0.0.1:8000/webhook?callback=PAYLOAD
http://127.0.0.1:8000/fetch_file?file=PAYLOAD
```

Save this to `demo_vuln_app/urls_ssrf.txt`

## Step 2: Start the Demo Vulnerable App

```bash
cd demo_vuln_app
python app.py --port 8000 &
# Wait 2-3 seconds for Flask to start
# You should see: "Running on http://0.0.0.0:8000"

cd ..
```

## Step 3: Verify App is Running

Test one of the endpoints manually:

```bash
# Test /fetch_image endpoint
curl "http://127.0.0.1:8000/fetch_image?url=http://example.com/image.jpg"

# Expected response:
# {"status":"success","url":"http://example.com/image.jpg","status_code":200,...}
```

## Step 4: Test SSRF with Local Callback (No ngrok needed)

```bash
# Terminal 1: Start the demo app (already running from Step 2)

# Terminal 2: Run SSRF scan
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2

# What to expect:
# [INFO] Starting OOB callback server...
# [SUCCESS] Callback server started
# [INFO] Scanning for SSRF vulnerabilities...
# [SSRF] Vulnerable endpoint detected: /fetch_image?url=
# [SUCCESS] Callbacks received: X
# [SUCCESS] Results saved to bssrf/output/findings_ssrf.json
```

## Step 5: Check Results

```bash
# View findings
cat bssrf/output/findings_ssrf.json

# View raw callbacks received
curl http://127.0.0.1:5000/api/callbacks

# Check specific injection
curl http://127.0.0.1:5000/api/check/{UUID}
```

## Full Automated Testing Script

Create `test_ssrf_demo.sh`:

```bash
#!/bin/bash

echo "[*] Step 1: Creating SSRF test URLs file..."
cat > demo_vuln_app/urls_ssrf.txt << 'EOF'
http://127.0.0.1:8000/fetch_image?url=PAYLOAD
http://127.0.0.1:8000/webhook?callback=PAYLOAD
http://127.0.0.1:8000/fetch_file?file=PAYLOAD
EOF

echo "[*] Step 2: Starting demo vulnerable app..."
cd demo_vuln_app
python app.py --port 8000 > /tmp/demo_app.log 2>&1 &
DEMO_PID=$!
sleep 3
cd ..

echo "[*] Step 3: Verifying app is running..."
if curl -s "http://127.0.0.1:8000/" > /dev/null 2>&1; then
    echo "[+] Demo app started (PID: $DEMO_PID)"
else
    echo "[-] Failed to start demo app!"
    exit 1
fi

echo "[*] Step 4: Running SSRF scan..."
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 2

echo "[*] Step 5: Results..."
echo ""
echo "[+] SSRF Findings:"
cat bssrf/output/findings_ssrf.json | python -m json.tool 2>/dev/null || cat bssrf/output/findings_ssrf.json

echo ""
echo "[+] All callbacks received:"
curl -s http://127.0.0.1:5000/api/callbacks | python -m json.tool 2>/dev/null || echo "No callbacks"

echo ""
echo "[*] Cleaning up..."
kill $DEMO_PID 2>/dev/null

echo "[+] Test complete!"
```

Run it:
```bash
chmod +x test_ssrf_demo.sh
./test_ssrf_demo.sh
```

## Expected Vulnerability Detection

The demo app has 3 SSRF-vulnerable endpoints:

### 1. `/fetch_image?url=PAYLOAD`
- **Vulnerability:** Direct URL fetching without validation
- **Detection:** Server makes requests to attacker's callback server
- **Expected:** VULNERABLE (100% confidence)

### 2. `/webhook?callback=PAYLOAD`
- **Vulnerability:** Registers callback URL and triggers requests
- **Detection:** Server POSTs to injected callback URL
- **Expected:** VULNERABLE (100% confidence)

### 3. `/fetch_file?file=PAYLOAD`
- **Vulnerability:** Fetches content from user-supplied file URL
- **Detection:** Can access internal services, metadata endpoints
- **Expected:** VULNERABLE (100% confidence)

## Troubleshooting

### Issue: Port 8000 already in use
```bash
# Find and kill process using port 8000
lsof -i :8000
kill -9 <PID>

# Or use different port
python demo_vuln_app/app.py --port 8001 &
# Then update urls_ssrf.txt to use 8001
```

### Issue: Callback server fails to start
```bash
# Check if port 5000 is in use
netstat -an | grep 5000

# Kill existing process or use different port
python main.py --scan bssrf -f demo_vuln_app/urls_ssrf.txt --listener http://127.0.0.1:6000 --wait 30
```

### Issue: No callbacks received
```bash
# Check demo app logs
tail /tmp/demo_app.log

# Verify app received requests
curl "http://127.0.0.1:8000/fetch_image?url=http://127.0.0.1:5000/callback"

# Check if callback server is listening
curl http://127.0.0.1:5000/health
```

## Advanced Testing

### Test with Advanced Payloads
```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --advanced
```

### Test with Recon First
```bash
# This will discover additional endpoints
python main.py --recon -u http://127.0.0.1:8000 --scan ssrf --listener http://127.0.0.1:5000 --wait 30
```

### Multi-threaded Performance Test
```bash
python main.py --scan ssrf \
  -f demo_vuln_app/urls_ssrf.txt \
  --listener http://127.0.0.1:5000 \
  --wait 30 \
  --threads 5
```

## Expected Output Example

```
[INFO] Starting BSSRF scan...
[INFO] Scanning 3 endpoints
[INFO] Starting OOB callback server...
[INFO] Callback server listening on http://127.0.0.1:5000
[SUCCESS] Callback server started

[*] Testing: http://127.0.0.1:8000/fetch_image?url=
  [SSRF] Found parameter: url
  [+] Injection point detected
  [+] Callback received!
  [+] Confidence: 100%

[*] Testing: http://127.0.0.1:8000/webhook?callback=
  [SSRF] Found parameter: callback
  [+] Injection point detected
  [+] Callback received!
  [+] Confidence: 100%

[*] Testing: http://127.0.0.1:8000/fetch_file?file=
  [SSRF] Found parameter: file
  [+] Injection point detected
  [+] Callback received!
  [+] Confidence: 100%

[SUCCESS] Scan complete: 3 vulnerabilities found
[SUCCESS] Callbacks received: 3
[SUCCESS] Results saved to bssrf/output/findings_ssrf.json
```

## Next Steps

1. **Review findings:**
   ```bash
   cat bssrf/output/findings_ssrf.json | jq .
   ```

2. **Compare with findings file:**
   ```bash
   diff bssrf/output/findings_ssrf.json bssrf/output/findings_ssrf.txt
   ```

3. **Check database:**
   ```bash
   sqlite3 bssrf/output/callbacks.db "SELECT * FROM callbacks LIMIT 5;"
   ```

4. **Export callbacks:**
   ```bash
   curl http://127.0.0.1:5000/api/callbacks > ssrf_callbacks.json
   ```
