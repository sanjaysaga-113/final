# README UPDATE: Control Flow & Recon Improvements

## New Features Added (January 20, 2026)

### 1. Optional, User-Controlled Reconnaissance

#### Before:
```bash
python main.py -u example.com --scan sqli  # Recon ran automatically
```

#### After:
```bash
# Option A: Direct scan with full URL (no recon needed)
python main.py -u 'https://example.com/search?q=test' --scan sqli

# Option B: Recon with base domain (required)
python main.py -u example.com --recon --recon-mode passive --scan sqli

# Option C: Recon with mode selection
python main.py -u example.com --recon --recon-mode active --scan sqli
```

### 2. Intelligent Input Recognition

The scanner now recognizes:

**Full URL with Parameters** (e.g., `https://example.com/search?q=test`)
- Can scan directly without recon
- Recon is optional but supported

**Base Domain** (e.g., `example.com`)
- Requires `--recon` flag to discover URLs
- Clear error message if missing

**URL File**
- Can be read directly without recon
- Or filtered/processed with recon enabled

### 3. Recon Mode Selection

#### `--recon-mode passive` (default)
- Runs GAU (Google Alert URLs)
- Filters with GF patterns
- Scores parameters by risk
- Fast, non-destructive

#### `--recon-mode active`
- Runs passive recon first
- Then blind reconnaissance probing
- Discovers more endpoints
- More thorough, may take longer

#### `--recon-mode both`
- Alias for `active`
- Full reconnaissance

---

## Updated Usage Examples

### SQLi Scanning

```bash
# Direct scan (no discovery needed)
python main.py -u 'https://example.com/search?q=test' --scan sqli

# With passive recon (GAU + GF)
python main.py -u example.com --recon --recon-mode passive --scan sqli

# From URL file (no recon)
python main.py -f targets.txt --scan sqli --threads 10

# From domain file (with recon)
python main.py -f domains.txt --recon --recon-mode passive --scan sqli

# Raw HTTP request (sqlmap -r format)
python main.py --raw request.txt --scan sqli
```

### Blind XSS Scanning

```bash
# With active recon + callback server
python main.py -u example.com --recon --recon-mode active \
  --scan bxss --listener https://abc123.ngrok.io --wait 120

# Direct targets (no recon)
python main.py -f bxss_targets.txt --scan bxss \
  --listener https://abc123.ngrok.io --wait 30
```

### Blind SSRF Scanning

```bash
# With passive recon
python main.py -u example.com --recon --recon-mode passive \
  --scan ssrf --listener http://attacker.com:5000

# Direct targets from file
python main.py -f ssrf_targets.txt --scan ssrf \
  --listener http://attacker.com:5000 --wait 30
```

---

## Logging Output

The scanner now clearly indicates recon status:

```
[INFO] [RECON] Enabled with mode: passive | URLs discovered: 42
[INFO] SQLi scan started with 10 threads...
```

vs.

```
[INFO] [*] Recon disabled | Target URLs: 5
[INFO] SQLi scan started with 10 threads...
```

---

## Repository Improvements

### New .gitignore

The repository now properly excludes:

```
# Output artifacts
**/output/*.json
**/output/*.txt
**/output/*.csv

# Generated databases
*.db
callbacks.db

# Cache & environment
__pycache__/
.venv/
.pytest_cache/

# IDE & system files
.vscode/
.idea/
.DS_Store
```

**Result:** Only source code and documentation are tracked. Generated findings don't clutter git history.

---

## Documentation Files

New comprehensive guides added:

1. **CONTROL_FLOW_RESTRUCTURING.md**
   - Detailed implementation guide
   - All scenarios explained
   - Usage patterns documented

2. **TESTING_GUIDE.md**
   - Test commands for all scenarios
   - Expected outputs
   - Automated test script

3. **THESIS_DEFENSE_SUMMARY.md**
   - Executive summary
   - Key achievements
   - Code quality metrics

---

## Help Message

Updated `python main.py --help` now shows:

```
options:
  -u URL, --url URL
                        Target domain/URL (e.g., example.com or
                        https://example.com/search?q=test)
  
  --recon               Enable reconnaissance (GAU + GF + scoring)
  
  --recon-mode {passive,active,both}
                        Recon strategy: passive (GAU+GF only), active
                        (passive + blind recon), both (alias for active)
  
  --scan {sqli,bxss,ssrf}
                        Scan module choice
  
  -f FILE, --file FILE  Batch scanning from URL/domain file
  
  --listener URL        Callback server for BXSS/SSRF
  
  --wait SECONDS        Wait time for OOB callbacks (default: 30)
  
  --raw FILE            Raw HTTP request (sqlmap -r format)
```

---

## Decision Tree

```
                    ┌─── PROVIDE TARGET ───┐
                    │                       │
              ┌─────────────┐          ┌───────────────┐
              │ Full URL    │          │ Base Domain   │
              │ (has ?=)    │          │               │
              └─────────────┘          └───────────────┘
                    │                        │
          ┌─────────┴──────┬────────────────┴──────────┐
          │                │                           │
      [--recon]?      [--recon]?                 (REQUIRED)
     /    |    \      /    |    \                     |
   No    Yes   Both No    Yes   Both          ┌──────────────┐
    │     │     │   │     │     │              │ Must include │
    │     │     │   │     │     │              │  --recon     │
    ▼     │     │   │     │     │              │   flag       │
  DIRECT  │     │   │     │     │              └──────────────┘
  SCAN    │     │   │     │     │                     │
          │     │   │    ERROR  │                     ▼
          │     │   │    MSG    │                   RECON
          │     │   └──────│────┘                   MODE
          │     │          │                        CHOICE
          │     │    ┌──────┴──────┐
          │     │    │             │
          │     │  RECON        RECON
          │     │  PASSIVE      ACTIVE
          │     │    │             │
          │     └────┬──────┬──────┘
          │          │      │
          └──────────┼──────┤
                     │      │
                   SCAN & DETECT
```

---

## Control Flow Logic

### Input Processing

```python
# Step 1: Identify input type
if has_file:
    input_source = "file"
elif has_url:
    input_source = "url"
    is_full_url = "?" in url and "=" in url
else:
    error("Missing target")

# Step 2: Check recon flag
if args.recon:
    recon_mode = args.recon_mode or "passive"
    urls = discover_and_filter(input_source, recon_mode)
elif input_source == "url" and not is_full_url:
    error("Base domain requires --recon")
else:
    urls = read_directly(input_source)

# Step 3: Route to scanner
scan_module.scan(urls)
```

---

## Error Messages

When user makes a mistake, they get helpful guidance:

**Scenario:** Base domain without `--recon`
```
[ERROR] Base domain provided without --recon flag. Provide either:
  -u 'https://example.com/search?q=test'  (full URL, direct scan)
  -u 'example.com' --recon               (base domain, discover URLs)
```

**Scenario:** Missing listener for BXSS
```
[ERROR] BXSS scan requires --listener URL
Examples:
  --listener https://abc123.ngrok.io     (use ngrok)
  --listener https://interactsh.com      (Interactsh)
  --listener http://your-server:5000     (your own server)
```

---

## Migration Guide

If you have **existing scripts** using the old format:

### Old Format
```bash
python main.py -u example.com --scan sqli
```

### New Format (Option A - Direct with Full URL)
```bash
# If you know specific URLs to scan:
python main.py -u 'https://example.com/api/search?q=test' --scan sqli
```

### New Format (Option B - With Recon)
```bash
# If you want to discover URLs from domain:
python main.py -u example.com --recon --recon-mode passive --scan sqli
```

**Backward Compatibility Note:**
- The `--recon` flag is now **required** when using a base domain
- This is a **breaking change** by design (prevents accidental recon runs)
- All new commands are more explicit and predictable

---

## Thesis Defense Highlights

This restructuring demonstrates:

✅ **Software Architecture**
- Explicit control flow
- Clear separation of concerns
- User-friendly error handling

✅ **Security Engineering**
- Flexible reconnaissance options
- User control over scanning strategy
- Production-ready logging

✅ **Code Quality**
- No syntax errors
- Comprehensive documentation
- Repository hygiene (proper .gitignore)

✅ **Professionalism**
- Detailed change documentation
- Testing procedures included
- Ready for production deployment

---

## Quick Reference

| Task | Command |
|------|---------|
| Scan known URL | `main.py -u 'https://...' --scan sqli` |
| Discover + scan | `main.py -u domain.com --recon --scan sqli` |
| Batch scan | `main.py -f urls.txt --scan sqli` |
| XSS with recon | `main.py -u domain --recon --scan bxss --listener URL` |
| Raw request | `main.py --raw file.txt --scan sqli` |

---

## See Also

- [CONTROL_FLOW_RESTRUCTURING.md](CONTROL_FLOW_RESTRUCTURING.md) - Full documentation
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Verification procedures
- [THESIS_DEFENSE_SUMMARY.md](THESIS_DEFENSE_SUMMARY.md) - Defense presentation guide
