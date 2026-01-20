# Control Flow Restructuring & Repository Cleanup

## Summary

This document outlines the restructuring of the Black-Box Vulnerability Scanner to make reconnaissance **optional and user-controlled**, along with repository hygiene improvements.

---

## PART 1: Recon Control Flow Restructuring

### New CLI Options

#### `--recon`
Explicitly enables reconnaissance. Recon is **NOT** run by default.

```bash
python main.py -u example.com --recon --scan sqli
```

#### `--recon-mode`
Selects the reconnaissance strategy (only used with `--recon`):

- **`passive`** (default): Run GAU + GF filtering + parameter scoring. No active probing.
- **`active`**: Run passive recon first, then blind reconnaissance on discovered endpoints.
- **`both`**: Alias for `active`.

```bash
python main.py -u example.com --recon --recon-mode active --scan ssrf
```

---

### Input Handling Logic

The control flow now distinguishes between **different input types**:

#### Scenario 1: Full URL with Parameters (NO recon needed)

**Input:** `-u 'https://example.com/search?q=test'`

**Without `--recon`:**
```bash
python main.py -u 'https://example.com/search?q=test' --scan sqli
```

**Behavior:**
- ✅ Skip all recon
- ✅ Directly scan the supplied URL with the detection module
- ✅ Log: `[*] Recon disabled — using user-supplied target`

#### Scenario 2: Base Domain (Recon required)

**Input:** `-u example.com`

**Without `--recon`:**
```bash
python main.py -u example.com --scan sqli
```

**Behavior:**
- ❌ Error: Base domain provided without `--recon` flag
- ❌ User must provide either:
  - Full URL: `python main.py -u 'https://example.com/path?q=test'`
  - Enable recon: `python main.py -u example.com --recon --recon-mode passive`

**With `--recon`:**
```bash
python main.py -u example.com --recon --recon-mode passive --scan sqli
```

**Behavior:**
- ✅ Run passive recon (GAU + GF)
- ✅ Discover parameterized URLs
- ✅ Log: `[RECON] Enabled with mode: passive`
- ✅ Pass discovered URLs to the scan module

#### Scenario 3: URL File (Optional recon)

**Input:** `-f targets.txt`

**Without `--recon`:**
```bash
python main.py -f targets.txt --scan sqli
```

**Behavior:**
- ✅ Read URLs directly from file
- ✅ No recon performed
- ✅ Log: `[*] Recon disabled — using URLs directly from file`

**With `--recon`:**
```bash
python main.py -f targets.txt --recon --recon-mode passive --scan sqli
```

**Behavior:**
- ✅ Read domains/URLs from file
- ✅ Apply GAU + GF + parameter scoring
- ✅ Log: `[RECON] Enabled with mode: passive`

---

### Example Commands

#### SQLi Scanning

```bash
# Direct scan (no recon)
python main.py -u 'https://example.com/search?q=test' --scan sqli

# With passive recon (discover parameters)
python main.py -u example.com --recon --recon-mode passive --scan sqli

# Batch file (no recon)
python main.py -f targets.txt --scan sqli

# Raw HTTP request
python main.py --raw request.txt --scan sqli
```

#### BXSS Scanning

```bash
# With active recon + callback server
python main.py -u example.com --recon --recon-mode active --scan bxss \
  --listener https://abc123.ngrok.io --wait 120

# Direct targets (no recon)
python main.py -f bxss_targets.txt --scan bxss \
  --listener https://abc123.ngrok.io
```

#### SSRF Scanning

```bash
# No recon, direct targets
python main.py -f ssrf_targets.txt --scan ssrf \
  --listener http://attacker.com:5000

# With passive recon
python main.py -u example.com --recon --recon-mode passive --scan ssrf \
  --listener http://attacker.com:5000
```

---

### Logging

The scanner now provides **clear logs** indicating recon status:

```
[RECON] Enabled with mode: passive
[*] Recon disabled — using user-supplied targets
```

Each module (SQLi, BXSS, SSRF) logs:

```
[RECON] Mode: passive | URLs discovered: 45
[*] Recon disabled | Target URLs: 10
```

---

## PART 2: Repository Hygiene & .gitignore

### What Was Removed from Version Control

The `.gitignore` file now properly excludes:

#### Output Artifacts
- `**/output/*.json` - Findings files
- `**/output/*.txt` - Report files
- `**/output/*.csv` - Feature extraction files
- `**/output/callbacks.json` - Callback logs

#### Generated Databases
- `*.db` - SQLite databases
- `callbacks.db` - Callback storage
- `injections.db` - Injection tracking

#### Cache & Environment
- `__pycache__/` - Python cache
- `.pytest_cache/` - Test cache
- `.venv/`, `venv/` - Virtual environments
- `*.egg-info/` - Build artifacts

#### System Files
- `.DS_Store` - macOS
- `Thumbs.db` - Windows
- `nul` - Linux artifacts

### Repository Structure After Cleanup

**Tracked (Source Code):**
```
main.py
requirements.txt
.gitignore
README.md
CHANGELOG.md
bsqli/
  ├── core/
  │   ├── config.py
  │   ├── logger.py
  │   ├── payload_strategy.py
  │   └── ...
  └── modules/
bxss/
  ├── core/
  ├── modules/
  └── ml/
bssrf/
  ├── modules/
  └── oob/
recon/
  ├── gau_runner.py
  ├── gf_filter.py
  └── ...
tests/
```

**Not Tracked (Generated):**
```
.venv/
**/output/
*.db
*.log
__pycache__/
```

---

## PART 3: Implementation Details

### Main.py Control Flow

**Key Functions:**

1. **Argument Parsing:**
   - `--recon`: Boolean flag
   - `--recon-mode`: Enum choice (passive/active/both)
   - All other flags remain unchanged

2. **Target Handling (Lines 207-243):**
   ```python
   if from_file:
       if args.recon:
           # Apply recon to file input
       else:
           # Read URLs directly
   else:
       # Single URL input
       if is_full_url_with_params and not args.recon:
           # Direct scan
       elif args.recon:
           # Apply recon
       else:
           # Error: base domain without recon
   ```

3. **Module Routing:**
   Each module (SQLi, BXSS, SSRF) logs recon status:
   ```python
   if args.recon:
       print_info(f"[RECON] Mode: {args.recon_mode} | URLs discovered: {len(urls)}")
   else:
       print_info(f"[*] Recon disabled | Target URLs: {len(urls)}")
   ```

### Backward Compatibility

- Existing `--recon` flag behavior is preserved
- `--recon-mode` defaults to `passive` if not specified
- Raw mode (`--raw`) unaffected
- All detection modules work independently of recon status

---

## Usage Summary

| Scenario | Command | Recon? | Notes |
|----------|---------|--------|-------|
| Full URL, no recon | `main.py -u 'https://ex.com/path?q=x' --scan sqli` | ❌ | Direct scan |
| Domain, passive recon | `main.py -u ex.com --recon --recon-mode passive --scan sqli` | ✅ | Discover URLs |
| Domain, active recon | `main.py -u ex.com --recon --recon-mode active --scan bxss` | ✅ | Full reconnaissance |
| File, no recon | `main.py -f targets.txt --scan sqli` | ❌ | Direct scan |
| File, with recon | `main.py -f targets.txt --recon --recon-mode passive --scan sqli` | ✅ | Filter + prioritize |
| Raw request | `main.py --raw req.txt --scan sqli` | ❌ | Bypass recon |

---

## Final State

✅ **Recon is optional and user-controlled**
✅ **Detection modules work independently**
✅ **Clear logging for all decisions**
✅ **Repository cleaned of artifacts**
✅ **Proper .gitignore rules**
✅ **Backward compatible with existing code**

This structure is production-ready and suitable for final-year evaluation and thesis defense.
