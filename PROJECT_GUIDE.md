# Project Guide

Contributor-focused notes: integration, testing, and documentation pointers for the scanner (SQLi, BXSS, SSRF, CMDi, XXE).

---

## Current Scope

- Five scanners wired in `main.py`: sqli, bxss, ssrf, cmdi, xxe
- Recon is optional and controlled via `--recon` + `--recon-mode {passive|active}`
- Raw-mode supported for SQLi and XXE (`--raw file.txt`)
- Callback-driven modules: bxss/ssrf/cmdi (when OOB), xxe (optional)

---

## Integration Notes

- CLI routing lives in main.py; add new modules by extending the scan dispatch and argparse choices.
- HttpClient now exposes `get` and `post` with rate limiting; reuse for new modules to inherit throttling/header rotation.
- OOB listeners: bxss/bssrf share the Flask callback server pattern; reuse correlation logic when adding new callback types.
- Recon flow: `recon_manager` orchestrates gau + gf filtering + param scoring. Safe to bypass when URLs already include params.
- Demo app: `demo_vuln_app/app.py` provides test targets for all modules (including cmdi/xxe endpoints).

---

## Testing Checklist

- Run baseline suite: `python -m pytest tests`
- XXE integration: `python test_xxe_integration.py`
- CMDi integration: `python test_cmdi_integration.py`
- Demo harnesses (optional): `python test_xxe_against_demo_app.py`, `python test_cmdi_against_demo_app.py`
- Manual sanity: SQLi/bxss/ssrf with demo target lists in `demo_vuln_app/`

Add new tests alongside modules under `tests/` or module-specific harnesses; prefer small fixtures and deterministic timeouts.

---

## Documentation Map

- README.md: manager/operator overview and commands
- QUICKSTART.md: operator cheat sheet
- PROJECT_GUIDE.md: contributor notes (this file)
- Module READMEs: bxss, bssrf, bcmdi, bxe (internals + usage)
- demo_vuln_app/README.md: demo endpoints and flows

Remove or archive inventories/summaries once merged (done in this cleanup).

---

## Release Prep

- Verify `requirements.txt` installs cleanly
- Confirm `--help` shows all modules and examples
- Ensure outputs write to module `output/` dirs (json/txt/csv)
- Keep `.gitignore` excluding findings, dbs, envs, caches

---

## Common Workflows (dev)

- Quick SQLi: `python main.py -u "https://t/search?q=1" --scan sqli --threads 5`
- BXSS with callbacks: `python main.py --scan bxss -f targets.txt --listener http://127.0.0.1:5000 --wait 60`
- SSRF: `python main.py --scan ssrf -f targets.txt --listener http://127.0.0.1:5000 --wait 30 --threads 5`
- CMDi: `python main.py --scan cmdi -u https://t/ping?host=1 --listener http://127.0.0.1:5000`
- XXE (raw): `python main.py --scan xxe --raw demo_raw_request.txt --listener http://127.0.0.1:5000`

Keep thread counts modest for OOB modules; allow `--wait` to cover callback latency.

---

## Notes for Future Work

- If adding more ML, reuse feature schemas in bsqli/bxe and gate on warm-up counts.
- For new OOB channels, extend correlation to store protocol/type and expiry.
- Keep payload engines data-driven so modules stay pluggable.

### Recon Options

| Flag | Effect |
|------|--------|
| (none) | Skip recon, use direct targets |
| `--recon` | Enable recon |
| `--recon-mode passive` | GAU + GF filtering (default) |
| `--recon-mode active` | Passive + blind recon |

### Scan Options

| Option | Type |
|--------|------|
| `--scan sqli` | Blind SQL Injection |
| `--scan bxss` | Blind XSS (requires `--listener`) |
| `--scan ssrf` | Blind SSRF (requires `--listener`) |

### Additional Options

| Option | Argument | Default |
|--------|----------|---------|
| `--threads` | N (int) | 5 |
| `--listener` | URL | (required for BXSS/SSRF) |
| `--wait` | Seconds | 30 |

---

## Verification Checklist

### Control Flow
- [x] `--recon` flag is boolean (on/off)
- [x] `--recon-mode` defaults to `passive`
- [x] Full URLs with `?param=` recognized
- [x] Base domain without recon produces error
- [x] File input with recon applies GAU+GF
- [x] File input without recon reads directly
- [x] All modules log recon status
- [x] Raw mode unaffected

### Repository
- [x] .gitignore created
- [x] Output artifacts excluded
- [x] Database files excluded
- [x] Cache directories excluded
- [x] Only source code tracked

### Code Quality
- [x] No syntax errors
- [x] All imports working
- [x] Backward compatible
- [x] Error handling proper
- [x] Logging comprehensive

---

## Deployment

### Pre-Defense Checklist

- [ ] Review this guide
- [ ] Run test commands from TESTING_GUIDE.md
- [ ] Verify help message: `python main.py --help`
- [ ] Test error handling: `python main.py -u example.com --scan sqli`
- [ ] Prepare demo commands
- [ ] Have QUICK_REFERENCE.md handy

### Git Workflow

```bash
# Add all changes
git add .gitignore main.py *.md

# Commit
git commit -m "Control flow restructuring: optional recon + repo cleanup"

# Push
git push
```

---

**Status: ✅ READY FOR FINAL-YEAR EVALUATION AND THESIS DEFENSE**

For quick commands, see [QUICK_REFERENCE.md](QUICK_REFERENCE.md)  
For testing procedures, see [TESTING_GUIDE.md](TESTING_GUIDE.md)
