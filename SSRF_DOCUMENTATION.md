# SSRF Documentation Index

## 📖 Complete Guide

**👉 Read this first:** [bssrf/GUIDE.md](bssrf/GUIDE.md)

This single file contains everything you need:
- Quick start (3 steps)
- How Blind SSRF works
- System architecture
- Complete usage examples
- All 51 payload types covered
- Callback server API reference
- Integration with main.py
- Testing & troubleshooting
- Teacher demo script
- Key classes & methods

---

## 🚀 Quick Links

### Get Started Fast
```bash
# 1. Start callback server
python bssrf/oob/callback_server.py

# 2. Start ngrok (new terminal)
ngrok http 5000

# 3. Run scanner (copy ngrok URL)
python -c "
from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
module = BlindSSRFModule('https://YOUR-NGROK.ngrok.io', verify_callbacks=True)
results = module.scan_and_verify('http://target.com?url=test')
print(f'Confirmed: {results[\"confirmed_count\"]}')
"
```

### Files You Need to Know About

```
bssrf/
├── GUIDE.md                          ← 📖 READ THIS (comprehensive guide)
├── oob/
│   ├── callback_server.py            ← Receives callbacks
│   └── correlation.py                ← Matches UUIDs
├── modules/blind_ssrf/
│   ├── payloads.py                   ← 51 payload types
│   ├── detector.py                   ← Injects payloads
│   └── ssrf_module.py                ← Main interface
├── output/
│   ├── callbacks.json                ← Logged callbacks
│   ├── findings_ssrf.json            ← Findings (JSON)
│   └── findings_ssrf.txt             ← Findings (TXT)
└── test_callback_system.py           ← System tests (5/5 passing ✅)
```

---

## ⚡ Common Tasks

### Run Full Demo
```bash
# See bssrf/GUIDE.md → "Teacher Demo Script" section
python bssrf/test_callback_system.py
```

### Test System Health
```bash
curl http://localhost:5000/health
curl http://localhost:5000/api/callbacks
```

### Check Findings
```bash
# View confirmed SSRF vulnerabilities
type bssrf\output\findings_ssrf.json
type bssrf\output\findings_ssrf.txt
```

### Debug Callbacks
```bash
# View all callbacks received
curl http://localhost:5000/api/callbacks | python -m json.tool

# Check specific UUID
curl http://localhost:5000/api/check/UUID-HERE
```

---

## ✅ Implementation Status

- ✅ **Blind SSRF module** - Fully implemented
- ✅ **51 payload types** - DNS, HTTP, Cloud, Services, Gopher, File, Encoding
- ✅ **Callback server** - Flask server receives requests
- ✅ **Automatic verification** - Correlates UUIDs with callbacks
- ✅ **Integration with main.py** - Already integrated
- ✅ **Tests** - 5/5 passing
- ✅ **Consolidated docs** - Single comprehensive guide

---

## 🎓 For Teacher Presentation

1. Read: [bssrf/GUIDE.md](bssrf/GUIDE.md) → "Teacher Demo Script" section
2. Setup: Run callback server + ngrok
3. Run: Teacher demo script (shows automatic verification)
4. Show: Confirmed SSRF findings with callback proof

---

## 📝 What's Included

### Payload Types (51 total)

| Type | Count |
|------|-------|
| Basic (DNS, HTTP, Cloud) | 6 |
| Internal Services (DB, Cache, etc) | 17 |
| Gopher Protocol | 4 |
| File Protocol | 7 |
| Encoding Variations | 11 |
| Internal IPs | 6 |

### Features

- ✅ Smart parameter detection (SSRF-risky params only)
- ✅ OOB callback verification (confirms real vulnerabilities)
- ✅ UUID tracking (each payload unique ID)
- ✅ Advanced payloads (internal services, protocols)
- ✅ Multiple encoding techniques (WAF bypass)
- ✅ Automatic correlation (UUIDs → callbacks)
- ✅ Thread-safe scanning
- ✅ Detailed findings (JSON + TXT)

---

**Need help?** See [bssrf/GUIDE.md](bssrf/GUIDE.md) → Troubleshooting section
