# BCMDI Module

Blind command injection detector with time-based confirmation, OS-aware payloads, and optional OOB-ready listener support.

## Highlights
- Time-based scaling with 3/5/7 delays and control payloads to filter slow servers
- OS-aware payload families (Linux sleep, Windows timeout/ping)
- Baseline (3 samples) + jitter tolerance to reduce noise
- Multiple separators (`; && || |`) with multi-confirmation scoring
- Payload obfuscation variants and chaining for WAF evasion
- Shared HttpClient with rate limiting/header rotation
- Structured findings (json/txt) in `bcmdi/output/`

## Usage
- Single URL: `python main.py --scan cmdi -u "https://target/ping?host=1" --threads 5 --listener http://127.0.0.1:5000`
- File input: `python main.py --scan cmdi -f targets.txt --threads 5 --listener http://127.0.0.1:5000`
- Raw request: `python main.py --scan cmdi --raw demo_raw_request.txt --listener http://127.0.0.1:5000`
- Recon (optional): add `--recon --recon-mode passive|active`

Keep threads modest for time-based scans; allow enough timeout to cover injected delays.

## Detection Flow
1. Baseline: 3 control requests → mean/stddev → jitter window
2. OS fingerprint: headers + path hints → choose Linux or Windows payloads
3. Time-based probes: separators × delays (3/5/7) → expect linear scaling
4. Controls: zero-delay + invalid command to reject false positives
5. Confidence: count independent confirmations; higher when multiple separators align
6. Features: response time, delta_ratio, jitter, status, content length (for future ML)

## Configuration (key defaults)
- Baseline samples: 3
- Delays: 3, 5, 7 seconds
- Minimum confirmations: 2
- Jitter tolerance: 1.5 × baseline stddev
- Latency threshold: 2.5 seconds above baseline

Adjust in `bcmdi/modules/blind_cmdi/detector.py` and `payloads.py` if needed.

## Outputs
- Findings: `bcmdi/output/findings_cmdi.json` and `.txt`
- Each record: parameter, injection point, technique, confidence, evidence (deltas, payloads)

## Testing
- Integration: `python test_cmdi_integration.py`
- Demo app targets available in `demo_vuln_app/`

## Safety
- No destructive commands; delays capped at 7s
- Reuses shared rate limiting and header rotation for stealth
- Designed for authorized testing only
