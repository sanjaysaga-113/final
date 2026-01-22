# Blind XXE Module

Blind XXE detector covering OOB callbacks, time-based delays, and parser-behavior anomalies. Integrated with the main scanner and demo app.

## Highlights
- Techniques: OOB (HTTP/DNS), time-based (/dev/random, slow endpoints, entity expansion), parser-behavior shifts
- Baseline (3 samples) + jitter tolerance; control payloads to cut false positives
- Supports XML bodies, SOAP, JSON-embedded XML, multipart uploads, raw requests
- Optional ML features: response time, delta_ratio, std_dev_ratio, status, control_passed, technique_count
- Safe payloads (bounded delays, no entity bombs) and shared HttpClient rate limiting

## Usage
- Direct URL: `python main.py --scan xxe -u "https://target/api/parse?x=1" --threads 5`
- Raw request: `python main.py --scan xxe --raw demo_raw_request.txt --listener http://127.0.0.1:5000`
- Listener (when using OOB): `--listener http://127.0.0.1:5000 --wait 60`
- Recon optional: `--recon --recon-mode passive|active`

Keep threads moderate; allow `--wait` to collect callbacks.

## Detection Flow
1. Baseline: 3 clean requests -> mean/stddev -> jitter window
2. Payload families:
   - OOB: external entity to listener (HTTP/DNS) with correlation IDs
   - Time-based: file:///dev/random, delayed endpoints, entity expansion
   - Parser behavior: expect status/length deltas and parser errors
3. Controls: benign entity payloads to separate real findings from noisy parsers
4. Confidence:
   - HIGH: OOB callback or multiple agreeing techniques
   - MEDIUM: strong time-based evidence with controls passed
   - LOW: parser anomalies only
5. Features captured for future ML scoring.

## Configuration (defaults)
- Baseline samples: 3
- Time confirmations: 2
- Jitter tolerance: 1.5 x stddev
- Latency threshold: +2.5s over baseline
- Minimum body change: 50 bytes
- HTTP timeout: 15s

Tune in `bxe/modules/blind_xxe/detector.py`.

## Outputs
- Findings: `bxe/output/findings_xxe.json` and `.txt`
- Each record: endpoint, parameter/method, technique(s), confidence, evidence (callbacks/deltas/status)

## Testing
- Integration: `python test_xxe_integration.py`
- Demo harness: `python test_xxe_against_demo_app.py`

## Safety
- No destructive operations; delays are bounded
- Control payloads to avoid mislabeling slow endpoints
- Use only on authorized targets
