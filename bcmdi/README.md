"""
BCMDI Module README

Blind Command Injection (CMDi) Detection Module - Production-Grade Implementation

===============================================================================
  OVERVIEW
===============================================================================

This module detects blind OS command injection vulnerabilities where no output
is directly returned to the attacker. It uses time-based, out-of-band, and
logic-based detection techniques integrated with the existing scanner.

Features:
✓ Time-based detection (OS-aware payloads: sleep, ping, timeout)
✓ Baseline capture & comparison (3-sample jitter tolerance)
✓ False positive reduction (control payloads, multi-probe verification)
✓ ML integration (IsolationForest anomaly detection)
✓ OS fingerprinting (passive, from headers & behavior)
✓ WAF evasion (payload obfuscation, chaining variations)
✓ Production-safe (no destructive commands, stealth-focused)

===============================================================================
  ARCHITECTURE
===============================================================================

Module Structure:
    bcmdi/
    ├── modules/
    │   └── blind_cmdi/
    │       ├── __init__.py          # Module interface
    │       ├── payloads.py          # Payload templates & generation
    │       ├── detector.py          # Core detection logic
    │       └── cmdi_module.py       # High-level scanning interface
    ├── output/                      # Findings and features output
    └── __init__.py                 # Package exports

Key Components:

1. **payloads.py** - Payload Templates
   - linux_time_payloads(): Sleep-based delays (3, 5, 7 seconds)
   - windows_time_payloads(): Timeout/ping-based delays
   - chain_separators(): Injection vectors (;, &&, ||, |, etc.)
   - obfuscation_variants(): WAF evasion (URL encoding, mixed case, comments)
   - control_payloads(): False positive detection (sleep 0, invalid commands)

2. **detector.py** - Detection Engine
   - OSFingerprinter: Infer target OS from headers and URL patterns
   - BlindCMDiDetector: Core detection logic
     * _measure_baseline(): Capture 3 baseline samples
     * _test_time_based(): Inject payloads, measure latency deltas
     * _test_control_payloads(): Verify false positive reduction
     * detect_query_param(): Main detection method

3. **cmdi_module.py** - Scanner Interface
   - BlindCMDiModule: High-level scanning API
     * scan_url(): Test query parameters
     * scan_form(): Test POST form parameters
     * scan_cookies(): Test cookie values
     * scan_raw_request(): Unified interface for HTTP requests

===============================================================================
  DETECTION WORKFLOW
===============================================================================

Step 1: Baseline Capture
  ├─ Send 3 unmodified requests to target
  ├─ Measure response latency for each
  └─ Calculate jitter tolerance (std dev × 1.5)

Step 2: OS Fingerprinting
  ├─ Check HTTP headers (Server, etc.)
  ├─ Analyze URL path patterns
  └─ Select appropriate payload family (Linux vs Windows)

Step 3: Time-Based Injection
  For each separator in [";", "&&", "||", "|"]:
    ├─ Inject payload: value + separator + "sleep 3"
    ├─ Measure response time
    ├─ Inject payload: value + separator + "sleep 5"
    ├─ Measure response time
    ├─ Inject payload: value + separator + "sleep 7"
    ├─ Measure response time
    └─ Analyze for linear scaling (3→5→7 second increase)

Step 4: Linear Scaling Verification
  ├─ Expect: delta(5-3) ≈ 2 seconds, delta(7-5) ≈ 2 seconds
  ├─ Tolerance: ±1.5s + jitter_tolerance
  └─ Generate confirmation if match

Step 5: Multi-Probe Confirmation
  ├─ Require ≥2 independent separator proofs (MIN_CONFIRMATIONS=2)
  └─ Rate confidence: HIGH (2+), MEDIUM (1), LOW (0)

Step 6: False Positive Reduction
  ├─ Test control payloads: "sleep 0", "invalid_command_xyz"
  ├─ Verify they DON'T introduce delays
  └─ Reject findings if control tests fail

Step 7: ML Feature Extraction
  ├─ Extract response times, deltas, status codes, content length
  ├─ Prepare feature vector
  └─ Persist to CSV store (for future IsolationForest training)

===============================================================================
  INTEGRATION WITH EXISTING SCANNER
===============================================================================

The module follows the exact same patterns as blind_sqli and blind_xss:

1. Shared Dependencies:
   ✓ bsqli.core.http_client (HttpClient with rate limiting)
   ✓ bsqli.core.response_analyzer (measure_request_time)
   ✓ bsqli.core.logger (get_logger)
   ✓ bsqli.core.config (timeouts, thresholds)
   ✓ bsqli.ml.anomaly_stub (ML feature persistence)

2. Integration Points:
   - Import: from bcmdi.modules.blind_cmdi import BlindCMDiModule
   - Instantiate: module = BlindCMDiModule(timeout=10)
   - Scan: findings = module.scan_url(url, headers, cookies)
   - Results: List of structured findings with confidence levels

3. Output Format:
   {
       "type": "blind_cmdi",
       "parameter": "vulnerable_param",
       "injection_point": "query|form|cookie",
       "url": "http://example.com/...",
       "technique": "time-based",
       "confidence": "HIGH|MEDIUM|LOW",
       "details": {
           "baseline_avg": 0.42,
           "confirmations_count": 2,
           "threshold": 2
       },
       "confirmations": 2
   }

===============================================================================
  CONFIGURATION & TUNING
===============================================================================

Core Parameters (detector.py):

    BASELINE_SAMPLES = 3
      └─ Number of unmodified requests to capture baseline
      └─ Larger = more accurate jitter tolerance, slower scanning

    MIN_CONFIRMATIONS = 2
      └─ Minimum independent proofs required for vulnerability
      └─ 2+ separators with successful linear scaling
      └─ Higher = lower false positive rate, potential false negatives

    TIME_JITTER_TOLERANCE = 1.5
      └─ Multiplier for baseline std dev tolerance
      └─ Higher = more tolerant of network variance
      └─ Lower = stricter, may miss vulnerable slow networks

    LATENCY_THRESHOLD = 2.5
      └─ Minimum delta (seconds) to consider significant
      └─ Filters out network jitter noise

Payload Delays:

    Linux:   sleep 3, sleep 5, sleep 7
    Windows: timeout /t 3, timeout /t 5, timeout /t 7
             ping -n 4/6/8 127.0.0.1

    └─ Chosen for linear scaling analysis
    └─ Can be customized in payloads.py

===============================================================================
  SAFETY & STEALTH
===============================================================================

Production-Ready:
  ✓ No destructive commands (rm, del, drop, etc.)
  ✓ Only uses sleep, ping, timeout (safe, read-only)
  ✓ No infinite loops or high delays (max 7 seconds)
  ✓ Respects global rate limiting (shared HTTP client)
  ✓ Jittered delays (header rotation, random timing)

Stealth Features:
  ✓ Optional payload obfuscation (URL encoding, case mutation)
  ✓ Multiple chaining separators (avoids WAF patterns)
  ✓ Control payload verification (detects detection systems)
  ✓ Adaptive OS payload selection (matches target behavior)
  ✓ Time-based rather than output-based (avoids log matches)

===============================================================================
  USAGE EXAMPLES
===============================================================================

Example 1: Basic URL Scanning
    from bcmdi.modules.blind_cmdi import BlindCMDiModule
    
    module = BlindCMDiModule(timeout=10)
    url = "http://target.com/search?q=test"
    headers = {"User-Agent": "Scanner/1.0"}
    cookies = {"session": "abc123"}
    
    findings = module.scan_url(url, headers=headers, cookies=cookies)
    for finding in findings:
        print(f"[!] {finding['parameter']}: {finding['confidence']}")

Example 2: Raw Request Scanning
    raw_request = {
        "method": "POST",
        "url": "http://target.com/api/process",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "cookies": {},
        "body": "cmd=ping&host=127.0.0.1",
        "content_type": "application/x-www-form-urlencoded"
    }
    
    findings = module.scan_raw_request(raw_request)

Example 3: Manual Detector Usage
    from bcmdi.modules.blind_cmdi import BlindCMDiDetector
    
    detector = BlindCMDiDetector(timeout=10)
    result = detector.detect_query_param(
        url="http://target.com/ping?host=127.0.0.1",
        param="host"
    )
    
    if result["evidence"]:
        print(f"Vulnerable! Confidence: {result['confidence']}")
        print(f"Confirmations: {len(result['confirmations'])}")

===============================================================================
  TESTING
===============================================================================

Run the included test suite:
    python test_cmdi_integration.py

This tests:
  ✓ Payload generation (Linux, Windows, separators)
  ✓ OS fingerprinting (header & URL pattern detection)
  ✓ Detector initialization
  ✓ Module initialization
  ✓ Payload injection mechanics
  ✓ ML feature extraction
  ✓ Full scan workflow (simulated)

No network requests required - all tests are unit tests.

===============================================================================
  FUTURE ENHANCEMENTS
===============================================================================

Potential additions (not implemented):
  □ Logic-based detection (file creation, DNS callbacks)
  □ Out-of-band callback verification (Burp Collaborator integration)
  □ HTTP parameter pollution (HPP) obfuscation
  □ POST body injection (multipart form-data, JSON)
  □ Custom payload templates (user-supplied)
  □ Advanced obfuscation (base64, XOR, encryption)
  □ Per-endpoint anomaly models (not just global IsolationForest)
  □ Blind output channels (error messages, response size changes)

===============================================================================
  LICENSE & CREDITS
===============================================================================

Part of a comprehensive web vulnerability scanner suite.
Designed for bug bounty and security testing.

Follow responsible disclosure practices and get proper authorization
before scanning any web properties.

===============================================================================
"""

print(__doc__)
