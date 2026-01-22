"""
BCMDI Module - Complete Architecture & File Reference

===============================================================================
  MODULE STRUCTURE
===============================================================================

bcmdi/                                     # Root CMDi Detection Module
│
├── __init__.py                           # Package initialization (17 lines)
│   └─ Exports: BlindCMDiDetector, BlindCMDiModule, OSFingerprinter
│
├── modules/
│   ├── __init__.py                       # Subpackage marker
│   │
│   └── blind_cmdi/
│       ├── __init__.py                   # Module exports (5 lines)
│       │   └─ Exports: BlindCMDiDetector, BlindCMDiModule, OSFingerprinter
│       │
│       ├── payloads.py                   # ★ PAYLOAD TEMPLATES (220 lines)
│       │   ├─ linux_time_payloads()
│       │   ├─ windows_time_payloads()
│       │   ├─ chain_separators()
│       │   ├─ obfuscation_variants()
│       │   ├─ logic_based_payloads_linux()
│       │   ├─ logic_based_payloads_windows()
│       │   ├─ get_control_payloads()
│       │   └─ PAYLOAD_CLASS_INDEX (for ML)
│       │
│       ├── detector.py                   # ★ CORE DETECTION ENGINE (450+ lines)
│       │   ├─ class OSFingerprinter
│       │   │   ├─ infer_from_headers()
│       │   │   └─ infer_from_url()
│       │   │
│       │   └─ class BlindCMDiDetector
│       │       ├─ __init__(timeout)
│       │       ├─ _measure_baseline() → (times, tolerance)
│       │       ├─ _param_replace_get() → URL
│       │       ├─ _inject_payload() → URL with payload
│       │       ├─ _select_os_payloads() → [payloads]
│       │       ├─ _test_time_based() → {evidence, confirmations}
│       │       ├─ _test_control_payloads() → {passed, reason}
│       │       ├─ detect_query_param() → finding dict
│       │       └─ _extract_and_persist_features() [internal]
│       │
│       └── cmdi_module.py                # ★ SCANNER INTERFACE (350+ lines)
│           └─ class BlindCMDiModule
│               ├─ __init__(timeout)
│               ├─ _flatten_form()
│               ├─ _result_to_finding()
│               ├─ scan_url() → [findings]
│               ├─ scan_form() → [findings]
│               ├─ scan_cookies() → [findings]
│               └─ scan_raw_request() → [findings]
│
├── output/                               # Findings & ML feature storage
│   └─ (generated at runtime)
│
├── README.md                             # ★ USER DOCUMENTATION (200+ lines)
│   ├─ Overview & features
│   ├─ Architecture
│   ├─ Detection workflow
│   ├─ Integration guide
│   ├─ Configuration
│   ├─ Safety & stealth
│   ├─ Usage examples
│   └─ Testing & future enhancements
│
├── IMPLEMENTATION_GUIDE.md               # ★ TECHNICAL DEEP DIVE (400+ lines)
│   ├─ Architecture & design patterns
│   ├─ Detection algorithm details
│   ├─ Payload design & OS awareness
│   ├─ ML integration
│   ├─ WAF evasion techniques
│   ├─ Scanner integration
│   ├─ Troubleshooting & optimization
│   └─ References
│
└── INTEGRATION_EXAMPLES.md               # ★ INTEGRATION PATTERNS (300+ lines)
    ├─ Add to main.py
    ├─ Standalone usage
    ├─ Advanced configuration
    ├─ Recon pipeline integration
    ├─ Output & storage
    ├─ Batch scanning
    ├─ Post-processing & filtering
    ├─ Error handling
    └─ Usage examples

test_cmdi_integration.py                  # ★ TEST SUITE (300+ lines)
├─ test_payload_generation()
├─ test_os_fingerprinting()
├─ test_detector_initialization()
├─ test_module_initialization()
├─ demonstrate_payload_injection()
├─ demonstrate_feature_extraction()
├─ demonstrate_full_scan()
└─ main() runner with 7 test categories

BCMDI_IMPLEMENTATION_SUMMARY.md           # ★ THIS SUMMARY (400+ lines)
├─ Project overview
├─ Implementation checklist
├─ Integration instructions
└─ Quick start guide

===============================================================================
  KEY COMPONENTS & THEIR ROLES
===============================================================================

1. payloads.py - Payload Database
   ────────────────────────────────
   Provides safe, time-based payloads for OS-specific command injection testing.
   
   Key Functions:
   - linux_time_payloads(): Returns [sleep 3, sleep 5, sleep 7, variants, controls]
   - windows_time_payloads(): Returns [timeout, ping, controls]
   - chain_separators(): Returns [;, &&, ||, |, \\n, backticks, $()]
   - control_payloads(): Returns [sleep 0, invalid_command, etc.]
   - obfuscation_variants(): URL encoding, case mixing, etc.
   
   Usage:
   payloads = linux_time_payloads()
   for p in payloads:
       print(p['payload'], p['delay'])


2. detector.py - Core Detection Engine
   ────────────────────────────────────
   Implements the 8-phase detection algorithm.
   
   Key Classes:
   
   a) OSFingerprinter (passive OS detection)
      - infer_from_headers(): Parse Server, X-Powered-By, etc.
      - infer_from_url(): Detect .aspx, /usr/, etc.
      - Returns: "linux", "windows", or None
   
   b) BlindCMDiDetector (main detector)
      - _measure_baseline(): Capture 3 samples, calculate jitter
      - _test_time_based(): Inject payloads, analyze linear scaling
      - _test_control_payloads(): Verify false positive reduction
      - detect_query_param(): Orchestrate full detection workflow
      - Returns: Dict with evidence, confirmations, confidence
   
   Detection Result Format:
   {
       "type": "time_based",
       "evidence": True,
       "confirmations": [
           {
               "separator": ";",
               "timings": {"3": 3.38, "5": 5.42, "7": 7.39},
               "linear_scaling": True,
               "deltas": [2.04, 1.97]
           },
           ...
       ],
       "details": {
           "baseline_avg": 0.40,
           "confirmations_count": 2,
           "threshold": 2
       },
       "confidence": "HIGH"
   }


3. cmdi_module.py - Scanner Interface
   ────────────────────────────────────
   High-level API that wraps the detector.
   
   Key Class: BlindCMDiModule
   
   Methods:
   - scan_url(url, headers, cookies) → [findings]
   - scan_form(url, form_data, headers, cookies) → [findings]
   - scan_cookies(url, cookies, headers) → [findings]
   - scan_raw_request(raw_dict) → [findings]
   
   Finding Format:
   {
       "type": "blind_cmdi",
       "parameter": "host",
       "injection_point": "query",
       "url": "http://...",
       "technique": "time-based",
       "confidence": "HIGH",
       "details": {...},
       "confirmations": 2
   }

===============================================================================
  DETECTION WORKFLOW (8 PHASES)
===============================================================================

┌─────────────────────────────────────────────────────────────────┐
│ PHASE 1: BASELINE CAPTURE                                       │
├─────────────────────────────────────────────────────────────────┤
│ _measure_baseline()                                              │
│ • Send 3 unmodified requests                                    │
│ • Measure response latency for each                             │
│ • Calculate mean, std dev, jitter tolerance                     │
│ Output: baseline_times = [0.42, 0.38, 0.40], tolerance = 0.03  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 2: OS FINGERPRINTING                                      │
├─────────────────────────────────────────────────────────────────┤
│ OSFingerprinter.infer_from_headers() + infer_from_url()        │
│ • Check "Server: IIS" → Windows                                 │
│ • Check "Server: Nginx" → Linux                                 │
│ • Check URL pattern (.aspx → Windows)                          │
│ Output: os_hint = "linux" or "windows"                          │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 3: SEPARATOR ENUMERATION                                  │
├─────────────────────────────────────────────────────────────────┤
│ chain_separators()                                               │
│ • Get list of separators: [";", "&&", "||", "|", ...]          │
│ • For each separator, continue to PHASE 4                       │
│ • Try highest-priority first                                    │
│ Output: Next process separator in order                         │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 4: TIME-BASED PAYLOAD INJECTION                           │
├─────────────────────────────────────────────────────────────────┤
│ _test_time_based()                                               │
│ • Inject: param + ";" + "sleep 3" → measure t1                 │
│ • Inject: param + ";" + "sleep 5" → measure t2                 │
│ • Inject: param + ";" + "sleep 7" → measure t3                 │
│ Output: timings = {3: 3.38, 5: 5.42, 7: 7.39}                 │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 5: LINEAR SCALING ANALYSIS                                │
├─────────────────────────────────────────────────────────────────┤
│ _test_time_based() continued                                    │
│ • delta1 = t2 - t1 = 5.42 - 3.38 = 2.04s (expect 2.0s)        │
│ • delta2 = t3 - t2 = 7.39 - 5.42 = 1.97s (expect 2.0s)        │
│ • Within tolerance? YES ✓                                       │
│ Output: confirmation = {separator, timings, deltas, linear}    │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 6: MULTI-PROBE CONFIRMATION                               │
├─────────────────────────────────────────────────────────────────┤
│ Loop back to PHASE 3 with next separator                        │
│ • Try "&&" → PHASE 4-5                                         │
│ • Try "||" → PHASE 4-5                                         │
│ • Try "|"  → PHASE 4-5                                         │
│ • Collect all confirmations                                     │
│ • Evaluate: 2+ = HIGH, 1 = MEDIUM, 0 = LOW                    │
│ Output: confirmations_count, confidence                         │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 7: FALSE POSITIVE REDUCTION                               │
├─────────────────────────────────────────────────────────────────┤
│ _test_control_payloads()                                        │
│ • Inject control payload: "sleep 0" → measure ctrl_t            │
│ • Verify ctrl_t is NOT significantly higher than baseline       │
│ • Inject: "invalid_command_xyz" → should fail silently          │
│ • If controls fail: REJECT finding (false positive)             │
│ Output: control_passed = True/False                             │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 8: ML FEATURE EXTRACTION                                  │
├─────────────────────────────────────────────────────────────────┤
│ _extract_and_persist_features()                                 │
│ • Extract 12+ features (time, entropy, status code, etc.)      │
│ • Calculate delta_ratio (delta / baseline_time)                │
│ • Prepare feature vector dict                                   │
│ • Persist to CSV (bcmdi/output/features.csv)                   │
│ Output: Feature vector in CSV storage                           │
└─────────────────────────────────────────────────────────────────┘

===============================================================================
  CONFIGURATION TUNING
===============================================================================

Core Parameters (in detector.py):

    BASELINE_SAMPLES = 3
    └─ Increase to 5-7 for noisier networks
    └─ Decrease to 1 for faster scanning (risky)

    MIN_CONFIRMATIONS = 2
    └─ Increase to 3-4 for fewer false positives
    └─ Decrease to 1 for faster scanning (risky)

    TIME_JITTER_TOLERANCE = 1.5
    └─ Increase (2.0+) for slower/noisier networks
    └─ Decrease (1.0) for stricter detection

    LATENCY_THRESHOLD = 2.5
    └─ Increase for very noisy networks
    └─ Decrease for faster/cleaner networks

Payload Timing:

    Standard: 3, 5, 7 seconds
    └─ Use for normal networks
    
    Slow networks: 5, 10, 15 seconds
    └─ Larger deltas easier to measure
    
    Fast scans: 2, 3, 4 seconds
    └─ Smaller deltas but quicker overall

===============================================================================
  INTEGRATION CHECKLIST
===============================================================================

Before integrating into scanner:
    □ Review README.md (overview & architecture)
    □ Run test suite: python test_cmdi_integration.py
    □ Review IMPLEMENTATION_GUIDE.md (technical details)
    □ Choose integration pattern from INTEGRATION_EXAMPLES.md
    □ Understand findings format (matches scanner conventions)
    □ Review shared dependencies (HttpClient, logger, etc.)

During integration:
    □ Import BlindCMDiModule in main.py or scanner class
    □ Initialize module: module = BlindCMDiModule(timeout=10)
    □ Add to scan workflow: findings.extend(module.scan_url(...))
    □ Test on sample vulnerable endpoint
    □ Verify findings format matches storage/export
    □ Check logging output (should see INFO and DEBUG messages)
    □ Monitor resource usage

After integration:
    □ Run on representative URL sample
    □ Measure false positive rate
    □ Compare with manual testing results
    □ Review generated features.csv (ML training data)
    □ Verify output file paths are writable
    □ Set up alerting for HIGH confidence findings
    □ Document expected scan time per parameter

===============================================================================
  SHARED DEPENDENCIES
===============================================================================

Core Components Used:

1. bsqli.core.http_client.HttpClient
   └─ Provides: HTTP requests with rate limiting, header rotation
   └─ Features: Per-host delays, 429/403 detection, automatic retry
   └─ Used by: detector.py for all HTTP requests

2. bsqli.core.response_analyzer.measure_request_time
   └─ Provides: Precise timing measurement with context manager
   └─ Features: Start/end timestamps, sub-millisecond accuracy
   └─ Used by: detector.py for baseline and injection timing

3. bsqli.core.logger.get_logger
   └─ Provides: Unified logging with colored output
   └─ Features: DEBUG, INFO, WARNING, ERROR levels
   └─ Used by: detector.py and cmdi_module.py for logging

4. bsqli.ml.anomaly_stub.prepare_feature_vector + persist_feature_vector
   └─ Provides: ML feature extraction and CSV persistence
   └─ Features: Normalization, entropy calculation, thread-safe storage
   └─ Used by: detector.py for ML data collection

No new dependencies required (uses only existing bsqli infrastructure).

===============================================================================
  TESTING STRATEGY
===============================================================================

Unit Tests (test_cmdi_integration.py):
    1. Payload generation - Verify all payload variants
    2. OS fingerprinting - Test header & URL detection
    3. Detector initialization - Verify object creation
    4. Module initialization - Verify scanner interface
    5. Payload injection mechanics - Test URL modification
    6. ML feature extraction - Verify feature vectors
    7. Full scan workflow - Simulate end-to-end scanning

Test Coverage:
    ✓ All major functions tested
    ✓ No network requests (unit tests only)
    ✓ ~300 lines of test code

Running Tests:
    $ python test_cmdi_integration.py
    Output: ✓ All Tests Passed!

Integration Testing (Manual):
    1. Set up vulnerable endpoint (time-based CMDi)
    2. Run module against it
    3. Verify HIGH confidence finding
    4. Review features.csv for ML data
    5. Compare with other tools (Burp, etc.)

Production Testing:
    1. Scan on staging environment
    2. Measure false positive rate
    3. Monitor resource usage
    4. Verify integration with scanner workflow
    5. Test export/storage of findings

===============================================================================
  DEPLOYMENT CHECKLIST
===============================================================================

Pre-Deployment:
    □ All tests passing
    □ Code review completed
    □ Documentation reviewed
    □ Integration points identified
    □ Resource requirements understood
    □ Error handling reviewed

Deployment:
    □ Copy bcmdi/ directory to scanner
    □ Update imports in main.py
    □ Run integration test on sample URL
    □ Verify findings output format
    □ Check logging looks correct
    □ Monitor first few scans

Post-Deployment:
    □ Monitor false positive rate (target <10%)
    □ Review HIGH confidence findings manually
    □ Check feature.csv is being populated
    □ Monitor resource usage (memory, network)
    □ Set up alerting for errors
    □ Collect metrics for optimization

===============================================================================
"""

print(__doc__)
