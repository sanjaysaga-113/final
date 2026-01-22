"""
BCMDI Implementation Guide - Technical Deep Dive

This document covers the technical implementation details of the Blind CMDi module.

===============================================================================
  TABLE OF CONTENTS
===============================================================================

1. Module Architecture & Design Patterns
2. Detection Algorithm Details
3. Payload Design & OS Awareness
4. ML Integration
5. WAF Evasion Techniques
6. Integration with Main Scanner
7. Troubleshooting & Optimization

===============================================================================
1. MODULE ARCHITECTURE & DESIGN PATTERNS
===============================================================================

Design Principles:
  ✓ Follows existing module patterns (blind_sqli, blind_xss, blind_ssrf)
  ✓ Shared dependencies (HttpClient, response_analyzer, logger)
  ✓ Structured findings output (consistent with scanner)
  ✓ ML-first design (feature extraction from day 1)
  ✓ Safety-focused (no destructive operations)

Module Layers:

    ┌─────────────────────────────────────────┐
    │    BlindCMDiModule (cmdi_module.py)     │ High-level API
    │  scan_url, scan_form, scan_cookies      │
    └───────────────────┬─────────────────────┘
                        │
    ┌───────────────────v─────────────────────┐
    │   BlindCMDiDetector (detector.py)       │ Core detection logic
    │  detect_query_param, _test_time_based   │
    └───────────────────┬─────────────────────┘
                        │
    ┌───────────────────v─────────────────────┐
    │   Payload Generation (payloads.py)      │ Payload templates
    │  linux_time_payloads, separators, etc.  │
    └───────────────────┬─────────────────────┘
                        │
    ┌───────────────────v─────────────────────┐
    │   Shared Core (bsqli.core.*)            │ Rate limiting, logging
    │  HttpClient, response_analyzer, logger  │
    └─────────────────────────────────────────┘

Key Design Decisions:

1. Time-Based Detection Only (for v1)
   - Why: Reliable, requires no output, works through filters
   - Future: Add logic-based and OOB detection

2. OS-Aware Payloads
   - Why: Linux (sleep) vs Windows (timeout/ping) are different
   - How: OSFingerprinter infers from headers/URL patterns

3. Multi-Probe Confirmation (MIN_CONFIRMATIONS=2)
   - Why: Reduces false positives dramatically
   - How: Different separators (;, &&, ||) must all work

4. Control Payloads
   - Why: Detects defensive measures (WAF, IDS)
   - How: Test sleep 0, invalid commands - should NOT delay

5. Linear Scaling Verification
   - Why: Proves timing is from injected command, not network
   - How: 3→5→7 seconds, verify each delta is ~2 seconds

===============================================================================
2. DETECTION ALGORITHM DETAILS
===============================================================================

The detection algorithm works in phases:

PHASE 1: BASELINE CAPTURE
├─ Purpose: Establish normal response latency
├─ Samples: 3 unmodified GET requests
├─ Metrics: Mean, std dev (for jitter tolerance)
└─ Output: baseline_times = [0.42, 0.38, 0.40] seconds

PHASE 2: OS FINGERPRINTING
├─ Check server header: "IIS" → Windows, "nginx" → Linux
├─ Check URL patterns: ".aspx" → Windows, "/usr/" → Linux
└─ Select payload family: windows_time_payloads or linux_time_payloads

PHASE 3: SEPARATOR ENUMERATION
├─ Try each separator in priority order:
│  1. ";"      (semicolon - most common)
│  2. " && "   (AND operator)
│  3. " || "   (OR operator)
│  4. " | "    (pipe)
│  5. "\n"     (newline)
│  ... etc
└─ For each separator, continue to Phase 4

PHASE 4: TIME-BASED PAYLOAD INJECTION
For separator in [";", "&&", "||", "|"]:
    ├─ Inject: param_value + ";" + "sleep 3"
    ├─ Measure: t1 = response latency
    ├─ Inject: param_value + ";" + "sleep 5"
    ├─ Measure: t2 = response latency
    ├─ Inject: param_value + ";" + "sleep 7"
    ├─ Measure: t3 = response latency
    └─ Proceed to Phase 5

PHASE 5: LINEAR SCALING ANALYSIS
    delta1 = t2 - t1  (should be ≈ 2 seconds)
    delta2 = t3 - t2  (should be ≈ 2 seconds)
    
    tolerance = max(
        0.3 * expected_delta,           # 30% relative tolerance
        jitter_tolerance * 2            # or 2x baseline jitter
    )
    
    if (abs(delta1 - 2.0) <= tolerance AND
        abs(delta2 - 2.0) <= tolerance):
        → CONFIRMATION! Add to confirmations list

PHASE 6: MULTI-PROBE CONFIRMATION
    if confirmations >= MIN_CONFIRMATIONS (2):
        confidence = "HIGH"
    elif confirmations == 1:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

PHASE 7: FALSE POSITIVE REDUCTION
    For each control_payload in ["sleep 0", "invalid_cmd"]:
        control_time = request_time(control_payload)
        if control_time > (LATENCY_THRESHOLD + 1.0):
            → REJECT finding (false positive)
        else:
            → ACCEPT finding

PHASE 8: ML FEATURE EXTRACTION
    features = {
        "timestamp": datetime.now().isoformat(),
        "url": url,
        "parameter": param,
        "injection_type": "command_injection",
        "payload": "sleep 5",
        "baseline_time": 0.40,
        "injected_time": 5.42,
        "delta": 5.02,
        "delta_ratio": 12.55,
        "content_length": 1024,
        "status_code": 200,
        "response_entropy": 3.47,
        "jitter_variance": 0.08,
        "endpoint_class": "search"
    }
    persist_feature_vector(features)  # Save to CSV

Example Execution Trace:

[CMDi] Testing parameter: host
[CMDi] Inferring OS from headers...
[CMDi] Inferred OS: linux
[CMDi] Capturing baseline (3 samples)...
  Sample 1: 0.42s
  Sample 2: 0.38s
  Sample 3: 0.40s
[CMDi] Baseline: avg=0.40s, jitter=0.02s, tolerance=0.03s
[CMDi] Testing separator: semicolon (safest)
  Testing payload: sleep 3 (expect 3s delay)
    Response time: 3.38s ✓
  Testing payload: sleep 5 (expect 5s delay)
    Response time: 5.42s ✓
  Testing payload: sleep 7 (expect 7s delay)
    Response time: 7.39s ✓
  Delta analysis:
    5.42 - 3.38 = 2.04s (expected 2.0s, within tolerance) ✓
    7.39 - 5.42 = 1.97s (expected 2.0s, within tolerance) ✓
  ✓ Time-based confirmation: ;
[CMDi] Testing separator: AND operator ( && )
  ... (similar process) ...
  ✓ Time-based confirmation: &&
[CMDi] ✓ HIGH confidence: 2 confirmations
[CMDi] Running control payload tests...
  Control: sleep 0 → 0.39s ✓ (no delay)
  Control: invalid_command_xyz → 0.41s ✓ (no delay)
[CMDi] ✓ Control tests passed
[CMDi] Feature vector persisted

===============================================================================
3. PAYLOAD DESIGN & OS AWARENESS
===============================================================================

Linux Payloads:
    sleep 3              # Basic, reliable
    $(sleep 3)           # Subshell (command substitution)
    `sleep 3`            # Backticks (older syntax)
    
Why these?
  - sleep: Universal on Linux, precise timing, no side effects
  - 3/5/7 seconds: Clear for linear scaling analysis
  - Variants: Multiple injection points (subshell, backticks)

Windows Payloads:
    timeout /t 3 /nobreak    # Timeout command (user-input version)
    ping -n 4 127.0.0.1      # Ping (more reliable than timeout)
    
Why?
  - timeout: Native Windows command but unreliable
  - ping: More reliable, creates consistent delays
  - -n N: Number of ping packets (N-1 delays)
  - 127.0.0.1: Loopback (guaranteed to respond)

Chaining Separators:
    ;       # Execute next command sequentially
    &&      # Execute next if previous succeeds
    ||      # Execute next if previous fails
    |       # Pipe output to next command
    \n      # Newline (on some systems)
    `...`   # Command substitution (backticks)
    $(...)  # Command substitution (modern)

Priority Order:
  1. ";" - Works almost everywhere
  2. "&&" - Common in both Unix and Windows
  3. "||" - Fallback strategy
  4. "|" - Less common but possible
  5. Special: backticks, dollar-parens (OS-specific)

Control Payloads:
    sleep 0           # No delay (should fail benignly)
    invalid_cmd_xyz   # Non-existent command (error or nothing)
    
Why?
  - If these also cause delays, injection likely failed
  - Detects defensive measures (WAF, rate limiting)
  - Proves difference isn't just baseline variance

===============================================================================
4. ML INTEGRATION
===============================================================================

Feature Extraction Strategy:

The detector captures 12+ features per injection attempt:

    1. baseline_time: Mean of 3 baseline samples
    2. injected_time: Response time with payload
    3. delta: Difference (injected - baseline)
    4. delta_ratio: Normalized delta (delta / baseline_time)
       └─ Critical for accuracy (handles different network speeds)
    5. status_code: HTTP response code
    6. content_length: Response body size
    7. response_entropy: Shannon entropy (randomness) of response
    8. jitter_variance: Std dev of baseline timing
    9. endpoint_class: URL path class (e.g., /search, /login)
   10. timestamp: When test was performed
   11. url: Full target URL
   12. parameter: Vulnerable parameter name

These features are persisted to CSV:
    bcmdi/output/features.csv

CSV Format:
    timestamp,url,parameter,injection_type,payload,baseline_time,injected_time,delta,delta_ratio,content_length,status_code,response_entropy,jitter_variance,endpoint_class

Future ML Training:
    sklearn.ensemble.IsolationForest
    - Learns anomalous timing patterns
    - Detects commands that don't follow linear scaling
    - Per-endpoint models for adaptive detection
    - Reduces false positives in slow/noisy networks

Feature Engineering Notes:
    - delta_ratio is critical for normalization
    - response_entropy detects response modification
    - jitter_variance indicates network instability
    - endpoint_class enables per-endpoint models

===============================================================================
5. WAF EVASION TECHNIQUES
===============================================================================

Implemented Techniques:

1. Separator Variation
   param=value;sleep 5        (semicolon)
   param=value && sleep 5     (AND operator)
   param=value || sleep 5     (OR fallback)
   param=value | sleep 5      (pipe)
   
   Why: WAF rules often whitelist/block specific separators

2. Payload Obfuscation (defined in payloads.py)
   Original: "sleep 5"
   URL encoded: "sleep%205"
   Mixed case: "sLeEp 5"
   Double encoded: "%73%6c%65%65%70%20%35"
   
   Why: Evades string matching rules

3. Chaining Strategies
   Try multiple separators in sequence
   If first fails, others likely to succeed
   Provides defense-in-depth

4. OS Awareness
   Linux targets: Send Linux payloads (sleep, bash syntax)
   Windows targets: Send Windows payloads (ping, cmd syntax)
   
   Why: Makes payloads more authentic, bypasses OS-detection WAF

5. Baseline Jitter Tolerance
   Network variance expected: ±20-30%
   Don't flag as vulnerability unless time >> baseline
   Respects noisy/slow networks
   
   Why: Reduces false positives on shared hosting

Not Implemented (Future):
  - HTTP Parameter Pollution (HPP)
  - Blind output channels (response size, error message)
  - Advanced encoding (base64, XOR)
  - Custom payload templates
  - Unicode/UTF-8 tricks

===============================================================================
6. INTEGRATION WITH MAIN SCANNER
===============================================================================

Integration Steps:

1. Import the module:
   from bcmdi.modules.blind_cmdi import BlindCMDiModule

2. Instantiate in scanner init:
   self.cmdi_module = BlindCMDiModule(timeout=10)

3. Add to scan workflow (after SQL/XSS):
   findings = self.cmdi_module.scan_raw_request(raw_request)
   all_findings.extend(findings)

4. Store results:
   for finding in findings:
       store_finding(finding)

Expected Integration Point in main.py:
    
    def scan_target(self, url):
        # ... existing SQL/XSS scanning ...
        
        # Add CMDi scanning
        cmdi_findings = self.cmdi_module.scan_url(url)
        all_findings.extend(cmdi_findings)
        
        return all_findings

Output compatibility:
    ✓ Findings have same structure as SQL/XSS/SSRF
    ✓ Type field identifies module (blind_cmdi)
    ✓ Confidence levels (HIGH/MEDIUM/LOW) consistent
    ✓ Details dict with extensible structure

Shared Components Used:
    ✓ bsqli.core.http_client.HttpClient
      └─ Rate limiting, header rotation, retries
    
    ✓ bsqli.core.response_analyzer.measure_request_time
      └─ Precise timing measurement
    
    ✓ bsqli.core.logger.get_logger
      └─ Unified logging
    
    ✓ bsqli.ml.anomaly_stub.persist_feature_vector
      └─ ML feature storage

===============================================================================
7. TROUBLESHOOTING & OPTIMIZATION
===============================================================================

Common Issues & Solutions:

Issue 1: "All requests have HIGH latency"
  Symptoms: Even baseline measurements take 10+ seconds
  Causes: 
    - Target is slow/overloaded
    - Network congestion
    - WAF rate limiting
  Solutions:
    - Increase BASELINE_SAMPLES jitter tolerance
    - Increase TIME_JITTER_TOLERANCE multiplier
    - Wait longer or scan at off-peak time

Issue 2: "False positives on noisy networks"
  Symptoms: Finding vulnerability that isn't there
  Causes:
    - Network variance > expected payload delays
    - Shared hosting (inconsistent latency)
  Solutions:
    - Increase MIN_CONFIRMATIONS (require 3+ proofs)
    - Decrease expected delay thresholds (don't use 3/5/7, use 5/10/15)
    - Run multiple scans and average results

Issue 3: "Windows payloads not working"
  Symptoms: timeout/ping payloads fail on Windows targets
  Causes:
    - Command not available in context
    - Firewall blocking ping
    - Shell restrictions
  Solutions:
    - Ensure OS detection is correct
    - Try multiple ping targets (not just 127.0.0.1)
    - Check for shell restrictions in target app

Issue 4: "Separator doesn't work"
  Symptoms: Payload injected but not executing
  Causes:
    - Shell escaping/sanitization
    - Parameter context (quoted, etc.)
    - WAF blocking
  Solutions:
    - Try other separators (module does this already)
    - Add more separator variants
    - Increase jitter tolerance (higher baseline variance)

Optimization Tips:

1. Faster Scanning
   - Reduce BASELINE_SAMPLES from 3 to 1 (risky)
   - Use shorter payload delays (2/3/4 instead of 3/5/7)
   - Scan only likely parameters (OS command injection hints)

2. Fewer False Positives
   - Increase MIN_CONFIRMATIONS to 3-4
   - Increase TIME_JITTER_TOLERANCE
   - Run all separators before deciding

3. Better Detection
   - Add logic-based detection (file creation, DNS)
   - Implement per-endpoint models (ML)
   - Use out-of-band callbacks (Burp Collaborator)

4. Production Deployment
   - Use RateLimiter properly (shared with other modules)
   - Respect 429/403 responses (slow down)
   - Log all findings to persistent store
   - Integrate with issue tracking (Jira, etc.)

===============================================================================
  REFERENCES & RESOURCES
===============================================================================

OWASP:
  - Command Injection: https://owasp.org/www-community/attacks/Command_Injection
  - Testing for Command Injection: https://owasp.org/www-project-testing-guide/

CWE:
  - CWE-78: Improper Neutralization of Special Elements used in an OS Command
  - CWE-88: Argument Injection or Modification

PortSwigger:
  - OS Command Injection: https://portswigger.net/web-security/os-command-injection

Time-Based Detection:
  - Blind SQL Injection timing: Similar concepts apply to CMDi
  - Network timing attacks: https://en.wikipedia.org/wiki/Timing_attack

Payload Resources:
  - PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/
  - HackTricks: https://book.hacktricks.xyz/

===============================================================================
"""

print(__doc__)
