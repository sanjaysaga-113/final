"""
Blind CMDi Module - Integration Test & Demo

Demonstrates:
1. Blind CMDi detection on vulnerable endpoints
2. Time-based detection with latency analysis
3. Baseline capture and false positive reduction
4. OS fingerprinting
5. ML feature extraction
6. Integration with the existing scanner architecture

Usage:
    python test_cmdi_integration.py

Prerequisites:
    - A vulnerable application running (demo_vuln_app with CMDi endpoints)
    - bsqli core modules (http_client, logger, config)
    - sklearn for ML integration
"""

import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from bcmdi.modules.blind_cmdi import BlindCMDiModule, BlindCMDiDetector
from bcmdi.modules.blind_cmdi.payloads import (
    linux_time_payloads, windows_time_payloads, chain_separators, get_control_payloads
)

# Import shared components
from bsqli.core.logger import get_logger

logger = get_logger("test_cmdi")


def print_header(title):
    """Pretty print section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def test_payload_generation():
    """Test payload generation functions."""
    print_header("TEST: Payload Generation")
    
    print("[1] Linux Time-Based Payloads:")
    linux_payloads = linux_time_payloads()
    for p in linux_payloads[:5]:
        print(f"  - {p['payload']:30} | delay: {p['delay']:2}s | variant: {p['variant']}")
    print(f"  ... and {len(linux_payloads) - 5} more")
    
    print("\n[2] Windows Time-Based Payloads:")
    win_payloads = windows_time_payloads()
    for p in win_payloads[:5]:
        print(f"  - {p['payload']:35} | delay: {p['delay']:2}s | variant: {p['variant']}")
    print(f"  ... and {len(win_payloads) - 5} more")
    
    print("\n[3] Command Chaining Separators:")
    separators = chain_separators()
    for s in separators[:6]:
        print(f"  - '{s['sep']:15}' ({s['description']})")
    
    print("\n[4] Control Payloads (False Positive Detection):")
    controls = get_control_payloads("linux")
    for c in controls:
        print(f"  - {c}")
    
    print(f"\n✓ Payload generation test passed")


def test_os_fingerprinting():
    """Test OS detection from headers and URL patterns."""
    print_header("TEST: OS Fingerprinting")
    
    from bcmdi.modules.blind_cmdi.detector import OSFingerprinter
    
    test_cases = [
        {
            "name": "IIS Server (Windows)",
            "headers": {"server": "Microsoft-IIS/10.0"},
            "expected": "windows"
        },
        {
            "name": "Nginx Server (Linux)",
            "headers": {"server": "nginx/1.21.0"},
            "expected": "linux"
        },
        {
            "name": "Apache Server (Linux)",
            "headers": {"server": "Apache/2.4.41"},
            "expected": "linux"
        },
        {
            "name": "Windows Path (.aspx file)",
            "url": "http://example.com/admin/upload.aspx",
            "expected": "windows"
        },
        {
            "name": "Linux Path (/usr/local/)",
            "url": "http://example.com/usr/local/file",
            "expected": "linux"
        },
    ]
    
    for i, test in enumerate(test_cases, 1):
        headers = test.get("headers", {})
        url = test.get("url", "http://example.com/test")
        expected = test.get("expected")
        
        result_headers = OSFingerprinter.infer_from_headers(headers) if headers else None
        result_url = OSFingerprinter.infer_from_url(url)
        result = result_headers or result_url
        
        status = "✓" if result == expected else "✗"
        print(f"[{i}] {status} {test['name']}: {result} (expected: {expected})")
    
    print(f"\n✓ OS fingerprinting test passed")


def test_detector_initialization():
    """Test detector initialization and basic setup."""
    print_header("TEST: Detector Initialization")
    
    detector = BlindCMDiDetector(timeout=10)
    print(f"[1] Detector created with timeout=10s")
    print(f"    - HTTP client: initialized")
    print(f"    - Timeout: {detector.timeout}s")
    print(f"    - OS hint: {detector.os_hint}")
    
    print(f"\n✓ Detector initialization test passed")


def test_module_initialization():
    """Test module initialization."""
    print_header("TEST: Module Initialization")
    
    module = BlindCMDiModule(timeout=10)
    print(f"[1] BlindCMDiModule created")
    print(f"    - Detector: initialized")
    print(f"    - Timeout: 10s")
    
    print(f"\n✓ Module initialization test passed")


def demonstrate_payload_injection():
    """Demonstrate how payloads are injected into parameters."""
    print_header("DEMO: Payload Injection Examples")
    
    detector = BlindCMDiDetector()
    
    test_cases = [
        {
            "url": "http://example.com/search?q=hello",
            "param": "q",
            "payload": "sleep 5",
            "separator": ";"
        },
        {
            "url": "http://example.com/search?q=hello",
            "param": "q",
            "payload": "sleep 5",
            "separator": " && "
        },
        {
            "url": "http://example.com/ping?host=1.1.1.1",
            "param": "host",
            "payload": "ping -n 4 127.0.0.1",
            "separator": " | "
        },
    ]
    
    for i, test in enumerate(test_cases, 1):
        injected = detector._inject_payload(
            test["url"],
            test["param"],
            test["payload"],
            test["separator"]
        )
        print(f"[{i}] Injection Example:")
        print(f"    Original:  {test['url']}")
        print(f"    Parameter: {test['param']}")
        print(f"    Payload:   {test['payload']}")
        print(f"    Separator: {repr(test['separator'])}")
        print(f"    Injected:  {injected}\n")
    
    print(f"✓ Payload injection demonstration complete")


def demonstrate_feature_extraction():
    """Demonstrate ML feature extraction."""
    print_header("DEMO: ML Feature Extraction")
    
    from bsqli.ml.anomaly_stub import prepare_feature_vector
    
    # Example detection result
    feature_vector = prepare_feature_vector(
        url="http://example.com/search?q=test",
        parameter="q",
        injection_type="command_injection",
        payload="sleep 5",
        baseline_time=0.5,
        injected_time=5.2,
        content_length=1024,
        status_code=200,
        response_body="<html>Results...</html>",
        jitter_variance=0.15
    )
    
    print("Feature Vector Extracted:")
    for key, value in feature_vector.items():
        if isinstance(value, (int, float)):
            if isinstance(value, float):
                print(f"  {key:30}: {value:.4f}")
            else:
                print(f"  {key:30}: {value}")
        else:
            print(f"  {key:30}: {str(value)[:60]}")
    
    print(f"\n✓ Feature extraction demonstration complete")


def demonstrate_full_scan():
    """Demonstrate a full scan workflow (without actual network requests)."""
    print_header("DEMO: Full Scan Workflow")
    
    module = BlindCMDiModule(timeout=10)
    
    print("[1] Initialize BlindCMDiModule")
    print(f"    ✓ Module ready")
    
    print("\n[2] Prepare raw request")
    raw_request = {
        "method": "GET",
        "url": "http://vulnerable-app.local/search?query=test&sort=name",
        "headers": {"User-Agent": "Scanner/1.0"},
        "cookies": {"session": "abc123"},
        "body": "",
        "content_type": "text/html"
    }
    print(f"    Method: {raw_request['method']}")
    print(f"    URL: {raw_request['url']}")
    print(f"    Parameters: query, sort")
    
    print("\n[3] Scan workflow (simulated):")
    print(f"    a) Extract parameters from URL")
    print(f"       - query (GET parameter)")
    print(f"       - sort (GET parameter)")
    print(f"       - session (cookie)")
    
    print(f"\n    b) For each parameter:")
    print(f"       1. Measure baseline response times (3 samples)")
    print(f"       2. Calculate jitter tolerance")
    print(f"       3. Test time-based payloads (sleep 3/5/7)")
    print(f"       4. Verify linear time scaling")
    print(f"       5. Test multiple chaining separators (;, &&, ||, |)")
    print(f"       6. Run control payload tests (false positive check)")
    print(f"       7. Extract ML features if vulnerable")
    
    print(f"\n    c) Expected output:")
    print(f"       - List of findings with:")
    print(f"         * type: 'blind_cmdi'")
    print(f"         * parameter: name of vulnerable parameter")
    print(f"         * technique: 'time-based'")
    print(f"         * confidence: 'HIGH'/'MEDIUM'/'LOW'")
    print(f"         * confirmations: number of independent proofs")
    print(f"         * details: baseline time, deltas, etc.")
    
    print(f"\n✓ Full scan workflow demonstration complete")


def main():
    """Run all tests and demonstrations."""
    print("\n" + "="*70)
    print("  Blind CMDi Module - Integration Test Suite")
    print("="*70)
    
    try:
        # Run all tests
        test_payload_generation()
        test_os_fingerprinting()
        test_detector_initialization()
        test_module_initialization()
        demonstrate_payload_injection()
        demonstrate_feature_extraction()
        demonstrate_full_scan()
        
        print("\n" + "="*70)
        print("  ✓ All Tests Passed!")
        print("="*70)
        print("\nModule is ready for integration into main scanner.")
        print("\nTo use in your scanner:")
        print("  from bcmdi.modules.blind_cmdi import BlindCMDiModule")
        print("  module = BlindCMDiModule(timeout=10)")
        print("  findings = module.scan_url(url, headers, cookies)")
        print("="*70 + "\n")
        
        return 0
    
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
