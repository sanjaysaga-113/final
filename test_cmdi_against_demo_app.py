"""
Test CMDi Module Against Demo Vulnerable App

This script demonstrates testing the Blind CMDi module against vulnerable endpoints
in the demo app (demo_vuln_app/app.py).

Prerequisites:
    1. Start the demo app: python demo_vuln_app/app.py --port 8000
    2. Run this test: python test_cmdi_against_demo_app.py

This tests:
    - /ping?host=127.0.0.1 (vulnerable to CMDi injection)
    - /dns?domain=example.com (vulnerable to CMDi injection)
    - /process?cmd=ls (vulnerable to CMDi injection)

Expected output:
    - HIGH confidence vulnerabilities detected on all three endpoints
    - Findings saved to bcmdi/output/findings_cmdi_demo.json
"""

import sys
import os
import json
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from bcmdi.modules.blind_cmdi import BlindCMDiModule
from bsqli.core.logger import get_logger

logger = get_logger("test_cmdi_demo")


def test_cmdi_against_demo_app():
    """Test CMDi module against vulnerable demo app endpoints."""
    
    print("\n" + "="*70)
    print("  Blind CMDi Module - Demo App Testing")
    print("="*70 + "\n")
    
    # Test endpoints
    test_cases = [
        {
            "name": "Ping Endpoint (time-based CMDi)",
            "url": "http://127.0.0.1:8000/ping?host=127.0.0.1",
            "description": "Vulnerable parameter: host"
        },
        {
            "name": "DNS Endpoint (time-based CMDi)",
            "url": "http://127.0.0.1:8000/dns?domain=example.com",
            "description": "Vulnerable parameter: domain"
        },
        {
            "name": "Process Endpoint (time-based CMDi)",
            "url": "http://127.0.0.1:8000/process?cmd=ls",
            "description": "Vulnerable parameter: cmd"
        },
    ]
    
    # Initialize CMDi module
    print("[*] Initializing CMDi module (timeout=15s)...")
    module = BlindCMDiModule(timeout=15)
    print("✓ Module initialized\n")
    
    all_findings = []
    
    # Test each endpoint
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[{i}/{len(test_cases)}] Testing: {test_case['name']}")
        print(f"    URL: {test_case['url']}")
        print(f"    {test_case['description']}\n")
        
        try:
            # Perform scan
            print("    Scanning (this may take 1-2 minutes)...")
            start = time.time()
            findings = module.scan_url(test_case['url'])
            elapsed = time.time() - start
            
            print(f"    Scan completed in {elapsed:.1f} seconds")
            
            if findings:
                print(f"    ✓ Found {len(findings)} vulnerability(ies)!")
                for finding in findings:
                    print(f"      - Parameter: {finding['parameter']}")
                    print(f"        Technique: {finding['technique']}")
                    print(f"        Confidence: {finding['confidence']}")
                    print(f"        Confirmations: {finding['confirmations']}")
                    all_findings.append(finding)
            else:
                print("    ✗ No vulnerabilities detected (expected: HIGH confidence)")
        
        except Exception as e:
            print(f"    ✗ Error: {e}")
            logger.debug(f"Exception during scan: {e}", exc_info=True)
    
    # Summary
    print("\n" + "="*70)
    print(f"  Summary: Found {len(all_findings)} vulnerabilities")
    print("="*70 + "\n")
    
    if all_findings:
        print("Findings Details:")
        for i, finding in enumerate(all_findings, 1):
            print(f"\n[{i}] {finding['parameter']} @ {finding['url']}")
            print(f"    Type: {finding['type']}")
            print(f"    Injection point: {finding['injection_point']}")
            print(f"    Technique: {finding['technique']}")
            print(f"    Confidence: {finding['confidence']}")
            print(f"    Details: {finding['details']}")
    
    # Save findings to JSON
    output_file = "bcmdi/output/findings_cmdi_demo.json"
    os.makedirs("bcmdi/output", exist_ok=True)
    
    with open(output_file, "w") as f:
        json.dump({
            "scan_type": "cmdi_demo",
            "total_endpoints": len(test_cases),
            "vulnerabilities_found": len(all_findings),
            "findings": all_findings
        }, f, indent=2)
    
    print(f"\n✓ Results saved to: {output_file}\n")
    
    return len(all_findings) == len(test_cases)


def main():
    """Run the demo app test."""
    print("\n" + "="*70)
    print("  PREREQUISITES:")
    print("="*70)
    print("""
Before running this test, ensure:

1. Demo app is running on port 8000:
   $ python demo_vuln_app/app.py --port 8000

2. Wait for "Running on http://127.0.0.1:8000/" message

3. Then run this test in another terminal:
   $ python test_cmdi_against_demo_app.py

Note: Each scan takes ~60-120 seconds per endpoint.
      Total test duration: ~5-10 minutes
""")
    
    print("="*70)
    print("  Starting test...")
    print("="*70 + "\n")
    
    try:
        success = test_cmdi_against_demo_app()
        
        if success:
            print("\n✓ All tests PASSED! CMDi module is working correctly.")
            print("\nNext steps:")
            print("  1. Review findings in bcmdi/output/findings_cmdi_demo.json")
            print("  2. Examine confidence levels and detection techniques")
            print("  3. Check bcmdi/output/features.csv for ML feature vectors")
            print("  4. Integrate module into main scanner (see INTEGRATION_EXAMPLES.md)")
            return 0
        else:
            print("\n✗ Some tests failed. Check logs above for details.")
            return 1
    
    except KeyboardInterrupt:
        print("\n\n[!] Test interrupted by user")
        return 1
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
