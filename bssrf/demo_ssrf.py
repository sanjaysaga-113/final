#!/usr/bin/env python3
"""
SSRF Module Demo & Test Script

Shows blind SSRF detection in action.
Demonstrates the module scanning vulnerable endpoints.
"""

import sys
import os
import json
import time
from datetime import datetime
from typing import List, Dict

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
from bsqli.core.logger import get_logger
from colorama import Fore, Back, Style

logger = get_logger("ssrf_demo")


def print_header(text):
    """Print a colored header."""
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Back.BLACK}{text.center(80)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")


def print_success(text):
    """Print success message."""
    print(f"{Fore.GREEN}[✓] {text}{Style.RESET_ALL}")


def print_info(text):
    """Print info message."""
    print(f"{Fore.BLUE}[*] {text}{Style.RESET_ALL}")


def print_finding(finding: Dict):
    """Print a formatted finding."""
    print(f"\n{Fore.YELLOW}[FINDING] SSRF Vulnerability Detected{Style.RESET_ALL}")
    print(f"  URL: {finding.get('url')}")
    print(f"  Parameter: {finding.get('parameter')}")
    print(f"  Payload Type: {finding.get('payload_type')}")
    print(f"  Status Code: {finding.get('status_code')}")
    print(f"  Response Length: {finding.get('response_length')} bytes")
    print(f"  Timestamp: {finding.get('timestamp')}")
    print(f"  Callback ID (UUID): {finding.get('uuid')}")
    print(f"  {Fore.MAGENTA}Awaiting OOB callback confirmation...{Style.RESET_ALL}")


def write_findings_to_files(findings: List[Dict], output_dir: str = "bssrf/output"):
    """Write findings to JSON and TXT files."""
    os.makedirs(output_dir, exist_ok=True)
    
    # JSON output
    json_path = os.path.join(output_dir, "findings_ssrf.json")
    with open(json_path, "w") as f:
        json.dump(findings, f, indent=2)
    print_success(f"Findings written to {json_path}")
    
    # TXT output
    txt_path = os.path.join(output_dir, "findings_ssrf.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 80 + "\n")
        f.write("BLIND SSRF DETECTION FINDINGS\n")
        f.write("=" * 80 + "\n\n")
        
        if not findings:
            f.write("No SSRF vulnerabilities detected.\n")
        else:
            f.write(f"Total findings: {len(findings)}\n\n")
            
            for idx, finding in enumerate(findings, 1):
                f.write(f"\n[FINDING #{idx}]\n")
                f.write(f"URL: {finding.get('url')}\n")
                f.write(f"Parameter: {finding.get('parameter')}\n")
                f.write(f"Payload Type: {finding.get('payload_type')}\n")
                f.write(f"Status Code: {finding.get('status_code')}\n")
                f.write(f"Response Length: {finding.get('response_length')} bytes\n")
                f.write(f"UUID (Callback ID): {finding.get('uuid')}\n")
                f.write(f"Timestamp: {finding.get('timestamp')}\n")
                f.write(f"Payload: {finding.get('payload')}\n")
                f.write(f"Method: {finding.get('method', 'GET')}\n")
                f.write(f"Confirmed: {finding.get('confirmed', False)}\n")
                f.write("-" * 80 + "\n")
        
        f.write("\n\nNOTE: Findings are considered CONFIRMED only when OOB callbacks are received.\n")
        f.write("UUID values can be matched against the OOB callback server logs.\n")
    
    print_success(f"Findings written to {txt_path}")


def demo_scan_vulnerable_app():
    """
    Demo: Scan the vulnerable Flask app for SSRF.
    """
    print_header("BLIND SSRF MODULE DEMONSTRATION")
    
    print_info("This demo scans vulnerable endpoints for blind SSRF")
    print_info("The vulnerable app must be running on http://127.0.0.1:8000")
    
    # OOB callback server URL (would be ngrok or similar in production)
    # For demo, we'll use localhost as the "attacker" server
    listener_url = "http://127.0.0.1:5001"  # Placeholder callback server
    
    print_info(f"Using callback server: {listener_url}")
    
    # Initialize SSRF module
    ssrf_module = BlindSSRFModule(listener_url, timeout=5, wait_time=3)
    
    # Vulnerable endpoints in the demo app
    vulnerable_urls = [
        "http://127.0.0.1:8000/fetch_image?url=http://google.com",
        "http://127.0.0.1:8000/webhook?callback=http://attacker.com/hook",
        "http://127.0.0.1:8000/fetch_file?file=http://localhost:8080/admin",
    ]
    
    all_findings = []
    
    print_header("SCANNING VULNERABLE ENDPOINTS")
    
    for idx, url in enumerate(vulnerable_urls, 1):
        print_info(f"[{idx}/{len(vulnerable_urls)}] Scanning: {url}")
        
        try:
            # Perform scan
            findings = ssrf_module.scan_url(url)
            
            if findings:
                all_findings.extend(findings)
                print_success(f"Found {len(findings)} injection points")
                
                for finding in findings:
                    print_finding(finding)
            else:
                print_info("No SSRF-vulnerable parameters found in URL")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Error scanning {url}: {e}{Style.RESET_ALL}")
            logger.debug(f"Error: {e}")
    
    # Wait for potential callbacks
    print_header("WAITING FOR OUT-OF-BAND CALLBACKS")
    print_info("In production, this would query the callback server")
    print_info("For this demo, we'll simulate the waiting period...")
    
    ssrf_module.wait_for_callbacks(timeout=3)
    
    print_success("Callback wait period completed")
    
    # Summary
    print_header("SCAN SUMMARY")
    
    print_info(f"Total endpoints scanned: {len(vulnerable_urls)}")
    print_info(f"Total injections performed: {len(all_findings)}")
    
    if all_findings:
        print_success(f"\n✓ Found {len(all_findings)} SSRF injection points!")
        print_info("Injection details written to output files\n")
        
        # Group by URL for clarity
        by_url = {}
        for finding in all_findings:
            url = finding['url']
            if url not in by_url:
                by_url[url] = []
            by_url[url].append(finding)
        
        for url, findings in by_url.items():
            print(f"\n{Fore.CYAN}{url}{Style.RESET_ALL}")
            print(f"  Vulnerable parameter: {Fore.YELLOW}{findings[0]['parameter']}{Style.RESET_ALL}")
            print(f"  Injection points tested: {len(findings)}")
            for finding in findings:
                print(f"    - {finding['payload_type']}: {finding['payload'][:60]}...")
    else:
        print_info("\n✓ No SSRF vulnerabilities detected in this scan")
    
    # Write findings to files
    print_header("SAVING FINDINGS")
    write_findings_to_files(all_findings)
    
    print_header("DEMONSTRATION COMPLETE")
    print_info("For real-world testing:")
    print_info("  1. Set up an actual OOB callback server (e.g., with ngrok)")
    print_info("  2. Correlate UUIDs in findings with received callbacks")
    print_info("  3. Only mark SSRF as CONFIRMED when callback is received")
    print_info("  4. Report confirmed SSRF findings with full evidence")


def test_payload_engine():
    """
    Test: Verify payload generation.
    """
    print_header("PAYLOAD ENGINE TEST")
    
    from bssrf.modules.blind_ssrf.payloads import SSRFPayloadEngine
    
    engine = SSRFPayloadEngine("http://attacker.com")
    callback_id = engine.generate_callback_id()
    
    print_info(f"Generated callback ID: {callback_id}")
    
    payloads = engine.get_all_payloads(callback_id)
    
    print_info(f"Payload types available: {len(payloads)}")
    for ptype, payload in payloads.items():
        print(f"  {ptype}: {payload}")
    
    # Test parameter scoring
    print_info("\nTesting SSRF parameter detection:")
    test_params = ["url", "image", "callback", "webhook", "redirect", "search", "id"]
    for param in test_params:
        is_ssrf = engine.is_ssrf_parameter(param)
        status = "✓ SSRF-risky" if is_ssrf else "✗ Not SSRF-risky"
        print(f"  {param}: {status}")
    
    print_success("Payload engine test completed")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Blind SSRF Module Demo")
    parser.add_argument("--test-payloads", action="store_true", 
                       help="Test payload generation only")
    parser.add_argument("--full-demo", action="store_true",
                       help="Run full demo (requires vulnerable app running)")
    args = parser.parse_args()
    
    if args.test_payloads:
        test_payload_engine()
    elif args.full_demo:
        demo_scan_vulnerable_app()
    else:
        # Default: show help
        parser.print_help()
        print("\n" + "="*80)
        print("QUICK START:")
        print("="*80)
        print("\n1. Test payload generation:")
        print("   python bssrf/demo_ssrf.py --test-payloads\n")
        print("2. Run full demo (requires vulnerable app on :8000):")
        print("   # In one terminal: python demo_vuln_app/app.py")
        print("   # In another: python bssrf/demo_ssrf.py --full-demo\n")
