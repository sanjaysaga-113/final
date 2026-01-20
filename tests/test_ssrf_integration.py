#!/usr/bin/env python3
"""
Integration Test - SSRF Module with Main Scanner

Verifies that the SSRF module is properly integrated.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def test_imports():
    """Test that all SSRF modules can be imported."""
    print("Testing imports...")
    
    try:
        from bssrf.modules.blind_ssrf.payloads import SSRFPayloadEngine
        print("✓ SSRFPayloadEngine")
    except ImportError as e:
        print(f"✗ SSRFPayloadEngine: {e}")
        return False
    
    try:
        from bssrf.modules.blind_ssrf.detector import BlindSSRFDetector
        print("✓ BlindSSRFDetector")
    except ImportError as e:
        print(f"✗ BlindSSRFDetector: {e}")
        return False
    
    try:
        from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
        print("✓ BlindSSRFModule")
    except ImportError as e:
        print(f"✗ BlindSSRFModule: {e}")
        return False
    
    return True


def test_payload_engine():
    """Test payload generation."""
    print("\nTesting payload engine...")
    
    from bssrf.modules.blind_ssrf.payloads import SSRFPayloadEngine
    
    engine = SSRFPayloadEngine("http://attacker.com")
    
    # Generate ID
    callback_id = engine.generate_callback_id()
    assert callback_id, "Failed to generate callback ID"
    print(f"✓ Generated callback ID: {callback_id[:8]}...")
    
    # Generate payloads
    payloads = engine.get_all_payloads(callback_id)
    assert len(payloads) > 0, "No payloads generated"
    print(f"✓ Generated {len(payloads)} payload types")
    
    # Test parameter detection
    assert engine.is_ssrf_parameter("url"), "Failed to detect 'url' parameter"
    assert engine.is_ssrf_parameter("callback"), "Failed to detect 'callback' parameter"
    assert not engine.is_ssrf_parameter("search"), "Incorrectly flagged 'search' as SSRF"
    print("✓ Parameter detection working")
    
    return True


def test_ssrf_module():
    """Test SSRF module initialization."""
    print("\nTesting SSRF module...")
    
    from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
    
    try:
        module = BlindSSRFModule("http://attacker.com:5000", timeout=10, wait_time=5)
        print("✓ BlindSSRFModule initialized")
        
        # Test that module has required methods
        assert hasattr(module, 'scan_url'), "Missing scan_url method"
        assert hasattr(module, 'scan_post_form'), "Missing scan_post_form method"
        assert hasattr(module, 'get_all_injections'), "Missing get_all_injections method"
        assert hasattr(module, 'wait_for_callbacks'), "Missing wait_for_callbacks method"
        print("✓ All required methods present")
        
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        return False


def test_output_directory():
    """Test that output directories are set up."""
    print("\nTesting output setup...")
    
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bssrf", "output")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        print(f"✓ Created output directory: {output_dir}")
    else:
        print(f"✓ Output directory exists: {output_dir}")
    
    return True


def test_main_integration():
    """Test that main.py includes SSRF option."""
    print("\nTesting main.py integration...")
    
    main_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "main.py")
    
    with open(main_file, 'r') as f:
        content = f.read()
    
    if "\"ssrf\"" in content or "'ssrf'" in content:
        print("✓ SSRF option found in main.py")
    else:
        print("✗ SSRF option not found in main.py")
        return False
    
    if "from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule" in content:
        print("✓ SSRF module import found in main.py")
    else:
        print("⚠ SSRF module import should be added to main.py for direct access")
    
    return True


def main():
    """Run all integration tests."""
    print("=" * 70)
    print("SSRF MODULE INTEGRATION TEST")
    print("=" * 70)
    
    all_passed = True
    
    # Run tests
    all_passed &= test_imports()
    all_passed &= test_payload_engine()
    all_passed &= test_ssrf_module()
    all_passed &= test_output_directory()
    all_passed &= test_main_integration()
    
    # Summary
    print("\n" + "=" * 70)
    if all_passed:
        print("✓ ALL INTEGRATION TESTS PASSED")
        print("\nReady to use:")
        print("  1. Demo: python bssrf/teacher_demo.py")
        print("  2. Vulnerable app: python demo_vuln_app/app.py")
        print("  3. Main scanner: python main.py -f targets.txt --scan ssrf --listener http://attacker.com")
    else:
        print("✗ SOME TESTS FAILED")
        print("Please check the errors above.")
        sys.exit(1)
    print("=" * 70)


if __name__ == "__main__":
    main()
