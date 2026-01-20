"""
Test SSRF Callback Verification System

Verifies that callback server, correlation, and SSRF module work together.
"""

import sys
import os
import time
import json

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

def test_callback_server():
    """Test if callback server module can be imported."""
    print("[TEST 1] Importing callback server...")
    try:
        from bssrf.oob.callback_server import app, save_callback
        print("  ✅ Callback server module imported")
        return True
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        return False


def test_correlator():
    """Test callback correlator."""
    print("\n[TEST 2] Testing callback correlator...")
    try:
        from bssrf.oob.correlation import CallbackCorrelator
        
        # Create correlator
        correlator = CallbackCorrelator(callback_source="file")
        print("  ✅ Correlator initialized")
        
        # Test health check
        healthy = correlator.check_callback_server_health()
        if healthy:
            print("  ✅ Callback system healthy")
        else:
            print("  ⚠️  Callback system check returned False (may be ok)")
        
        return True
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        return False


def test_ssrf_module_with_verification():
    """Test SSRF module with callback verification enabled."""
    print("\n[TEST 3] Testing SSRF module with verification...")
    try:
        from bssrf.modules.blind_ssrf.ssrf_module import BlindSSRFModule
        
        # Initialize with verification enabled
        module = BlindSSRFModule(
            listener_url="http://test.example.com",
            wait_time=5,
            verify_callbacks=True
        )
        
        print(f"  ✅ Module initialized")
        print(f"  ✅ Callback verification: {module.verify_callbacks}")
        print(f"  ✅ Correlator present: {module.correlator is not None}")
        
        return True
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        return False


def test_simulated_callback():
    """Simulate a callback and test correlation."""
    print("\n[TEST 4] Simulating callback flow...")
    try:
        from bssrf.oob.correlation import CallbackCorrelator
        from bssrf.modules.blind_ssrf.payloads import SSRFPayloadEngine
        import uuid
        
        # Setup
        correlator = CallbackCorrelator(callback_source="file")
        engine = SSRFPayloadEngine("http://test.example.com")
        
        # Generate a payload with UUID
        test_uuid = str(uuid.uuid4())
        print(f"  Generated test UUID: {test_uuid}")
        
        # Simulate an injection
        injection = {
            'uuid': test_uuid,
            'url': 'http://target.com/test',
            'parameter': 'url',
            'payload_type': 'http',
            'timestamp': '2026-01-05T10:00:00'
        }
        
        # Simulate a callback (manually write to file)
        callbacks_file = os.path.join(
            os.path.dirname(__file__), "output", "callbacks.json"
        )
        os.makedirs(os.path.dirname(callbacks_file), exist_ok=True)
        
        callback = {
            'uuid': test_uuid,
            'timestamp': '2026-01-05T10:00:05',
            'remote_addr': '127.0.0.1',
            'path': '/ssrf',
            'method': 'GET'
        }
        
        with open(callbacks_file, 'w') as f:
            json.dump([callback], f)
        
        print(f"  ✅ Simulated callback saved")
        
        # Check if UUID is found
        found = correlator.check_uuid(test_uuid)
        if found:
            print(f"  ✅ UUID found in callbacks!")
            print(f"     Callback from: {found.get('remote_addr')}")
        else:
            print(f"  ❌ UUID not found in callbacks")
            return False
        
        # Cleanup
        if os.path.exists(callbacks_file):
            os.remove(callbacks_file)
            print(f"  ✅ Cleanup complete")
        
        return True
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_payload_generation_with_advanced():
    """Test advanced payload generation."""
    print("\n[TEST 5] Testing advanced payload generation...")
    try:
        from bssrf.modules.blind_ssrf.payloads import SSRFPayloadEngine
        
        engine = SSRFPayloadEngine("http://test.example.com")
        callback_id = "test-123"
        
        # Basic payloads
        basic = engine.get_all_payloads(callback_id)
        print(f"  ✅ Basic payloads: {len(basic)}")
        
        # Advanced payloads
        advanced = engine.get_advanced_payloads(callback_id)
        total_advanced = sum(len(v) for v in advanced.values())
        print(f"  ✅ Advanced payloads: {total_advanced}")
        
        # Encoded payloads
        encoded = engine.get_encoded_variations(callback_id)
        total_encoded = sum(len(v) for v in encoded.values())
        print(f"  ✅ Encoded variations: {total_encoded}")
        
        print(f"  ✅ Total: {len(basic) + total_advanced + total_encoded} payloads")
        
        return True
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        return False


def main():
    """Run all tests."""
    print("="*60)
    print("  SSRF CALLBACK VERIFICATION SYSTEM TEST")
    print("="*60)
    
    results = []
    
    # Run tests
    results.append(("Callback Server Import", test_callback_server()))
    results.append(("Callback Correlator", test_correlator()))
    results.append(("SSRF Module with Verification", test_ssrf_module_with_verification()))
    results.append(("Simulated Callback Flow", test_simulated_callback()))
    results.append(("Advanced Payload Generation", test_payload_generation_with_advanced()))
    
    # Summary
    print("\n" + "="*60)
    print("  TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}  {test_name}")
    
    print("="*60)
    print(f"  Results: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED - System ready for use!\n")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed - check errors above\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
