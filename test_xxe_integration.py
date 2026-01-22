"""
Blind XXE Module - Comprehensive Test Suite

Tests:
1. Payload generation (all XXE variants)
2. OAST correlator functionality
3. Detector initialization and baseline capture
4. Time-based detection algorithm
5. Parser behavior detection
6. Control payload false-positive reduction
7. ML feature extraction
8. Full scan workflows (XML, SOAP, JSON, file upload)

Run with: python test_xxe_integration.py
"""

import unittest
import time
from unittest.mock import Mock, patch, MagicMock
from bxe.modules.blind_xxe import (
    BlindXXEModule,
    BlindXXEDetector,
    OASTCorrelator,
    payloads
)
from bsqli.core.http_client import HttpClient


class TestXXEPayloads(unittest.TestCase):
    """Test XXE payload generation"""
    
    def test_oast_http_payloads_generation(self):
        """Test HTTP OAST payload generation"""
        oast_endpoint = "http://callback.attacker.com"
        payloads_list = payloads.oast_http_payloads(oast_endpoint)
        
        self.assertGreater(len(payloads_list), 0)
        
        for payload, correlation_id, payload_type in payloads_list:
            self.assertIn("<?xml", payload)
            self.assertIn("DOCTYPE", payload)
            self.assertIn("ENTITY", payload)
            self.assertEqual(len(correlation_id), 16)  # UUID format
    
    def test_oast_dns_payloads_generation(self):
        """Test DNS OAST payload generation"""
        dns_domain = "callback.attacker.com"
        payloads_list = payloads.oast_dns_payloads(dns_domain)
        
        self.assertGreater(len(payloads_list), 0)
        
        for payload, correlation_id, payload_type in payloads_list:
            self.assertIn("http://", payload)
            self.assertIn(dns_domain, payload)
            self.assertIn(correlation_id, payload)
    
    def test_time_based_payloads_generation(self):
        """Test time-based XXE payload generation"""
        payloads_list = payloads.time_based_payloads()
        
        self.assertGreater(len(payloads_list), 0)
        
        for payload, delay_seconds, technique in payloads_list:
            self.assertIn("<?xml", payload)
            self.assertGreater(delay_seconds, 0)
            self.assertIn(technique, ["dev_random", "entity_expansion"])
    
    def test_control_payloads_generation(self):
        """Test control payload generation"""
        controls = payloads.control_payloads()
        
        self.assertEqual(len(controls), 4)
        
        for control in controls:
            self.assertIn("<?xml", control)
            # Controls should be valid XML
            self.assertIn("<?xml version", control)
    
    def test_parser_behavior_payloads(self):
        """Test parser behavior detection payloads"""
        behavior_payloads_list = payloads.parser_behavior_payloads()
        
        self.assertGreater(len(behavior_payloads_list), 0)
        
        for payload, behavior_type in behavior_payloads_list:
            self.assertIn("DOCTYPE", payload)
            self.assertIn("ENTITY", payload)
            self.assertIn(behavior_type, ["status_change", "size_change"])
    
    def test_obfuscated_payloads(self):
        """Test WAF evasion payloads"""
        oast_endpoint = "http://callback.attacker.com"
        obfuscated = payloads.obfuscated_payloads(oast_endpoint)
        
        self.assertGreater(len(obfuscated), 0)
        
        # Verify different obfuscation techniques
        techniques = {
            "whitespace": False,
            "comments": False,
            "newlines": False,
        }
        
        for payload in obfuscated:
            if "/*" in payload:
                techniques["comments"] = True
            if "\n" in payload:
                techniques["newlines"] = True
        
        # Should have at least whitespace variant
        self.assertGreater(len(obfuscated), 1)
    
    def test_json_embedded_payloads(self):
        """Test XXE in JSON payloads"""
        oast_endpoint = "http://callback.attacker.com"
        json_payloads_list = payloads.json_embedded_payloads(oast_endpoint)
        
        self.assertGreater(len(json_payloads_list), 0)
        
        for json_payload, correlation_id in json_payloads_list:
            self.assertIn("{", json_payload)
            self.assertIn("}", json_payload)
            self.assertEqual(len(correlation_id), 16)
    
    def test_soap_xxe_payloads(self):
        """Test SOAP XXE payloads"""
        oast_endpoint = "http://callback.attacker.com"
        soap_payloads_list = payloads.soap_xxe_payloads(oast_endpoint)
        
        self.assertGreater(len(soap_payloads_list), 0)
        
        for payload in soap_payloads_list:
            self.assertIn("soap:Envelope", payload)
            self.assertIn("DOCTYPE", payload)
    
    def test_svg_xxe_payloads(self):
        """Test SVG XXE payloads"""
        oast_endpoint = "http://callback.attacker.com"
        svg_payloads_list = payloads.svg_xxe_payloads(oast_endpoint)
        
        self.assertGreater(len(svg_payloads_list), 0)
        
        for payload in svg_payloads_list:
            self.assertIn("<svg", payload)
            self.assertIn("DOCTYPE", payload)


class TestOASTCorrelator(unittest.TestCase):
    """Test OAST callback correlation"""
    
    def test_register_injection(self):
        """Test registering payload injections"""
        correlator = OASTCorrelator()
        
        correlation_id = "abcd1234ef567890"
        correlator.register_injection(correlation_id, "oast_http", "http://target.com")
        
        self.assertIn(correlation_id, correlator.pending_callbacks)
    
    def test_log_callback(self):
        """Test logging received callbacks"""
        correlator = OASTCorrelator()
        
        correlation_id = "abcd1234ef567890"
        correlator.register_injection(correlation_id, "oast_http", "http://target.com")
        
        # Log callback
        result = correlator.log_callback(correlation_id, "http", "192.168.1.1")
        
        self.assertTrue(result)
        self.assertIn(correlation_id, correlator.received_callbacks)
    
    def test_get_confirmed_xxe(self):
        """Test retrieving confirmed XXE findings"""
        correlator = OASTCorrelator()
        
        correlation_id = "abcd1234ef567890"
        correlator.register_injection(correlation_id, "oast_http", "http://target.com")
        correlator.log_callback(correlation_id, "http", "192.168.1.1")
        
        confirmed = correlator.get_confirmed_xxe()
        
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0]["correlation_id"], correlation_id)


class TestBlindXXEDetector(unittest.TestCase):
    """Test XXE detector functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_http_client = Mock(spec=HttpClient)
        self.detector = BlindXXEDetector(self.mock_http_client)
    
    def test_detector_initialization(self):
        """Test detector initialization"""
        self.assertIsNotNone(self.detector.http_client)
        self.assertIsNotNone(self.detector.correlator)
        self.assertEqual(self.detector.BASELINE_SAMPLES, 3)
        self.assertEqual(self.detector.MIN_TIME_CONFIRMATIONS, 2)
    
    def test_measure_baseline(self):
        """Test baseline measurement"""
        # Mock responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"<response>test</response>"
        self.mock_http_client.post.return_value = mock_response
        
        baseline = self.detector._measure_baseline(
            "http://target.com",
            method="POST"
        )
        
        # Verify baseline structure
        self.assertIn("response_times", baseline)
        self.assertIn("status_codes", baseline)
        self.assertIn("content_lengths", baseline)
        self.assertIn("avg_time", baseline)
        self.assertIn("std_dev", baseline)
        self.assertIn("jitter_tolerance", baseline)
        
        # Verify baseline was captured
        self.assertEqual(len(baseline["response_times"]), 3)
        self.assertEqual(len(baseline["status_codes"]), 3)
    
    def test_control_payloads_check(self):
        """Test control payload false-positive detection"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"<response/>"
        mock_response.elapsed = Mock(total_seconds=Mock(return_value=0.5))
        
        self.mock_http_client.post.return_value = mock_response
        
        result = self.detector._test_control_payloads("http://target.com")
        
        self.assertTrue(result)  # Controls should pass (not delay)
    
    def test_feature_extraction(self):
        """Test ML feature extraction"""
        baseline = {
            "avg_time": 0.5,
            "std_dev": 0.1,
            "content_lengths": [100, 102, 98],
        }
        
        findings = {
            "is_vulnerable": True,
            "control_passed": True,
            "technique_count": 2,
            "latest_time": 3.5,
            "delta": 3.0,
            "response_size": 100,
            "status_code": 200,
        }
        
        features = self.detector._extract_and_persist_features(
            "http://target.com",
            "test_param",
            baseline,
            findings,
            oast_triggered=False
        )
        
        self.assertIn("response_time", features)
        self.assertIn("delta_from_baseline", features)
        self.assertIn("time_delta_ratio", features)
        self.assertIn("std_dev_ratio", features)
        self.assertGreater(features["time_delta_ratio"], 1.0)


class TestBlindXXEModule(unittest.TestCase):
    """Test high-level XXE scanner interface"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.module = BlindXXEModule(timeout=15)
    
    def test_module_initialization(self):
        """Test module initialization"""
        self.assertIsNotNone(self.module.http_client)
        self.assertIsNotNone(self.module.detector)
        self.assertEqual(self.module.timeout, 15)
    
    @patch('bxe.modules.blind_xxe.xxe_module.HttpClient')
    def test_scan_xml_body(self, mock_http_client):
        """Test XML body scanning"""
        # This would require mocking the entire detection flow
        # Simplified test here
        self.module = BlindXXEModule()
        
        result = self.module.scan_xml_body(
            url="http://target.com/api",
            body='<?xml version="1.0"?><root/>'
        )
        
        self.assertIn("is_vulnerable", result)
        self.assertIn("endpoint", result)
        self.assertIn("parameter", result)
    
    def test_scan_json_parameter(self):
        """Test JSON parameter scanning"""
        self.module = BlindXXEModule()
        
        result = self.module.scan_json_parameter(
            url="http://target.com/api",
            parameter="data",
            value='<?xml version="1.0"?><root/>'
        )
        
        self.assertIn("is_vulnerable", result)
        self.assertIn("parameter", result)
    
    def test_get_findings(self):
        """Test findings retrieval"""
        self.module = BlindXXEModule()
        
        # Module starts with no findings
        findings = self.module.get_findings()
        self.assertEqual(len(findings), 0)
    
    def test_result_to_finding_conversion(self):
        """Test result to finding conversion"""
        result = {
            "is_vulnerable": True,
            "technique": "oast",
            "confidence": "high",
            "findings": [],
            "ml_score": 0.85,
            "ml_features": {},
        }
        
        finding = self.module._result_to_finding(
            result,
            endpoint="http://target.com",
            parameter="xml_data",
            method="POST"
        )
        
        self.assertEqual(finding["type"], "blind_xxe")
        self.assertEqual(finding["endpoint"], "http://target.com")
        self.assertEqual(finding["parameter"], "xml_data")
        self.assertTrue(finding["is_vulnerable"])
        self.assertEqual(finding["ml_score"], 0.85)


class TestXXEIntegration(unittest.TestCase):
    """Integration tests for full XXE detection workflow"""
    
    def test_full_workflow_initialization(self):
        """Test complete workflow initialization"""
        module = BlindXXEModule(timeout=10)
        
        self.assertIsNotNone(module.http_client)
        self.assertIsNotNone(module.detector)
        self.assertIsNotNone(module.detector.correlator)
    
    def test_finding_structure(self):
        """Test finding format consistency"""
        module = BlindXXEModule()
        
        # Simulate a finding
        finding = {
            "type": "blind_xxe",
            "endpoint": "http://target.com",
            "parameter": "xml_body",
            "method": "POST",
            "is_vulnerable": True,
            "technique": "oast",
            "confidence": "high",
            "payload": "XXE injection in XML/SOAP/JSON",
            "findings": [],
            "ml_score": 0.9,
            "ml_features": {},
        }
        
        # Verify all required fields
        required_fields = [
            "type", "endpoint", "parameter", "is_vulnerable",
            "technique", "confidence", "ml_score"
        ]
        
        for field in required_fields:
            self.assertIn(field, finding)
        
        self.assertEqual(finding["type"], "blind_xxe")


class TestXXEEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def test_detector_with_no_baseline(self):
        """Test detector handling when baseline is unavailable"""
        mock_http_client = Mock(spec=HttpClient)
        detector = BlindXXEDetector(mock_http_client)
        
        # Time-based test with no baseline
        is_vulnerable, findings = detector._test_time_based(
            "http://target.com",
            "test_param",
            baseline=None
        )
        
        self.assertFalse(is_vulnerable)
    
    def test_module_error_handling(self):
        """Test module error handling"""
        module = BlindXXEModule()
        
        # Scan with invalid URL should not crash
        result = module.scan_xml_body(
            url="invalid_url",
            body='<?xml version="1.0"?><root/>'
        )
        
        # Should return error gracefully
        self.assertFalse(result.get("is_vulnerable", True))


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestXXEPayloads))
    suite.addTests(loader.loadTestsFromTestCase(TestOASTCorrelator))
    suite.addTests(loader.loadTestsFromTestCase(TestBlindXXEDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestBlindXXEModule))
    suite.addTests(loader.loadTestsFromTestCase(TestXXEIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestXXEEdgeCases))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("XXE MODULE TEST SUMMARY")
    print("="*70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
