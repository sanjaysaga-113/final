"""
BCMDI Integration Example - How to Add to Your Scanner

This file shows exactly how to integrate the CMDi module into your main scanner.
"""

# ============================================================================
# OPTION 1: Add to main.py (Recommended)
# ============================================================================

# At the top of main.py, add this import:
from bcmdi.modules.blind_cmdi import BlindCMDiModule

# In your Scanner class __init__:
class Scanner:
    def __init__(self, timeout=10, listener_url=None):
        # ... existing code ...
        
        # Add CMDi module initialization
        self.cmdi_module = BlindCMDiModule(timeout=timeout)
        
        # ... rest of init ...
    
    def scan_target(self, url, headers=None, cookies=None):
        """
        Main scanning method.
        
        Args:
            url: Target URL
            headers: HTTP headers dict
            cookies: Cookies dict
        
        Returns:
            List of findings (SQL, XSS, SSRF, CMDi, etc.)
        """
        all_findings = []
        headers = headers or {}
        cookies = cookies or {}
        
        # ... existing SQL injection scanning ...
        
        # ... existing XSS scanning ...
        
        # ... existing SSRF scanning ...
        
        # ADD: CMDi scanning
        cmdi_findings = self.cmdi_module.scan_url(url, headers=headers, cookies=cookies)
        all_findings.extend(cmdi_findings)
        
        return all_findings
    
    def scan_raw_request(self, raw_request):
        """
        Scan a raw HTTP request for all vulnerability types.
        
        Args:
            raw_request: Dict with method, url, headers, cookies, body, content_type
        
        Returns:
            List of findings
        """
        all_findings = []
        
        # ... existing scanning ...
        
        # ADD: CMDi scanning
        cmdi_findings = self.cmdi_module.scan_raw_request(raw_request)
        all_findings.extend(cmdi_findings)
        
        return all_findings


# ============================================================================
# OPTION 2: Standalone Usage (for testing)
# ============================================================================

from bcmdi.modules.blind_cmdi import BlindCMDiModule

def scan_for_command_injection(url, headers=None, cookies=None):
    """Quick CMDi scan utility function."""
    module = BlindCMDiModule(timeout=10)
    findings = module.scan_url(url, headers=headers, cookies=cookies)
    return findings

# Usage:
# findings = scan_for_command_injection("http://example.com/search?q=test")
# for finding in findings:
#     print(f"Vulnerable: {finding['parameter']}")


# ============================================================================
# OPTION 3: Advanced Configuration
# ============================================================================

from bcmdi.modules.blind_cmdi import BlindCMDiDetector

class AdvancedScanner:
    def __init__(self, timeout=10, custom_payloads=False):
        self.detector = BlindCMDiDetector(timeout=timeout)
        self.custom_payloads = custom_payloads
    
    def scan_with_custom_os_hint(self, url, os_type="linux"):
        """Scan with explicit OS type."""
        self.detector.os_hint = os_type
        result = self.detector.detect_query_param(url, param="test")
        return result


# ============================================================================
# OPTION 4: Integration with Recon Pipeline
# ============================================================================

from bcmdi.modules.blind_cmdi import BlindCMDiModule
from recon.recon_manager import ReconManager

def integrated_scan_pipeline():
    """Full pipeline: recon → parameter scoring → vulnerability scanning."""
    
    # 1. Run reconnaissance
    recon = ReconManager()
    urls = recon.gather_urls()
    params = recon.score_parameters(urls)
    
    # 2. Initialize vulnerability scanners
    cmdi_module = BlindCMDiModule()
    
    # 3. Scan likely vulnerable parameters
    all_findings = []
    for param_info in params:
        url = param_info["url"]
        findings = cmdi_module.scan_url(url)
        all_findings.extend(findings)
    
    return all_findings


# ============================================================================
# OPTION 5: Output Format & Storage
# ============================================================================

import json
from pathlib import Path
from bcmdi.modules.blind_cmdi import BlindCMDiModule

def scan_and_save(url, output_file="bcmdi_findings.json"):
    """Scan and save findings to JSON."""
    module = BlindCMDiModule()
    findings = module.scan_url(url)
    
    # Convert to JSON-serializable format
    output = {
        "url": url,
        "scan_type": "blind_cmdi",
        "findings": findings
    }
    
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2, default=str)
    
    return len(findings)


# ============================================================================
# OPTION 6: Batch Scanning
# ============================================================================

from bcmdi.modules.blind_cmdi import BlindCMDiModule
from concurrent.futures import ThreadPoolExecutor

def batch_scan_urls(urls, max_workers=5):
    """Scan multiple URLs concurrently."""
    module = BlindCMDiModule(timeout=10)
    all_findings = []
    
    def scan_single(url):
        try:
            return module.scan_url(url)
        except Exception as e:
            print(f"Error scanning {url}: {e}")
            return []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(scan_single, urls)
        for result in results:
            all_findings.extend(result)
    
    return all_findings


# ============================================================================
# OPTION 7: Result Post-Processing & Filtering
# ============================================================================

def filter_findings_by_confidence(findings, min_confidence="MEDIUM"):
    """Filter CMDi findings by confidence level."""
    confidence_levels = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    min_level = confidence_levels.get(min_confidence, 0)
    
    filtered = []
    for finding in findings:
        if finding.get("type") == "blind_cmdi":
            finding_level = confidence_levels.get(finding.get("confidence", "LOW"), 0)
            if finding_level >= min_level:
                filtered.append(finding)
    
    return filtered


def group_findings_by_parameter(findings):
    """Group CMDi findings by vulnerable parameter."""
    grouped = {}
    for finding in findings:
        if finding.get("type") == "blind_cmdi":
            param = finding.get("parameter", "unknown")
            if param not in grouped:
                grouped[param] = []
            grouped[param].append(finding)
    
    return grouped


# ============================================================================
# OPTION 8: Error Handling & Resilience
# ============================================================================

from bcmdi.modules.blind_cmdi import BlindCMDiModule
import logging

logger = logging.getLogger(__name__)

def resilient_scan(url, headers=None, cookies=None, retries=2):
    """Scan with retry logic and error handling."""
    for attempt in range(retries):
        try:
            module = BlindCMDiModule(timeout=10)
            findings = module.scan_url(url, headers=headers, cookies=cookies)
            logger.info(f"[CMDi] Scanned {url}: {len(findings)} findings")
            return findings
        
        except TimeoutError:
            logger.warning(f"[CMDi] Timeout on {url}, attempt {attempt+1}/{retries}")
            if attempt == retries - 1:
                raise
        
        except Exception as e:
            logger.error(f"[CMDi] Error scanning {url}: {e}")
            if attempt == retries - 1:
                raise
    
    return []


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

if __name__ == "__main__":
    # Example 1: Simple URL scan
    from bcmdi.modules.blind_cmdi import BlindCMDiModule
    
    module = BlindCMDiModule()
    url = "http://target.com/search?q=test"
    findings = module.scan_url(url)
    
    for finding in findings:
        print(f"[!] CMDi vulnerability found")
        print(f"    Parameter: {finding['parameter']}")
        print(f"    Confidence: {finding['confidence']}")
        print(f"    Technique: {finding['technique']}")
    
    # Example 2: Batch scanning
    # urls = ["http://target1.com/api", "http://target2.com/search"]
    # all_findings = batch_scan_urls(urls)
    
    # Example 3: Save to file
    # output_file = scan_and_save("http://target.com/", output_file="findings.json")
    # print(f"Scan complete: {output_file}")

"""
Integration Checklist:

Before integrating into main scanner:
  □ Verify imports work (from bcmdi.modules.blind_cmdi import ...)
  □ Test on vulnerable endpoint (if available)
  □ Verify findings format matches scanner conventions
  □ Check rate limiting is respected
  □ Verify output file paths are writable
  □ Test with real headers/cookies
  □ Monitor resource usage (memory, CPU, network)
  □ Review log output for errors
  □ Add error handling for network timeouts
  □ Document in project README

Production Deployment:
  □ Test in staging environment
  □ Monitor false positive rate
  □ Verify database schema for findings storage
  □ Set up alerting for HIGH confidence findings
  □ Review ML feature collection (CSV storage)
  □ Plan for log rotation (large scanning = large logs)
  □ Document expected scan time per parameter
  □ Create runbook for troubleshooting

Optional Enhancements:
  □ Add to main.py argparse (--cmdi-only, --skip-cmdi)
  □ Add to progress bar/reporting
  □ Add to findings export (JSON, HTML report)
  □ Add to analytics/metrics collection
  □ Integrate with Slack/webhook notifications
"""

print(__doc__)
