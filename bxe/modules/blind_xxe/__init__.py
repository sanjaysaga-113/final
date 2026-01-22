"""
Blind XXE Detection Module

Detects XML External Entity vulnerabilities through:
- Out-of-band (OAST) callbacks
- Time-based detection
- Parser behavior analysis

Example:
    from bxe.modules.blind_xxe import BlindXXEModule
    
    module = BlindXXEModule()
    finding = module.scan_xml_body(
        url="http://target.com/api/parse",
        body='<?xml version="1.0"?><root/>'
    )
    if finding["is_vulnerable"]:
        print(f"XXE Found: {finding['technique']}")
"""

from .xxe_module import BlindXXEModule
from .detector import BlindXXEDetector, OASTCorrelator
from . import payloads

__all__ = [
    "BlindXXEModule",
    "BlindXXEDetector",
    "OASTCorrelator",
    "payloads",
]
