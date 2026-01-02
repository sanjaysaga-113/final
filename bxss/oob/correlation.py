"""
Correlation Logic for Blind XSS Detection (Production-Grade)

Features:
- Injection expiration (ignore old injections beyond TTL)
- Enhanced validation (timestamp, expiry checks)
- ML feature integration

Matches injected payloads (UUID) with received callbacks.
A finding is VALID only if:
  - Callback UUID matches injection UUID
  - Callback timestamp > injection timestamp
  - Injection not expired (within TTL window)
"""
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from threading import Lock

# Injection expiration window (matches callback_server.py)
INJECTION_EXPIRY_HOURS = 24


class InjectionTracker:
    """
    Thread-safe tracker for injected payloads.
    Maps UUID -> injection metadata.
    """
    
    def __init__(self):
        self.injections = {}
        self.lock = Lock()
    
    def record_injection(self, uuid: str, url: str, parameter: str, payload: str, timestamp: str = None):
        """
        Record a payload injection for later correlation.
        """
        if timestamp is None:
            timestamp = datetime.utcnow().isoformat()
        
        # Normalize UUID to lowercase for consistent matching
        uuid = uuid.lower() if uuid else uuid
        
        with self.lock:
            self.injections[uuid] = {
                "uuid": uuid,
                "url": url,
                "parameter": parameter,
                "payload": payload,
                "timestamp": timestamp,
                "correlated": False,
            }
    
    def get_injection(self, uuid: str) -> Optional[Dict]:
        """
        Retrieve injection metadata by UUID.
        """
        with self.lock:
            return self.injections.get(uuid)
    
    def mark_correlated(self, uuid: str):
        """
        Mark an injection as correlated (callback received).
        """
        with self.lock:
            if uuid in self.injections:
                self.injections[uuid]["correlated"] = True
    
    def get_all_injections(self) -> Dict:
        """
        Return all tracked injections.
        """
        with self.lock:
            return self.injections.copy()


# Global injection tracker
_injection_tracker = InjectionTracker()


def record_injection(uuid: str, url: str, parameter: str, payload: str):
    """
    Record an injection for later correlation.
    """
    _injection_tracker.record_injection(uuid, url, parameter, payload)


def correlate_callbacks(callbacks: List[Dict]) -> List[Dict]:
    """
    Correlate callbacks with injected payloads.
    
    Returns a list of findings where:
      - UUID matches
      - Callback timestamp > injection timestamp
      - Injection not expired (within INJECTION_EXPIRY_HOURS window)
    """
    from bsqli.core.logger import get_logger
    logger = get_logger("correlation")
    
    findings = []
    now = datetime.utcnow()
    expiry_window = timedelta(hours=INJECTION_EXPIRY_HOURS)
    
    # Debug: Show tracked injections and received callbacks
    all_injections = _injection_tracker.get_all_injections()
    logger.info(f"[CORRELATION] Tracked injections: {len(all_injections)} | Received callbacks: {len(callbacks)}")
    
    tracked_uuids = set(all_injections.keys())
    callback_uuids = {cb.get("uuid") for cb in callbacks if cb.get("uuid")}
    logger.info(f"[CORRELATION] Tracked UUIDs sample: {list(tracked_uuids)[:3]}")
    logger.info(f"[CORRELATION] Callback UUIDs sample: {list(callback_uuids)[:3]}")
    
    for callback in callbacks:
        uuid = callback.get("uuid", "")
        if not uuid:
            continue
        
        # Normalize UUID to lowercase for consistent matching
        uuid = uuid.lower()
        
        injection = _injection_tracker.get_injection(uuid)
        if not injection:
            # Callback received but no matching injection (possibly from previous scan)
            logger.debug(f"[CORRELATION] No matching injection for UUID: {uuid}")
            continue
        
        # Parse timestamps
        injection_time = datetime.fromisoformat(injection["timestamp"])
        callback_time = datetime.fromisoformat(callback["timestamp"])
        
        # Check if injection has expired
        injection_age = now - injection_time
        if injection_age > expiry_window:
            # Injection too old - ignore callback
            logger.debug(f"[CORRELATION] Injection expired (age={injection_age}): {uuid}")
            continue
        
        # Validate timestamp ordering
        if callback_time < injection_time:
            # Invalid: callback before injection (clock skew or error)
            logger.debug(f"[CORRELATION] Callback before injection (skew): {uuid}")
            continue
        
        # Valid finding
        finding = {
            "url": injection["url"],
            "parameter": injection["parameter"],
            "payload": injection["payload"],
            "injection_timestamp": injection["timestamp"],
            "callback_timestamp": callback["timestamp"],
            "callback_source_ip": callback.get("source_ip", ""),
            "callback_user_agent": callback.get("user_agent", ""),
            "callback_referer": callback.get("referer", ""),
            "callback_x_forwarded_for": callback.get("x_forwarded_for", ""),
            "uuid": uuid,
            "delay_seconds": (callback_time - injection_time).total_seconds(),
            "injection_age_hours": injection_age.total_seconds() / 3600,
        }
        
        findings.append(finding)
        _injection_tracker.mark_correlated(uuid)
        logger.info(f"[CORRELATION] Correlated: {uuid} | param={injection['parameter']} | delay={finding['delay_seconds']:.2f}s")
    
    return findings


def calculate_confidence(findings: List[Dict]) -> str:
    """
    Calculate confidence level based on number of callbacks and timing.
    
    LOW: Single callback
    MEDIUM: Multiple callbacks from same endpoint
    HIGH: Repeated callbacks over time
    """
    if not findings:
        return "NONE"
    
    if len(findings) == 1:
        return "LOW"
    
    # Check if callbacks are from same endpoint (parameter)
    endpoints = set(f"{f['url']}:{f['parameter']}" for f in findings)
    if len(endpoints) == 1 and len(findings) >= 2:
        return "MEDIUM"
    
    # Check if callbacks span multiple time periods (> 60 seconds apart)
    times = sorted([datetime.fromisoformat(f['callback_timestamp']) for f in findings])
    if len(times) >= 2:
        time_span = (times[-1] - times[0]).total_seconds()
        if time_span > 60:
            return "HIGH"
    
    return "MEDIUM"


def get_injection_tracker() -> InjectionTracker:
    """
    Get the global injection tracker.
    """
    return _injection_tracker


def load_callbacks_from_file(filepath: str) -> List[Dict]:
    """
    Load callbacks from JSON file.
    """
    if not os.path.exists(filepath):
        return []
    
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception:
        return []


def save_findings(findings: List[Dict], output_dir: str = None):
    """
    Save correlated findings to JSON and TXT files.
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), "..", "output")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # ML: Score findings before saving
    try:
        from bxss.ml.features import score_findings
        scored_findings = score_findings(findings)
        print(f"[ML] Scored {len(scored_findings)} findings with anomaly detection")
    except Exception as e:
        print(f"[ML] Warning: Failed to score findings: {e}")
        scored_findings = findings
    
    # JSON output
    json_file = os.path.join(output_dir, "findings_xss.json")
    with open(json_file, 'w') as f:
        json.dump(scored_findings, f, indent=2)

    # Text output (human-friendly)
    txt_file = os.path.join(output_dir, "findings_xss.txt")
    with open(txt_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("BLIND XSS FINDINGS\n")
        f.write("=" * 80 + "\n\n")
        if not scored_findings:
            f.write("No confirmed callbacks correlated to injections.\n")
        
        for idx, finding in enumerate(scored_findings, 1):
            f.write(f"[{idx}] {finding['url']}\n")
            f.write(f"    Target: {finding['parameter']}\n")
            f.write(f"    Delay: {finding['delay_seconds']:.2f}s (inj→cb)\n")
            f.write(f"    Payload (trunc): {finding['payload'][:80]}...\n")
            f.write(f"    Callback IP: {finding['callback_source_ip']}\n")
            f.write(f"    User-Agent: {finding['callback_user_agent'][:80]}...\n")
            f.write(f"    UUID: {finding['uuid']}\n")
            # ML scoring info
            ml_conf = finding.get('ml_confidence', 'N/A')
            anomaly_score = finding.get('anomaly_score', 'N/A')
            decision = finding.get('anomaly_decision', 'N/A')
            f.write(f"    ML: {ml_conf} (score={anomaly_score}, decision={decision})\n")
            f.write("-" * 80 + "\n")

    # Persist features for ML pipeline
    try:
        from bxss.ml.features import append_features
        append_features(findings)
        print(f"[ML] Persisted {len(findings)} features to ML dataset")
    except Exception as e:
        # do not fail report generation if ML feature persistence fails
        print(f"[ML] Warning: Failed to persist features: {e}")
    
    return json_file, txt_file
