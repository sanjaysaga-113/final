"""
BXSS Feature Extraction

Converts correlated findings + callback metadata into ML-ready numeric features.
Stores features in bxss/output/features.csv
"""
import os
import csv
import hashlib
from datetime import datetime
from typing import Dict, List

FEATURES_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "features.csv")
FEATURE_HEADERS = [
    "uuid",
    "delay_seconds",
    "time_bucket",           # NEW: 0-10s, 10-60s, >60s (categorical)
    "callback_repeat_count", # NEW: how many callbacks for same UUID
    "ua_fingerprint",        # NEW: browser vs bot detection
    "has_header_context",
    "has_json_context",
    "payload_type_script",
    "payload_type_event",
    "payload_type_bypass",
    "payload_type_json",
    "payload_type_header",
    "payload_type_exfil",
    "endpoint_hash",
    "hour_of_day",
]


def _hash_endpoint(url: str, parameter: str) -> int:
    h = hashlib.sha256(f"{url}|{parameter}".encode("utf-8")).hexdigest()
    return int(h[:8], 16)  # 32-bit int


def _payload_type_onehot(payload: str) -> Dict[str, int]:
    # naive mapping based on substrings used in our payload templates
    p = payload.lower()
    return {
        "payload_type_script": 1 if "<script" in p else 0,
        "payload_type_event": 1 if "onerror" in p or "onload" in p or "onfocus" in p or "ontoggle" in p else 0,
        "payload_type_bypass": 1 if "javascript:" in p or "\x00" in p or "<!--" in p else 0,
        "payload_type_json": 1 if "{" in p and "}" in p and "script" in p else 0,
        "payload_type_header": 1 if "user-agent" in p or "referer" in p else 0,
        "payload_type_exfil": 1 if "document.cookie" in p or "localstorage" in p else 0,
    }


def _classify_time_bucket(delay: float) -> int:
    """Classify callback delay into buckets: 0=0-10s, 1=10-60s, 2=>60s"""
    if delay < 10:
        return 0
    elif delay < 60:
        return 1
    else:
        return 2

def _fingerprint_ua(user_agent: str) -> int:
    """
    Classify User-Agent as browser (1) vs bot/unknown (0).
    Reduces false positives from automated callbacks.
    """
    if not user_agent:
        return 0
    ua_lower = user_agent.lower()
    # Browser signatures
    browsers = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera']
    bots = ['bot', 'crawler', 'spider', 'curl', 'wget', 'python', 'java']
    
    if any(bot in ua_lower for bot in bots):
        return 0  # Bot
    if any(browser in ua_lower for browser in browsers):
        return 1  # Browser
    return 0  # Unknown (conservative)

def extract_feature_row(finding: Dict) -> List:
    """
    Produce a feature row list aligned with FEATURE_HEADERS.
    Required keys in finding: uuid, delay_seconds, url, parameter, payload, injection_timestamp
    
    NEW FEATURES:
    - time_bucket: categorical delay classification (0-10s, 10-60s, >60s)
    - ua_fingerprint: browser vs bot detection
    - callback_repeat_count: how many callbacks for same UUID (passed in finding)
    """
    uuid = finding.get("uuid", "")
    delay = float(finding.get("delay_seconds", 0.0))
    time_bucket = _classify_time_bucket(delay)
    
    # Extract callback repeat count (if correlated multiple times)
    callback_repeat_count = int(finding.get("callback_repeat_count", 1))
    
    # Fingerprint User-Agent
    user_agent = finding.get("callback_user_agent", "")
    ua_fingerprint = _fingerprint_ua(user_agent)
    
    param = finding.get("parameter", "")
    has_header = 1 if param.startswith("HEADER:") else 0
    has_json = 1 if param.startswith("JSON:") else 0
    payload = finding.get("payload", "")
    onehot = _payload_type_onehot(payload)
    endpoint = _hash_endpoint(finding.get("url", ""), param)

    # hour of day from injection timestamp
    try:
        ts = datetime.fromisoformat(finding.get("injection_timestamp", datetime.utcnow().isoformat()))
        hour = ts.hour
    except Exception:
        hour = 0

    row = [
        uuid,
        delay,
        time_bucket,
        callback_repeat_count,
        ua_fingerprint,
        has_header,
        has_json,
        onehot["payload_type_script"],
        onehot["payload_type_event"],
        onehot["payload_type_bypass"],
        onehot["payload_type_json"],
        onehot["payload_type_header"],
        onehot["payload_type_exfil"],
        endpoint,
        hour,
    ]
    return row


def ensure_features_file():
    os.makedirs(os.path.dirname(FEATURES_FILE), exist_ok=True)
    if not os.path.exists(FEATURES_FILE):
        with open(FEATURES_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(FEATURE_HEADERS)


def append_features(findings: List[Dict]):
    if not findings:
        return
    ensure_features_file()
    with open(FEATURES_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        for finding in findings:
            writer.writerow(extract_feature_row(finding))


def score_findings(findings: List[Dict]) -> List[Dict]:
    """
    Score findings using trained IsolationForest model.
    Returns findings with 'anomaly_score' field added.
    Score: -1 = anomaly (likely true positive), 1 = normal (potential false positive)
    """
    if not findings:
        return findings
    
    try:
        import pickle
        model_file = os.path.join(os.path.dirname(__file__), "..", "output", "bxss_isolation_forest.pkl")
        scaler_file = os.path.join(os.path.dirname(__file__), "..", "output", "bxss_scaler.pkl")
        
        if not os.path.exists(model_file) or not os.path.exists(scaler_file):
            # Model not trained yet, return findings unchanged
            for f in findings:
                f["anomaly_score"] = None
                f["ml_confidence"] = "N/A (model not trained)"
            return findings
        
        with open(model_file, "rb") as mf:
            model = pickle.load(mf)
        with open(scaler_file, "rb") as sf:
            scaler = pickle.load(sf)
        
        # Extract features for prediction
        scored_findings = []
        for finding in findings:
            row = extract_feature_row(finding)
            # Skip UUID (column 0), use numeric features only
            numeric_features = [float(x) for x in row[1:]]
            
            # Scale and predict
            scaled = scaler.transform([numeric_features])
            score = model.predict(scaled)[0]
            decision_score = model.decision_function(scaled)[0]
            
            finding_copy = finding.copy()
            finding_copy["anomaly_score"] = int(score)
            finding_copy["anomaly_decision"] = float(decision_score)
            finding_copy["ml_confidence"] = "HIGH" if score == -1 else "LOW"
            scored_findings.append(finding_copy)
        
        return scored_findings
    
    except Exception as e:
        # If scoring fails, return original findings
        for f in findings:
            f["anomaly_score"] = None
            f["ml_confidence"] = f"Error: {str(e)[:50]}"
        return findings

