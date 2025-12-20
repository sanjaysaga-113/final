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


def extract_feature_row(finding: Dict) -> List:
    """
    Produce a feature row list aligned with FEATURE_HEADERS.
    Required keys in finding: uuid, delay_seconds, url, parameter, payload, injection_timestamp
    """
    uuid = finding.get("uuid", "")
    delay = float(finding.get("delay_seconds", 0.0))
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

