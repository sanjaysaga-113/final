import csv
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import logging
import pickle
from ..core.config import OUTPUT_DIR

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

"""
ML stub for future work. DO NOT IMPLEMENT ML NOW.

This module provides:
- persist_feature_vector: append a structured feature vector to a CSV store (thread-safe).
- load_feature_store: read stored feature vectors for future training.
- prepare_feature_vector: small helper to normalize detector output into a feature dict.
- load_model / train_model: placeholders (NO ML logic here).

Design notes (for future implementation):
- Feature schema includes:
    baseline_time, injected_time, delta, content_length, status_code, url, parameter, injection_type, payload, timestamp
- Use this CSV to train IsolationForest / OneClassSVM later.
- Keep ML interfaces decoupled from detection pipeline.
"""

LOGGER = logging.getLogger("bsqli.ml.anomaly_stub")
FEATURE_STORE = Path(OUTPUT_DIR) / "features.csv"
_LOCK = threading.Lock()

# canonical headers for the feature store
_FEATURE_HEADERS = [
    "timestamp",
    "url",
    "parameter",
    "injection_type",
    "payload",
    "baseline_time",
    "injected_time",
    "delta",
    "content_length",
    "status_code",
]

def _ensure_store():
    FEATURE_STORE.parent.mkdir(parents=True, exist_ok=True)
    if not FEATURE_STORE.exists():
        with FEATURE_STORE.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_FEATURE_HEADERS)
            writer.writeheader()

def persist_feature_vector(vec: Dict[str, Optional[object]]) -> None:
    """
    Append a feature vector to the CSV store in a thread-safe manner.
    Expecting keys matching _FEATURE_HEADERS (missing keys will be written as empty).
    Keep this function lightweight and synchronous (called from scanner).
    """
    try:
        _ensure_store()
        row = {k: vec.get(k, "") for k in _FEATURE_HEADERS}
        # normalize types to strings
        row["timestamp"] = row.get("timestamp") or datetime.utcnow().isoformat()
        with _LOCK:
            with FEATURE_STORE.open("a", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=_FEATURE_HEADERS)
                writer.writerow(row)
    except Exception as e:
        LOGGER.debug("Failed to persist feature vector: %s", e)

def load_feature_store(limit: Optional[int] = None) -> List[Dict[str, str]]:
    """
    Load stored feature vectors from CSV.
    Returns list of dictionaries (all values as strings). Optionally limit rows.
    """
    res: List[Dict[str, str]] = []
    if not FEATURE_STORE.exists():
        return res
    try:
        with FEATURE_STORE.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                res.append(row)
                if limit and i + 1 >= limit:
                    break
    except Exception as e:
        LOGGER.debug("Failed to load feature store: %s", e)
    return res

def prepare_feature_vector(
    url: str,
    parameter: str,
    injection_type: str,
    payload: str,
    baseline_time: Optional[float],
    injected_time: Optional[float],
    content_length: Optional[int],
    status_code: Optional[int],
) -> Dict[str, Optional[object]]:
    """
    Build a normalized feature vector from detector outputs.
    This keeps feature construction centralized for future ML pipelines.
    """
    delta = None
    try:
        if baseline_time is not None and injected_time is not None:
            delta = injected_time - baseline_time
    except Exception:
        delta = None

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "url": url,
        "parameter": parameter,
        "injection_type": injection_type,
        "payload": payload,
        "baseline_time": baseline_time,
        "injected_time": injected_time,
        "delta": delta,
        "content_length": content_length,
        "status_code": status_code,
    }

# Placeholders for future ML work (do not implement ML logic here)
# ML Model Implementation
MODEL_PATH = Path(OUTPUT_DIR) / "isolation_forest_model.pkl"
SCALER_PATH = Path(OUTPUT_DIR) / "feature_scaler.pkl"

def load_model(path: Optional[str] = None) -> Optional[Tuple]:
    """
    Load persisted ML model and scaler from disk.
    Returns: (model, scaler) or None if not found.
    """
    if not HAS_SKLEARN:
        LOGGER.warning("scikit-learn not installed; ML inference disabled")
        return None
    
    model_file = Path(path) if path else MODEL_PATH
    scaler_file = Path(path).parent / "feature_scaler.pkl" if path else SCALER_PATH
    
    if not model_file.exists() or not scaler_file.exists():
        LOGGER.debug(f"Model file not found at {model_file}")
        return None
    
    try:
        with model_file.open("rb") as f:
            model = pickle.load(f)
        with scaler_file.open("rb") as f:
            scaler = pickle.load(f)
        LOGGER.info(f"Loaded ML model from {model_file}")
        return (model, scaler)
    except Exception as e:
        LOGGER.debug(f"Failed to load model: {e}")
        return None

def train_model(data_source: Optional[str] = None) -> Optional[str]:
    """
    Train IsolationForest model on feature vectors from CSV store.
    Args:
        data_source: path to feature CSV (default: FEATURE_STORE)
    Returns:
        Path to saved model, or None on failure.
    """
    if not HAS_SKLEARN:
        LOGGER.warning("scikit-learn not installed; training skipped")
        return None
    
    csv_path = Path(data_source) if data_source else FEATURE_STORE
    if not csv_path.exists():
        LOGGER.warning(f"Feature store not found: {csv_path}")
        return None
    
    try:
        # Load features from CSV
        features_list = []
        with csv_path.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    # Extract numeric features
                    baseline = float(row.get("baseline_time") or 0)
                    injected = float(row.get("injected_time") or 0)
                    delta = float(row.get("delta") or 0)
                    content_len = float(row.get("content_length") or 0)
                    status = float(row.get("status_code") or 200)
                    
                    features_list.append([baseline, injected, delta, content_len, status])
                except (ValueError, TypeError):
                    continue
        
        if not features_list:
            LOGGER.warning("No valid features to train on")
            return None
        
        # Train IsolationForest
        X = [[f[0], f[1], f[2], f[3], f[4]] for f in features_list]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        model = IsolationForest(
            contamination=0.1,  # assume 10% anomalies
            random_state=42,
            n_estimators=100
        )
        model.fit(X_scaled)
        
        # Save model and scaler
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with MODEL_PATH.open("wb") as f:
            pickle.dump(model, f)
        with SCALER_PATH.open("wb") as f:
            pickle.dump(scaler, f)
        
        LOGGER.info(f"Trained IsolationForest on {len(features_list)} samples. Saved to {MODEL_PATH}")
        return str(MODEL_PATH)
    except Exception as e:
        LOGGER.error(f"Model training failed: {e}")
        return None

def score_anomaly(model_tuple: Optional[Tuple], features: List[float]) -> Optional[float]:
    """
    Score a feature vector using loaded model.
    Args:
        model_tuple: (model, scaler) from load_model()
        features: [baseline_time, injected_time, delta, content_length, status_code]
    Returns:
        Anomaly score (higher = more anomalous) or None
    """
    if not model_tuple or not HAS_SKLEARN:
        return None
    
    try:
        model, scaler = model_tuple
        X_scaled = scaler.transform([features])
        # IsolationForest decision_function: negative = inlier, positive = outlier
        score = model.decision_function(X_scaled)[0]
        return score
    except Exception as e:
        LOGGER.debug(f"Anomaly scoring failed: {e}")
        return None
