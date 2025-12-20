"""
Train IsolationForest model for BXSS anomaly detection.
Reads features from bxss/output/features.csv and saves model+scaler to bxss/output.
"""
import os
import csv
import json
from typing import List
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle

FEATURES_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "features.csv")
MODEL_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "bxss_isolation_forest.pkl")
SCALER_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "bxss_scaler.pkl")

NUMERIC_IDX = list(range(1, 12))  # indices excluding uuid (col 0)


def load_features() -> List[List[float]]:
    if not os.path.exists(FEATURES_FILE):
        return []
    rows = []
    with open(FEATURES_FILE, "r") as f:
        reader = csv.reader(f)
        headers = next(reader, None)
        for r in reader:
            try:
                nums = [float(r[i]) for i in NUMERIC_IDX]
                rows.append(nums)
            except Exception:
                continue
    return rows


def train():
    X = load_features()
    if not X or len(X) < 10:
        print("[WARN] Not enough features to train (need >=10). Current:", len(X))
        return None
    
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(Xs)
    
    os.makedirs(os.path.join(os.path.dirname(__file__), "..", "output"), exist_ok=True)
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)
    with open(SCALER_FILE, "wb") as f:
        pickle.dump(scaler, f)
    
    print("[OK] Trained IsolationForest")
    print("[OK] Saved:", MODEL_FILE, "and", SCALER_FILE)
    return MODEL_FILE


if __name__ == "__main__":
    train()
