"""
Show BXSS ML dataset and model info.
"""
import os
import csv
import pickle

FEATURES_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "features.csv")
MODEL_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "bxss_isolation_forest.pkl")
SCALER_FILE = os.path.join(os.path.dirname(__file__), "..", "output", "bxss_scaler.pkl")


def info():
    # Dataset
    count = 0
    headers = []
    if os.path.exists(FEATURES_FILE):
        with open(FEATURES_FILE, "r") as f:
            reader = csv.reader(f)
            headers = next(reader, None) or []
            for _ in reader:
                count += 1
    print("[DATA] Features file:", FEATURES_FILE)
    print("[DATA] Rows:", count)
    print("[DATA] Headers:", headers)

    # Model presence
    print("[MODEL] Exists:", os.path.exists(MODEL_FILE))
    print("[SCALER] Exists:", os.path.exists(SCALER_FILE))


if __name__ == "__main__":
    info()
