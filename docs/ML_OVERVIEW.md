# Machine Learning Overview

This document summarizes how machine learning is wired into the project for Blind SQLi (BSQLI) and Blind XSS (BXSS), what data is collected, how models are trained, where artifacts live, and the current limitations/next steps.

## Quick status
- BSQLI: Feature logging and optional IsolationForest scoring are implemented in the scanning pipeline. Training is available but requires scikit-learn and enough feature rows.
- BXSS: Feature extraction and scoring hooks are implemented; an IsolationForest training script is provided. Functionality depends on collected callback data and installed scikit-learn.
- Both paths gracefully degrade if models are missing; scanning still runs and continues to log features.

## Components (files)
- BSQLI ML stub and model utils: [bsqli/ml/anomaly_stub.py](bsqli/ml/anomaly_stub.py)
- BSQLI detectors that emit feature vectors: [bsqli/modules/blind_sqli/detector.py](bsqli/modules/blind_sqli/detector.py)
- BXSS feature extraction and scoring: [bxss/ml/features.py](bxss/ml/features.py)
- BXSS training script: [bxss/ml/train_bxss.py](bxss/ml/train_bxss.py)
- BXSS dataset/model info helper: [bxss/ml/info_bxss.py](bxss/ml/info_bxss.py)
- BXSS future roadmap (stub only): [bxss/ml_stub.py](bxss/ml_stub.py)
- Integration smoke check script: [verify_ml_integration.py](verify_ml_integration.py)

## Data flow
### BSQLI
1) During scans, detector methods call `prepare_feature_vector()` and `persist_feature_vector()` when boolean or time-based heuristics find evidence. See [bsqli/modules/blind_sqli/detector.py](bsqli/modules/blind_sqli/detector.py).
2) Feature rows are appended to CSV at [bsqli/output/features.csv](bsqli/output/features.csv).
3) Optional: `train_model()` in [bsqli/ml/anomaly_stub.py](bsqli/ml/anomaly_stub.py) loads the CSV, scales numeric features, trains an IsolationForest, and persists model + scaler to [bsqli/output/isolation_forest_model.pkl](bsqli/output/isolation_forest_model.pkl) and [bsqli/output/feature_scaler.pkl](bsqli/output/feature_scaler.pkl).
4) Optional scoring: `score_feature_vector()` loads the saved model and returns `(label, decision_score)` for a single vector.

### BXSS
1) After callbacks are correlated, findings pass through [bxss/ml/features.py](bxss/ml/features.py). `append_features()` writes feature rows to [bxss/output/features.csv](bxss/output/features.csv).
2) `score_findings()` (same file) attempts to load [bxss/output/bxss_isolation_forest.pkl](bxss/output/bxss_isolation_forest.pkl) and [bxss/output/bxss_scaler.pkl](bxss/output/bxss_scaler.pkl). If present, it adds `anomaly_score`, `anomaly_decision`, and `ml_confidence` to each finding; otherwise, it annotates with placeholders.
3) Training script [bxss/ml/train_bxss.py](bxss/ml/train_bxss.py) reads the BXSS feature CSV, fits a scaler + IsolationForest, and saves artifacts back to the output directory.

## Feature schemas
### BSQLI feature CSV columns (canonical order)
- timestamp
- url
- parameter
- injection_type (boolean, boolean-form, boolean-cookie, time-based, time-form, time-cookie, etc.)
- payload
- baseline_time
- injected_time
- delta (injected_time - baseline_time)
- delta_ratio (delta / baseline_time)
- content_length
- status_code
- response_entropy (Shannon entropy of body)
- jitter_variance (baseline timing std dev, if provided)
- endpoint_class (auth, search, api, admin, generic, unknown)

### BXSS feature CSV columns (canonical order)
- uuid
- delay_seconds
- time_bucket (0=0-10s, 1=10-60s, 2=>60s)
- callback_repeat_count
- ua_fingerprint (1=browser, 0=bot/unknown)
- has_header_context
- has_json_context
- payload_type_script
- payload_type_event
- payload_type_bypass
- payload_type_json
- payload_type_header
- payload_type_exfil
- endpoint_hash (sha256(url|param) truncated to 32-bit int)
- hour_of_day

## Model training and usage
### Prerequisites
- Python environment with scikit-learn and numpy installed (see requirements.txt for base deps; install extras as needed).

### BSQLI training
- Command: `python -m bsqli.ml.anomaly_stub` (or call `train_model()` programmatically).
- Input: [bsqli/output/features.csv](bsqli/output/features.csv) with valid numeric rows.
- Output: [bsqli/output/isolation_forest_model.pkl](bsqli/output/isolation_forest_model.pkl) and [bsqli/output/feature_scaler.pkl](bsqli/output/feature_scaler.pkl).
- Warmup: `_endpoint_request_counts` with `WARMUP_THRESHOLD = 30` to avoid scoring before enough baseline data per endpoint.
- Scoring: `score_feature_vector(vec)` returns `(label, decision_score)` where label -1 indicates anomaly (potential true positive) and 1 indicates normal.

### BXSS training
- Command: `python bxss/ml/train_bxss.py`.
- Input: [bxss/output/features.csv](bxss/output/features.csv) with at least 10 rows (else training warns and exits).
- Output: [bxss/output/bxss_isolation_forest.pkl](bxss/output/bxss_isolation_forest.pkl) and [bxss/output/bxss_scaler.pkl](bxss/output/bxss_scaler.pkl).
- Scoring: `score_findings(findings)` attaches `anomaly_score` (-1 anomaly, 1 normal), `anomaly_decision` (float from `decision_function`), and `ml_confidence` (HIGH/LOW or reason when unavailable).

## Model details and prediction logic
- Shared stack: StandardScaler for normalization, then scikit-learn IsolationForest (unsupervised, n_estimators=100, contamination=0.1, random_state=42, max_samples=auto for BSQLI and default for BXSS). If scikit-learn or artifacts are missing, scoring is skipped and scanning continues while still logging features.

### How scoring works (mathematical view)
1) Build feature vector in the same order used at train time.
2) Normalize: $X_{scaled} = (X - \mu) / \sigma$ with the saved scaler.
3) IsolationForest predicts label: -1 for sparse regions (anomalies), 1 for dense regions (normal). The `decision_function` gives relative isolation depth; more negative implies stronger anomaly.
4) Post-process:
	- BSQLI: `score_feature_vector` returns `(label, decision_score)`; caller can treat -1 as likely true positive.
	- BXSS: `score_findings` adds `anomaly_score` (-1/1), `anomaly_decision` (float), and `ml_confidence` (HIGH for -1, LOW for 1, or a placeholder when unavailable).

### BSQLI model inputs/behavior
- Training vector: [baseline_time, injected_time, delta, content_length, status_code] from [bsqli/ml/anomaly_stub.py](bsqli/ml/anomaly_stub.py). Richer fields (delta_ratio, response_entropy, jitter_variance, endpoint_class) are logged but not yet used in training.
- Warmup guard: `_endpoint_request_counts` with `WARMUP_THRESHOLD = 30` per endpoint_class to avoid premature scoring.
- Runtime collection sites: boolean/time detectors in [bsqli/modules/blind_sqli/detector.py](bsqli/modules/blind_sqli/detector.py) call `prepare_feature_vector` then `persist_feature_vector`.
- Persistence: thread-safe CSV writes to [bsqli/output/features.csv](bsqli/output/features.csv).

### BXSS model inputs/behavior
- Training vector: numeric columns from [bxss/ml/features.py](bxss/ml/features.py) excluding `uuid` (delay bucket, repeat count, UA fingerprint, context flags, payload one-hot, endpoint hash, hour).
- Runtime collection site: correlation step calls `append_features` to store rows in [bxss/output/features.csv](bxss/output/features.csv).
- Scoring: `score_findings` loads artifacts, scales vectors, predicts labels, and annotates findings; if artifacts are absent, it fills placeholders and returns original findings.

### Fallbacks and robustness
- Missing models or scaler: scoring is skipped; scanning and feature logging continue.
- Missing scikit-learn: training and scoring return early with warnings; data collection still happens.
- Output folders: auto-created; BSQLI writes are lock-protected.

### Current limitations
- BSQLI training ignores some logged signals (delta_ratio, entropy, jitter, endpoint class); expanding the training vector is a near-term improvement.
- BXSS features are heuristic; adaptive payload selection and richer anomaly signals (per the roadmap in [bxss/ml_stub.py](bxss/ml_stub.py)) are not yet implemented.
- No automated retraining/versioning; rerun training scripts as data grows.

## Operational notes
- Absence of model files does not block scanning; the pipelines keep logging features for future training.
- Feature persistence is thread-safe on the BSQLI path via a lock in [bsqli/ml/anomaly_stub.py](bsqli/ml/anomaly_stub.py).
- Output directories are auto-created if missing.
- To check integration, run: `python verify_ml_integration.py`.

## Limitations and next steps
- BSQLI model uses only five numeric features (timings, content length, status); richer signals (entropy, jitter) are logged but not yet consumed in training.
- BXSS ML currently relies on simple feature heuristics and an unsupervised IsolationForest; no adaptive payload selection yet.
- No automated retraining or model versioning; manual execution is required.
- BXSS roadmap for adaptive scanning and advanced anomaly filtering is described in [bxss/ml_stub.py](bxss/ml_stub.py) but not implemented.

## Artifacts and locations
- BSQLI features: [bsqli/output/features.csv](bsqli/output/features.csv)
- BSQLI model: [bsqli/output/isolation_forest_model.pkl](bsqli/output/isolation_forest_model.pkl)
- BSQLI scaler: [bsqli/output/feature_scaler.pkl](bsqli/output/feature_scaler.pkl)
- BXSS features: [bxss/output/features.csv](bxss/output/features.csv)
- BXSS model: [bxss/output/bxss_isolation_forest.pkl](bxss/output/bxss_isolation_forest.pkl)
- BXSS scaler: [bxss/output/bxss_scaler.pkl](bxss/output/bxss_scaler.pkl)
