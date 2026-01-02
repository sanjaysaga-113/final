"""
Deterministic ML-guided payload selection for Blind SQLi / Blind XSS.

Constraints honored:
- Does NOT generate new payload strings; only selects/prioritizes existing classes + mutations.
- ML is used only for selection/prioritization/scoring (IsolationForest).
- Deterministic, explainable, reproducible (fixed random_state, explicit feature set).
"""
from __future__ import annotations
import csv
import logging
import os
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

LOGGER = logging.getLogger("payload_strategy")

# Enumerate payload classes we already have templates for.
PAYLOAD_CLASS_INDEX = {
    "boolean": 0,
    "time": 1,
    "bxss_script": 2,
    "bxss_event": 3,
    "bxss_bypass": 4,
    "bxss_json": 5,
    "bxss_header": 6,
    "bxss_exfil": 7,
}

MUTATION_FLAGS = {
    "case": "mutation_case",
    "comment": "mutation_comment",
    "whitespace": "mutation_whitespace",
    "encoding": "mutation_encoding",
}

FEATURE_HEADERS = [
    "payload_id",
    "payload_class_idx",
    "baseline_time",
    "injected_time",
    "delta_time",
    "status_code",
    "content_length",
    "mutation_case",
    "mutation_comment",
    "mutation_whitespace",
    "mutation_encoding",
    "aggressive",
]


@dataclass
class PayloadMeta:
    payload_id: str
    payload_class: str
    mutations: List[str] = field(default_factory=list)
    aggressive: bool = False
    target_key: Optional[str] = None  # e.g., "QUERY:param" or "HEADER:UA"


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def extract_features(response, payload_meta: PayloadMeta, baseline_time: Optional[float], injected_time: Optional[float]) -> Dict[str, object]:
    """Build feature dict for a single attempt."""
    text = getattr(response, "text", "") or ""
    status = getattr(response, "status_code", None)
    delta = None
    if baseline_time is not None and injected_time is not None:
        delta = injected_time - baseline_time

    def flag(name: str) -> int:
        return 1 if name in payload_meta.mutations else 0

    payload_class_idx = PAYLOAD_CLASS_INDEX.get(payload_meta.payload_class, -1)

    return {
        "payload_id": payload_meta.payload_id,
        "payload_class_idx": payload_class_idx,
        "baseline_time": baseline_time if baseline_time is not None else 0.0,
        "injected_time": injected_time if injected_time is not None else 0.0,
        "delta_time": delta if delta is not None else 0.0,
        "status_code": status if status is not None else 0,
        "content_length": len(text),
        "mutation_case": flag("case"),
        "mutation_comment": flag("comment"),
        "mutation_whitespace": flag("whitespace"),
        "mutation_encoding": flag("encoding"),
        "aggressive": 1 if payload_meta.aggressive else 0,
    }


def _persist_row(row: Dict[str, object], feature_store: Path) -> None:
    _ensure_dir(feature_store)
    write_header = not feature_store.exists()
    with feature_store.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FEATURE_HEADERS)
        if write_header:
            writer.writeheader()
        writer.writerow({k: row.get(k, 0) for k in FEATURE_HEADERS})


def _load_feature_matrix(feature_store: Path) -> Optional[np.ndarray]:
    if not feature_store.exists():
        return None
    X: List[List[float]] = []
    try:
        with feature_store.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    X.append([
                        float(row["payload_class_idx"]),
                        float(row["baseline_time"]),
                        float(row["injected_time"]),
                        float(row["delta_time"]),
                        float(row["status_code"]),
                        float(row["content_length"]),
                        float(row["mutation_case"]),
                        float(row["mutation_comment"]),
                        float(row["mutation_whitespace"]),
                        float(row["mutation_encoding"]),
                        float(row["aggressive"]),
                    ])
                except Exception:
                    continue
    except Exception as exc:
        LOGGER.debug("Failed to load feature matrix: %s", exc)
        return None
    return np.array(X) if X else None


def _train_model(feature_store: Path, model_path: Path, scaler_path: Path, min_samples: int) -> Optional[Tuple[IsolationForest, StandardScaler]]:
    X = _load_feature_matrix(feature_store)
    if X is None or len(X) < min_samples:
        return None

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(
        n_estimators=200,
        contamination=0.1,
        random_state=42,
    )
    model.fit(Xs)

    _ensure_dir(model_path)
    with model_path.open("wb") as mf:
        pickle.dump(model, mf)
    with scaler_path.open("wb") as sf:
        pickle.dump(scaler, sf)

    return model, scaler


def score_payload(features: Dict[str, object], feature_store: Path, model_path: Path, scaler_path: Path, min_samples: int = 30) -> Optional[int]:
    """Return anomaly label (-1 anomaly, 1 normal) or None if model unavailable."""
    try:
        # try load model
        model = scaler = None
        if model_path.exists() and scaler_path.exists():
            with model_path.open("rb") as mf:
                model = pickle.load(mf)
            with scaler_path.open("rb") as sf:
                scaler = pickle.load(sf)
        else:
            trained = _train_model(feature_store, model_path, scaler_path, min_samples)
            if trained:
                model, scaler = trained

        if model is None or scaler is None:
            return None

        vec = np.array([
            [
                float(features.get("payload_class_idx", 0)),
                float(features.get("baseline_time", 0.0)),
                float(features.get("injected_time", 0.0)),
                float(features.get("delta_time", 0.0)),
                float(features.get("status_code", 0)),
                float(features.get("content_length", 0)),
                float(features.get("mutation_case", 0)),
                float(features.get("mutation_comment", 0)),
                float(features.get("mutation_whitespace", 0)),
                float(features.get("mutation_encoding", 0)),
                float(features.get("aggressive", 0)),
            ]
        ])
        vec_s = scaler.transform(vec)
        return int(model.predict(vec_s)[0])
    except Exception as exc:
        LOGGER.debug("score_payload failed: %s", exc)
        return None


def reorder_payload_queue(queue: List[PayloadMeta], scores: Dict[str, int], reject_status_hits: Dict[str, int], max_mutations: int = 2) -> List[PayloadMeta]:
    """
    Reorder payload queue based on anomaly scores and rejection signals.
    - Anomaly (-1) gets highest priority
    - Normal (1) lower priority
    - If a payload_id has many rejects (400/403), deprioritize
    - Enforce at most `max_mutations` per payload
    """
    def priority(meta: PayloadMeta) -> Tuple[int, int, str]:
        score = scores.get(meta.payload_id)
        anomaly_rank = 0 if score == -1 else 1 if score == 1 else 2
        reject_penalty = reject_status_hits.get(meta.payload_id, 0)
        # deterministic ordering fallback by payload_id
        return (anomaly_rank, reject_penalty, meta.payload_id)

    filtered: List[PayloadMeta] = []
    for meta in queue:
        if len(meta.mutations) > max_mutations:
            trimmed = PayloadMeta(
                payload_id=meta.payload_id,
                payload_class=meta.payload_class,
                mutations=meta.mutations[:max_mutations],
                aggressive=meta.aggressive,
                target_key=meta.target_key,
            )
            filtered.append(trimmed)
        else:
            filtered.append(meta)

    return sorted(filtered, key=priority)


class PayloadStrategySelector:
    """Deterministic strategy helper for choosing payloads and mutations."""

    def __init__(
        self,
        feature_store: Path,
        model_path: Path,
        scaler_path: Path,
        min_train_samples: int = 30,
        reject_statuses: Tuple[int, ...] = (400, 403),
        aggressive_attempt_threshold: int = 12,
    ) -> None:
        self.feature_store = feature_store
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.min_train_samples = min_train_samples
        self.reject_statuses = reject_statuses
        self.aggressive_attempt_threshold = aggressive_attempt_threshold

        # state trackers
        self.reject_status_hits: Dict[str, int] = {}
        self.anomaly_scores: Dict[str, int] = {}
        self.attempts_without_anomaly: Dict[str, int] = {}
        self.aggressive_allowed_for_key: Dict[str, bool] = {}

    def register_attempt(
        self,
        payload_meta: PayloadMeta,
        response,
        baseline_time: Optional[float],
        injected_time: Optional[float],
    ) -> Optional[int]:
        """
        Persist features, score with ML (if available), and update bookkeeping.
        Returns anomaly label (-1/1) or None.
        """
        feats = extract_features(response, payload_meta, baseline_time, injected_time)
        _persist_row(feats, self.feature_store)

        label = score_payload(
            feats,
            feature_store=self.feature_store,
            model_path=self.model_path,
            scaler_path=self.scaler_path,
            min_samples=self.min_train_samples,
        )

        self.anomaly_scores[payload_meta.payload_id] = label if label is not None else 1

        status = getattr(response, "status_code", None)
        if status in self.reject_statuses:
            self.reject_status_hits[payload_meta.payload_id] = self.reject_status_hits.get(payload_meta.payload_id, 0) + 1

        if label == -1:
            self.attempts_without_anomaly[payload_meta.target_key or "*"] = 0
        else:
            key = payload_meta.target_key or "*"
            self.attempts_without_anomaly[key] = self.attempts_without_anomaly.get(key, 0) + 1
            # enable aggressive per target if repeated misses and filters observed
            if (
                self.attempts_without_anomaly[key] >= self.aggressive_attempt_threshold
                and self.reject_status_hits.get(payload_meta.payload_id, 0) >= 2
            ):
                self.aggressive_allowed_for_key[key] = True

        return label

    def should_escalate(self, target_key: str) -> bool:
        return self.aggressive_allowed_for_key.get(target_key, False)

    def reprioritize(self, queue: List[PayloadMeta]) -> List[PayloadMeta]:
        return reorder_payload_queue(queue, self.anomaly_scores, self.reject_status_hits)


__all__ = [
    "PayloadMeta",
    "PayloadStrategySelector",
    "extract_features",
    "score_payload",
    "reorder_payload_queue",
]
