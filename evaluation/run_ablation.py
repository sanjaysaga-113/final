#!/usr/bin/env python3
"""
Run stage-wise ablation evaluation for ShadowProbe.

Stages (reviewer-requested):
1) regression: base detector outputs
2) control: add control-payload/high-confidence filter
3) delta_if: add delta-ratio / ML anomaly filter
4) oob: add callback-confirmation requirement where applicable
"""

import argparse
import csv
import json
import os
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

import requests

DEFAULT_FINDINGS = {
    "sqli": "bsqli/output/findings.json",
    "bxss": "bxss/output/findings_xss.json",
    "ssrf": "bssrf/output/findings_ssrf.json",
    "cmdi": "bcmdi/output/findings_cmdi.json",
    "xxe": "bxe/output/findings_xxe.json",
}

MODULES = ["sqli", "bxss", "ssrf", "cmdi", "xxe"]
STAGES = ["regression", "control", "delta_if", "oob"]


@dataclass
class AblationRow:
    module: str
    stage: str
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def _path_of(url: str) -> str:
    try:
        return urlparse(url).path
    except Exception:
        return ""


def _normalize_param(param: str) -> str:
    if not param:
        return ""
    text = str(param)
    if ":" in text:
        return text.split(":", 1)[-1]
    return text


def _load_ground_truth(ground_truth_url: str = "", ground_truth_file: str = "") -> dict:
    if ground_truth_file:
        with open(ground_truth_file, "r", encoding="utf-8") as f:
            return json.load(f)
    response = requests.get(ground_truth_url, timeout=15)
    response.raise_for_status()
    return response.json()


def _load_findings(path: str) -> List[dict]:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
    except Exception:
        return []
    return []


def _extract_truth(module: str, targets: List[dict]) -> Tuple[Set[Tuple[str, str, str]], Set[Tuple[str, str, str]]]:
    pos = set()
    neg = set()
    for target in targets:
        if target.get("module") != module:
            continue
        key = (module, _path_of(target.get("url", "")), _normalize_param(target.get("parameter")))
        if target.get("vulnerable"):
            pos.add(key)
        else:
            neg.add(key)
    return pos, neg


def _confidence_value(item: dict) -> str:
    conf = item.get("confidence")
    if conf is None and isinstance(item.get("details"), dict):
        conf = item["details"].get("confidence")
    return str(conf or "").upper()


def _pass_stage(module: str, stage: str, item: dict, ml_threshold: float) -> bool:
    if module == "xxe":
        regression_ok = True
    else:
        regression_ok = True

    if stage == "regression":
        return regression_ok

    conf = _confidence_value(item)
    control_ok = (
        conf in {"HIGH", "MEDIUM"}
        or bool(item.get("confirmations"))
        or bool(item.get("is_vulnerable", False))
        or bool(item.get("details", {}).get("evidence")) if isinstance(item.get("details"), dict) else False
    )
    if stage == "control":
        return control_ok

    ml_score = item.get("ml_score")
    anomaly_score = item.get("anomaly_score")
    ml_ok = False
    if anomaly_score is not None:
        try:
            ml_ok = int(anomaly_score) == -1
        except Exception:
            ml_ok = False
    if ml_score is not None:
        try:
            ml_ok = ml_ok or float(ml_score) >= ml_threshold
        except Exception:
            pass
    if stage == "delta_if":
        return control_ok and (ml_ok or ml_score is None)

    # stage == oob
    if module == "ssrf":
        return control_ok and (ml_ok or ml_score is None) and bool(item.get("confirmed", False))
    if module == "bxss":
        # correlated BXSS findings typically include callback fields
        has_callback = bool(item.get("callback_timestamp") or item.get("delay_seconds") is not None)
        return control_ok and (ml_ok or ml_score is None) and has_callback

    # non-OOB modules keep delta_if stage behavior
    return control_ok and (ml_ok or ml_score is None)


def _predicted_keys(module: str, findings: List[dict], stage: str, ml_threshold: float) -> Set[Tuple[str, str, str]]:
    keys = set()
    for item in findings:
        if module == "xxe" and not bool(item.get("is_vulnerable", True)):
            continue
        if not _pass_stage(module, stage, item, ml_threshold):
            continue
        endpoint = item.get("url") or item.get("endpoint") or ""
        parameter = _normalize_param(item.get("parameter"))
        keys.add((module, _path_of(endpoint), parameter))
    return keys


def _compute_row(module: str, stage: str, predicted: Set[Tuple[str, str, str]], pos: Set[Tuple[str, str, str]], neg: Set[Tuple[str, str, str]]) -> AblationRow:
    tp = len(predicted & pos)
    fp = len(predicted & neg)
    fn = len(pos - predicted)
    tn = len(neg - predicted)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return AblationRow(
        module=module,
        stage=stage,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
    )


def _write_csv(path: str, rows: List[AblationRow]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["module", "stage", "tp", "fp", "fn", "tn", "precision", "recall", "f1"])
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def main():
    parser = argparse.ArgumentParser(description="Run reviewer-aligned stage-wise ablation")
    parser.add_argument("--ground-truth-url", default="http://127.0.0.1:8000/_shadowprobe/ground-truth")
    parser.add_argument("--ground-truth-file", default="")
    parser.add_argument("--findings-map", default="", help="Optional JSON map of module->findings path")
    parser.add_argument("--modules", nargs="+", choices=MODULES, default=MODULES)
    parser.add_argument("--ml-threshold", type=float, default=0.55)
    parser.add_argument("--output-json", default="evaluation/output/ablation_report.json")
    parser.add_argument("--output-csv", default="evaluation/output/ablation_table.csv")
    args = parser.parse_args()

    gt = _load_ground_truth(args.ground_truth_url, args.ground_truth_file)
    targets = gt.get("targets", [])

    findings_map = dict(DEFAULT_FINDINGS)
    if args.findings_map:
        with open(args.findings_map, "r", encoding="utf-8") as f:
            findings_map.update(json.load(f))

    rows: List[AblationRow] = []
    details = {}

    for module in args.modules:
        findings = _load_findings(findings_map.get(module, ""))
        pos, neg = _extract_truth(module, targets)
        details[module] = {
            "findings_path": findings_map.get(module, ""),
            "findings_count": len(findings),
            "positive_truth_count": len(pos),
            "negative_truth_count": len(neg),
            "stages": {},
        }

        for stage in STAGES:
            predicted = _predicted_keys(module, findings, stage, args.ml_threshold)
            row = _compute_row(module, stage, predicted, pos, neg)
            rows.append(row)
            details[module]["stages"][stage] = {
                "predicted_count": len(predicted),
                "predicted_keys": sorted(list(predicted)),
                "metrics": asdict(row),
            }

    _write_csv(args.output_csv, rows)
    os.makedirs(os.path.dirname(args.output_json), exist_ok=True)
    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(
            {
                "dataset": gt.get("dataset", "unknown"),
                "generated_at": gt.get("generated_at", "unknown"),
                "stages": STAGES,
                "ml_threshold": args.ml_threshold,
                "rows": [asdict(r) for r in rows],
                "details": details,
            },
            f,
            indent=2,
        )

    print(json.dumps({"output_json": args.output_json, "output_csv": args.output_csv, "modules": args.modules}, indent=2))


if __name__ == "__main__":
    main()
