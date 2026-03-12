#!/usr/bin/env python3
"""
Evaluate scanner findings against ground truth with auditable metrics.

Outputs:
- Per-module confusion matrix (TP/FP/FN/TN)
- Precision/Recall/F1/Specificity/FPR/FNR/Accuracy
- Dataset inventory (#targets, #params, #vulnerable per class)
- JSON + CSV artifacts for paper tables
"""

import argparse
import csv
import json
import os
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Set, Optional
from urllib.parse import urlparse, parse_qsl

import requests

DEFAULT_FINDINGS = {
    "sqli": "bsqli/output/findings.json",
    "bxss": "bxss/output/findings_xss.json",
    "ssrf": "bssrf/output/findings_ssrf.json",
    "cmdi": "bcmdi/output/findings_cmdi.json",
    "xxe": "bxe/output/findings_xxe.json",
}

DEFAULT_TARGET_FILES = {
    "sqli": "demo_vuln_app/urls_sqli.txt",
    "bxss": "demo_vuln_app/urls_bxss.txt",
    "ssrf": "demo_vuln_app/urls_ssrf.txt",
    "cmdi": "demo_vuln_app/urls_cmdi.txt",
    "xxe": "demo_vuln_app/urls_xxe.txt",
}

MODULES = ["sqli", "bxss", "ssrf", "cmdi", "xxe"]


@dataclass
class Metrics:
    module: str
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    specificity: float
    fpr: float
    fnr: float
    accuracy: float


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


def _load_json(path: str):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_findings(path: str) -> Tuple[List[dict], List[str]]:
    warnings = []
    if not path or not os.path.exists(path):
        return [], [f"findings file not found: {path}"]

    try:
        data = _load_json(path)
        if isinstance(data, dict):
            return [data], warnings
        if isinstance(data, list):
            return data, warnings
        return [], [f"unsupported findings format in {path}: expected list or dict"]
    except Exception as e:
        return [], [f"failed to read findings file ({path}): {e}"]


def _extract_truth_keys(
    module: str,
    truth_targets: List[dict],
    scoped_paths: Optional[Set[str]] = None,
) -> Tuple[Set[Tuple[str, str, str]], Set[Tuple[str, str, str]]]:
    pos = set()
    neg = set()
    for target in truth_targets:
        if target.get("module") != module:
            continue
        target_path = _path_of(target.get("url", ""))
        if scoped_paths is not None and target_path not in scoped_paths:
            continue
        key = (module, target_path, _normalize_param(target.get("parameter")))
        if target.get("vulnerable"):
            pos.add(key)
        else:
            neg.add(key)
    return pos, neg


def _load_target_scope(target_files: Dict[str, str], modules: List[str]) -> Dict[str, Set[str]]:
    scope: Dict[str, Set[str]] = {}
    for module in modules:
        scope[module] = set()
        path = target_files.get(module, "")
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith("#"):
                        scope[module].add(_path_of(url))
        except Exception:
            continue
    return scope


def _is_predicted_positive(module: str, finding: dict, include_unconfirmed_ssrf: bool) -> bool:
    if module == "ssrf" and not include_unconfirmed_ssrf:
        return bool(finding.get("confirmed", False))
    if module == "xxe":
        return bool(finding.get("is_vulnerable", True))
    return True


def _extract_predicted_keys(module: str, findings: List[dict], include_unconfirmed_ssrf: bool) -> Set[Tuple[str, str, str]]:
    keys = set()
    for item in findings:
        if not _is_predicted_positive(module, item, include_unconfirmed_ssrf):
            continue
        endpoint = item.get("url") or item.get("endpoint") or ""
        parameter = _normalize_param(item.get("parameter"))
        keys.add((module, _path_of(endpoint), parameter))
    return keys


def _compute_metrics(module: str, predicted: Set[Tuple[str, str, str]], truth_pos: Set[Tuple[str, str, str]], truth_neg: Set[Tuple[str, str, str]]) -> Metrics:
    tp = len(predicted & truth_pos)
    fp = len(predicted & truth_neg)
    fn = len(truth_pos - predicted)
    tn = len(truth_neg - predicted)

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    specificity = _safe_div(tn, tn + fp)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)
    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)

    return Metrics(
        module=module,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        specificity=round(specificity, 4),
        fpr=round(fpr, 4),
        fnr=round(fnr, 4),
        accuracy=round(accuracy, 4),
    )


def _load_ground_truth(ground_truth_url: str = "", ground_truth_file: str = "") -> dict:
    if ground_truth_file:
        with open(ground_truth_file, "r", encoding="utf-8") as f:
            return json.load(f)
    response = requests.get(ground_truth_url, timeout=15)
    response.raise_for_status()
    return response.json()


def _dataset_inventory(targets: List[dict]) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for module in MODULES:
        subset = [t for t in targets if t.get("module") == module]
        vulnerable = [t for t in subset if t.get("vulnerable")]
        out[module] = {
            "targets": len(subset),
            "vulnerable_targets": len(vulnerable),
            "non_vulnerable_targets": len(subset) - len(vulnerable),
            "unique_parameters": len(set(_normalize_param(t.get("parameter")) for t in subset)),
            "unique_paths": len(set(_path_of(t.get("url", "")) for t in subset)),
        }
    return out


def _discovered_surface_inventory(targets: List[dict]) -> Dict[str, int]:
    """Compute broad discovered attack-surface stats from saved scan artifacts.

    Uses URL corpus from bsqli feature logs plus ground-truth URLs to avoid
    reporting only the small labeled subset used for TP/FP/FN.
    """
    urls: List[str] = []

    features_path = os.path.join("bsqli", "output", "features.csv")
    if os.path.exists(features_path):
        try:
            with open(features_path, "r", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    u = (row.get("url") or "").strip()
                    if u.startswith("http"):
                        urls.append(u)
        except Exception:
            pass

    # Include truth URLs so local benchmark endpoints are always represented.
    for t in targets:
        u = (t.get("url") or "").strip()
        if u.startswith("http"):
            urls.append(u)

    uniq_urls = set(urls)
    param_urls = set()
    endpoint_param_pairs = set()

    for u in uniq_urls:
        parsed = urlparse(u)
        if parsed.query:
            param_urls.add(u)
        for k, _ in parse_qsl(parsed.query, keep_blank_values=True):
            endpoint_param_pairs.add((parsed.path, k))

    return {
        "total_endpoints_discovered": len(uniq_urls),
        "endpoints_with_parameters": len(param_urls),
        "total_endpoint_parameter_pairs": len(endpoint_param_pairs),
    }


def _write_csv(path: str, rows: List[Metrics]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["module", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "specificity", "fpr", "fnr", "accuracy"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def main():
    parser = argparse.ArgumentParser(description="Evaluate scanner findings against auditable ground truth")
    parser.add_argument("--ground-truth-url", default="http://127.0.0.1:8000/_shadowprobe/ground-truth")
    parser.add_argument("--ground-truth-file", default="")
    parser.add_argument("--modules", nargs="+", default=MODULES, choices=MODULES)
    parser.add_argument("--findings-map", default="", help="Optional JSON map: {\"sqli\": \"path/to/findings.json\", ...}")
    parser.add_argument("--targets-map", default="", help="Optional JSON map: {\"sqli\": \"path/to/urls.txt\", ...}")
    parser.add_argument("--use-target-scope", action="store_true", help="Evaluate only ground-truth paths present in target URL files")
    parser.add_argument("--include-unconfirmed-ssrf", action="store_true")
    parser.add_argument("--output-json", default="evaluation/output/evaluation_report.json")
    parser.add_argument("--output-csv", default="evaluation/output/evaluation_table.csv")
    args = parser.parse_args()

    findings_map = dict(DEFAULT_FINDINGS)
    if args.findings_map:
        with open(args.findings_map, "r", encoding="utf-8") as f:
            findings_map.update(json.load(f))

    target_files = dict(DEFAULT_TARGET_FILES)
    if args.targets_map:
        with open(args.targets_map, "r", encoding="utf-8") as f:
            target_files.update(json.load(f))

    gt = _load_ground_truth(args.ground_truth_url, args.ground_truth_file)
    targets = gt.get("targets", [])
    scoped_paths_by_module = _load_target_scope(target_files, args.modules) if args.use_target_scope else {}

    all_metrics: List[Metrics] = []
    warnings: Dict[str, List[str]] = {}
    per_module_details = {}

    for module in args.modules:
        findings, warn = _load_findings(findings_map.get(module, ""))
        if warn:
            warnings[module] = warn

        predicted = _extract_predicted_keys(module, findings, include_unconfirmed_ssrf=args.include_unconfirmed_ssrf)
        truth_pos, truth_neg = _extract_truth_keys(
            module,
            targets,
            scoped_paths=scoped_paths_by_module.get(module) if args.use_target_scope else None,
        )
        metrics = _compute_metrics(module, predicted, truth_pos, truth_neg)
        all_metrics.append(metrics)

        per_module_details[module] = {
            "findings_path": findings_map.get(module, ""),
            "findings_count": len(findings),
            "predicted_keys": sorted(list(predicted)),
            "truth_positive_keys": sorted(list(truth_pos)),
            "truth_negative_keys": sorted(list(truth_neg)),
        }

    os.makedirs(os.path.dirname(args.output_json), exist_ok=True)
    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump(
            {
                "dataset": gt.get("dataset", "unknown"),
                "generated_at": gt.get("generated_at", "unknown"),
                "inventory": _dataset_inventory(targets),
                "discovered_surface": _discovered_surface_inventory(targets),
                "metrics": [asdict(m) for m in all_metrics],
                "warnings": warnings,
                "details": per_module_details,
                "ssrf_confirmed_only": not args.include_unconfirmed_ssrf,
                "target_scope_enabled": bool(args.use_target_scope),
                "target_scope_paths": {k: sorted(list(v)) for k, v in scoped_paths_by_module.items()} if args.use_target_scope else {},
                "metric_definitions": {
                    "precision": "TP/(TP+FP)",
                    "recall": "TP/(TP+FN)",
                    "f1": "2PR/(P+R)",
                    "specificity": "TN/(TN+FP)",
                    "fpr": "FP/(FP+TN)",
                    "fnr": "FN/(FN+TP)",
                    "accuracy": "(TP+TN)/(TP+TN+FP+FN)",
                },
            },
            f,
            indent=2,
        )

    _write_csv(args.output_csv, all_metrics)

    print(json.dumps({"output_json": args.output_json, "output_csv": args.output_csv, "modules": args.modules}, indent=2))


if __name__ == "__main__":
    main()
