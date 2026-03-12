import argparse
import json
import os
from urllib.parse import urlparse
import requests

DEFAULT_FINDINGS = {
    "sqli": "bsqli/output/findings.json",
    "bxss": "bxss/output/findings_xss.json",
    "ssrf": "bssrf/output/findings_ssrf.json",
    "cmdi": "bcmdi/output/findings_cmdi.json",
    "xxe": "bxe/output/findings_xxe.json",
}


def _path_of(url: str) -> str:
    try:
        return urlparse(url).path
    except Exception:
        return ""


def _normalize_param(param: str) -> str:
    if not param:
        return ""
    p = str(param)
    if ":" in p:
        return p.split(":", 1)[-1]
    return p


def _load_findings(path: str):
    if not path or not os.path.exists(path):
        return [], f"findings file not found: {path}"

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return [], f"invalid JSON in findings file ({path}): {e}"
    except Exception as e:
        return [], f"failed to read findings file ({path}): {e}"

    if isinstance(data, dict):
        return [data], None
    if isinstance(data, list):
        return data, None
    return [], f"unsupported findings format in {path}: expected list or dict"


def _extract_predicted_keys(module: str, findings: list, confirmed_only: bool = True):
    keys = set()
    for item in findings:
        if module == "xxe":
            endpoint = item.get("endpoint") or item.get("url") or ""
            parameter = _normalize_param(item.get("parameter"))
            is_vuln = item.get("is_vulnerable", True)
            if not is_vuln:
                continue
            keys.add((module, _path_of(endpoint), parameter))
            continue

        if module == "ssrf" and confirmed_only:
            if not item.get("confirmed", False):
                continue

        endpoint = item.get("url") or item.get("endpoint") or ""
        parameter = _normalize_param(item.get("parameter"))
        keys.add((module, _path_of(endpoint), parameter))
    return keys


def _extract_truth_keys(module: str, truth_targets: list):
    pos = set()
    neg = set()
    for t in truth_targets:
        if t.get("module") != module:
            continue
        key = (module, _path_of(t.get("url", "")), _normalize_param(t.get("parameter")))
        if t.get("vulnerable"):
            pos.add(key)
        else:
            neg.add(key)
    return pos, neg


def main():
    parser = argparse.ArgumentParser(description="Evaluate scanner findings against demo ground truth")
    parser.add_argument("--module", required=True, choices=["sqli", "bxss", "ssrf", "cmdi", "xxe"])
    parser.add_argument("--findings", help="Path to findings JSON")
    parser.add_argument("--ground-truth-url", default="http://127.0.0.1:8000/_shadowprobe/ground-truth")
    parser.add_argument(
        "--include-unconfirmed",
        action="store_true",
        help="For SSRF, include unconfirmed injection attempts as predicted positives (default: false)",
    )
    args = parser.parse_args()

    findings_path = args.findings or DEFAULT_FINDINGS[args.module]

    gt = requests.get(args.ground_truth_url, timeout=10).json()
    targets = gt.get("targets", [])

    findings, findings_warning = _load_findings(findings_path)

    predicted = _extract_predicted_keys(
        args.module,
        findings,
        confirmed_only=(args.module == "ssrf" and not args.include_unconfirmed),
    )
    truth_pos, truth_neg = _extract_truth_keys(args.module, targets)

    tp = len(predicted & truth_pos)
    fp = len(predicted & truth_neg)
    fn = len(truth_pos - predicted)
    tn = len(truth_neg - predicted)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    report = {
        "module": args.module,
        "findings_path": findings_path,
        "findings_count": len(findings),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "ssrf_confirmed_only": (args.module == "ssrf" and not args.include_unconfirmed),
        "warnings": [w for w in [findings_warning] if w],
        "predicted_keys": sorted(list(predicted)),
        "truth_positive_keys": sorted(list(truth_pos)),
        "truth_negative_keys": sorted(list(truth_neg)),
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
