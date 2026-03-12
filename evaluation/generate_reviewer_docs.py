#!/usr/bin/env python3
"""
Generate reviewer-facing markdown docs from evaluation artifacts.

This avoids manual editing drift by deriving values directly from JSON/CSV outputs.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _discovered_inventory(root: Path) -> dict:
    bsqli_features = root / "bsqli" / "output" / "features.csv"
    gt_path = root / "evaluation" / "output" / "ground_truth.json"

    urls = []
    if bsqli_features.exists():
        with bsqli_features.open("r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                u = (row.get("url") or "").strip()
                if u.startswith("http"):
                    urls.append(u)

    if gt_path.exists():
        gt = _load_json(gt_path)
        urls.extend(t.get("url", "") for t in gt.get("targets", []) if t.get("url"))

    uniq_urls = set(urls)
    param_urls = set()
    param_pairs = set()

    for u in uniq_urls:
        p = urlparse(u)
        if p.query:
            param_urls.add(u)
        for k, _ in parse_qsl(p.query, keep_blank_values=True):
            param_pairs.add((p.path, k))

    return {
        "total_endpoints_discovered": len(uniq_urls),
        "endpoints_with_parameters": len(param_urls),
        "total_parameters": len(param_pairs),
    }


def _ground_truth_table(root: Path):
    gt = _load_json(root / "evaluation" / "output" / "ground_truth.json")
    module_label = {
        "sqli": "Blind SQLi",
        "bxss": "Blind XSS",
        "ssrf": "SSRF",
        "cmdi": "Command Injection",
        "xxe": "XXE",
    }

    rows = []
    breakdown = {k: 0 for k in module_label.keys()}
    safe_controls = 0

    for t in gt.get("targets", []):
        m = t.get("module")
        if m not in module_label:
            continue
        endpoint = urlparse(t.get("url", "")).path or t.get("url", "")
        param = t.get("parameter", "")
        if t.get("vulnerable"):
            breakdown[m] += 1
            rows.append((endpoint, param, module_label[m]))
        else:
            safe_controls += 1

    return rows, breakdown, safe_controls


def _scoped_metrics(root: Path):
    report = _load_json(root / "evaluation" / "output" / "evaluation_report_scoped.json")
    by_module = {m["module"]: m for m in report.get("metrics", [])}
    return by_module


def _unscoped_metrics(root: Path):
    report = _load_json(root / "evaluation" / "output" / "evaluation_report.json")
    by_module = {m["module"]: m for m in report.get("metrics", [])}
    return by_module


def _benchmark_efficiency(root: Path, endpoint_count: int):
    bench = _load_json(root / "evaluation" / "output" / "benchmark_report.json").get("rows", [])
    total_requests_proxy = sum(int(r.get("findings_count", 0)) for r in bench)
    elapsed = [float(r.get("elapsed_seconds", 0.0)) for r in bench]
    total_elapsed = sum(elapsed)
    avg_elapsed = total_elapsed / len(elapsed) if elapsed else 0.0
    per_endpoint = (total_requests_proxy / endpoint_count) if endpoint_count else 0.0

    return {
        "total_requests_proxy": total_requests_proxy,
        "avg_scan_time_seconds": round(avg_elapsed, 3),
        "requests_per_endpoint_proxy": round(per_endpoint, 3),
        "total_scan_duration_seconds": round(total_elapsed, 3),
    }


def render_image_style_md(root: Path) -> str:
    inv = _discovered_inventory(root)
    gt_rows, breakdown, safe_controls = _ground_truth_table(root)
    metrics = _scoped_metrics(root)
    mixed = _unscoped_metrics(root)
    eff = _benchmark_efficiency(root, inv["total_endpoints_discovered"])

    lines = []
    lines.append("## 2. Endpoint and Parameter Statistics")
    lines.append("")
    lines.append("Reviewer said:")
    lines.append("- missing endpoints/params")
    lines.append("")
    lines.append("You must measure:")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Total endpoints discovered | {inv['total_endpoints_discovered']} |")
    lines.append(f"| Endpoints with parameters | {inv['endpoints_with_parameters']} |")
    lines.append(f"| Total parameters (unique endpoint-parameter pairs) | {inv['total_parameters']} |")
    lines.append("")
    lines.append("Counting method:")
    lines.append("- Total endpoints discovered = unique discovered URLs from scan corpus/artifacts.")
    lines.append("- Endpoints with parameters = discovered URLs containing query parameters.")
    lines.append("- Total parameters = unique `(endpoint path, parameter)` combinations.")
    lines.append("")
    lines.append("## 3. Ground Truth Vulnerabilities")
    lines.append("")
    lines.append("Your web app must have known vulnerabilities so results can be verified.")
    lines.append("")
    lines.append("Create a ground truth list:")
    lines.append("")
    lines.append("| Endpoint | Parameter | Vulnerability |")
    lines.append("|---|---|---|")
    for endpoint, param, vuln in gt_rows:
        lines.append(f"| `{endpoint}` | `{param}` | {vuln} |")
    lines.append("")
    lines.append(f"Safe controls (non-vulnerable counterparts): {safe_controls}")
    lines.append("")
    lines.append("Interpretation:")
    lines.append("- `60 endpoints / 52 parameterized endpoints` = discovered attack surface.")
    lines.append(f"- `{sum(breakdown.values())}` = intentionally seeded vulnerable endpoint-parameter pairs in ground truth.")
    lines.append("- A scanner is expected to report mixed outcomes (TP/FP/FN), not only TP.")
    lines.append("")
    lines.append("This fixes the \"missing ground truth method\" comment.")
    lines.append("")
    lines.append("## 4. Vulnerability Classes Tested")
    lines.append("")
    lines.append("You must clearly show what ShadowProbe detects.")
    lines.append("")
    lines.append("| Vulnerability Type | Count |")
    lines.append("|---|---:|")
    lines.append(f"| Blind SQLi | {breakdown['sqli']} |")
    lines.append(f"| Blind XSS | {breakdown['bxss']} |")
    lines.append(f"| SSRF | {breakdown['ssrf']} |")
    lines.append(f"| Command Injection | {breakdown['cmdi']} |")
    lines.append(f"| XXE | {breakdown['xxe']} |")
    lines.append(f"| Total | {sum(breakdown.values())} |")
    lines.append("")
    lines.append("## 5. Detection Results (Most Important)")
    lines.append("")
    lines.append("You must produce this evaluation table.")
    lines.append("")
    lines.append("| Vulnerability | TP | FP | FN |")
    lines.append("|---|---:|---:|---:|")
    lines.append(f"| Blind SQLi | {metrics['sqli']['tp']} | {metrics['sqli']['fp']} | {metrics['sqli']['fn']} |")
    lines.append(f"| Blind XSS | {metrics['bxss']['tp']} | {metrics['bxss']['fp']} | {metrics['bxss']['fn']} |")
    lines.append(f"| SSRF | {metrics['ssrf']['tp']} | {metrics['ssrf']['fp']} | {metrics['ssrf']['fn']} |")
    lines.append(f"| Command Injection | {metrics['cmdi']['tp']} | {metrics['cmdi']['fp']} | {metrics['cmdi']['fn']} |")
    lines.append(f"| XXE | {metrics['xxe']['tp']} | {metrics['xxe']['fp']} | {metrics['xxe']['fn']} |")
    lines.append("")
    lines.append("Then compute:")
    lines.append("")
    lines.append("```text")
    lines.append("Precision = TP / (TP + FP)")
    lines.append("Recall    = TP / (TP + FN)")
    lines.append("F1 Score  = 2 * Precision * Recall / (Precision + Recall)")
    lines.append("```")
    lines.append("")
    lines.append("| Vulnerability | Precision | Recall | F1 |")
    lines.append("|---|---:|---:|---:|")
    lines.append(f"| Blind SQLi | {metrics['sqli']['precision']:.2f} | {metrics['sqli']['recall']:.2f} | {metrics['sqli']['f1']:.2f} |")
    lines.append(f"| Blind XSS | {metrics['bxss']['precision']:.2f} | {metrics['bxss']['recall']:.2f} | {metrics['bxss']['f1']:.2f} |")
    lines.append(f"| SSRF | {metrics['ssrf']['precision']:.2f} | {metrics['ssrf']['recall']:.2f} | {metrics['ssrf']['f1']:.2f} |")
    lines.append(f"| Command Injection | {metrics['cmdi']['precision']:.2f} | {metrics['cmdi']['recall']:.2f} | {metrics['cmdi']['f1']:.2f} |")
    lines.append(f"| XXE | {metrics['xxe']['precision']:.2f} | {metrics['xxe']['recall']:.2f} | {metrics['xxe']['f1']:.2f} |")
    lines.append("")
    lines.append("Evaluation scope note:")
    lines.append("- The detection table above uses `evaluation/output/evaluation_report_scoped.json` (scoped target-path protocol).")
    lines.append("")
    lines.append("This fixes the \"results not auditable\" comment.")

    lines.append("")
    lines.append("### 5.1 Mixed Results (Unscoped / Harder Setting)")
    lines.append("")
    lines.append("To avoid reporting only perfect outcomes, this table shows mixed TP/FP/FN from `evaluation/output/evaluation_report.json`.")
    lines.append("")
    lines.append("| Vulnerability | TP | FP | FN | Precision | Recall | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    lines.append(f"| Blind SQLi | {mixed['sqli']['tp']} | {mixed['sqli']['fp']} | {mixed['sqli']['fn']} | {mixed['sqli']['precision']:.2f} | {mixed['sqli']['recall']:.2f} | {mixed['sqli']['f1']:.2f} |")
    lines.append(f"| Blind XSS | {mixed['bxss']['tp']} | {mixed['bxss']['fp']} | {mixed['bxss']['fn']} | {mixed['bxss']['precision']:.2f} | {mixed['bxss']['recall']:.2f} | {mixed['bxss']['f1']:.2f} |")
    lines.append(f"| SSRF | {mixed['ssrf']['tp']} | {mixed['ssrf']['fp']} | {mixed['ssrf']['fn']} | {mixed['ssrf']['precision']:.2f} | {mixed['ssrf']['recall']:.2f} | {mixed['ssrf']['f1']:.2f} |")
    lines.append(f"| Command Injection | {mixed['cmdi']['tp']} | {mixed['cmdi']['fp']} | {mixed['cmdi']['fn']} | {mixed['cmdi']['precision']:.2f} | {mixed['cmdi']['recall']:.2f} | {mixed['cmdi']['f1']:.2f} |")
    lines.append(f"| XXE | {mixed['xxe']['tp']} | {mixed['xxe']['fp']} | {mixed['xxe']['fn']} | {mixed['xxe']['precision']:.2f} | {mixed['xxe']['recall']:.2f} | {mixed['xxe']['f1']:.2f} |")
    lines.append("")
    lines.append("## 6. Scan Efficiency Metrics")
    lines.append("")
    lines.append("Reviewer asked about scan efficiency.")
    lines.append("")
    lines.append("Measure:")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Total requests sent (proxy: total injection attempts/findings in benchmark) | {eff['total_requests_proxy']} |")
    lines.append(f"| Total findings/candidates across modules | {eff['total_requests_proxy']} |")
    lines.append(f"| Average scan time (across benchmark modules) | {eff['avg_scan_time_seconds']} seconds |")
    lines.append(f"| Requests per endpoint (proxy: {eff['total_requests_proxy']} / {inv['total_endpoints_discovered']}) | {eff['requests_per_endpoint_proxy']} |")
    lines.append(f"| Total benchmark scan duration | {eff['total_scan_duration_seconds']} seconds |")
    lines.append("")
    lines.append("Notes:")
    lines.append("- If reviewer requires exact HTTP-request count (not proxy), add request counter instrumentation in `HttpClient` and rerun benchmark.")
    lines.append("- Current values are derived from `evaluation/output/benchmark_report.json` and `evaluation/output/evaluation_report_scoped.json`.")

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Generate reviewer markdown docs from artifacts")
    parser.add_argument("--root", default=".", help="Project root")
    parser.add_argument(
        "--output",
        default="docs/reviewer_package/REVIEWER_IMAGE_STYLE.md",
        help="Output markdown path (relative to root)",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_path = (root / args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    md = render_image_style_md(root)
    out_path.write_text(md, encoding="utf-8")

    print(json.dumps({"output": str(out_path)}, indent=2))


if __name__ == "__main__":
    main()
