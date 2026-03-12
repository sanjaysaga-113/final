#!/usr/bin/env python3
"""
Run reproducible benchmark scans and export timing/request-oriented tables.

This script helps produce auditable runtime evidence requested by reviewers:
- scan wall-clock time per module
- observed demo-app event/request count per module
- findings count per module
"""

import argparse
import csv
import json
import os
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import Dict, List

import requests


@dataclass
class BenchmarkRow:
    module: str
    command: str
    return_code: int
    elapsed_seconds: float
    demo_event_count: int
    findings_count: int
    findings_artifact_exists: bool
    stdout_tail: str
    stderr_tail: str


OUTPUT_FILES = {
    "sqli": "bsqli/output/findings.json",
    "bxss": "bxss/output/findings_xss.json",
    "ssrf": "bssrf/output/findings_ssrf.json",
    "cmdi": "bcmdi/output/findings_cmdi.json",
    "xxe": "bxe/output/findings_xxe.json",
}


def _load_findings_count(path: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            return 1
    except Exception:
        return 0
    return 0


def _get_event_count(base_url: str, module: str) -> int:
    try:
        response = requests.get(f"{base_url}/_shadowprobe/events", params={"module": module}, timeout=10)
        response.raise_for_status()
        payload = response.json()
        return int(payload.get("count", 0))
    except Exception:
        return -1


def _reset_events(base_url: str) -> None:
    try:
        requests.post(f"{base_url}/_shadowprobe/reset", timeout=10)
    except Exception:
        # Non-fatal: benchmark can still run without demo event telemetry.
        return


def _build_command(python_exe: str, module: str, target_file: str, listener: str, wait: int, threads: int) -> List[str]:
    cmd = [python_exe, "main.py", "--scan", module, "-f", target_file, "--threads", str(threads)]
    if module in {"bxss", "ssrf"}:
        cmd.extend(["--listener", listener, "--wait", str(wait)])
    return cmd


def _write_csv(path: str, rows: List[BenchmarkRow]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "module",
                "command",
                "return_code",
                "elapsed_seconds",
                "demo_event_count",
                "findings_count",
                "findings_artifact_exists",
                "stdout_tail",
                "stderr_tail",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def main():
    parser = argparse.ArgumentParser(description="Run benchmark scans and export runtime/request table")
    parser.add_argument("--python", default="python")
    parser.add_argument("--demo-base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--modules", nargs="+", default=["sqli", "bxss", "ssrf", "cmdi", "xxe"], choices=["sqli", "bxss", "ssrf", "cmdi", "xxe"])
    parser.add_argument("--targets-map", default="", help="Optional JSON map of module to target file path")
    parser.add_argument("--listener", default="http://127.0.0.1:5000")
    parser.add_argument("--wait", type=int, default=30)
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--skip-demo-events", action="store_true", help="Do not call demo app reset/events APIs")
    parser.add_argument("--output-json", default="evaluation/output/benchmark_report.json")
    parser.add_argument("--output-csv", default="evaluation/output/benchmark_table.csv")
    args = parser.parse_args()

    default_targets = {
        "sqli": "demo_vuln_app/urls_sqli.txt",
        "bxss": "demo_vuln_app/urls_bxss.txt",
        "ssrf": "demo_vuln_app/urls_ssrf.txt",
        "cmdi": "demo_vuln_app/urls_cmdi.txt",
        "xxe": "demo_vuln_app/urls_xxe.txt",
    }
    if args.targets_map:
        with open(args.targets_map, "r", encoding="utf-8") as f:
            default_targets.update(json.load(f))

    rows: List[BenchmarkRow] = []

    for module in args.modules:
        if not args.skip_demo_events:
            _reset_events(args.demo_base_url)
        cmd = _build_command(
            python_exe=args.python,
            module=module,
            target_file=default_targets[module],
            listener=args.listener,
            wait=args.wait,
            threads=args.threads,
        )

        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.time() - t0

        findings_count = _load_findings_count(OUTPUT_FILES[module])
        demo_event_count = -1
        if not args.skip_demo_events:
            demo_event_count = _get_event_count(args.demo_base_url, module)

        stdout_tail = (proc.stdout or "")[-400:].replace("\n", " ").strip()
        stderr_tail = (proc.stderr or "")[-400:].replace("\n", " ").strip()
        artifact_exists = os.path.exists(OUTPUT_FILES[module])

        rows.append(
            BenchmarkRow(
                module=module,
                command=" ".join(cmd),
                return_code=proc.returncode,
                elapsed_seconds=round(elapsed, 3),
                demo_event_count=demo_event_count,
                findings_count=findings_count,
                findings_artifact_exists=artifact_exists,
                stdout_tail=stdout_tail,
                stderr_tail=stderr_tail,
            )
        )

    _write_csv(args.output_csv, rows)
    os.makedirs(os.path.dirname(args.output_json), exist_ok=True)
    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump({"rows": [asdict(r) for r in rows]}, f, indent=2)

    print(json.dumps({"output_json": args.output_json, "output_csv": args.output_csv}, indent=2))


if __name__ == "__main__":
    main()
