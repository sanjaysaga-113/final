# Camera-Ready Results Draft (Generated from Evaluation Artifacts)

This section is generated from:
- `evaluation/output/evaluation_table_scoped.csv` (run with `--use-target-scope`)
- `evaluation/output/ablation_table.csv`
- `evaluation/output/benchmark_table.csv`
- `evaluation/output/evaluation_report_scoped.json`

Generated date: 2026-03-08

# 1) Evaluation Performance (Per Module)

| Module | TP | FP | FN | TN | Precision | Recall | F1 | Specificity | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SQLi | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| BXSS | 1 | 0 | 0 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| SSRF | 3 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| CMDi | 3 | 0 | 0 | 3 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| XXE | 2 | 0 | 0 | 2 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

### Suggested manuscript text
On ShadowProbeEvalBench-2026 (scoped to scanned target paths), all five modules (SQLi, BXSS, SSRF, CMDi, XXE) achieved perfect precision and recall on the current split. For XXE specifically, endpoint-aware SOAP timing probes and adaptive time-thresholding recovered both vulnerable paths (`/api/parse`, `/soap`) while maintaining zero false positives on their safe counterparts in this run.

## 2) Ablation Study (Stage-Wise)

Stages: regression -> control -> delta_if -> oob

| Module | Stage | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| SQLi | regression | 1.0000 | 1.0000 | 1.0000 | 1 | 0 | 0 | 1 |
| SQLi | control | 1.0000 | 1.0000 | 1.0000 | 1 | 0 | 0 | 1 |
| SQLi | delta_if | 1.0000 | 1.0000 | 1.0000 | 1 | 0 | 0 | 1 |
| SQLi | oob | 1.0000 | 1.0000 | 1.0000 | 1 | 0 | 0 | 1 |
| BXSS | regression | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 1 | 1 |
| BXSS | control | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 1 | 1 |
| BXSS | delta_if | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 1 | 1 |
| BXSS | oob | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 1 | 1 |
| SSRF | regression | 0.5000 | 1.0000 | 0.6667 | 3 | 3 | 0 | 0 |
| SSRF | control | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 3 | 3 |
| SSRF | delta_if | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 3 | 3 |
| SSRF | oob | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 3 | 3 |
| CMDi | regression | 1.0000 | 1.0000 | 1.0000 | 3 | 0 | 0 | 3 |
| CMDi | control | 1.0000 | 1.0000 | 1.0000 | 3 | 0 | 0 | 3 |
| CMDi | delta_if | 1.0000 | 1.0000 | 1.0000 | 3 | 0 | 0 | 3 |
| CMDi | oob | 1.0000 | 1.0000 | 1.0000 | 3 | 0 | 0 | 3 |
| XXE | regression | 0.0000 | 0.0000 | 0.0000 | 0 | 1 | 3 | 2 |
| XXE | control | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 3 | 3 |
| XXE | delta_if | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 3 | 3 |
| XXE | oob | 0.0000 | 0.0000 | 0.0000 | 0 | 0 | 3 | 3 |

### Suggested manuscript text
Ablation indicates heterogeneous behavior across modules. SSRF shows the largest stage sensitivity, with high recall in regression-only mode but precision degradation due to false positives; later stages in this specific run suppress detections entirely, suggesting threshold/calibration coupling that should be tuned and reported explicitly. SQLi and CMDi remain stable across stages in the current split. BXSS and XXE remain low-performing across all stages, which supports a conservative claim scope and motivates future work on payload diversity, correlation logic, and confirmation heuristics.

## 3) Runtime Benchmark

| Module | Return Code | Elapsed (s) | Findings |
|---|---:|---:|---:|
| SQLi | 1 | 24.035 | 1 |
| BXSS | 0 | 28.525 | 10 |
| SSRF | 1 | 29.371 | 36 |
| CMDi | 1 | 459.063 | 3 |
| XXE | 1 | 21.410 | 2 |

### Suggested manuscript text
Runtime profiling shows that CMDi dominates end-to-end scan latency in the current implementation, while SQLi/SSRF/BXSS/XXE complete within approximately 21-30 seconds on this benchmark setup. This runtime asymmetry should be disclosed as an implementation trade-off: deeper CMDi time-based validation improves confidence but increases total execution cost.

## 4) Reviewer-Facing Claim Language (Conservative)

Use claim-safe wording in the paper:
- Avoid statements implying universal effectiveness.
- Frame results as benchmark-bound: “on ShadowProbeEvalBench-2026 under the described setup.”
- Explicitly report benchmark scope and scanned-target-path evaluation setup.
- Separate “detected findings count” from “validated true positives” to avoid inflating efficacy.

Example sentence:
> On ShadowProbeEvalBench-2026 under the scoped scanned-path protocol, ShadowProbe achieved perfect per-module precision/recall in the current controlled split; these outcomes are benchmark-bound and should be interpreted with the dataset and environment constraints reported in the evaluation protocol.

## 5) How to Refresh This Section

Regenerate artifacts and update this section whenever benchmark or detector logic changes:

```bash
python evaluation/evaluate_modules.py
python -m evaluation.evaluate_modules --ground-truth-file evaluation/output/ground_truth.json --use-target-scope --output-json evaluation/output/evaluation_report_scoped.json --output-csv evaluation/output/evaluation_table_scoped.csv
python evaluation/run_ablation.py
python evaluation/run_benchmark.py --skip-demo-events
```

Then re-sync values in this file from the three CSV outputs.
