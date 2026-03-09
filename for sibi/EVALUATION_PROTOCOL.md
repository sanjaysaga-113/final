# Evaluation Protocol (Conference Revision)

This protocol defines auditable, reproducible evaluation for ShadowProbe.

## 1) Scope and Dataset
- Target benchmark source: demo app endpoint `/_shadowprobe/ground-truth`.
- Classes: `sqli`, `bxss`, `ssrf`, `cmdi`, `xxe`.
- Unit of evaluation: `(module, URL path, parameter)`.
- Positive sample: ground-truth entry with `vulnerable=true`.
- Negative sample: ground-truth entry with `vulnerable=false`.

## 2) Metrics (exact formulas)
For each class:
- $TP$: predicted positive and truly vulnerable
- $FP$: predicted positive and truly non-vulnerable
- $FN$: predicted negative but truly vulnerable
- $TN$: predicted negative and truly non-vulnerable

Derived metrics:
- Precision: $\frac{TP}{TP+FP}$
- Recall: $\frac{TP}{TP+FN}$
- F1: $\frac{2PR}{P+R}$
- Specificity: $\frac{TN}{TN+FP}$
- FPR: $\frac{FP}{FP+TN}$
- FNR: $\frac{FN}{FN+TP}$
- Accuracy: $\frac{TP+TN}{TP+TN+FP+FN}$

## 3) Confirmation Policy
- SSRF default: use callback-confirmed findings only (`confirmed=true`).
- BXSS default: use correlated callback findings (records with callback timing/correlation fields).
- XXE: use `is_vulnerable=true` as positive prediction.

## 4) Stage-wise Recon Audit
Recon count tracking is emitted via env var:
- `SHADOWPROBE_RECON_AUDIT=evaluation/output/recon_audit.jsonl`

Tracked fields:
- `input_count`
- `filtered_count`
- `dedup_count`
- `prioritized_count`
- top parameter frequencies

This supports reporting of scope reduction and dedup impact.

## 5) Runtime/Request Accounting
For each scan run report:
- scan wall-clock start/end and duration
- module list and target list size
- total findings produced per module
- confirmed findings per OOB module

(These are exported by evaluation scripts and scanner outputs.)

Benchmark runner:

```bash
python evaluation/run_benchmark.py \
  --demo-base-url http://127.0.0.1:8000 \
  --listener http://127.0.0.1:5000 \
  --output-json evaluation/output/benchmark_report.json \
  --output-csv evaluation/output/benchmark_table.csv
```

If running from WSL while the demo app is running in Windows (localhost boundary issue), use:

```bash
python evaluation/run_benchmark.py \
  --skip-demo-events \
  --listener http://127.0.0.1:5000 \
  --output-json evaluation/output/benchmark_report.json \
  --output-csv evaluation/output/benchmark_table.csv
```

In this mode, `demo_event_count` is set to `-1` and scan-time/findings metrics are still produced.

## 6) Reproducible Commands
1. Run scanner and collect findings.
2. Evaluate metrics:

```bash
python evaluation/evaluate_modules.py \
  --ground-truth-url http://127.0.0.1:8000/_shadowprobe/ground-truth \
  --output-json evaluation/output/evaluation_report.json \
  --output-csv evaluation/output/evaluation_table.csv
```

3. Run stage-wise ablation:

```bash
python evaluation/run_ablation.py \
  --ground-truth-url http://127.0.0.1:8000/_shadowprobe/ground-truth \
  --output-json evaluation/output/ablation_report.json \
  --output-csv evaluation/output/ablation_table.csv
```

## 7) Reporting Requirements (paper tables)
Required table columns:
- class, TP, FP, FN, TN, precision, recall, F1, specificity
- #targets, #params, #vulnerable per class
- scan duration and requests (if available)
- recon stage counts and dedup reduction

## 8) Claim Policy
Do not report “100% accuracy” unless TP/FP/FN/TN evidence and setting are explicitly included.
Use “high-confidence confirmation” wording for OOB-confirmed findings.
