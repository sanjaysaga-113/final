# Reviewer Metrics Pack (ShadowProbe)

Generated: 2026-03-09

This report consolidates the reviewer-requested evidence from repository artifacts.

Primary sources:
- `evaluation/output/ground_truth.json`
- `evaluation/output/evaluation_report.json`
- `evaluation/output/ablation_report.json`
- `evaluation/output/benchmark_report.json`
- `bxss/output/findings_xss.json`
- `bssrf/output/findings_ssrf.json`
- `bxe/output/findings_xxe.json`
- `bsqli/output/features.csv`
- `evaluation/output/recon_audit.jsonl`

## 1. Ground Truth Dataset (Prerequisite)

### 1.1 Attack surface and inventory (requested classes only: BSQLi, BXSS, SSRF, XXE)

| Metric | Value |
|---|---:|
| Total attack surface (parameter tests) | 16 |
| Total endpoints discovered | 16 |
| Parameterized endpoints | 10 |
| Total endpoint-parameter pairs | 16 |
| Safe controls (non-vulnerable params) | 8 |

### 1.2 Vulnerability breakdown

| Class | Vulnerable instances |
|---|---:|
| BSQLi (`sqli`) | 1 |
| BXSS | 1 |
| SSRF | 3 |
| XXE | 3 |
| Total vulnerable | 8 |

### 1.3 Ground-truth endpoint list

| Endpoint | Parameter | Label |
|---|---|---|
| `/search` | `name` | BSQLi |
| `/sqli/search_safe` | `name` | Safe |
| `/comment` | `text` | BXSS |
| `/xss/comment_safe` | `text` | Safe |
| `/fetch_image` | `url` | SSRF |
| `/ssrf/fetch_safe` | `url` | Safe |
| `/webhook` | `callback` | SSRF |
| `/ssrf/webhook_safe` | `callback` | Safe |
| `/fetch_file` | `file` | SSRF |
| `/ssrf/file_safe` | `file` | Safe |
| `/api/parse` | `xml_body` | XXE |
| `/xxe/parse_safe` | `xml_body` | Safe |
| `/soap` | `soap_body` | XXE |
| `/xxe/soap_safe` | `soap_body` | Safe |
| `/upload` | `file` | XXE |
| `/xxe/upload_safe` | `file` | Safe |

## 2. Machine Learning Metrics (Isolation Forest / anomaly layer)

### 2.1 Baseline latency and deltas

| Metric | Value |
|---|---:|
| Baseline latency mean (local demo targets) | 46.528 ms |
| Successful injection `delta_ratio` (observed unique) | 0.8 |
| Noise/jitter-only `delta_ratio` bucket | N/A in current saved local rows |

### 2.2 Anomaly scores on successful injections

| Module | Score(s) observed | Decision |
|---|---|---|
| SSRF | 0.5019 | anomaly |
| BXSS | N/A | scaler/model feature mismatch in current artifact |

### 2.3 Fixed 5-second comparison (closest auditable artifact)

Direct standalone "fixed sleep vs lag" experiment file is not present. The closest auditable comparison is stage-wise ablation FP:

| Module | FP (Regression) | FP (Delta_IF) | FP reduction |
|---|---:|---:|---:|
| SQLi | 0 | 0 | 0 |
| BXSS | 0 | 0 | 0 |
| SSRF | 3 | 0 | 3 |
| CMDi | 0 | 0 | 0 |
| XXE | 1 | 0 | 1 |

Interpretation: anomaly/delta stage suppressed false positives seen in regression for SSRF and XXE.

## 3. OOB Interaction Data

### 3.1 Timestamped interaction evidence

| Module | Records with send+callback timestamps | Mean send-to-callback delay |
|---|---:|---:|
| BXSS | 11/11 | 0.4472 s |
| SSRF | 18 confirmed records | (confirmed callback evidence used) |

### 3.2 Correlation ID success rate

| Module | Correlation result |
|---|---|
| BXSS | 11/11 correlated (`uuid` + injection/callback timestamps) |
| SSRF | 3 unique confirmed correlation IDs across 18 confirmed payload records |

### 3.3 Deterministic OOB accuracy claim

| Module | FP (evaluation report) |
|---|---:|
| BXSS | 0 |
| SSRF | 0 |

Current artifact evidence supports 0 FP for OOB-confirmed BXSS/SSRF in this run.

## 4. Reconnaissance Efficiency

`recon_manager` audit fields used: `input_count`, `filtered_count`, `dedup_count`, `prioritized_count`.

| Metric | Value |
|---|---:|
| Input count | 6 |
| Filtered count | 4 |
| Dedup count | 4 |
| Prioritized output count | 4 |
| Candidate reduction | 33.3% |

Top parameters (audit): `artist`, `cat`, `test`, `post`.

Time-saved with-vs-without recon in one identical scan command is not available as a stable saved artifact in current outputs. The auditable, reviewer-safe claim is the 33.3% scope reduction.

## 5. Comparative Table Data

### 5.1 TP / FP / FN and Precision / Recall / F1

Formulas:
- `Precision = TP / (TP + FP)`
- `Recall = TP / (TP + FN)`
- `F1 = 2 * Precision * Recall / (Precision + Recall)`

| Class | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| BSQLi (`sqli`) | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| BXSS | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| SSRF | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| XXE | 0 | 1 | 2 | 0.00 | 0.00 | 0.00 |

### 5.2 Detection speed (hybrid)

Computed as `elapsed_seconds / TP` from benchmark + evaluation report.

| Class | Hybrid detection speed |
|---|---:|
| BSQLi (`sqli`) | 25.431 s / true vuln |
| BXSS | 29.248 s / true vuln |
| SSRF | 10.327 s / true vuln |
| XXE | N/A in this unscoped report (TP=0) |

### 5.3 Traditional method speed comparison

A direct, standalone traditional baseline speed artifact is not present in current outputs. Use the ablation FP comparison in Section 2.3 as auditable support for robustness claims, and run one explicit fixed-sleep benchmark script if strict speed side-by-side is required by reviewers.

## 6. Audit Notes (important for rebuttal consistency)

- `evaluation/output/evaluation_report.json` (current unscoped run) shows XXE underperformance.
- `docs/CAMERA_READY_RESULTS.md` references a scoped run with stronger XXE numbers.
- Keep one protocol consistent per table in the paper (scoped or unscoped), and state it explicitly to avoid reviewer mismatch concerns.
