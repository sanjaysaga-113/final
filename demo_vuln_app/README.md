# ShadowProbe Evaluation Benchmark App (Local Only)

This app now supports conference-review style evaluation with auditable ground truth, per-module vulnerable/safe pairs, and event logging.

## Why this update

Reviewer feedback asked for auditable metrics, clearer methodology, and explicit false-positive/false-negative analysis.  
This benchmark app addresses that by exposing:

- Vulnerable endpoints (`*_vuln` or legacy routes)
- Safe control endpoints (`*_safe`)
- Machine-readable ground truth API
- Event logging API and JSONL audit trail

## Evaluation APIs

- Ground truth: `/_shadowprobe/ground-truth`
- Runtime events: `/_shadowprobe/events`
- Reset benchmark state: `/_shadowprobe/reset` (POST)
- Event file: `demo_vuln_app/output/events.jsonl`

## Module endpoint pairs

- SQLi
  - Vulnerable: `/search?name=...`
  - Safe: `/sqli/search_safe?name=...`
- BXSS
  - Vulnerable: `/comment?text=...`
  - Safe: `/xss/comment_safe?text=...`
- SSRF
  - Vulnerable: `/fetch_image?url=...`, `/webhook?callback=...`, `/fetch_file?file=...`
  - Safe: `/ssrf/fetch_safe?url=...`, `/ssrf/webhook_safe?callback=...`, `/ssrf/file_safe?file=...`
- CMDi
  - Vulnerable: `/ping?host=...`, `/dns?domain=...`, `/process?cmd=...`
  - Safe: `/cmdi/ping_safe?...`, `/cmdi/dns_safe?...`, `/cmdi/process_safe?...`
- XXE
  - Vulnerable: `/api/parse`, `/soap`, `/upload`
  - Safe: `/xxe/parse_safe`, `/xxe/soap_safe`, `/xxe/upload_safe`

## Quick start

1) Start benchmark app:

```bash
python demo_vuln_app/app.py --port 8000
```

2) Inspect ground truth:

```bash
curl http://127.0.0.1:8000/_shadowprobe/ground-truth
```

3) Run scanner module(s) using fixture files in `demo_vuln_app/`:

```bash
python main.py -f demo_vuln_app/urls_sqli.txt --scan sqli --threads 5
python main.py -f demo_vuln_app/urls_bxss.txt --scan bxss --listener http://127.0.0.1:5000 --wait 10
python main.py -f demo_vuln_app/urls_ssrf.txt --scan ssrf --listener http://127.0.0.1:5000 --wait 10
python main.py -f demo_vuln_app/urls_cmdi.txt --scan cmdi --threads 5
```

4) Evaluate metrics against ground truth:

```bash
python demo_vuln_app/evaluate_results.py --module sqli
python demo_vuln_app/evaluate_results.py --module bxss
python demo_vuln_app/evaluate_results.py --module ssrf
python demo_vuln_app/evaluate_results.py --module cmdi
python demo_vuln_app/evaluate_results.py --module xxe
```

## Notes

- This app is intentionally vulnerable in designated routes; run only in local lab environments.
- Legacy vulnerable routes are preserved for compatibility with existing tests.
- Safe endpoints are designed as control baselines to support FP/FN reporting in your paper revisions.
