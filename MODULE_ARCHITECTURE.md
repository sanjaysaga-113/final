# Module Architecture (Updated)

This document describes the current architecture of the project, which supports two pipelines:

- Blind SQL Injection (BSQLi)
- Blind Cross-Site Scripting (BXSS) with out-of-band (OOB) callback correlation

Both pipelines share a consistent orchestration pattern and some core infrastructure, but each has its own module-level payload generation and detection logic.

## High-Level Flow

```
                         +------------------+
                         |      main.py     |
                         +---------+--------+
                                        |
                        +----------v-----------+
                        |  Recon (gau + gf)    |
                        |  bsqli.recon.*       |
                        +----------+-----------+
                                        |
                     +------------+-------------+
                     |                          |
    +----------v-----------+    +---------v----------+
    |  BSQLi Scan (default) |    |   BXSS Scan       |
    |  BlindSQLiModule      |    |   BlindXSSModule  |
    |  bsqli.modules.*      |    |   bxss.modules.*  |
    +----------+------------+    +---------+----------+
                     |                              |
    +----------v------------+         +-------v-------------------+
    |  Detector + Payloads  |         | Detector + Payloads       |
    |  boolean/time-based   |         | OOB, UUID-tagged payloads |
    +----------+------------+         +-------+-------------------+
                     |                              |
    +----------v------------+         +-------v-------------------+
    | Core HTTP/Analysis    |         | OOB Callback + Correlate |
    | logger/http/analysis  |         | bxss/oob/*               |
    +----------+------------+         +-------+-------------------+
                     |                              |
    +----------v------------+         +-------v-------------------+
    |     output/*          |         |   bxss/output/*          |
    +-----------------------+         +--------------------------+
```

## Directory Overview

- recon/
   - gau_runner.py: gau integration
   - gf_filter.py: gf sqli filter + normalization/dedup
   - recon_manager.py: `gather_parameterized_urls()` entry point (scan_type aware)

- bsqli/
   - core/: shared infrastructure used primarily by BSQLi and imported by BXSS where useful
      - config.py: global tuning (timeouts, thresholds, output dir, threads)
      - http_client.py: session, retries, GET wrapper
      - response_analyzer.py: timing and content similarity helpers
      - logger.py: colored console logging
   - modules/blind_sqli/: BSQLi module
      - sqli_module.py: orchestrates per-parameter checks
      - detector.py: boolean and time-based strategies using `measure_request_time()` and similarity
      - payload_engine.py: data-driven SQLi seeds + mutators
      - payloads.py: static pairs/seeds (used by detector)
   - output/: bsqli-specific findings (JSON/TXT)

- bxss/
   - modules/blind_xss/: BXSS module
      - xss_module.py: orchestration; scans query params, headers, optional POST/JSON
      - detector.py: injects UUID-tagged payloads, records injections for correlation
      - payloads.py: context-aware XSS templates with placeholders
   - core/payload_engine.py: BXSS payload builder (UUID injection, type selection)
   - oob/: out-of-band callback + correlation
      - callback_server.py: lightweight Flask listener; persists callbacks
      - correlation.py: correlates callbacks to recorded injections, confidence, save reports
   - ml/: feature extraction and stubs for learning
      - features.py: appends correlated finding features to CSV for offline analysis
   - output/: bxss-specific artifacts (callbacks, features, findings)

- tests/: unit tests (e.g., payload engine)

## Orchestration

- Entry: [main.py](main.py)
   - Args include `--recon`, `--scan {sqli|bxss}`, `--listener` (required for BXSS)
   - Recon: [recon/recon_manager.py](recon/recon_manager.py) gathers candidate URLs
      - `scan_type="sqli"` → filter with `gf sqli`
      - `scan_type="bxss"` → accept any parameterized URLs

- BSQLi path:
   - Module: [bsqli/modules/blind_sqli/sqli_module.py](bsqli/modules/blind_sqli/sqli_module.py)
   - Detector: [bsqli/modules/blind_sqli/detector.py](bsqli/modules/blind_sqli/detector.py)
      - Boolean heuristics using length/similarity deltas
      - Time-based using MSSQL/MySQL/PG templates via payload engine
   - Payloads: [bsqli/modules/blind_sqli/payload_engine.py](bsqli/modules/blind_sqli/payload_engine.py) (+ [payloads.py](bsqli/modules/blind_sqli/payloads.py))
      - Seed types: boolean, time, error, union, stack
      - Mutators: case, comment spacing, URL encode, hex-encode
      - API: `generate_payloads(seed_type, db, obfuscate, depth, delay, max_results, seed)`
   - Output: [bsqli/output/findings.json](bsqli/output/findings.json), [bsqli/output/findings.txt](bsqli/output/findings.txt)

- BXSS path:
   - Module: [bxss/modules/blind_xss/xss_module.py](bxss/modules/blind_xss/xss_module.py)
   - Detector: [bxss/modules/blind_xss/detector.py](bxss/modules/blind_xss/detector.py)
      - Records each injection (UUID, URL, param, payload)
      - Sends requests without relying on response content
   - Payloads: [bxss/modules/blind_xss/payloads.py](bxss/modules/blind_xss/payloads.py)
      - Templates with `{UUID}`, `{LISTENER}`, `{LISTENER_HOST}` placeholders
   - Engine: [bxss/core/payload_engine.py](bxss/core/payload_engine.py)
      - UUID injection, context-specific selection
   - OOB: [bxss/oob/callback_server.py](bxss/oob/callback_server.py)
      - Receives callbacks; persists to `bxss/output/callbacks.json`
   - Correlation: [bxss/oob/correlation.py](bxss/oob/correlation.py)
      - Matches callbacks to injections, computes confidence, saves findings
   - Output: [bxss/output/findings_xss.json](bxss/output/findings_xss.json), [bxss/output/findings_xss.txt](bxss/output/findings_xss.txt)
   - ML: [bxss/ml/features.py](bxss/ml/features.py) appends to [bxss/output/features.csv](bxss/output/features.csv)

## Core Utilities (Shared)

- [bsqli/core/logger.py](bsqli/core/logger.py): colored logging
- [bsqli/core/http_client.py](bsqli/core/http_client.py): session, retries, timeout
- [bsqli/core/response_analyzer.py](bsqli/core/response_analyzer.py): timing, similarity, time-delta significance
- [bsqli/core/config.py](bsqli/core/config.py): thresholds, defaults, output paths

## Adding a New Module

1) New BSQLi-like module (example: command injection):

- Create: `bsqli/modules/blind_cmd_injection/`
- Implement `payload_engine.py` (seeds + optional mutators)
- Implement `detector.py` (HTTP strategy + heuristics)
- Implement `<name>_module.py` as the orchestration facade
- Plug into `main.py` (new `--scan` option and routing)

2) New BXSS context or variant:

- Add templates to [bxss/modules/blind_xss/payloads.py](bxss/modules/blind_xss/payloads.py)
- If needed, extend [bxss/core/payload_engine.py](bxss/core/payload_engine.py) for new selection logic
- Add detector methods in [bxss/modules/blind_xss/detector.py](bxss/modules/blind_xss/detector.py) for new injection points (e.g., cookies)

## Notes & Conventions

- Separation of concerns: module-specific payload engines live with their modules (BSQLi), while BXSS centralizes UUID injection logic under `bxss/core` and keeps templates under the module.
- Recon is reused for both scan types; filtering differs by `scan_type`.
- Outputs are separated: `output/*` for BSQLi, `bxss/output/*` for BXSS.
- Tests live under [tests/](tests/), with targeted unit tests (e.g., payload engines).

## Key Public APIs

- Recon: `gather_parameterized_urls(src, from_file=False, scan_type="sqli"|"bxss")`
- BSQLi:
   - `BlindSQLiModule.scan_url(url) -> list`
   - `generate_payloads(seed_type, db, obfuscate, depth, delay, max_results, seed) -> list`
- BXSS:
   - `BlindXSSModule.scan_url(url) -> list[dict]` (injection records)
   - `record_injection(uuid, url, parameter, payload)` / `correlate_callbacks(callbacks)`
   - `save_findings(findings, output_dir) -> (json_path, txt_path)`

This reflects the current codebase as of this update and fixes previous doc inaccuracies (e.g., BXSS existing under `bxss/` package, not `bsqli/`).

