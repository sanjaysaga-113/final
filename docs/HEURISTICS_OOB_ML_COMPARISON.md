# Comparison: Heuristics vs OOB vs ML

| Dimension | Classical Heuristics | OOB Correlation | ML Anomaly Layer |
|---|---|---|---|
| Primary signal | Timing/content diffs | Callback receipt + UUID match | Feature-space outlier score |
| Strength | Fast and simple | Strong confirmation evidence | Can suppress noisy false positives |
| Weakness | Sensitive to jitter/WAF/network noise | Requires reachable callback path | Depends on feature quality and training data |
| Typical failure mode | FP under unstable latency | FN when egress/DNS blocked | Drift/miscalibration without retraining |
| Best use in ShadowProbe | Baseline detector stage | Confirmation stage for BXSS/SSRF | Ranking/support stage (`ml_score`, `anomaly_score`) |
| Evidence type | Local response metrics | External callback records | Model score + threshold |

## Recommended Decision Flow
1. Heuristic trigger (candidate generation)
2. Control-payload checks (false positive reduction)
3. ML score interpretation (`delta_ratio`/timing features)
4. OOB confirmation when supported (BXSS/SSRF)

This sequence is implemented and evaluated using the ablation protocol in [docs/ABLATION_PROTOCOL.md](docs/ABLATION_PROTOCOL.md).
