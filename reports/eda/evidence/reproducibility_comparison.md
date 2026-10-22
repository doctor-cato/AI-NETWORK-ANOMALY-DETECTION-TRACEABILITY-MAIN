# NF-UNSW-NB15-v3 EDA reproducibility comparison

**Overall result: PASS** (summary content) /
PASS (run evidence)
Two independent executions of `scripts/eda_nf_unsw_nb15_v3.py` on the same verified
source file are compared here. The comparison walks both machine-readable summaries and
reports PASS or FAIL per metric. Only the metadata that is allowed to differ between two
runs of the same command is excluded: the run timestamp
(`generated_at_utc, tool.python, tool.platform`) and the environment description.

## Run identity

| Run | Git HEAD | Started (UTC) | Finished (UTC) | Duration | Exit code | Summary SHA-256 |
|---|---|---|---|---|---|---|
| run-1 | `435d56afb448` | 2026-10-22T08:47:32+00:00 | 2026-10-22T08:48:12+00:00 | 39.7 s | 0 | `7d712c3df71e67e7ffd46391d70ea126158c6b83c7441ef3d36d5d3822d45019` |
| run-2 | `435d56afb448` | 2026-10-22T08:48:13+00:00 | 2026-10-22T08:48:53+00:00 | 40.5 s | 0 | `579aceacfe0759402f7dc74c5707aa8af3c8787e8e677cb58903d377c0db9afe` |

| Run | Directory | Dataset SHA-256 | Manifest verified | Rows verified |
|---|---|---|---|---|
| run-1 | `C:\Users\Admin\Documents\code_workspace\AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN\reports\eda\evidence\run-1` | `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5` | PASS | PASS |
| run-2 | `C:\Users\Admin\Documents\code_workspace\AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN\reports\eda\evidence\run-2` | `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5` | PASS | PASS |

## Per-metric result on the deterministic summary content

| Metric | Result | Differences |
|---|---|---|
| `rows` | PASS | 0 |
| `expected_rows` | PASS | 0 |
| `row_count_matches_manifest` | PASS | 0 |
| `parse_mode` | PASS | 0 |
| `label_counts` | PASS | 0 |
| `attack_counts` | PASS | 0 |
| `protocol_counts` | PASS | 0 |
| `l7_proto_counts` | PASS | 0 |
| `categorical_counts` | PASS | 0 |
| `numeric_statistics` | PASS | 0 |
| `quantiles` | PASS | 0 |
| `class_conditional` | PASS | 0 |
| `class_conditional_quantiles` | PASS | 0 |
| `duration_throughput` | PASS | 0 |
| `time_coverage` | PASS | 0 |
| `duplicates` | PASS | 0 |
| `correlations` | PASS | 0 |
| `sample` | PASS | 0 |
| `sample_statistics` | PASS | 0 |
| `contract` | PASS | 0 |
| `readiness` | PASS | 0 |
| `leakage_boundary` | PASS | 0 |

## Per-metric result on the run evidence

| Check | Result |
|---|---|
| `command_normalized` | PASS |
| `exit_code` | PASS |
| `git_head` | PASS |
| `dataset_sha256` | PASS |
| `manifest_sha256_matches` | PASS |
| `row_count_matches` | PASS |

The two summary artifacts have different file hashes because each artifact embeds its own run timestamp: `7d712c3df71e67e7ffd46391d70ea126158c6b83c7441ef3d36d5d3822d45019` and `579aceacfe0759402f7dc74c5707aa8af3c8787e8e677cb58903d377c0db9afe`. The deterministic content comparison above is the authoritative check.

## Key aggregates observed in both runs

| Aggregate | run-1 | run-2 |
|---|---|---|
| Rows | 2,365,424 | 2,365,424 |
| Benign flows | 2,237,731 | 2,237,731 |
| Attack flows | 127,693 | 127,693 |
| Exact duplicate rows | 14,815 | 14,815 |
| Repeated rows, 47-feature equivalence | 1,134,553 | 1,134,553 |
| Non-finite values in the rate fields | 244,986 | 244,986 |
| Correlation observations | 2,242,931 | 2,242,931 |

## Differences

Summary content:

No deterministic difference was found between the two runs.

Run evidence:

No difference was found between the two evidence bundles outside the allowed metadata.

## How to re-check this evidence

```text
python scripts/verify_eda_reproducibility.py
```

The command re-runs the EDA twice, writes one bundle per run under
`reports/eda/evidence/` and regenerates this report. Each bundle contains the captured
`stdout.log` and `stderr.log`, the exact `eda_summary.json` and `eda_report.md` of that
run, and a `run_metadata.json` with the git state, the interpreter, the dependencies, the
dataset identity, the manifest and schema verification, the key aggregates, the command,
the exit code, the timestamps and the SHA-256 of the produced summary.
