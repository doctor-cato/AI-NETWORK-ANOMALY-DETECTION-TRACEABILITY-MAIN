# Ma trận truy vết Phương án B

Trạng thái vòng đời: `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`.
Trạng thái kiểm chứng: `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED`.

| C | Requirement | Issue | Deliverable/evidence | Trạng thái hiện tại |
|---|---|---|---|---|
| C0 | Governance, scope, architecture, backlog | #23 | docs, backlog, PR evidence | IMPLEMENTED; trạng thái remote phải đọc lại theo từng PR |
| C1 | NF-UNSW-NB15-v3 provenance, quality, EDA, leakage | #4–#7 | v3 manifest, schema, real numeric/duplicate audit, EDA report, leakage decision | `SOURCE_INTEGRITY: PASS`; `RAW_QUALITY: FINDINGS_RECORDED`; EDA IMPLEMENTED/TESTED on real data; real split/leakage audit PASS (PR #41); `ML_READY: BLOCKED` |
| C2 | Preprocessing không leakage | #8 | train-only pipeline artifact, fit-boundary tests, single-load verified loader | IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED on verified v3 bytes; AC1–AC4 PASS (provenance synchronized across artifact, manifest, split bb84c1e0..., smoke report); `ML_READY: BLOCKED` |
| C3 | RF và XGBoost supervised | #9, #10, #12, #31 | model artifacts, metrics, reproduction | PLANNED |
| C4 | IF, Autoencoder, unknown holdout | #11, #29 | thresholds, holdout protocol, results | PLANNED |
| C5 | Behavioral Vector | #28 | versioned schemas, fixtures, correlation tests | PLANNED |
| C6 | Risk và Trace | #32, #24 | explanation, calibration, evidence/timeline tests | PLANNED |
| C7 | AES-GCM và key lifecycle | #26 | integrity/recovery/rotation tests | PLANNED |
| C8 | Adaptive response | #27 | cooldown/rate/idempotency/concurrency audit | PLANNED |
| C9 | API, persistence, dashboard | #30, #16, #17 | OpenAPI, DB recovery, E2E | PLANNED |
| C10 | 7 experiments | #25 | protocol, artifacts, results, limitations | PLANNED |
| C11 | Delivery | #18–#20 | PDF, slides, demo, guides, 5-role handoff | PLANNED |

## Dataset migration A–H

| Gate | Implementation | Tests/evidence | Status |
|---|---|---|---|
| A — Research/source | decision, provenance, schema, impact records | official UQ/RDM bytes and metadata compared | VERIFIED |
| B — Architecture | component inventory, default/historical paths, rollback boundary | `git diff --check` | PASS |
| C — Acquisition/manifest | bounded fetch, safe ZIP, lock, transaction, checksums | synthetic safety tests + official download/cache verification | PASS |
| D — Quality audit | streaming validator, disk-backed numeric/duplicate/label-conflict audit | real report on 2.365.424 rows | SOURCE_INTEGRITY PASS; RAW_QUALITY FINDINGS_RECORDED; ML_READY BLOCKED |
| E — Split contract | 47-feature exclusion, versioned fingerprints, group/temporal guards | synthetic + real split tests (PR #41) | TESTED / EXPERIMENTALLY VALIDATED; real split/leakage audit PASS |
| F — Architecture/docs | v3 default throughout current docs | link/text/status checks | IMPLEMENTED / VERIFIED |
| G — Tests/CI | Windows/Linux matrix, migration regression tests, lint audit workflow | 219 pytest PASS (211 previous + 8 reproducibility tests); PR-scoped Ruff and Black PASS; repository-wide Ruff (5 findings) and Black (11 files) still FAIL on pre-existing files, tracked in #37; CI matrix PASS 4/4; lint audit workflow PASS on Linux | PARTIAL — remote CI PASS, repository-wide lint debt remains in #37 |
| H — Issues/PR | #6–#15, #17, #18, #20, #25, #29, #31; historical notes #4/#5; M1–M5/M7 | #6/#7/#8/#17/#20 hardening contracts read back OPEN; PR #36 OPEN into `main` | VERIFIED; not merged |
| I — EDA (Issue #6) | `scripts/eda_nf_unsw_nb15_v3.py`, `src/network_anomaly/eda/`, generated report + summary | 15 EDA unit tests + 8 reproducibility tests on synthetic fixtures PASS; real run on 2.365.424 rows; inherited findings reproduced (rows, labels, exact duplicates, repeated rows all MATCH) | IMPLEMENTED / TESTED; no split, no fitted artifact, `ML_READY: BLOCKED` |
| J — EDA reproducibility evidence | `scripts/verify_eda_reproducibility.py`, `reports/eda/evidence/` | two independent real-data runs with captured stdout/stderr, git state, environment, dataset identity, manifest/schema verification and key aggregates; deterministic content comparison PASS per metric | VERIFIED — evidence retrievable per run |

UNSW-NB15 (2015) evidence is preserved under `historical/`; its old validation cannot satisfy a v3
gate. PR #22 and #35 are merged historical workstreams, not pending proof for this migration.

Chuỗi bắt buộc cho mọi claim:
`Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
Synthetic fixture/CI không thay thế real-data experiment. Mỗi result phải gắn commit,
dataset/split identifier, dependency versions, seed/config, artifact và reproduction command.

Cập nhật: 2026-10-22 (migration NF-UNSW-NB15-v3 + EDA Issue #6; self-review, không phải reviewer độc lập)
