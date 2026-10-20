# Ma trận truy vết Phương án B

Trạng thái vòng đời: `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`.
Trạng thái kiểm chứng: `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED`.

| C | Requirement | Issue | Deliverable/evidence | Trạng thái hiện tại |
|---|---|---|---|---|
| C0 | Governance, scope, architecture, backlog | #23 | docs, backlog, PR evidence | IMPLEMENTED; trạng thái remote phải đọc lại theo từng PR |
| C1 | NF-UNSW-NB15-v3 provenance, quality, EDA, leakage | #4–#7 | v3 manifest, schema, real audit, leakage decision | Provenance/schema TESTED; quality real-data FAIL; EDA/split NOT VERIFIED |
| C2 | Preprocessing không leakage | #8 | train-only pipeline artifact, fit-boundary tests | Feature/split guards TESTED; fitted artifact PLANNED |
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
| D — Quality audit | streaming validator, disk-backed duplicate audit | real report on 2.365.424 rows | FAIL due missing/Inf/duplicates |
| E — Split contract | feature exclusions, group key, bounded overlap guards | synthetic split tests | TESTED; real split NOT VERIFIED |
| F — Architecture/docs | v3 default throughout current docs | link/text/status checks | IMPLEMENTED; verification pending |
| G — Tests/CI | Windows/Linux matrix and migration regression tests | full gates | pending |
| H — Issues/PR | affected backlog and migration PR | GitHub readback/CI | pending |

UNSW-NB15 (2015) evidence is preserved under `historical/`; its old validation cannot satisfy a v3
gate. PR #22 and #35 are merged historical workstreams, not pending proof for this migration.

Chuỗi bắt buộc cho mọi claim:
`Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
Synthetic fixture/CI không thay thế real-data experiment. Mỗi result phải gắn commit,
dataset/split identifier, dependency versions, seed/config, artifact và reproduction command.

Cập nhật: 2026-10-20 (migration NF-UNSW-NB15-v3; self-review, không phải reviewer độc lập)
