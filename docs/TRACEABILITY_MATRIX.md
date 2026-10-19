# Ma trận truy vết Phương án B

Trạng thái vòng đời: `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`.
Trạng thái kiểm chứng: `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED`.

C0 chỉ xác nhận governance/backlog. Mọi checkpoint C1–C11 vẫn `PLANNED` cho đến khi có
code, test và evidence tương ứng. PR #22 là workstream #4/#5 riêng, không tự merge.

| C | Requirement | Issue | Deliverable/evidence bắt buộc | Trạng thái C0 |
|---|---|---|---|---|
| C0 | Governance, scope, architecture, backlog | #23 | docs, GitHub readback, branch/commit/PR | IMPLEMENTED; VERIFY chờ CI/PR |
| C1 | Data quality, EDA, leakage | #4–#7, PR #22 | manifest/report/EDA/leakage decision | #4/#5 TESTED trên PR #22; #6/#7 PLANNED |
| C2 | Preprocessing không leakage | #8 | pipeline artifact, fit-boundary tests | PLANNED |
| C3 | RF và XGBoost supervised | #9, #10, #12, #31 | model artifacts, metrics, reproduction | PLANNED |
| C4 | IF, Autoencoder, unknown holdout | #11, #29 | thresholds, holdout protocol, results | PLANNED |
| C5 | Behavioral Vector | #28 | versioned schemas, fixtures, correlation tests | PLANNED |
| C6 | Risk và Trace | #32, #24 | explanation, calibration, evidence/timeline tests | PLANNED |
| C7 | AES-GCM và key lifecycle | #26 | integrity/recovery/rotation tests | PLANNED |
| C8 | Adaptive response | #27 | cooldown/rate/idempotency/concurrency audit | PLANNED |
| C9 | API, persistence, dashboard | #30, #16, #17 | OpenAPI, DB recovery, E2E | PLANNED |
| C10 | 7 experiments | #25 | protocol, artifact, results, limitations | PLANNED |
| C11 | Delivery | #18–#20 | PDF, slides, demo, guides, 5-role handoff | PLANNED |

Chuỗi bắt buộc cho từng claim:
`Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
Synthetic fixture/CI không thay thế real-data experiment. Mỗi result phải gắn commit,
dataset/split identifier, dependency versions, seed/config, artifact và reproduction command.

## Review PR #22 và Issue #4/#5 tại C0

- Remote: PR #22 `OPEN`, `MERGEABLE`, chưa có `reviewDecision`; 4/4 CI jobs thành công.
- Local review worktree: 105 tests PASS; manifest verify PASS; real split validation PASS
  với duplicate warning; `git diff --check` PASS.
- Giới hạn: SHA-256 là project-computed, UNSW không công bố checksum; duplicate/overlap
  leakage thuộc #7. Không merge hoặc đóng #4/#5 trong C0.

Cập nhật: 2026-10-19 (self-review; không phải reviewer độc lập khác)
