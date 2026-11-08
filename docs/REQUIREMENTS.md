# Yêu cầu Phương án B

## Yêu cầu chức năng

| ID | Yêu cầu | Checkpoint | Issue |
|---|---|---|---|
| F01 | Provenance, schema, quality, EDA và leakage audit NF-UNSW-NB15-v3 | C1 | #4–#7 |
| F02 | Split trước fit; preprocessing artifact và leakage tests | C2 | #8 |
| F03 | Random Forest và XGBoost cùng supervised protocol | C3 | #9, #10, #12, #31 |
| F04 | Isolation Forest và Autoencoder; validation-only threshold; unknown holdout | C4 | #11, #29 |
| F05 | Versioned Network/API/Session Behavioral Vector và correlation confidence | C5 | #28 |
| F06 | Risk Score 0–100 có explanation/calibration; Trace Engine có evidence/timeline | C6 | #32, #24 |
| F07 | AES-GCM, key lifecycle, recovery, historical decrypt và fixed rotation | C7 | #26 |
| F08 | Adaptive early rotation/response lab-only có cooldown/rate-limit/idempotency | C8 | #27 |
| F09 | FastAPI, SQLite persistence, Streamlit thin client và E2E | C9 | #30, #16, #17 |
| F10 | Bảy experiments có protocol, artifact, result, limitations và reproduction | C10 | #25 |
| F11 | Report PDF, 10–12 slides, demo, guides và handoff 5 vai trò | C11 | #18–#20 |

## Yêu cầu phi chức năng

| ID | Yêu cầu | Kiểm chứng |
|---|---|---|
| N01 | Python 3.11+; code dưới `src/network_anomaly/` | import, CI matrix |
| N02 | Không secret/key/raw dataset/model artifact lớn trong Git | ignore/secret/size scan |
| N03 | Input schema validate; lỗi fail closed ở security boundary | negative/security tests |
| N04 | Tái lập: commit, dependency, seed, dataset/split, feature/config, artifact | run manifest/reproduction command |
| N05 | Phân biệt PLANNED/IMPLEMENTED/TESTED/EXPERIMENTALLY VALIDATED | traceability review |
| N06 | Apache-2.0 cho source; dependency/asset/dataset có nghĩa vụ riêng | license inventory |
| N07 | Lab-only dry-run; không response trên hệ thống thật | config defaults và tests |

## Điều kiện chung

Unit/integration test synthetic chỉ chứng minh hành vi code. `EXPERIMENTALLY VALIDATED`
đòi dữ liệu thật có provenance, protocol không leakage, artifact và result được đối chiếu.
Thiếu dữ liệu là `SKIPPED` hoặc `NOT VERIFIED`, không phải `PASS`.

Cập nhật: 2026-10-20 (dataset migration)
