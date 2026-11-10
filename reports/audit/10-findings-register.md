# Report 10 — Findings Register

## 1. Quy ước

- **Severity**: P0 = chặn nghiệm thu/nguy cơ bảo mật; P1 = sai lệch khoa học/hoàn thành; P2 = chất lượng/tái lập; P3 = vận hành/tài liệu.
- **Confidence**: High = đã tái lập bằng lệnh/artifact; Medium = suy ra từ code/manifest nhưng thiếu môi trường chạy; Low = chỉ suy luận.
- **Status**: `OPEN` trên HEAD; `FIX IN DIRTY WORKTREE` nghĩa là có fix chưa commit, **không được credit**.
- Mọi đường dẫn là tại `b14dfee`.

## 2. Bảng findings

| ID | Sev | Conf | Finding | Bằng chứng chính | Tác động | Remediation |
|---|---|---|---|---|---|---|
| **F-01** | **P0** | High | Inference loader fail-open: model không manifest hoặc manifest `{}` vẫn được nạp/predict | `src/network_anomaly/inference/predict.py:283-301, 316-359, 363`; `inference/pipeline.py:25-44`; reproducer `INFERENCE_NO_MANIFEST ACCEPTED`, `INFERENCE_EMPTY_MANIFEST ACCEPTED` | RCE qua pickle; dự đoán bằng model không kiểm chứng | Bắt buộc manifest; hash/contract/feature/class bắt buộc; xóa legacy loader; ký artifact |
| **F-02** | **P0** | High | `RandomForestModel.load_verified()` chấp nhận `provenance_status: "UNVERIFIED"` | `src/network_anomaly/models/random_forest.py:405-411`; reproducer `RF_UNVERIFIED_PROVENANCE ACCEPTED` | Model “verified” nhưng provenance không đạt | Chỉ chấp nhận `VERIFIED`; đồng bộ với XGB |
| **F-03** | **P0** | High | Chuỗi hash split → preprocessor → model không nhất quán; hardcode hash | split `main` `1ba6b2ef…`; RF `bb84c1e0…`; XGB/prep `845d8863…`; `scripts/train_random_forest.py:71` (pin có từ baseline `b212377`, không phải regression trong range); `.gitattributes` `eol=lf` | Không thể verify/reproduce từ clean checkout | Chọn một canonical split; tái sinh artifact; bỏ hardcode; lưu hash do tool tính |
| **F-04** | **P1** | High | XGBoost không có artifact; CLI không hỗ trợ; issue #31 đóng khi 0/4 AC | `reports/models/xgboost_manifest.json`; `artifacts/models/xgboost/` vắng; `scripts/predict.py:50-67`; `--model xgboost` → exit 1 | Không thể train lại, load, predict, evaluate XGB | Sinh artifact thật hoặc mở lại #31; thêm `--model xgboost` |
| **F-05** | **P1** | High | Test partition bị materialize/transform trong preprocessing trước evaluation | `reports/preprocessing/execution_evidence.json:52-59` (test row_count/all_finite/zero_duration); RF `test_lock_audit` chỉ cho training | Vi phạm strict test isolation; không có audit toàn vòng đời | Tách preprocessing test khỏi run train; chỉ transform test tại evaluation; ghi audit trail |
| **F-06** | **P1** | High | Shortcut learning trên TTL | `MIN_TTL`+`MAX_TTL` = `45,48%` importance; 1-feature DT accuracy `0,9998494373`; `MIN_TTL=31` attack rate 0; `=62` rate 1,0 | Metric 99,99% không chứng minh phát hiện hành vi; false confidence | Ablation TTL; báo metric có/không TTL; cross-dataset |
| **F-07** | **P1** | High | IF inference trả raw `-1/1`, không áp threshold; `decision_score` ngược dấu | `inference/predict.py:467, 494-498`; `isolation_forest.py:301-309`; `train_isolation_forest.py:1490-1548` | Output sai semantics; score cao = bình thường | Dùng `anomaly_scores` + threshold; map `score >= threshold` → 1; lưu threshold trong manifest |
| **F-08** | **P1** | High | Đóng issue sớm: #15, #17, #31; #7/#8/#10 thiếu tái lập | Report 04; GitHub issue states | False completion; milestone sai | Mở lại issue chưa đạt; cập nhật AC theo evidence |
| **F-09** | **P1** | High | M2 đóng dù #31 không đạt; M4 0 open nhưng không đóng | GitHub milestone data; #31 0/4; M4 0 open/2 closed | Milestone không phản ánh thực tế | Đóng/mở lại theo acceptance gate |
| **F-10** | **P2** | High | Tài liệu trạng thái lỗi thời: README vẫn ghi model training “PLANNED” sau khi IF/XGB/inference đã merge; ARCHITECTURE chỉ là target, không có status as-built | `README.md:23-24, 139`; `docs/ARCHITECTURE.md:28-36` | Người đọc không phân biệt được code đã merge với năng lực đã xác minh | Cập nhật status matrix theo Report 12 |
| **F-11** | **P2** | High | CI/lint gate bỏ sót; không chạy lint trên push main; repo-wide lint non-gating | `.github/workflows/lint-audit.yml:7-17, 44-79, 111-125`; `ci.yml` | Nợ lint vào main; “CI xanh” không đủ | Thêm push trigger; mở rộng scoped list; gate Ruff/Black |
| **F-12** | **P2** | High | CLI/runner integration thiếu: evaluate/inference exit 3; XGB không chọn được | `scripts/run_experiments.py:28-37, 79-84`; `scripts/predict.py:50-67` | Không có entrypoint end-to-end | Implement evaluate/inference; thêm XGB branch |
| **F-13** | **P2** | High | Không có evaluation test cho #12/#13 | Issue #12/#13 open; không có metric test trong repo; `run_experiments evaluate` exit 3 | Không có bằng chứng M3 | Chạy một lần trên test, lưu predictions/metrics |
| **F-14** | **P2** | High | Execution evidence bị ghi đè bởi run XGB, không khớp RF | `execution_evidence.json` `git_commit=89c32fa`, split `845d…`, prep `e1e89b…`; RF manifest `git_commit=6f50633`, split `bb84…`, prep `12d436…` | Không truy vết được run RF | Tách evidence theo run_id; không ghi đè |
| **F-15** | **P2** | Medium | Duplicate/group/temporal leakage chưa verify | EDA: 14.815 exact; 1.134.553 ML-equivalent; 1.270 mixed-category groups; split audit report | Metric có thể lạc quan; không chứng minh leakage-safe | Audit byte-level trên index thật; báo overlap |
| **F-16** | **P2** | High | Supply chain không pin/lock/audit | `pyproject.toml:25-30` dùng `>=`; Actions dùng tag; không lockfile/pip-audit/SBOM | Build không tái lập; rủi ro dependency | Pin version/hash; pin Actions SHA; thêm audit |
| **F-17** | **P2** | High | PR merge khi review `CHANGES_REQUESTED` | PR #38, #40 (trong range); #41 (trước baseline) | Giảm chất lượng review gate | Yêu cầu approve trước merge |
| **F-18** | **P3** | High | Năng lực branch-only bị hiểu nhầm là main | PR #51 (+3.390/−5, 13 file, CI 5/5), #47, #49, #52 | Credit sai | Ghi rõ branch-only trong mọi báo cáo |
| **F-19** | **P2** | Medium | Contract 47 vs 49 features không nhất quán | Issue #31 dataset contract ghi “49-feature”; baseline 47 | Nguy cơ train sai schema | Sửa issue/docs về 47 |
| **F-20** | **P2** | Medium | Không có calibration/external validity/cross-dataset | Không có calibration curve/Brier; không có cross-dataset trên main; TTL shortcut | Không chứng minh generalization | Calibration + cross-dataset + TTL ablation |
| **F-21** | **P3** | High | Trainer tạo manifest `git_commit=UNKNOWN` ngoài Git → reload fail | `git archive` export: 2 failed, 737 passed; `_get_git_commit()` trả UNKNOWN | Không reproducible từ source tarball | Cho phép build metadata tường minh; không phụ thuộc `.git` |
| **F-22** | **P3** | Medium | Môi trường artifact khác CI | RF manifest Python 3.14.10/sklearn 1.9.1/numpy 2.5.4; CI 3.11/3.12 | Artifact có thể không load trong CI | Pin environment; test load artifact trong CI |
| **F-23** | **P3** | High | Không tìm thấy secrets; không có API trong main | tracked files; `src/` không có api/storage | **Positive control** | Giữ nguyên; audit lại khi merge #52 |

## 3. Nhóm theo mức độ

### P0 — phải sửa trước mọi nghiệm thu

- F-01, F-02, F-03.

### P1 — phải sửa trước khi tuyên bố milestone/issue hoàn thành

- F-04, F-05, F-06, F-07, F-08, F-09.

### P2 — phải sửa trước khi coi là “production-ready” hoặc “reproducible”

- F-10, F-11, F-12, F-13, F-14, F-15, F-16, F-17, F-19, F-20.

### P3 — vận hành/tài liệu

- F-18, F-21, F-22.
- F-23 là **positive control** (không có secrets/API trong `main`), không phải defect cần remediation.

## 4. Liên kết với remediation issues

| Finding | Issue |
|---|---|
| F-01 | #53, #60 |
| F-02 | #53, #60 |
| F-03 | #55, #60 |
| F-04 | #55, #60 |
| F-05 | #56, #60 |
| F-06 | #57, #60 |
| F-07 | #54, #60 |
| F-08/F-09 | #60 |
| F-11 | #37, #60 |
| F-12 | #60 |
| F-13 | #56, #60 |
| F-14 | #55 |
| F-15 | #57 |
| F-16 | #60 |
| F-17 | #60 |
| F-18 | #58, #59 |
| F-19 | #55 |
| F-20 | #57 |
| F-21/F-22 | #55 |

## 5. Điều không được làm

- Không đóng F-01/F-02 dựa trên fix trong working tree chưa commit.
- Không đóng F-03 bằng cách sửa hash trong manifest cho khớp; phải tái sinh artifact.
- Không đóng F-04 bằng cách tạo manifest mới mà không có `.joblib`.
- Không đóng F-06 bằng cách báo metric cao hơn; phải ablation TTL.
- Không đóng F-08/F-09 bằng checkbox; phải có evidence.
