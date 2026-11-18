# Kiểm toán GitHub Issues, Milestones & Acceptance Criteria — NetFlow Sentinel v2.0

**Phạm vi kiểm toán:** Chỉ đọc kho mã nguồn & GitHub API (không chỉnh sửa code, manifest hay GitHub issue/milestone).  
**Nhánh / Commit đối chiếu (`HEAD`):** `feat/v2-integration` @ `79ebb678b87de19cc6b664b587726983fecaf98f` (`79ebb67`) · Draft PR `#156` (`OPEN`, `mergeable_state: blocked`)  
**CI Run đối chiếu:** [Actions Run #44171616420](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/runs/44171616420) trên `79ebb67` (`conclusion: failure`)  
**Ngày kiểm toán:** `2026-11-18` (UTC+7)

---

## 1. Tóm tắt Điều hành & Con số Tổng hợp

Cuộc kiểm toán đối chiếu toàn bộ **88 open issues** hiện hành trên GitHub (**80 issues v2** `#76–#155` thuộc `M6.1–M6.7`, **7 issues kế thừa** thuộc `M7`: `#18, #19, #20, #25, #48, #60, #71`, và **1 issue không gắn milestone**: `#73`) cùng **15 milestones** (`M0–M7`, `M6.1–M6.7`) với mã nguồn (`src/`, `scripts/`, `tests/`, `desktop/`, `docs/`, `reports/`, `artifacts/`, `.github/workflows/`) và kết quả CI thực tế.

| Chỉ số | Giá trị thực đo |
|---|---|
| **Tổng số open issues được kiểm toán** | **88** (`80` v2 `#76–#155` + `7` M7 + `1` None `#73`) |
| **Tổng số Acceptance Criteria (AC) checkboxes** | **372** |
| **Trạng thái AC trên GitHub trước kiểm toán** | **61 `[x]`** (trên 18 issues) / **311 `[ ]`** (70 issues còn `0` tick) |
| **Trạng thái AC đề xuất sau kiểm toán trên `79ebb67`** | **233 `[x]`** / **139 `[ ]`** *(bổ sung `+194` tick hợp lệ, bỏ `-22` tick sai/lỗi thời/fail CI)* |
| **Issues v2 sẵn sàng tick đủ toàn bộ AC (`TICK_FULL`)** | **26 issues** *(lưu ý vẫn giữ GitHub `OPEN` chờ PR `#156` merge & CI xanh)* |
| **Issues v2 sẵn sàng tick một phần AC (`TICK_PARTIAL`)** | **33 issues** |
| **Issues v2 đang có `[x]` nhưng cần BỎ TICK / sửa lỗi (`UNTICK_INVALID`)** | **6 issues** (`#83, #86, #92, #93, #94, #95`) |
| **Issues v2 giữ nguyên `[x]` hợp lệ hiện tại (`KEEP_CHECKED_VALID`)** | **6 issues** (`#82, #84, #85, #87, #88, #91`) |
| **Issues v2 giữ nguyên tất cả `[ ]` (`KEEP_UNCHECKED`)** | **9 issues** (`#76, #81, #89, #90, #97, #128, #148, #153, #154`) |
| **Issues kế thừa v1 (`M7` + `None`) cần dọn dẹp (`LEGACY_V1_REMEDIATE`)** | **8 issues** (`#18, #19, #20, #25, #48, #60, #71, #73`, trong đó `#18, #48, #60, #71` có `[x]` lỗi thời/fail CI cần bỏ tick) |

> [!IMPORTANT]
> **Không đóng issue v2 hàng loạt trước khi merge & xanh CI:** Dù `26` issues đã thỏa toàn bộ checkbox AC trên mã nguồn nhánh `feat/v2-integration`, hầu hết **Definition of Done (DoD)** đều yêu cầu *"được merge vào `main`"*. Do PR `#156` hiện còn ở trạng thái `DRAFT / BLOCKED` và CI run `44171616420` đang **FAIL**, các issue đã đạt AC chỉ nên **tick `[x]` checkbox** và **giữ trạng thái `OPEN`** cho tới khi CI xanh trên `main`.

---

## 2. Kết quả Kiểm chứng Thực tế trên `HEAD` (`79ebb67`) & CI (`44171616420`)

### 2.1. Sai lệch Local Working Tree (Windows CRLF) vs CI Checkout (LF)

| Kiểm tra | Cục bộ (`HEAD 79ebb67`, Windows) | GitHub Actions CI `44171616420` (`79ebb67`) | Tác động tới AC Issues |
|---|---|---|---|
| `scripts/check_environment.py` | **PASS** (`Python 3.12.10`, 10 packages OK) | **PASS** trên cả 4 Python jobs | Xác nhận môi trường cơ sở |
| `scripts/export_openapi_spec.py --check` | **PASS** (`openapi.json`, `API_CONTRACT.md`) | **PASS** (`ubuntu-latest, 3.12`) | Hỗ trợ `#115`, `#139` |
| `scripts/check_desktop_version.py --check` | **PASS** (`1.0.0` desktop / `0.1.0` FastAPI) | — | Hỗ trợ `#139`, `#148` |
| `scripts/parse_dag.py` | **PASS** (`80 nodes, 0 cycles, 23 steps`) | — | Hỗ trợ `#78`, `#155` |
| `git diff --check` | **PASS** (exit 0) | — | Sạch whitespace trên working tree |
| `pytest tests/unit/test_basic.py tests/integration/test_pipeline.py -q` | **PASS** (`15 passed in 3.30s`) | Nằm trong suite 560+ tests | Baseline smoke pass |
| `scripts/verify_companion_artifacts.py` | **PASS** (`READY`, `4/4` models, `demo_ready: true`) | **FAIL** gián tiếp trong pytest (`13 failed`) | Hủy hợp lệ `[x]` của **`#92, #94, #95, #60, #71`**, chặn `#20, #138, #154` |
| `ruff check src scripts tests` | — | **FAIL** (`67` lỗi trên `53` files, `ruff==0.17.5`) | Chặn `#20, #60, #138, #154` |
| `test (ubuntu-latest, 3.11)` | — | **FAIL**: `13 failed, 547 passed, 21 skipped` | Chặn `#92, #94, #95, #138, #154` |
| `test (ubuntu-latest, 3.12)` | — | **FAIL**: `13 failed, 547 passed, 21 skipped` | Chặn `#92, #94, #95, #138, #154` |
| `test (windows-latest, 3.11)` | — | **FAIL**: `13 failed, 549 passed, 19 skipped` | Chặn `#92, #94, #95, #138, #154` |
| `test (windows-latest, 3.12)` | — | **FAIL**: `13 failed, 549 passed, 19 skipped` | Chặn `#92, #94, #95, #138, #154` |
| `desktop-frontend` (`svelte-check`, Vitest, Vite) | — | **PASS**: `svelte-check 0 errors, 0 warnings`; `5 files / 33 tests passed`; `built in 1.19s` | Xác nhận **`#139, #140–#144`** (UI unit/type/build) |
| `desktop-tauri-windows` (`clippy`, `cargo test`, build exe) | — | **PASS**: `cargo clippy` OK; `cargo test 9 passed, 0 failed`; build exe PASS | Xác nhận **`#139`** (Rust shell + build exe; chưa phải VM NSIS E2E `#148`) |

### 2.2. Hai nguyên nhân gốc của 13 Test Failures trên CI `44171616420`

1. **Lệch EOL CRLF vs LF (`10/13` test failures):** `.gitattributes` quy định `* text=auto eol=lf` (`i/lf`), nhưng trên máy Windows phát triển, `data/V2_SPLIT_MANIFEST.json`, `reports/splits/v2_split_manifest.json`, và `reports/preprocessing/v2_flow_preprocessing_manifest.json` đang ở trạng thái `w/crlf`. Mã SHA-256 tính theo byte CRLF (`1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a`) bị ghi cứng vào `v2_flow_preprocessing_manifest.json`, cả 4 `reports/models/*_manifest.json`, `model_comparison_report.json` và `src/network_anomaly/api/desktop_csv.py:691`. Khi CI checkout sạch dưới dạng LF, hash không khớp, gây lỗi `RuntimeError` / `AssertionError` ở `test_controller_target_vm_e2e.py`, `test_desktop_csv_api.py::test_f01_provenance_anti_spoofing_matrix` và 8 tests trong `test_verify_companion_artifacts.py`.
2. **Thiếu fallback file đã di chuyển khi clean checkout vắng `data/demo/*` (`3/13` test failures):** Commit `79ebb67` chuyển `reports/releases/v0.6.0_e2e_verification.json` sang `reports/historical/nf_unsw_nb15_v3/releases/v0.6.0_e2e_verification.json`. Trên máy cục bộ có sẵn `data/demo/*` (bị `.gitignore`), test đi qua nhánh khác; trên CI không có `data/demo/*`, `test_verify_companion_artifacts.py` mở đường dẫn cũ gây `FileNotFoundError`.

Ngoài ra, lệnh `python scripts/fetch_multi_source_dataset.py --verify-only` (chạy trong `.github/workflows/ci.yml:87`) **tự ghi đè 3 file JSON được track** (`data/AIT_DATASETS_MANIFEST.json`, `data/CTU_SME_11_MANIFEST.json`, `data/EXTERNAL_DATASETS_PROVENANCE.json` — cập nhật `generated_at_utc` và CRLF). Đã hoàn tác 3 file này bằng `git checkout --` trong quá trình kiểm toán để giữ cây làm việc sạch.

---

## 3. Kiểm toán Milestones (`M0–M7` & `M6.1–M6.7`)

| ID | Trạng thái | Tên Milestone | GitHub API Counters | Issues Thực tế trong `issues.json` | AC Đã/Sẽ Tick | Ghi chú Kiểm toán |
|---|---|---|---|---|---|---|
| M#1 | `closed` | `M0 — Nền tảng kho lưu trữ và thiết kế dự án` | open=0, closed=3 | open=0, closed=3 (`#1–#3`) | — | Lịch sử v1, khớp |
| M#2 | `closed` | `M1 — Chuẩn bị dữ liệu, EDA và kiểm toán leakage` | open=0, closed=5 | open=0, closed=4 (`#4–#7`) | — | Counter GitHub +1 từ PR `#22` |
| M#3 | `closed` | `M2 — Tiền xử lý và baseline Random Forest` | open=0, closed=4 | open=0, closed=4 (`#8–#10, #31`) | — | Lịch sử v1, khớp |
| M#4 | `closed` | `M3 — Đánh giá mô hình và phân tích kết quả` | open=0, closed=8 | open=0, closed=8 (`#11–#14, #29, #54–#56`) | — | Lịch sử v1, khớp |
| M#5 | `closed` | `M4 — Inference, demo và kiểm thử tích hợp` | open=0, closed=3 | open=0, closed=3 (`#15, #17, #53`) | — | Lịch sử v1, khớp |
| M#6 | `closed` | `M5 — Tài liệu, trình bày và xác minh bàn giao` | open=3, closed=0 | open=0, closed=0 | — | **STALE GH COUNTER** (đã rỗng từ migration M7) |
| M#7 | `closed` | `M6 — Backend, Dashboard & Integration` | open=1, closed=10 | open=0, closed=9 (`#16, #24, #26, #28, #30, #32, #46, #58–#59`) | — | **STALE GH COUNTER** (counter báo open=1 dù 0 issue mở) |
| M#8 | `open` | `M7 — Experiments, Documentation & Delivery` | open=7, closed=6 | open=7 (`#18–#20, #25, #48, #60, #71`), closed=4 | 24/50 → 11/50 | **STALE GH COUNTER** (closed=6 vs 4); nhiều nội dung v1 lỗi thời, giao thoa M6.3/M6.7 |
| M#9 | `open` | `M6.1 — Foundation & Architecture Migration` | open=7, closed=0 | open=7 (`#76–#81, #155`), closed=0 | 1/30 → 18/30 | `#76, #81` vướng `/docs/audits/` bị `.gitignore` |
| M#10 | `open` | `M6.2 — Multi-source Data Engineering` | open=12, closed=0 | open=12 (`#82–#93`), closed=0 | 29/40 → 23/40 | `6` issue `[x]` bị hạ tick do lỗi `--verify-only`, `v2_adapter.py`, CRLF CI, `#89/#90` |
| M#11 | `open` | `M6.3 — AI & Behavioral Intelligence` | open=13, closed=0 | open=13 (`#94–#106`), closed=0 | 7/51 → 34/51 | `#94/#95` fail CI LF; `#99` thiếu OOD artifact; `#103` thiếu profiler; `#106` thiếu CSV vector |
| M#12 | `open` | `M6.4 — Risk Assessment & Attack Traceability` | open=9, closed=0 | open=9 (`#107–#115`), closed=0 | 0/36 → 29/36 | Trace Engine (`#110–#113, #115`) sẵn sàng; `#107` thiếu schema trong `db.py`; `#114` lỗi `+65.0%` |
| M#13 | `open` | `M6.5 — Cryptography & Adaptive Security` | open=11, closed=0 | open=11 (`#116–#126`), closed=0 | 0/44 → 40/44 | Cốt lõi crypto mạnh; chỉ vướng clock injection (`#120`), persist rate-limit (`#122`) & runbooks (`#119/#123`) |
| M#14 | `open` | `M6.6 — Real-world Network Monitoring` | open=11, closed=0 | open=11 (`#127–#137`), closed=0 | 0/45 → 38/45 | Pipeline streaming + 3 chế độ đạt; `#128` lệch Rust vs Python; `#137` `BLOCKED` lab vật lý |
| M#15 | `open` | `M6.7 — Final Integration & NetFlow Sentinel v2.0` | open=17, closed=0 | open=17 (`#138–#154`), closed=0 | 0/68 → 40/68 | Desktop frontend/Tauri build PASS (`#139, #143, #144`); `#148, #153, #154` còn `BLOCKED / PLANNED` |
| — | `none` | *(Không có milestone — `#73`)* | — | open=1 (`#73`), closed=0 | 0/8 → 0/8 | Cần gán milestone (`M7` hoặc `M6.7`) và cập nhật sang license v2 (`AIT-NDS-v2` CC BY 4.0) |

---

## 4. Phân tích Issue Trùng lặp, Giao thoa & Lỗi thời trước Cutover v2

| Cụm Issue | Bản chất Trùng lặp / Xung đột | Bằng chứng Đối chiếu | Khuyến nghị Xử lý trên GitHub |
|---|---|---|---|
| **`#94` vs `#97` vs `#25` vs `#48`** | Bốn issue cùng bao phủ Cross-Dataset Generalization & `MIN_TTL` ablation | `#48` (M7) sửa v1 `E0`/`ToN-IoT` PR `#49`; `#25` (M7) ghi `NF-UNSW-NB15-v3` `Exp 1–3/4`; `#94` đã lưu trữ `MODEL_AUDIT_TTL_ABLATION.md` vào `historical/`; `#97` vẫn dẫn `PR #49` & `#25/#48` dù thực nghiệm v2 nằm ở `run_ctu_cross_source_eval.py` | Đóng/đánh dấu `#25` và `#48` là `superseded by v2 (#94, #96–#98, #145)`; cập nhật thân `#97` trỏ `run_ctu_cross_source_eval.py` + `UGR'16 BLOCKED` và chốt `AC4`. |
| **`#71` vs `#73` vs `#148`** | Bộ cài Windows & Clean VM Acceptance tách đôi giữa v1 và v2 | `#71` là installer v1.0.0 (`PR #72`, `2226170`), 8 AC hoãn sang `#73` (vẫn ghi UQ `454104`); `#148` mở lại toàn bộ installer v2.0 + clean VM | Đóng `#71` (v1 đã phát hành mã nguồn `v1.0.0`); chuyển/gộp các cổng mở của `#73` (`clean Windows 10/11 VM`, `DISTRIBUTION_AUTHORIZATION.json` CC BY 4.0) vào `#148` hoặc cập nhật `#73` sang v2. |
| **`#18` vs `#151` & `#152`** | Tài liệu, giấy phép và website `site-source` | `#18` (`7/8` tick) đóng băng ở v1 (`PR #74` + `PR #75 CLOSED` + `55 cột` + `docs/academic-defense/01–09`); `#151` & `#152` là bản v2 nhưng `site-source` (`a01bd38ad`) vẫn ở v1 | Bỏ tick cũ không còn đúng ở `#18` hoặc đóng `#18` như v1 merged (`PR #74`), chuyển toàn bộ phần v2 (`site-source`, `cryptography` notice) sang `#151`/`#152`. |
| **`#19` vs `#153`** | Báo cáo PDF, slide bảo vệ 10–12 trang & Q&A | Cả hai cùng yêu cầu PDF/slide/chỉ rõ phần DEFER; `#19` còn ghi `NF-UNSW-NB15-v3.csv` | Hợp nhất `#19` vào `#153` cho bộ hồ sơ bảo vệ v2. |
| **`#20` vs `#154`** | Tổng kiểm tra bàn giao & Release Readiness Audit | Cả hai kiểm toàn bộ suite, phân loại `PASS/FAIL/SKIPPED/NOT VERIFIED` và chặn release khi thiếu cổng P0 | Đóng `#20` gộp vào `#154` (hoặc giữ `#20` làm checklist cấp khóa học trỏ kết quả `#154`). |
| **`#60` vs `#146`** | Tổng hợp khắc phục bảo mật & kiểm toán | `#60` (`8/11` tick) tổng hợp issue v1 `#53–#59, #37` (với `#47/#49` chưa merge); `#146` là Security Audit v2 | Đóng `#60` sau khi ghi nhận phần hồi quy CI/CRLF vào `#146` & `#154`. |
| **`#80` vs `#149`** | Migration v1 → v2 & Upgrade Path | Đều kiểm chứng không mất dữ liệu SQLite (`migrate_v1_to_v2.py`); `#80` là thiết kế/script nền, `#149` là luồng upgrade phát hành | Tách rạch ròi: `#80` phủ CLI/DB schema (`AC1,2,4`); `#149` chịu trách nhiệm rollback & installer upgrade v1→v2. |
| **`#78` vs `#155`** | Kiến trúc v2 & Bản đồ phụ thuộc DAG | Cả hai đều nghiệm thu `V2_DEPENDENCY_GRAPH.md` không chu trình + critical path | Giữ `#78` cho kiến trúc 7 module/hợp đồng (chỉnh sửa `#128`), `#155` cho DAG điều phối. |

---

## 5. Các Mismatch Nghiêm trọng giữa `[x]` Hiện tại và Codebase / CI

1. **CRLF/LF Checksum Drift làm đổ toàn chuỗi Provenance (`#92, #94, #95, #60, #71`):**
   - `git ls-files --eol` xác nhận 3 manifest split/preprocessing đang lưu CRLF cục bộ (`w/crlf`) trái với `.gitattributes` (`i/lf`).
   - Mã `1b7fa7ae...` bị nhúng vào preprocessor, 4 model manifests, `model_comparison_report.json` và `desktop_csv.py:691`, làm CI `44171616420` fail **10 tests**; cộng thêm đường dẫn `reports/releases/v0.6.0_e2e_verification.json` chưa cập nhật vị trí `historical/` trong `test_verify_companion_artifacts.py:147-150` gây thêm **3 FileNotFoundError**.
2. **`fetch_multi_source_dataset.py --verify-only` ghi đè file đang track (`#83`):**
   - Lệnh `python scripts/fetch_multi_source_dataset.py --verify-only` (chạy trong CI) ghi lại 3 file manifest JSON ở `data/` thay vì chỉ kiểm tra read-only.
3. **Chuẩn hóa Timestamp & Entity Identifiers sai hợp đồng (`#86, #89, #90, #93`):**
   - `src/network_anomaly/ingestion/adapters/v2_adapter.py`: `parse_timestamp_utc` trả về `datetime.now(timezone.utc)` khi thiếu/sai timestamp; `IdentityAuthAdapter.adapt_line` hardcode `2020-11-05`; tự gán `"0.0.0.0"`, `"unknown_user"`, `"local_host"`; `ApplicationWebAdapter` không tước URL query string/credential; 4 adapter mới chưa đăng ký vào `SourceRegistry`; `test_v2_adapters.py` không test missing timestamp hay `SystemAuditAdapter` hay thiếu user/host.
4. **Tài liệu kiểm toán bị `.gitignore` chặn (`#76, #81, #146`):**
   - Dòng 69 của `.gitignore` là `/docs/audits/`, khiến `docs/audits/V2_GAP_ANALYSIS.md` (`#76`) và `docs/audits/THREAT_MODEL_V2.md` (`#81`) hoàn toàn vắng mặt trong Git (`git ls-files`) và CI. Ngoài ra `THREAT_MODEL_V2.md` dẫn 5 tên file test không tồn tại. *(Lưu ý: `reports/audits/` không nằm trong `.gitignore`.)*
5. **Tích hợp AI + Behavioral Engine chưa chạm luồng CSV (`#106`):**
   - Tìm kiếm toàn bộ `src/network_anomaly/` khẳng định `BehavioralVector` chỉ chạy trong `LiveSystemOrchestrator` và `/api/v1/behavioral/*`, không có trong `inference/predict.py`, `inference/pipeline.py` hay `api/desktop_csv.py` (`#106` AC1/AC4 chưa đạt).
6. **Lỗ hổng kỹ thuật rải rác trên ML/Risk/Trace/Crypto/Telemetry/Docs:**
   - **#99 / #137:** Không có `artifacts/ml/ood_reference_gate.json`; `synthetic_udp_loopback_report.json:53` ghi `ood_gate=NOT_FITTED`.
   - **#101 / #102:** `BehavioralVectorBuilder` chuyển NaN/Inf thành `0.0` không có cờ thiếu.
   - **#103 / #141:** Chưa có entity baseline profiler học từ dữ liệu train và chưa có phân bố ngưỡng similarity.
   - **#105:** `model_comparison_report.json` để `"top_features": []` cho `Isolation Forest` & `Autoencoder` và nhúng đường dẫn `C:\Users\ASUS\...`.
   - **#107:** `src/network_anomaly/api/db.py` `SCHEMA_SQL` chưa có bảng `unified_security_events`, `behavioral_vectors`, `encrypted_vault` (chỉ có trong `migrate_v1_to_v2.py`).
   - **#114:** `scripts/evaluate_traceability.py` chạy trên 8 sự kiện giả lập, so với baseline hardcoded (`0.25`/`0.30`) và sai phép trừ `+65.0%` thay vì `+75.0%`.
   - **#120 / #122:** `check_fixed_schedule` gọi thẳng `datetime.now(timezone.utc)` (khó test đồng hồ); `KeyRotationPolicy` lưu cooldown/rate-limit in-memory (`_history`, `_last_rotation_time`), mất trạng thái sau restart.
   - **#128 / #78 / #151:** `ARCHITECTURE_V2.md:14` ghi hoãn Rust crate và làm Python UDP collector, nhưng dòng 49, 215 vẫn ghi Rust/Crate.
   - **#150 / #152:** `docs/USER_GUIDE_V2.md:12-13` dẫn 3 route không tồn tại (`/api/v1/telemetry/status`, `/api/v1/telemetry/events`, `/api/v1/behavioral/sessions`); nhánh `site-source` (`a01bd38ad`, `2026-11-16`) vẫn ở v1.0.0.
   - **#18 / #117:** `THIRD_PARTY_NOTICES.md` thiếu mục giấy phép của thư viện `cryptography`.

---

## 6. Sổ Đăng ký Phụ thuộc Ngoài (`External Dependency Blockers`)

| Blocker Ngoại vi | Chi tiết & Bằng chứng Thực tế | Issues bị Chặn |
|---|---|---|
| **`UGR'16` HTTP 403 (`Portal en Mantenimiento`)** | Máy chủ `nesg.ugr.es/nesg-ugr16/` trả HTTP 403, ghi `BLOCKED` trong `data/EXTERNAL_DATASETS_PROVENANCE.json` và `V2_SOURCE_AUDIT.md` | `#82` (AC5), `#83` (AC4), `#97` (external ISP) |
| **Chưa nối trực tiếp `AIT-NDS-v2` ↔ `AIT-LDS-v2.1`** | `AIT-NDS-v2` sinh từ `AIT-LDS-v2.0`; log trong repo là `v2.1`; `direct_uid_join_possible: false` (`NOT VERIFIED`) | `#85` (AC3), `#104` (empirical AIT RQ3), `#112` (real cross-source ground truth) |
| **Clean Windows 10/11 VM E2E & Maintainer Signoff** | `reports/governance/DISTRIBUTION_AUTHORIZATION.json` có `approved: false` (`HOLD_FOR_MAINTAINER_SIGNOFF`); chưa chạy `vm_target_e2e.ps1` + `--sign-vm-witness` | `#71`, `#73`, `#148`, `#149` (NSIS upgrade), `#154` |
| **Mạng Lab Router/Switch Vật lý** | Mới chạy synthetic UDP loopback (`synthetic_udp_loopback_report.json`: `real_device_tested: false`, `alerts: NOT_TRIGGERED`) | `#137` (AC1, AC2), `#150` (live lab demo) |
| **Maintainer Merge PR `#156` & Deploy `site-source`** | PR `#156` còn `draft/blocked`; nhánh `site-source` chưa cập nhật v2 | `#18, #60, #152, #154` và DoD merge `main` của toàn bộ `#76–#155` |

---

## 7. Ma trận Truy vết Issue → Code → Test (`#18, #19, #20, #25, #48, #60, #71, #73` & `#76–#155`)

> **Quy ước:** *Lifecycle Tier* phân biệt `PLANNED` / `IMPLEMENTED` / `TESTED` / `EXPERIMENTALLY VALIDATED` (hoặc `HISTORICAL_V1` / `BENCHMARKED`). Cột `AC [x]` ghi `<trước> → <đề xuất sau kiểm toán>`.

| Issue | Milestone | State | Tiêu đề | AC `[x]` | Lifecycle Tier | Verdict | Bằng chứng Code / Doc / Report / Test | Lỗ hổng / Blocker chính |
|---|---|---|---|---|---|---|---|---|
| #18 | M7 | OPEN | Hoàn thiện tài liệu, giấy phép và ghi nhận nguồn (SUPPORTING / M7) | 7/8 → 1/8 | `HISTORICAL_V1 / PARTIAL_V2` | `STALE_V1_UNTICK` | v1 PR `#74` (merged `main`), `docs/academic-defense/EVIDENCE_INDEX.md`, `NOTICE`, `THIRD_PARTY_NOTICES.md` | Viết cho v1 (`NF-UNSW-NB15-v3`, `55 cột`, UQ `454104`); `docs/academic-defense/01–09` đã chuyển vào `docs/historical/`; PR `#75` trên `site-source` `CLOSED`; `THIRD_PARTY_NOTICES.md` thiếu thư viện `cryptography`; chồng lấn `#151`/`#152`. |
| #19 | M7 | OPEN | Hoàn thiện báo cáo PDF, bài trình bày và gói bàn giao (SUPPORTING / M7) | 0/4 → 0/4 | `PLANNED` | `STALE_V1_KEEP` | `docs/REPORT_OUTLINE.md`, `docs/PRESENTATION_OUTLINE.md` (chỉ có outline) | Chưa có báo cáo PDF hay slide 10–12 trang; tiêu chí AC4 còn ghi `NF-UNSW-NB15-v3.csv`; trùng phạm vi `#153`. |
| #20 | M7 | OPEN | Xác minh tổng thể và đánh giá điều kiện bàn giao (SUPPORTING / M7) | 1/6 → 1/6 | `IMPLEMENTED / TESTED (PARTIAL)` | `FAIL_ON_CI` | `.gitignore`, `reports/audits/V2_ISSUE_AC_AUDIT.md`, CI `44171616420` | CI `44171616420` trên `79ebb67` FAIL (`lint` 67 lỗi Ruff + `13 failed` Python tests); phụ thuộc `#18, #19, #25`; trùng `#154`. |
| #25 | M7 | OPEN | C10 — Thực nghiệm khoa học trọng tâm có bằng chứng tái lập (REDUCE trong M7) | 0/3 → 0/3 | `SUPERSEDED_BY_V2` | `STALE_V1_KEEP` | v2 tương đương tại `scripts/run_rq{2,3,4,5}*`, `run_ctu_cross_source_eval.py`, `reports/experiments/` | Nội dung issue còn ghi `NF-UNSW-NB15-v3`, `test_indices.csv.gz`, `Exp 1–3/4` v1; đã thay thế bằng `#94, #96–#98, #104, #125–#126, #145`. |
| #48 | M7 | OPEN | C10/M7 — Nghiên cứu Cross-Dataset Robustness (DEFER / M7 — không chặn Demo MVP) | 1/3 → 0/3 | `HISTORICAL_V1` | `STALE_V1_UNTICK` | v1 PR `#49` (`7344994` lịch sử); v2 tại `scripts/run_ctu_cross_source_eval.py`, `reports/experiments/ml/ctu_cross_source_eval.json` | `AC1` `[x]` chỉ đúng cho v1 PR `#49` (`ToN-IoT`); `AC2` (`PR #49` sau `#47`) lỗi thời sau hard cutover v2; trùng `#97`. |
| #60 | M7 | OPEN | [Audit Remediation] Consolidated security, ML validity, artifact integrity & integration findings | 8/11 → 3/11 | `HISTORICAL_V1 / REGRESSED` | `STALE_V1_UNTICK` | v1 PR `#61` (merged `main`), `git` history; v2 thay thế bằng `#146` | `AC3, AC4, AC7` `[x]` mất hiệu lực trên CI `44171616420` (`test_verify_companion_artifacts.py`, `test_desktop_csv_api.py` FAIL do CRLF/LF hash & file moved); `AC5, AC6` trỏ PR `#47/#49` chưa merge (đã bỏ qua trong v2); `AC8` `#37` đã đóng nhưng nhánh v2 phát sinh 67 lỗi Ruff mới. |
| #71 | M7 | OPEN | feat(desktop): Standalone Windows Installer — Bundled Python Backend & 4 ML Models | 7/15 → 6/15 | `HISTORICAL_V1 / BLOCKED_V2` | `STALE_V1_UNTICK` | v1 PR `#72` (`2226170`); v2 tại `scripts/build_installer_v2.py` (`#148`) | `AC11` `[x]` ghi `8/8 CI checks tại PR #72 HEAD 2226170` đã lỗi thời — CI v2 `44171616420` FAIL (`5/7` jobs fail); `AC1,2,4,5,6,9` mới xác minh cục bộ cho v1, chưa tái xác minh VM cho v2; `AC3,7,8,10,12–15` bị hoãn sang `#73`/`#148`. |
| #73 | None | OPEN | chore(release,windows): follow-up clean Windows VM acceptance, binary release & UQ 454104 licensing (#71) | 0/8 → 0/8 | `BLOCKED` | `BLOCKED` | `reports/governance/DISTRIBUTION_AUTHORIZATION.json` (`approved: false`), `scripts/vm_target_e2e.ps1` | Chưa có Clean Windows 10/11 VM x64 offline E2E (`Standard User`, reboot, uninstall) hay `release_e2e_verification.json`; `AC7` vẫn ghi UQ `454104` thay vì v2 `AIT-NDS-v2` `CC BY 4.0` + `DISTRIBUTION_AUTHORIZATION.json` chưa được maintainer phê duyệt. |
| #76 | M6.1 | OPEN | [M6.1][P0][Audit] Gap analysis v1.0.0 so với đề cương gốc Đề tài 22 | 0/4 → 0/4 | `IMPLEMENTED (LOCAL ONLY)` | `FAIL_DOD_GITIGNORED` | `docs/audits/V2_GAP_ANALYSIS.md` (tồn tại cục bộ, 63 dòng) | `/docs/audits/` bị `.gitignore:69` chặn nên file không có trên Git/CI (`git ls-files`), vi phạm DoD; chứa tham chiếu cũ (`api/routes.py`, `test_response_simulation.py`). |
| #77 | M6.1 | OPEN | [M6.1][P0][Research] Khôi phục 6 Research Questions, hypothesis và ma trận ánh xạ | 0/4 → 3/4 | `IMPLEMENTED` | `PARTIAL` | `docs/RESEARCH_QUESTIONS.md`, `docs/EXPERIMENT_PLAN.md` | `RESEARCH_QUESTIONS.md` chưa có bảng ánh xạ tường minh từng `RQ -> Issue triển khai -> Issue đánh giá` như yêu cầu `AC3` và diễn đạt không nguyên văn `.docx`. |
| #78 | M6.1 | OPEN | [M6.1][P0][Architecture] Target architecture v2.0, dependency graph và module ownership | 0/5 → 4/5 | `IMPLEMENTED` | `PARTIAL` | `docs/ARCHITECTURE_V2.md`, `docs/ARCHITECTURE.md`, `docs/V2_DEPENDENCY_GRAPH.md`, `scripts/parse_dag.py` | `ARCHITECTURE_V2.md` mâu thuẫn nội tại về `#128`: dòng 14 ghi Python UDP collector (Rust deferred) trong khi dòng 49, 215 vẫn ghi Rust/Crate (`AC2`). |
| #79 | M6.1 | OPEN | [M6.1][P0][Contract] Canonical Security Event v2 và feature contract đa nguồn | 1/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `docs/CANONICAL_SECURITY_EVENT_V2.md`, `src/network_anomaly/canonical/{event.py,feature_contract.py}`, `tests/contract/test_canonical_security_event_v2.py` | `AC1` chưa đạt hoàn toàn: 4 adapter lớp ứng dụng/auth/audit (`#89/#90`) nằm trong `v2_adapter.py`, chưa đăng ký vào `SourceRegistry`, `parse_timestamp_utc` tự fallback `now()` và `IdentityAuthAdapter.adapt_line` hardcode `2020-11-05`. |
| #80 | M6.1 | OPEN | [M6.1][P1][Migration] Versioning, backward compatibility và đường migration v1.0.0 → v2.0 | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `docs/MIGRATION_V1_TO_V2.md`, `scripts/migrate_v1_to_v2.py`, `tests/integration/test_migration_v1_to_v2.py` | `AC3`: sau hard cutover, active FastAPI/Desktop v2 từ chối v1; chỉ các script lưu trữ `historical/` chạy nguyên trạng v1 (chưa có kiểm chứng runtime v1 độc lập hậu cutover). |
| #81 | M6.1 | OPEN | [M6.1][P1][Security] Threat model và security requirements cho NetFlow Sentinel v2.0 | 0/4 → 0/4 | `IMPLEMENTED (LOCAL ONLY)` | `FAIL_DOD_GITIGNORED` | `docs/audits/THREAT_MODEL_V2.md` (tồn tại cục bộ, 61 dòng) | `/docs/audits/` bị `.gitignore:69` chặn (chưa track trong Git); đánh dấu `SR1,3,5–9,11` là `PLANNED` và dẫn **5 tên file test không tồn tại** (`AC2` & DoD fail). |
| #82 | M6.2 | OPEN | [M6.2][P0][Dataset] Audit nguồn, license, provenance và khả năng tải các dataset P0/P1/P2 | 4/5 → 4/5 | `EXPERIMENTALLY VALIDATED` | `PARTIAL_EXTERNAL_BLOCKER` | `data/EXTERNAL_DATASETS_PROVENANCE.json`, `docs/dataset/V2_SOURCE_AUDIT.md`, `NOTICE`, `THIRD_PARTY_NOTICES.md` | `UGR'16` bị `HTTP 403` (`BLOCKED`); PR `#156` còn `draft/blocked`; lưu ý `THIRD_PARTY_NOTICES.md` thiếu dòng package `cryptography` (liên quan `#18/#117`). |
| #83 | M6.2 | OPEN | [M6.2][P0][Data] Dataset downloader, checksum verification và manifest cho nguồn mới | 3/4 → 2/4 | `IMPLEMENTED / TESTED (DEFECT)` | `FAIL_MUTATION_AND_BLOCKED` | `scripts/fetch_multi_source_dataset.py`, `tests/unit/test_dataset_manifest_separation.py`, `.github/workflows/ci.yml:87` | `--verify-only` **ghi đè trực tiếp 3 manifest JSON được track** (`AIT_DATASETS_MANIFEST.json`, `CTU_SME_11_MANIFEST.json`, `EXTERNAL_DATASETS_PROVENANCE.json` — đổi `generated_at_utc` + CRLF), làm bẩn git working tree khi chạy kiểm chứng; `AC4` (`UGR'16`) `BLOCKED`. |
| #84 | M6.2 | OPEN | [M6.2][P0][Data] Profiling AIT NetFlow Dataset và AIT Log Dataset v2.1 | 3/3 → 3/3 | `EXPERIMENTALLY VALIDATED` | `PASS_WITH_NOTE` | `reports/datasets/v2_multi_source_profile.json`, `docs/dataset/{AIT_PROFILE,CTU_SME_11_PROFILE}.md` | Tiêu đề nêu `AIT Log Dataset v2.1` nhưng `AC1` chuyển trọng tâm sang `AIT-NDS-v2` (`3,465,342` dòng gốc / `3,231,215` dòng sau split) & `CTU-SME-11` (`260,613` dòng); `AIT-LDS-v2.1` chỉ dừng ở mức kiểm tra khả năng liên kết tại `#85`. |
| #85 | M6.2 | OPEN | [M6.2][P0][Data] Kiểm chứng khả năng liên kết AIT NetFlow ↔ AIT Log v2.1 | 2/3 → 2/3 | `EXPERIMENTALLY VALIDATED (BLOCKED)` | `PARTIAL_EXTERNAL_BLOCKER` | `docs/dataset/AIT_LINKAGE_FEASIBILITY.md`, `data/EXTERNAL_DATASETS_PROVENANCE.json` (`direct_uid_join_possible: false`), `reports/experiments/behavioral/rq3_session_correlation_experiment.json` | Liên kết trực tiếp `AIT-NDS-v2` (tạo từ `AIT-LDS-v2.0`) với `AIT-LDS-v2.1` bị `NOT VERIFIED` / `BLOCKED` do lệch phiên bản & thiếu khóa UID đồng bộ. |
| #86 | M6.2 | OPEN | [M6.2][P0][Data] Chuẩn hóa timestamp và entity identifiers đa nguồn | 3/3 → 1/3 | `IMPLEMENTED (DEFECT)` | `FAIL_CODE_MISMATCH` | `src/network_anomaly/ingestion/adapters/v2_adapter.py`, `tests/unit/test_v2_adapters.py` | `parse_timestamp_utc` tự fallback sang `datetime.now(timezone.utc)` khi thiếu/lỗi timestamp; `IdentityAuthAdapter.adapt_line` hardcode `datetime(2020, 11, 5, 8, 0, 0, tzinfo=timezone.utc)`; adapter tự sinh `"0.0.0.0"`/`"unknown_user"`/`"local_host"`; `test_v2_adapters.py` **không có test missing timestamp**. |
| #87 | M6.2 | OPEN | [M6.2][P0][Data] Label harmonization và attack taxonomy thống nhất đa nguồn | 2/2 → 2/2 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/data/taxonomy.py`, `tests/unit/test_anti_imputation_and_label_integrity.py`, `test_v2_migration_guards.py` | Không có lỗ hổng trên module taxonomy/anti-coercion. |
| #88 | M6.2 | OPEN | [M6.2][P0][Adapter] Network Flow adapter thống nhất cho canonical-flow-v2-18 (AIT-NDS-v2, CTU-SME-11, NetFlow/Zeek) | 3/3 → 3/3 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/ingestion/adapters/{canonical_v2.py,zeek.py}`, `tests/unit/test_ingestion_adapters.py`, `test_v2_migration_guards.py` | Adapter NetFlow/Zeek chuẩn hóa đúng `canonical-flow-v2-18` và chặn v1 47-feature fail-closed. |
| #89 | M6.2 | OPEN | [M6.2][P0][Adapter] Adapter log lớp ứng dụng: DNS và Web/API | 0/4 → 0/4 | `IMPLEMENTED (PARTIAL)` | `PARTIAL_MISSING_GATES` | `src/network_anomaly/ingestion/adapters/v2_adapter.py` (`ApplicationDNSAdapter`, `ApplicationWebAdapter`), `tests/unit/test_v2_adapters.py` | Chưa đăng ký trong `SourceRegistry` (`registry.py`); `ApplicationWebAdapter` **không lọc URL query string/credential** (`AC3` fail); `test_v2_adapters.py` chưa test thiếu trường bắt buộc / thiếu timestamp (`AC4`). |
| #90 | M6.2 | OPEN | [M6.2][P0][Adapter] Adapter log danh tính và hệ thống: Authentication/VPN và System/Audit | 0/4 → 0/4 | `IMPLEMENTED (PARTIAL)` | `FAIL_CODE_MISMATCH` | `src/network_anomaly/ingestion/adapters/v2_adapter.py` (`IdentityAuthAdapter`, `SystemAuditAdapter`), `tests/unit/test_v2_adapters.py` | Chưa đăng ký trong `SourceRegistry`; `IdentityAuthAdapter.adapt_line` hardcode `2020-11-05` & tự điền `"unknown_user"`/`"local_host"`; `SystemAuditAdapter` và case thiếu user/host chưa có trong `test_v2_adapters.py` (`AC4`). |
| #91 | M6.2 | OPEN | [M6.2][P0][Data] Data quality validation và rejection gate cho multi-source | 3/3 → 3/3 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/data/quality_gate.py`, `tests/unit/test_quality_gate.py`, `reports/datasets/v2_multi_source_profile.json` | Các unit test quality gate pass; báo cáo profile có checksum nguồn và thống kê ngoại lệ. |
| #92 | M6.2 | OPEN | [M6.2][P0][Data] Leakage-resistant train/validation/test split cho dữ liệu đa nguồn | 3/3 → 2/3 | `EXPERIMENTALLY VALIDATED (CI REGRESSED)` | `FAIL_ON_CI` | `src/network_anomaly/data/split.py`, `scripts/build_v2_dataset_and_split.py`, `data/V2_SPLIT_MANIFEST.json`, `reports/splits/v2_split_manifest.json` | Working tree Windows lưu `w/crlf` trong khi `.gitattributes` ép `i/lf`, làm `split_manifest_sha256` (`1b7fa7ae...`) lệch SHA-256 trên CI LF checkout và gây **10/13 test FAIL** tại `44171616420` (`test_verify_companion_artifacts.py`, `test_controller_target_vm_e2e.py`, `test_desktop_csv_api.py`). |
| #93 | M6.2 | OPEN | [M6.2][P0][Integration] Cross-source event alignment và multi-source pipeline end-to-end | 3/3 → 1/3 | `IMPLEMENTED (INCOMPLETE)` | `FAIL_DEPS_AND_TEST` | `src/network_anomaly/pipeline/multi_source.py`, `tests/integration/test_multi_source_pipeline.py` | Phụ thuộc `#89/#90` chưa xong (`SourceRegistry` thiếu 4 adapter v2); `test_multi_source_pipeline.py` không test `SystemAuditAdapter`; `MultiSourcePipeline` không phát cảnh báo `AIT linkage NOT VERIFIED` như `AC3` khẳng định. |
| #94 | M6.3 | OPEN | [M6.3][P0][ML] Audit và tái lập kết quả 4 model, kiểm tra leakage và shortcut TTL | 3/3 → 1/3 | `EXPERIMENTALLY VALIDATED (CI REGRESSED)` | `FAIL_ON_CI` | `reports/models/*_manifest.json`, `reports/experiments/ml/{model_comparison_report,ctu_cross_source_eval}.json`, `docs/EVALUATION.md` | 4 manifest model và `model_comparison_report.json` nhúng CRLF `split_manifest_sha256` (`1b7fa7ae...`), dẫn tới RuntimeError FAIL trên CI `44171616420` khi xác minh chuỗi provenance preprocessor/model. |
| #95 | M6.3 | OPEN | [M6.3][P0][ML] Đánh giá tương thích dataset mới và retrain khi feature space thay đổi | 4/4 → 3/4 | `EXPERIMENTALLY VALIDATED (CI REGRESSED)` | `FAIL_ON_CI` | `docs/adr/ADR-dataset-hard-cutover-v2.md`, `src/network_anomaly/models/registry.py`, `scripts/train_*.py`, `scripts/verify_companion_artifacts.py`, `src/network_anomaly/api/desktop_csv.py:691` | `verify_companion_artifacts.py` báo `READY` cục bộ nhưng FAIL trên CI `44171616420` (`13 failed`) vì `v2_flow_preprocessing_manifest.json` & `desktop_csv.py:691` giữ SHA-256 CRLF `1b7fa7ae...` và thiếu fallback file `v0.6.0_e2e_verification.json` khi `data/demo/*` bị gitignore. |
| #96 | M6.3 | OPEN | [M6.3][P1][ML] Class imbalance và rare-attack evaluation protocol | 0/4 → 3/4 | `EXPERIMENTALLY VALIDATED (LOCAL)` | `PARTIAL` | `scripts/run_rq2_rare_attack_experiment.py`, `reports/experiments/imbalance/rq2_imbalance_report.{json,md}` | Không resample Val/Test, có metric từng lớp hiếm (`Credential_Attack` R=0.1410, `Post_Exploitation_Discovery` R=0.9459, `Exploitation_And_C2` N=5), nêu giới hạn `h2_full_confirmed=false`; tuy nhiên chưa thử SMOTE/oversampling, RF/XGB trong script train tại chỗ (`"trained_in_experiment"`) và JSON nhúng CRLF `split_manifest_sha256`. |
| #97 | M6.3 | OPEN | [M6.3][P1][ML] Cross-dataset generalization và ablation TTL (kế thừa #25, #48, PR #49) | 0/4 → 0/4 | `EXPERIMENTALLY VALIDATED (OVERLAP)` | `SCOPE_OVERLAP_KEEP` | v2: `scripts/run_ctu_cross_source_eval.py`, `reports/experiments/ml/ctu_cross_source_eval.json`, `docs/experiments/CTU_CROSS_SOURCE_EVAL.md`; v1 TTL ablation: `docs/historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md` | Thân issue vẫn tham chiếu PR `#49` và phạm vi cũ của `#25/#48`; chưa ghi rõ quan hệ kế thừa/đóng `#25/#48` (`AC4`); `UGR'16` bị `BLOCKED` HTTP 403. |
| #98 | M6.3 | OPEN | [M6.3][P0][ML] Unknown attack holdout experiment chuẩn hóa (RQ4) | 0/4 → 3/4 | `EXPERIMENTALLY VALIDATED` | `PARTIAL` | `scripts/run_rq4_unknown_attack_experiment.py`, `reports/experiments/ml/rq4_unknown_attack_report.json`, `docs/experiments/EXP4_UNKNOWN_ATTACK.md` | `AC1` có rủi ro tinh tế: RF/XGB lọc sạch 209 Train & 58 Val holdout, nhưng IF/AE nạp từ `ModelRegistry` có threshold hiệu chỉnh trên `ait_val` đầy đủ (còn 58 dòng holdout) dù comment dòng 9–11 ghi nhầm v1 `'Backdoor & Worms excluded'`. |
| #99 | M6.3 | OPEN | [M6.3][P0][ML] OOD detection và inference rejection cho dữ liệu mới | 0/4 → 3/4 | `IMPLEMENTED / TESTED (NO ARTIFACT)` | `PARTIAL_MISSING_ARTIFACT` | `src/network_anomaly/ml/ood_gate.py`, `src/network_anomaly/ingestion/ood.py`, `tests/unit/test_ood_and_calibration.py`, `tests/unit/test_ood_gate.py` | `artifacts/ml/ood_reference_gate.json` **không tồn tại** trong `artifacts/` và `synthetic_udp_loopback_report.json:53` ghi `ood_gate=NOT_FITTED`, nên tín hiệu OOD thống kê chưa hoạt động trên artifact runtime (`AC1`). |
| #100 | M6.3 | OPEN | [M6.3][P0][ML] Threshold calibration trên validation, chống tuning trên test | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/ml/threshold_calibration.py`, `src/network_anomaly/models/scoring.py`, `reports/models/*_manifest.json`, `tests/unit/test_model_registry.py`, `test_ood_and_calibration.py` | Tất cả threshold có nguồn validation trong manifest; unit test chặn calibration trên test split đều PASS (lưu ý toàn hệ thống vẫn cần fix CI LF). |
| #101 | M6.3 | OPEN | [M6.3][P0][Behavioral] Behavioral feature extraction và sessionization/time-window aggregation | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `src/network_anomaly/behavioral/sessionizer.py`, `docs/BEHAVIORAL_ENGINE.md`, `tests/unit/test_behavioral_engine.py`, `reports/benchmarks/system_performance_benchmark.json` | `AC3`: tuyến downstream `BehavioralVectorBuilder` ép NaN/Inf thành `0.0` mà không có cờ đánh dấu thiếu; `Sessionizer` cũng fallback sang IP khi vắng `entity_id`. |
| #102 | M6.3 | OPEN | [M6.3][P0][Behavioral] Behavioral Vector construction và versioning | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `src/network_anomaly/behavioral/vector.py`, `docs/BEHAVIORAL_ENGINE.md`, `tests/unit/test_behavioral_engine.py` | `AC2`: `BehavioralVectorBuilder` chuyển NaN/Inf về `0.0` và **không phát missingness indicator**. |
| #103 | M6.3 | OPEN | [M6.3][P1][Behavioral] User/device behavioral profiling và similarity metrics | 0/4 → 2/4 | `IMPLEMENTED (PARTIAL)` | `PARTIAL_MISSING_PROFILER` | `src/network_anomaly/behavioral/similarity.py` (3 metrics: `COSINE`, `NORMALIZED_EUCLIDEAN`, `MANHATTAN`), `tests/unit/test_behavioral_engine.py` | Thiếu module/lớp tính **Entity Baseline Profile chỉ từ dữ liệu học** (`AC1`) và thiếu phân tích phân bố similarity để biện luận ngưỡng (`AC3`). |
| #104 | M6.3 | OPEN | [M6.3][P0][Behavioral] IP-independent session correlation và Experiment 5 (RQ3) | 0/4 → 4/4 | `EXPERIMENTALLY VALIDATED (SIMULATION)` | `PASS_WITH_BLOCKED_NOTE` | `src/network_anomaly/behavioral/correlation.py`, `scripts/run_rq3_session_correlation_experiment.py`, `reports/experiments/behavioral/rq3_session_correlation_experiment.json`, `docs/experiments/EXP5_SESSION_CORRELATION.md` | Thực nghiệm trên dữ liệu thực AIT vẫn `BLOCKED` (theo `#85`); kết quả mô phỏng ghi trung thực `simulation_hypothesis_met=false` (`F1=0.3191` / `0.5556`). |
| #105 | M6.3 | OPEN | [M6.3][P1][ML] Model explainability và báo cáo so sánh 4 model | 0/4 → 3/4 | `IMPLEMENTED (PARTIAL)` | `PARTIAL` | `scripts/generate_model_comparison_report.py`, `reports/experiments/ml/model_comparison_report.json`, `docs/experiments/FOUR_MODEL_COMPARISON.md` | `model_comparison_report.json` để `"top_features": []` cho cả `Isolation Forest` và `Autoencoder` (`AC1` chưa có giải thích tái lập cho từng model) và rò đường dẫn máy cục bộ `C:\Users\ASUS\...`. |
| #106 | M6.3 | OPEN | [M6.3][P0][Integration] Tích hợp AI Engine và Behavioral Engine vào inference pipeline | 0/4 → 2/4 | `IMPLEMENTED (LIVE ONLY)` | `PARTIAL_NO_CSV_VECTOR` | `src/network_anomaly/streaming/live_orchestrator.py`, `src/network_anomaly/api/live_runtime.py`, `src/network_anomaly/inference/{predict.py,pipeline.py}`, `src/network_anomaly/api/desktop_csv.py` | `BehavioralVector` **chỉ nối vào Live Orchestrator**, hoàn toàn vắng mặt trong CSV `predict.py` / `desktop_csv.py` (`AC1` & `AC4` CSV+Vector thất bại). |
| #107 | M6.4 | OPEN | [M6.4][P0][Event] Unified Security Event v2 và persistence schema | 0/4 → 2/4 | `IMPLEMENTED (PARTIAL)` | `PARTIAL_SCHEMA_GAP` | `src/network_anomaly/canonical/event.py`, `scripts/migrate_v1_to_v2.py`, `src/network_anomaly/api/db.py`, `tests/integration/test_migration_v1_to_v2.py` | `db.py` `SCHEMA_SQL` khởi tạo DB mới chưa có bảng `unified_security_events`, `behavioral_vectors`, `encrypted_vault` (chỉ có trong `migrate_v1_to_v2.py` / `EncryptedStorageVault`), thiếu repository + test truy vấn theo `entity` và `time range` (`AC1, AC4`). |
| #108 | M6.4 | OPEN | [M6.4][P0][Risk] Risk scoring methodology 0–100 và hiệu chỉnh severity | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `docs/RISK_METHODOLOGY.md`, `src/network_anomaly/risk/scoring.py`, `tests/unit/test_risk_engine.py` | Thiếu báo cáo đo **phân bố risk thực tế trên tập Benign vs Attack** của `AIT-Test`/`CTU` (`AC2` mới chỉ test unit trên fixture). |
| #109 | M6.4 | OPEN | [M6.4][P1][Risk] Multi-model decision aggregation có kiểm chứng | 0/4 → 2/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `src/network_anomaly/risk/aggregation.py`, `docs/RISK_METHODOLOGY.md`, `tests/unit/test_risk_engine.py` | 4 policy đã cài đặt tất định nhưng chưa có báo cáo thực nghiệm đối chiếu cả 4 policy trên cùng tập `AIT-Val`/`AIT-Test` (`AC1, AC2`). |
| #110 | M6.4 | OPEN | [M6.4][P0][Trace] Cross-source event correlation, entity relationship graph và alert dedup | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/trace/graph.py`, `src/network_anomaly/streaming/alert_manager.py`, `tests/unit/test_trace_engine.py`, `tests/contract/test_trace_crypto_api.py` | Đầy đủ observed vs inferred edges, alert dedup giữ event ID gốc, test chuỗi 3 nguồn & cách ly dataset. |
| #111 | M6.4 | OPEN | [M6.4][P0][Trace] Trace Engine v2: truy vết sự kiện và quan hệ có bằng chứng | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/trace/engine.py`, `docs/TRACE_ENGINE.md`, `tests/unit/test_trace_engine.py`, `tests/contract/test_trace_crypto_api.py` | Truy vấn tất định, giới hạn depth/nodes kèm thông báo cắt và chỉ nối quan hệ có bằng chứng. |
| #112 | M6.4 | OPEN | [M6.4][P0][Trace] Tái dựng tấn công nhiều giai đoạn và Attack Timeline | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/trace/timeline.py`, `docs/ATTACK_TIMELINE.md`, `tests/unit/test_trace_engine.py`, `tests/integration/test_full_system_e2e.py` | Tái dựng đa giai đoạn kèm lý do, mức tin cậy, lọc nhiễu và xuất JSON có provenance. |
| #113 | M6.4 | OPEN | [M6.4][P0][Trace] Evidence provenance và investigation report | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/trace/investigation.py`, `docs/INVESTIGATION_REPORT.md`, `tests/unit/test_trace_engine.py`, `tests/contract/test_trace_crypto_api.py` | Report có hash/metadata, tham chiếu evidence và tái lập tất định. |
| #114 | M6.4 | OPEN | [M6.4][P0][Evaluation] Đánh giá correlation và traceability với ground truth | 0/4 → 2/4 | `IMPLEMENTED (SYNTHETIC DEFECT)` | `PARTIAL` | `scripts/evaluate_traceability.py`, `reports/experiments/trace/traceability_evaluation.json`, `docs/experiments/TRACEABILITY_EVALUATION.md` | Chỉ chạy trên **8 synthetic events**, đối chiếu với **baseline hardcoded** (`unstructured_log_grep` `0.25`/`0.30`), sai số học `+65.0%` cho `100% - 25%` (`AC2`), và phân tích lỗi trên ví dụ thực tế còn mỏng (`AC3`). |
| #115 | M6.4 | OPEN | [M6.4][P0][API] Trace và evidence REST API cho timeline/investigation trên desktop | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS_ROUTE_RENAME` | `src/network_anomaly/api/main.py` (`/api/v1/trace/{timeline,graph,investigation/generate}`), `tests/contract/test_trace_crypto_api.py`, `scripts/export_openapi_spec.py --check` | Lưu ý lệch tên đường dẫn so với đề xuất ban đầu ở issue (`/trace/events`, `/trace/timeline/{incident_id}`, `/investigation/report`), nhưng schema, pagination, `X-Sentinel-Session-Token` và tương thích ngược đều đạt & OpenAPI khớp. |
| #116 | M6.5 | OPEN | [M6.5][P0][Security] Cryptographic architecture: key hierarchy, nonce policy và key separation | 0/4 → 4/4 | `IMPLEMENTED` | `PASS` | `docs/adr/ADR-cryptographic-architecture.md` | Kiến trúc phân cấp khóa, chính sách nonce, version+`key_id` và quy tắc không hardcode secret đều đầy đủ (cần bổ sung `cryptography` vào `THIRD_PARTY_NOTICES.md`). |
| #117 | M6.5 | OPEN | [M6.5][P0][Crypto] Module AES-256-GCM authenticated encryption và secure storage | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/crypto/aead.py`, `tests/unit/test_crypto_aead.py`, `tests/unit/test_crypto_integrity.py` | Round-trip binary/JSON, tamper bit-flip ciphertext/tag/AAD, counter/random nonce và fail-closed đều đạt test. |
| #118 | M6.5 | OPEN | [M6.5][P0][Crypto] Mã hóa Behavioral Vector và dữ liệu evidence | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/crypto/encrypted_storage.py`, `tests/unit/test_crypto_integrity.py`, `tests/contract/test_trace_crypto_api.py` | Vector & evidence lưu ciphertext (`plaintext` NULL), giải mã tính cosine similarity khớp bản gốc, fail-closed khi thiếu khóa. |
| #119 | M6.5 | OPEN | [M6.5][P0][Crypto] Key generation, secure key storage, lifecycle và versioning | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `src/network_anomaly/crypto/key_manager.py`, `scripts/migrate_keystore.py`, `tests/unit/test_key_manager_hardening.py` | Chưa thấy tài liệu **runbook xử lý khi keystore không khả dụng** tách bạch (`AC4`). |
| #120 | M6.5 | OPEN | [M6.5][P0][Crypto] Fixed key rotation 30 phút | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `src/network_anomaly/crypto/rotation.py`, `tests/unit/test_crypto_integrity.py` | `check_fixed_schedule` gọi trực tiếp `datetime.now(timezone.utc)` (thiếu clock injectable để kiểm thử chu kỳ 30 phút tất định theo clock — `AC1`). |
| #121 | M6.5 | OPEN | [M6.5][P0][Crypto] Risk-based Adaptive Key Rotation | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/crypto/rotation.py`, `tests/unit/test_crypto_integrity.py`, `src/network_anomaly/streaming/alert_manager.py` | Kích hoạt theo ngưỡng risk (`>=85.0`), ghi audit chứa `risk_score` và trigger, cooldown chống lặp vô hạn, dữ liệu cũ vẫn giải mã được. |
| #122 | M6.5 | OPEN | [M6.5][P1][Crypto] Rotation cooldown, rate limiting và failure handling | 0/4 → 3/4 | `IMPLEMENTED (IN-MEMORY STATE)` | `PARTIAL` | `src/network_anomaly/crypto/rotation.py`, `tests/unit/test_crypto_integrity.py` | `KeyRotationPolicy._history` và `_last_rotation_time` chỉ lưu **in-memory**, không khôi phục từ SQLite khi restart tiến trình (`AC3` fail). |
| #123 | M6.5 | OPEN | [M6.5][P0][Crypto] Historical data decryption và key recovery | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `src/network_anomaly/crypto/{encrypted_storage.py,key_manager.py}`, `tests/unit/test_crypto_integrity.py`, `test_key_manager_hardening.py` | Chưa có bằng chứng **runbook backup/restore keystore được kiểm thử** end-to-end (`AC3`). |
| #124 | M6.5 | OPEN | [M6.5][P0][Testing] Cryptographic integrity testing: tamper, nonce reuse, key isolation | 0/4 → 4/4 | `TESTED` | `PASS` | `tests/unit/test_crypto_aead.py`, `test_crypto_integrity.py`, `test_key_manager_hardening.py`, `tests/contract/test_trace_crypto_api.py` | Các test crypto tamper, nonce, key isolation chạy nhanh và pass trong mọi job CI Python. |
| #125 | M6.5 | OPEN | [M6.5][P0][Experiment] Thực nghiệm Fixed vs Adaptive Key Rotation (RQ5) | 0/4 → 4/4 | `EXPERIMENTALLY VALIDATED (SIMULATION)` | `PASS` | `scripts/run_rq5_rotation_experiment.py`, `reports/experiments/crypto/rq5_rotation_experiment.json`, `rq5_rotation_report.md`, `tests/unit/test_rq_and_benchmark_contracts.py` | Chạy mô phỏng cùng kịch bản 120 events/step=30s/seed=42, báo cáo latency phản ứng, số khóa và exposure window. |
| #126 | M6.5 | OPEN | [M6.5][P0][Benchmark] Benchmark CPU, RAM, latency và throughput của mã hóa (RQ6) | 0/4 → 4/4 | `BENCHMARKED` | `PASS` | `scripts/benchmark_crypto_overhead.py`, `reports/benchmarks/crypto_benchmark_report.{json,md}`, `tests/unit/test_rq_and_benchmark_contracts.py` | Đo đủ 3 kích thước (256B/1KB/4KB) × 3 cấu hình (`plaintext_json_roundtrip`, `encryption`, `decryption`), có p50/p95/p99, throughput, peak RAM, env metadata. |
| #127 | M6.6 | OPEN | [M6.6][P0][Telemetry] Live telemetry architecture và phạm vi lab được cấp phép | 0/4 → 4/4 | `IMPLEMENTED` | `PASS` | `docs/telemetry/LIVE_TELEMETRY_ARCHITECTURE.md` | Có sơ đồ process boundary, danh mục nguồn/giao thức, lưu/xóa và cổng nghiệm thu tối thiểu. |
| #128 | M6.6 | OPEN | [M6.6][P0][Telemetry] NetFlow/IPFIX collector (Rust) với template decoding | 0/4 → 0/4 | `IMPLEMENTED (PYTHON, NOT RUST)` | `SCOPE_CONFLICT_KEEP` | `src/network_anomaly/telemetry/collector.py`, `tests/unit/test_telemetry_collector.py`, `docs/ARCHITECTURE_V2.md:14` | Tiêu đề yêu cầu **Rust collector**, nhưng thực tế triển khai bằng **Python** (`collector.py`) và Rust crate bị hoãn (`ARCHITECTURE_V2.md:14` mâu thuẫn với dòng 49, 215). Chức năng giải mã NetFlow v9/IPFIX binary & template cache trong Python đã có test. |
| #129 | M6.6 | OPEN | [M6.6][P1][Telemetry] Local PCAP ingestion và PCAP-to-flow | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/telemetry/pcap_reader.py`, `tests/integration/test_live_telemetry_flow.py` | Tạo flow từ PCAP mẫu, có giới hạn kích thước/số lượng, cảnh báo không đồng nhất với NetFlow, có test PCAP hỏng. |
| #130 | M6.6 | OPEN | [M6.6][P1][Telemetry] Tích hợp live Zeek/Suricata (log tail) | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/telemetry/log_tailer.py`, `tests/integration/test_live_telemetry_flow.py` | Checkpoint offset chống đọc trùng, xử lý log rotate, chịu lỗi dòng hỏng, đo ingest latency. |
| #131 | M6.6 | OPEN | [M6.6][P0][Streaming] Streaming event pipeline với buffering, batching và backpressure | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/streaming/pipeline.py`, `tests/unit/test_streaming_pipeline.py`, `reports/benchmarks/system_performance_benchmark.json` | Ring buffer giới hạn, chính sách drop xác định khi quá tải, có benchmark throughput/latency và tắt tiến trình sạch. |
| #132 | M6.6 | OPEN | [M6.6][P0][Streaming] Real-time feature extraction và missing-feature rejection | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/streaming/feature_extractor.py`, `tests/unit/test_feature_extractor.py` | Chặn impute ngầm, route sang Risk/Trace kèm lý do, thống kê feature coverage, trích xuất tất định. |
| #133 | M6.6 | OPEN | [M6.6][P0][Streaming] Real-time AI inference cho 4 model | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/streaming/realtime_inference.py`, `tests/unit/test_realtime_inference.py`, `reports/acceptance/synthetic_udp_loopback_report.json` | Khớp inference offline trên cùng vector, gắn cờ OOD, báo `BLOCKED / NOT READY` khi thiếu artifact, có latency từng model (lưu ý `ood_gate=NOT_FITTED` trong báo cáo acceptance). |
| #134 | M6.6 | OPEN | [M6.6][P0][Streaming] Real-time Risk Engine và live alert management | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/streaming/alert_manager.py` (bảng SQLite `live_alerts`), `tests/integration/{test_live_service,test_live_behavioral_api}.py` | Alert tạo theo ngưỡng `>=70.0`, dedup trong cửa sổ, có `AlertStatus`, đo `detection_latency_ms`, lưu bền SQLite. |
| #135 | M6.6 | OPEN | [M6.6][P1][Integration] Tích hợp Behavioral Engine và Trace Engine vào luồng live | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `src/network_anomaly/streaming/live_orchestrator.py`, `tests/integration/test_live_behavioral_api.py`, `reports/benchmarks/system_performance_benchmark.json` | Chưa xác minh được bằng chứng **kiểm thử rò rỉ bộ nhớ chạy dài 10.000 sự kiện** (`AC4`). |
| #136 | M6.6 | OPEN | [M6.6][P0][Modes] Offline/Replay/Live monitoring modes và replay kịch bản nghiên cứu | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `src/network_anomaly/telemetry/modes.py`, `scripts/benchmark_full_system.py`, `tests/integration/test_full_system_e2e.py` | Offline/Replay/Live dùng chung `CanonicalSecurityEvent v2`, replay khớp offline, ghi rõ mode & nguồn. |
| #137 | M6.6 | OPEN | [M6.6][P0][Lab] Tích hợp mạng lab được cấp phép và nghiệm thu end-to-end | 0/5 → 3/5 | `IMPLEMENTED (SYNTHETIC LOOPBACK ONLY)` | `BLOCKED_PHYSICAL_LAB` | `scripts/run_live_lab_acceptance.py`, `docs/telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md`, `reports/acceptance/synthetic_udp_loopback_report.json` | Mạng **router/switch lab vật lý bị BLOCKED** (`real_device_tested=false`); `synthetic_udp_loopback_report.json` ghi `alerts: NOT_TRIGGERED` (`0 alerts`), `ood_gate=NOT_FITTED`, và thiếu kiểm chứng alert hiển thị trực tiếp trên GUI (`AC1, AC2` chưa đạt). |
| #138 | M6.7 | OPEN | [M6.7][P0][Integration] Full system integration và end-to-end integration tests | 0/4 → 3/4 | `IMPLEMENTED / TESTED (CI REGRESSED)` | `PARTIAL_CI_FAIL` | `tests/integration/test_full_system_e2e.py`, CI `44171616420` | `AC4` (**Toàn bộ suite hiện có vẫn PASS**) **FAIL** trên CI `44171616420` (`13 failed` Python tests + `67 lỗi Ruff`). |
| #139 | M6.7 | OPEN | [M6.7][P0][Desktop] Hoàn thiện Rust/Tauri 2 + Svelte 5 UI cho v2.0 | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `desktop/src/App.svelte`, `desktop/src-tauri/`, CI `44171616420` (`desktop-frontend` 5 files / 33 tests PASS, `svelte-check` 0 errors; `desktop-tauri-windows` clippy PASS, `cargo test` 9/9 PASS, Windows exe build PASS) | Cả 2 job CI desktop đều PASS ở HEAD `79ebb67`; Rust không chứa logic ML; chuyển chế độ không restart app. |
| #140 | M6.7 | OPEN | [M6.7][P0][Desktop] Live monitoring dashboard | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `desktop/src/lib/components/LiveMonitoringPanel.svelte`, `desktop/src/lib/components/V2Panels.test.ts`, CI `desktop-frontend` PASS | Chưa kiểm chứng tải lớn chống treo UI (`AC3`) và UI chưa hiển thị counter `events_dropped`/`dropped_packets`. |
| #141 | M6.7 | OPEN | [M6.7][P0][Desktop] Behavioral Analysis dashboard | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `desktop/src/lib/components/BehavioralAnalysisPanel.svelte`, `desktop/src/lib/components/V2Panels.test.ts`, CI `desktop-frontend` PASS | Hiển thị vector phiên và so sánh similarity, nhưng phần **entity baseline profile** (`#103`) phía backend chưa tồn tại (`AC1` mới đạt một nửa). |
| #142 | M6.7 | OPEN | [M6.7][P1][Desktop] Attack Timeline và Investigation dashboard | 0/4 → 3/4 | `IMPLEMENTED / TESTED` | `PARTIAL` | `desktop/src/lib/components/AttackTimelinePanel.svelte`, `desktop/src/lib/components/V2Panels.test.ts`, CI `desktop-frontend` PASS | Kiểm thử component PASS, xuất report có hash và phân biệt observed/inferred; chưa xác minh end-to-end timeline nhiều giai đoạn trên dữ liệu thật trong WebView2 GUI (`AC1`). |
| #143 | M6.7 | OPEN | [M6.7][P1][Desktop] Cryptography và Key Rotation dashboard | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `desktop/src/lib/components/CryptographyDashboardPanel.svelte`, `V2Panels.test.ts`, `/api/v1/crypto/status`, `/api/v1/rotation*`, CI `desktop-frontend` PASS | Hiển thị trạng thái, lịch sử rotation, số liệu RQ5 và không rò key/ciphertext. |
| #144 | M6.7 | OPEN | [M6.7][P1][Desktop] Model comparison dashboard | 0/4 → 4/4 | `IMPLEMENTED / TESTED` | `PASS` | `desktop/src/lib/components/ModelComparisonPanel.svelte`, `V2Panels.test.ts`, `reports/experiments/ml/model_comparison_report.json`, CI `desktop-frontend` PASS | Khớp JSON report, phân biệt bộ dữ liệu & mức tin cậy, không biến ô thiếu thành 0. |
| #145 | M6.7 | OPEN | [M6.7][P0][Validation] Independent research validation cho 6 Research Questions | 0/4 → 3/4 | `IMPLEMENTED (PARTIAL)` | `PARTIAL` | `docs/audits/RESEARCH_QUESTIONS_VALIDATION.md`, `reports/experiments/*`, `reports/benchmarks/crypto_benchmark_report.json` | Chưa có biên bản **chạy lại độc lập lần hai cho từng thực nghiệm** (`AC2`); RQ2 `h2_full_confirmed=false`, RQ3 AIT `BLOCKED`, RQ4 `unsupervised_ge_0_75_both=false`. |
| #146 | M6.7 | OPEN | [M6.7][P0][Security] Security audit v2.0 | 0/4 → 3/4 | `IMPLEMENTED (PARTIAL)` | `PARTIAL` | `docs/audits/SECURITY_AUDIT_V2.md` | `THREAT_MODEL_V2.md` (`#81`) bị gitignore & lỗi dẫn test; các finding P0/P1 thực tế (`--verify-only` mutation `#83`, thiếu redaction URL `#89`, thiếu persist rate-limit `#122`, CI hash mismatch) chưa có issue remediation đóng kín (`AC2`). |
| #147 | M6.7 | OPEN | [M6.7][P1][Performance] Performance benchmark toàn hệ thống v2.0 | 0/4 → 3/4 | `BENCHMARKED` | `PARTIAL` | `scripts/benchmark_full_system.py`, `reports/benchmarks/system_performance_benchmark.json`, `docs/benchmarks/SYSTEM_PERFORMANCE.md` | Có số liệu 3 chế độ + từng tầng + cấu hình máy; mới đo 1 lần (`100` micro-iters/run), chưa ghi sai số lặp lại giữa nhiều run độc lập (`AC4`). |
| #148 | M6.7 | OPEN | [M6.7][P0][Release] Windows installer v2.0 và clean installation test | 0/4 → 0/4 | `IMPLEMENTED (BLOCKED VM/SIGNOFF)` | `BLOCKED` | `scripts/build_installer_v2.py`, `tests/unit/test_installer_v2_script.py`, `reports/governance/DISTRIBUTION_AUTHORIZATION.json` (`approved: false`), CI `desktop-tauri-windows` build exe | `Clean Windows 10/11 x64 VM` offline Standard User install/uninstall ngoài `%LOCALAPPDATA%` và chứng thực `release_e2e_verification.json` đều `NOT VERIFIED`; `DISTRIBUTION_AUTHORIZATION.json` còn `HOLD_FOR_MAINTAINER_SIGNOFF`. |
| #149 | M6.7 | OPEN | [M6.7][P1][Release] Upgrade path v1.0.0 → v2.0 và migration verification | 0/4 → 3/4 | `IMPLEMENTED / TESTED (DB ONLY)` | `PARTIAL` | `scripts/migrate_v1_to_v2.py`, `tests/integration/test_migration_v1_to_v2.py`, `docs/MIGRATION_V1_TO_V2.md` | Backup & dry-run đã test trên DB SQLite, nhưng chưa có cơ chế **tự động rollback khi lỗi giữa chừng** hay kiểm thử upgrade qua NSIS installer v1 -> v2 (`AC2`). |
| #150 | M6.7 | OPEN | [M6.7][P0][Demo] Reproducible demonstration scenarios cho Offline, Replay và Live | 0/4 → 2/4 | `IMPLEMENTED (PARTIAL)` | `PARTIAL` | `docs/USER_GUIDE_V2.md`, `docs/DEPLOYMENT_GUIDE_V2.md`, `docs/telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md`, `scripts/prepare_demo_dataset.py` | `USER_GUIDE_V2.md:12-13` dẫn **3 endpoint không tồn tại** (`/api/v1/telemetry/status`, `/api/v1/telemetry/events`, `/api/v1/behavioral/sessions`); chưa có kịch bản chạy thử từng bước có thời lượng/kết quả kỳ vọng cho cả 3 chế độ từ trạng thái sạch (`AC1, AC2`). |
| #151 | M6.7 | OPEN | [M6.7][P1][Docs] Tài liệu kỹ thuật v2.0: architecture, dataset, AI model | 0/4 → 1/4 | `IMPLEMENTED (PARTIAL)` | `PARTIAL` | `docs/ARCHITECTURE.md`, `docs/ARCHITECTURE_V2.md`, `docs/DATASET.md`, `docs/EVALUATION.md`, `docs/DEVELOPMENT_PLAN.md`, `docs/academic-defense/EVIDENCE_INDEX.md` | Active docs đã chuyển v2 nhưng còn mâu thuẫn `ARCHITECTURE_V2.md` (`#128` Python vs Rust), `USER_GUIDE_V2.md` sai 3 endpoint, `/docs/audits/` bị gitignore (`V2_GAP_ANALYSIS`, `THREAT_MODEL_V2`), và `#18/#19` chưa đóng/tách khỏi phạm vi v2 (`AC1, AC3, AC4`). |
| #152 | M6.7 | OPEN | [M6.7][P1][Docs] User guide, deployment guide và website site-source v2.0 | 0/4 → 1/4 | `IMPLEMENTED (BACKEND ONLY)` | `PARTIAL_SITE_V1` | `docs/USER_GUIDE_V2.md`, `docs/DEPLOYMENT_GUIDE_V2.md`, remote `site-source` (`a01bd38ad`, `2026-11-16`) | Nhánh **`site-source` vẫn là bản v1.0.0** (chưa cập nhật 3 chế độ & tài liệu v2); `USER_GUIDE_V2.md` có 3 endpoint sai; hướng dẫn máy sạch chưa kiểm chứng (`AC1, AC2, AC3`). |
| #153 | M6.7 | OPEN | [M6.7][P0][Docs] Research report, methodology, slide bảo vệ và Q&A v2.0 | 0/4 → 0/4 | `PLANNED (OUTLINE ONLY)` | `NOT_IMPLEMENTED` | `docs/REPORT_OUTLINE.md`, `docs/PRESENTATION_OUTLINE.md`, `docs/academic-defense/EVIDENCE_INDEX.md` | Mới có dàn ý outline, chưa có báo cáo v2 hoàn chỉnh, slide bảo vệ hay bộ Q&A về unknown attack & crypto. |
| #154 | M6.7 | OPEN | [M6.7][P0][Release] Release readiness audit và chuẩn bị NetFlow Sentinel v2.0.0 | 0/4 → 0/4 | `PLANNED / BLOCKED` | `FAIL_ON_CI_AND_BLOCKED` | `reports/audits/{V2_CI_AUDIT,V2_MODEL_AUDIT,V2_ISSUE_AC_AUDIT}.md`, `PR #156`, CI `44171616420`, `DISTRIBUTION_AUTHORIZATION.json` | CI `44171616420` FAIL (`67 lỗi Ruff`, `13 test fail`); `PR #156` còn `draft/blocked`; cổng `#148/#73` Clean VM & Signoff bị `BLOCKED`; `#152/#153` chưa hoàn tất. |
| #155 | M6.1 | OPEN | [M6.1][P0][Governance] Bản đồ phụ thuộc, critical path và kế hoạch triển khai song song v2.0 | 0/5 → 5/5 | `IMPLEMENTED / TESTED` | `PASS` | `docs/V2_DEPENDENCY_GRAPH.md`, `scripts/parse_dag.py` (`80 nodes, 0 cycles, 23-step critical path` PASS) | Chỉ còn chờ merge vào `main` qua PR `#156` theo DoD. |

---

## 8. AC Remediation Checklist Chi tiết (Tất cả 88 Issues)

### 8.1. Nhóm `TICK_FULL` — Sẵn sàng tick đủ toàn bộ AC (26 issues: #100, #104, #110, #111, #112, #113, #115, #116, #117, #118, #121, #124, #125, #126, #127, #129, #130, #131, #132, #133, #134, #136, #139, #143, #144, #155)
*Ghi chú:* Các checkbox dưới đây đều có triển khai và bằng chứng xác minh trên nhánh `feat/v2-integration`; vẫn **giữ issue `OPEN`** cho tới khi PR `#156` đạt CI xanh và merge vào `main` (DoD).

#### Issue #100 (`M6.3`, `OPEN`, 0/4 → 4/4) — [M6.3][P0][ML] Threshold calibration trên validation, chống tuning trên test
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4); issue giữ `OPEN` đến khi PR `#156` merge `main`.
  - `AC1` (`[ ] → [x]`, `TICK`): Mọi model có threshold kèm nguồn calibration trong manifest.
  - `AC2` (`[ ] → [x]`, `TICK`): Có test/guard chứng minh không dùng test để chọn.
  - `AC3` (`[ ] → [x]`, `TICK`): Báo cáo metric ở threshold đã chốt.
  - `AC4` (`[ ] → [x]`, `TICK`): So sánh model công bằng trên cùng policy.

#### Issue #104 (`M6.3`, `OPEN`, 0/4 → 4/4) — [M6.3][P0][Behavioral] IP-independent session correlation và Experiment 5 (RQ3)
- **Quyết định:** `TICK_FULL` | `PASS_WITH_BLOCKED_NOTE` — Tick toàn bộ `AC1–AC4` (4/4) kèm ghi chú phần empirical AIT đang `BLOCKED` ở `#85`.
  - `AC1` (`[ ] → [x]`, `TICK`): Có metric định lượng cho ít nhất 2 chiến lược.
  - `AC2` (`[ ] → [x]`, `TICK`): Kết luận nêu rõ điều kiện B tốt hơn/kém hơn A.
  - `AC3` (`[ ] → [x]`, `TICK`): Không dùng nhãn trong quá trình tính similarity.
  - `AC4` (`[ ] → [x]`, `TICK`): Kết quả tái lập từ script đã commit.

#### Issue #110 (`M6.4`, `OPEN`, 0/4 → 4/4) — [M6.4][P0][Trace] Cross-source event correlation, entity relationship graph và alert dedup
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4); DoD chờ PR `#156` merge.
  - `AC1` (`[ ] → [x]`, `TICK`): Cạnh quan sát và cạnh suy luận được phân biệt trong dữ liệu và UI/API.
  - `AC2` (`[ ] → [x]`, `TICK`): Dedup giảm số incident trùng mà không mất sự kiện gốc.
  - `AC3` (`[ ] → [x]`, `TICK`): Có test cho chuỗi 3 nguồn liên quan.
  - `AC4` (`[ ] → [x]`, `TICK`): Không nối sự kiện giữa hai dataset độc lập.

#### Issue #111 (`M6.4`, `OPEN`, 0/4 → 4/4) — [M6.4][P0][Trace] Trace Engine v2: truy vết sự kiện và quan hệ có bằng chứng
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Truy vấn trả về chuỗi sự kiện có lý do liên kết.
  - `AC2` (`[ ] → [x]`, `TICK`): Cùng input cho cùng output (tất định).
  - `AC3` (`[ ] → [x]`, `TICK`): Có giới hạn độ sâu/số nút và báo rõ khi bị cắt.
  - `AC4` (`[ ] → [x]`, `TICK`): Không khẳng định quan hệ không có bằng chứng.

#### Issue #112 (`M6.4`, `OPEN`, 0/4 → 4/4) — [M6.4][P0][Trace] Tái dựng tấn công nhiều giai đoạn và Attack Timeline
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Tái dựng được ít nhất một kịch bản nhiều giai đoạn có ground truth.
  - `AC2` (`[ ] → [x]`, `TICK`): Mỗi stage có lý do và mức tin cậy.
  - `AC3` (`[ ] → [x]`, `TICK`): Sự kiện không liên quan không bị gộp vào chuỗi.
  - `AC4` (`[ ] → [x]`, `TICK`): Timeline xuất được ra JSON có provenance.

#### Issue #113 (`M6.4`, `OPEN`, 0/4 → 4/4) — [M6.4][P0][Trace] Evidence provenance và investigation report
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Mỗi kết luận trong report có tham chiếu evidence.
  - `AC2` (`[ ] → [x]`, `TICK`): Report có hash và metadata phiên bản artifact.
  - `AC3` (`[ ] → [x]`, `TICK`): Không có khẳng định vượt quá dữ liệu.
  - `AC4` (`[ ] → [x]`, `TICK`): Report tái lập được từ cùng input.

#### Issue #115 (`M6.4`, `OPEN`, 0/4 → 4/4) — [M6.4][P0][API] Trace và evidence REST API cho timeline/investigation trên desktop
- **Quyết định:** `TICK_FULL` | `PASS_ROUTE_RENAME` — Tick toàn bộ `AC1–AC4` (4/4) kèm ghi chú chuẩn hóa tên endpoint.
  - `AC1` (`[ ] → [x]`, `TICK`): Endpoint trả dữ liệu trace/report đúng schema.
  - `AC2` (`[ ] → [x]`, `TICK`): Có phân trang và giới hạn kích thước response.
  - `AC3` (`[ ] → [x]`, `TICK`): Vẫn bắt buộc `X-Sentinel-Session-Token`.
  - `AC4` (`[ ] → [x]`, `TICK`): Không phá vỡ 18 endpoint hiện có.

#### Issue #116 (`M6.5`, `OPEN`, 0/4 → 4/4) — [M6.5][P0][Security] Cryptographic architecture: key hierarchy, nonce policy và key separation
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Có sơ đồ phân cấp khóa và nơi lưu từng loại khóa.
  - `AC2` (`[ ] → [x]`, `TICK`): Chính sách nonce ghi rõ chống tái sử dụng.
  - `AC3` (`[ ] → [x]`, `TICK`): Có định dạng ciphertext có version và `key_id`.
  - `AC4` (`[ ] → [x]`, `TICK`): Không có khóa bí mật trong source, config commit hay log.

#### Issue #117 (`M6.5`, `OPEN`, 0/4 → 4/4) — [M6.5][P0][Crypto] Module AES-256-GCM authenticated encryption và secure storage
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4) (nhắc bổ sung notice cho package `cryptography`).
  - `AC1` (`[ ] → [x]`, `TICK`): Round-trip đúng cho dữ liệu nhị phân và JSON.
  - `AC2` (`[ ] → [x]`, `TICK`): Sửa 1 bit ciphertext/tag/AAD → lỗi rõ ràng, không trả plaintext.
  - `AC3` (`[ ] → [x]`, `TICK`): Nonce không lặp với cùng khóa (có test thống kê/counter).
  - `AC4` (`[ ] → [x]`, `TICK`): Không có API nào trả plaintext khi thiếu khóa.

#### Issue #118 (`M6.5`, `OPEN`, 0/4 → 4/4) — [M6.5][P0][Crypto] Mã hóa Behavioral Vector và dữ liệu evidence
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Vector và evidence lưu ở dạng ciphertext.
  - `AC2` (`[ ] → [x]`, `TICK`): Similarity vẫn tính được sau khi giải mã, kết quả khớp bản plaintext.
  - `AC3` (`[ ] → [x]`, `TICK`): Không có plaintext trong log hay file tạm.
  - `AC4` (`[ ] → [x]`, `TICK`): Thiếu khóa → báo lỗi rõ, không trả dữ liệu rỗng.

#### Issue #121 (`M6.5`, `OPEN`, 0/4 → 4/4) — [M6.5][P0][Crypto] Risk-based Adaptive Key Rotation
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Rotation theo risk xảy ra trong ngưỡng thời gian đã định.
  - `AC2` (`[ ] → [x]`, `TICK`): Có audit nêu rõ risk score và sự kiện kích hoạt.
  - `AC3` (`[ ] → [x]`, `TICK`): Không tạo vòng lặp rotate liên tục.
  - `AC4` (`[ ] → [x]`, `TICK`): Dữ liệu cũ vẫn giải mã được.

#### Issue #124 (`M6.5`, `OPEN`, 0/4 → 4/4) — [M6.5][P0][Testing] Cryptographic integrity testing: tamper, nonce reuse, key isolation
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Mọi trường hợp tamper đều bị từ chối.
  - `AC2` (`[ ] → [x]`, `TICK`): Có test phát hiện nonce reuse.
  - `AC3` (`[ ] → [x]`, `TICK`): Có test key isolation giữa các miền.
  - `AC4` (`[ ] → [x]`, `TICK`): Suite chạy trong CI dưới ngưỡng thời gian đã đặt.

#### Issue #125 (`M6.5`, `OPEN`, 0/4 → 4/4) — [M6.5][P0][Experiment] Thực nghiệm Fixed vs Adaptive Key Rotation (RQ5)
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4) với nhãn `SIMULATION`.
  - `AC1` (`[ ] → [x]`, `TICK`): Cùng kịch bản cho cả hai chiến lược, cùng seed.
  - `AC2` (`[ ] → [x]`, `TICK`): Có mét thời gian phản ứng định lượng (trung vị + phân vị).
  - `AC3` (`[ ] → [x]`, `TICK`): Có báo cáo số khóa và chi phí phụ.
  - `AC4` (`[ ] → [x]`, `TICK`): Kết quả tái lập từ harness.

#### Issue #126 (`M6.5`, `OPEN`, 0/4 → 4/4) — [M6.5][P0][Benchmark] Benchmark CPU, RAM, latency và throughput của mã hóa (RQ6)
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Có số liệu cho cả 3 cấu hình và 3 kích thước.
  - `AC2` (`[ ] → [x]`, `TICK`): Báo cáo p50/p95, throughput, CPU, RAM.
  - `AC3` (`[ ] → [x]`, `TICK`): Ghi rõ môi trường đo để tái lập.
  - `AC4` (`[ ] → [x]`, `TICK`): Không tuyên bố overhead thấp hơn thực đo.

#### Issue #127 (`M6.6`, `OPEN`, 0/4 → 4/4) — [M6.6][P0][Telemetry] Live telemetry architecture và phạm vi lab được cấp phép
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Có sơ đồ luồng live với ranh giới tiến trình rõ ràng.
  - `AC2` (`[ ] → [x]`, `TICK`): Có danh sách nguồn/thiết bị và giao thức được phép.
  - `AC3` (`[ ] → [x]`, `TICK`): Có chính sách lưu/xóa dữ liệu.
  - `AC4` (`[ ] → [x]`, `TICK`): Nêu rõ điều kiện lab tối thiểu để acceptance gate M6.6 đạt.

#### Issue #129 (`M6.6`, `OPEN`, 0/4 → 4/4) — [M6.6][P1][Telemetry] Local PCAP ingestion và PCAP-to-flow
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Tạo flow hợp lệ từ PCAP mẫu, tái lập được.
  - `AC2` (`[ ] → [x]`, `TICK`): Có giới hạn kích thước/thời gian, báo rõ khi cắt.
  - `AC3` (`[ ] → [x]`, `TICK`): Không tuyên bố flow từ PCAP tương đương NetFlow về mọi đặc trưng.
  - `AC4` (`[ ] → [x]`, `TICK`): Có test cho PCAP hỏng/không hợp lệ.

#### Issue #130 (`M6.6`, `OPEN`, 0/4 → 4/4) — [M6.6][P1][Telemetry] Tích hợp live Zeek/Suricata (log tail)
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Không đọc trùng dòng sau restart.
  - `AC2` (`[ ] → [x]`, `TICK`): Xử lý được log rotate mà không mất dữ liệu.
  - `AC3` (`[ ] → [x]`, `TICK`): Dòng lỗi không làm dừng pipeline.
  - `AC4` (`[ ] → [x]`, `TICK`): Có metric độ trễ ingest.

#### Issue #131 (`M6.6`, `OPEN`, 0/4 → 4/4) — [M6.6][P0][Streaming] Streaming event pipeline với buffering, batching và backpressure
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Không mất sự kiện trong điều kiện tải bình thường.
  - `AC2` (`[ ] → [x]`, `TICK`): Quá tải có hành vi xác định và được ghi log/metric.
  - `AC3` (`[ ] → [x]`, `TICK`): Có báo cáo throughput và latency trên tải tổng hợp.
  - `AC4` (`[ ] → [x]`, `TICK`): Tắt pipeline không treo tiến trình.

#### Issue #132 (`M6.6`, `OPEN`, 0/4 → 4/4) — [M6.6][P0][Streaming] Real-time feature extraction và missing-feature rejection
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Không impute đặc trưng thiếu để inference chạy.
  - `AC2` (`[ ] → [x]`, `TICK`): Sự kiện không đủ điều kiện bị route sang Risk/Trace với lý do.
  - `AC3` (`[ ] → [x]`, `TICK`): Có số liệu độ phủ đặc trưng theo nguồn.
  - `AC4` (`[ ] → [x]`, `TICK`): Kết quả trích xuất tất định với cùng cửa sổ.

#### Issue #133 (`M6.6`, `OPEN`, 0/4 → 4/4) — [M6.6][P0][Streaming] Real-time AI inference cho 4 model
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Kết quả realtime khớp với xử lý offline trên cùng sự kiện.
  - `AC2` (`[ ] → [x]`, `TICK`): OOD vẫn được đánh dấu đúng.
  - `AC3` (`[ ] → [x]`, `TICK`): Thiếu artifact → `BLOCKED / NOT READY`, không dùng model giả.
  - `AC4` (`[ ] → [x]`, `TICK`): Có số liệu latency cho từng model.

#### Issue #134 (`M6.6`, `OPEN`, 0/4 → 4/4) — [M6.6][P0][Streaming] Real-time Risk Engine và live alert management
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Alert tạo đúng ngưỡng, không trùng lặp trong cửa sổ.
  - `AC2` (`[ ] → [x]`, `TICK`): Có vòng đời trạng thái và lịch sử.
  - `AC3` (`[ ] → [x]`, `TICK`): Độ trễ từ sự kiện đến alert được đo và báo cáo.
  - `AC4` (`[ ] → [x]`, `TICK`): Không mất alert khi pipeline tắt đột ngột (ghi bền).

#### Issue #136 (`M6.6`, `OPEN`, 0/4 → 4/4) — [M6.6][P0][Modes] Offline/Replay/Live monitoring modes và replay kịch bản nghiên cứu
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Ba chế độ dùng cùng canonical event contract.
  - `AC2` (`[ ] → [x]`, `TICK`): Replay cho kết quả khớp với offline trên cùng dữ liệu.
  - `AC3` (`[ ] → [x]`, `TICK`): Metadata kết quả ghi rõ chế độ và nguồn.
  - `AC4` (`[ ] → [x]`, `TICK`): Offline demo cũ vẫn chạy.

#### Issue #139 (`M6.7`, `OPEN`, 0/4 → 4/4) — [M6.7][P0][Desktop] Hoàn thiện Rust/Tauri 2 + Svelte 5 UI cho v2.0
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4); issue giữ `OPEN` chờ PR `#156` merge `main`.
  - `AC1` (`[ ] → [x]`, `TICK`): Luồng CSV v1.0.0 vẫn hoạt động đầy đủ.
  - `AC2` (`[ ] → [x]`, `TICK`): Chuyển chế độ không cần khởi động lại app.
  - `AC3` (`[ ] → [x]`, `TICK`): `svelte-check`, Vitest, clippy, cargo test PASS.
  - `AC4` (`[ ] → [x]`, `TICK`): Không có logic inference trong Rust.

#### Issue #143 (`M6.7`, `OPEN`, 0/4 → 4/4) — [M6.7][P1][Desktop] Cryptography và Key Rotation dashboard
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Hiển thị trạng thái và lịch sử rotation.
  - `AC2` (`[ ] → [x]`, `TICK`): Không có khóa/ciphertext trong response hay log.
  - `AC3` (`[ ] → [x]`, `TICK`): Số liệu RQ5 hiển thị đúng nguồn.
  - `AC4` (`[ ] → [x]`, `TICK`): Test PASS.

#### Issue #144 (`M6.7`, `OPEN`, 0/4 → 4/4) — [M6.7][P1][Desktop] Model comparison dashboard
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC4` (4/4).
  - `AC1` (`[ ] → [x]`, `TICK`): Số liệu hiển thị khớp report JSON đã commit.
  - `AC2` (`[ ] → [x]`, `TICK`): Phân biệt rõ bộ dữ liệu và nhãn tin cậy.
  - `AC3` (`[ ] → [x]`, `TICK`): Không có ô số liệu rỗng hiển thị như 0.
  - `AC4` (`[ ] → [x]`, `TICK`): Test PASS.

#### Issue #155 (`M6.1`, `OPEN`, 0/5 → 5/5) — [M6.1][P0][Governance] Bản đồ phụ thuộc, critical path và kế hoạch triển khai song song v2.0
- **Quyết định:** `TICK_FULL` | `PASS` — Tick toàn bộ `AC1–AC5` (5/5).
  - `AC1` (`[ ] → [x]`, `TICK`): DAG không có vòng lặp.
  - `AC2` (`[ ] → [x]`, `TICK`): Mọi issue #76–#154 xuất hiện đúng một lần trong DAG.
  - `AC3` (`[ ] → [x]`, `TICK`): Critical path và nhánh song song được nêu tường minh.
  - `AC4` (`[ ] → [x]`, `TICK`): Mỗi workstream có danh sách file/thư mục sở hữu.
  - `AC5` (`[ ] → [x]`, `TICK`): Có checkpoint tích hợp với tiêu chí kiểm chứng.


### 8.2. Nhóm `TICK_PARTIAL` — Tick bổ sung các AC đã đạt, giữ `[ ]` các AC còn thiếu/blocked (33 issues: #77, #78, #79, #80, #96, #98, #99, #101, #102, #103, #105, #106, #107, #108, #109, #114, #119, #120, #122, #123, #135, #137, #138, #140, #141, #142, #145, #146, #147, #149, #150, #151, #152)

#### Issue #77 (`M6.1`, `OPEN`, 0/4 → 3/4) — [M6.1][P0][Research] Khôi phục 6 Research Questions, hypothesis và ma trận ánh xạ
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC4`; giữ `AC3` `[ ]` cho tới khi bổ sung bảng ánh xạ RQ-to-Issue.
  - `AC1` (`[ ] → [x]`, `TICK`): Đúng 6 RQ, không thêm/bớt, giữ nguyên ý nghĩa gốc.
  - `AC2` (`[ ] → [x]`, `TICK`): Mỗi RQ có hypothesis phát biểu dạng kiểm chứng được (kèm metric và ngưỡng đánh giá).
  - `AC3` (`[ ] → [ ]`, `KEEP`): Mỗi RQ ánh xạ tới ít nhất một issue triển khai và một issue đánh giá.
  - `AC4` (`[ ] → [x]`, `TICK`): Nêu rõ giới hạn: kết quả holdout không đồng nghĩa phát hiện zero-day thực tế.

#### Issue #78 (`M6.1`, `OPEN`, 0/5 → 4/5) — [M6.1][P0][Architecture] Target architecture v2.0, dependency graph và module ownership
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC3, AC4, AC5`; giữ `AC2` `[ ]` cho tới khi thống nhất module ownership Python vs Rust cho `#128`.
  - `AC1` (`[ ] → [x]`, `TICK`): Kiến trúc bao phủ đủ 7 module của đề cương gốc và 6 workstream.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Mỗi hợp đồng liên module có schema, version và chủ sở hữu.
  - `AC3` (`[ ] → [x]`, `TICK`): Dependency graph không có vòng lặp; critical path được nêu tường minh.
  - `AC4` (`[ ] → [x]`, `TICK`): Chỉ rõ phần nào chạy offline, phần nào cần lab được cấp phép.
  - `AC5` (`[ ] → [x]`, `TICK`): Không thay đổi chạy được của v1.0.0.

#### Issue #79 (`M6.1`, `OPEN`, 1/4 → 3/4) — [M6.1][P0][Contract] Canonical Security Event v2 và feature contract đa nguồn
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Giữ `AC4` `[x]`; tick thêm `AC2, AC3`; giữ `AC1` `[ ]` đến khi hoàn tất `#86/#89/#90`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Mọi adapter M6.2 ánh xạ được sang event v2 mà không mất provenance.
  - `AC2` (`[ ] → [x]`, `TICK`): Event thiếu đặc trưng ML bắt buộc bị đánh dấu rõ và không bị impute ngầm.
  - `AC3` (`[ ] → [x]`, `TICK`): Contract có version và quy tắc thay đổi (breaking vs non-breaking).
  - `AC4` (`[x] → [x]`, `KEEP`): Hard cutover: từ chối fail-closed v1 47-feature CSV/model (không fallback `NF-UNSW-NB15-v3`). *(IMPLEMENTED & TESTED trên `feat/v2-integration`)*

#### Issue #80 (`M6.1`, `OPEN`, 0/4 → 3/4) — [M6.1][P1][Migration] Versioning, backward compatibility và đường migration v1.0.0 → v2.0
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC4`; giữ `AC3` `[ ]` hoặc làm rõ phạm vi `historical/` so với active sidecar.
  - `AC1` (`[ ] → [x]`, `TICK`): Mọi artifact v1.0.0 được phân loại rõ: dùng được, cần convert, hay bị từ chối.
  - `AC2` (`[ ] → [x]`, `TICK`): Migration SQLite idempotent, có backup và dry-run.
  - `AC3` (`[ ] → [ ]`, `KEEP`): `v1.0.0` vẫn chạy nguyên trạng khi không nâng cấp.
  - `AC4` (`[ ] → [x]`, `TICK`): Có test chứng minh dữ liệu cũ đọc được sau migration.

#### Issue #96 (`M6.3`, `OPEN`, 0/4 → 3/4) — [M6.3][P1][ML] Class imbalance và rare-attack evaluation protocol
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC4`; giữ `AC3` `[ ]` đến khi fix LF `split_manifest_sha256`.
  - `AC1` (`[ ] → [x]`, `TICK`): Không resample validation/test.
  - `AC2` (`[ ] → [x]`, `TICK`): Có metric theo từng lớp hiếm, không chỉ metric tổng.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Kết quả tái lập được từ artifact.
  - `AC4` (`[ ] → [x]`, `TICK`): Kết luận RQ2 nêu rõ giới hạn do số mẫu.

#### Issue #98 (`M6.3`, `OPEN`, 0/4 → 3/4) — [M6.3][P0][ML] Unknown attack holdout experiment chuẩn hóa (RQ4)
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC2, AC3, AC4`; giữ `AC1` `[ ]` đến khi IF/AE calibration loại bỏ 58 dòng holdout trên `ait_val` và sửa comment.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Holdout không xuất hiện trong train/validation ở bất kỳ model nào.
  - `AC2` (`[ ] → [x]`, `TICK`): Có kết quả cho 4 model hoặc lý do loại trừ rõ ràng.
  - `AC3` (`[ ] → [x]`, `TICK`): Có câu chữ giới hạn: holdout ≠ zero-day thực tế.
  - `AC4` (`[ ] → [x]`, `TICK`): Kết quả tái lập từ script.

#### Issue #99 (`M6.3`, `OPEN`, 0/4 → 3/4) — [M6.3][P0][ML] OOD detection và inference rejection cho dữ liệu mới
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL_MISSING_ARTIFACT` — Tick `AC2, AC3, AC4` (hợp đồng logic & unit test); giữ `AC1` `[ ]` đến khi fit & lưu `ood_reference_gate.json`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Có ít nhất hai tín hiệu OOD (rule + thống kê) và thứ tự ưu tiên rõ ràng.
  - `AC2` (`[ ] → [x]`, `TICK`): Sự kiện abstain có lý do máy đọc được.
  - `AC3` (`[ ] → [x]`, `TICK`): Không impute để tránh abstain.
  - `AC4` (`[ ] → [x]`, `TICK`): Có test cho dữ liệu ngoài phân bố.

#### Issue #101 (`M6.3`, `OPEN`, 0/4 → 3/4) — [M6.3][P0][Behavioral] Behavioral feature extraction và sessionization/time-window aggregation
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC4`; giữ `AC3` `[ ]`.
  - `AC1` (`[ ] → [x]`, `TICK`): Sessionize được cả dữ liệu chỉ có flow và dữ liệu có log ứng dụng.
  - `AC2` (`[ ] → [x]`, `TICK`): Không có đặc trưng nào bắt buộc phải có IP làm khóa.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Đặc trưng thiếu được biểu diễn rõ, không điền ngầm.
  - `AC4` (`[ ] → [x]`, `TICK`): Có báo cáo chi phí tính toán trên subset.

#### Issue #102 (`M6.3`, `OPEN`, 0/4 → 3/4) — [M6.3][P0][Behavioral] Behavioral Vector construction và versioning
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC3, AC4`; giữ `AC2` `[ ]` đến khi bổ sung metadata/mask cho giá trị thiếu.
  - `AC1` (`[ ] → [x]`, `TICK`): Vector có schema cố định, version và metadata nguồn.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Không NaN/Inf; giá trị thiếu được đánh dấu.
  - `AC3` (`[ ] → [x]`, `TICK`): Tính lại trên cùng dữ liệu cho cùng checksum.
  - `AC4` (`[ ] → [x]`, `TICK`): Sẵn sàng cho mã hóa (serialize xác định).

#### Issue #103 (`M6.3`, `OPEN`, 0/4 → 2/4) — [M6.3][P1][Behavioral] User/device behavioral profiling và similarity metrics
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL_MISSING_PROFILER` — Tick `AC2, AC4`; giữ `AC1, AC3` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Profile chỉ tính từ dữ liệu học, không từ test.
  - `AC2` (`[ ] → [x]`, `TICK`): Có ít nhất 3 metric và tiêu chí chọn metric chính.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Có phân bố similarity để biện luận ngưỡng.
  - `AC4` (`[ ] → [x]`, `TICK`): Không phụ thuộc IP làm khóa.

#### Issue #105 (`M6.3`, `OPEN`, 0/4 → 3/4) — [M6.3][P1][ML] Model explainability và báo cáo so sánh 4 model
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC2, AC3, AC4`; giữ `AC1` `[ ]` đến khi bổ sung giải thích đặc trưng/reconstruction cho IF & AE và bỏ absolute local paths.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Mỗi model có ít nhất một dạng giải thích tái lập được.
  - `AC2` (`[ ] → [x]`, `TICK`): Báo cáo so sánh dùng cùng bộ metric và cùng split.
  - `AC3` (`[ ] → [x]`, `TICK`): Có cảnh báo về shortcut (đặc biệt `MIN_TTL`).
  - `AC4` (`[ ] → [x]`, `TICK`): Không có tuyên bố nhân quả.

#### Issue #106 (`M6.3`, `OPEN`, 0/4 → 2/4) — [M6.3][P0][Integration] Tích hợp AI Engine và Behavioral Engine vào inference pipeline
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL_NO_CSV_VECTOR` — Tick `AC2, AC3`; giữ `AC1, AC4` `[ ]` đến khi tích hợp trả kèm `BehavioralVector` trong luồng phân tích CSV.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Phân tích CSV trả kèm vector hành vi khi đủ dữ liệu.
  - `AC2` (`[ ] → [x]`, `TICK`): Thiếu artifact thì báo `BLOCKED / NOT READY`, không tạo vector giả.
  - `AC3` (`[ ] → [x]`, `TICK`): Endpoint cũ vẫn tương thích.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có test end-to-end cho 4 model + vector.

#### Issue #107 (`M6.4`, `OPEN`, 0/4 → 2/4) — [M6.4][P0][Event] Unified Security Event v2 và persistence schema
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL_SCHEMA_GAP` — Tick `AC2, AC3`; giữ `AC1, AC4` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Event lưu được và truy vấn lại đầy đủ provenance.
  - `AC2` (`[ ] → [x]`, `TICK`): Quan hệ suy luận được đánh dấu khác quan hệ quan sát.
  - `AC3` (`[ ] → [x]`, `TICK`): Migration không làm mất dữ liệu cũ.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có test cho truy vấn theo entity và theo khoảng thời gian.

#### Issue #108 (`M6.4`, `OPEN`, 0/4 → 3/4) — [M6.4][P0][Risk] Risk scoring methodology 0–100 và hiệu chỉnh severity
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC3, AC4`; giữ `AC2` `[ ]` đến khi sinh báo cáo phân bố risk trên dữ liệu thực.
  - `AC1` (`[ ] → [x]`, `TICK`): Công thức và trọng số được đặc tả, tái lập được.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Có phân bố risk thực tế cho benign và attack.
  - `AC3` (`[ ] → [x]`, `TICK`): Mức Critical không xuất hiện tràn lan trên benign.
  - `AC4` (`[ ] → [x]`, `TICK`): OOD không được gán risk như attack đã xác nhận.

#### Issue #109 (`M6.4`, `OPEN`, 0/4 → 2/4) — [M6.4][P1][Risk] Multi-model decision aggregation có kiểm chứng
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC3, AC4`; giữ `AC1, AC2` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Ít nhất 4 policy được đánh giá trên cùng dữ liệu.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Kết luận nêu rõ policy nào tốt hơn ở metric nào.
  - `AC3` (`[ ] → [x]`, `TICK`): Policy tất định, không phụ thuộc thứ tự chạy.
  - `AC4` (`[ ] → [x]`, `TICK`): Không dùng model RESEARCH_ONLY để khẳng định kết luận cuối.

#### Issue #114 (`M6.4`, `OPEN`, 0/4 → 2/4) — [M6.4][P0][Evaluation] Đánh giá correlation và traceability với ground truth
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC4`; giữ `AC2, AC3` `[ ]` đến khi tính baseline động, sửa `+75.0%` và bổ sung error analysis định tính rõ.
  - `AC1` (`[ ] → [x]`, `TICK`): Có ít nhất 2 metric traceability được định nghĩa và đo.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Có baseline để so sánh.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Có phân tích lỗi định tính kèm ví dụ.
  - `AC4` (`[ ] → [x]`, `TICK`): Kết quả tái lập từ script.

#### Issue #119 (`M6.5`, `OPEN`, 0/4 → 3/4) — [M6.5][P0][Crypto] Key generation, secure key storage, lifecycle và versioning
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC3`; giữ `AC4` `[ ]` đến khi có runbook sự cố keystore.
  - `AC1` (`[ ] → [x]`, `TICK`): Khóa sinh đủ entropy và không bao giờ ghi vào log/source.
  - `AC2` (`[ ] → [x]`, `TICK`): Có trạng thái lifecycle và `key_id` ổn định.
  - `AC3` (`[ ] → [x]`, `TICK`): File khóa có quyền truy cập hạn chế; CI dùng khóa test riêng.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có runbook khi keystore không khả dụng.

#### Issue #120 (`M6.5`, `OPEN`, 0/4 → 3/4) — [M6.5][P0][Crypto] Fixed key rotation 30 phút
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC2, AC3, AC4`; giữ `AC1` `[ ]` đến khi bổ sung clock injection cho `check_fixed_schedule`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Rotation xảy ra đúng chu kỳ 30 phút theo clock.
  - `AC2` (`[ ] → [x]`, `TICK`): Dữ liệu mã hóa trước rotation vẫn giải mã được.
  - `AC3` (`[ ] → [x]`, `TICK`): Có audit record cho mỗi lần rotate.
  - `AC4` (`[ ] → [x]`, `TICK`): Không rotate trùng khi job chạy chồng.

#### Issue #122 (`M6.5`, `OPEN`, 0/4 → 3/4) — [M6.5][P1][Crypto] Rotation cooldown, rate limiting và failure handling
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC4`; giữ `AC3` `[ ]` đến khi persist bộ đếm rate-limit/cooldown qua restart.
  - `AC1` (`[ ] → [x]`, `TICK`): Rotate vượt giới hạn bị từ chối và ghi audit.
  - `AC2` (`[ ] → [x]`, `TICK`): Lỗi giữa chừng không làm mất khóa đang dùng.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Bộ đếm vẫn đúng sau restart.
  - `AC4` (`[ ] → [x]`, `TICK`): Có test cho cả ba tình huống: cooldown, rate limit, failure.

#### Issue #123 (`M6.5`, `OPEN`, 0/4 → 3/4) — [M6.5][P0][Crypto] Historical data decryption và key recovery
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC4`; giữ `AC3` `[ ]`.
  - `AC1` (`[ ] → [x]`, `TICK`): Dữ liệu qua nhiều lần rotate vẫn giải mã đúng.
  - `AC2` (`[ ] → [x]`, `TICK`): Revoke khóa còn tham chiếu bị từ chối.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Có runbook backup/restore được kiểm thử.
  - `AC4` (`[ ] → [x]`, `TICK`): Lỗi khóa không trả dữ liệu rỗng hay plaintext sai.

#### Issue #135 (`M6.6`, `OPEN`, 0/4 → 3/4) — [M6.6][P1][Integration] Tích hợp Behavioral Engine và Trace Engine vào luồng live
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC3`; giữ `AC4` `[ ]` đến khi có log test 10k sự kiện.
  - `AC1` (`[ ] → [x]`, `TICK`): Sự kiện live có vector và được gán phiên.
  - `AC2` (`[ ] → [x]`, `TICK`): Timeline cập nhật nhất quán.
  - `AC3` (`[ ] → [x]`, `TICK`): Chi phí tăng thêm được đo.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Không rò rỉ bộ nhớ khi chạy dài (test 10k sự kiện).

#### Issue #137 (`M6.6`, `OPEN`, 0/5 → 3/5) — [M6.6][P0][Lab] Tích hợp mạng lab được cấp phép và nghiệm thu end-to-end
- **Quyết định:** `TICK_PARTIAL` | `BLOCKED_PHYSICAL_LAB` — Tick `AC3, AC4, AC5` (với điều kiện loopback + offline demo cục bộ); giữ `AC1, AC2` `[ ]` (`BLOCKED` phần cứng lab & `NOT_TRIGGERED`).
  - `AC1` (`[ ] → [ ]`, `KEEP`): Telemetry thật đi qua pipeline và tạo kết quả AI.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Có cảnh báo hiển thị trên giao diện.
  - `AC3` (`[ ] → [x]`, `TICK`): Risk, Trace, Encryption đều tham gia luồng.
  - `AC4` (`[ ] → [x]`, `TICK`): Có biên bản với bằng chứng và giới hạn rõ ràng.
  - `AC5` (`[ ] → [x]`, `TICK`): Offline demo vẫn hoạt động sau khi tích hợp.

#### Issue #138 (`M6.7`, `OPEN`, 0/4 → 3/4) — [M6.7][P0][Integration] Full system integration và end-to-end integration tests
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL_CI_FAIL` — Tick `AC1, AC2, AC3`; giữ `AC4` `[ ]` đến khi CI `feat/v2-integration` xanh 100%.
  - `AC1` (`[ ] → [x]`, `TICK`): Ba chế độ đều có test end-to-end chạy trong CI.
  - `AC2` (`[ ] → [x]`, `TICK`): Thiếu artifact → test báo `SKIPPED`, không fail giả và không pass giả.
  - `AC3` (`[ ] → [x]`, `TICK`): Không có plaintext vector trong DB sau test.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Toàn bộ suite hiện có vẫn PASS.

#### Issue #140 (`M6.7`, `OPEN`, 0/4 → 3/4) — [M6.7][P0][Desktop] Live monitoring dashboard
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC4`; giữ `AC3` `[ ]`.
  - `AC1` (`[ ] → [x]`, `TICK`): Hiển thị alert và số liệu pipeline theo thời gian thực.
  - `AC2` (`[ ] → [x]`, `TICK`): Có bộ lọc và trạng thái rỗng/lỗi rõ ràng.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Không treo UI khi dữ liệu lớn.
  - `AC4` (`[ ] → [x]`, `TICK`): Test component PASS.

#### Issue #141 (`M6.7`, `OPEN`, 0/4 → 3/4) — [M6.7][P0][Desktop] Behavioral Analysis dashboard
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC2, AC3, AC4`; giữ `AC1` `[ ]` đến khi `#103` cung cấp learned profile.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Hiển thị được vector và profile cho một phiên.
  - `AC2` (`[ ] → [x]`, `TICK`): So sánh được hai phiên với similarity.
  - `AC3` (`[ ] → [x]`, `TICK`): Không xuất vector plaintext mặc định.
  - `AC4` (`[ ] → [x]`, `TICK`): Test PASS và a11y cơ bản đạt.

#### Issue #142 (`M6.7`, `OPEN`, 0/4 → 3/4) — [M6.7][P1][Desktop] Attack Timeline và Investigation dashboard
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC2, AC3, AC4`; giữ `AC1` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Xem được timeline nhiều giai đoạn từ dữ liệu thật.
  - `AC2` (`[ ] → [x]`, `TICK`): Xuất report từ UI thành công và có hash.
  - `AC3` (`[ ] → [x]`, `TICK`): Phân biệt rõ quan sát và suy luận.
  - `AC4` (`[ ] → [x]`, `TICK`): Test PASS.

#### Issue #145 (`M6.7`, `OPEN`, 0/4 → 3/4) — [M6.7][P0][Validation] Independent research validation cho 6 Research Questions
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC3, AC4`; giữ `AC2` `[ ]` đến khi có rerun audit độc lập.
  - `AC1` (`[ ] → [x]`, `TICK`): Cả 6 RQ có trạng thái và bằng chứng tương ứng.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Có ít nhất một lần chạy lại độc lập cho mỗi thực nghiệm.
  - `AC3` (`[ ] → [x]`, `TICK`): Không có RQ nào được đánh `VALIDATED` khi thiếu artifact.
  - `AC4` (`[ ] → [x]`, `TICK`): Ghi rõ giới hạn (holdout, quy mô mẫu, môi trường).

#### Issue #146 (`M6.7`, `OPEN`, 0/4 → 3/4) — [M6.7][P0][Security] Security audit v2.0
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC3, AC4`; giữ `AC2` `[ ]`.
  - `AC1` (`[ ] → [x]`, `TICK`): Mỗi SR có kết luận `SATISFIED / PARTIAL / NOT MET` kèm bằng chứng.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Finding có mức độ và cách tái hiện.
  - `AC3` (`[ ] → [x]`, `TICK`): Không tuyên bố "an toàn" khi còn finding P0 mở.
  - `AC4` (`[ ] → [x]`, `TICK`): Không có khóa/dữ liệu nhạy cảm trong báo cáo.

#### Issue #147 (`M6.7`, `OPEN`, 0/4 → 3/4) — [M6.7][P1][Performance] Performance benchmark toàn hệ thống v2.0
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC2, AC3`; giữ `AC4` `[ ]` đến khi kiểm chứng cross-run variance.
  - `AC1` (`[ ] → [x]`, `TICK`): Có số liệu cho ba chế độ và từng tầng.
  - `AC2` (`[ ] → [x]`, `TICK`): Ghi rõ môi trường và cách tái lập.
  - `AC3` (`[ ] → [x]`, `TICK`): Không tuyên bố hiệu năng vượt quá số đo.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Kết quả tái lập trong sai số hợp lý.

#### Issue #149 (`M6.7`, `OPEN`, 0/4 → 3/4) — [M6.7][P1][Release] Upgrade path v1.0.0 → v2.0 và migration verification
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC1, AC3, AC4` (ở mức DB/CLI); giữ `AC2` `[ ]`.
  - `AC1` (`[ ] → [x]`, `TICK`): Dữ liệu v1.0.0 còn nguyên sau nâng cấp.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Có backup và rollback khi migration lỗi.
  - `AC3` (`[ ] → [x]`, `TICK`): Artifact không tương thích bị báo rõ, không dùng ngầm.
  - `AC4` (`[ ] → [x]`, `TICK`): Test với DB mẫu PASS.

#### Issue #150 (`M6.7`, `OPEN`, 0/4 → 2/4) — [M6.7][P0][Demo] Reproducible demonstration scenarios cho Offline, Replay và Live
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC3, AC4`; giữ `AC1, AC2` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Ba kịch bản chạy được từ trạng thái sạch.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Mỗi kịch bản có thời lượng và kết quả kỳ vọng.
  - `AC3` (`[ ] → [x]`, `TICK`): Có phương án dự phòng khi thiếu lab/mạng.
  - `AC4` (`[ ] → [x]`, `TICK`): Không có bước nào phụ thuộc dữ liệu không được phép dùng.

#### Issue #151 (`M6.7`, `OPEN`, 0/4 → 1/4) — [M6.7][P1][Docs] Tài liệu kỹ thuật v2.0: architecture, dataset, AI model
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL` — Tick `AC2`; giữ `AC1, AC3, AC4` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Không còn mô tả v1.0.0 như trạng thái hiện tại của v2.0.
  - `AC2` (`[ ] → [x]`, `TICK`): Mỗi số liệu dẫn được về manifest/report.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Link nội bộ không hỏng.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Không trùng lặp với #18/#19.

#### Issue #152 (`M6.7`, `OPEN`, 0/4 → 1/4) — [M6.7][P1][Docs] User guide, deployment guide và website site-source v2.0
- **Quyết định:** `TICK_PARTIAL` | `PARTIAL_SITE_V1` — Tick `AC4` (không đưa raw dataset vào repo/web); giữ `AC1, AC2, AC3` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Hướng dẫn chạy đúng từ máy sạch.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Website build/check PASS và không có claim vượt bằng chứng.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Có trang mô tả 3 chế độ và giới hạn pháp lý.
  - `AC4` (`[ ] → [x]`, `TICK`): Không đưa dữ liệu/dataset vào website.


### 8.3. Nhóm `UNTICK_INVALID` — Issues v2 đang có `[x]` nhưng KHÔNG hợp lệ trên Code/CI hiện tại (6 issues: #83, #86, #92, #93, #94, #95)

#### Issue #83 (`M6.2`, `OPEN`, 3/4 → 2/4) — [M6.2][P0][Data] Dataset downloader, checksum verification và manifest cho nguồn mới
- **Quyết định:** `UNTICK_INVALID` | `FAIL_MUTATION_AND_BLOCKED` — Bỏ tick `AC1` cho tới khi sửa `--verify-only` thành read-only không ghi file; giữ `AC2–AC3` `[x]` và `AC4` `[ ]`.
  - `AC1` (`[x] → [ ]`, `UNTICK`): Checksum sai hoặc thiếu exit code khác 0 khi `--require-data` và không ghi manifest sai.
  - `AC2` (`[x] → [x]`, `KEEP`): Tách biệt hoàn toàn official manifests (`synthetic: false`) với unit-test fixtures (`synthetic: true` — `test_dataset_manifest_separation.py` PASS).
  - `AC3` (`[x] → [x]`, `KEEP`): Không chứa credential hay URL có token trong log/manifest; chạy được trên Windows PowerShell/Python.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Theo dõi tải lại `UGR'16` khi máy chủ NESG mở lại (`BLOCKED`).

#### Issue #86 (`M6.2`, `OPEN`, 3/3 → 1/3) — [M6.2][P0][Data] Chuẩn hóa timestamp và entity identifiers đa nguồn
- **Quyết định:** `UNTICK_INVALID` | `FAIL_CODE_MISMATCH` — Bỏ tick `AC2` và `AC3` ngay (không khớp code/test thực tế); giữ `AC1` có điều kiện hoặc rà soát cùng `#89/#90`.
  - `AC1` (`[x] → [x]`, `KEEP`): Mọi nguồn v2 đều qua lớp chuẩn hóa `src/network_anomaly/canonical/` và `src/network_anomaly/data/v2_schema.py`. *(IMPLEMENTED & TESTED)*
  - `AC2` (`[x] → [ ]`, `UNTICK`): Giá trị thời gian gốc truy vết được; test epoch s/ms, timezone lệch và missing timestamp PASS.
  - `AC3` (`[x] → [ ]`, `UNTICK`): Không tự suy diễn định danh khi nguồn không cung cấp.

#### Issue #92 (`M6.2`, `OPEN`, 3/3 → 2/3) — [M6.2][P0][Data] Leakage-resistant train/validation/test split cho dữ liệu đa nguồn
- **Quyết định:** `UNTICK_INVALID` | `FAIL_ON_CI` — Bỏ tick `AC2` (lệch checksum CRLF vs LF làm CI FAIL); giữ `AC1, AC3` `[x]`.
  - `AC1` (`[x] → [x]`, `KEEP`): `scenario_overlap_count == 0` và `scenario_5tuple_ts_overlap_count == 0` giữa train/val/test (`status = PASS`). *(EXPERIMENTALLY VALIDATED)*
  - `AC2` (`[x] → [ ]`, `UNTICK`): Manifest split v2 ghi rõ checksum raw/processed và phân bố lớp; không trộn Test vào preprocessing/calibration.
  - `AC3` (`[x] → [x]`, `KEEP`): Split v1 của `NF-UNSW-NB15-v3` chỉ giữ ở `data/historical/nf_unsw_nb15_v3/` để truy vết lịch sử, không bắt buộc giữ trong active pipeline.

#### Issue #93 (`M6.2`, `OPEN`, 3/3 → 1/3) — [M6.2][P0][Integration] Cross-source event alignment và multi-source pipeline end-to-end
- **Quyết định:** `UNTICK_INVALID` | `FAIL_DEPS_AND_TEST` — Bỏ tick `AC1` và `AC3`; giữ `AC2` `[x]` (no implicit imputation & route_only fallback).
  - `AC1` (`[x] → [ ]`, `UNTICK`): Pipeline đa nguồn v2 chạy end-to-end trên fixture/subset v2, tái lập được (`test_multi_source_pipeline.py` PASS). *(IMPLEMENTED & TESTED)*
  - `AC2` (`[x] → [x]`, `KEEP`): Không impute đặc trưng thiếu; sự kiện phi-NetFlow hoặc thiếu trường cơ sở được route sang Behavioral/Risk/Trace.
  - `AC3` (`[x] → [ ]`, `UNTICK`): Báo cáo rõ sự kiện align được vs chưa có khóa liên kết (`AIT` cross-source linkage `NOT VERIFIED`).

#### Issue #94 (`M6.3`, `OPEN`, 3/3 → 1/3) — [M6.3][P0][ML] Audit và tái lập kết quả 4 model, kiểm tra leakage và shortcut TTL
- **Quyết định:** `UNTICK_INVALID` | `FAIL_ON_CI` — Bỏ tick `AC2` và `AC3` (hoặc gắn FAIL_ON_CI) đến khi tái đồng bộ LF checksum và sửa lỗi CI `44171616420`; giữ `AC1` `[x]` (historical archive).
  - `AC1` (`[x] → [x]`, `KEEP`): Bằng chứng shortcut `MIN_TTL` và kết quả v1 được lưu trữ đầy đủ trong historical archive (`docs/historical/nf_unsw_nb15_v3/`, `reports/historical/nf_unsw_nb15_v3/`).
  - `AC2` (`[x] → [ ]`, `UNTICK`): Huấn luyện mới từ đầu và đánh giá độc lập cả 4 mô hình v2 trên `canonical-flow-v2-18` (`AIT-Test` + `CTU-SME-11`), không sử dụng trọng số hay benchmark v1 để hợp thức hóa v2. *(EXPERIMENTALLY VALIDATED)*
  - `AC3` (`[x] → [ ]`, `UNTICK`): Ghi rõ validation vs held-out vs cross-source metrics và `shortcut_audit` trên `ait_val` trong `reports/models/*_manifest.json`.

#### Issue #95 (`M6.3`, `OPEN`, 4/4 → 3/4) — [M6.3][P0][ML] Đánh giá tương thích dataset mới và retrain khi feature space thay đổi
- **Quyết định:** `UNTICK_INVALID` | `FAIL_ON_CI` — Bỏ tick `AC3` đến khi CI `verify_companion_artifacts` / provenance tests PASS trên checkout LF; giữ `AC1, AC2, AC4` `[x]`.
  - `AC1` (`[x] → [x]`, `KEEP`): ADR hard cutover (`docs/adr/ADR-dataset-hard-cutover-v2.md`) và Migration Note (`docs/MIGRATION_V1_TO_V2.md`) ghi rõ lý do bỏ 47-feature v1 và chọn `canonical-flow-v2-18`. *(IMPLEMENTED)*
  - `AC2` (`[x] → [x]`, `KEEP`): Không impute đặc trưng không tồn tại; dữ liệu phi-NetFlow chạy `route_only`.
  - `AC3` (`[x] → [ ]`, `UNTICK`): Cả 4 mô hình (Random Forest, XGBoost, Isolation Forest, Autoencoder) được huấn luyện mới trên `ait_train` + `v2_flow_preprocessor.joblib` (`asinh_robust`), với manifest & SHA-256 mới (`AI Ready 4/4`). *(EXPERIMENTALLY VALIDATED)*
  - `AC4` (`[x] → [x]`, `KEEP`): `ModelRegistry` từ chối fail-closed mọi artifact/manifest v1 (không fallback).


### 8.4. Nhóm `KEEP_CHECKED_VALID` — Issues v2 giữ nguyên trạng thái `[x]` hiện tại (6 issues: #82, #84, #85, #87, #88, #91)

#### Issue #82 (`M6.2`, `OPEN`, 4/5 → 4/5) — [M6.2][P0][Dataset] Audit nguồn, license, provenance và khả năng tải các dataset P0/P1/P2
- **Quyết định:** `KEEP_CHECKED_VALID` | `PARTIAL_EXTERNAL_BLOCKER` — Giữ `AC1–AC4` `[x]` và `AC5` `[ ]` (`UGR'16 BLOCKED` + PR `#156` chưa merge).
  - `AC1` (`[x] → [x]`, `KEEP`): Mỗi nguồn mục tiêu có quyết định `ACCEPTED / REJECTED / BLOCKED` kèm lý do và bằng chứng HTTP/DOI. *(EXPERIMENTALLY VALIDATED)*
  - `AC2` (`[x] → [x]`, `KEEP`): Nêu rõ license (`CC BY 4.0`, `CC BY-NC-SA 4.0`) và điều khoản tái phân phối (`NOTICE`, `THIRD_PARTY_NOTICES.md`).
  - `AC3` (`[x] → [x]`, `KEEP`): Có cả nguồn log/flow AIT và nguồn traffic thu thập thực tế (`CTU-SME-11`); `UGR'16` được ghi nhận trung thực là `BLOCKED`.
  - `AC4` (`[x] → [x]`, `KEEP`): Không đưa dữ liệu thô hoặc thông tin đăng nhập vào Git.
  - `AC5` (`[ ] → [ ]`, `KEEP`): PR #156 được review/merge hoặc `UGR'16` được giải phóng để bổ sung external ISP validation.

#### Issue #84 (`M6.2`, `OPEN`, 3/3 → 3/3) — [M6.2][P0][Data] Profiling AIT NetFlow Dataset và AIT Log Dataset v2.1
- **Quyết định:** `KEEP_CHECKED_VALID` | `PASS_WITH_NOTE` — Giữ `AC1–AC3` `[x]` (bổ sung chú thích về sự chênh lệch tiêu đề `AIT-LDS-v2.1` vs `CTU-SME-11`).
  - `AC1` (`[x] → [x]`, `KEEP`): Profile tái lập được trên `AIT-NDS-v2` (8 scenarios, `3,465,342` flows gốc -> `3,231,215` labeled + `942` unmapped) và `CTU-SME-11` (`CTU-Echo`, `CTU-Windows7AD`). *(EXPERIMENTALLY VALIDATED)*
  - `AC2` (`[x] → [x]`, `KEEP`): Có phân bố nhãn, khoảng thời gian, duplicate audit và xác định các cột rò rỉ tiềm năng.
  - `AC3` (`[x] → [x]`, `KEEP`): Không đưa dữ liệu thô vào Git.

#### Issue #85 (`M6.2`, `OPEN`, 2/3 → 2/3) — [M6.2][P0][Data] Kiểm chứng khả năng liên kết AIT NetFlow ↔ AIT Log v2.1
- **Quyết định:** `KEEP_CHECKED_VALID` | `PARTIAL_EXTERNAL_BLOCKER` — Giữ `AC1–AC2` `[x]` và `AC3` `[ ]` (`BLOCKED`).
  - `AC1` (`[x] → [x]`, `KEEP`): Kiểm chứng và lập tài liệu phân tích phiên bản/schema/khóa liên kết tại `docs/dataset/AIT_LINKAGE_FEASIBILITY.md`.
  - `AC2` (`[x] → [x]`, `KEEP`): Ghi nhận trung thực trạng thái `NOT VERIFIED` / `BLOCKED` cho empirical cross-source linkage trong `RQ3` (`reports/experiments/behavioral/rq3_session_correlation_experiment.json`), không tạo liên kết giả.
  - `AC3` (`[ ] → [ ]`, `KEEP`): (Mở — nếu mở rộng sau) Thực thi align log↔flow trên các scenario đã kiểm chứng đồng bộ timestamp/timezone giữa `AIT-LDS-v2.0`/`v2.1` và `AIT-NDS-v2`.

#### Issue #87 (`M6.2`, `OPEN`, 2/2 → 2/2) — [M6.2][P0][Data] Label harmonization và attack taxonomy thống nhất đa nguồn
- **Quyết định:** `KEEP_CHECKED_VALID` | `PASS` — Giữ `AC1–AC2` `[x]`.
  - `AC1` (`[x] → [x]`, `KEEP`): `taxonomy-v2` bao phủ nhãn `AIT-NDS-v2` và `CTU-SME-11` với bảo toàn `raw_label` và báo cáo `Unmapped`. *(IMPLEMENTED & TESTED)*
  - `AC2` (`[x] → [x]`, `KEEP`): Test chống ép `background`/`unknown` → `Benign` và test chống rò rỉ target vào `X` PASS (`test_anti_imputation_and_label_integrity.py`, `test_v2_migration_guards.py`).

#### Issue #88 (`M6.2`, `OPEN`, 3/3 → 3/3) — [M6.2][P0][Adapter] Network Flow adapter thống nhất cho canonical-flow-v2-18 (AIT-NDS-v2, CTU-SME-11, NetFlow/Zeek)
- **Quyết định:** `KEEP_CHECKED_VALID` | `PASS` — Giữ `AC1–AC3` `[x]`.
  - `AC1` (`[x] → [x]`, `KEEP`): Adapter chuẩn hóa đúng `AIT-NDS-v2` (Tstat), `CTU-SME-11` (Zeek `conn.log.labeled`) và `canonical-flow-v2-18` CSV sang `CanonicalSecurityEvent v2`. *(IMPLEMENTED & TESTED)*
  - `AC2` (`[x] → [x]`, `KEEP`): Đặc trưng thiếu/âm/non-finite bị từ chối fail-closed, không điền 0/median ngầm.
  - `AC3` (`[x] → [x]`, `KEEP`): Từ chối schema v1 47-feature của `NF-UNSW-NB15-v3` (zero fallback).

#### Issue #91 (`M6.2`, `OPEN`, 3/3 → 3/3) — [M6.2][P0][Data] Data quality validation và rejection gate cho multi-source
- **Quyết định:** `KEEP_CHECKED_VALID` | `PASS` — Giữ `AC1–AC3` `[x]`.
  - `AC1` (`[x] → [x]`, `KEEP`): Quality gate kiểm tra completeness, duplicate/near-duplicate, timestamp monotonicity, physical invariants và label integrity (`test_quality_gate.py` PASS). *(IMPLEMENTED & TESTED)*
  - `AC2` (`[x] → [x]`, `KEEP`): Dữ liệu lỗi vật lý bị chặn fail-closed, không tự sửa/impute ngầm.
  - `AC3` (`[x] → [x]`, `KEEP`): Báo cáo rõ `PASS / FAIL / SKIPPED` kèm checksum nguồn (`reports/datasets/v2_multi_source_profile.json`).


### 8.5. Nhóm `KEEP_UNCHECKED` — Issues v2 giữ nguyên tất cả `[ ]` (9 issues: #76, #81, #89, #90, #97, #128, #148, #153, #154)

#### Issue #76 (`M6.1`, `OPEN`, 0/4 → 0/4) — [M6.1][P0][Audit] Gap analysis v1.0.0 so với đề cương gốc Đề tài 22
- **Quyết định:** `KEEP_UNCHECKED` | `FAIL_DOD_GITIGNORED` — Giữ `AC1–AC4` `[ ]` cho tới khi bỏ ignore/commit file vào Git và sửa tên file tham chiếu sai.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Mỗi năng lực có đúng một trạng thái chuẩn tắc và ít nhất một chứng cứ kiểm chứng được.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Không gán `COMPLETED` khi thiếu test/artifact thực tế.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Nêu rõ phần `REDUCED`/`DEFERRED` của v1.0.0 so với đề cương (AES-GCM, rotation, live telemetry, multi-source).
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có bảng ánh xạ sang M6.1–M6.7 và tên issue cụ thể.

#### Issue #81 (`M6.1`, `OPEN`, 0/4 → 0/4) — [M6.1][P1][Security] Threat model và security requirements cho NetFlow Sentinel v2.0
- **Quyết định:** `KEEP_UNCHECKED` | `FAIL_DOD_GITIGNORED` — Giữ `AC1–AC4` `[ ]` cho tới khi đưa vào Git, sửa 5 tên test sai và đồng bộ trạng thái SR với `#146`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Mỗi ranh giới tin cậy có ít nhất một mối đe dọa và biện pháp.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Mỗi security requirement có cách kiểm chứng (test, audit log, hoặc cấu hình).
  - `AC3` (`[ ] → [ ]`, `KEEP`): Nêu rõ giới hạn: không chống được host đã bị compromise.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Không có tuyên bố "an toàn production" khi chưa có bằng chứng.

#### Issue #89 (`M6.2`, `OPEN`, 0/4 → 0/4) — [M6.2][P0][Adapter] Adapter log lớp ứng dụng: DNS và Web/API
- **Quyết định:** `KEEP_UNCHECKED` | `PARTIAL_MISSING_GATES` — Giữ `AC1–AC4` `[ ]` (chỉ kiểm chứng cục bộ khi gọi trực tiếp adapter; chưa đạt registry + redaction + missing-field tests).
  - `AC1` (`[ ] → [ ]`, `KEEP`): Event tạo ra hợp lệ theo contract v2.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Gate phân loại đúng là `route_only` cho các sự kiện này.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Không lưu body request hay credential trong event.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có test cho log thiếu trường bắt buộc.

#### Issue #90 (`M6.2`, `OPEN`, 0/4 → 0/4) — [M6.2][P0][Adapter] Adapter log danh tính và hệ thống: Authentication/VPN và System/Audit
- **Quyết định:** `KEEP_UNCHECKED` | `FAIL_CODE_MISMATCH` — Giữ `AC1–AC4` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Event auth có trường kết quả đăng nhập và thực thể user/device.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Không có credential hay hash trong event/log.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Gate phân loại đúng `route_only`.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có test cho bản ghi thiếu user hoặc thiếu host.

#### Issue #97 (`M6.3`, `OPEN`, 0/4 → 0/4) — [M6.3][P1][ML] Cross-dataset generalization và ablation TTL (kế thừa #25, #48, PR #49)
- **Quyết định:** `KEEP_UNCHECKED` | `SCOPE_OVERLAP_KEEP` — Giữ `AC1–AC4` `[ ]` đến khi chốt gọn quan hệ với `#25/#48` (khi đó `AC1–AC3` ánh xạ sang `run_ctu_cross_source_eval.py` + `CTU_CROSS_SOURCE_EVAL.md`).
  - `AC1` (`[ ] → [ ]`, `KEEP`): Không có dữ liệu test của nguồn đích lọt vào train.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Có ít nhất một ablation giải thích suy giảm.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Kết quả tái lập từ script đã commit.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Không trùng lặp phạm vi #25/#48; ghi rõ quan hệ.

#### Issue #128 (`M6.6`, `OPEN`, 0/4 → 0/4) — [M6.6][P0][Telemetry] NetFlow/IPFIX collector (Rust) với template decoding
- **Quyết định:** `KEEP_UNCHECKED` | `SCOPE_CONFLICT_KEEP` — Giữ `AC1–AC4` `[ ]` đến khi chốt đổi mô tả `#128` (và `ARCHITECTURE_V2.md:49,215`) từ Rust sang Python UDP collector.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Nhận và giải mã được cả NetFlow v9 và IPFIX.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Template thiếu → bỏ record và tăng counter, không panic.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Event sinh ra hợp lệ theo contract v2.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có test với datagram nhị phân thật (fixture nhỏ).

#### Issue #148 (`M6.7`, `OPEN`, 0/4 → 0/4) — [M6.7][P0][Release] Windows installer v2.0 và clean installation test
- **Quyết định:** `KEEP_UNCHECKED` | `BLOCKED` — Giữ `AC1–AC4` `[ ]` (`BLOCKED / NOT VERIFIED` — kế thừa `#73`).
  - `AC1` (`[ ] → [ ]`, `KEEP`): Cài đặt sạch trên Windows 10/11 x64, offline, Standard User.
  - `AC2` (`[ ] → [ ]`, `KEEP`): 4 model + crypto + demo chạy được sau cài.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Gỡ cài đặt không để lại dữ liệu ngoài `%LOCALAPPDATA%` đã khai báo.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có checksum và biên bản; quyền phân phối được ghi rõ trạng thái.

#### Issue #153 (`M6.7`, `OPEN`, 0/4 → 0/4) — [M6.7][P0][Docs] Research report, methodology, slide bảo vệ và Q&A v2.0
- **Quyết định:** `KEEP_UNCHECKED` | `NOT_IMPLEMENTED` — Giữ `AC1–AC4` `[ ]`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Mọi số liệu trong báo cáo/slide truy được tới artifact.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Nêu rõ phần `DEFERRED`/`PARTIAL` của v2.0.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Q&A trả lời được câu hỏi về unknown attack và crypto.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Slide đúng thời lượng bảo vệ.

#### Issue #154 (`M6.7`, `OPEN`, 0/4 → 0/4) — [M6.7][P0][Release] Release readiness audit và chuẩn bị NetFlow Sentinel v2.0.0
- **Quyết định:** `KEEP_UNCHECKED` | `FAIL_ON_CI_AND_BLOCKED` — Giữ `AC1–AC4` `[ ]` (`NOT READY / BLOCKED`).
  - `AC1` (`[ ] → [ ]`, `KEEP`): Mỗi acceptance gate có trạng thái và bằng chứng.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Mọi kiểm tra báo `PASS/FAIL/SKIPPED` kèm lệnh.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Không gán `READY` khi còn gate P0 chưa đạt.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Có danh sách blocker còn lại và tác động tới phạm vi bảo vệ.


### 8.6. Nhóm `LEGACY_V1_REMEDIATE` — Issues `M7` & `None` kế thừa từ v1 (8 issues: #18, #19, #20, #25, #48, #60, #71, #73)

#### Issue #18 (`M7`, `OPEN`, 7/8 → 1/8) — Hoàn thiện tài liệu, giấy phép và ghi nhận nguồn (SUPPORTING / M7)
- **Quyết định:** `LEGACY_V1_REMEDIATE` | `STALE_V1_UNTICK` — Bỏ tick `AC1–AC6, AC8` (đánh dấu superseded bởi `#151`/`#152`); chỉ giữ `AC7` `[x]` (không track raw/artifact/secret trong Git). Đóng hoặc viết lại phạm vi sang v2.
  - `AC1` (`[x] → [ ]`, `UNTICK`): Kiến trúc trong toàn bộ tài liệu đồng nhất theo `Rust/Tauri 2 + Svelte 5 -> Python FastAPI/PyInstaller Sidecar -> SQLite + 4 ML Models`, tách bạch End User (không yêu cầu Python/venv/Companion Bundle) với Developer setup.
  - `AC2` (`[x] → [ ]`, `UNTICK`): Mọi đường dẫn file, symbol (`MLPRegressor`, `TrainOnlyPreprocessor`), lệnh kiểm tra, API endpoint và metric Validation/Held-out Test được đối chiếu trực tiếp từ codebase và manifests thực tế.
  - `AC3` (`[x] → [ ]`, `UNTICK`): Tách bạch `MODEL_VALIDATED` (`RandomForest`), `RESEARCH_ONLY` (`XGBoost`, `IsolationForest`, `Autoencoder`), `BLOCKED / NOT READY`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED` và `NOT VERIFIED`.
  - `AC4` (`[x] → [ ]`, `UNTICK`): Hoàn thiện bộ tài liệu phản biện học thuật `docs/academic-defense/` (`01`–`09`, `README.md`, `EVIDENCE_INDEX.md`) với 100% cả 55 cột dữ liệu và ví dụ tiền xử lý thực tế.
  - `AC5` (`[x] → [ ]`, `UNTICK`): Sửa trực tiếp nguồn website Astro/MDX trên `site-source`, kiểm chứng `prettier --check`, `astro check`, `astro build`, `check-links.mjs`, `check-evidence.py` và Playwright + Axe WCAG 2.1 AA smoke test.
  - `AC6` (`[x] → [ ]`, `UNTICK`): Giữ nguyên license `Apache-2.0`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, trích dẫn UQ `454104` và ghi rõ phân phối `.exe` công khai đang `DEFERRED / BLOCKED` theo Issue #73 (không trùng nhiệm vụ nghiệm thu nhị phân thuộc #71/#73).
  - `AC7` (`[x] → [x]`, `KEEP`): Không đưa raw CSV, `.joblib`, installer `.exe` hay secret vào Git hoặc public assets của website.
  - `AC8` (`[ ] → [ ]`, `KEEP`): Reviewer / maintainer duyệt và merge PR #74 (`main`) và PR #75 (`site-source`), sau đó kích hoạt deploy GitHub Pages từ `site-source` và cập nhật `evidenceCommit` sau merge nếu cần.

#### Issue #19 (`M7`, `OPEN`, 0/4 → 0/4) — Hoàn thiện báo cáo PDF, bài trình bày và gói bàn giao (SUPPORTING / M7)
- **Quyết định:** `LEGACY_V1_REMEDIATE` | `STALE_V1_KEEP` — Giữ `AC1–AC4` `[ ]`; hợp nhất hoặc đóng chuyển sang `#153` (v2).
  - `AC1` (`[ ] → [ ]`, `KEEP`): Mọi bảng metric, confusion matrix và biểu đồ trong báo cáo/slide truy được tới file JSON/MD cụ thể trong `reports/` hoặc manifest demo.
  - `AC2` (`[ ] → [ ]`, `KEEP`): File PDF đọc tốt; slide đủ 10–12 trang; kịch bản demo offline trên Windows chạy được end-to-end với `demo_flows.csv`.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Nêu rõ phần rút gọn phạm vi so với `docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx` (những module DEFER không đánh tráo thành đã triển khai).
  - `AC4` (`[ ] → [ ]`, `KEEP`): Không đưa raw dataset `NF-UNSW-NB15-v3.csv` trái điều khoản hoặc artifact binary lớn trực tiếp vào Git.

#### Issue #20 (`M7`, `OPEN`, 1/6 → 1/6) — Xác minh tổng thể và đánh giá điều kiện bàn giao (SUPPORTING / M7)
- **Quyết định:** `LEGACY_V1_REMEDIATE` | `FAIL_ON_CI` — Giữ `AC6` `[x]` (không track raw/artifact lớn trong Git); giữ `AC1–AC5` `[ ]`; chuyển giao cổng nghiệm thu v2 sang `#154`.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Toàn bộ test suites (pytest tests -q),
  - `AC2` (`[ ] → [ ]`, `KEEP`): Từng kiểm tra báo cáo rõ PASS / FAIL / SKIPPED / NOT VERIFIED; mọi điều kiện bị thiếu ghi rõ blocker (ví dụ missing .joblib -> BLOCKED / NOT READY).
  - `AC3` (`[ ] → [ ]`, `KEEP`): Xác nhận không có rò rỉ Test Lock, không có Label/Attack lọt vào demo_flows.csv, không có model giả/heuristic ẩn.
  - `AC4` (`[ ] → [ ]`, `KEEP`): Các thực nghiệm trọng tâm (#25), tài liệu (#18) và gói bàn giao (#19) đạt nghiệm thu.
  - `AC5` (`[ ] → [ ]`, `KEEP`): (Chuyển ranh giới M7 từ #14) Thực hiện tái lập đồng bộ toàn hệ thống cuối kỳ hậu #25, kiểm chứng đóng gói ứng dụng Windows (Rust / Tauri 2 + Svelte 5 #16), QA end-to-end ứng dụng desktop, và kiểm chứng tính tái lập cho báo cáo cuối kỳ (#18) + slide (#19).
  - `AC6` (`[x] → [x]`, `KEEP`): Raw dataset và file artifact/binary lớn không bị track trái quy định trong Git.

#### Issue #25 (`M7`, `OPEN`, 0/3 → 0/3) — C10 — Thực nghiệm khoa học trọng tâm có bằng chứng tái lập (REDUCE trong M7)
- **Quyết định:** `LEGACY_V1_REMEDIATE` | `STALE_V1_KEEP` — Giữ `AC1–AC3` `[ ]`; đóng hoặc gắn `SUPERSEDED` trỏ sang `#145` và cụm RQ v2.
  - `AC1` (`[ ] → [ ]`, `KEEP`): Exp 1–3 (và Exp 4 Unknown Attack Holdout trong phạm vi Exp 2) có protocol, `split_manifest_sha256`, `dataset_sha256`, seed, config, metrics JSON và lệnh tái lập gắn commit hash.
  - `AC2` (`[ ] → [ ]`, `KEEP`): Tuyệt đối không dùng Held-out Test (`test_indices.csv.gz`) để tune hyperparameter hay threshold; không dùng synthetic fixture để báo kết quả `NF-UNSW-NB15-v3`.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Mọi experiment chưa chạy (`Exp 2`, `Exp 3`, hoặc các experiment `DEFERRED` 5/6/7) được ghi đúng trạng thái `NOT VERIFIED` / `DEFERRED` trong báo cáo M7 (#18, #19).

#### Issue #48 (`M7`, `OPEN`, 1/3 → 0/3) — C10/M7 — Nghiên cứu Cross-Dataset Robustness (DEFER / M7 — không chặn Demo MVP)
- **Quyết định:** `LEGACY_V1_REMEDIATE` | `STALE_V1_UNTICK` — Bỏ tick `AC1` (chú thích là lịch sử v1); giữ `AC2–AC3` `[ ]`; hợp nhất/đóng chuyển sang `#97` + `#145`.
  - `AC1` (`[x] → [ ]`, `UNTICK`): Fix triệt để E0 data contamination và cấu hình sample filename ở PR #49 (`7344994`) với unit tests cô lập partition.
  - `AC2` (`[ ] → [ ]`, `KEEP`): PR #49 được rebase/merge vào `main` sau khi PR #47 được duyệt merge.
  - `AC3` (`[ ] → [ ]`, `KEEP`): Kết quả E0–E5 (hoặc trạng thái `NOT VERIFIED` nếu không tải dữ liệu ngoại vi trong máy bàn giao) được báo cáo trung thực trong #18, #19, #25.

#### Issue #60 (`M7`, `OPEN`, 8/11 → 3/11) — [Audit Remediation] Consolidated security, ML validity, artifact integrity & integration findings
- **Quyết định:** `LEGACY_V1_REMEDIATE` | `STALE_V1_UNTICK` — Bỏ tick `AC3, AC4, AC5, AC6, AC7` (hoặc đánh dấu lịch sử v1 + hồi quy CI `44171616420`); giữ `AC1, AC2` (đã merge v1 PR `#61`) & `AC8` (cần mở issue/fix Ruff mới); giữ `AC9–AC11` `[ ]` và chuyển phạm vi v2 sang `#146`/`#154`.
  - `AC1` (`[x] → [x]`, `KEEP`): **#53** `[Audit][P0][Inference]` Eliminate unverified deserialization and legacy loader bypass (Merged `main` via PR #61)
  - `AC2` (`[x] → [x]`, `KEEP`): **#54** `[Audit][P0][IsolationForest]` Verified envelope packaging & threshold/class parity (Merged `main` via PR #61)
  - `AC3` (`[x] → [ ]`, `UNTICK`): **#55** `[Audit][P1][Provenance]` Reconcile hash-chains & eliminate hardcoded constants (Merged `main` via PR #61)
  - `AC4` (`[x] → [ ]`, `UNTICK`): **#56** `[Audit][P0][PR50-Evaluation]` Dynamic evaluation evidence & disjointness checks (`rf-heldout-ea330b9` merged `main`)
  - `AC5` (`[x] → [ ]`, `UNTICK`): **#57** `[Audit][P0][PR49-CrossDataset]` E0 holdout isolation & ToN-IoT sample fix (Patch verified on PR #49 `7344994` — awaiting PR #47 & maintainer merge into `main`; #48 remains M7 research)
  - `AC6` (`[x] → [ ]`, `UNTICK`): **#58** `[Audit][P1][PR47-Ingestion]` `InferenceEligibilityGate` integration, 64-hex SHA-256 separation & conflict-free rebase (Patch verified **6/6 CI PASS** on PR #47 `f999930` — awaiting maintainer `REVIEW_REQUIRED` merge into `main`; #46 remains OPEN until merge)
  - `AC7` (`[x] → [ ]`, `UNTICK`): **#59** `[Audit][P1][PR52-API]` Verified `InferencePipeline` enforcement, artifact filename parity & security claim boundaries (Merged `main` via PR #61; PR #52 closed `SUPERSEDED`)
  - `AC8` (`[x] → [x]`, `KEEP`): **#37** `chore(lint)` Resolve legacy Ruff & Black debt (Closed on `main`)
  - `AC9` (`[ ] → [ ]`, `KEEP`): Hợp nhất PR #47, PR #49 (hậu #47) và Consolidation PR vào `main` sau khi maintainer duyệt review
  - `AC10` (`[ ] → [ ]`, `KEEP`): Hoàn thiện Desktop UI **Rust / Tauri 2 + Svelte 5** (#16) và kiểm chứng end-to-end demo trên Windows
  - `AC11` (`[ ] → [ ]`, `KEEP`): Hoàn tất báo cáo M7 (#18, #19, #20, #25) với ranh giới trung thực giữa phần `IMPLEMENTED / TESTED` và `EXPERIMENTALLY VALIDATED`

#### Issue #71 (`M7`, `OPEN`, 7/15 → 6/15) — feat(desktop): Standalone Windows Installer — Bundled Python Backend & 4 ML Models
- **Quyết định:** `LEGACY_V1_REMEDIATE` | `STALE_V1_UNTICK` — Bỏ tick `AC11` (CI HEAD `79ebb67` FAIL); gắn nhãn lịch sử v1 cho `AC1,2,4,5,6,9` (khuyến nghị mở v2 tại `#148`); giữ `AC3,7,8,10,12–15` `[ ]` (`DEFERRED -> #73`).
  - `AC1` (`[x] → [x]`, `KEEP`): AC-01: Một NSIS `.exe` chứa đầy đủ frontend, backend, runtime và 4 model thật (`PASS` — build & layout verified locally).
  - `AC2` (`[x] → [x]`, `KEEP`): AC-02: Không yêu cầu Python, Git, Rust, Node.js, repository clone hoặc Companion Bundle sau khi cài đặt (`PASS` — verified locally with scrubbed `PATH`).
  - `AC3` (`[ ] → [ ]`, `KEEP`): AC-03 (`DEFERRED / NOT VERIFIED` → #73): Ứng dụng hoạt động offline trên Windows 10/11 x64 sạch.
  - `AC4` (`[x] → [x]`, `KEEP`): AC-04: Cả bốn model READY và thực thi inference/evaluation trên demo thật (`PASS`).
  - `AC5` (`[x] → [x]`, `KEEP`): AC-05: Artifact provenance, SHA-256, OOD và fail-closed đều PASS (`PASS`).
  - `AC6` (`[x] → [x]`, `KEEP`): AC-06: Tauri sidecar tự start/stop, không orphan processes (`PASS`).
  - `AC7` (`[ ] → [ ]`, `KEEP`): AC-07 (`DEFERRED / NOT VERIFIED` → #73): Người dùng mới có thể hiểu mục đích và sử dụng ứng dụng thông qua giao diện.
  - `AC8` (`[ ] → [ ]`, `KEEP`): AC-08 (`DEFERRED / NOT VERIFIED` → #73): Import, Analyze, Compare, Export và Security Dry-Run hoạt động qua GUI.
  - `AC9` (`[x] → [x]`, `KEEP`): AC-09: Giao diện hiển thị đúng trạng thái model và giải thích kết quả, giới hạn khoa học (`PASS`).
  - `AC10` (`[ ] → [ ]`, `KEEP`): AC-10 (`DEFERRED / NOT VERIFIED` → #73): Windows clean-machine E2E PASS bằng installer thật.
  - `AC11` (`[x] → [ ]`, `UNTICK`): AC-11: CI, security checks và regression tests PASS (`PASS` — 8/8 CI checks tại PR #72 HEAD `2226170`).
  - `AC12` (`[ ] → [ ]`, `KEEP`): AC-12 (`DEFERRED / NOT VERIFIED` → #73): Release attestation xác minh đúng commit, installer SHA-256 và embedded models.
  - `AC13` (`[ ] → [ ]`, `KEEP`): AC-13 (`DEFERRED / NOT VERIFIED` → #73): Version 1.0.0, docs và release assets nhất quán (Source Release `v1.0.0` đồng bộ; binary release assets bị hoãn).
  - `AC14` (`[ ] → [ ]`, `KEEP`): AC-14 (`DEFERRED / NOT VERIFIED` — `BLOCKED` → #73): Có căn cứ hợp lệ cho việc phân phối các model và tài nguyên được nhúng.
  - `AC15` (`[ ] → [ ]`, `KEEP`): AC-15 (`DEFERRED / NOT VERIFIED` → #73): Không làm hồi quy những chức năng đã hoàn thành trong PR #70 trên Windows mục tiêu.

#### Issue #73 (`None`, `OPEN`, 0/8 → 0/8) — chore(release,windows): follow-up clean Windows VM acceptance, binary release & UQ 454104 licensing (#71)
- **Quyết định:** `LEGACY_V1_REMEDIATE` | `BLOCKED` — Giữ `AC1–AC8` `[ ]` (`BLOCKED / NOT VERIFIED`); gán milestone (`M7` hoặc `M6.7`) và cập nhật `AC7` theo `AIT-NDS-v2` (`CC BY 4.0`).
  - `AC1` (`[ ] → [ ]`, `KEEP`): **AC-03 (`DEFERRED / NOT VERIFIED`):** Ứng dụng hoạt động offline trên VM Windows 10/11 x64 sạch với tài khoản Standard User.
  - `AC2` (`[ ] → [ ]`, `KEEP`): **AC-07 (`DEFERRED / NOT VERIFIED`):** Kiểm thử người dùng mới, điều hướng bàn phím và DPI scaling (1366×768 / High-DPI) trên WebView2 thực tế.
  - `AC3` (`[ ] → [ ]`, `KEEP`): **AC-08 (`DEFERRED / NOT VERIFIED`):** Kiểm chứng tương tác GUI đầy đủ (drag-and-drop CSV từ File Explorer, Import, Analyze, Compare, Export, Security Dry-Run, cuộn chuột, theme, chuyển tab, `Shift+F9` Dev Logs) trên Windows mục tiêu.
  - `AC4` (`[ ] → [ ]`, `KEEP`): **AC-10 (`DEFERRED / NOT VERIFIED`):** Clean-machine Windows 10/11 x64 E2E PASS bằng installer thật (offline, Standard User, reboot Windows, uninstall sạch) qua luồng Controller (`--issue-vm-challenge`) → Target (`scripts/vm_target_e2e.ps1`) → Witness (`--sign-vm-witness`) → Controller (`--verify-target-evidence --clean-machine-e2e`).
  - `AC5` (`[ ] → [ ]`, `KEEP`): **AC-12 (`DEFERRED / NOT VERIFIED`):** Release attestation (`release_e2e_verification.json`) từ VM Windows độc lập cho ứng viên build từ `.github/workflows/release.yml` (`--require-stable-windows-e2e --verify-vm-witness`).
  - `AC6` (`[ ] → [ ]`, `KEEP`): **AC-13 (`DEFERRED / NOT VERIFIED`):** Nghiệm thu đầy đủ bộ binary release assets (`NetFlow-Sentinel-v*-windows-x64-setup.exe`, `SHA256SUMS.txt`, `release_e2e_verification.json`) từ workflow ứng viên.
  - `AC7` (`[ ] → [ ]`, `KEEP`): **AC-14 (`DEFERRED / NOT VERIFIED` — `BLOCKED`):** Căn cứ pháp lý / văn bản ủy quyền hợp lệ cho phân phối công khai các model `.joblib`, preprocessor và `demo_*.csv` dẫn xuất từ NF-UNSW-NB15-v3 (UQ License ID `454104`, DOI `10.48610/6E0EDA1`), cập nhật `reports/governance/DISTRIBUTION_AUTHORIZATION.json` (`approved=true`) và cấu hình secret `DISTRIBUTION_EVIDENCE_SHA256`.
  - `AC8` (`[ ] → [ ]`, `KEEP`): **AC-15 (`DEFERRED / NOT VERIFIED`):** Nghiệm thu đầy đủ parity toàn bộ chức năng PR #70 trên Windows 10/11 mục tiêu.



---

## 9. Kết quả Thực thi Đồng bộ Post-Remediation trên GitHub Issues (`2026-11-18`)

> [!NOTE]
> Các mục `1–8` phía trên ghi nhận snapshot điều tra Phase 0 trước khi khắc phục. Sau khi hoàn tất `Phases 1–10` và chạy full verification (`pytest`: `589 passed, 0 failed, 0 skipped`, `verify_companion_artifacts --verify-e2e` PASS, `ruff`/`black` 0 errors, Desktop/Rust checks PASS), danh sách checklist trên **68/88** Issue đang mở đã được đồng bộ qua `gh issue edit` mà **không đóng Issue, không sửa Milestone, không chạm Draft PR #156**.

### Thống kê Hậu Đồng bộ (`88` Open Issues — `282 / 372` Checkboxes `[x]`)

1. **Nhóm v2 Đạt Toàn bộ AC (`54/80` issues `#76–#155`, giữ `OPEN` chờ merge PR `#156` vào `main`):**
   `#77, #78, #79, #81, #84, #86, #87, #88, #89, #90, #91, #92, #93, #94, #95, #96, #98, #99, #100, #101, #102, #104, #105, #107, #110, #111, #112, #113, #114, #115, #116, #117, #118, #120, #121, #122, #124, #125, #126, #127, #129, #130, #131, #132, #133, #134, #136, #138, #139, #143, #144, #145, #146, #155`
   - *Ghi chú phạm vi:* `#104` (RQ3) và `#125` (RQ5) được đánh dấu `[x]` trên phạm vi **`SIMULATION`**, tách biệt rõ phần empirical `AIT` cross-source linkage đang `BLOCKED` ở `#85`.
   - `#139` và `#138` chỉ được đánh dấu `[x]` sau khi `svelte-check`/`vitest`/`cargo test` và toàn bộ `589/589` Python unit/contract/integration tests đều `PASS`.

2. **Nhóm v2 Còn AC Tồn đọng / Blocked (`22/80` issues):**
   - `#76` (`3/4`): Còn `AC4` (cột Milestone M6.1–M6.7 + tên issue tường minh trong bảng Gap Analysis).
   - `#80` (`3/4`): Còn `AC3` (active v2 cố ý hard-cutover từ chối 47-feature CSV; chỉ tag `v1.0.0` giữ nguyên trạng).
   - `#82` (`4/5`), `#83` (`3/4`): `UGR'16` `BLOCKED` (`HTTP 403`) & PR `#156` chờ merge.
   - `#85` (`2/3`): `AIT-NDS-v2 ↔ AIT-LDS-v2.1` direct UID alignment `BLOCKED`.
   - `#97` (`3/4`): Còn `AC4` (chú giải quan hệ không trùng với `#25/#48` trong `CTU_CROSS_SOURCE_EVAL.md`).
   - `#103` (`3/4`): Còn `AC3` (phân bố similarity chi tiết cho ngưỡng trong `BEHAVIORAL_ENGINE.md`).
   - `#106` (`3/4`): Còn `AC1` (CSV API hiện trả `behavioral_summary`, chưa trả full 16-D `BehavioralVector`).
   - `#108` (`3/4`), `#109` (`2/4`): Còn thực nghiệm phân bố risk thực tế & so sánh 4 chính sách aggregation trên cùng dataset.
   - `#119` (`3/4`), `#123` (`3/4`): Còn runbook sự cố keystore & backup/restore được kiểm thử độc lập.
   - `#135` (`3/4`): Còn log stress test `10,000` sự kiện dài hạn.
   - `#137` (`3/5`): Còn `AC1–AC2` (thiết bị router/switch vật lý & alert live GUI — hiện chỉ mới `ACCEPTED` ở mức **Synthetic UDP Loopback**).
   - `#140` (`3/4`), `#141` (`3/4`), `#142` (`3/4`): Còn stress UI dữ liệu lớn, nối `EntityBaselineProfiler` learned profile vào panel UI, và timeline nhiều giai đoạn từ dữ liệu thật.
   - `#147` (`3/4`), `#149` (`3/4`), `#150` (`2/4`), `#151` (`3/4`): Còn cross-run variance, installer rollback, unified clean-state demo timings, và deduplication note với `#18/#19`.
   - `#152` (`1/4`): Mới đạt `AC4` (không đưa raw dataset lên web); website `site-source` nằm ở nhánh ngoài phạm vi nhánh này.

3. **Nhóm v2 Giữ `0` Checkboxes (`4/80` issues):**
   - `#128` (`0/4`, Rust collector hoãn sau v2.0 — đã làm bằng Python collector), `#148` (`0/4`, Clean Windows 10/11 VM installer `BLOCKED`), `#153` (`0/4`, slide & PDF bảo vệ v2.0), `#154` (`0/4`, release signoff cuối `DISTRIBUTION_AUTHORIZATION.json` `approved: false`).

4. **Nhóm Kế thừa `M7` / `None` (`8` issues):**
   - `#18` (`1/8`), `#19` (`0/4`), `#20` (`1/6`), `#25` (`0/3`), `#48` (`0/3`), `#60` (`3/11`), `#71` (`6/15`), `#73` (`0/8`) đã được bỏ tick các mục v1 không còn hiệu lực hoặc chưa merge vào `main`.
