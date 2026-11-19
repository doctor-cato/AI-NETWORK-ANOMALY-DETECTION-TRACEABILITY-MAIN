# Đánh giá Mức độ Sẵn sàng Phát hành — NetFlow Sentinel v2.0 (`V2_RELEASE_READINESS.md`)

> **Phạm vi Kiểm toán:** Issue `#154` (v2.0 Release Readiness) & Issue `#20` (M7 System-Wide QA Gate)
>
> **Nhánh & Mốc Tham chiếu:** `feat/v2-integration` · PR `#156` (pushed HEAD `93416ed` / CI Run `44544489397` `7/7 SUCCESS` + bản vá review-remediation & bộ hồ sơ bảo vệ `#153`)
>
> **Phiên bản Sản phẩm:** Desktop Tauri/Svelte `2.0.0` · FastAPI Contract `0.1.0`

---

## 1. Phán quyết Phân tầng Sẵn sàng Phát hành (4-Tier Readiness Verdict)

Thay vì gộp chung một nhãn nhị phân gây hiểu lầm, mức độ sẵn sàng của **NetFlow Sentinel v2.0** được phân tách minh bạch thành **4 tầng độc lập**:

| Tầng Sẵn sàng (*Readiness Tier*) | Trạng thái Phán quyết | Căn cứ Xác minh & Điều kiện Ràng buộc |
|---|---|---|
| **1. Academic Thesis Defense & Research Submission** *(Bảo vệ Đồ án & Nộp Hồ sơ Nghiên cứu — `#153`)* | **`READY`** | Hoàn tất trọn vẹn 4 tài liệu bảo vệ (`docs/thesis/RESEARCH_REPORT_V2.md`, `docs/thesis/DEFENSE_SLIDES_V2.md`, `docs/thesis/DEFENSE_QA_V2.md`, `docs/audits/V2_RELEASE_READINESS.md`); `RQ1–RQ6` có báo cáo JSON/MD đầy đủ kèm kết quả âm tính trung thực (`H2=False`, `AE H4=False`, `RQ3 L2=False`). |
| **2. Controlled Lab / Local Offline Prototype** *(Thử nghiệm Lab Có kiểm soát & Chạy Cục bộ)* | **`READY_WITH_LIMITS`** | `verify_companion_artifacts.py --verify-distribution-permission research-only --target-channel local_offline` trả **`APPROVED`** (`exit 0`, `public_release_allowed = false`); `4/4 REAL_MODELS` tải thành công ở chế độ `"deployment"` khi cấp `NETFLOW_OOD_GATE_SHA256`; Synthetic UDP Loopback (`#137`) & Replay (`65/65` flows) đạt `PASS`. Giới hạn: `real_device_tested = false`, `4/4 RESEARCH_ONLY`. |
| **3. Clean Windows VM Standalone Binary Installer** *(Bộ cài NSIS Độc lập trên Windows Sạch — `#148` / `#73`)* | **`DEFERRED / UNVERIFIED`** | Đã hoàn tất staging `ood_reference_gate.json` & `score_normalization.json` vào `tauri.standalone.conf.json` (`20` companion files) và cập nhật `vm_target_e2e.ps1:457`; nhưng **chưa** build PyInstaller v2 + NSIS (`pyinstaller`/`makensis` vắng trên môi trường dev) và **chưa** chạy kiểm định Clean Windows 10/11 VM Standard User (`#148`: `0/4 AC`). |
| **4. Public Binary Release / Production Deployment** *(Phát hành Công khai & Triển khai Sản xuất — `#154`)* | **`BLOCKED`** | `reports/governance/DISTRIBUTION_AUTHORIZATION.json` giữ **`approved = false`** (`status = "HOLD_FOR_MAINTAINER_SIGNOFF"`); `4/4` mô hình `E0` giữ `deployment_tier = "RESEARCH_ONLY"` (`cross_source_validated = false`, `production_ready = false`); `training_git_commit = 79ebb678` giữ `git_dirty = true`. |

---

## 2. Sổ Kiểm chứng Kỹ thuật & Governance Trước Cổng Phát hành

| Trục Kiểm tra | Kết quả | Bằng chứng & Giới hạn Thực tế |
|---|---|---|
| **Git & PR `#156` Governance** | `OPEN / BLOCKED` | PR `#156` (`isDraft: false`) tại `93416ed` có CI Run `44544489397` đạt `7/7 SUCCESS`, nhưng còn `1` review `CHANGES_REQUESTED` (`ViolaPeracia` từ `5483794`) và `mergeStateStatus = BLOCKED`; bản vá review-remediation cần commit & CI run mới trước khi review lại. |
| **Artifact & Companion Integrity** | `PASS` / `PARTIAL_UNANCHORED` | `verify_companion_artifacts.py` xác nhận `20` tệp companion, `4/4` model `.joblib`, preprocessor `0866dec7...`, split `ed542ee8...`, AE `score_normalization.json` (`d7bcb78f...`) và cross-check `reports/ml/ood_reference_gate_manifest.json`; báo `PARTIAL_UNANCHORED` khi thiếu external `NETFLOW_OOD_GATE_SHA256`. |
| **Distribution & License Gate** | `PASS (local_offline)` / `BLOCKED (public)` | `100%` model `E0` và `demo_*.csv` dùng `AIT-NDS-v2` (`CC BY 4.0`); `AIT-LDS-v2.1` (`CC BY-NC-SA 4.0`) cách ly `.gitignored` (`0%` rò rỉ). Còn placeholder tại `LICENSE:1` và `pyproject.toml:12-13` cần xử lý trước phát hành công khai. |
| **Runtime Security & Fail-Closed OOD** | `PASS` | Toàn bộ entry points (`backend.rs`, `run_api.py`, `create_app`, `LiveRuntime`, `RealtimeInferenceEngine`) mặc định `"deployment"`, yêu cầu `X-Sentinel-Session-Token`, khóa `UNAVAILABLE` nếu thiếu `NETFLOW_OOD_GATE_SHA256`, và khóa `ResponsePolicy` ở `dry_run = True` (`executed = false`). |
| **Test Suite & Contract Parity** | `PASS` | HEAD `93416ed` (CI Run `44544489397`) + bản vá review-remediation: `670+` pytest, `41/41` Vitest (`desktop-frontend`), `11/11` Rust (`cargo test --lib`), `export_openapi_spec.py --check`, `check_desktop_version.py --check`; `raw dataset integrity` trên CI giữ `SKIPPED` do không chứa raw archive trong runner. |
| **Physical Lab & External Datasets** | `BLOCKED` | `UGR'16` trả `HTTP 403`; liên kết UID `AIT-NDS-v2 ↔ AIT-LDS-v2.1` (`#85`) `DIRECT_UID_LINK = False`; nghiệm thu router/switch vật lý (`#137`) `real_device_tested = false`. |

---

## 3. Đối chiếu Kế thừa các Legacy Milestone M7 Issues (`#18, #19, #20, #25, #48, #60, #71`)

Để đảm bảo truy vết liên tục từ lộ trình v1 (`M7`) sang hệ thống v2 (`M6.1–M6.7`), bảng dưới đây ánh xạ đầy đủ từng issue di sản sang các issue và bằng chứng v2 tương ứng:

| Legacy Issue (M7 / v1) | Nội dung Gốc | Issue / Artifact Kế thừa trong v2 | Trạng thái Hiện tại |
|---|---|---|---|
| **`#18`** | Tài liệu kỹ thuật, giấy phép & provenance | **`#151`** (`ARCHITECTURE_V2.md`, `DATASET.md`, `EVALUATION.md`), **`#152`** (`site-source`, `DEFERRED`), [`V2_DISTRIBUTION_GOVERNANCE_REVIEW.md`](../../reports/audits/V2_DISTRIBUTION_GOVERNANCE_REVIEW.md) | `VERIFIED` (tài liệu v2 & governance); `#152` `DEFERRED` |
| **`#19`** | Báo cáo nghiên cứu, slide bảo vệ, demo & handoff | **`#153`** (`docs/thesis/{RESEARCH_REPORT_V2,DEFENSE_SLIDES_V2,DEFENSE_QA_V2}.md`, `PRESENTATION_OUTLINE.md`), **`#150`** (demo guide) | **`READY`** (bộ 4 văn bản bảo vệ; `.pptx`/`.pdf` để mở cho nhu cầu trình chiếu ngoài repo) |
| **`#20`** | Kiểm toán tổng thể hệ thống & Release Readiness | **`#154`** & [`docs/audits/V2_RELEASE_READINESS.md`](V2_RELEASE_READINESS.md), [`reports/audits/V2_FINAL_AUDIT.md`](../../reports/audits/V2_FINAL_AUDIT.md) | **`HOLD / BLOCKED`** cho public release; **`READY`** cho bảo vệ |
| **`#25`** | Thực thi 7 thực nghiệm & benchmark đa nguồn | **`#94–#98`**, **`#104`**, **`#125`**, **`#126`**, **`#145`** (`RQ1–RQ6`, `CTU-SME-11`, `E1`, `Stage-2`, `WP3`) | **`EXPERIMENTALLY VALIDATED`** (kèm báo cáo trung thực `H2=False`, `AE H4=False`) |
| **`#48`** *(PR `#49`)* | Cross-dataset generalization & `MIN_TTL` ablation trên v1 | Đóng băng chỉ đọc tại [`docs/historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md`](../historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md); kế thừa sang **`#94`**, **`#97`** (`CTU_CROSS_SOURCE_EVAL.md`) | `VERIFIED` (hard cutover v2 & đánh giá `CTU-SME-11` / `E1`) |
| **`#60`** | Consolidated remediation & cổng an ninh/QA | **`#146`** (`SECURITY_AUDIT_V2.md`, `THREAT_MODEL_V2.md`, fail-closed `"deployment"` OOD gate, SHA-256 verification) | `VERIFIED` (cổng bảo mật & kiểm thử tự động `PASS`) |
| **`#71`** *(kèm `#73`)* | Bộ cài Windows x64 Standalone & Clean VM E2E | **`#148`** (NSIS v2.0, `tauri.standalone.conf.json`, `vm_target_e2e.ps1`); UQ `454104` đã thay bằng `CC BY 4.0` | **`DEFERRED / NOT VERIFIED`** (chưa build NSIS & test Clean VM) |

---

## 4. Điều kiện Tiên quyết để Mở khóa Phát hành Công khai (`BLOCKED -> READY`)

Để chuyển tầng **Public Binary Release (`#154`)** từ `BLOCKED` sang đủ điều kiện phát hành, cần hoàn tất tuần tự 5 điều kiện sau:
1. **Commit sạch & Re-review PR `#156`:** Hợp nhất các bản vá cục bộ, chạy đầy đủ CI trên GitHub Actions (`7/7 SUCCESS`, công bố `-rs`) và hoàn tất review gỡ `CHANGES_REQUESTED`.
2. **Loại bỏ `git_dirty: true` (`F-03`):** Gắn hoặc tái huấn luyện/tái xác minh 4 mô hình `E0` và `demo_*.csv` trên một commit sạch của `main`.
3. **Trusted Build-Time OOD Anchor & Legal Metadata:** Thay thế placeholder `LICENSE:1` và `pyproject.toml:12-13`; truyền `NETFLOW_OOD_GATE_SHA256` độc lập lúc build Tauri (`build.rs` `option_env!`).
4. **Nghiệm thu Clean Windows 10/11 VM (`#148`):** Build PyInstaller v2 sidecar + NSIS installer và chạy `vm_target_e2e.ps1` + `--sign-vm-witness` dưới tài khoản Standard User.
5. **Maintainer Signoff (`#154`):** Maintainer/Legal Owner ký duyệt `DISTRIBUTION_AUTHORIZATION.json` (`approved: true`, điền `maintainer_approver`, `approved_at_utc`, `evidence_sha256`) và cấu hình `secrets.DISTRIBUTION_EVIDENCE_SHA256`.
