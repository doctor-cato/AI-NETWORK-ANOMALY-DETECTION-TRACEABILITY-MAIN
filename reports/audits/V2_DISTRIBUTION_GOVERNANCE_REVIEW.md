# Báo cáo Kiểm toán Quản trị Phân phối & Bản quyền — NetFlow Sentinel v2.0 (`V2_DISTRIBUTION_GOVERNANCE_REVIEW.md`)

- **Vai trò thực hiện:** Agent F — Kiểm toán viên Quản trị Phân phối & Bản quyền (`Distribution Authorization & Licensing Governance Auditor`) *(đồng bộ hậu kiểm PR `#156` ngày `2026-11-18`)*
- **Ngày kiểm toán:** `2026-11-18` (`UTC+7`)
- **Nhánh / Commit kiểm toán:**
  - **Historical Implementation Snapshots:** `feat/v2-integration` @ `a6c87ae8397e466ab1bd3d19f82d880e71084b88` (CI **Run `#211` / ID `44278751854`**, `7/7` `SUCCESS`) và `5483794160e877bf2d65144f30fd1ffc181372c3` (CI **Run `#212` / ID `44312426631`**, `7/7` `SUCCESS`; `1` submitted review `CHANGES_REQUESTED` bởi `ViolaPeracia`), kèm đợt khắc phục `P1-01`/`P2-02`/`P2-03`/`P3-01`/`P3-02` tiếp theo trên `feat/v2-integration`.
  - **Model Training Provenance (Tách biệt):** `training_git_commit = 79ebb678b87de19cc6b664b587726983fecaf98f`, `git_dirty = true`, `git_clean = false`, `DIRTY_DISCLOSED` (giữ nguyên trung thực; `4/4` model tiers giữ `RESEARCH_ONLY`; `DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false`).
- **Phương pháp:** Đọc trực tiếp toàn bộ hồ sơ bản quyền, manifest dữ liệu, manifest 4 mô hình + preprocessor + demo, `scripts/verify_companion_artifacts.py`, cấu hình Tauri/Cargo/npm/PyInstaller, CI/Release workflows và chạy lệnh kiểm chứng read-only. Không chỉnh sửa [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](../governance/DISTRIBUTION_AUTHORIZATION.json), không giả mạo phê duyệt và không thay đổi mã nguồn.

---

## 1. Tóm tắt Điều hành & Phán quyết Phân phối

| Phạm vi / Kênh mục tiêu | Trạng thái Hiện tại | Điều kiện & Giới hạn Áp dụng |
|---|---|---|
| **Nghiên cứu & Đánh giá Cục bộ (`research-only` / `local_offline`)** | **`PASS / APPROVED`** | Hợp lệ với bộ `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE` hiện có; không tải/upload artifact ra ngoài. |
| **Đóng gói Nội bộ Cục bộ hoặc Repo Riêng tư (`private-build-only`, `non-commercial-controlled`)** | **`APPROVED` *(cục bộ / private CI verified)*** | Chạy được trên `local_offline`, hoặc `private_ci_artifact` **chỉ khi** GitHub API xác nhận `repo_is_private=true`. Tuyệt đối **chặn** nếu repo ở chế độ `public`. |
| **Phát hành Công khai (`public-release-approved`, `public_ci_artifact`, `public_github_release`)** | **`BLOCKED (`HOLD_FOR_MAINTAINER_SIGNOFF`)`** | Cổng `verify_distribution_permission()` **fail-closed (exit code `1`)** vì `public_release_authorization.approved = false`, `status = "HOLD_FOR_MAINTAINER_SIGNOFF"`, `maintainer_approver = null`, `approved_at_utc = null`, `evidence_sha256 = null`. Ngoài ra vẫn còn các điểm chặn kỹ thuật/pháp lý trước phát hành công khai (xem Mục 5 & Mục 6). |

**Kết luận cốt lõi về cách ly `CC BY-NC-SA 4.0`:** Toàn bộ `4` mô hình ML (`random_forest`, `xgboost`, `isolation_forest`, `autoencoder`), `v2_flow_preprocessor.joblib` và bộ demo `data/demo/demo_*.csv` được huấn luyện/fit/trích xuất **100% từ `AIT-NDS-v2` (`CC BY 4.0`, DOI `10.5281/zenodo.13168643`)**. Dữ liệu log máy chủ `AIT-LDS-v2.1` (`CC BY-NC-SA 4.0`, DOI `10.5281/zenodo.19483937`) chỉ nằm trong hai tệp nén gốc `.gitignored` tại `data/raw/ait_lds_v2_1/` và **hoàn toàn không tham gia** vào pipeline chia tập, fit preprocessor, huấn luyện mô hình hay tạo bộ demo. Do đó, các trọng số mô hình và bộ cài nhị phân hiện tại **không bị nhiễm ràng buộc `NonCommercial-ShareAlike` (`NC-SA`)**.

---

## 2. Ma trận Ranh giới Giấy phép (License Boundary Matrix)

### 2.1. Mã nguồn, Hạ tầng Đóng gói & Thư viện Phụ thuộc

| Thành phần | Phạm vi | Giấy phép Thực tế Xác minh | Nguồn Bằng chứng | Nghĩa vụ & Lưu ý Tuân thủ |
|---|---|---|---|---|
| **Mã nguồn NetFlow Sentinel** | `src/`, `desktop/`, `scripts/`, `docs/`, `tests/` | **Apache License 2.0** (`Apache-2.0`) | [`LICENSE`](../../LICENSE), [`pyproject.toml`](../../pyproject.toml#L10) | Phải kèm `LICENSE` và `NOTICE` khi tái phân phối Source hoặc Object form (Điều 4(a), 4(d) Apache-2.0). **Lưu ý:** `LICENSE:1` hiện vẫn ghi placeholder `Copyright 2026 [Project Team / Course Assignment — placeholder; replace with actual owner if known]`. |
| **Python Runtime (Sidecar)** | Nhúng trong `netflow-sentinel-backend.exe` | **PSF License Agreement** (`CPython 3.12.10`) | [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md#L22) | Giữ nguyên thông báo bản quyền PSF trong `THIRD_PARTY_NOTICES.md`. |
| **PyInstaller** | Toolchain đóng gói sidecar (`[packaging]`) | **GPL-2.0-or-later with Bootloader Exception** | [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md#L23), [`scripts/build_backend_sidecar.py`](../../scripts/build_backend_sidecar.py) | Nhờ **Bootloader Exception**, việc đóng gói mã ứng dụng Apache-2.0 bằng bootloader PyInstaller nguyên bản không kéo toàn bộ ứng dụng sang GPL-2.0; không được sửa mã nguồn bootloader mà bỏ qua nghĩa vụ GPL. *(Ghi chú: `pyinstaller` hiện không cài trong `.venv` cục bộ).* |
| **Python Runtime Dependencies** | `requirements-runtime.txt` (nhúng vào sidecar) | `FastAPI 0.163.1` (**MIT**), `Uvicorn 0.54.0` (**BSD-3-Clause**), `Pydantic 2.14.3` (**MIT**), `NumPy 2.5.5` (**BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0**), `Pandas 3.1.1` (**BSD-3-Clause**), `scikit-learn 1.9.1` (**BSD-3-Clause**), `XGBoost 3.4.1` (**Apache-2.0**), `joblib 1.6.0` (**BSD-3-Clause**), `cryptography 50.0.2` (**Apache-2.0 OR BSD-3-Clause**), `httpx 0.28.1` (**BSD-3-Clause**) | [`requirements-runtime.txt`](../../requirements-runtime.txt), [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md#L24-L33), metadata wheel trong `.venv` | Toàn bộ là permissive licenses tương thích với `Apache-2.0`. Cần giữ danh sách attribution/copyright notices trong `THIRD_PARTY_NOTICES.md` khi phân phối nhị phân. |
| **Python Dev / EDA Dependencies** | `pyproject.toml` (`matplotlib`, `seaborn`, `pytest`, `jupyter`, `ruff`, `black`, `mypy`) | `pytest 9.2.0` (**MIT**), `matplotlib 3.11.2` (**PSF-based Matplotlib License**), `seaborn 0.13.2` (metadata wheel ghi `UNKNOWN`; BSD-3-Clause trên repo gốc) | [`pyproject.toml`](../../pyproject.toml#L31-L47), [`scripts/build_backend_sidecar.py`](../../scripts/build_backend_sidecar.py#L28-L47) | Bị loại trừ tường minh khỏi PyInstaller sidecar qua `EXCLUDED_MODULES` (`tkinter`, `matplotlib`, `seaborn`, `torch`, `jupyter`, `pytest`, `black`, `ruff`, `mypy`, v.v.) nên không đi vào bộ cài phân phối. |
| **Rust / Tauri 2 Crates** | `desktop/src-tauri/` (`Cargo.toml`, `Cargo.lock`, `427` crates phụ thuộc ngoài app) | Direct crates: `tauri 2.12.5` (**Apache-2.0 OR MIT**), `tauri-plugin-dialog 2.8.4` (**Apache-2.0 OR MIT**), `serde 1.0.229` (**MIT OR Apache-2.0**), `serde_json 1.0.154` (**MIT OR Apache-2.0**), `reqwest 0.13.5` (**MIT OR Apache-2.0**), `tokio 1.54.1` (**MIT**), `getrandom 0.4.3` (**MIT OR Apache-2.0**), `tauri-build 2.7.4` (**Apache-2.0 OR MIT**). Transitive crates: **0** crate thiếu license hoặc GPL/AGPL thuần; gồm **7** transitive crates **`MPL-2.0`** (`cssparser 0.37.0/0.38.0`, `cssparser-macros 0.7.1`, `dtoa-short 0.3.5`, `option-ext 0.2.0`, `selectors 0.38.0/0.41.0`), **2** crates `MIT OR Apache-2.0 OR LGPL-2.1-or-later` (chọn `MIT`/`Apache-2.0`), phần còn lại `MIT` / `Apache-2.0` / `BSD-3-Clause` / `ISC` / `Unicode-3.0` / `Zlib` / `Unlicense` / `CC0-1.0` / `0BSD` / `BSL-1.0`. | [`desktop/src-tauri/Cargo.toml`](../../desktop/src-tauri/Cargo.toml), [`desktop/src-tauri/Cargo.lock`](../../desktop/src-tauri/Cargo.lock), `cargo metadata --offline` | Tương thích phân phối nhị phân dưới `Apache-2.0`. **Khoảng trống nhỏ:** `THIRD_PARTY_NOTICES.md` mới nêu `Tauri 2`, chưa liệt kê các direct Rust crates và `7` transitive `MPL-2.0` crates (theo MPL-2.0 mục 3.2, nên bổ sung thông báo nơi lấy mã nguồn MPL-2.0 gốc nếu phát hành nhị phân công khai). |
| **Svelte 5 / npm Frontend** | `desktop/package.json`, `package-lock.json` (`143` packages) | `122 MIT`, `13 Apache-2.0 OR MIT`, `4 Apache-2.0`, `2 ISC`, `1 BSD-3-Clause`, `1 0BSD` (`svelte ^5.20.0`, `@tauri-apps/api ^2.2.0`) | [`desktop/package.json`](../../desktop/package.json), [`desktop/package-lock.json`](../../desktop/package-lock.json), [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md#L35) | Toàn bộ permissive; các `devDependencies` (`vite`, `vitest`, `typescript`, `svelte-check`) chỉ chạy lúc build/test. |
| **Microsoft Edge WebView2 Runtime** | Nhúng offline installer trong NSIS | **Microsoft Software License Terms** | [`desktop/src-tauri/tauri.conf.json`](../../desktop/src-tauri/tauri.conf.json#L34-L37), [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md#L36) | Cấu hình `"webviewInstallMode": {"type": "offlineInstaller", "silent": true}` nhúng trực tiếp trình cài Microsoft WebView2 vào NSIS setup; cần bảo đảm tuân thủ điều khoản phân phối lại WebView2 của Microsoft khi phát hành công khai. |

### 2.2. Bộ Dữ liệu (Datasets) & Artifact Phái sinh

| Dataset | Publisher & DOI | Giấy phép Xác minh | Vai trò Thực tế trong v2 | Ranh giới Phân phối & Thương mại |
|---|---|---|---|---|
| **`AIT-NDS-v2`** *(AIT NetFlow Data Set v2, sinh từ PCAP `AIT-LDS-v2.0`)* | AIT Austrian Institute of Technology GmbH · DOI `10.5281/zenodo.13168643` | **CC BY 4.0** | Nguồn huấn luyện/đánh giá duy nhất của Preprocessor, `4` model `.joblib` (`RF`, `XGB`, `IF`, `AE`) và `200` flows demo (`data/demo/`). | Cho phép tái phân phối công khai & thương mại các artifact phái sinh (`forbids_commercial_use: false`) **với điều kiện bắt buộc** giữ nguyên thông tin ghi công (`NOTICE`, `THIRD_PARTY_NOTICES.md`, DOI). |
| **`CTU-SME-11`** | Stratosphere Laboratory, CTU Prague · Concept DOI `10.5281/zenodo.7958258` / Version `10.5281/zenodo.7958259` | **CC BY 4.0** | Đánh giá chéo nguồn thực tế (`ctu_echo`, `ctu_windows7ad`); không nằm trong trọng số của 4 model phát hành mặc định hay `data/demo/`. | Cho phép ghi nhận và công bố kết quả/báo cáo công khai khi giữ nguyên attribution tới Stratosphere Laboratory (CTU Prague) và DOI. |
| **`AIT-ADS`** *(AIT Alert Data Set, sinh từ `AIT-LDS-v2.0`)* | AIT Austrian Institute of Technology GmbH · DOI `10.5281/zenodo.8263181` | **CC BY 4.0** | Đối chiếu cảnh báo Wazuh/AMiner & attack time windows (`profile_multi_source.py`); **không** đi vào trọng số ML hay `data/demo/`. | Xác nhận chính xác là **CC BY 4.0** tại [`data/AIT_DATASETS_MANIFEST.json`](../../data/AIT_DATASETS_MANIFEST.json#L19), [`data/EXTERNAL_DATASETS_PROVENANCE.json`](../../data/EXTERNAL_DATASETS_PROVENANCE.json#L20), [`NOTICE`](../../NOTICE#L34), [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md#L12). |
| **`AIT-LDS-v2.1`** *(AIT Log Data Set v2.1)* | AIT Austrian Institute of Technology GmbH · DOI `10.5281/zenodo.19483937` | **CC BY-NC-SA 4.0** | Lưu mẫu `fox_no-pcaps.zip` và `russellmitchell_no-pcaps.zip` cục bộ để kiểm đếm file và đối chiếu khả năng liên kết (`direct_uid_join_possible: false`). | **Cấm thương mại (`NC`) & lây lan ShareAlike (`SA`)**. Bất kỳ trọng số, preprocessor, bộ demo hay bản build nào chứa/dẫn xuất trực tiếp từ `AIT-LDS-v2.1` đều phải áp dụng CC BY-NC-SA 4.0 và bị cấm phân phối thương mại. **Hiện tại được cách ly hoàn toàn (xem Mục 3).** |
| **`UGR'16`** | NESG (`https://nesg.ugr.es/nesg-ugr16/`) | Chưa thể chấp nhận (`BLOCKED`) | Dự kiến đánh giá domain shift ISP | Cổng NESG trả **`HTTP 403`** (*Portal en Mantenimiento*); không tải, không có dữ liệu giả lập thay thế. |
| **`NF-UNSW-NB15-v3`** *(Legacy v1)* | University of Queensland · DOI `10.48610/6E0EDA1` | **UQ License ID `454104`** | Đã loại bỏ hoàn toàn khỏi active pipeline (`hard cutover`); chỉ lưu metadata/report chỉ đọc dưới `*/historical/nf_unsw_nb15_v3/`. | Không được đóng gói vào `staged_bundle` hoặc tái sử dụng trong v2 (`load_verified_model` từ chối fail-closed v1). |

---

## 3. Kiểm chứng Cách ly `AIT-LDS-v2.1` (`CC BY-NC-SA 4.0`) & Kiểm tra Rò rỉ Git

### 3.1. Tại sao `CC BY-NC-SA 4.0` có nguy cơ lây nhiễm và cơ chế bảo vệ của hệ thống

1. **Ràng buộc pháp lý của `CC BY-NC-SA 4.0`:**
   - **NonCommercial (NC):** Cấm mọi hành vi sử dụng hoặc tái phân phối nhằm mục đích chủ yếu hướng tới lợi ích thương mại hoặc bồi hoàn tài chính. Nếu một mô hình ML hoặc bộ cài desktop được huấn luyện trên `AIT-LDS-v2.1` hoặc nhúng trích đoạn log của `AIT-LDS-v2.1`, bản phân phối đó không còn đủ điều kiện cấp phép thương mại mở theo Apache-2.0 / CC BY 4.0.
   - **ShareAlike (SA):** Mọi *Adapted Material* (tác phẩm phái sinh như vector đặc trưng trích trực tiếp từ log, trọng số mô hình huấn luyện từ log đó, hoặc bộ dataset trích xuất) khi chia sẻ lại bắt buộc phải đặt dưới cùng giấy phép `CC BY-NC-SA 4.0` (hoặc giấy phép tương thích được CC công nhận), xung đột trực tiếp với mô hình phân phối `Apache-2.0` + `CC BY 4.0` (`forbids_commercial_use: false`) của NetFlow Sentinel v2.
2. **Bằng chứng xác minh 0% `AIT-LDS-v2.1` xâm nhập vào Training, Preprocessing và Demo CSV:**
   - **Split & Preprocessor (`scripts/build_v2_dataset_and_split.py`):** Script chỉ đọc `data/raw/ait_nds_v2/*_netflows.zip` và `data/raw/ctu_sme_11_extracted/**/conn.log.labeled` (`lines 66-67`). Hàm `dataset_sha256` (`lines 513-516`) được băm từ 8 tệp zip của `AIT-NDS-v2`, cho ra `cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf` ghi trong [`data/V2_SPLIT_MANIFEST.json`](../../data/V2_SPLIT_MANIFEST.json#L5). `TrainOnlyPreprocessor` (`asinh_robust`) chỉ fit trên `2,097,891` dòng `AIT-NDS-v2` Train (`fox`, `harrison`, `santos`, `wardbeck`, `wilson`), cho ra `v2_flow_preprocessor.joblib` (`SHA-256: 0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7`) ghi tại [`reports/preprocessing/v2_flow_preprocessing_manifest.json`](../../reports/preprocessing/v2_flow_preprocessing_manifest.json#L4-L8,L81,L93).
   - **Cả 4 Model Manifests (`reports/models/*_manifest.json`):** Khớp 100% chuỗi băm nguồn `AIT-NDS-v2`:
     - **Random Forest** (`v2-rf-20261117T231214Z`): `dataset_name = "AIT-NDS-v2"`, `dataset_provenance = "AIT-NDS-v2 (10.5281/zenodo.13168643); Train={fox,harrison,santos,wardbeck,wilson}"`, `dataset_sha256 = cc7553...`, `split_manifest_sha256 = ed542e...`, `preprocessor_artifact_sha256 = 0866dec7...`.
     - **XGBoost** (`v2-xgb-20261117T231609Z`): `dataset_name = "NetFlow-Sentinel-v2-MultiSource"`, `dataset_provenance = "AIT-NDS-v2 (10.5281/zenodo.13168643); Train={fox,harrison,santos,wardbeck,wilson}"`, `dataset_sha256 = cc7553...`, `split_manifest_sha256 = ed542e...`, `preprocessor_artifact_sha256 = 0866dec7...`. *(Ghi chú: khác tên trường `dataset_name` so với 3 model còn lại nhưng provenance & digest hoàn toàn là `AIT-NDS-v2`).*
     - **Isolation Forest** (`v2-if-20261118T020525Z`): `dataset_name = "AIT-NDS-v2"`, `dataset_provenance = "AIT-NDS-v2 (10.5281/zenodo.13168643); Benign-only Train={fox,harrison,santos,wardbeck,wilson}"`, `dataset_sha256 = cc7553...`, `split_manifest_sha256 = ed542e...`, `preprocessor_artifact_sha256 = 0866dec7...`.
     - **Autoencoder** (`v2-ae-20261118T020635Z`): `dataset_name = "AIT-NDS-v2"`, `dataset_provenance = "AIT-NDS-v2 (10.5281/zenodo.13168643); Benign-only Train={fox,harrison,santos,wardbeck,wilson}"`, `dataset_sha256 = cc7553...`, `split_manifest_sha256 = ed542e...`, `preprocessor_artifact_sha256 = 0866dec7...`.
   - **Demo Files (`data/demo/`):** `scripts/prepare_demo_dataset.py` lấy mẫu `200` dòng (`100` Benign / `100` Attack) **duy nhất từ `ait_val.csv.gz` (`AIT-NDS-v2`, kịch bản `russellmitchell`)**, `train_overlap_count = 0`, `test_overlap_count = 0` ([`data/demo/demo_manifest.json`](../../data/demo/demo_manifest.json#L4-L18)). Kiểm tra trực tiếp `demo_flows.csv` và `demo_labels.csv` xác nhận chỉ chứa flow metrics `canonical-flow-v2-18` + `row_id`/`5-tuple`/`timestamp_ms` và nhãn flow từ `AIT-NDS-v2`, không có bất kỳ log host nào.
   - **Cách dùng thực tế của `AIT-LDS-v2.1` trong codebase:** Quét toàn bộ `scripts/`, `src/`, `docs/`, `reports/` cho thấy chỉ `scripts/fetch_multi_source_dataset.py` (xác minh SHA-256/MD5 tệp nén) và `scripts/profile_multi_source.py:450-455` (đọc `ZipFile.namelist()` để đếm số tệp `16,094` và `14,898`) từng chạm vào `data/raw/ait_lds_v2_1/`. **Không có bất kỳ trích đoạn nội dung host log (`auth.log`, `dns`, `apache`, `audit`) nào từ `AIT-LDS-v2.1` được trích xuất, lưu trong `reports/`, `docs/`, `src/` hay đóng gói vào bundle.**

### 3.2. Kiểm tra `.gitignore` và Trạng thái Theo dõi Git

- Thư mục `data/raw/ait_lds_v2_1/` hiện chứa 2 tệp nén (`fox_no-pcaps.zip` `688,586,900 B`, `russellmitchell_no-pcaps.zip` `522,084,364 B`) được kiểm tra qua `git check-ignore -v`:
  - `.gitignore:4:data/raw/*` khớp trực tiếp với cả 2 tệp trong `data/raw/ait_lds_v2_1/`.
  - `git ls-files data/` xác nhận `data/raw/` chỉ track duy nhất `data/raw/.gitkeep`; `data/demo/` chỉ track `data/demo/.gitkeep`; `artifacts/` chỉ track `artifacts/.gitkeep`.
- **Tình trạng tài liệu hóa giấy phép `AIT-LDS-v2.1`:** Kiểm tra trực tiếp các tài liệu hiện hành (`README.md:33`, `docs/DATASET.md:10`, `docs/DEPLOYMENT_GUIDE_V2.md:80`, `docs/WINDOWS_INSTALLATION.md:3,41`, `docs/TRACEABILITY_MATRIX.md:10`, `docs/RELEASE_PROCESS.md:29`, `docs/ETHICS_AND_PRIVACY.md:5`, `docs/releases/v2.0.0.md:23`) cho thấy toàn bộ đã được cập nhật ghi đúng `AIT-LDS-v2.1` là **`CC BY-NC-SA 4.0`** (những nhầm lẫn ghi `CC BY 4.0` được nêu trong các audit cũ trước đây đã được khắc phục trên working tree).

---

## 4. Kiểm toán Chi tiết `reports/governance/DISTRIBUTION_AUTHORIZATION.json`

### 4.1. Cấu trúc & Giá trị Trường Hiện tại

Qua đọc trực tiếp [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](../governance/DISTRIBUTION_AUTHORIZATION.json) (59 dòng):

- **Header tổng thể (`lines 2-8`):**
  - `schema_version`: `2`
  - `dataset`: `"NetFlow-Sentinel-v2-MultiSource"`
  - `dataset_publisher`: `"AIT Austrian Institute of Technology GmbH & Stratosphere Laboratory (CTU)"`
  - `dataset_doi`: `"10.5281/zenodo.13168643"`
  - `dataset_license_id`: `"CC-BY-4.0"`
  - `dataset_license_title`: `"Creative Commons Attribution 4.0 International (CC BY 4.0)"`
  - `dataset_license_grants_derived_public_redistribution`: `true`
- **4 Tầng quyền (`permission_tiers`, `lines 9-36`):**
  1. `research_only` (`scope: "research-only"`): `public_upload_allowed: false`, `public_release_allowed: false`.
  2. `private_build_only` (`scope: "private-build-only"`): `public_upload_allowed: false`, `private_ci_upload_allowed: true`, `public_release_allowed: false`.
  3. `non_commercial_controlled` (`scope: "non-commercial-controlled"`): `public_upload_allowed: false`, `private_ci_upload_allowed: true`, `public_release_allowed: false`.
  4. `public_release_approved` (`scope: "public-release-approved"`): `public_upload_allowed: true`, `public_release_allowed: true`.
- **Khối phê duyệt phát hành công khai (`public_release_authorization`, `lines 37-58`):**
  - `approved`: **`false`**
  - `status`: **`"HOLD_FOR_MAINTAINER_SIGNOFF"`**
  - `legal_basis`: `"verified-open-redistribution-license"` *(thuộc `APPROVED_PUBLIC_LEGAL_BASES` trong `verify_companion_artifacts.py:115-121`)*
  - `maintainer_approver`: **`null`**
  - `approved_at_utc`: **`null`**
  - `evidence_ref`: `"CC BY 4.0 (AIT-NDS-v2 DOI 10.5281/zenodo.13168643)"`
  - `evidence_sha256`: **`null`**
  - `forbids_commercial_use`: `false`
  - `requires_attribution_notices`: `true`
  - `covered_artifacts`: 8 đường dẫn (`v2_flow_preprocessor.joblib`, 4 `.joblib` model, `demo_flows.csv`, `demo_labels.csv`, `demo_manifest.json`).
  - `notes`: `"AIT-NDS-v2 and CTU-SME-11 are CC BY 4.0; AIT-LDS-v2.1 (CC BY-NC-SA 4.0) is excluded from trained ML artifacts and demo CSVs."`

### 4.2. Phân định Được phép vs Đang bị chặn

| Kịch bản / Mục tiêu | Được phép? | Cơ sở Kiểm soát |
|---|---|---|
| Chạy nghiên cứu, đánh giá mô hình, UI demo cục bộ (`research-only` + `local_offline`) | **ĐƯỢC PHÉP** | `verify_distribution_permission()` trả `APPROVED` (`upload_allowed: false`, `public_release_allowed: false`). |
| Stage bundle / build NSIS installer nội bộ trên máy phát triển cục bộ (`private-build-only` + `local_offline`) | **ĐƯỢC PHÉP** | `verify_distribution_permission()` trả `APPROVED` (`upload_allowed: false`, `public_release_allowed: false`). |
| Build & upload CI artifact nội bộ trên GitHub Actions với **private repository** đã xác nhận qua `gh api` (`private-build-only` hoặc `non-commercial-controlled` + `private_ci_artifact` + `--repo-private true`) | **ĐƯỢC PHÉP** | Trả `APPROVED` với `upload_allowed: true`, `public_release_allowed: false` (vẫn chặn `gh release create`). |
| Phát hành mã nguồn không kèm nhị phân/model (`release_mode=source-only` trong `.github/workflows/release.yml:206-220, 671-723`) | **ĐƯỢC PHÉP** *(khi clean tree & đủ release notes)* | Kiểm tra không track `.joblib`, `setup.exe`, `netflow-sentinel-backend*.exe`, `demo_*.csv` trên Git; chỉ phát hành source + `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`. |
| Upload workflow artifact lên **public repo** (`public_ci_artifact`), kể cả dry-run | **BỊ CHẶN (`BLOCKED`)** | `private-build-only`/`non-commercial-controlled` cấm kênh công khai; `public-release-approved` bị chặn vì `approved=false`, `status="HOLD_FOR_MAINTAINER_SIGNOFF"`, `evidence_sha256=null`. |
| Đóng gói trọng số 4 mô hình + `demo_*.csv` vào NSIS installer để phát hành rộng rãi trên **Public GitHub Release** (`public_github_release`) | **BỊ CHẶN (`BLOCKED`)** | Bắt buộc phải có signoff của Maintainer trong `DISTRIBUTION_AUTHORIZATION.json` (`approved=true`, `status="APPROVED"`, `maintainer_approver`, `approved_at_utc`, `evidence_sha256`) và khớp `secrets.DISTRIBUTION_EVIDENCE_SHA256` + Clean Windows VM attestation. |
| Sử dụng chuỗi phạm vi cũ `non-commercial-academic-approved` | **BỊ CHẶN (`BLOCKED`)** | `verify_companion_artifacts.py:467-473` từ chối fail-closed với thông báo `NOT legal evidence`. |

---

## 5. Kiểm toán Vận hành `scripts/verify_companion_artifacts.py` & Kết quả Thực đo

### 5.1. Cơ chế Kiểm tra Kỹ thuật & Bảo mật Fail-Closed

1. **Xác minh SHA-256 toàn bộ Companion Artifacts (`verify_companion_artifacts()`):**
   - Kiểm tra `v2_flow_preprocessor.joblib` qua `load_verified_preprocessor()` (`src/network_anomaly/inference/predict.py`): khớp SHA-256 với `v2_flow_preprocessing_manifest.json` và `split_manifest_sha256`.
   - Kiểm tra lần lượt 4 mô hình (`random_forest`, `xgboost`, `isolation_forest`, `autoencoder`) qua `load_verified_model()`: khớp `model_artifact_sha256`, `feature_contract_version == "canonical-flow-v2-18"`, `preprocessor_artifact_sha256 == prep_sha`, cross-check `score_normalization.json` cho AE, không cho phép artifact/manifest v1 hoặc model thiếu metadata.
   - Kiểm tra bộ `data/demo/`: yêu cầu `sampling.partition == "validation"`, `train_overlap_count == 0`, `test_overlap_count == 0`, khớp `split_manifest_sha256` và khớp SHA-256 của `demo_flows.csv` & `demo_labels.csv` với `demo_manifest.json`.
   - **Không** chạm vào `data/raw/ait_lds_v2_1/` và khi `stage_companion_bundle()` / `stage_embedded_bundle()` chạy, hệ thống kiểm đếm và đóng gói **`20` `companion_files`** (đã bổ sung `artifacts/ml/ood_reference_gate.json` `8a52bfe5...` và `artifacts/models/autoencoder/score_normalization.json` `d7bcb78f...` trong đợt WP5) + `6` tệp `EMBEDDED_EXTRA_FILES_REL` (`V2_SPLIT_MANIFEST.json`, `AIT_DATASETS_MANIFEST.json`, `CTU_SME_11_MANIFEST.json`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`), rồi ghi `EMBEDDED_SHA256SUMS.txt` và `EMBEDDED_ARTIFACTS_MANIFEST.json` kèm kiểm tra `ood_gate.status == "FITTED"`.
2. **Xác minh Quyền Phân phối (`verify_distribution_permission()`):**
   - Kiểm tra sự tồn tại và nội dung không rỗng của `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`, đồng thời bắt buộc có cả 3 chuỗi `_REQUIRED_NOTICE_MARKERS` (`"AIT NetFlow Data Set v2"`, `"10.5281/zenodo.13168643"`, `"CTU-SME-11"`) trong `NOTICE` và `THIRD_PARTY_NOTICES.md`.
   - Kiểm tra header của `DISTRIBUTION_AUTHORIZATION.json`: `schema_version in (1, 2)`, `dataset == "NetFlow-Sentinel-v2-MultiSource"`, `dataset_license_id in {"CC-BY-4.0", "CC BY 4.0"}`, `dataset_doi == "10.5281/zenodo.13168643"`.
   - Nếu `norm_scope == "public-release-approved"` hoặc kênh công khai (`public_ci_artifact`, `public_github_release`): bắt buộc `approved is True`, `status == "APPROVED"`, `legal_basis in APPROVED_PUBLIC_LEGAL_BASES`, `maintainer_approver` & `evidence_ref` không rỗng, `approved_at_utc` đúng chuẩn ISO-8601, `evidence_sha256` đúng 64 ký tự hex, `requires_attribution_notices is True`, `forbids_commercial_use` là `bool`, `covered_artifacts` bao phủ đủ 8 artifact bắt buộc, và nếu `require_evidence_hash=True` phải có biến môi trường đối chiếu khớp hằng thời gian (`hmac.compare_digest`).
3. **Tích hợp trong `.github/workflows/release.yml`:**
   - Gate chạy fail-closed **trước** bước tải/stage mô hình (`lines 268-288`), kiểm tra lại lần nữa trước `gh release create` (`lines 569-580`), không dùng `rust-cache` để tránh rò rỉ tài nguyên model qua Actions Cache (`lines 411-412`), và luôn chạy bước dọn `build/`, `staged_bundle/`, `binaries/`, `target/release/{artifacts,data,bundle}`, `dist/` với `if: always()` (`lines 725-738`).

### 5.2. Xác minh SHA-256 Thực tế của `8` `covered_artifacts`

Tất cả `8` artifact liệt kê trong `public_release_authorization.covered_artifacts` đều tồn tại trên đĩa và khớp 100% SHA-256 giữa file thật, model/preprocessor/demo manifests và đầu ra `verify_companion_artifacts.py`:

| STT | Artifact trong `covered_artifacts` | Kích thước (bytes) | SHA-256 Thực đo trên Đĩa | Khớp Manifest & Verifier |
|---:|---|---:|---|---|
| 1 | `artifacts/preprocessing/v2_flow_preprocessor.joblib` | `1,673` | `0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7` | **PASS** (`v2_flow_preprocessing_manifest.json`) |
| 2 | `artifacts/models/random_forest/random_forest_baseline.joblib` | `12,445,660` | `b2e42f85f2625f5bf04902a032a4db734f4c4e744d45f4fef3ddffd05a694f2f` | **PASS** (`random_forest_manifest.json`) |
| 3 | `artifacts/models/xgboost/xgboost_baseline.joblib` | `249,182` | `33d201f8f3d842c0b71547532c74f3d107bd402d8a65e20241ff5f407723aa48` | **PASS** (`xgboost_manifest.json`) |
| 4 | `artifacts/models/isolation_forest/isolation_forest.joblib` | `925,957` | `11b1690088bca1984df9280b3c5662fbb13a76ca31e55258b9de43d6a10a6885` | **PASS** (`isolation_forest_manifest.json`) |
| 5 | `artifacts/models/autoencoder/autoencoder_model.joblib` | `25,581` | `e6afecefdc939a09e3c7fedd3e994a10c404f74e9b52c9ab95dfd984aae0cd4f` | **PASS** (`autoencoder_manifest.json`) |
| 6 | `data/demo/demo_flows.csv` | `36,151` | `90b028939c36e84cf43eb9595e6d74ee9fc0f2d03c40f46d439f1886f50d01a3` | **PASS** (`demo_manifest.json`) |
| 7 | `data/demo/demo_labels.csv` | `6,923` | `9332ddd7513350f04ece64ee5ac9256948880a712e1d9741e7684d92b9daff9e` | **PASS** (`demo_manifest.json`) |
| 8 | `data/demo/demo_manifest.json` | `9,229` | `235dce5720d5e5ac9bbb843f38e6cf99cd444c1c8812cf1526d2f26451781fbd` | **PASS** (`verify_companion_artifacts.py`) |

*(Xác minh thêm: 4 tệp sidecar `artifacts/models/*/*_manifest.json` trùng khớp 100% SHA-256 theo byte với `reports/models/*_manifest.json`).*

### 5.3. Kết quả Thực thi Read-Only `verify_companion_artifacts.py`

| Lệnh Kiểm tra Read-Only | Exit Code | Trạng thái / Kết quả Thực đo |
|---|---|---|
| `.\.venv\Scripts\python.exe scripts/verify_companion_artifacts.py --verify-distribution-permission research-only --target-channel local_offline` | `0` | **`PASS` (`status: "APPROVED"`):** `upload_allowed: false`, `public_release_allowed: false`, `dataset_license: "CC-BY-4.0"`, `citation_doi: "10.5281/zenodo.13168643"`, `notices_verified: ["NOTICE", "THIRD_PARTY_NOTICES.md", "LICENSE"]`. |
| `... --verify-distribution-permission public-release-approved --target-channel public_github_release` | `1` | **`BLOCKED` (đúng kỳ vọng fail-closed):** `[DISTRIBUTION PERMISSION BLOCKED] ... Public distribution of v2 derived models/demo CSV is NOT authorized (status='HOLD_FOR_MAINTAINER_SIGNOFF', approved=False).` |
| `... --verify-distribution-permission research-only --target-channel public_github_release` | `1` | **`BLOCKED`:** `Scope 'research-only' is restricted to target_channel='local_offline', cannot target 'public_github_release'.` |
| `... --verify-distribution-permission private-build-only --target-channel local_offline` | `0` | **`PASS` (`status: "APPROVED"`):** `upload_allowed: false`, `public_release_allowed: false`. |
| `... --verify-distribution-permission private-build-only --target-channel private_ci_artifact` *(không có `--repo-private true`)* | `1` | **`BLOCKED`:** `Refusing 'private-build-only' artifact upload because repository privacy is not verified private (repo_is_private=None).` |
| `... --verify-distribution-permission private-build-only --target-channel private_ci_artifact --repo-private true` | `0` | **`PASS` (`status: "APPROVED"`):** `upload_allowed: true`, `public_release_allowed: false`. |
| `... --verify-distribution-permission private-build-only --target-channel public_ci_artifact` | `1` | **`BLOCKED`:** `Scope 'private-build-only' forbids public channel 'public_ci_artifact'`. |
| `... --verify-distribution-permission non-commercial-controlled --target-channel private_ci_artifact --repo-private true` | `0` | **`PASS` (`status: "APPROVED"`):** `upload_allowed: true`, `public_release_allowed: false`. |
| `... --verify-distribution-permission non-commercial-academic-approved --target-channel local_offline` | `1` | **`BLOCKED`:** `Legacy string 'non-commercial-academic-approved' is NOT legal evidence...` |
| `.\.venv\Scripts\python.exe scripts/verify_companion_artifacts.py` | `0` | **`READY` (`4/4` models, `preprocessor: READY`) / `OOD Gate: PARTIAL_UNANCHORED` (khi không truyền external expected SHA):** Liệt kê `20` `companion_files` *(gồm `ood_reference_gate.json` & AE `score_normalization.json`)*; OOD kiểm chứng `structural_schema_verified: true`, `preprocessor_linkage_verified: true`, `trusted_digest_verified: false` nếu thiếu `--expect-ood-gate-sha256` / `NETFLOW_OOD_GATE_SHA256` / `NETFLOW_EMBEDDED_OOD_GATE_SHA256`. |
| `.\.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only` | `0` | **`PASS` (read-only) / `BLOCKED` (`UGR16`):** `10 AIT-NDS-v2`, `2 AIT-LDS-v2.1`, `2 AIT-ADS`, `4 CTU-SME-11` file(s) khớp digest; `UGR16=BLOCKED`. |

### 5.4. Các Phát hiện Quản trị & Đóng gói Cần lưu ý trước Release

1. **Dirty Worktree Provenance trên cả 4 Model Manifests (`P1` cho Release):** Cả `RF`, `XGB`, `IF`, `AE` đều ghi `environment.git`: `git_commit: "79ebb678b87de19cc6b664b587726983fecaf98f"`, `git_dirty: true`, `git_clean: false`, `worktree_provenance: "DIRTY_DISCLOSED"` (`172–199` đường dẫn dirty lúc train). Trong khi đó, `.github/workflows/release.yml:99-103, 515` kiểm tra clean tree và truyền `--require-clean-git`. Trước khi phát hành công khai, mã nguồn phải được commit sạch lên `main`, và bundle 4 mô hình/preprocessor/demo cần được xác minh hoặc tái huấn luyện lại từ đúng commit sạch đó.
2. **Placeholder Bản quyền trong `LICENSE` & `pyproject.toml` (`P1` cho Public Release):** `LICENSE:1` vẫn là `Copyright 2026 [Project Team / Course Assignment — placeholder; replace with actual owner if known]`, và `pyproject.toml:12-13` ghi `authors = [{name = "Project Team", email = "example@institution.edu"}]`.
3. **Thông tin `v1.0.0` trong `docs/RELEASE_PROCESS.md` & `.github/workflows/release.yml` (`[FIXED ON WORKING TREE]`):** Đã được sửa trên working tree ở cụm remediation (`RELEASE_PROCESS.md:92` & `release.yml:12,312`).
4. **Cấu hình `desktop/src-tauri/tauri.standalone.conf.json` (`[FIXED ON WORKING TREE]`):** Đã sửa mục `isolation_forest` (`isolation_forest.joblib` + `isolation_forest_manifest.json`) và bổ sung `ood_reference_gate.json` + AE `score_normalization.json` vào `bundle.resources`, đồng bộ với `20` `companion_files` trong `verify_companion_artifacts.py`. Vẫn phụ thuộc merge `bundle.resources` từ `tauri.conf.json` cho `NOTICE` / `THIRD_PARTY_NOTICES.md` / `LICENSE` — cần xác minh trên NSIS installed directory bằng `verify_installed_standalone_layout()` khi build `.exe` (`#148`).
5. **Độ phủ của `THIRD_PARTY_NOTICES.md` & `_REQUIRED_NOTICE_MARKERS`:** Direct Rust crates và transitive `MPL-2.0` Rust crates đã được bổ sung vào `THIRD_PARTY_NOTICES.md` trên working tree; `_REQUIRED_NOTICE_MARKERS` trong `scripts/verify_companion_artifacts.py` kiểm `"AIT NetFlow Data Set v2"`, `"10.5281/zenodo.13168643"`, `"CTU-SME-11"`.

---

## 6. Checklist Từng bước cho Maintainer Signoff & Sẵn sàng Phát hành Công khai

Trước khi người duy trì / chủ sở hữu pháp lý (`Human Maintainer / Legal Owner`) chuyển trạng thái sang cho phép phân phối công khai (`public_github_release`), **tất cả các bước sau phải được thực hiện tuần tự và xác minh bằng chứng thực tế**:

1. **Hoàn thiện Pháp lý & Thông báo Bản quyền (`LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`):**
   - [ ] Thay thế placeholder tại [`LICENSE`](../../LICENSE#L1) (`[Project Team / Course Assignment — placeholder; ...]`) và [`pyproject.toml`](../../pyproject.toml#L12-L13) bằng tên chủ sở hữu bản quyền và liên hệ chính thức của dự án.
   - [x] Rà soát sơ bộ [`NOTICE`](../../NOTICE) và [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) (ghi công **CC BY 4.0**, loại trừ `AIT-LDS-v2.1` `CC BY-NC-SA 4.0`, bổ sung Rust direct + `MPL-2.0` transitive crates, sửa `RELEASE_PROCESS.md:92` và `tauri.standalone.conf.json` trên working tree); **chờ đối chiếu lại WebView2 redistribution & commit sạch lên `main` trước release công khai**.

2. **Đóng băng Commit Sạch & Xác minh Zero `NC-SA` / Zero Raw Data:**
   - [ ] Commit toàn bộ thay đổi vào nhánh chuẩn và merge sạch vào `main` (`git status --porcelain` trống, `git diff --check` exit `0`).
   - [ ] Tái tạo/tái xác minh `v2_flow_preprocessor.joblib`, `4` mô hình và `data/demo/` trên **commit sạch đó** để `environment.git.git_dirty = false` và `git_clean = true` trong toàn bộ `reports/models/*_manifest.json`.
   - [ ] Chạy kiểm tra xác nhận **zero dữ liệu `CC BY-NC-SA 4.0` hoặc dữ liệu raw** được theo dõi hoặc đóng gói:
     - `git ls-files` không chứa `*.joblib`, `*.exe`, `data/raw/*` (trừ `.gitkeep`), `data/processed/*` (trừ `.gitkeep`), `data/demo/demo_*.csv`.
     - Toàn bộ `4` model manifests + `v2_flow_preprocessing_manifest.json` + `demo_manifest.json` chỉ tham chiếu `AIT-NDS-v2` (`dataset_sha256: cc7553...` và `split_manifest_sha256` khớp bản sạch).

3. **Build & Kiểm chứng Đóng gói Installer + Nghiệm thu Máy Windows Sạch (`#73`, `#148`):**
   - [ ] Tạo gói staged embedded (`--stage-embedded-dir`) và build NSIS installer (`release.yml` dry-run từ commit sạch trên private repository/runner hoặc build kiểm chứng có kiểm soát).
   - [ ] Kiểm tra trực tiếp thư mục cài đặt sau khi chạy NSIS installer (`verify_installed_standalone_layout()`): xác nhận `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`, `data/AIT_DATASETS_MANIFEST.json`, `data/CTU_SME_11_MANIFEST.json`, `data/V2_SPLIT_MANIFEST.json`, `EMBEDDED_ARTIFACTS_MANIFEST.json`, `EMBEDDED_SHA256SUMS.txt` và `4` model + preprocessor + `demo_*.csv` đều hiện diện đầy đủ trong thư mục cài đặt (và có thể truy cập từ người dùng cuối), **không** có bất kỳ tệp nào từ `data/raw/ait_lds_v2_1/` hay `historical/nf_unsw_nb15_v3/`.
   - [ ] Hoàn tất quy trình **Controller ↔ Clean Windows 10/11 VM** (`--issue-vm-challenge`, `scripts/vm_target_e2e.ps1`, `--sign-vm-witness`, `--verify-target-evidence` + `consumed_nonces_file`) cho cả `windows_10_x64` và `windows_11_x64`, đạt `--require-stable-windows-e2e`.

4. **Tạo Bằng chứng Ủy quyền & Ký Duyệt `DISTRIBUTION_AUTHORIZATION.json`:**
   - [ ] Maintainer / Chủ sở hữu pháp lý lập biên bản/hồ sơ phê duyệt phát hành công khai (ghi rõ đối chiếu điều khoản `CC BY 4.0` của `AIT-NDS-v2`, `CTU-SME-11`, `Apache-2.0`, `PyInstaller Bootloader Exception`, `MPL-2.0`, `WebView2`, xác nhận `0%` `AIT-LDS-v2.1` trong bundle), lưu giữ hồ sơ kiểm toán ngoài repo công khai (hoặc tài liệu lưu trữ nội bộ) và tính toán mã băm **SHA-256 (64 ký tự hex)** của tệp bằng chứng ủy quyền đó.
   - [ ] Cập nhật khối `public_release_authorization` trong [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](../governance/DISTRIBUTION_AUTHORIZATION.json) bằng một commit có review trên `main`:
     - `"approved": true`
     - `"status": "APPROVED"`
     - `"legal_basis": "verified-open-redistribution-license"` *(hoặc giá trị hợp lệ trong `APPROVED_PUBLIC_LEGAL_BASES`)*
     - `"maintainer_approver": "<tên / email / GitHub handle người phê duyệt>"`
     - `"approved_at_utc": "<ISO-8601 UTC timestamp>"`
     - `"evidence_ref": "<Mã hồ sơ / tham chiếu văn bản phê duyệt CC BY 4.0 & notice compliance>"`
     - `"evidence_sha256": "<64-hex SHA-256 của bằng chứng phê duyệt>"`
     - Kiểm tra `covered_artifacts` khớp toàn bộ 8 artifact hiện hành (`preprocessor`, `4` models, `3` demo files).
   - [ ] Cấu hình GitHub Repository Secrets & Variables cho workflow `.github/workflows/release.yml`:
     - `secrets.DISTRIBUTION_EVIDENCE_SHA256` = đúng giá trị `evidence_sha256` 64-hex ở trên.
     - `vars.ALLOW_EMBEDDED_MODEL_REDISTRIBUTION` = `"public-release-approved"`.
     - `vars.RELEASE_MODE` = `"windows-binary"` (khi đã sẵn sàng phát hành installer; giữ `"source-only"` nếu chỉ phát hành mã nguồn).
     - `vars.VERIFIED_WINDOWS_CANDIDATE_RUN_ID`, `secrets.VERIFIED_WINDOWS_VM_ATTESTATION`, `secrets.NETFLOW_VM_ATTESTATION_HMAC_KEY`, `vars.MODEL_BUNDLE_URL` / `MODEL_ARTIFACT_RUN_ID`, `vars.MODEL_BUNDLE_SHA256`.

5. **Kiểm tra Cổng Phân phối Trước khi Gắn Tag Phát hành (`refs/tags/v2.0.0`):**
   - [ ] Xác minh cục bộ/CI vượt qua fail-closed gate:
     ```powershell
     .\.venv\Scripts\python.exe scripts/verify_companion_artifacts.py --verify-distribution-permission public-release-approved --target-channel public_github_release --evidence-sha256-env DISTRIBUTION_EVIDENCE_SHA256 --require-evidence-hash --public-release
     ```
   - [ ] Đảm bảo `docs/releases/v2.0.0.md` khớp chính xác chế độ phát hành thực tế (`Source Release` vs `Standalone Windows x64 Release`) và đính kèm `NOTICE`, `THIRD_PARTY_NOTICES.md`, `SHA256SUMS.txt` cùng attestation lên GitHub Release.
