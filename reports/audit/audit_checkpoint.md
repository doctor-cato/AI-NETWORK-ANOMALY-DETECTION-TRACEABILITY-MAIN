# FORENSIC TECHNICAL AUDIT - CHECKPOINT TOÀN DIỆN TIẾN ĐỘ

> **HISTORICAL / SUPERSEDED.** Đây là checkpoint trung gian, không phải báo cáo cuối. Một số số liệu đã được đính chính trong Reports 01–14: “60 issues” thực tế là **41 issue + 19 PR**; 5 PR open gồm 2 non-draft (#50, #51) và 3 draft (#47, #49, #52); Autoencoder **có code trên PR #51 branch-only**, không phải “chưa code”; PR #51 **chưa merge**. Dùng `00-index.md` và Reports 01–14 làm kết luận chính thức.

- **Repository**: `doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`
- **Thời điểm Checkpoint**: `2026-11-10T02:08:00+07:00` (Giờ địa phương) / `2026-11-09T19:08:00Z` (UTC)
- **Baseline Commit**: `b212377a614aadbfb27eccff8d808c5b7dda551f` (PR #43: RF baseline protocol review fixes, fail-closed entrypoint)
- **Current HEAD SHA**: `b14dfeed9e7cbb07201cfb0ac8ce69c951434be1` (`origin/main`, branch `ViolaPeracia/AUDIT`)
- **Trạng thái thực thi**: **ĐÃ DỪNG LẠI TOÀN BỘ CÁC SUBAGENTS & LƯU TRỮ TRẠNG THÁI (STOPPED & CHECKPOINTED)**
- **Chế độ kiểm toán**: `STRICT READ-ONLY FORENSIC AUDIT` (Không có bất kỳ file tracked nào bị sửa đổi).

---

## 1. TỔNG QUAN TÌNH TRẠNG KIỂM TOÁN TẠI CHECKPOINT

| Thành phần | Phạm vi kiểm toán | Trạng thái hiện tại | Bằng chứng thực nghiệm thu thập |
|---|---|---|---|
| **Git Topology & Commits** | 38 commits từ baseline đến HEAD | **HOÀN THÀNH KHẢO SÁT 100%** | Đã lập chỉ mục 38/38 commits vào `commits_survey.json` & `commits_38.json` |
| **Pull Requests** | 19 PRs (13 merged, 1 closed, 2 open, 3 draft) | **HOÀN THÀNH KHẢO SÁT 100%** | Đã lập ma trận toàn bộ PRs và mổ xẻ chuyên sâu PR #51 (3 commits) |
| **Issues & Milestones** | 60 issues, 8 milestones (M0-M7) | **HOÀN THÀNH KHẢO SÁT 100%** | Đã trích xuất 60/60 issue bodies vào `issues_bodies.json` |
| **Data Engineering** | Tập dữ liệu thô NF-UNSW-NB15-v3 | **XÁC MINH PHÁP CHỨNG ĐẠT** | 2.365.424 dòng, SHA-256 `4ebb97bd...` khớp 100% BagIt manifest |
| **ML Scientific Validity** | Rủi ro Leakage & Shortcut Learning | **PHÁT HIỆN RỦI RO NGHIÊM TRỌNG** | `MIN_TTL`/`MAX_TTL` chiếm 45.48% importance; 1-feature DT đạt 99.98% Acc |
| **ML Models & Artifacts** | RF, XGBoost, Isolation Forest, Autoencoder | **PHÁT HIỆN THIẾU ARTIFACTS** | XGBoost thiếu artifact; Autoencoder chưa code; RF thiếu binary on-tree |
| **System Architecture** | Thực tế vs `docs/ARCHITECTURE.md` | **PHÁT HIỆN LỆCH PHA LỚN** | FastAPI, SQLite, Streamlit là "paper architecture", không có code trong `src/` |
| **CLI & Integration** | `predict.py`, `run_experiments.py` | **PHÁT HIỆN LỖI TÍCH HỢP** | `predict.py` không nhận `xgboost`; `run_experiments.py` trả Exit code 3 |
| **Test Suite & CI** | Toàn bộ pytest suite & GitHub Actions | **KIỂM TOÁN THỰC THI ĐẠT** | 739 passed (thuần synthetic/toy fixtures), 10 skipped, 13 warnings |
| **Bảo mật & An toàn** | Quét lỗ hổng, CWE-502, Supply Chain | **PHÁT HIỆN CWE-502** | Rủi ro deserialization không an toàn trong `inference/pipeline.py:44` |
| **12 Failure Scenarios** | Scenarios A đến L | **ĐÁNH GIÁ ĐỦ 12 KỊCH BẢN** | Đã có ma trận phân tích chi tiết cho cả 12 kịch bản tích hợp |

---

## 2. CÁC PHÁT HIỆN KỸ THUẬT QUAN TRỌNG NHẤT (CORE FORENSIC FINDINGS)

### 2.1. Phát hiện Khoa học ML: Shortcut Learning trên đặc trưng TTL nhân tạo (P0/P1)
- **Thực tế thực nghiệm**:
  - Dữ liệu thô `NF-UNSW-NB15-v3.csv` có 2.365.424 dòng. Phân tích thực nghiệm trên mô hình Random Forest cho thấy hai đặc trưng `MIN_TTL` và `MAX_TTL` chiếm tới **45,48% tổng độ quan trọng đặc trưng (feature importance)**.
  - Khi xây dựng một Decision Tree thử nghiệm chỉ sử dụng **duy nhất 1 đặc trưng `MIN_TTL`**, mô hình đạt độ chính xác phân loại nhị phân lên tới **99,98%**.
- **Ý nghĩa khoa học**:
  - TTL (Time To Live) trong tập dữ liệu UNSW-NB15 phản ánh khoảng cách số chặng mạng (hop count) giữa các máy ảo phát sinh tấn công và máy chủ thu thập trong môi trường lab IXIA CyberRange của Đại học New South Wales, chứ **không phải đặc tính nội tại của hành vi tấn công mạng**.
  - Các mô hình đạt điểm F1 ~0.99 thực chất đang học thuộc lòng kiến trúc topo mạng của phòng thí nghiệm tạo dữ liệu (Shortcut Learning), dẫn đến nguy cơ suy giảm hoàn toàn khi triển khai trên mạng thực tế.

### 2.2. Lệch pha kiến trúc: Tài liệu Roadmap vs Mã nguồn thực tế (P1/P2)
- **Tài liệu công bố (`docs/ARCHITECTURE.md`)**: Mô tả hệ sinh thái hoàn chỉnh gồm Web API (`FastAPI`), giao diện Dashboard (`Streamlit`), cơ sở dữ liệu (`SQLite Repositories`), mã hóa (`AES GCM Storage`), bộ máy tương quan (`Correlation & Risk Engine`), và vectơ hành vi (`Behavioral Vector`).
- **Mã nguồn thực tế (`src/`)**: Chỉ tồn tại duy nhất package `network_anomaly/` phục vụ các script ML dòng lệnh (preprocessing, training, scoring, CLI inference). **Hoàn toàn không có bất kỳ dòng mã nào** của FastAPI, Streamlit, SQLite hay AES GCM. Đây là kiến trúc trên giấy tờ chưa được hiện thực hóa.

### 2.3. Hiện trạng các Mô hình ML & Artifacts
- **Random Forest (Baseline M2)**: Code và giao thức huấn luyện hoàn thiện tại `src/network_anomaly/models/random_forest.py`. Manifest kiểm tra băm SHA-256 đầy đủ, tuy nhiên file binary mô hình `.joblib` bị `.gitignore` nên các test kiểm tra tải model thật trong CI đều bị SKIPPED.
- **XGBoost (PR #40 / Issue #31)**: Code mô hình đã được merge vào `src/network_anomaly/models/xgboost_model.py`. Tuy nhiên, **file artifact mô hình hoàn toàn không tồn tại** trên đĩa. Ngoài ra, CLI `scripts/predict.py:50-73` không nhận diện đối số `--model xgboost`, gây crash `FileNotFoundError`.
- **Autoencoder (PR #51 / Issue #29)**: Chưa được merge vào default branch. Vẫn đang nằm trên nhánh riêng `feat/issue-29-autoencoder-unknown-attack` và chưa có artifact huấn luyện nào.
- **Isolation Forest (PR #41)**: Code có sẵn nhưng chưa được đối chiếu chuẩn hóa artifact.

### 2.4. Bản chất của 739 Test PASS trong Test Suite
- Thực thi lệnh: `python -m pytest -q` trả về: `739 passed, 10 skipped, 13 warnings in 126.66s` (Exit code: 0).
- **Bản chất**: Cả 739 test này đều chạy trên **fixtures nhân tạo nhỏ (20–50 dòng ngẫu nhiên)** hoặc chỉ kiểm tra việc khởi tạo đối tượng class mà không fit/predict dữ liệu. Không có test nào đo lường benchmark hay performance thật trên tập dữ liệu `NF-UNSW-NB15-v3`.
- **10 test bị SKIPPED**: Đều là các test yêu cầu dữ liệu thật, artifact mô hình thật hoặc báo cáo `REAL_DATA_SMOKE_REPORT.md` — minh chứng rằng CI xanh không đồng nghĩa với việc pipeline thật đã chạy thông suốt.

### 2.5. Phát hiện An ninh: CWE-502 Unsafe Deserialization
- Tại `src/network_anomaly/inference/pipeline.py:44`: Hàm nạp mô hình sử dụng `joblib.load()` mà không có cơ chế kiểm tra chữ ký số hoặc mã băm cryptographic integrity bắt buộc trước khi giải tuần tự hóa. Nếu kẻ tấn công thay thế model binary trên đĩa, có thể dẫn đến thực thi mã tùy ý (RCE).

---

## 3. TÀI NGUYÊN PHÁP CHỨNG ĐÃ ĐƯỢC BẢO LƯU (STATE ASSETS)

Toàn bộ các file dữ liệu phân tích chi tiết của giai đoạn khảo sát và lập chỉ mục đã được lưu trữ an toàn trong repository (không bị git track):

```
.agents/teamwork/
├── PROJECT.md                                                # Kiến trúc mục tiêu & ma trận 14 deliverables
├── ORIGINAL_REQUEST.md                                       # Yêu cầu kiểm toán gốc
├── explorer_survey_1/
│   ├── handoff.md                                           # Báo cáo chi tiết khảo sát Git/PR/Issue (39 KB)
│   ├── commits_survey.json                                  # Dữ liệu phân tích 38 commits (112 KB)
│   └── baseline_commit.json                                 # Chi tiết baseline commit b212377a
├── explorer_survey_2/
│   └── handoff.md                                           # Báo cáo chi tiết Data Engineering & ML (21 KB)
├── explorer_survey_3/
│   └── handoff.md                                           # Báo cáo chi tiết Kiến trúc, Test, Security (25 KB)
├── worker_m1_git_governance/
│   ├── commits_38.json                                      # Chi tiết từng commit từ baseline đến HEAD (57 KB)
│   ├── prs_all.json & prs_matrix_19.json                    # Toàn bộ 19 PRs đã ánh xạ (27 KB)
│   ├── issues_all.json & issues_bodies.json                 # Nội dung chi tiết 60 Issues (712 KB)
│   ├── milestones_all.json                                  # 8 Milestones M0-M7 (18 KB)
│   └── pr51_details.json                                    # Phân tích chuyên sâu PR #51 (26 KB)
└── interviewer/
    └── prompt_draft.md                                      # Task prompt đã được phê duyệt
```

---

## 4. QUY TRÌNH TIẾP TỤC KIỂM TOÁN (RESUMPTION PROCEDURE)

Khi bạn muốn tiếp tục quá trình kiểm toán từ điểm dừng này:
1. Bạn chỉ cần yêu cầu: *"Tiếp tục kiểm toán từ checkpoint"* hoặc chạy lệnh thực hiện từng báo cáo cụ thể (Report 01 đến Report 14).
2. Toàn bộ dữ liệu 38 commits, 19 PRs, 60 issues, bằng chứng shortcut learning và kết quả test đã sẵn sàng trong `.agents/teamwork/` và `PROJECT.md` — không cần phải quét lại từ đầu, tiết kiệm thời gian và tài nguyên context.
3. Nhóm có thể trực tiếp sinh 14 báo cáo kiểm toán chuyên sâu lưu tại `reports/audit/` theo đúng cấu trúc đã thống nhất.
