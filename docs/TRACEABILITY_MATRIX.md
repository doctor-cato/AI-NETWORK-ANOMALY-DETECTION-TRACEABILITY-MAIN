# Ma trận truy vết — Requirement → Issue → Deliverable → Acceptance Criteria → Verification

Nguồn chuẩn: `docs/REQUIREMENTS.md` (F01–F08, N01–N07), `docs/PROJECT_CHARTER.md`, và Acceptance Criteria
viết trong từng GitHub Issue. Ma trận này là cách kiểm chứng duy nhất được dùng để đóng issue; tồn tại file
không phải bằng chứng chức năng chạy được.

Quy ước trạng thái: `PASS` = đã chạy lệnh và đạt · `SKIPPED` = cố ý bỏ qua vì thiếu dataset ·
`NOT VERIFIED` = chưa chạy / chưa đủ bằng chứng · `OPTIONAL` = không chặn core.

Trạng thái trong bảng là kết quả local trên máy Windows (Python 3.14.6) của lượt hoàn thiện M0. Trạng thái
CI được cập nhật ở `FINAL_REPORT.md` sau khi commit đã push lên remote.

## A. Yêu cầu lõi (core) — bắt buộc để chấp nhận

| Req | Yêu cầu | Issue | Deliverable | Acceptance Criteria (rút gọn từ issue) | Cách kiểm chứng | Trạng thái M0 |
|---|---|---|---|---|---|---|
| R01 (F01) | Tải và kiểm tra schema UNSW-NB15 | #4, #5 | `docs/DATASET.md`, `scripts/validate_data.py` | Fixture hợp lệ đạt; fixture sai thất bại kèm exit code; thiếu dữ liệu = SKIPPED | `python scripts/validate_data.py`; `python -m pytest tests/unit/test_validate_data.py -q` | PASS (fixture) / SKIPPED (dữ liệu thật) |
| R02 (F02) | Phân tích nhãn, phân bố lớp, duplicates, missing | #6 | Notebook EDA + diễn giải | Có nguồn, lệnh, thứ tự chạy và diễn giải mất cân bằng/missing/duplicates | Notebook + mô tả bằng chứng | NOT VERIFIED (cần dataset, M1) |
| R03 (F03) | Tiền xử lý không rò rỉ: chia trước, fit trên train | #7, #8 | Quyết định split; pipeline + artifact | Test chứng minh chỉ train tham gia fit | `pytest` cho pipeline (chưa có, M2) | NOT VERIFIED (M2) |
| R04 (F04) | Baseline Random Forest với siêu tham số đã ghi | #9, #10 | Protocol + artifact + log | Training trên UNSW-NB15 đã xác minh; cấu hình tái chạy được | `python scripts/run_experiments.py --step baseline` (hiện exit 3) | NOT VERIFIED (M2) |
| R05 (F05) | Đánh giá: Precision, Recall, F1, Macro-F1, confusion matrix, FPR | #12 | Bảng metric + confusion matrix | Metric đúng trên fixture; kết quả thật có manifest | `pytest` cho `evaluation/metrics.py`; `compute_metrics` **chưa có FPR** → thuộc #12 | NOT VERIFIED (M3) |
| R06 (F07) | Pipeline suy luận cho dữ liệu mới | #15 | Entrypoint inference + CSV | Artifact load/predict; CSV giữ quan hệ row → prediction | `python scripts/run_experiments.py --step inference` (hiện exit 3) | NOT VERIFIED (M4) |
| R07 (F08) | Hướng dẫn chạy thực nghiệm tái lập | #3, #14 | `docs/REPRODUCIBILITY.md`, `scripts/` | Lệnh trong hướng dẫn được chạy thật; chưa chạy được ghi NOT VERIFIED | Xem mục D | PASS cho lệnh M0; phần M1–M4 NOT VERIFIED |
| R08 (objective 8, `docs/PROJECT_CHARTER.md`) | Phân tích dương tính giả / âm tính giả và hạn chế | #13 | Mục phân tích lỗi | FP/FN nhất quán confusion matrix; đề xuất cải thiện ghi là hướng tương lai | Chưa có — cần confusion matrix thật | NOT VERIFIED (M3) |
| R09 (N01) | Mã nguồn dưới `src/network_anomaly/`, gọi được từ script | #3 | Package cài editable | Import và cài đặt đạt | `python -m pip install -e .`; `python -c "import network_anomaly"` | PASS |
| R10 (N02) | Python 3.11+; dependency tối thiểu; ghi phiên bản môi trường | #3 | `pyproject.toml`, `requirements.txt`, CI matrix | CI chạy trên 3.11 và 3.12 | CI matrix `ubuntu/windows × 3.11/3.12` | NOT VERIFIED — CI đã cấu hình, xem `FINAL_REPORT.md` |
| R11 (N03) | Không hardcode đường dẫn tuyệt đối | #3 | `config.py` dùng `pathlib` tương đối | Không có đường dẫn máy cá nhân trong mã nguồn | `git grep -nE '[A-Za-z]:[/\\]' -- src scripts` (không khớp) | PASS |
| R12 (N04) | Không secret, không dataset, không artifact lớn trong Git | #3 | `.gitignore` | Dữ liệu/artifact/audit snapshot bị chặn | `git check-ignore -v data/raw/UNSW-NB15.csv artifacts/model.joblib docs/audits/x.md` | PASS |
| R13 (N05) | CI kiểm tra import + test nhẹ, không cần dataset | #3 | `.github/workflows/ci.yml` | CI xanh; bước dữ liệu ghi SKIPPED | CI run URL (mục D) | NOT VERIFIED — chờ CI trên commit |
| R14 (N07) | Tài liệu phân biệt planned / implemented / tested / verified | #2 | README + docs + ma trận này | Nhãn trạng thái khớp mã nguồn | Đối chiếu README với `src/` | PASS sau M0 |
| R15 | Bước thí nghiệm chưa triển khai không được báo như thành công | #3 | `scripts/run_experiments.py` | `baseline` / `evaluate` / `inference` trả exit khác 0 (3); lỗi dòng lệnh trả 2 | `python -m pytest tests/unit/test_run_experiments.py -q` | PASS |
| R16 (N06) | Apache-2.0; ghi nhận nghĩa vụ riêng của dependency/assets | #18 | `LICENSE`, `README.md` | Không có nội dung MIT; LICENSE là Apache-2.0 đầy đủ | `Select-String -Path LICENSE -Pattern 'Apache License'` (khớp) và `git grep -n 'MIT' -- LICENSE` (không khớp) | PASS |

## B. Yêu cầu tùy chọn — không chặn core

| Req | Yêu cầu | Issue | Deliverable | Acceptance Criteria | Cách kiểm chứng | Trạng thái M0 |
|---|---|---|---|---|---|---|
| O01 (F06) | Protocol đánh giá riêng cho Isolation Forest | #11 | Mục protocol trong `docs/METHODOLOGY.md` | Không có kết quả IF vẫn không chặn chấp nhận core | Văn bản protocol; chưa cần chạy | OPTIONAL (tài liệu đã có) |
| O02 | Chạy nhiều seed, báo mean/std | #12 | Bảng metric mở rộng | Nêu rõ điều kiện "nếu còn thời gian" | — | OPTIONAL |
| O03 | Demo giao diện (đề xuất Streamlit) | #16 | Demo | Cần issue riêng để thêm dependency | `streamlit` **không** nằm trong `requirements.txt` | OPTIONAL (chưa thêm dependency) |

## C. Yêu cầu ngoài phạm vi — ghi để tránh hiểu nhầm, KHÔNG triển khai

Autoencoder, LSTM, Transformer, GNN; phát hiện zero-day; truy vết danh tính thiết bị / hành vi từ vector đặc
trưng (Trace Engine); mã hóa vector hành vi; xoay khóa thích ứng; mã hóa hậu lượng tử (post-quantum); chặn
tự động / phản công; triển khai production hoặc xử lý phân tán. Nguồn: `README.md` (mục "Rõ ràng ngoài phạm
vi"), `docs/FUTURE_WORK.md`, `docs/PROJECT_CHARTER.md`, `.agents/rules/project-scope.md`.

## D. Kiểm chứng nền M0 — lệnh và kết quả thực tế

| # | Lệnh | Kết quả | Exit code |
|---|---|---|---|
| D1 | `python -m pip install -e .` (venv sạch) | PASS | 0 |
| D2 | `python scripts/check_environment.py` | PASS — Python + 6 dependency + `network_anomaly` | 0 |
| D3 | `python -m compileall -q src scripts tests` | PASS | 0 |
| D4 | `python -c "import network_anomaly, network_anomaly.inference.pipeline, ..."` | PASS | 0 |
| D5 | `python -m pytest tests -q` | PASS — unit + integration | 0 |
| D6 | `python scripts/validate_data.py` | SKIPPED — UNSW-NB15 chưa tải (không phải validation PASS) | 0 |
| D7 | `python scripts/run_experiments.py --step baseline` | NOT IMPLEMENTED — cố ý exit khác 0 | 3 |
| D8 | `python .agents/skills/repo-workflow/scripts/check_workflows.py` | PASS — cấu trúc workflow và link nội bộ | 0 |
| D9 | `git diff --check` | PASS — không lỗi whitespace | 0 |
| D10 | GitHub Actions trên commit M0 | NOT VERIFIED — CI chưa chạy trên commit đã push; xem `FINAL_REPORT.md` | — |

Giới hạn: D1–D9 chạy trên máy Windows với Python 3.14.6. Tương thích 3.11/3.12 **chỉ được chứng minh bằng CI**.
Không có dữ liệu UNSW-NB15 nên R01–R06, R08 chưa được kiểm chứng thực nghiệm; test fixture tổng hợp không thay
thế thực nghiệm thật.

## E. Điều kiện bàn giao giảng viên và nơi đáp ứng

| Yêu cầu | Nơi đáp ứng | Issue |
|---|---|---|
| Báo cáo PDF: phân tích, thiết kế, kết quả, đánh giá | `docs/REPORT_OUTLINE.md` | #19 |
| Gói nộp bộ: mã nguồn, tài liệu, dữ liệu theo điều khoản | `docs/REPORT_OUTLINE.md` (mục "Gói nộp bộ") | #19, #20 |
| Bảng phân công công việc | `docs/TEAM_TASKS.md` | #19 |
| Slide trình bày 10–12 trang | `docs/PRESENTATION_OUTLINE.md` | #19 |
| Chuẩn bị thuyết trình và vấn đáp cá nhân | `docs/PRESENTATION_OUTLINE.md` (mục "Chuẩn bị thuyết trình và vấn đáp") | #19 |

## F. Thay đổi phạm vi

Mọi thay đổi phạm vi phải cập nhật bảng này và ghi vào `docs/PROJECT_CHARTER.md` mục "Key design decisions".
Không mở rộng sang deep learning, production hoặc phát hiện zero-day.

Cập nhật: 2026-10-17 (M0)
