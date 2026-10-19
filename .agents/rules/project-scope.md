# Phạm vi dự án — Phương án B

Nguồn yêu cầu: `docs/ROADMAP_FULL_SYSTEM.md` và đề cương
`docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx`. Roadmap C0–C11 thay thế phạm vi
prototype M0–M5 cũ cho công việc mới; lịch sử và bằng chứng cũ vẫn được giữ nguyên.

## Phạm vi bắt buộc

- Dataset chính: UNSW-NB15 published train/test partition. Raw data nằm ngoài Git.
- Data quality, EDA và leakage audit trước feature selection; split trước mọi fitting.
- Supervised: Random Forest baseline và XGBoost dùng cùng protocol.
- Unsupervised: Isolation Forest và Autoencoder reconstruction-error; threshold chỉ chọn
  trên validation. Unknown-attack evaluation dùng holdout không tham gia fit/tuning.
- Network/API/session Behavioral Vector có versioned schema, missing-feature policy và
  correlation confidence; không suy diễn danh tính thật.
- Risk Engine 0–100 có trọng số chuẩn hóa, explanation và calibration không dùng test.
- Trace Engine có incident grouping, evidence reference, confidence và timeline.
- AES-GCM, key identifier, unique nonce, metadata versioning, historical decryption,
  restart recovery, fixed 30-minute rotation và adaptive early rotation trong lab.
- Security response mặc định dry-run, có cooldown, rate limit, idempotency, concurrency
  control và rotation-storm prevention. Không tác động hệ thống thật.
- FastAPI + SQLite mặc định; PostgreSQL adapter optional. Streamlit chỉ gọi API.
- Bảy experiments trong đề cương và bàn giao report, 10–12 slides, demo, tài liệu cho
  đúng 5 vai trò; không tự điền tên thành viên.

## Ranh giới khoa học và an toàn

- Không gọi unknown-attack holdout là chứng minh phát hiện zero-day.
- Không dùng test set để chọn feature, hyperparameter, threshold hoặc calibration.
- Không gọi fixture synthetic là kết quả UNSW-NB15 hoặc benchmark thực nghiệm.
- Không tự tải dataset ngoài checkpoint được giao; không commit raw/processed dataset
  lớn, model artifact lớn, secret hoặc key material.
- Không tự thiết kế cryptography; post-quantum, LSTM, Transformer, GNN, production,
  distributed processing và SOAR thật vẫn ngoài phạm vi.
- Không block, cô lập hay rate-limit người dùng/hệ thống thật; response chỉ lab/dry-run.

## Trạng thái và bằng chứng

Dùng `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED` cho vòng đời và
`PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED` cho kiểm chứng. Chuỗi bắt buộc:
`Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
