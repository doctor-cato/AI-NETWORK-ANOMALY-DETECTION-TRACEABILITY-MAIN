# Roadmap triển khai hệ thống đầy đủ — Phương án B

## Mục đích và nguyên tắc

Tài liệu này chuyển yêu cầu trong `docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx`
thành roadmap prototype lab có thể kiểm chứng. Đây là kế hoạch, không phải bằng chứng
rằng bất kỳ module hoặc thí nghiệm nào đã hoàn thành. Mọi claim phải truy vết theo
`Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment
Results` và dùng một trong các trạng thái `PLANNED`, `IMPLEMENTED`, `TESTED`,
`EXPERIMENTALLY VALIDATED`, `PASS`, `FAIL`, `SKIPPED`, hoặc `NOT VERIFIED`.

Raw dataset, secret và artifact lớn không được commit. Không tự động block, cô lập
người dùng thật, hoặc suy diễn danh tính thật của attacker; mọi response là dry-run
trong lab cho đến khi có phê duyệt riêng.

## Kiến trúc đã chốt

- **Core services:** Python package tách theo `data`, `preprocessing`, `detection`,
  `classification`, `behavioral`, `risk`, `trace`, `security`, `response`, `storage`
  và `api`.
- **AI:** Random Forest, XGBoost, Isolation Forest và Autoencoder; LSTM/Transformer
  vẫn là hướng tùy chọn, không chặn prototype.
- **Integration:** FastAPI là lớp API; Streamlit là dashboard mỏng và chỉ gọi API,
  không lặp inference logic.
- **Storage:** SQLite là mặc định local/lab; repository abstraction cho PostgreSQL
  là tùy chọn triển khai. Event, session, incident, evidence reference, key metadata
  và rotation audit phải persistent.
- **Security:** AES-GCM với nonce duy nhất, authentication tag, key identifier và
  quản lý vòng đời khóa; không tự thiết kế cryptography.

API tối thiểu sẽ hỗ trợ ingest event, analyze event/session, truy vấn incident/timeline,
xem rotation events và health. Toàn bộ input phải được schema-validate.

## GitHub, roadmap và nhánh

- Giữ M0–M5 và toàn bộ lịch sử. Bổ sung M6 (Backend, Dashboard & Integration) và M7
  (Experiments, Documentation & Delivery) thay vì đổi số milestone cũ.
- Chỉ cập nhật Issue khi thiếu mục tiêu, dependency, implementation tasks, Acceptance
  Criteria, Test Plan, deliverable hoặc Definition of Done; chỉ tạo Issue cho module
  thực sự chưa có Issue tương ứng.
- PR #22 là workstream review độc lập: không là dependency bắt buộc để viết hoặc cập
  nhật roadmap này, không bị thay đổi/merge trước khi review hoàn tất, và không đóng
  #4/#5 nếu chưa có bằng chứng Acceptance Criteria.
- Mỗi checkpoint chức năng dùng branch và PR riêng; không gom dự án vào một PR lớn.

## Quyết định C0 và mapping GitHub

- Đề cương ghi nhóm 6 người, nhưng yêu cầu triển khai hiện tại chốt **5 vai trò**; tên
  thành viên để trống đến khi nhóm xác nhận.
- Đề cương mô tả UNSW-NB15 ở mức 49 feature; implementation dùng published train/test
  partition 45 cột gồm `attack_cat` và `label`. Không trộn schema giữa các biến thể.
- M6 (milestone #7) chứa C5–C9; M7 (milestone #8) chứa C0, C10–C11.
- Issue mapping mới: C0 #23; C3 XGBoost #31; C4 Autoencoder #29; C5 #28;
  C6 Risk #32 và Trace #24; C7 #26; C8 #27; C9 API #30 và Streamlit #16;
  C10 #25; C11 #18–#20.
- Issue #11 được nâng từ optional M0–M5 thành phần Isolation Forest bắt buộc của C4.
  LSTM/Transformer/GNN vẫn ngoài phạm vi.

## Checkpoint C0–C11

| Checkpoint | Phạm vi, kết quả cần có và điều kiện chuyển tiếp |
| --- | --- |
| C0 — Governance & documentation | Cập nhật charter, traceability, architecture, roadmap và backlog cho Phương án B; mapping DOCX → module → Issue → milestone → evidence. Review PR #22 là workstream riêng, không chặn tài liệu roadmap. |
| C1 — Data quality & EDA | Source/manifest/checksum, schema, missing, duplicate, class distribution, EDA và leakage audit. Không ghi số liệu khi raw dataset không khả dụng. |
| C2 — Preprocessing | Split trước mọi fit; feature selection có căn cứ; transformers fit trên train duy nhất; artifact serialization và test leakage. |
| C3 — Supervised ML | Random Forest và XGBoost dùng cùng protocol; binary/multiclass evaluation, Precision, Recall, F1, Macro-F1, FPR, confusion matrix, artifacts và reproduction config. |
| C4 — Unsupervised & unknown attacks | Isolation Forest và Autoencoder reconstruction-error; threshold chỉ chọn trên validation; holdout-attack evaluation không dùng lớp bị giữ lại để tối ưu detector. |
| C5 — Behavioral Vector | Versioned network/API/session vector schemas; API/session event schemas; nguồn dữ liệu lab có ground truth; deterministic fixtures; correlation labels; normalization, missing-feature policy và similarity. Test phải bao gồm false association và thiếu evidence; correlation chỉ là confidence, không là kết luận danh tính. |
| C6 — Risk & Trace | Risk score 0–100, configurable normalized weights, explanation, calibration và boundary tests; incident grouping, identity/time/behavior correlation tách bạch, evidence references, confidence và attack timeline. |
| C7 — Encryption & key lifecycle | AES-GCM, key-id/tag/nonce, local/lab key-storage strategy không lưu secret trong source, metadata versioning, restart recovery, historical decryption, backup, retention, retirement/revocation và rotation 30 phút. Test cả encryption integrity, recovery và mất/hỏng key metadata. |
| C8 — Adaptive security response | Risk-triggered early rotation và lab-only dry-run response. Acceptance Criteria: cooldown ngăn duplicate rotation trong cửa sổ cấu hình; rate limit chặn vượt quota; idempotency trả kết quả nhất quán cho cùng request; concurrency tests chứng minh không tạo nhiều rotation cho một trigger; rotation-storm prevention có audit event và fallback an toàn. |
| C9 — Backend & dashboard | FastAPI tái dùng services đã test; SQLite persistence và PostgreSQL adapter optional; Streamlit hiển thị traffic, anomaly/classification/risk, incidents, related sessions, confidence, timeline, encryption và rotation events; integration/E2E tests. |
| C10 — Experiments | Thực hiện đủ bảy experiments DOCX: RF vs XGBoost; Isolation Forest vs Autoencoder; imbalance; known vs unknown; identity vs behavioral correlation; fixed vs adaptive rotation; encryption overhead. Mỗi experiment bắt buộc có protocol, baseline, dataset/split identifier, metrics, artifact, results có bằng chứng, limitations và reproduction command. C10 không được đóng khi experiment bắt buộc còn chưa chạy hoặc chưa xác minh. |
| C11 — Delivery | Regression/security audit, reproducibility, deployment/user guide, report PDF, 10–12 slides, demo, experiment results và bảng phân công đúng năm vai trò, không tự điền tên thành viên. |

## Kiểm chứng chung

Mỗi PR chạy targeted unit/integration tests trước, sau đó checkpoint bàn giao chạy
environment check, full pytest phù hợp, serialization compatibility, schema/input
validation, `git diff --check`, và kiểm tra CI. CI hoặc fixture synthetic không thay thế
kết quả thực nghiệm trên UNSW-NB15. PostgreSQL, Docker và GPU không là yêu cầu cho CI
mặc định; mọi check phụ thuộc dịch vụ phải ghi rõ điều kiện và trạng thái.
