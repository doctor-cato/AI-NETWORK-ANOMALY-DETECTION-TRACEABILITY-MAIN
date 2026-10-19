# Hiến chương dự án — Hệ thống AI an toàn mạng Phương án B

## Mục tiêu

Xây dựng prototype lab có thể tái lập để thu thập và chuẩn hóa network/API/session
events, phát hiện và phân loại bất thường, biểu diễn Behavioral Vector, tính Risk Score,
liên kết evidence thành incident timeline, bảo vệ dữ liệu bằng AES-GCM và trình diễn qua
FastAPI/Streamlit. Random Forest là baseline chính; XGBoost, Isolation Forest và
Autoencoder là các nhánh so sánh bắt buộc trong roadmap C3–C4.

## Nguyên tắc chấp nhận

- UNSW-NB15 là dataset chính. Published train/test partition có 45 cột gồm
  `attack_cat` và `label`; không mô tả nhầm là 49 feature của biến thể khác.
- Split trước mọi fit; preprocessing/feature selection/threshold/calibration chỉ học từ
  train/validation theo protocol, không từ test.
- Behavioral correlation là confidence trong phạm vi dữ liệu được phép giám sát, không
  là kết luận danh tính thật.
- Encryption dùng AES-GCM từ thư viện chuẩn; secret/key material không nằm trong source.
- Adaptive response mặc định dry-run và chỉ chạy trong lab; không block/cô lập hệ thống thật.
- Streamlit chỉ gọi FastAPI; SQLite là mặc định local/CI, PostgreSQL là optional.
- Không có metric hoặc experiment result nếu chưa chạy và lưu bằng chứng tái lập.

## Kết quả cần bàn giao

Roadmap gồm C0–C11: governance; data/EDA; preprocessing; supervised ML; unsupervised và
unknown attacks; Behavioral Vector; Risk/Trace; encryption/key lifecycle; adaptive
response; backend/dashboard; bảy experiments; report, 10–12 slides, demo và handoff cho
5 vai trò. Tên thành viên chỉ được điền khi nhóm xác nhận.

## Ngoài phạm vi

Production deployment, distributed processing, SOAR thật, post-quantum cryptography,
LSTM/Transformer/GNN và mọi tuyên bố zero-day hoặc attacker identity không có chứng cứ.

## Quản trị thay đổi

`docs/ROADMAP_FULL_SYSTEM.md` là roadmap chuẩn; `docs/TRACEABILITY_MATRIX.md` ánh xạ
requirement/checkpoint/issue/evidence. Mỗi checkpoint dùng branch, commit và PR riêng;
không tự merge. M0–M5 được giữ như lịch sử, M6/M7 mở rộng Phương án B.

Cập nhật: 2026-10-19 (C0)
