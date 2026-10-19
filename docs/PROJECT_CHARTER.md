# Hiến chương dự án — phát hiện bất thường mạng bằng học máy

## Nhận diện dự án

- **Tên tiếng Việt:** Xây dựng hệ thống AI phát hiện kết nối mạng bất thường bằng học máy và phân tích hành vi lưu lượng mạng
- **Repository:** https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN
- **License:** Apache License 2.0 (NOT MIT)
- **Runtime target:** Python 3.11+ (CI kiểm tra 3.11 và 3.12); scikit-learn 1.5+; pandas 2.2+; NumPy 1.26+ (xem `requirements.txt`)

## Mục tiêu

Mục tiêu 1–5 và 7–10 là **bắt buộc** (core). Mục tiêu 6 (Isolation Forest) là **tùy chọn**: thiếu kết quả IF
không chặn chấp nhận core, và chỉ thực hiện sau khi baseline Random Forest đã có kết quả thật.

1. Phân tích phát hiện bất thường trong lưu lượng mạng và xác định đối tượng phát hiện. (bắt buộc)
2. Dùng UNSW-NB15 làm dataset chính; xác minh schema, nhãn và phân bố lớp. (bắt buộc)
3. Kiểm tra chất lượng dữ liệu, xử lý missing value, encode feature phù hợp và tránh target leakage. (bắt buộc)
4. Thiết kế train/validation/test split tái lập được, không rò rỉ dữ liệu. (bắt buộc)
5. Xây dựng baseline Random Forest với pipeline và config đã ghi. (bắt buộc — baseline chính)
6. Xây dựng Isolation Forest như phương pháp phát hiện không giám sát nếu đủ dữ liệu và thời gian. (TÙY CHỌN)
7. So sánh model bằng Precision, Recall, F1-score, Macro-F1, confusion matrix và False Positive Rate, mô tả protocol rõ cho từng model do nhãn và threshold khác nhau. (bắt buộc cho RF; IF nếu có)
8. Phân tích false positive/negative, giới hạn dữ liệu và ràng buộc model. (bắt buộc)
9. Cung cấp pipeline inference và demo tối thiểu. (bắt buộc)
10. Cung cấp script/notebook thực nghiệm tái lập được, tài liệu, sơ đồ kiến trúc và dàn ý trình bày. (bắt buộc)

Ma trận yêu cầu → issue → deliverable → cách kiểm chứng: `docs/TRACEABILITY_MATRIX.md`.

## Phạm vi và ngoài mục tiêu

### Trong phạm vi (bắt buộc)
- Phân tích vấn đề; nguồn UNSW-NB15; EDA; preprocessing; train/val/test split; Random Forest; evaluation; error analysis; inference; demo; tài liệu; dàn ý báo cáo; dàn ý trình bày.
- Isolation Forest **chỉ khi khả thi** và **không chặn** chấp nhận core.

### Rõ ràng ngoài phạm vi (không triển khai lúc này; chỉ ghi trong `docs/FUTURE_WORK.md` hoặc issue mở rộng)
- Autoencoder, LSTM, Transformer, GNN.
- Tuyên bố phát hiện zero-day khi chưa có bằng chứng thực nghiệm.
- Truy vết danh tính thiết bị / kẻ tấn công từ behavior vector.
- Mã hóa behavior vector và cơ chế adaptive key rotation.
- Post-quantum cryptography cho lưu lượng hoặc biểu diễn đặc trưng.
- Chặn, cô lập hoặc phản công thiết bị tự động.
- Triển khai production, xử lý phân tán hoặc giám sát mạng doanh nghiệp.

## Tiêu chí thành công (có thể kiểm chứng)

- [ ] Cấu trúc repository khớp thiết kế; có đủ tài liệu bắt buộc.
- [ ] README phân biệt PLANNED / IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED; không có metric bịa đặt.
- [ ] Script validation dữ liệu đạt với fixture; đã ghi hướng dẫn tải UNSW-NB15.
- [ ] Có thể dựng lại pipeline preprocessing từ `docs/REPRODUCIBILITY.md` và `config.py`.
- [ ] Model Random Forest train và evaluation cùng seed, metric, confusion matrix đã ghi.
- [ ] Protocol evaluation Isolation Forest được ghi riêng với evaluation giám sát.
- [ ] Không có nội dung MIT trong LICENSE hoặc README; có đủ Apache 2.0.
- [ ] Có milestone M0–M5; issue có label và liên kết milestone.
- [ ] CI chạy kiểm tra import/test cơ bản, không cần dataset lớn hoặc GPU.
- [ ] Không hardcode đường dẫn tuyệt đối, không secret, không claim benchmark chưa xác minh.

## Ghi chú rủi ro và giới hạn

- Kích thước/khả dụng dataset: UNSW-NB15 khoảng 2,5 GB nén; không commit vào Git.
- Isolation Forest cần evaluation khác (score không giám sát → threshold → pseudo-label); so sánh trực tiếp với F1 giám sát cần giải thích rõ threshold và sự khớp nhãn.
- Ngân sách thời gian: 5–6 tuần; các hướng deep-learning phức tạp để sau.
- Rủi ro chất lượng dữ liệu: missing value, dòng trùng, cột định danh dễ gây leakage.

## Time plan (5–6 weeks)

- Week 1 (M0): Repository, docs, environment, CI.
- Week 2 (M1): Dataset sourcing, validation, EDA, leakage audit.
- Week 3 (M2): Preprocessing pipeline, baseline, Random Forest.
- Week 4 (M3): Isolation Forest (if time), evaluation, comparison, error analysis.
- Week 5 (M4): Inference, demo, visualization, integration tests.
- Week 6 (M5): Final report, presentation, release verification.

## Key design decisions (recorded)

- Source code organized under `src/network_anomaly/`; logic callable from notebooks/scripts.
- Pipeline objects (scikit-learn Pipeline / custom) to prevent test-set leakage.
- Random seeds fixed; results logged with version info.
- No dataset committed; download instructions and checksum references documented (not verified yet;
  marked as planned).

Updated: 2026-10-17 (M0)
