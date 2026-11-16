# Dàn ý trình bày — 12 Slide Bảo vệ Đồ án (NetFlow Sentinel v1.0.0)

> Tài liệu dàn ý nhanh cho bộ slide. Kịch bản chi tiết 10–15 phút, bản đồ mở code/manifest khi vấn đáp và sơ đồ pipeline đầy đủ xem tại [`docs/academic-defense/09_PRESENTATION_AND_DEMO_DEFENSE_GUIDE.md`](academic-defense/09_PRESENTATION_AND_DEMO_DEFENSE_GUIDE.md).

1. **Slide 1 — Tiêu đề & Bối cảnh** — *NetFlow Sentinel v1.0.0 (AI-Based Network Anomaly Detection and Traceability System)*; 5 vai trò nhóm (tên thành viên điền khi chốt bàn giao) và mục tiêu đồ án AI cuối kỳ.
2. **Slide 2 — Bài toán & Ranh giới Sản phẩm** — Phân biệt `Benign` / `Attack` trên NetFlow, chống rò rỉ dữ liệu, truy vết artifact bằng SHA-256 và ứng dụng Desktop Windows offline; công bố rõ phạm vi nghiên cứu học thuật (không phải production IDS).
3. **Slide 3 — Bộ dữ liệu `NF-UNSW-NB15-v3`** — Nguồn The University of Queensland (DOI `10.48610/6E0EDA1`, `arXiv:2503.04404`, UQ License `454104` phi thương mại); `2.365.424` dòng (`94,60%` Benign / `5,40%` Attack, 9 họ `Attack`); ý nghĩa 1 dòng flow vs PCAP/log.
4. **Slide 4 — Schema 55 Cột & Tiền xử lý Train-Only** — Tách `6` trace metadata & `2` targets khỏi `47` ML features (`10` categorical-coded + `37` quantitative); `TrainOnlyPreprocessor` fit chỉ trên Train (`1.655.797`), điền `""`/`+Inf` bằng median/mode, **không One-Hot Encoding**, **không scaling (`scaler=none`)**; minh họa trước/sau trên `row_id=92156`.
5. **Slide 5 — Thiết kế Chia Tập & Chống Rò rỉ** — Chronological split + Purge Gap 5 phút (`Train 1.655.797` / `Val 345.371` / `Test 345.953` / `Purged 18.303`); `0` overlap dòng gốc và flow-group.
6. **Slide 6 — Kiến trúc `v1.0.0` (Tauri 2 + Svelte 5 ↔ PyInstaller FastAPI Sidecar)** — Kiến trúc standalone sidecar trên `127.0.0.1` với token phiên `X-Sentinel-Session-Token`, SQLite single-writer tại `%LOCALAPPDATA%\NetFlowSentinel\`, phân tầng `MODEL_VALIDATED` vs `RESEARCH_ONLY`, OOD gate (`ABSTAINED_OOD`) và Security Dry-Run `#27` (`executed=false`).
7. **Slide 7 — Bốn Mô hình AI & Giao thức Đánh giá** — `Random Forest` (`MODEL_VALIDATED`), `XGBoost` (`RESEARCH_ONLY`), `Isolation Forest` & `Autoencoder (MLPRegressor 32-16-32)` (`RESEARCH_ONLY`, train benign-only `1.590.608`, ngưỡng đóng băng trên Validation tách `{Backdoor, Worms}`).
8. **Slide 8 — Kết quả Thực nghiệm Held-out Test (`345.953` flow)** — Bảng đối chiếu tách biệt cả 4 model: RF `F1=0,999853`, XGB `F1=0,999984`, IF `F1=0,5064` (`Recall=0,8997`, Unknown `0,8657`), AE `F1=0,1361` (`Recall=0,1093`, `FPR=0,0482`, Unknown `0,0625`).
9. **Slide 9 — Kiểm toán Shortcut Learning & Cross-Dataset Collapse** — Phát hiện `49,98%–53,21%` lặp vector ML, cây 1 biến `MIN_TTL` đạt `0,999849` trên Validation, và bằng chứng Random Forest tụt xuống `Recall=0,0`, `FPR=0,3802` trên `100.000` dòng `NF-CSE-CIC-IDS2018-v3`.
10. **Slide 10 — Demo Trực tiếp NetFlow Sentinel `v1.0.0`** — Quy trình 4 bước trên `demo_flows.csv` (200 dòng Validation: `198` dự đoán + `2` `ABSTAINED_OOD` tại `MIN_TTL=0`), so sánh 4 model, Confusion Matrix với `demo_labels.csv`, Tab 4 Dry-Run và Export CSV + SHA-256.
11. **Slide 11 — Phạm vi Rút gọn, Giấy phép & Trạng thái Phát hành** — Minh bạch phần `REDUCED`/`DEFERRED` (firewall thật, AES-256-GCM keyring), tách biệt `v1.0.0` Source Release trên GitHub với bộ cài Windows `.exe` đang chờ nghiệm thu Clean VM & cấp phép UQ `454104` (#73).
12. **Slide 12 — Kết luận, Hướng phát triển & Tài liệu tham khảo** — Tổng hợp đóng góp đã kiểm chứng, đề xuất scaler/domain adaptation cho tương lai, trích dẫn UQ DOI `10.48610/6E0EDA1` và `Apache-2.0`.

## Chuẩn bị thuyết trình và vấn đáp dựa trên bằng chứng

- [ ] Phân vai người trình bày cho đúng 5 vai trò (tên để trống đến khi nhóm xác nhận); diễn tập có bấm giờ (10–15 phút).
- [ ] Chuẩn bị kịch bản dự phòng (kết quả `data/demo/` và `reports/evaluation/`) nếu máy chiếu gặp sự cố.
- [ ] Đối chiếu mọi câu hỏi chuyên sâu về dữ liệu, cột, tiền xử lý và 4 model theo [bộ 20 Q&A](academic-defense/08_TEACHER_QUESTIONS_AND_ANSWERS.md) và [chỉ mục bằng chứng](academic-defense/EVIDENCE_INDEX.md).
