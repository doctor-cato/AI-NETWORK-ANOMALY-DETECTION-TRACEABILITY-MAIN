# Hồ sơ Bảo vệ Học thuật — NetFlow Sentinel v1.0.0 (`docs/academic-defense/`)

> **Mục đích:** Bộ tài liệu kỹ thuật chuyên sâu, độc lập với User Guide và Developer Guide, giúp giảng viên phản biện và hội đồng bảo vệ đồ án kiểm chứng chính xác **dữ liệu đầu vào, cấu trúc 55 cột, tiền xử lý trước `model.fit()`, cơ chế chia Train/Validation/Test, hoạt động của 4 mô hình AI, code huấn luyện/suy luận thực tế và giới hạn khoa học** của dự án **NetFlow Sentinel v1.0.0**.
>
> Mọi khẳng định trong bộ tài liệu này đều được đối chiếu trực tiếp với mã nguồn, cấu hình, manifest và báo cáo thực nghiệm trong repository. Tài liệu tuân thủ phân loại trạng thái nghiêm ngặt: `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`, `NOT VERIFIED` và không tự suy diễn lý thuyết chung thành năng lực đã triển khai.

---

## Mục lục tài liệu

| STT | Tài liệu | Nội dung trọng tâm cho Hội đồng / Giảng viên |
|---|---|---|
| 01 | [01_DATASET_ORIGIN_AND_STRUCTURE.md](01_DATASET_ORIGIN_AND_STRUCTURE.md) | Nguồn gốc `NF-UNSW-NB15-v3` (UQ, DOI `10.48610/6E0EDA1`), bản chất NetFlow vs PCAP/log, ý nghĩa `Label=0/1` và 9 họ `Attack`, phân bố 2.365.424 dòng, điều khoản phi thương mại `UQ 454104` |
| 02 | [02_COMPLETE_FEATURE_DICTIONARY.md](02_COMPLETE_FEATURE_DICTIONARY.md) | Giải thích **100% (55/55 cột)** trong schema thực tế: 6 trace metadata (loại), 2 targets (loại), 47 ML features (10 categorical-coded + 37 quantitative), kiểu dữ liệu, ví dụ, tiền xử lý, rủi ro leakage |
| 03 | [03_DATA_PREPROCESSING_PIPELINE.md](03_DATA_PREPROCESSING_PIPELINE.md) | Luồng `Raw CSV → 47 Features → Token Audit → Median/Mode Imputation (Train-only) → (N, 47) float64`; giải thích vì sao **không dùng One-Hot Encoding** và **không scale (`scaler_type="none"`)**; ví dụ thật trước/sau từ `demo_flows.csv` |
| 04 | [04_TRAIN_VALIDATION_TEST_DESIGN.md](04_TRAIN_VALIDATION_TEST_DESIGN.md) | Chronological split + 5-minute purge gap (`1.655.797` / `345.371` / `345.953`, purged `18.303`), zero group/row overlap, mất cân bằng 94,60%/5,40%, trùng vector 49,98%/53,21%, `MIN_TTL` shortcut và sụp đổ cross-dataset |
| 05 | [05_FOUR_MODELS_EXPLAINED.md](05_FOUR_MODELS_EXPLAINED.md) | Cơ chế, đầu vào/đầu ra, hyperparameters, ngưỡng, artifact và bằng chứng đánh giá của **Random Forest** (`MODEL_VALIDATED`), **XGBoost**, **Isolation Forest** và **Autoencoder (`MLPRegressor 32-16-32`)** (`RESEARCH_ONLY`) |
| 06 | [06_TRAINING_CODE_WALKTHROUGH.md](06_TRAINING_CODE_WALKTHROUGH.md) | Dẫn đường từng dòng code: file train ở đâu, data đọc từ đâu, `TrainOnlyPreprocessor` fit/transform ở dòng nào, `model.fit()` ở đâu, tính metric/manifest ở đâu, chứng minh demo **không retrain** |
| 07 | [07_MODEL_RESULTS_AND_LIMITATIONS.md](07_MODEL_RESULTS_AND_LIMITATIONS.md) | So sánh tách biệt **Validation**, **Held-out Test (345.953 dòng)**, **Cross-Dataset (100.000 dòng)** và **Demo CSV (200 dòng: 198 hợp lệ + 2 `ABSTAINED_OOD`)**; giải thích vì sao không công bố là production IDS |
| 08 | [08_TEACHER_QUESTIONS_AND_ANSWERS.md](08_TEACHER_QUESTIONS_AND_ANSWERS.md) | Bộ **20 câu hỏi phản biện trực diện của giảng viên** kèm trả lời ngắn khi thuyết trình, giải thích kỹ thuật, ví dụ, dẫn chứng file/hàm và giới hạn trung thực |
| 09 | [09_PRESENTATION_AND_DEMO_DEFENSE_GUIDE.md](09_PRESENTATION_AND_DEMO_DEFENSE_GUIDE.md) | Kịch bản bảo vệ 10–15 phút, bản đồ mở code/manifest/màn hình theo câu hỏi và sơ đồ Mermaid end-to-end |
| — | [EVIDENCE_INDEX.md](EVIDENCE_INDEX.md) | Bảng truy vết `Claim → Source File → Function/Config → Experiment/Test → Status` và script đọc kiểm chứng [export_academic_schema_summary.py](../../scripts/export_academic_schema_summary.py) |

---

## Liên kết chéo với hệ thống tài liệu dự án

- **Trang chủ dự án:** [README.md](../../README.md)
- **Tài liệu Kiến trúc & Phát triển:** [ARCHITECTURE.md](../ARCHITECTURE.md) · [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md) · [TESTING.md](../TESTING.md) · [REPRODUCIBILITY.md](../REPRODUCIBILITY.md)
- **Tài liệu Người dùng cuối & Cài đặt Windows (`v1.0.0`):** [WINDOWS_INSTALLATION.md](../WINDOWS_INSTALLATION.md) · [v1.0.0 Release Notes](../releases/v1.0.0.md)
- **Tài liệu Dữ liệu & Kiểm toán:** [DATASET.md](../DATASET.md) · [NF_UNSW_NB15_V3_SCHEMA.md](../dataset/NF_UNSW_NB15_V3_SCHEMA.md) · [NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md](../NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md) · [NF_UNSW_NB15_V3_PREPROCESSING_POLICY.md](../NF_UNSW_NB15_V3_PREPROCESSING_POLICY.md)
- **Script kiểm chứng chỉ đọc (read-only):** `python scripts/export_academic_schema_summary.py`
