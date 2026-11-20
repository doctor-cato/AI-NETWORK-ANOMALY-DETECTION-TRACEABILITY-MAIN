# Dàn ý Báo cáo Khoa học — NetFlow Sentinel v2

1. **Trang tiêu đề** — Tên dự án (*NetFlow Sentinel v2 — AI-Based Network Anomaly Detection and Traceability System*), tác giả, cơ sở đào tạo, ngày, giấy phép `Apache-2.0` + `CC BY 4.0` (datasets).
2. **Tóm tắt** — Bài toán phát hiện xâm nhập trên NetFlow đa nguồn, hard cutover sang dữ liệu v2, kết quả chính trên `AIT-NDS-v2` & `CTU-SME-11`, và các giới hạn/negative results đã xác minh.
3. **Giới thiệu** — Động lực, phát biểu vấn đề (`docs/PROBLEM_STATEMENT.md`), mục tiêu, ngoài mục tiêu (không production SOAR, không tự động chặn mạng thật).
4. **Nguồn dữ liệu & Migration v1 $\to$ v2** — Lý do loại bỏ `NF-UNSW-NB15-v3` (`docs/adr/ADR-dataset-hard-cutover-v2.md`), provenance & quality findings của `AIT-NDS-v2`, `AIT-LDS-v2.1`, `AIT-ADS`, `CTU-SME-11` và trạng thái `BLOCKED` của `UGR'16` (`docs/DATASET.md`).
5. **Phương pháp** — Hợp đồng `canonical-flow-v2-18`, `taxonomy-v2` (chống ép `background`/`unknown`), chia tập scenario-disjoint `v2-scenario-group-purged-v1`, tiền xử lý train-only `asinh_robust`, 4 mô hình AI (RF, XGBoost, IF, Autoencoder), Behavioral Vector 16-D, Risk Engine, Trace Engine và AES-256-GCM Adaptive Key Rotation.
6. **Thiết lập thực nghiệm** — Môi trường phần cứng/phần mềm, `RANDOM_SEED = 42`, hyperparameters, giao thức hiệu chuẩn ngưỡng trên Validation (`empirical_val_fpr <= 0.05`) và định nghĩa metric.
7. **Kết quả Thực nghiệm (RQ1–RQ6 & Cross-Source)** — Metric `AIT-Test`, `CTU-SME-11` (`CTU-Echo`, `CTU-Windows7AD`), rare-class `RQ2`, unknown-attack holdout `RQ4`, simulation `RQ3`/`RQ5`, crypto & E2E benchmark `RQ6`.
8. **Thảo luận** — Phân tích nguyên nhân sụp đổ zero-shot synthetic-to-real, false positive/negative, tác động của unmapped labels và giá trị bổ trợ giữa supervised vs unsupervised models.
9. **Kết luận** — Tóm tắt đóng góp đã kiểm chứng, giới hạn trung thực và hướng phát triển tiếp theo.
10. **Tài liệu tham khảo** — `AIT-NDS-v2` (`10.5281/zenodo.13168643`), `AIT-LDS-v2.1` (`10.5281/zenodo.19483937`), `AIT-ADS` (`10.5281/zenodo.8263181`), `CTU-SME-11` (`10.5281/zenodo.7958258`), scikit-learn, XGBoost, Tauri/FastAPI.
11. **Phụ lục** — Sơ đồ kiến trúc, hợp đồng schema `canonical-flow-v2-18`, bảng SHA-256 manifests và lệnh tái lập (`docs/REPRODUCIBILITY.md`).

## Ràng buộc Gói Nộp & Tái lập

- **Không commit vào Git:** raw datasets (`data/raw/`), processed CSVs (`data/processed/`), model binaries (`.joblib`), SQLite runtime DB hay secrets.
- **Chỉ ghi nhận chứng cứ thực tế:** Mọi chỉ số báo cáo phải truy xuất trực tiếp được về manifest/report JSON trong `reports/` (`docs/academic-defense/EVIDENCE_INDEX.md`).
- **Kiểm tra trước bàn giao:** `python scripts/check_environment.py`, `python -m pytest tests -q`, `npm --prefix desktop run test`, `cargo test --manifest-path desktop/src-tauri/Cargo.toml --lib`, `git diff --check`.
