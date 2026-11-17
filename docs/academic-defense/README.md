# Hồ sơ Bảo vệ Học thuật — NetFlow Sentinel v2 (`docs/academic-defense/`)

> **Lưu ý Migration v1 → v2:** Toàn bộ bộ hồ sơ bảo vệ học thuật cũ dựa trên `NF-UNSW-NB15-v3` (55 cột / 47 features) đã được chuyển vào lưu trữ lịch sử tại [`docs/historical/nf_unsw_nb15_v3/academic-defense/`](../historical/nf_unsw_nb15_v3/academic-defense/). Thư mục `docs/academic-defense/` hiện hành phản ánh hoàn toàn kiến trúc và thực nghiệm **NetFlow Sentinel v2**.

---

## Tổng quan tài liệu kỹ thuật & thực nghiệm v2

| Chủ đề | Tài liệu v2 chính thức | Nội dung kiểm chứng |
|---|---|---|
| **Nguồn dữ liệu & Quality Gates** | [`docs/DATASET.md`](../DATASET.md) · [`AIT_PROFILE.md`](../dataset/AIT_PROFILE.md) · [`CTU_SME_11_PROFILE.md`](../dataset/CTU_SME_11_PROFILE.md) · [`AIT_LINKAGE_FEASIBILITY.md`](../dataset/AIT_LINKAGE_FEASIBILITY.md) | `AIT-NDS-v2` (CC BY 4.0, DOI `10.5281/zenodo.13168643`), `AIT-LDS-v2.1`, `AIT-ADS`, `CTU-SME-11` (real SME capture), và trạng thái `UGR'16 BLOCKED` |
| **Feature Contract & Schema v2** | [`CANONICAL_SECURITY_EVENT_V2.md`](../CANONICAL_SECURITY_EVENT_V2.md) · [`FEATURE_COMPATIBILITY_MATRIX.md`](../FEATURE_COMPATIBILITY_MATRIX.md) · [`v2_schema_summary.json`](../../reports/schema/v2_schema_summary.json) | Hợp đồng `canonical-flow-v2-18` (18 ML features + 5 trace metadata + 4 target columns + 4 provenance columns); `taxonomy-v2` không ép `background`/`unknown` thành `Benign` |
| **Split & Tiền xử lý Train-only** | [`MULTI_SOURCE_SPLIT_PROTOCOL.md`](../dataset/MULTI_SOURCE_SPLIT_PROTOCOL.md) · [`V2_LEAKAGE_AUDIT.md`](../dataset/V2_LEAKAGE_AUDIT.md) | `v2-scenario-group-purged-v1` (Train `1,930,219` / Val `377,704` / Test `923,292`, 0 overlap scenario & 5-tuple); `TrainOnlyPreprocessor` `asinh_robust` |
| **Kết quả 4 Mô hình & Cross-Source** | [`FOUR_MODEL_COMPARISON.md`](../experiments/FOUR_MODEL_COMPARISON.md) · [`CTU_CROSS_SOURCE_EVAL.md`](../experiments/CTU_CROSS_SOURCE_EVAL.md) · [`EVALUATION.md`](../EVALUATION.md) | Đánh giá `AIT-Test` (`RF F1=0.8997`, `XGB F1=0.8910`, `AE F1=0.5788`, `IF F1=0.5766`) và suy giảm domain-shift trên `CTU-SME-11` |
| **6 Câu hỏi Nghiên cứu (RQ1–RQ6)** | [`RESEARCH_QUESTIONS.md`](../RESEARCH_QUESTIONS.md) · [`RESEARCH_QUESTIONS_VALIDATION.md`](../audits/RESEARCH_QUESTIONS_VALIDATION.md) | Kết quả đầy đủ RQ1–RQ6 kèm negative results (`h2_full_confirmed=false`, `unsupervised_ge_0_75_both=false`, `RQ3 empirical BLOCKED`) |
| **Chỉ mục Truy vết Bằng chứng** | [`EVIDENCE_INDEX.md`](EVIDENCE_INDEX.md) | Bảng `Claim → Code/Manifest → Experiment JSON → Status` |

**Script kiểm chứng schema & preprocessor (read-only):**

```powershell
.venv\Scripts\python.exe scripts/export_academic_schema_summary.py --format json --output reports/schema/v2_schema_summary.json
```
