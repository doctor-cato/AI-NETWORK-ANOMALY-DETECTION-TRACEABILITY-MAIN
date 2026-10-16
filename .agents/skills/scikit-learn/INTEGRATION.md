name: scikit-learn
source_global: C:\Users\Admin\.agents\skills\scikit-learn
license: BSD-3-Clause (SKILL.md line 4)
date_checked: 2026-10-16

trigger: xây dựng/training RF (`models/random_forest.py`), IF (`models/isolation_forest.py`), evaluation (`evaluation/metrics.py`), preprocessing pipeline.

repo_notes:
- Baseline: `RandomForestClassifier` với `config.RANDOM_FOREST_DEFAULTS` (n_estimators=200, max_depth=16, random_state=42).
- IF: `IsolationForest` có `build_model()` nhưng chưa có protocol đánh giá đầy đủ (score→threshold→label); chỉ triển khai khi baseline ổn.
- Preprocessing: placeholder hiện tại (`preprocessing/__init__.py`); khi triển khai phải fit chỉ trên train, rồi transform val/test; lưu artifact.
- Metrics: `precision_score`, `recall_score`, `f1_score`, `confusion_matrix`; `average="binary"` với `zero_division=0`; báo cáo cả macro khi mất cân bằng.
- Data leakage: kiểm tra cột nhãn, cột dẫn xuất, identity (IP/port/time) trước chọn đặc trưng; không dùng nhãn test để chọn hyperparameter.
- Không cam kết benchmark UNSW-NB15 nếu chưa có dataset thật.

activation: tham chiếu SKILL.md toàn cục khi cần chi tiết (pipeline, preprocessing, cross-validation). Luôn kết hợp `.agents/rules/ml-experiment-rules.md`.
