---
name: model-experiment
description: "Thiết kế, triển khai hoặc tái lập thí nghiệm Random Forest và Isolation Forest có artifact/metadata nhất quán. Dùng khi issue cho phép training, tuning, evaluation hoặc lưu model; không kích hoạt training hay tải dataset chỉ để kiểm tra skill."
---

# Model Experiment & Reproducibility

Chỉ thực hiện experiment khi task/issue hiện tại cho phép và dữ liệu thật đã qua protocol. Đọc
[EXPERIMENT_PLAN.md](../../../docs/EXPERIMENT_PLAN.md), [REPRODUCIBILITY.md](../../../docs/REPRODUCIBILITY.md) và
[ml-experiment-audit](../ml-experiment-audit/SKILL.md). Việc skill được kích hoạt không cấp quyền tải dataset hoặc
chạy training tốn tài nguyên.

## Random Forest — baseline bắt buộc

1. Chốt binary/multiclass target, positive class, input feature và lý do giữ/loại.
2. Tách dữ liệu theo protocol trước fit; categorical feature đi qua encoder trong pipeline. Fit imputer/encoder/
   scaler/selector chỉ trên training boundary.
3. Cố định và ghi seed cho split/model khi thành phần hỗ trợ; không gọi một seed là bảo đảm tái lập tuyệt đối.
4. Chọn hyperparameter bằng training/validation hoặc CV đúng boundary; không dùng final test để chọn model/ngưỡng.
5. Đánh giá một lần trên held-out test: Precision, Recall, F1, Macro-F1, labeled confusion matrix, FPR và per-class
   support/metrics khi phù hợp.
6. So sánh train với validation/test để nhận diện overfitting; phân tích FP/FN bằng feature/traffic context có bằng
   chứng, không gán nguyên nhân tùy tiện.
7. Lưu preprocessing pipeline và model cùng một contract; inference không được fit lại preprocessing.

## Isolation Forest — tùy chọn

- Chỉ làm khi task/issue cho phép và core Random Forest không bị chặn.
- Ghi rõ dữ liệu fit: normal-only hay contaminated/unlabeled training population; model không nhận target khi fit.
- Sinh anomaly score, chọn score direction và threshold bằng training/validation protocol; test label không được dùng
  hiệu chỉnh threshold.
- Áp threshold cố định lên test rồi mới tính metric. Không so sánh trực tiếp với RF nếu population/split/target hoặc
  selection budget khác nhau.

## Manifest tối thiểu cho một run

- run ID/thời gian; issue/requirement; commit và trạng thái working tree;
- nguồn, biến thể, tên file và checksum dataset; split protocol/fold/seed;
- danh sách feature/target/label mapping và preprocessing fitted boundary;
- model class, full config/tuning space, random seeds, dependency/Python/OS versions;
- lệnh tái lập, artifact paths/hashes, metric + labeled confusion matrix và lỗi/warning;
- liên kết evidence cho validation và final test, cùng giới hạn chưa kiểm chứng.

Metadata phải đi cùng artifact để kiểm tra schema, feature order, label mapping và compatibility trước inference. Không
ghi đè run/artifact âm thầm và không commit artifact lớn/dataset.

## Trạng thái trung thực

- `PLANNED`: protocol/config dự kiến, chưa có implementation.
- `IMPLEMENTED`: code tồn tại; chưa đủ bằng chứng test/run.
- `TESTED`: test đã chạy, có thể chỉ dùng synthetic data.
- `EXPERIMENTALLY VALIDATED`: run trên UNSW-NB15 thật có provenance, manifest, held-out evaluation và evidence.

Không tạo metric, benchmark table, manifest hay model artifact giả để nâng trạng thái.
