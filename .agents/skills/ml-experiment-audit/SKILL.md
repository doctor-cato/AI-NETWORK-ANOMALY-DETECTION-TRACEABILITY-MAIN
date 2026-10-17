---
name: ml-experiment-audit
description: "Audit ranh giới split, preprocessing, feature selection, tuning, threshold và metric để phát hiện leakage hoặc evaluation sai. Dùng khi review pipeline/thí nghiệm ML hoặc xác minh claim leakage-safe; không coi tài liệu là bằng chứng runtime."
---

# ML Leakage & Evaluation Audit

Audit từ code, config, data lineage, test và log thực thi. Đọc
[quy tắc thí nghiệm](../../rules/ml-experiment-rules.md) và protocol dữ liệu/model liên quan; không xác nhận
`leakage-safe` chỉ vì tài liệu mô tả đúng.

## Checklist leakage

Với mỗi mục, tìm đường dữ liệu cụ thể từ input đến fit/select/evaluate:

| Rủi ro | PASS khi | FAIL khi |
|---|---|---|
| Target leakage | target và feature dẫn xuất bị loại trước fit | target/proxy có trong `X` |
| Train/test contamination | test bị cô lập đến final evaluation | test tham gia fit, model/feature choice hoặc debugging lặp |
| Preprocessing leakage | imputer/encoder/scaler fit chỉ trên training fold | fit trước split hoặc trên val/test |
| Feature-selection leakage | selector fit trong training boundary/CV fold | chọn feature bằng toàn bộ dữ liệu hoặc test statistic |
| Tuning leakage | model/config chọn bằng train/validation hoặc nested CV phù hợp | test metric quyết định cấu hình |
| Duplicate/group leakage | duplicate/near-duplicate/session group được audit và split phù hợp | cùng thực thể/flow family đi qua split mà không kiểm soát |
| Threshold leakage | threshold chọn trên training/validation đã định | dùng test label để chọn threshold |

Không có code/log đủ quan sát thì ghi `NOT VERIFIED`, không suy đoán PASS. IP, port và timestamp cần quyết định theo
mục tiêu/split/evidence, không phải blacklist mặc định.

## Audit evaluation

- Chốt task binary hay multiclass, target, positive class, label order và support trước khi đọc metric.
- Binary: kiểm tra đúng định nghĩa Precision, Recall, F1 và FPR = FP/(FP+TN). Confusion matrix phải truyền/ghi thứ
  tự nhãn rõ ràng.
- Multiclass: không dùng `average="binary"`; báo per-class và Macro-F1 khi imbalance làm aggregate dễ gây hiểu sai.
- Tách validation performance (chọn model/threshold) khỏi final held-out test performance.
- Kiểm tra overfitting bằng train so với validation/test theo cùng metric/protocol; không kết luận chỉ từ một số.
- Random Forest và Isolation Forest chỉ so sánh khi input population, split, target interpretation và threshold
  protocol tương thích; nếu không, báo riêng.

## Bằng chứng và kết luận

Ghi cho từng check: `PASS / FAIL / SKIPPED / NOT VERIFIED`, lệnh/query, exit code, artifact/log và giới hạn. Test nên
có phản ví dụ chứng minh fit boundary, label order/FPR và lỗi binary-vs-multiclass; import hoặc constructor không đủ.

Map finding về `Issue → Requirement → Implementation → Tests → Verification Evidence → Experiment Results`.
Một FAIL về contamination, test-set tuning, target leakage hoặc metric/label semantics làm mất hiệu lực claim liên
quan cho đến khi sửa và chạy lại. Không tạo metric thay thế khi chưa có dữ liệu thật.
