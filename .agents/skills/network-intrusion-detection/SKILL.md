---
name: network-intrusion-detection
description: "Phân tích hoặc triển khai logic phát hiện xâm nhập trên network flow, diễn giải feature, nhãn, FP/FN và giới hạn benchmark. Dùng khi task liên quan semantics NIDS, error analysis hoặc security claim; không dùng cho thay đổi repository thuần túy."
---

# Network Intrusion Detection

Áp dụng kiến thức NIDS vào code, test, đánh giá và báo cáo trong phạm vi bài tập. Đọc
[phạm vi dự án](../../rules/project-scope.md) trước khi đề xuất hành vi mới; không biến repository thành IDS
production.

## Xác định bài toán trước khi hành động

- **Binary supervised classification:** dự đoán `normal`/`attack` từ flow có nhãn.
- **Multiclass supervised classification:** dự đoán `normal` và attack category; phải kiểm tra category thật có trong
  biến thể dữ liệu đang dùng.
- **Unsupervised anomaly detection:** học hoặc chấm điểm mà không dùng target khi fit; score chưa phải nhãn cho đến
  khi có threshold hợp lệ.

Không gọi supervised intrusion classification là bằng chứng phát hiện anomaly chưa biết, và không tuyên bố
zero-day nếu protocol không đo khả năng đó.

## Lập luận trên network flow

Một hàng flow tóm tắt phiên/kết nối, không phải toàn bộ packet stream. Khi xem feature hoặc lỗi dự đoán, nhóm theo:

- giao thức/dịch vụ/trạng thái kết nối;
- khối lượng và hướng truyền (`bytes`, `packets`, loss);
- thời lượng, rate, inter-arrival, jitter và TCP timing;
- TTL/window/handshake và các thống kê hành vi tổng hợp;
- context đếm theo source/destination/service trong một cửa sổ.

IP, port, timestamp và identifier có thể hữu ích hoặc gây memorization/leakage. Không mặc định giữ hay loại toàn bộ;
ghi mục tiêu, split protocol, bằng chứng và quyết định cho từng nhóm feature.

## Áp dụng vào thay đổi

- **Code:** định nghĩa rõ target, mapping nhãn, positive class và feature contract; không nhúng assumption của một
  biến thể CSV vào module dùng chung nếu chưa validate schema.
- **Test:** có normal và attack, kiểm tra mapping/label order và đường lỗi schema; synthetic fixture chỉ chứng minh
  hành vi test, không chứng minh hiệu năng UNSW-NB15.
- **Evaluation:** xem class support và imbalance; báo per-class khi binary aggregate che giấu lớp hiếm. Phân tích
  false positive (normal bị báo động: alert fatigue/chi phí điều tra) và false negative (attack bị bỏ sót: rủi ro
  giám sát), không chỉ accuracy.
- **Report:** nêu rõ binary hay multiclass, mức flow, dữ liệu/split, positive class và giới hạn suy rộng.

UNSW-NB15 là benchmark được tạo trong môi trường lab, pha trộn hoạt động normal và attack của thời kỳ tạo dữ liệu.
Kết quả trên benchmark không tự chứng minh khả năng chịu concept drift, traffic mã hóa, topology khác, adversarial
evasion, latency hay vận hành thời gian thực.

## Điều kiện kết luận

Chỉ gọi kết quả là `EXPERIMENTALLY VALIDATED` khi đã chạy trên UNSW-NB15 thật với provenance và protocol được
ghi. Constructor, unit test hoặc synthetic flow tối đa chứng minh `IMPLEMENTED`/`TESTED`. Nếu task cần dữ liệu,
phối hợp [unsw-nb15-protocol](../unsw-nb15-protocol/SKILL.md); nếu cần đánh giá, dùng
[ml-experiment-audit](../ml-experiment-audit/SKILL.md).
