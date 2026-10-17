---
name: unsw-nb15-protocol
description: "Xác minh, kiểm tra và ghi provenance cho các biến thể UNSW-NB15, schema, nhãn, official split và rủi ro leakage. Dùng khi task đọc, validate, chia hoặc mô tả dữ liệu UNSW-NB15; không tự tải dữ liệu."
---

# UNSW-NB15 Dataset Protocol

Đọc [DATASET.md](../../../docs/DATASET.md), [REPRODUCIBILITY.md](../../../docs/REPRODUCIBILITY.md) và code validator
thực tế trước khi thay đổi. Nguồn chính thức là
[UNSW Research](https://research.unsw.edu.au/projects/unsw-nb15-dataset); đường tải, điều khoản và checksum phải
được xác minh tại thời điểm lấy dữ liệu.

## Phân biệt biến thể và trạng thái dữ liệu

- Bộ bốn CSV gốc và file feature/ground-truth không có cùng layout với official partition
  `UNSW_NB15_training-set.csv` / `UNSW_NB15_testing-set.csv`.
- Official training/testing partition được công bố với 45 cột gồm feature, `attack_cat` và binary `label`; đối chiếu
  tài liệu feature, file thật và validator hiện hành trước khi code. Không áp schema này cho biến thể khác chỉ vì tên
  chứa `UNSW-NB15`, và không coi validator header tối thiểu là xác minh đủ 45 cột.
- Báo rõ một trong ba trạng thái: **ABSENT** (chưa có dữ liệu), **SYNTHETIC** (fixture/test-only), hoặc
  **REAL UNSW-NB15** (file đã xác minh provenance). Không dùng kết quả của trạng thái trước làm bằng chứng cho trạng
  thái sau.

Không tự tải/tạo bản sao dataset để làm cho check đi qua và không sửa file raw tại chỗ.

## Protocol bắt buộc khi dữ liệu thật được giao

1. Ghi source URL, ngày lấy, điều khoản/citation, biến thể, tên file, byte size và SHA-256; so khớp manifest nếu có.
2. Xác minh header/thứ tự cột, data type, finite numeric values, missing values, duplicate names/rows và số bản ghi.
3. Xác minh `label` chỉ dùng representation đã ghi (thường `0=normal`, `1=attack`) và kiểm tra tính nhất quán với
   `attack_cat`; category phải được chuẩn hóa/ánh xạ có bằng chứng, không đoán từ chính tả.
4. Báo distribution của binary label và attack category, bao gồm lớp ít mẫu; không suy ra tính đại diện chỉ từ tổng
   số hàng.
5. Mặc định giữ official train/test partition. Nếu cần tuning, tách validation chỉ từ training partition. Không trộn
   rồi random-split lại nếu chưa có lý do và đánh giá ảnh hưởng.
6. Audit exact duplicate, near-duplicate và flow/session/group overlap qua split. Xem các feature tổng hợp, ID, IP,
   port, timestamp và feature liên quan trực tiếp nhãn như ứng viên leakage/memorization, không tự động loại toàn bộ.
7. Ghi decision log cho mỗi feature giữ/loại/biến đổi: mục tiêu, bằng chứng, quyết định và ảnh hưởng.

## PASS/FAIL và giới hạn

- `PASS`: check đã chạy trên file được định danh và đáp ứng invariant được kiểm tra; kèm lệnh, exit code, hash/report.
- `FAIL`: checksum/schema/type/label/integrity không hợp lệ hoặc protocol split bị vi phạm.
- `SKIPPED`: check chủ đích không chạy vì dữ liệu vắng mặt; exit 0 không biến thành PASS.
- `NOT VERIFIED`: thiếu provenance, chưa kiểm tra near-duplicate/group leakage, hoặc không đủ bằng chứng.

Validator cấu trúc không chứng minh dataset đại diện, leakage-safe hay phù hợp production. Không train/evaluate từ
skill này trừ khi issue hiện tại cho phép riêng.
