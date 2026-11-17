# Multi-Source Data Quality Gates & Validation Methodology

**Document ID:** `METHODOLOGY-QUALITY-001`  
**Milestone:** `M6.2 (Multi-source Data Engineering)`  
**Issue:** `#91`  
**Status:** `ACTIVE & ENFORCED`  

---

## 1. Mục đích & Nguyên tắc cốt lõi

Việc thu nạp và tích hợp dữ liệu từ nhiều nguồn độc lập (Network Flow, DNS query, Web/API access, Host auth/audit) tiềm ẩn các nguy cơ suy giảm chất lượng dữ liệu:
- Nhãn xung đột (Label conflict): cùng một kết nối hoặc luồng tại một thời điểm lại bị gán nhãn khác nhau giữa các sensor.
- Bản ghi trùng lặp (Duplicates): do re-transmission hoặc nhiều probe thu nạp cùng một packet.
- Timestamp nghịch đảo hoặc sai lệch múi giờ (Clock skew / Inversion).
- Giá trị trường bắt buộc bị thiếu hàng loạt (Missing rates).

**Nguyên tắc vàng:**
1. **Zero Silent Imputation:** Tuyệt đối không tự động điền giá trị 0, mean, median hoặc mode ngầm để vượt qua gate.
2. **Fail-Closed Semantics:** Khi vi phạm vượt quá ngưỡng dung sai định trước, pipeline lập tức chuyển trạng thái `FAIL` và ngừng nạp, trừ khi người dùng chỉ định rõ ràng cờ `--allow-degraded`.
3. **Cryptographic Input Provenance:** Mọi báo cáo thẩm định chất lượng (`QualityReport`) đều tính và lưu trữ mã băm SHA-256 của tập dữ liệu đầu vào.

---

## 2. Ngưỡng kiểm định chất lượng (Quality Thresholds)

| Chỉ số kiểm tra | Ngưỡng mặc định | Hành động khi vi phạm | Ghi chú |
| :--- | :---: | :--- | :--- |
| **Missing Field Rate** | $\le 5.0\%$ | `FAIL` | Áp dụng cho các trường định danh cơ bản: IP nguồn, IP đích, port. |
| **Duplicate Proxy Rate** | $\le 2.0\%$ | `FAIL` | Khóa proxy: `(src_ip, dst_ip, src_port, dst_port, protocol, timestamp_sec)`. |
| **Label Conflict Count** | $0$ | `FAIL` | Nghiêm cấm hoàn toàn nhãn mâu thuẫn (vừa Benign vừa Attack) trên cùng một proxy key. |
| **Timestamp Inversion** | $\le 60s$ tolerance | `WARNING / REJECT` | Cảnh báo khi có sự đảo ngược thời gian lớn hơn 60 giây. |

---

## 3. Trạng thái báo cáo thẩm định

- **`PASS`:** Dữ liệu hoàn toàn đáp ứng các tiêu chuẩn chất lượng. Đủ điều kiện đưa vào pipeline huấn luyện ML và truy vết.
- **`FAIL`:** Dữ liệu vi phạm ngưỡng nghiêm trọng. Quá trình xử lý bị hủy ngay lập tức và không sinh dữ liệu trung gian.
- **`PASS_DEGRADED`:** Dữ liệu có vi phạm nhưng người dùng kích hoạt cờ chấp nhận suy giảm chất lượng có kiểm soát. Báo cáo ghi rõ lý do.
- **`SKIPPED`:** Không tìm thấy dữ liệu hoặc tệp đầu vào rỗng.

---

## 4. Cấu trúc Quality Report Schema

```json
{
  "source_id": "source:ait-netflow",
  "status": "PASS",
  "input_sha256": "81879b0e707bfc4e4fbe7b646dc06698ffd4aea831bf8ee158fb44e150a17d8a",
  "evaluated_at_utc": "2026-11-17T15:00:00Z",
  "metrics": {
    "total_records": 5000,
    "valid_records": 4995,
    "duplicate_records": 3,
    "label_conflict_records": 0,
    "missing_required_fields": 2,
    "out_of_order_timestamps": 0,
    "pass_rate_pct": 99.9
  },
  "violations": [],
  "rejection_reason": null
}
```
