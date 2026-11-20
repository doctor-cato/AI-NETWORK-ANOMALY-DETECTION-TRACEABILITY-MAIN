# Multi-Source Chronological Split & Leakage Audit Protocol

**Document ID:** `PROTOCOL-SPLIT-V2-001`  
**Milestone:** `M6.2 (Multi-source Data Engineering)`  
**Issue:** `#92`  
**Status:** `VERIFIED & ZERO-LEAKAGE`  

---

## 1. Bối cảnh & Rủi ro rò rỉ dữ liệu (Data Leakage)

Trong bài toán phát hiện bất thường và truy vết đa nguồn (Network Flow, DNS, Web, Auth):
1. **Temporal Leakage:** Phân chia ngẫu nhiên (random k-fold) dẫn đến việc mô hình được huấn luyện bằng dữ liệu tương lai để dự đoán quá khứ, phóng đại hiệu năng thực tế.
2. **Session / Entity Group Leakage:** Một phiên tấn công (attack session) kéo dài hoặc cùng một thực thể (IP, user) xuất hiện ở cả tập Train và Test khiến mô hình ghi nhớ (memorization) thay vì học đặc trưng tổng quát.

---

## 2. Quy trình phân chia không rò rỉ (Leakage-Resistant Protocol)

```
[--------- TRAIN ---------] [PURGE GAP] [--- VAL ---] [PURGE GAP] [--- TEST ---]
      <= T_train - 300s         300s                     300s
      (Group set A)                         (Group set B)             (Group set C)
  
   BẢO ĐẢM TUYỆT ĐỐI: Group set A ∩ B = ∅, Group set A ∩ C = ∅, Group set B ∩ C = ∅
```

### 2.1 Các bước thực thi
1. **Sắp xếp theo thời gian:** Toàn bộ tập dữ liệu đa nguồn được sắp xếp đơn điệu theo trường thời gian chuẩn hóa UTC.
2. **Phân ranh giới cơ sở:** Tỷ lệ mặc định 70% Train, 15% Validation, 15% Test.
3. **Cửa sổ thanh lọc (Purge Window):** Tạo vùng đệm 300 giây (5 phút) tại các điểm giao cắt giữa Train-Val và Val-Test. Các bản ghi nằm trong vùng đệm bị loại bỏ (`purged_gap_rows`).
4. **Cô lập nhóm thực thể (Group Isolation):**
   - Khóa nhóm (`group_key`): Có thể là `session_id`, `(source_ip, dest_ip)`, hoặc `entity_id`.
   - Nếu bất kỳ nhóm nào đã xuất hiện trong tập Train mà tiếp tục xuất hiện trong Val hoặc Test, toàn bộ các bản ghi thuộc nhóm đó trong Val/Test lập tức bị thanh lọc (`purged_group_overlap_rows`).
5. **Kiểm định rò rỉ tự động (Assert Zero Overlap):**
   - Kiểm tra giao cắt giữa các tập: `len(train_groups ∩ val_groups) == 0`, `len(train_groups ∩ test_groups) == 0`, `len(val_groups ∩ test_groups) == 0`.
   - Nếu phát hiện bất kỳ overlap nào, tiến trình lập tức báo lỗi nghiêm trọng.

---

## 3. Cấu trúc Manifest phân chia mẫu

Manifest được xuất tại `data/processed/multi_source_split_manifest.json`:

```json
{
  "protocol_version": "multi-source-temporal-group-purged-v2",
  "source_name": "ait_multi_source_suite",
  "generated_at_utc": "2026-11-17T15:00:00Z",
  "purge_gap_seconds": 300.0,
  "group_key_column": "group_key",
  "total_rows_evaluated": 10000,
  "partitions": {
    "train_rows": 6800,
    "val_rows": 1420,
    "test_rows": 1410,
    "purged_gap_rows": 250,
    "purged_group_overlap_rows": 120
  },
  "leakage_audit": {
    "train_val_group_overlap": 0,
    "train_test_group_overlap": 0,
    "val_test_group_overlap": 0,
    "zero_leakage_verified": true
  }
}
```
