# Báo cáo Đánh giá Tổng quát hóa Cross-Dataset (Issue #46)

**Tập dữ liệu Kiểm định Ngoại vi:** `NF-CSE-CIC-IDS2018-v3`  
**Mô hình Đánh giá:** Canonical Random Forest (`rf-baseline-canonical-v1`)  
**Thời gian Đánh giá:** `2026-11-08T14:40:22.328420+00:00`  
**Số dòng Đánh giá:** `100,000` dòng  
**Thời gian Thực thi:** `7.52` giây  
**Trạng thái Tương thích:** `MODEL_VALIDATED`  

---

## 1. Tóm tắt Đối chiếu Hiệu năng (Internal Validation vs External Benchmark)

| Chỉ số (Metric) | Nội bộ `NF-UNSW-NB15-v3` (Validation) | Ngoại vi `NF-CSE-CIC-IDS2018-v3` (Generalization) | Độ Lệch ($\Delta$) | Nhận xét & Đánh giá Khoa học |
|---|:---:|:---:|:---:|---|
| **Accuracy** | `0.999977` | `0.433990` | `-0.565987` | Tổng quan độ chính xác phân loại toàn cục. |
| **Precision** | `0.999836` | `0.000000` | `-0.999836` | Tỷ lệ dự đoán Attack thực sự là tấn công. |
| **Recall** | `0.999902` | `0.000000` | `-0.999902` | Tỷ lệ bắt giữ tấn công thực tế trên môi trường mạng mới. |
| **F1-Score** | `0.999869` | `0.000000` | `-0.999869` | Đo lường cân bằng giữa Precision và Recall. |
| **Macro-F1** | `0.999928` | `0.302645` | `-0.697283` | Trung bình không trọng số giữa Benign và Attack. |
| **False Positive Rate (FPR)** | `0.000016` | `0.380191` | `+0.380175` | Tỷ lệ báo động giả trên lưu lượng bình thường. |

---

## 2. Ma trận Nhầm lẫn (Confusion Matrix)

Trục tung: Nhãn Thực tế (Ground Truth) — Trục hoành: Mô hình Dự đoán (Predicted)

```text
                  Predicted Benign (0)    Predicted Attack (1)
Actual Benign (0)              43,399                  26,621   (TN / FP)
Actual Attack (1)              29,980                       0   (FN / TP)
```

- **True Negatives (TN):** `43,399`
- **False Positives (FP):** `26,621` (Báo động giả)
- **False Negatives (FN):** `29,980` (Bỏ lọt tấn công)
- **True Positives (TP):** `0`

---

## 3. Phân tích Chi tiết theo Từng Họ Tấn công (Per-Category Breakdown)

| Danh mục Lưu lượng | Tổng số Dòng | Phát hiện Đúng | Bỏ lọt (Missed) / Dương tính Giả (FP) | Tỷ lệ Thành công |
|---|:---:|:---:|:---:|:---:|
| **Benign** | `70,020` | `43,399` (TN) | `26,621` (FP) | FPR: `38.0191%` |
| **FTP-BruteForce** | `29,980` | `0` (TP) | `29,980` (FN) | Recall: `0.0000%` |

---

## 4. Phân tích Nguyên nhân Lệch Phân phối (Domain Shift & Shortcut Collapse Analysis)

Kiểm toán thực nghiệm xác nhận kết luận chẩn đoán tại `rf_baseline_validation_audit.json`:

1. **Sự sụp đổ của Shortcut `MIN_TTL`:**
   - Trong tập dữ liệu phòng lab `NF-UNSW-NB15-v3` (IXIA PerfectStorm), `MIN_TTL` là một đường tắt phân loại gần như tuyệt đối (`MIN_TTL=31` là 100% Benign; `MIN_TTL ∈ {62, 254, 255}` là 99.997% Attack).
   - Khi chuyển sang môi trường AWS thực tế của `NF-CSE-CIC-IDS2018-v3`, có tới **`99,990` dòng (99.99%)** có `MIN_TTL` hoàn toàn nằm ngoài 4 giá trị lab này (chủ yếu là `MIN_TTL=0` hoặc các bước nhảy định tuyến Internet thực tế).
   - Điều này giải thích định lượng lý do tại sao hiệu năng trên miền dữ liệu mới thay đổi và minh chứng tính tất yếu của **Cổng OOD (Out-of-Distribution Gate)** nhằm cảnh báo người vận hành khi dữ liệu mạng không còn tuân theo phân phối huấn luyện ban đầu.

2. **Khuyến nghị Vận hành Sản phẩm (Milestone M6):**
   - Không được công bố mô hình đạt 99.99% trong production mà phải hiển thị rõ trạng thái `OOD_WARNING` trên Dashboard Streamlit (#16).
   - Tự động chuyển các sự kiện có độ tin cậy thấp hoặc drift shortcut sang **Trace Engine (#24)** và **Risk Engine (#32)** để kiểm chứng đa chiều.
