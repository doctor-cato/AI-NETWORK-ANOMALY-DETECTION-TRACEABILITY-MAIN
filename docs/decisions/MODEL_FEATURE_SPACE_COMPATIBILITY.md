# Architecture Decision: Model Feature Space Compatibility & Zero-Imputation Policy

**Document ID:** `ADR-ML-002`  
**Milestone:** `M6.3 (AI Research)`  
**Issue:** `#95`  
**Status:** `APPROVED & ADOPTED`  

---

## 1. Bối cảnh & Vấn đề kỹ thuật

Phiên bản NetFlow Sentinel v2.0 mở rộng phạm vi giám sát từ luồng mạng thuần túy (NetFlow) sang kiến trúc đa nguồn kết hợp nhật ký tầng ứng dụng (DNS, Web HTTP, API) và nhật ký hệ thống (Auth sshd, Sysmon, Auditd).

Tuy nhiên, 4 họ mô hình học máy cốt lõi (Random Forest, XGBoost, Isolation Forest, Autoencoder) được thiết kế và tối ưu trên **Không gian đặc trưng 47 chiều chuẩn hóa nProbe v3 (NF-UNSW-NB15-v3 Baseline)**.
- Các bản ghi DNS, Web hoặc Auth chỉ chứa các trường ngữ cảnh (FQDN, URI, Username, HTTP Status, Process Name), hoàn toàn không có các đặc trưng thống kê luồng như `IN_BYTES`, `OUT_BYTES`, `FLOW_DURATION_MILLISECONDS`, `TCP_FLAGS`.
- Nếu cố ép các mô hình AI chạy trên dữ liệu này bằng cách điền giá trị 0 hoặc median ngầm (silent imputation), mô hình sẽ đưa ra các dự đoán sai lệch nghiêm trọng và làm suy giảm độ tin cậy của toàn bộ hệ thống.

---

## 2. Quyết định (Decision)

1. **Bảo toàn 4 Họ Mô hình Baseline:**
   - Bốn họ mô hình AI (Random Forest, XGBoost, Isolation Forest, Autoencoder) được giữ nguyên không gian đầu vào 47 đặc trưng luồng chuẩn hóa.
   - Không thực hiện retrain cưỡng bức trên tập dữ liệu tổng hợp pha tạp các đặc trưng phi luồng.
2. **Chính sách phân luồng Zero Imputation (Strict Zero-Imputation Routing):**
   - Chỉ các sự kiện có `event_kind == EventKind.FLOW` và thỏa mãn đầy đủ 47 đặc trưng (`is_ml_complete == True`) mới được đưa vào pipeline suy luận của 4 mô hình AI.
   - Các sự kiện thiếu đặc trưng hoặc thuộc tầng ứng dụng/hệ thống (`is_ml_complete == False`) sẽ được định tuyến sang chế độ **`route_only`**.
3. **Khai thác giá trị của dữ liệu phi luồng:**
   - Dữ liệu `route_only` được chuyển giao trực tiếp cho:
     - **Behavioral Sessionizer (#101, #102):** Tích lũy hành vi theo thực thể (host, user) để tạo vector hành vi 16 chiều.
     - **Multi-criteria Risk Engine (#108):** Tính điểm rủi ro dựa trên trọng số sự kiện xác thực và lỗi hệ thống.
     - **Entity Graph & Attack Timeline Reconstructor (#110, #112):** Liên kết ngữ cảnh để tái dựng đồ thị tấn công.

---

## 3. Hệ quả (Consequences)

- **Tích cực:** 
  - Loại bỏ hoàn toàn nguy cơ rò rỉ hoặc suy giảm độ chính xác do giá trị giả lập ngầm.
  - Tái sử dụng trọn vẹn kết quả nghiên cứu và trọng số mô hình đã được kiểm chứng của v1.0.0.
  - Phân định rõ ràng trách nhiệm giữa Tầng phát hiện luồng (AI NIDS) và Tầng tương quan hành vi (Behavioral & Trace Engine).
- **Tiêu cực:**
  - Mô hình AI không trực tiếp phân loại các trường text tự do trong application log (được bù đắp bằng các Rule-based Security Event Adapters).
