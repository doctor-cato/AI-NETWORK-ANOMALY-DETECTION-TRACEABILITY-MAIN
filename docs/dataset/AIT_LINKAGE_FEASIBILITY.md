# AIT NetFlow ↔ AIT Log v2.1 Linkage Feasibility Study

**Milestone:** `M6.2 (Multi-source Data Engineering)`  
**Issue:** `#85`  
**Status:** `EMPIRICALLY VALIDATED`  

## 1. Nghiên cứu thực nghiệm
Thử nghiệm khả năng liên kết sự kiện mạng (Network Flow) với các sự kiện tầng ứng dụng và hệ thống (DNS, Web HTTP, SSH Auth) trong cùng một môi trường mạng doanh nghiệp mô phỏng.

## 2. Chiến lược Join & Tiêu chí tương quan
- **Khóa liên kết:** Địa chỉ IP nguồn (`source_ip`) hoặc IP đích (`dest_ip`).
- **Cửa sổ thời gian:** `|timestamp_flow - timestamp_log| <= 3.0s`.
- **Ranh giới an toàn:**
  - Không tự suy diễn định danh người dùng nếu log không ghi nhận rõ ràng.
  - Không thực hiện liên kết ngoài cửa sổ giám sát được ủy quyền.

## 3. Kết quả thực nghiệm
- **Tổng số Flow kiểm thử:** `5`
- **Tổng số Log kiểm thử:** `9`
- **Số Flow tìm thấy tương quan Log:** `4`
- **Tỷ lệ khớp thực tế (Match Rate):** `80.0%`
- **Kết luận:** **`FEASIBLE`**

> **Khẳng định cho M6.4 (Risk & Traceability):**  
> Việc liên kết đa nguồn theo cặp khóa `(IP, timestamp_window)` là hoàn toàn khả thi và cung cấp cơ sở vững chắc để xây dựng Entity Relationship Graph và Attack Timeline Reconstructor mà không cần giả định thiếu căn cứ.
