# NetFlow Sentinel v2.0 — Trace Engine & Entity Relationship Graph

> **Tài liệu kỹ thuật Trace Engine (Issues #110, #111 — Milestone M6.4)**  
> **Phiên bản:** 2.0.0-trace  
> **Module thực thi:** `src/network_anomaly/trace/`

---

## 1. Giới thiệu và Mục tiêu
Trace Engine v2 là công cụ truy vết và phân tích ngữ cảnh đe dọa, kết nối các sự kiện mạng rời rạc thành đồ thị quan hệ thực thể (Entity Relationship Graph).

Khác biệt cốt lõi của Trace Engine v2:
- **Phân định Rạch ròi giữa Quan sát Thực tế (`is_observed=True`) và Suy luận Giả thuyết (`is_observed=False`):** Ngăn ngừa việc đưa ra các kết luận điều tra không có căn cứ thực nghiệm.
- **Alert Deduplication:** Khử trùng lặp cảnh báo trong cửa sổ thời gian trượt (mặc định 60s) để chống tràn ngập thông tin cho chuyên viên phân tích.
- **Bounded Traversal:** Giới hạn độ sâu duyệt đồ thị (`max_depth=5`) và số lượng nút (`max_nodes=200`) để đảm bảo đáp ứng thời gian thực và chống cạn kiệt bộ nhớ.

---

## 2. Cấu trúc Đồ thị Quan hệ Thực thể (Entity Graph Schema)

### 2.1. Các loại Nút (Entity Nodes)
- `IP`: Địa chỉ IP nguồn hoặc đích (`192.168.1.100`, `10.0.0.5`).
- `PORT`: Cổng dịch vụ mạng (`port:80`, `port:445`, `port:3389`).
- `DOMAIN`: Tên miền truy vấn DNS (`malicious.example.com`).
- `USER`: Danh tính tài khoản xác thực (`user:admin`, `user:root`).
- `PROCESS`: Tên tiến trình hệ thống (`powershell.exe`, `mimikatz.exe`).
- `ALERT`: Bản ghi cảnh báo bất thường từ AI Detection Engine.

### 2.2. Các loại Cạnh (Relation Edges)
- `CONNECTS_TO`: Kết nối luồng mạng giữa 2 nút (Quan sát thực nghiệm).
- `RESOLVES_TO`: Phân giải DNS giữa domain và IP (Quan sát thực nghiệm).
- `AUTHENTICATES_AS`: Phiên đăng nhập giữa host và tài khoản (Quan sát thực nghiệm).
- `SPAWNS`: Tiến trình cha tạo tiến trình con (Quan sát thực nghiệm).
- `TRIGGERED_ALERT`: Cạnh nối giữa sự kiện mạng và cảnh báo rủi ro (Quan sát thực nghiệm).
- `SIMILAR_BEHAVIOR`: Cạnh nối giữa 2 thực thể hoặc 2 phiên có khoảng cách Cosine trên Behavioral Vector $\ge 0.85$ (Suy luận dựa trên độ tương đồng).

---

## 3. Thuật toán Duyệt Đồ thị (Graph Traversal & Root Cause Tracing)
Trace Engine sử dụng thuật toán tìm kiếm theo chiều rộng (Breadth-First Search - BFS) có kiểm soát ranh giới tin cậy:
1. Nhận `start_node_id` (nút gốc cần truy vết, ví dụ: IP máy chủ bị tấn công hoặc ID cảnh báo).
2. Duyệt các lân cận vào (`in-degree`) để tìm nguồn gốc xâm nhập (Root Cause / Threat Actor).
3. Duyệt các lân cận ra (`out-degree`) để đánh giá phạm vi ảnh hưởng (Blast Radius / Lateral Movement).
4. Tách kết quả thành 2 nhóm danh sách: `observed_edges` và `inferred_edges`.
