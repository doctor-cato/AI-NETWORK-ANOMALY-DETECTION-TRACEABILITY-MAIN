# Bổ sung đề xuất cho GitHub Issues (chưa cập nhật từ xa)

**Lý do chưa cập nhật từ xa:** Không có `GITHUB_TOKEN`/`gh` CLI ghi quyền; `curl` chỉ đọc. Các đề xuất dưới đây cần được áp dụng thủ công trên GitHub hoặc khi có quyền API.

## Các Issue liên quan đã audit (từ API)

| # | Trạng thái | Tiêu đề | Milestone | Ghi chú đề xuất |
|---|---|---|---|---|
| 11 | open | Isolation Forest implementation and evaluation protocol | M3 | **Đánh dấu tùy chọn**. Thêm điều kiện: chỉ thực hiện sau khi RF baseline ổn, pipeline đánh giá độc lập hoàn thành, inference/demo tối thiểu chạy được. Yêu cầu mô tả rõ cách chuyển score → nhãn, chọn threshold trên validation, đánh giá trên test. |
| 9 | open | Baseline implementation — establish comparison point | M2 | **Làm rõ RF là baseline chính**; có thể thêm baseline đơn giản nếu hữu ích nhưng không làm chậm tiến độ. Không bắt buộc nhiều thuật toán. |
| 8 | open | Preprocessing pipeline design and reproducibility | M2 | Giữ nguyên; chỉ bổ sung yêu cầu fit chỉ trên train, lưu artifact. |
| 15 | open | Inference pipeline — load artifacts and predict new input | M4 | **Bổ sung kiểm thử thực tế**: cần CLI/script dự đoán trên CSV; kiểm tra cột bắt buộc, dữ liệu thiếu; dùng preprocessing đã fit; sinh CSV kết quả; báo lỗi nếu artifact chưa có. |
| 16 | open | Demo and visualization — minimal demo and result plots | M4 | **Ưu tiên Streamlit** nếu chưa có giải pháp tương đương. Cho phép upload CSV, hiển thị số dự đoán bình thường/bất thường theo bản ghi, tải CSV đầu ra, báo lỗi rõ khi schema sai hoặc artifact thiếu. Dùng chính pipeline inference đã kiểm thử. |
| 17 | open | Unit and integration tests — import, pipeline, basic predictions | M4 | Phân biệt rõ fixture synthetic (`fixture_small.csv`) với đánh giá thực tế UNSW-NB15. CI có thể SKIP phần đánh giá dữ liệu thật có chủ đích; không coi SKIP là bằng chứng model đã đánh giá thật. |

## Đề xuất nội dung bổ sung chung cho Inference / Demo / Test (mức Issue hoặc note)

**A. Train và đánh giá thực tế**
- Tải UNSW-NB15 từ nguồn xác nhận (`docs/DATASET.md`).
- Kiểm tra schema, nhãn (`label`), missing values, kiểu dữ liệu.
- Xác định bài toán nhị phân normal/anomaly hay phân loại đa lớp.
- Chia train/val/test đúng (stratified hoặc theo thời gian; ghi chiến lược + seed).
- Fit preprocessing chỉ trên train.
- Huấn luyện RF với seed và cấu hình tái lập (`RANDOM_FOREST_DEFAULTS`).
- Đánh giá trên test độc lập; tính Precision, Recall, F1, Macro-F1, confusion matrix, FPR.
- Ghi kết quả thực tế, cấu hình, phiên bản thư viện; không dùng test set chọn mô hình/ngưỡng.

**B. Lưu và nạp artifact**
- Lưu model cùng preprocessing đã fit, thứ tự/tên feature.
- Script inference phải nạp artifact; nếu thiếu phải báo rõ và hướng dẫn chạy train.
- Không commit dataset / model artifact lớn vào Git (trừ khi có cơ chế lưu trữ được phê duyệt).

**C. Inference trên CSV mới**
- CLI/script cho CSV đầu vào.
- Kiểm tra cột bắt buộc, kiểu dữ liệu, xử lý thiếu.
- Dùng đúng preprocessing đã fit (không fit lại).
- Sinh CSV kết quả với prediction từng bản ghi.
- Nếu có nhãn thật: tính metrics sau khi xác định đúng target; nếu không: chỉ hiển thị dự đoán, không bịa Precision/Recall/F1.

**D. Demo tối thiểu (ưu tiên Streamlit)**
- Upload CSV.
- Hiển thị tổng số dự đoán bình thường / bất thường.
- Hiển thị kết quả từng bản ghi.
- Tải CSV đầu ra.
- Báo lỗi dễ hiểu khi schema sai hoặc artifact chưa tồn tại.
- Có hướng dẫn chạy local trên Windows.

**E. Kiểm thử tự động**
- Unit: preprocessing, load model, schema check.
- Integration: nạp artifact → dự đoán → xuất kết quả.
- Fixture nhỏ cố định cho CI không cần tải dataset lớn.
- Phân biệt smoke test synthetic và đánh giá thực tế UNSW-NB15.
- Khi dataset chưa có, CI SKIP rõ ràng; không coi SKIP là bằng chứng model đã đánh giá.

## Đề xuất chỉnh sửa Milestone (đã Vietnamese một phần từ trước)

- M0 → M5 đã có tên tiếng Việt; chỉ cần đảm bảo mô tả phản ánh đúng thứ tự trên và IF được đánh dấu tùy chọn ở M3.
- Không đổi milestone ID, không đóng/mở tùy tiện, không chuyển Issue sang milestone khác không có lý do.

## Đề xuất chỉnh sửa Labels (từ API: 23 label)

- `bug`, `documentation`, `duplicate`, `enhancement`, `good first issue`, `help wanted`, `invalid`, `priority:*`, `question`, `type:*`, `wontfix`: có thể dịch mô tả nếu không ảnh hưởng automation;
- `accessibility`, `area:*`: giữ nguyên vì có thể liên quan workflow; chỉ dịch description nếu an toàn.
- Không đổi tên mặc định hệ thống (ví dụ `bug`, `enhancement`) nếu có automation dựa trên chúng.
