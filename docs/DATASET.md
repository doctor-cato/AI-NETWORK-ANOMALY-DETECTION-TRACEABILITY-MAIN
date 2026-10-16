# Bộ dữ liệu — UNSW-NB15

## Nguồn

- **Tên:** UNSW-NB15 (University of New South Wales — Network Based Data Set 15)
- **Nguồn chính (tham chiếu dự kiến; xác minh khi tải):**
  - Cổng dữ liệu UNSW Canberra Cyber Center
  - Bài báo / tài liệu từ UNSW (đã ghi trong tài liệu tham khảo)
- **Truy cập:** Công khai cho nghiên cứu / học thuật; kiểm tra giấy phép / điều khoản hiện tại trước khi phân phối lại.
- **Ngày truy cập / xác minh:** Chưa xác minh tại thời điểm viết (2026-10-16). Dự kiến xác nhận trước lần chạy huấn luyện đầu tiên.
- **Checksum / tính toàn vẹn file:** Chưa xác minh. Dự kiến ghi SHA-256 hoặc MD5 sau khi tải nếu có từ nguồn.

## Cấu trúc (dự kiến; xác minh sau khi tải)

- File CSV (ví dụ: UNSW-NB15.csv, UNSW-NB15_training_set.csv, UNSW-NB15_testing_set.csv tùy phiên bản phát hành).
- Các cột gồm: src_ip, dst_ip, sport, dport, proto, service, duration, state, sbytes, dbytes, sttl, dttl, sloss, dloss, sload, dload, spkts, dpkts, swin, dwin, stcpb, dtcpb, sresb, dresb, stime, atime, ltim, ct_flw_http_mthd, ct_flw_http_done, ct_src_ltm, ct_src_dport_ltm, ct_dst_sm, ct_dst_sport_ltm, ct_dst_ltm, ct_src_dport_ltm, is_ftp_login, ct_ftp_cmd, ct_ftp_subcmd, ct_flw_http_mthd, label (hoặc tương tự).
- Giá trị nhãn: thường 0 = bình thường, 1 = bất thường; một số phiên bản có danh mục tấn công (ví dụ: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms).

## Giấy phép / điều kiện sử dụng

- UNSW-NB15 được cung cấp cho mục đích nghiên cứu / học thuật. Không phân phối lại bộ dữ liệu dẫn xuất chứa dữ liệu gốc without confirming terms.
- Repo này KHÔNG chứa file UNSW-NB15 do kích thước (~2,5 GB nén, lớn hơn khi giải nén) và điều kiện cấp phép.
- Người dùng phải tải từ nguồn chính thức, đặt vào `data/raw/`, và kiểm tra schema trước khi chạy thực nghiệm.

## Hướng dẫn tải (dự kiến)

1. Truy cập cổng dữ liệu chính thức UNSW (liên kết sẽ xác nhận trong `REPRODUCIBILITY.md` sau khi kiểm tra).
2. Tải gói dữ liệu (CSV hoặc CSV + file nhãn).
3. Kiểm tra tên file và cấu trúc theo tài liệu.
4. Đặt file vào `data/raw/`.
5. Chạy `python scripts/validate_data.py`: tự kiểm tra mọi file hiện có trong hai tên `UNSW-NB15.csv`, `UNSW-NB15_training_set.csv`. Tên khác dùng `python scripts/validate_data.py --file <ten-file.csv>`. Script chỉ kiểm tra cấu trúc CSV: header có `label` và `proto`, tên cột không trống/trùng, có bản ghi và số cột mỗi bản ghi khớp header. Không yêu cầu IP vì biến thể dữ liệu có thể khác nhau; CSV không có header chưa được hỗ trợ. Kiểm tra đầy đủ kiểu dữ liệu, giá trị nhãn, missing values, duplicates và leakage còn là công việc tương lai.
6. Ghi phiên bản và checksum vào `REPRODUCIBILITY.md`. Khi không có file mặc định, script báo SKIPPED và exit 0; file được chỉ định qua `--file` mà thiếu hoặc CSV không hợp lệ phải exit khác 0. Không coi SKIPPED là validation dữ liệu thật PASS.

## Hạn chế dữ liệu (phải ghi trước khi huấn luyện)

- Mất cân bằng lớp được dự kiến (bình thường >> bất thường ở một số phiên bản).
- Có thể có giá trị thiếu; phải kiểm tra từng cột.
- Có thể có bản ghi trùng; phải kiểm tra và ghi quy tắc loại bỏ.
- Các cột định danh (IP nguồn / đích, port, thời gian) có thể gây rò rỉ nếu dùng trực tiếp hoặc nếu chia không theo thời gian / phiên; phải kiểm tra và ghi lại việc chọn / loại bỏ.
- Cần mã hóa đặc trưng cho biến phân loại (giao thức, dịch vụ, trạng thái, cờ TCP).

## Dữ liệu fixture cho kiểm thử

- `tests/unit/test_validate_data.py` tạo CSV fixture tổng hợp trong thư mục tạm để kiểm tra validation; không có file fixture dataset thật trong Git.
- Các test model hiện tại chỉ kiểm tra config/constructor; chưa kiểm chứng training hoặc pipeline trên UNSW-NB15. Fixture CSV không thay thế thực nghiệm dữ liệu thật.

Cập nhật: 2026-10-16 — hướng dẫn tải và xác minh checksum được dự kiến; chưa xác minh.
