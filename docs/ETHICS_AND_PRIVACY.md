# Đạo đức và quyền riêng tư

## Sử dụng dữ liệu

- Các dataset hiện hành (**AIT-NDS-v2**, **AIT-LDS-v2.1**, **AIT-ADS**, **CTU-SME-11**) áp dụng giấy phép **CC BY 4.0**: phải ghi nhận đầy đủ nguồn và DOI trích dẫn trong `NOTICE` và `THIRD_PARTY_NOTICES.md`. Nguồn cũ `NF-UNSW-NB15-v3` đã ngừng sử dụng trong active pipeline (chuyển vào `historical/`). Apache-2.0 của source code không relicense dataset.
- Repository này chỉ chứa hướng dẫn và mã nguồn; không kèm dataset.
- Mã nguồn và tài liệu không nhúng dữ liệu cá nhân như tên, địa chỉ hoặc nội dung mạng riêng tư.

## Bảo vệ quyền riêng tư

- Dữ liệu lưu lượng mạng có thể chứa thông tin nhạy cảm như IP, port và protocol. Khi xử lý dữ liệu thật, phải ẩn danh hoặc giới hạn quyền truy cập; không commit lưu lượng thô có thông tin nhận dạng.
- Dự án phân loại hành vi kết nối, không cố nhận diện cá nhân hoặc thiết bị cụ thể.
- Không đưa ra suy luận về kẻ tấn công hay danh tính cụ thể.

## Sử dụng an toàn và giới hạn

- Đây là hệ thống phục vụ học tập/nghiên cứu. Không triển khai như một biện pháp kiểm soát an ninh nếu chưa có kiểm chứng, audit và đánh giá chuyên gia bổ sung.
- Mô hình không bảo đảm phát hiện zero-day; mọi tuyên bố như vậy cần thực nghiệm có kiểm soát, hiện chưa được thực hiện.
- Cần diễn giải kết quả cùng với nguy cơ false positive và các giới hạn dữ liệu.

Cập nhật: 2026-10-20
