# NF-UNSW-NB15-v3 source and provenance report

## Nguồn chính thức

| Trường | Giá trị đã xác minh ngày 2026-10-20 |
| --- | --- |
| Publisher | The University of Queensland |
| Dataset | `NF-UNSW-NB15-v3` |
| DOI | `10.48610/6E0EDA1` |
| UQ RDM UUID | `abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f` |
| Landing page | <https://staff.itee.uq.edu.au/marius/NIDS_datasets/> |
| Metadata API | <https://api.rdm.uq.edu.au/datasets/abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f/file-details> |
| Download API | <https://api.rdm.uq.edu.au/datasets/abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f/download> |
| Access | Open, anonymous download URL do API cấp, URL S3 hết hạn sau một giờ |
| Issued | 2025; UQRDM package tạo 2025-02-28 và publish 2025-03-05 |
| License | `Permitted Re-Use with Commercial Use Restriction` |
| Obligations | Full citation/acknowledgement; non-commercial use only |

Điều kiện license được đọc từ metadata API (`externalId=454104`) và trang UQ
“Permitted reuse with commercial use restriction”. Link `terms_and_conditions` cũ trong
record trả 404, nhưng client UQRDM hiện ánh xạ đúng license ID sang trang điều kiện mới.

## Công trình liên quan

Majed Luay, Siamak Layeghy, Seyedehfaezeh Hosseininoorbin, Mohanad Sarhan,
Nour Moustafa và Marius Portmann, “Temporal Analysis of NetFlow Datasets for Network
Intrusion Detection Systems”, arXiv:2503.04404. Bản đầu nộp ngày 2025-03-06. Dataset
landing page yêu cầu dùng citation này cho NetFlow v3.

## Package thực tế

- Media type: `application/zip`; HTTP range được hỗ trợ.
- Archive size: `110825147` bytes.
- Archive SHA-256 do dự án tính từ byte tải chính thức:
  `6d51554df43e324ba8d68fc31a02a83d860ba0a3a93d63320a4a6fc314c9cdfd`.
- S3 version ID quan sát khi kiểm tra:
  `hs070VLSKCiR6pCh0N0Y4qUg1FQOHULp`.
- Package identifier: `f7546561558c07c5_NFV3DATA-A11964_A11964`.
- Payload CSV: `data/NF-UNSW-NB15-v3.csv`, `577360958` bytes.
- Feature dictionary: `data/NetFlow_v3_Features.csv`, `2935` bytes.
- Package là BagIt 0.96 và có publisher-bundled `manifest-sha1.txt`.

SHA-256 ở trên và trong manifest repository là **project-computed local checksum**, không
phải SHA-256 do tác giả công bố. Publisher-bundled SHA-1 cho hai payload lần lượt là:

- `2cba4879ead17c51e3268a01c06af41186cd90e4` — `NF-UNSW-NB15-v3.csv`;
- `d028597391217f78df3db31c1dbd96805203196f` — `NetFlow_v3_Features.csv`.

## Sai khác giữa website và dữ liệu thật

CSV có đúng `2365424` data rows. Binary label thật là `2237731` benign và `127693`
attack; tổng này khớp row count. Website ghi `127639` attack, thiếu 54 so với file thật.
Website cũng gắn count `2381`, `1226`, `4659` lần lượt cho Analysis, Backdoor,
Shellcode, trong khi CSV thật gắn lần lượt `1226`, `4659`, `2381`. Manifest và validator
dùng file thật làm contract; tài liệu vẫn lưu sai khác này thay vì tự sửa nguồn.

## Khả năng tái lập

Download phải gọi stable UQRDM API để nhận signed URL mới, stream vào staging, giới hạn
đúng kích thước đã ghim, kiểm tra ZIP magic/size/SHA-256, kiểm tra archive path và
decompressed-size, xác minh từng payload rồi mới publish. Không ghi signed URL hết hạn
vào manifest và không dùng mirror khi API/DOI chính thức không khả dụng.
