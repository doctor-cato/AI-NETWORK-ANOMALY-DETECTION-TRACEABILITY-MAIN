# UNSW-NB15: nguồn và đầu vào M1 (#4, #5)

## Biến thể và bằng chứng nguồn

Dự án dùng hai partition được trang UNSW công bố:
`UNSW_NB15_training-set.csv` (175.341 bản ghi) và
`UNSW_NB15_testing-set.csv` (82.332 bản ghi). Bốn file nguồn đầy đủ và các bản
parquet 49 cột là biến thể khác, không thuộc profile validation này.

Ngày 2026-10-17, trang UNSW truy cập được nhưng link tải SharePoint yêu cầu
forms-based authentication và trả HTTP 403 cho truy cập ẩn danh. UNSW không công bố
SHA-256 cho hai partition. Dự án lấy byte từ mirror GitHub tại revision cố định
`44bbd02b9e70f74dd915218d5eb702f125341ffc`, rồi đối chiếu độc lập:

- Kaggle `quohuysgu/unsw-nb15` v1 và `pankaj4321/unswnb15` v1: cả hai file trùng byte.
- Hugging Face `Mouwiya/UNSW-NB15` revision
  `8ad6b19373f143086a66f52b0d6035a6959d83a9`: training CSV trùng SHA-256;
  nguồn này không có testing CSV.
- Zenodo record 3768048 bị loại: file dùng tab, không có header và nội dung train/test
  nằm dưới tên ngược với partition UNSW.

Chi tiết URL, thời điểm UTC, revision, kích thước, checksum và giới hạn provenance nằm
trong `data/UNSW_NB15_MANIFEST.json`. Đây là checksum do dự án tính và được các mirror
corroborate, không phải checksum do UNSW xác nhận.

UNSW nêu dữ liệu được dùng miễn phí cho nghiên cứu học thuật; sử dụng thương mại cần
thỏa thuận với tác giả và phải trích dẫn các công trình trên trang nguồn. Metadata
license của mirror không thay thế điều khoản UNSW. Dataset không thuộc Apache-2.0 của
mã nguồn.

## Tải tái lập

```text
python scripts/fetch_unsw_nb15.py
python scripts/dataset_manifest.py verify
python scripts/validate_data.py --manifest data/UNSW_NB15_MANIFEST.json --report reports/data_quality/unsw_nb15_validation.json
```

`fetch_unsw_nb15.py` tải từng file vào thư mục tạm, yêu cầu HTTP 200, từ chối HTML
và Git LFS pointer, kiểm tra kích thước và SHA-256, rồi mới sao chép byte không đổi vào
`data/raw/`. File đã tồn tại chỉ được giữ nếu khớp manifest. Script dùng mirror
revision-pinned vì endpoint chính thức cần đăng nhập.

`data/raw/*` nằm ngoài Git. Kiểm tra bằng:

```text
git check-ignore data/raw/UNSW_NB15_training-set.csv data/raw/UNSW_NB15_testing-set.csv
git status --short
```

Không dùng `git add -f` cho CSV. Manifest và báo cáo tổng hợp không chứa dòng dữ liệu
gốc nên được version-control để reviewer tái kiểm tra cùng byte.

## Profile validation

`scripts/validate_data.py` kiểm tra UTF-8 BOM, đúng 45 cột theo thứ tự, độ rộng hàng,
kiểu số/text, số hữu hạn, nhãn binary `0/1`, các trường bắt buộc và tính nhất quán:
`label=0` phải có `attack_cat=Normal`, còn `label=1` phải là category khác. Khi
dùng manifest, validator kiểm tra size, SHA-256 và số bản ghi chính thức.

Báo cáo riêng cho mỗi split gồm số hàng/cột, schema, phân bố nhãn và attack category,
missing theo cột, duplicate sau khi bỏ cột định danh `id`, invalid labels và tỷ lệ lớp.
Sai schema/hash/size/row count/nhãn/kiểu/cấu trúc là lỗi chặn (exit 1). Missing feature
không bắt buộc và duplicate là cảnh báo; validator không xóa, điền, chuẩn hóa hay thay
đổi dữ liệu.

Kết quả thực ngày 2026-10-17 nằm tại
`reports/data_quality/unsw_nb15_validation.json`: cả hai split khớp manifest, schema
45 cột, số hàng 175.341/82.332, không missing, không invalid label và không mâu thuẫn
label/category. Duplicate bỏ qua `id` lần lượt là 67.601 và 26.387; đây là đầu vào
cho leakage audit ở issue sau, không bị tự động xóa trong #5.

Khi cả hai CSV vắng mặt, validator in `SKIPPED` và exit 0 theo contract M0; trạng thái
đó không phải PASS. Fixture tổng hợp chỉ kiểm tra hành vi validator, không thay thế báo
cáo dữ liệu thật.
