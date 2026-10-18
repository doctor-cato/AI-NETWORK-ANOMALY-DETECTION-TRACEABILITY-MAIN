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

Mọi timestamp trong manifest dùng ISO 8601 nguyên giây kèm offset tường minh:
`YYYY-MM-DDTHH:MM:SSZ` hoặc `YYYY-MM-DDTHH:MM:SS±HH:MM`. Naive datetime không được
dùng. `record` chuẩn hóa `--downloaded-at` về UTC trước khi ghi, nên timestamp có
offset khác UTC có thể đổi ngày theo lịch. `verify` kiểm tra mọi trường timestamp
tìm thấy trong manifest và từ chối giá trị naive, sai định dạng hoặc không phải chuỗi;
`verify` chỉ đọc, không bao giờ ghi lại provenance hay thêm timestamp biến động.

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

`fetch_unsw_nb15.py` tái sử dụng cache local an toàn: mỗi file đã có trong `data/raw/`
được kiểm tra lại tiền tố (HTML, Git LFS pointer), kích thước và SHA-256 trước khi
quyết định. File hợp lệ được giữ nguyên và log `CACHE_HIT`, nên chạy lại không gọi
mạng. File thiếu hoặc sai checksum được log `CACHE_INVALID` kèm lý do rồi tải lại từ
mirror revision-pinned. Byte tải về nằm ở staging tạm cùng thư mục đích, được kiểm tra
trọn vẹn trước khi thay thế nguyên tử (`DOWNLOAD` rồi `VERIFIED`), và staging luôn
được dọn kể cả khi lỗi. Không tin cache chỉ dựa trên tên file hay kích thước.

Cài đặt chỉ diễn ra sau khi mọi file cần thiết đã tải và verify xong. Trước khi thay byte
đầu tiên, script sao lưu bản cũ của mọi file sẽ bị thay. Nếu `os.replace` thất bại ở bất kỳ
file nào, script hoàn nguyên các file **đã thay** về byte trước đó rồi ném lại lỗi gốc.

Nguyên tắc phục hồi: **không bao giờ xóa dữ liệu hợp lệ trước khi biết bản thay thế đã
nằm đúng chỗ.** Vì `os.replace` ghi đè đích một cách nguyên tử, khôi phục không cần xóa
file đích trước; nếu bản khôi phục lỗi, file đích vẫn giữ byte mới đã verify và bản sao lưu
được giữ lại, kèm dòng `RECOVERY` chỉ rõ tên file để phục hồi thủ công. File mới tạo ra
trong lần chạy đó không có bản cũ để khôi phục nên được giữ lại kèm dòng `ROLLBACK: kept`,
vì xóa đi chỉ là vứt bỏ byte đã verify mà không thu được gì.

Dọn staging và backup trong `finally` không được ném lỗi mới đè lên lỗi đang báo; lỗi dọn
được ghi `CLEANUP WARNING`. Backup chỉ bị xóa khi nó không còn là bản duy nhất.

Tên file staging và backup có kèm PID, nên hai lần tải chạy đồng thời không dùng chung file
tạm. Vì mọi byte đều đã verify trước khi thay, hai tiến trình cùng thay vẫn cho ra kết quả
giống hệt.

Script dùng mirror revision-pinned vì endpoint chính thức cần đăng nhập.

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

Dòng trống không bị bỏ qua âm thầm. Dòng không có delimiter và không có giá trị (rỗng
hoặc chỉ khoảng trắng) được đếm và là lỗi chặn, thông báo nêu tổng số dòng và vị trí tối
đa 5 dòng đầu. Dòng có delimiter nhưng giá trị rỗng không phải dòng trống: đủ 45 cột
thì thành missing value, thiếu cột thành lỗi độ rộng hàng. Báo cáo cho mỗi split gồm
số hàng/cột, schema, số dòng trống, phân bố nhãn và attack category, missing theo cột,
duplicate sau khi bỏ cột định danh `id`, invalid labels và tỷ lệ lớp.
Sai schema/hash/size/row count/nhãn/kiểu/cấu trúc/dòng trống là lỗi chặn (exit 1).
Missing feature không bắt buộc và duplicate là cảnh báo; validator không xóa, điền,
chuẩn hóa hay thay đổi dữ liệu.

Kết quả thực ngày 2026-10-17 nằm tại
`reports/data_quality/unsw_nb15_validation.json`: cả hai split khớp manifest, schema
45 cột, số hàng 175.341/82.332, không dòng trống, không missing, không invalid label và
không mâu thuẫn label/category. Duplicate bỏ qua `id` lần lượt là 67.601 và 26.387;
đây là đầu vào cho leakage audit ở #7, không bị tự động xóa trong #5.

Khi cả hai CSV vắng mặt, validator in `SKIPPED` và exit 0 theo contract M0; trạng thái
đó không phải PASS. Fixture tổng hợp chỉ kiểm tra hành vi validator, không thay thế báo
cáo dữ liệu thật.
