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

Cài đặt chỉ diễn ra sau khi mọi file cần thiết đã tải và verify xong. Byte tải về được
ghi với giới hạn cứng bằng kích thước đã ghim: vòng đọc dừng ngay ở byte vượt quá, nên
mirror hoặc trung gian trả body vô hạn không thể đầy đĩa trước khi kiểm tra kích thước.
Trước khi thay byte đầu tiên, script sao lưu bản cũ của mọi file sẽ bị thay. Nếu
`os.replace` thất bại ở bất kỳ file nào, script hoàn nguyên các file **đã thay** về byte
trước đó rồi ném lại lỗi gốc.

Nguyên tắc phục hồi: **không bao giờ xóa dữ liệu hợp lệ trước khi biết bản thay thế đã
nằm đúng chỗ.** Vì `os.replace` ghi đè đích một cách nguyên tử, khôi phục không cần xóa
file đích trước; nếu bản khôi phục lỗi, file đích vẫn giữ byte mới đã verify và bản sao lưu
được giữ lại, kèm dòng `RECOVERY` chỉ rõ tên file để phục hồi thủ công. File **mới tạo ra**
trong lần chạy đó không có bản cũ, nên rollback xóa nó để thư mục trở về đúng trạng thái
trước lần chạy: chỉ byte do chính lần chạy này tải về bị bỏ đi và lần chạy sau tải lại
được. Nếu thao tác xóa đó lỗi, file vẫn được giữ lại và báo `ROLLBACK WARNING` kèm tên
file trong `RECOVERY` để dọn thủ công — thư mục có thể tạm thời lệch so với manifest cho
đến khi chạy lại `fetch_unsw_nb15.py`.

Dọn staging và backup trong `finally` không được ném lỗi mới đè lên lỗi đang báo; lỗi dọn
được ghi `CLEANUP WARNING`. Backup chỉ bị xóa khi nó không còn là bản duy nhất. Nếu
`shutil.copyfile` lỗi giữa chừng, file backup dở dang bị xóa ngay để không tích tụ file tạm
qua nhiều lần chạy lỗi. Tên backup lấy tên trống kế tiếp nếu tên chuẩn đã tồn tại, vì PID
được tái sử dụng: một backup còn sót sau khi khôi phục lỗi là bản duy nhất của byte cũ và
không được lần chạy sau ghi đè hay xóa.

Mỗi thư mục đích có một lock `.unsw-nb15.lock` giữ xuyên suốt giao dịch: kiểm tra cache,
tải, sao lưu, mọi lần thay và cả rollback. Tên staging/backup có kèm PID chỉ ngăn hai lần
chạy dùng chung **tên file tạm**; nếu không có lock, tiến trình A có thể rollback đè bản cũ
của một file lên cặp file mới mà tiến trình B vừa cài xong, để lại train/test lệch phiên bản.

Lock là **khóa byte-range của hệ điều hành** (`msvcrt.locking` trên Windows, `fcntl.flock`
trên POSIX), không phải file đánh dấu kèm luật "stale". Kernel giải phóng khi tiến trình
kết thúc, kể cả khi bị giết cứng, nên không tồn tại trạng thái lock bỏ rơi và không có bước
"phá lock cũ" nào có thể xóa nhầm lock của một tiến trình chỉ vì nó chậm — đó chính là race mà
luật dựa trên mtime tạo ra. File lock **được giữ lại** sau khi thả, vì xóa nó sẽ cho phép tiến
trình khác tạo inode mới và giành lock trong lúc lần chạy hiện tại vẫn nghĩ mình đang giữ.
Lần chạy thứ hai chờ tối đa 900s rồi báo lỗi nếu lock chưa được giải phóng.

`dataset_manifest.py` không dùng lock của `fetch_unsw_nb15.py`. Chạy `record` đúng lúc một
lần fetch đang thay file có thể ghi lại trạng thái lẫn, nhưng `verify` chạy sau đó sẽ báo
mismatch SHA-256, nên sai lệch bị phát hiện chứ không lan. `record` cũng từ chối ghi đè một
manifest đã tồn tại.

Tên staging và backup có kèm PID nên hai lần chạy đồng thời không dùng chung file tạm; cả hai đều
được mở bằng `O_CREAT|O_EXCL` sau khi xóa bất kỳ thứ gì đang nằm ở tên đó. Tên scratch là tất
định, nên một symlink được cài sẵn tại đó sẽ chuyển hướng ghi ra ngoài thư mục đích trước khi
checksum kịp kiểm tra; `O_EXCL` làm cho việc mở file trở nên nguyên tử và an toàn với symlink
trên cả Windows, nơi không có `O_NOFOLLOW`.

Cài đặt ghi một marker `.unsw-nb15-transaction.json` **trước lần thay đầu tiên**, ghi lại trạng
thái trước đó của từng file (tên backup, hoặc "trước đó không tồn tại"). Rollback chỉ chạy khi
tiến trình còn sống, nên nếu bị giết cứng giữa hai lần thay thì lần chạy sau thấy marker và
hoàn nguyên cặp file về đúng trạng thái trước đó **trước khi** tin vào cache. Marker bị xóa khi
cài đặt thành công, khi rollback hoàn tất và sau khi recovery; nếu rollback còn file chưa khôi
phục được thì marker được giữ lại cho lần chạy sau.

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
dùng manifest, validator kiểm tra size và SHA-256. Số bản ghi chính thức của hai split
(175.341 và 82.332) được kiểm tra khi không có manifest, và khi manifest có ghi
`expected_rows` thì lấy theo manifest; `--no-row-count` bỏ qua **cả hai** nguồn cho
fixture hoặc tập con. File không thuộc hai split mặc định thì không có số bản ghi công bố
để so.

Dòng trống không bị bỏ qua âm thầm. Dòng không có delimiter và không có giá trị (rỗng
hoặc chỉ khoảng trắng) được đếm và là lỗi chặn, thông báo nêu tổng số dòng và vị trí tối
đa 5 dòng đầu. Dòng có delimiter nhưng giá trị rỗng không phải dòng trống: đủ 45 cột
thì thành missing value, thiếu cột thành lỗi độ rộng hàng. Báo cáo cho mỗi split gồm
số hàng/cột, schema, số dòng trống, phân bố nhãn và attack category, missing theo cột,
duplicate sau khi bỏ cột định danh `id`, invalid labels và tỷ lệ lớp.
Sai schema/hash/size/row count/nhãn/kiểu/cấu trúc/dòng trống là lỗi chặn (exit 1).
`--report` trỏ tới chính file CSV đầu vào, hoặc tới manifest được dùng làm đối chiếu (kể cả
khi resolve về cùng một file), đều bị từ chối trước khi ghi — validator tuyên bố chỉ đọc và
không sửa dữ liệu lẫn provenance của nó.
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
