# NF-UNSW-NB15-v3: nguồn, acquisition và quality gate

## Dataset mặc định

`NF-UNSW-NB15-v3` là dataset network-flow mặc định duy nhất. Gói UQRDM đã xác minh chứa một CSV
2.365.424 dòng, 53 feature và hai target `Label`/`Attack`. UNSW-NB15 (2015) không còn được gọi bởi
pipeline mặc định; artifact cũ nằm trong các thư mục `historical/`.

Nguồn chuẩn:

- University of Queensland NIDS datasets: <https://staff.itee.uq.edu.au/marius/NIDS_datasets/>
- DOI: <https://doi.org/10.48610/6E0EDA1>
- UQRDM UUID: `abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f`
- Paper liên quan: arXiv `2503.04404`
- License record: `Permitted Re-Use with Commercial Use Restriction`; phải trích dẫn đầy đủ và
  chỉ dùng cho mục đích phi thương mại.

Chi tiết bằng chứng nằm tại `docs/dataset/NF_UNSW_NB15_V3_PROVENANCE.md`. SHA-256 trong manifest
do dự án tính từ byte tải qua API chính thức, không được mô tả là checksum chính thức của tác giả.

## Layout thống nhất

| Vai trò | Đường dẫn |
|---|---|
| Manifest version-control | `data/NF_UNSW_NB15_V3_MANIFEST.json` |
| Package local, ignored | `data/raw/NF-UNSW-NB15-v3/` |
| Dataset CSV | `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` |
| Feature dictionary | `data/raw/NF-UNSW-NB15-v3/data/NetFlow_v3_Features.csv` |
| Quality report | `reports/data_quality/nf_unsw_nb15_v3_validation.json` |
| Downloader | `scripts/fetch_nf_unsw_nb15_v3.py` |
| Manifest verifier | `scripts/dataset_manifest.py` |
| Validator | `scripts/validate_data.py` |

## Acquisition tái lập

```text
python scripts/fetch_nf_unsw_nb15_v3.py
python scripts/dataset_manifest.py verify
```

Fetcher:

- lấy signed HTTPS URL từ UQRDM API và xác minh UUID/access state;
- tải streaming vào staging, dừng nếu vượt `110825147` byte;
- từ chối HTML, ZIP magic sai, checksum sai, archive traversal, symlink, member lạ/thiếu và
  extracted size vượt giới hạn;
- xác minh SHA-256 của archive và từng member trước publish;
- dùng lock theo destination để tuần tự hóa concurrent fetch;
- ghi transaction marker trước swap, giữ backup và phục hồi sau lỗi/crash;
- chỉ trả `CACHE_HIT` khi toàn bộ bảy member vẫn đúng size/checksum.

Raw package không được commit. Kiểm tra boundary:

```text
git check-ignore data/raw/NF-UNSW-NB15-v3
```

## Schema và target

Manifest ghi đúng thứ tự 55 cột. Phân loại vai trò:

- 53 NetFlow v3 fields;
- binary target `Label`: `0` benign, `1` attack;
- multiclass target `Attack`: `Benign`, `Analysis`, `Backdoor`, `DoS`, `Exploits`, `Fuzzers`,
  `Generic`, `Reconnaissance`, `Shellcode`, `Worms`;
- absolute timestamps và IP được giữ như trace metadata và mặc định loại khỏi `X`;
- `Label` và `Attack` tuyệt đối không đi vào `X`.

Website UQ và CSV không đồng nhất ở tổng attack và ánh xạ ba category count. Manifest theo byte CSV
đã tải và giữ mô tả discrepancy. Xem `docs/dataset/NF_UNSW_NB15_V3_SCHEMA.md`.

## Validation thật

```text
python scripts/validate_data.py
```

Validator stream CSV, kiểm tra schema/order, width, row count, numeric/NaN/Inf/missing, giá trị âm,
IPv4, port, label/category consistency, timestamp ordering và duration. Exact và near-duplicate
fingerprint được ghi vào SQLite tạm để RAM không tăng theo số dòng.

Kết quả đã ghi trong repository là **FAIL**:

- 63.425 missing tại `SRC_TO_DST_SECOND_BYTES`;
- 59.068 positive infinity tại `SRC_TO_DST_SECOND_BYTES`;
- 122.493 positive infinity tại `DST_TO_SRC_SECOND_BYTES`;
- 14.815 dòng exact-duplicate;
- 1.134.553 dòng lặp theo fingerprint hành vi đã công bố trong report.

Schema, row count, SHA-256, label/category distribution, IP/port và temporal ordering đạt các check
đã triển khai. Điều này không đổi status tổng thành PASS vì các finding trên vẫn chặn raw-to-model.

Khi raw package không có, lệnh mặc định trả `SKIPPED`/exit `0` để CI không tải dataset. Exit `0`
trong trường hợp đó không phải bằng chứng real-data PASS.

## Split và preprocessing gate

Dataset chỉ có một CSV; không dùng split cũ của UNSW-NB15. Contract temporal/group-aware, duplicate
consolidation, metadata/target exclusion và train-only fitting nằm tại
`docs/NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md`.

Chưa được train cho đến khi:

1. chọn và test chính sách missing/non-finite chỉ dựa trên train;
2. đánh giá tác động deduplication tới rare attack categories;
3. materialize split manifest không có exact/group overlap;
4. ghi boundaries, seed, class distributions và row-index hashes;
5. audit feature list và fitted preprocessing artifact.

## Historical evidence

Các file sau chỉ phục vụ audit migration:

- `data/historical/UNSW_NB15_MANIFEST_2015.json`;
- `scripts/historical/fetch_unsw_nb15_2015.py`;
- `scripts/historical/dataset_manifest_unsw_nb15_2015.py`;
- `scripts/historical/validate_unsw_nb15_2015.py`;
- `reports/data_quality/historical/unsw_nb15_2015_validation.json`.

Không xóa hoặc diễn giải chúng như trạng thái hiện tại của pipeline.
