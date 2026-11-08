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
| EDA summary (machine-readable) | `reports/eda/nf_unsw_nb15_v3_eda_summary.json` |
| EDA report (generated) | `docs/dataset/NF_UNSW_NB15_V3_EDA.md` |
| EDA reproducibility evidence | `reports/eda/evidence/` |
| EDA figures (local, ignored) | `reports/figures/nf_unsw_nb15_v3/` |
| Downloader | `scripts/fetch_nf_unsw_nb15_v3.py` |
| Manifest verifier | `scripts/dataset_manifest.py` |
| Validator | `scripts/validate_data.py` |
| Exploratory analysis | `scripts/eda_nf_unsw_nb15_v3.py` |

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
- sáu metadata fields gồm absolute timestamps, IP và hai L4 port được giữ cho grouping/Trace
  Engine và mặc định loại khỏi `X`;
- 47 NetFlow fields còn lại là baseline ML input theo đúng thứ tự CSV;
- `Label` và `Attack` tuyệt đối không đi vào `X`.

Website UQ và CSV không đồng nhất ở tổng attack và ánh xạ ba category count. Manifest theo byte CSV
đã tải và giữ mô tả discrepancy. Xem `docs/dataset/NF_UNSW_NB15_V3_SCHEMA.md`.

## Validation thật

```text
python scripts/validate_data.py
```

Validator stream CSV, kiểm tra schema/order, width, row count, numeric/NaN/Inf/missing, giá trị âm,
IPv4, port, label/category consistency, timestamp ordering và duration. Exact, 47-feature và
behavioral-v1 fingerprints được ghi vào SQLite tạm để RAM không tăng theo số dòng.

Kết quả đã ghi trong repository là `SOURCE_INTEGRITY: PASS`,
`RAW_QUALITY: FINDINGS_RECORDED`, `ML_READY: BLOCKED`:

- 63.425 missing tại `SRC_TO_DST_SECOND_BYTES`;
- 59.068 positive infinity tại `SRC_TO_DST_SECOND_BYTES`;
- 122.493 positive infinity tại `DST_TO_SRC_SECOND_BYTES`;
- 14.815 dòng exact-duplicate;
- 1.134.553 repeated rows theo 47-feature/behavioral-v1 equivalence, thuộc 189.788
  fingerprints;
- 0 binary-label/Benign-vs-Attack conflict fingerprints, nhưng 1.270 fingerprints có nhiều
  malicious `Attack` categories; không có deduplication tự động.

Schema, row count, SHA-256, label/category distribution, IP/port và temporal ordering đạt các check
đã triển khai. Source integrity PASS không đổi ML readiness thành PASS; findings vẫn chặn
raw-to-model.

Khi raw package không có, lệnh mặc định trả `SOURCE_INTEGRITY: SKIPPED`/exit `0` để CI không tải
dataset. Dataset nguyên vẹn nhưng ML-blocked trả exit `1`; corruption/integrity error trả exit `2`.
Exit `0` cho SKIPPED không phải bằng chứng real-data PASS.

## Exploratory data analysis (Issue #6)

```text
python scripts/eda_nf_unsw_nb15_v3.py
```

EDA dùng lại contract và byte verification của `scripts/validate_data.py` (không copy logic),
stream population trong bộ nhớ giới hạn và ghi:

- `reports/eda/nf_unsw_nb15_v3_eda_summary.json` — summary máy đọc được (đã commit);
- `docs/dataset/NF_UNSW_NB15_V3_EDA.md` — báo cáo Markdown sinh tự động từ summary;
- `reports/figures/nf_unsw_nb15_v3/*.png` — biểu đồ có nhãn (bị `.gitignore` loại, sinh lại local).

Kết luận chính từ lượt chạy trên dữ liệu thật (2.365.424 dòng, SHA-256 khớp manifest):

- Target: 2.237.731 benign / 127.693 attack (tỉ lệ 17,52:1); `Worms` hiếm nhất với 158 dòng;
- 122.493 dòng có duration bằng 0 và đồng thời có giá trị rate không hữu hạn;
- 14.815 dòng exact-duplicate và 1.134.553 dòng lặp theo 47-feature equivalence (189.788 nhóm),
  trong đó 1.270 nhóm trộn nhiều category tấn công và không nhóm nào mâu thuẫn nhãn nhị phân;
- traffic tập trung trên 3 ngày UTC trong cửa sổ 27 ngày;
- feature byte/packet/duration lệch phải mạnh, không có feature hằng số.

EDA là mô tả: không chọn feature, không fit transformer, không xóa dòng và không tạo split.
Mọi khuyến nghị phụ thuộc train vẫn ở trạng thái `PENDING ISSUE #7`; `ML_READY` giữ `BLOCKED`.

## Bằng chứng tái lập EDA (hai lần chạy)

```text
python scripts/verify_eda_reproducibility.py
```

Lệnh chạy EDA hai lần độc lập trên cùng raw CSV đã xác thực và ghi mỗi lần chạy thành một
bundle có thể truy xuất tại `reports/eda/evidence/run-1` và `run-2`:

- `run_metadata.json`: git HEAD/branch, Python/OS, dependency versions, dataset identity (size +
  SHA-256), manifest/schema verification, key aggregates, command, exit code, start/end timestamp,
  SHA-256 của summary và report;
- `stdout.log` / `stderr.log`: stdout và stderr thực tế của lần chạy đó;
- `eda_summary.json` / `eda_report.md`: đúng artifact mà lần chạy đó sinh ra.

Báo cáo so sánh `reports/eda/evidence/reproducibility_comparison.md` và `.json` hiển thị
PASS/FAIL theo từng chỉ số và liệt kê mọi khác biệt. Chỉ metadata được phép khác giữa hai
lần chạy (timestamp và môi trường) bị loại khỏi so sánh. Exit `0` khi hai lần chạy giống nhau
hoặc khi thiếu raw package (in `SKIPPED`, không phải PASS), exit `1` khi lệch.

## Split và preprocessing gate

Dataset chỉ có một CSV; không dùng split cũ của UNSW-NB15. Giao thức phân chia theo thời gian có vùng đệm bảo vệ nhóm (chronological with 5-minute canonical group purge gap) và kiểm toán rò rỉ chéo phân vùng đã được thực thi và xác minh tại `reports/splits/nf_unsw_nb15_v3_split_manifest.json` và `docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md`.
Contract temporal/group-aware, duplicate consolidation, metadata/target exclusion và train-only fitting nằm tại `docs/NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md`.
The handling contract for missing/non-finite values, short-duration flows and numeric-coded fields is `docs/NF_UNSW_NB15_V3_PREPROCESSING_POLICY.md`; no fitted transformer exists yet.

Chưa được train cho đến khi hoàn thành Issue #8:

1. chọn và test chính sách missing/non-finite chỉ dựa trên train;
2. fit transformers (imputer, scaler, encoder) chỉ trên tập train;
3. audit feature list và fitted preprocessing artifact.

Chi tiết aggregate numeric và duplicate/label-conflict nằm tại
`docs/dataset/NF_UNSW_NB15_V3_QUALITY_ANALYSIS.md` và
`docs/dataset/NF_UNSW_NB15_V3_DUPLICATE_AUDIT.md`.

## Historical evidence

Các file sau chỉ phục vụ audit migration:

- `data/historical/UNSW_NB15_MANIFEST_2015.json`;
- `scripts/historical/fetch_unsw_nb15_2015.py`;
- `scripts/historical/dataset_manifest_unsw_nb15_2015.py`;
- `scripts/historical/validate_unsw_nb15_2015.py`;
- `reports/data_quality/historical/unsw_nb15_2015_validation.json`.

Không xóa hoặc diễn giải chúng như trạng thái hiện tại của pipeline.
