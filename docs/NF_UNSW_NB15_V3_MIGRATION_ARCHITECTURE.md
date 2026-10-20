# Kiến trúc migration NF-UNSW-NB15-v3

## Luồng dữ liệu mặc định

```text
UQRDM stable dataset UUID
  -> download API (signed URL ngắn hạn)
  -> bounded ZIP staging
  -> archive/package verification
  -> safe extraction staging
  -> atomic package publish + rollback marker + OS lock
  -> manifest verification
  -> streaming quality audit
  -> split contract / split manifest
  -> train-only preprocessing (future C2)
```

Không có fallback mirror. Nếu metadata API, signed URL, license metadata hoặc byte đã
ghim không xác minh được, acquisition `FAIL` và giữ nguyên cache/package cũ.

## File contract

| Vai trò | Path |
| --- | --- |
| Downloader | `scripts/fetch_nf_unsw_nb15_v3.py` |
| Manifest verifier | `scripts/dataset_manifest.py` |
| Validator | `scripts/validate_data.py` |
| Version-control manifest | `data/NF_UNSW_NB15_V3_MANIFEST.json` |
| Published local package | `data/raw/NF-UNSW-NB15-v3/` |
| Dataset CSV | `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` |
| Feature dictionary | `data/raw/NF-UNSW-NB15-v3/data/NetFlow_v3_Features.csv` |
| Validation report | `reports/data_quality/nf_unsw_nb15_v3_validation.json` |
| Split protocol | `docs/NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md` |
| Historical 2015 evidence | `data/historical/`, `reports/data_quality/historical/`, `scripts/historical/` |

## Acquisition transaction

Một OS byte-range lock theo destination bao phủ cache check, download, extraction,
publish và rollback. Staging ZIP và directory nằm cùng filesystem với destination.
Archive chỉ được extract khi đúng size/SHA-256, ZIP magic, expected entry set và
decompressed-size limit. Entry tuyệt đối, `..`, symlink, file lạ hoặc entry vượt size
đều bị từ chối.

Package hiện có chỉ là cache hit khi mọi expected file đúng size/SHA-256. Cache mismatch
không bị xóa trước. Publisher tạo package mới trong staging, đổi package cũ sang backup,
rồi đổi staging sang path chính. Transaction marker ghi đủ path để lần chạy sau khôi
phục nếu process chết giữa hai rename. Publish/rollback failure giữ byte cũ hoặc backup
và dừng fail-closed; cleanup không được che lỗi gốc.

## Manifest contract

Manifest version-control ghim DOI/RDM UUID, package identifier, archive size,
project-computed SHA-256, publisher-bundled BagIt SHA-1, expected entry set/size/hash,
row count, schema order, target semantics và source discrepancy. Signed S3 URL không
được lưu vì hết hạn. Verifier chỉ đọc; không tự cập nhật provenance.

## Validation contract

Validator stream CSV và chỉ ghi aggregate report. Blocking defects gồm manifest/hash,
schema/order, row width/count, invalid target, target/category inconsistency, invalid
timestamp/IP/port và parsing error. Missing, NaN/Inf, negative-value policy, exact
duplicate và behavior-equivalent near-duplicate được báo riêng; duplicate audit dùng
disk-backed index để RAM không tăng theo số dòng.

`PASS` chỉ khi chạy trên file thật đã đối chiếu manifest và không có blocking quality
failure. Fixture chỉ là `TESTED`. Vắng package mặc định là `SKIPPED` và CI warning.

## Split và leakage boundary

NF-UNSW-NB15-v3 là một CSV, không có official split. Contract mặc định đánh giá
time-aware split trên `FLOW_START_MILLISECONDS`, giữ test cô lập và kiểm tra exact/
behavior duplicate cùng canonical flow-group overlap qua boundary. Vì không có session
ID authoritative, canonical 5-tuple/time-window chỉ là heuristic và phải ghi limitation.

`Label` và `Attack` luôn bị loại khỏi `X`. Hai absolute timestamp, hai IP và hai L4 port
tạo thành sáu trace/grouping metadata fields, không nằm trong baseline ML matrix 47 fields.
Imputer/encoder/scaler/selector chỉ
được fit trên train. Seed, boundary, group rule, counts và class distribution phải nằm
trong split manifest trước training.

## Compatibility và historical evidence

Ba script acquisition/manifest/validation cho UNSW-NB15 (2015), manifest và report thật
cũ được chuyển vào khu vực historical để giữ regression evidence nhưng không còn được
`run_experiments.py`, README hay CI gọi mặc định. Model constructors và các module ngoài
dataset không đổi; migration không triển khai training, API/UI hoặc cryptography.
