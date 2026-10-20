# Dataset decision record: NF-UNSW-NB15-v3

- **Quyết định:** dùng `NF-UNSW-NB15-v3` làm dataset network-flow mặc định duy nhất
  cho pipeline ML tương lai.
- **Ngày quyết định:** 2026-10-20.
- **Định danh nguồn:** UQ RDM UUID
  `abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f`, DOI `10.48610/6E0EDA1`.
- **Trạng thái:** `IMPLEMENTED` cho quyết định/provenance contract; validation dữ liệu
  thật hiện `FAIL` ở quality gate do missing/non-finite throughput values. Không có
  training hoặc metric ML trong checkpoint này.

## Lý do

NetFlow v3 bổ sung 10 temporal features vào 43 NetFlow v2 features, tạo 53 network-flow
features. Package có timestamp bắt đầu/kết thúc flow và thống kê IAT hai chiều, phù hợp
hơn với nghiên cứu temporal split, Behavioral Vector và Trace Engine so với published
train/test partition UNSW-NB15 (2015) 45 cột đang dùng trước migration.

## Ranh giới quyết định

- CSV thật có **55 cột**: 53 network-flow features, binary target `Label` và multiclass
  target `Attack`. Con số “53 features” không bao gồm hai target.
- `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, hai port và absolute timestamps là metadata/identifier
  candidates. Chúng được giữ cho audit/correlation/traceability nhưng mặc định không vào
  ma trận feature ML. Baseline duy nhất có 47 ordered features; cấu hình 49 features có port
  chỉ là experiment tương lai và cần protocol/evidence riêng.
- NF-UNSW-NB15-v3 không cung cấp API, authentication hay application-session logs. Các
  nguồn đó phải có schema và provenance riêng cho Behavioral Vector/Trace Engine.
- Dataset chỉ được dùng cho mục đích non-commercial và phải được trích dẫn đầy đủ theo
  điều kiện UQ. Apache-2.0 của source code không áp dụng cho dataset.
- UNSW-NB15 (2015) được giữ như historical evidence; không còn là default input.

## Điều kiện chặn experiment

Trước khi training phải có split manifest, versioned exact/ML-feature/group-overlap audit,
policy xử lý missing/`inf` chỉ fit trên train, và test chứng minh `Label`/`Attack` không
lọt vào `X`. Cho đến lúc đó trạng thái là `NOT VERIFIED`, không phải leakage-safe.
