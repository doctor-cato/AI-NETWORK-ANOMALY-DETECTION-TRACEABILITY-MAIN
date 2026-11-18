---
name: unsw-nb15-protocol
description: "Xác minh, kiểm tra và ghi provenance cho các bộ dữ liệu trong dự án: active v2 (AIT-NDS-v2, CTU-SME-11, UWF-ZeekData24 evaluation-only) và di sản v1 UNSW-NB15 / NF-UNSW-NB15-v3 trong historical/. Dùng khi task đọc, validate, chia hoặc mô tả dữ liệu; không tự tải dữ liệu."
---

# Dataset Provenance & Split Protocol (v2 Active + v1 Historical)

> **Lưu ý Hard Cutover v2:** Tên skill `unsw-nb15-protocol` được giữ để tương thích validator workflow, nhưng theo [MIGRATION_V1_TO_V2.md](../../../docs/MIGRATION_V1_TO_V2.md), dataset **`NF-UNSW-NB15-v3` đã nghỉ hưu sang `historical/`**. Mọi pipeline active v2 sử dụng **`canonical-flow-v2-18`** trên `AIT-NDS-v2`, `CTU-SME-11` và nguồn kiểm chứng bổ sung `UWF-ZeekData24`.

Đọc [DATASET.md](../../../docs/DATASET.md), [REPRODUCIBILITY.md](../../../docs/REPRODUCIBILITY.md) và [V2_SOURCE_AUDIT.md](../../../docs/dataset/V2_SOURCE_AUDIT.md) trước khi sửa code dữ liệu.

## Phân loại nguồn dữ liệu & Ranh giới bản quyền

1. **Active Training/Validation/Test (`AIT-NDS-v2`, `CC BY 4.0`, DOI `10.5281/zenodo.13168643`):**
   - `3,464,400` flows có nhãn + `942` unmapped = `3,465,342` raw flows (`data/V2_SPLIT_MANIFEST.json`, split theo scenario `v2-scenario-group-purged-v1`: `ait_train = 2,097,891`, `ait_val = 377,704`, `ait_test = 988,805`). Zero overlap scenario & `(scenario, 5-tuple, timestamp)`.
2. **External Zero-Shot Cross-Source (`evaluation_only = true`):**
   - **`CTU-SME-11`** (`10.5281/zenodo.7958258`, `CC BY 4.0`): `ctu_echo` (`76,073`) & `ctu_windows7ad` (`175,146` labeled, xử lý overlap minh bạch).
   - **`UWF-ZeekData24`** (`CC BY 4.0`): kiểm chứng L4 payload độc lập (`95,871` flows, `93,000` strict complete, `UWFZeekAdapter`). Không dùng để train hay calibrate `E0`.
3. **Cách ly & Bị chặn:**
   - **`AIT-LDS-v2.1`** (`10.5281/zenodo.19483937`, **`CC BY-NC-SA 4.0`**): **Cấm** đưa vào trọng số ML và `data/demo/`. Không có UID nối trực tiếp sang `AIT-NDS-v2` (`#85` `DIRECT_UID_LINK=NO`).
   - **`UGR'16`**: giữ trạng thái **`BLOCKED`** (`HTTP 403`).
4. **Historical v1 (`UNSW-NB15` / `NF-UNSW-NB15-v3`, `*/historical/nf_unsw_nb15_v3/`):**
   - Chỉ đọc khi đối chiếu lịch sử; không cho phép fallback trong `ModelRegistry`, `TrainOnlyPreprocessor`, FastAPI hay Desktop UI.

Báo rõ trạng thái dữ liệu khi kiểm tra: **ABSENT**, **SYNTHETIC**, **REAL V2 (`AIT`/`CTU`/`UWF`)**, hoặc **HISTORICAL V1**. Không tự tải hay sửa file raw tại chỗ.

## Protocol bắt buộc khi đọc / kiểm chứng dữ liệu thật

1. Kiểm chứng manifest, SHA-256, byte size (`scripts/fetch_multi_source_dataset.py --verify-only`, `data/UWF_ZEEKDATA24_MANIFEST.json`).
2. Kiểm tra schema `canonical-flow-v2-18`, kiểu dữ liệu, finite values, missing/unset Zeek tokens (tách `strict` vs `allow_zeek_unset_zero`), và mapping taxonomy v2 (`src/network_anomaly/data/taxonomy.py`), giữ dòng unmapped tách biệt thay vì ép nhãn.
3. Báo phân bố binary label & `attack_category`, nêu rõ lớp hiếm (`Exploitation_And_C2`, `Credential_Attack`, `Post_Exploitation_Discovery`).
4. Bảo toàn split `v2-scenario-group-purged-v1`; không trộn train/val/test, không fit preprocessing ngoài `ait_train`.

## PASS/FAIL và giới hạn

- `PASS`: checksum, schema, label mapping và split invariants đạt theo log/exit code thực tế.
- `FAIL`: sai checksum/schema/label coercion hoặc vi phạm split boundary.
- `SKIPPED`: dữ liệu raw chưa có trên runner (như CI GitHub checkout); `exit 0` vẫn báo `SKIPPED`.
- `NOT VERIFIED`: thiếu provenance hoặc chưa chạy đối chiếu đầy đủ.
