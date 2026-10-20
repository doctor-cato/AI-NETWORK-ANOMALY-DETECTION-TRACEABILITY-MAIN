# NF-UNSW-NB15-v3 migration impact assessment

## 1. Phải thay thế

- Default source, manifest, downloader, validator, raw path và report path.
- Schema 45 cột/lowercase, hai published split và row counts 175.341/82.332.
- `attack_cat`/`label` thành `Attack`/`Label`; category `Normal` thành `Benign`.
- Default split assumption: NF-UNSW-NB15-v3 chỉ có một CSV và không kế thừa official
  train/test partition của UNSW-NB15 2015.
- README, `docs/DATASET.md`, `docs/REPRODUCIBILITY.md`, CI data-check và test fixtures.

## 2. Phải điều chỉnh

- Methodology/evaluation/experiment plan cho temporal/group-aware split, missing/Inf,
  imbalance và 10 temporal NetFlow features.
- Feature contract: tách 47 ML candidates, 6 metadata/identifier candidates và 2 targets.
- Issues #6–#14, #17, #18, #20, #25, #29, #31 cùng milestone M1–M4/M7.
- Behavioral Vector/Risk/Trace docs phải nói rõ network-flow metadata không thay thế
  API/auth/session event sources.

## 3. Giữ như historical evidence

- Manifest, real-data report và acquisition/validation code cho UNSW-NB15 (2015),
  cùng PR #22 và Issues #4/#5 đã đóng.
- Mọi số liệu 175.341/82.332, schema 45 cột và duplicate counts cũ chỉ được xuất hiện
  trong khu vực `historical`, không là trạng thái dataset mặc định.

## 4. Không liên quan, giữ nguyên

- Model constructors, metric helpers và placeholder inference không chứa schema cụ thể.
- AES-GCM, Adaptive Key Rotation, FastAPI, SQLite và Streamlit vẫn `PLANNED`; migration
  không triển khai các module đó.
- Apache-2.0 của source code và giới hạn lab/dry-run.

## Naming contract mới

- Package local: `data/raw/NF-UNSW-NB15-v3/`.
- CSV: `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv`.
- Feature dictionary: `data/raw/NF-UNSW-NB15-v3/data/NetFlow_v3_Features.csv`.
- Manifest: `data/NF_UNSW_NB15_V3_MANIFEST.json`.
- Quality report: `reports/data_quality/nf_unsw_nb15_v3_validation.json`.
- Split contract: `docs/NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md`.
