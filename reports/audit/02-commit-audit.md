# Report 02 — Commit Audit

## 1. Phạm vi

- Range: `b212377a614aadbfb27eccff8d808c5b7dda551f..b14dfeed9e7cbb07201cfb0ac8ce69c951434be1`
- Tổng: **38 commit**, trong đó **28 non-merge** và **10 merge**.
- Diff tổng: **49 file**, **+13.469 / −158**.
- Merge PR trong range: **#44** (`c286149`), **#45** (`905da0d`), **#38** (`72e74b2`), **#40** (`b14dfee`).
- Các merge nhánh trung gian: `7bd2cd3`, `3aac74d`, `a2ff97c`, `5f4e899`, `47c6186`, `c6ccc01`.

## 2. Bảng commit

| # | SHA | Commit | Hành vi thay đổi thực tế | Đánh giá |
|---|---|---|---|---|
| 1 | `4211017` | `feat(models): hoàn thiện model component Isolation Forest cho Issue #11` | Thêm `validate_config`, `build_model`, `fit_model`, `anomaly_scores` và unit test cho IF. Chưa có threshold, chưa có inference. | Code có thật; **chưa đủ DoD #11** |
| 2 | `30cd851` | `feat(c3): implement XGBoost supervised model for Issue #31` | Thêm wrapper `xgboost_model.py`, dependency `xgboost`, test constructor. | Chỉ là scaffold; **không chứng minh train/predict** |
| 3 | `fd74070` | `fix(isolation-forest): reject complex dtype...` | IF từ chối complex dtype, sai shape, `max_features=None`; tăng độ chặt input validation. | Tốt, **low risk** |
| 4 | `01080cb` | `feat(pipeline): implement real-data training and evaluation pipeline for Isolation Forest` | Thêm `scripts/train_isolation_forest.py`, loader split, trạng thái `blocked_status.json`. | Entrypoint có thật; **chưa chạy được do thiếu artifact** |
| 5 | `7bd2cd3` | `Merge branch 'main' into feat/issue-11-isolation-forest-model` | Hợp nhất main cũ vào nhánh IF; giải quyết conflict lớn. | Merge trung gian; **không tạo behavior mới** |
| 6 | `cb59e81` | `fix(isolation-forest): align split and preprocessor contracts...` | Ràng buộc IF với split/preprocessor manifest; thêm test manifest. | Tăng tính đúng đắn; **phụ thuộc artifact** |
| 7 | `e9b9a45` | `fix(isolation-forest): address review findings A-G...` | Sửa 7 nhóm review findings; thêm E2E integration test. | Tốt; **chưa có real artifact** |
| 8 | `4154e26` | `fix(isolation-forest): load partition indices using canonical split loader` | Chuyển sang loader split chuẩn thay vì tự đọc index. | Giảm lệch contract |
| 9 | `dbf17c3` | `feat(inference): implement verified CSV inference pipeline...` | Thêm `scripts/predict.py`, `inference/predict.py`, integration test E2E. Đây là entrypoint inference đầu tiên. | **Behavior mới quan trọng**; loader về sau bị fail-open |
| 10 | `c6ccc01` | `fix(inference): resolve merge conflict...` | Hợp nhất main, xóa trailing whitespace. Đây là **merge commit** thứ 10 trong range (dù message là fix). | Merge fix; low risk |
| 11 | `75a83b4` | `fix(inference): refine model manifest candidate discovery...` | Tự dò manifest theo tên model; định dạng smoke report. | Tăng tiện dụng; **tăng khả năng load nhầm manifest** |
| 12 | `702f723` | `fix(isolation-forest): mandate preprocessor sha256...` | Bắt buộc preprocessor SHA-256; bỏ đường dẫn explicit; xử lý FPR khi zero alert. | Tốt; **fail-closed hơn** |
| 13 | `3aac74d` | `chore: merge main into feat/c3-xgboost-issue-31` | Merge main vào nhánh XGB. | Merge trung gian |
| 14 | `90f1829` | `feat(c3): align XGBoost supervised architecture...` | Thêm `scripts/train_xgboost.py`, protocol XGB, test cấu trúc. | **Code có thật**, chưa có artifact |
| 15 | `c286149` | `Merge pull request #44 ...` | `main` nhận inference CSV pipeline. | **Thay đổi main**: có inference entrypoint |
| 16 | `c30b6c0` | `test: bổ sung unit test và integration test... (Issue #17)` | +806 dòng test; sửa `inference/predict.py` và `random_forest.py` sau merge. | **Rủi ro**: thay đổi loader trong commit “test” |
| 17 | `905da0d` | `Merge pull request #45 ...` | `main` nhận bộ test bổ sung. | **Thay đổi main**: coverage tăng |
| 18 | `a2ff97c` | `Merge branch 'main' into feat/c3-xgboost-issue-31` | Merge main vào nhánh XGB. | Merge trung gian |
| 19 | `89c32fa` | `feat(c3): complete XGBoost protocol specification...` | Thêm `docs/XGB_BASELINE_PROTOCOL.md`; tích hợp `--step xgboost` vào `run_experiments.py`. | **Behavior CLI mới**; `evaluate/inference` vẫn exit 3 |
| 20 | `b4022f1` | `perf(isolation-forest): stream partition loading...` | IF đọc partition theo chunk; nới bound calibration test. | Hiệu năng; **nới test bound** cần review |
| 21 | `5f4e899` | `Merge branch 'main' into feat/issue-11-isolation-forest-model` | Merge main vào nhánh IF. | Merge trung gian |
| 22 | `fe79d51` | `fix(isolation-forest): resolve copilot review findings...` | Sửa validation, encoding, metric của IF. | Tốt |
| 23 | `7d760e0` | `feat(c3): implement XGBoost supervised training pipeline` | Thêm train pipeline XGB; **sửa split manifest, preprocessing manifest, execution evidence, leakage audit, smoke report**. | **RỦI RO CAO**: thay đổi provenance toàn cục trong commit feature |
| 24 | `e2c7aff` | `feat(c3): record XGBoost training evidence...` | Thêm `reports/models/xgboost_manifest.json`, training report; sửa train script. | **Manifest không đi kèm artifact** |
| 25 | `0c36676` | `fix(isolation-forest): xu ly reviewer feedback...` | Sửa IF theo review; sửa `lint-audit.yml`, config. | Trung bình |
| 26 | `9b0d4b3` | `fix(xgb): enforce strict verified loading...` | XGB `load_verified` bắt buộc manifest, provenance `VERIFIED`, git commit, 47 features, classes `[0,1]`. | **Đúng hướng**; RF không được sửa tương ứng |
| 27 | `fdd8b43` | `fix(data): add split membership parity audit...` | Thêm script audit parity + report + unit test. | Tốt; **chỉ là audit synthetic/real tùy dữ liệu** |
| 28 | `1e2c991` | `ci: expand scoped lint gate...` | Mở rộng lint gate, thêm import check XGBoost. | Tốt một phần; **bỏ sót RF/IF/inference** |
| 29 | `d3fb7ef` | `refactor(xgb): resolve ruff and black...` | Sửa lint cho XGB và test. | Low risk |
| 30 | `fc3a7b7` | `docs(c3): restore checkpoint history and reconcile evidence` | Sửa checkpoint, protocol, **XGB manifest/report**. | **RỦI RO**: “reconcile evidence” bằng sửa manifest |
| 31 | `2eacf66` | `fix(models): sort imports...` | Sắp xếp import. | Low risk |
| 32 | `7b8d547` | `fix(data): harden split parity audit...` | Thêm kiểm tra boundary/distribution cho parity audit. | Tốt |
| 33 | `3fd8dad` | `docs(c3): align dataset contract with canonical 55-column schema` | Sửa docs/script XGB theo schema 55 cột. | Tốt; **issue #31 vẫn ghi 49-feature** |
| 34 | `fda13fa` | `fix(isolation-forest): kich hoat xac thuc partition index checksum...` | IF bật kiểm tra checksum index fail-closed. | Tốt; **phụ thuộc index không có trong Git** |
| 35 | `72e74b2` | `Merge pull request #38 ...` | `main` nhận IF model + training pipeline. PR bị `CHANGES_REQUESTED` nhưng vẫn merge. | **Thay đổi main**; process risk |
| 36 | `a9787bd` | `fix(c3): fail closed on unverified XGBoost provenance` | XGB từ chối provenance không `VERIFIED`; sửa audit parity. | **Đúng hướng**; chỉ XGB |
| 37 | `47c6186` | `merge: resolve main integration for C3 XGBoost` | Hợp nhất main vào nhánh XGB; tree trùng PR head. | Merge cuối trước #40 |
| 38 | `b14dfee` | `Merge pull request #40 ...` | `main` nhận XGBoost code, protocol, manifests. PR bị `CHANGES_REQUESTED` nhưng vẫn merge. | **HEAD hiện tại**; không có XGB artifact |

## 3. Phân tích theo cụm hành vi

### 3.1. Dữ liệu và split (`01080cb`, `cb59e81`, `4154e26`, `702f723`, `fda13fa`, `fdd8b43`, `7b8d547`)

- Các commit này làm pipeline IF đọc split index đúng contract, kiểm tra checksum, audit parity.
- Tuy nhiên, **không commit nào mang theo file index `.csv.gz` thật**. Vì vậy các hash index ghi trong manifest `main` (`30ed493e…`, `a3e4470c…`, `90219f75…`) không thể kiểm chứng từ repository.
- External clone có index thật nhưng hash khác (`a09ba175…`, `7d41a71a…`, `63e2e081…`); row count và label distribution giống hệt, nên **có thể** là manifest được tái sinh/serialize khác, nhưng không chứng minh được membership giống nhau ở mức byte. Manifest `main` sinh `2026-11-08`, bản RF dùng sinh `2026-10-27`.

### 3.2. Provenance bị sửa trong commit feature (`7d760e0`, `e2c7aff`, `fc3a7b7`)

Đây là **rủi ro nghiêm trọng nhất về mặt kiểm toán**:

- `7d760e0` không chỉ thêm XGBoost; nó sửa:
  - `data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json`
  - `reports/preprocessing/execution_evidence.json`
  - `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json`
  - `reports/splits/nf_unsw_nb15_v3_split_manifest.json`
  - `reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md`
- `e2c7aff` và `fc3a7b7` tiếp tục sửa `reports/models/xgboost_manifest.json` và report.
- Hệ quả: **cùng một commit vừa tạo model vừa sửa bằng chứng provenance**, khiến không thể phân biệt “bằng chứng được ghi lại” với “bằng chứng được điều chỉnh cho khớp”.
- Đây là lý do chính khiến chuỗi hash hiện tại không nhất quán.

### 3.3. Inference (`dbf17c3`, `75a83b4`, `c30b6c0`)

- `dbf17c3` tạo entrypoint inference có manifest verification.
- `75a83b4` thêm auto-discovery manifest.
- `c30b6c0` sửa loader trong một commit test.
- Kết quả tại HEAD: `load_verified_model()` vẫn **không bắt buộc manifest**, và chỉ kiểm tra hash nếu field tồn tại. Đây là lỗi thiết kế, không phải lỗi merge.

### 3.4. Merge PR với review chưa approve

- PR #38 (IF) và #40 (XGB) được merge khi GitHub review decision là `CHANGES_REQUESTED`.
- PR #41 (split) cũng `CHANGES_REQUESTED` rồi merge, nhưng PR này **trước baseline** `b212377`; chỉ dùng làm tiền lệ lịch sử, không tính vào range.
- Điều này không tự động chứng minh code sai, nhưng **phá vỡ giả định “merge = đã review đạt”** và giải thích vì sao nhiều AC chưa đạt vẫn vào main.

## 4. Commit không nằm trên `main`

Commit tạo artifact RF thật:

```text
6f50633544ccbf93fa4dd193355c1d8222360e37
```

không phải ancestor của `b14dfee`; nó chỉ tồn tại trên nhánh `feat/issue-9-rf-baseline-protocol` (external clone đang ở `15f42318…`). Vì vậy:

- `reports/models/random_forest_manifest.json` trên `main` mô tả một run **không thể tái lập từ lịch sử `main`**;
- `scripts/train_random_forest.py` pin split `bb84…` trong khi `main` có split `1ba6…`;
- mọi tuyên bố “RF đã huấn luyện trên main” là **không chính xác về mặt lịch sử Git**.

## 5. Kết luận

- 38 commit đã được khảo sát; không có commit nào bị bỏ sót.
- Phần lớn commit là code/test hợp lệ.
- **Bốn điểm nóng** cần remediation: `7d760e0` (provenance), `c30b6c0` (loader trong commit test), `75a83b4` (manifest auto-discovery), và các merge PR #38/#40 khi review chưa approve.
- Không thể dùng commit message làm bằng chứng hoàn thành; mọi kết luận phải quay về code/artifact/test thực tế.
