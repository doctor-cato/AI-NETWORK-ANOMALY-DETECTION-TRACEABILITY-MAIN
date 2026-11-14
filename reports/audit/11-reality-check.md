# Report 11 — Reality Check: 17 câu hỏi của ULTIMATE OBJECTIVE

> Mỗi câu trả lời dưới đây chỉ dùng bằng chứng đã kiểm tra trong phiên audit. Các nhãn `PASS`, `FAIL`, `PARTIAL`, `SKIPPED`, `NOT VERIFIED`, `BLOCKED` giữ nguyên nghĩa ở Report 00.

---

## Q1. Repository đã thay đổi gì từ baseline đến HEAD?

**Trả lời ngắn**: 38 commit, 49 file, +13.469/−158. Repository chuyển từ baseline “RF protocol + fail-closed entrypoint” sang một prototype có thêm:

- Inference CSV pipeline (`#44`);
- bộ test/integration lớn (`#45`);
- Isolation Forest model + training/eval script (`#38`);
- XGBoost model/protocol/training script (`#40`);
- nhiều manifest/evidence cho split, preprocessing, XGB;
- CI lint gate mở rộng.

**Nhưng**:

- Không có API/DB/dashboard/security module mới trong `src/`;
- Không có artifact XGB/IF/AE;
- Không có test evaluation;
- Chuỗi provenance bị đứt.

**Verdict**: **PARTIAL** — nhiều code mới, nhưng không tương ứng với mức hoàn thành mà issue/milestone tuyên bố.

---

## Q2. Từng commit đã thay đổi hành vi gì?

**Trả lời ngắn**: Xem bảng đầy đủ ở Report 02. Tóm tắt hành vi:

| Nhóm | Commit | Hành vi |
|---|---|---|
| IF model | `4211017`, `fd74070`, `cb59e81`, `e9b9a45`, `4154e26`, `702f723`, `b4022f1`, `fe79d51`, `fda13fa` | Thêm/hoàn thiện IF component, validation, split contract, threshold/eval script, checksum fail-closed |
| XGB | `30cd851`, `90f1829`, `89c32fa`, `7d760e0`, `e2c7aff`, `9b0d4b3`, `a9787bd` | Thêm wrapper/protocol/training; strict load; ghi manifest; **sửa provenance toàn cục** |
| Inference | `dbf17c3`, `75a83b4`, `c30b6c0` | Thêm CSV inference; auto-discovery manifest; sửa payload/`classes_` |
| Tests/docs/CI | `c30b6c0`, `1e2c991`, `d3fb7ef`, `fc3a7b7`, `2eacf66`, `3fd8dad`, `fdd8b43`, `7b8d547` | Test, lint, parity audit, docs |
| Merge | `7bd2cd3`, `c286149`, `905da0d`, `3aac74d`, `a2ff97c`, `5f4e899`, `72e74b2`, `47c6186`, `b14dfee`, `c6ccc01` | Hợp nhất nhánh/PR; đưa IF/XGB/inference vào main |

**Điểm bất thường**:

- `7d760e0`, `e2c7aff`, `fc3a7b7` sửa manifest/evidence trong commit feature;
- `c30b6c0` sửa loader trong commit “test”;
- `75a83b4` thêm auto-discovery manifest;
- merge PR #38/#40 khi review `CHANGES_REQUESTED`.

**Verdict**: **PASS về khảo sát**, **FAIL về traceability của các commit provenance**.

---

## Q3. Từng PR có giải quyết đúng vấn đề không?

**Trả lời ngắn**: Xem Report 03. Phân loại:

- **PASS**: #21, #22, #33, #35, #36 (docs/data/EDA).
- **PARTIAL**: #34, #38, #41, #42, #43, #44, #45.
- **FAIL DoD**: #40 (XGB).
- **SUPERSEDED**: #39.
- **NOT MERGED**: #47, #49, #50, #51, #52.

Các PR merged giải quyết **đúng hướng kỹ thuật**, nhưng nhiều PR không đạt definition of done vì thiếu artifact/test/real evaluation. PR #38/#40 bị `CHANGES_REQUESTED` nhưng vẫn merge.

**Verdict**: **PARTIAL** — đúng vấn đề, không đủ bằng chứng hoàn thành.

---

## Q4. Từng issue có đạt acceptance criteria không?

**Trả lời ngắn**: Xem Report 04. Không có issue nào có thể coi là “đạt đầy đủ” chỉ vì checkbox hoặc merge. Tóm tắt:

- **Đạt tương đối**: #2, #3, #4, #5, #6, #9.
- **PARTIAL**: #7, #8, #10, #11, #14, #17, #20, #23, #37.
- **FAIL acceptance**: #15, #31.
- **Chưa bắt đầu/paper**: #12, #13, #16, #18, #19, #24, #25, #26, #27, #28, #32.
- **Branch-only**: #29, #30, #46, #48.
- **Remediation open**: #53–#60.
- **N/A**: #1 (milestone link test).

**Verdict**: **FAIL** cho tuyên bố “issue đã đóng = AC đạt”.

---

## Q5. Issue nào đóng sớm?

**Trả lời ngắn**: Ba issue rõ ràng:

1. **#15** — inference: AC fail-closed không đạt; smoke real artifact `SKIPPED`; loader fail-open.
2. **#17** — tests: 2/4 AC còn unchecked; không có real split/model evaluation.
3. **#31** — XGBoost: 0/4 AC; không có artifact; CLI không hỗ trợ.

Ba issue “đóng đúng phạm vi nhưng thiếu tái lập”:

- **#7**: split/leakage audit không verify được byte-level;
- **#8**: evidence hiện tại được tạo/cập nhật sau khi đóng;
- **#10**: RF artifact/run commit không nằm trên `main`.

**Verdict**: **FAIL** về closure integrity.

---

## Q6. PR nào từng PASS nay regression?

**Trả lời ngắn**: **Không có regression chức năng đã từng PASS** theo nghĩa “feature hoạt động rồi bị làm hỏng trong range”. Các trường hợp là **false-positive PASS** hoặc **historical PASS không tái lập**:

| PR | CI/review lúc merge | Trạng thái HEAD | Loại |
|---|---|---|---|
| #44 inference | CI PASS, APPROVED | Loader fail-open; không chứng minh real artifact | **False-positive PASS**, không phải regression |
| #40 XGB | CI PASS, merge dù CHANGES_REQUESTED | Không artifact; CLI không hỗ trợ | **False-positive PASS** |
| #38 IF | CI PASS, merge dù CHANGES_REQUESTED | Không artifact; inference raw `-1/1` | **False-positive PASS** |
| #43 RF | CI PASS, APPROVED | Artifact/run commit ngoài main; hash pin không khớp | **Historical PASS không tái lập** |

Lưu ý: lỗi hash `bb84…` đã tồn tại từ **baseline** `b212377` (PR #43), không phải do #38/#40 tạo ra. PR #45 chỉ thêm `classes_` và unpack payload, không làm xấu thêm.

**Verdict**: **Không có regression rõ ràng**; có **3 false-positive PASS** (#44, #40, #38) và **1 historical PASS không tái lập** (#43).

---

## Q7. Milestone nào thật sự xong?

**Trả lời ngắn**:

- **M0**: xong thật (**PASS**).
- **M1**: gần xong, nhưng #7 chưa verify byte-level (**PARTIAL**).
- **M2**: **không xong** — #31 0/4, không artifact XGB; đóng sai.
- **M3**: chưa xong — #11/#12/#13/#14/#29 open.
- **M4**: không nên đóng dù 0 open/2 closed; end-to-end chưa chạy.
- **M5/M6/M7**: chưa xong.

**Verdict**: chỉ **M0** thật sự xong; **M2 là false completion**.

---

## Q8. Data pipeline còn nhất quán không?

**Trả lời ngắn**: **Không**. Chuỗi hash:

| Mắt xích | Hash | Khớp? |
|---|---|---|
| Raw dataset | `4ebb97bd…` | **PASS** |
| Split manifest `main` | `1ba6b2ef…` | — |
| Split manifest RF dùng | `bb84c1e0…` | **FAIL** |
| Split manifest XGB/prep dùng | `845d8863…` (CRLF variant) | **FAIL** |
| RF preprocessor artifact | `12d4360a…` | không có trong Git |
| XGB preprocessor artifact | `e1e89bde…` | không có trong Git |
| Preprocessing manifest `main` | `666a7aae…` | khớp file, nhưng ghi split `845d…` |
| RF model artifact | `801afcbb…` | có ngoài Git |
| XGB model artifact | `c70ec52f…` | **không tồn tại** |

Hệ quả:

- `verify_preprocessing_artifact()` fail trên clean checkout;
- `train_random_forest.py --verify-only` fail;
- `InferencePipeline.from_artifacts` chạy với external split `bb84…` nhưng fail với main split `1ba6…`;
- XGB không thể load vì thiếu artifact.

**Verdict**: **FAIL** — data gốc nhất quán, nhưng pipeline split → preprocessing → model **không nhất quán**.

---

## Q9. Model train/load/evaluate/inference thật được không?

**Trả lời ngắn**:

| Model | Train | Load | Evaluate | Inference | Verdict |
|---|---|---|---|---|---|
| Random Forest | **Có, lịch sử** | Có với external artifact; pipeline fail ở main split do preprocessor mismatch | **Validation có**; test **không** | Có với external artifact; fail-open | **PARTIAL** |
| XGBoost | Code có, artifact **không** | **Không** | **Không** | CLI **không** | **FAIL** |
| Isolation Forest | Code có, artifact **không** | **Không** | **Không** | Raw `-1/1`, sai threshold | **FAIL/PARTIAL** |
| Autoencoder | **Không** (branch-only) | **Không** | **Không** | **Không** | **NOT VERIFIED** |

**Bằng chứng RF**:

- 1.000 dòng inference với external split/artifact → 829 benign/171 attack;
- validation 345.371 dòng → metric khớp manifest 100%;
- main split `1ba6…` → fail do preprocessor mismatch.

**Verdict**: chỉ **RF validation/inference với artifact lịch sử** là thật; **không có end-to-end từ main**.

---

## Q10. Kết quả ML có hợp lệ khoa học không?

**Trả lời ngắn**: **Chưa đủ**.

Điểm mạnh:

- dữ liệu thật, hash khớp;
- split trước fit, preprocessor train-only;
- RF metric validation tái lập;
- IF protocol threshold đúng về thiết kế.

Điểm yếu:

- **không có test metric**;
- **không có calibration**;
- **không có external/cross-dataset validation**;
- **TTL shortcut** chiếm 45,48% importance; 1 feature đạt 99,98%;
- duplicate/group/temporal leakage chưa verify;
- single seed/split, không confidence interval.

**Verdict**: **EXPERIMENTALLY VALIDATED trên validation** cho RF; **không đủ** cho claim “mô hình phát hiện tấn công tốt” hoặc “generalize”.

---

## Q11. Có leakage, shortcut hay false confidence không?

**Trả lời ngắn**: **Có cả ba**.

| Loại | Kết luận | Bằng chứng |
|---|---|---|
| Target leakage | **Không phát hiện** | `Label`/`Attack` bị loại khỏi X |
| Metadata leakage | **Không phát hiện** | 6 cột IP/port/timestamp bị loại |
| Duplicate leakage | **Chưa verify** | 14.815 exact; 1.134.553 ML-equivalent; không dedup |
| Group leakage | **Chưa verify** | 1.270 nhóm mixed-category |
| Temporal leakage | **Chưa verify** | 3 ngày traffic trong 27 ngày |
| Test isolation | **Vi phạm strict** | Test được materialize trong preprocessing |
| Shortcut learning | **Có, nghiêm trọng** | TTL 45,48%; 1-feature DT 99,98% |
| False confidence | **Có** | Metric 99,99% được trình bày như thành tựu |

**Verdict**: **FAIL** cho tuyên bố “leakage-safe” và “high performance” nếu không có ablation/audit bổ sung.

---

## Q12. Chức năng nào chỉ trên giấy hoặc synthetic tests?

**Trả lời ngắn**:

**Trên giấy hoàn toàn (không có code trong `main` lẫn branch đã audit)**:

- Streamlit dashboard (#16);
- AES-GCM/key lifecycle (#26, #27);
- Behavioral Vector (#28);
- Risk Engine (#32);
- Trace Engine (#24);
- PDF/slides/demo/handoff (#19, #25).

**Branch-only (có code, chưa merge)**:

- FastAPI + SQLite persistence (#30, PR #52);
- Multi-source ingestion + cross-dataset (#46/#48, PR #47/#49);
- Autoencoder (#29, PR #51).

**Chỉ synthetic**:

- 739 test pass;
- RF/XGB training mock integration;
- inference E2E fixture;
- IF threshold/E2E fixture.

**Chỉ manifest/claim**:

- XGBoost artifact + metric (không có `.joblib`);
- RF test metric (không có);
- Autoencoder real experiment (không có).

**Verdict**: phần lớn C5–C9 là **paper architecture**; phần ML thật chỉ có RF validation.

---

## Q13. Có lỗi security/integrity/supply-chain không?

**Trả lời ngắn**: **Có**.

- **P0**: `joblib.load` fail-open, model không manifest/`{}` vẫn load (`F-01`).
- **P0**: RF `load_verified` chấp nhận `UNVERIFIED` (`F-02`).
- **P0**: chuỗi hash split/preprocessor/model đứt; hardcode hash (`F-03`).
- **P2**: dependency không pin/lock; Actions dùng tag; không pip-audit/SBOM (`F-16`).
- **P1**: test partition bị materialize trước evaluation (`F-05`).
- **P3**: trainer phụ thuộc `.git`, manifest `UNKNOWN` ngoài Git (`F-21`).

Không tìm thấy secrets trong tracked files; không có API trong `main` để test auth.

**Verdict**: **FAIL** cho “verified inference”; **PASS** cho secrets.

---

## Q14. Dependency/implementation nào bị bỏ sót giữa các PR?

**Trả lời ngắn**:

| Bỏ sót | PR liên quan | Hệ quả |
|---|---|---|
| RF loader không được làm strict như XGB | #40 vs #43 | F-02 |
| XGB artifact không được đóng gói | #40 | F-04 |
| CLI không cập nhật khi thêm XGB | #40 | `--model xgboost` fail |
| IF threshold không tích hợp inference | #38 | F-07 |
| Hash chain không reconcile giữa #42/#43/#40 | #42, #43, #40 | F-03 |
| Test evaluation không tích hợp `run_experiments` | #45 | `evaluate` exit 3 |
| `classes_` cho RF chỉ thêm sau #44 | #45 | trước đó inference thiếu class map |
| 47 vs 49 feature contract | #31 | F-19 |
| XGBoost không có trong `check_environment` | #40 | F-11 |
| API/ingestion chưa merge/rebase | #47/#49/#52 | không có end-to-end |
| EOL normalization không được tính trong hash pin | #41/#42/#43 | F-03 |

**Verdict**: **FAIL** về integration completeness.

---

## Q15. Mức sẵn sàng end-to-end?

**Trả lời ngắn**: **NOT READY**.

| Lớp | Sẵn sàng |
|---|---|
| Data acquisition/validation | **PASS** |
| EDA | **PASS** |
| Split | **PARTIAL** |
| Preprocessing | **PARTIAL** |
| RF training | **PARTIAL** (historical) |
| RF test evaluation | **BLOCKED** |
| XGB | **FAIL** |
| IF | **FAIL/PARTIAL** |
| AE | **NOT VERIFIED** |
| Inference | **FAIL (fail-open)** |
| API/DB/dashboard | **ABSENT** |
| Security | **FAIL** |
| Delivery | **ABSENT** |

**Verdict**: research prototype ở tầng data/RF; **không phải hệ thống end-to-end**, không production-ready, không đủ điều kiện bàn giao.

---

## Q16. Lỗi bắt buộc sửa trước milestone/nghiệm thu?

**Trả lời ngắn**: theo thứ tự chặn:

1. **F-01/F-02** — fail-closed loader (P0 security).
2. **F-03** — canonical provenance chain (P0 integrity).
3. **F-04** — XGB artifact hoặc mở lại #31.
4. **F-05** — test isolation + **F-13** test evaluation.
5. **F-06** — TTL ablation/shortcut disclosure.
6. **F-07** — IF inference threshold.
7. **F-08/F-09** — mở lại issue/milestone chưa đạt.
8. **F-11/F-12** — CI gate + CLI integration.
9. **F-15/F-20** — duplicate/leakage/calibration/cross-dataset.
10. **F-10/F-14/F-16/F-17/F-19** — docs status, evidence theo run, supply chain, review gate, contract 47 feature; không chặn thí nghiệm nhưng phải xử lý trước khi tuyên bố reproducible/production.

**Điều kiện nghiệm thu tối thiểu**:

- clean checkout → verify split/preprocessor/model hash PASS;
- inference từ chối model không manifest/không hash;
- RF test metric có manifest + prediction;
- XGB có artifact hoặc issue mở;
- IF output `0/1` theo threshold;
- 0 issue đóng sai.

---

## Q17. Sửa gì, thứ tự nào, chứng minh bằng cách nào?

**Trả lời ngắn**: 8 bước, chi tiết ở Report 13.

1. **Chốt canonical split**: chọn `bb84…` hoặc tái sinh; commit index `.csv.gz`/manifest; bỏ hardcode.
2. **Tái sinh preprocessor** từ canonical split; ghi hash thật; sửa EOL policy.
3. **Tái train RF** trên `main`; lưu artifact + manifest; chạy `--verify-only`.
4. **Tái train XGB** cùng split/preprocessor; lưu artifact; thêm CLI.
5. **Fail-closed loaders**: manifest bắt buộc; hash/contract/feature/class bắt buộc; xóa legacy.
6. **Test evaluation một lần**: RF (và XGB) trên test; lưu metric/prediction/confusion.
7. **IF inference**: dùng `anomaly_scores` + threshold; map `0/1`; lưu threshold.
8. **Governance**: mở lại #15/#17/#31 nếu chưa đạt; đóng M2 sai; cập nhật docs/CI; pin dependency/Actions; sửa contract 47 feature.

**Cách chứng minh**:

- `python scripts/preprocess_nf_unsw_nb15_v3.py --verify-only` → PASS;
- `python scripts/train_random_forest.py --verify-only` → PASS;
- `python scripts/predict.py --model random_forest ...` → output có `prediction`, hash, metadata;
- `python -m pytest tests -q -rs` → PASS;
- test mới: model không manifest/`UNVERIFIED` → **FAIL** (mong đợi);
- test mới: XGB load/predict → PASS;
- test mới: IF threshold → `0/1` đúng;
- test mới: test metric khớp manifest.

**Verdict**: có thể sửa trong 1–2 vòng remediation, nhưng **không được đóng issue bằng tài liệu**.
