# Reproducibility

## Môi trường hiện tại

- Python >=3.11; CI chạy ma trận 3.11 và 3.12 trên Ubuntu và Windows (`.github/workflows/ci.yml`).
- Cài bằng `python -m pip install -e .` hoặc `python -m pip install -r requirements.txt`.
- `pyproject.toml` và `requirements.txt` dùng giới hạn phiên bản tối thiểu (`>=`), chưa phải lockfile. Cùng câu lệnh cài đặt có thể giải quyết ra các phiên bản khác nhau.
- Khi ghi nhận một lần chạy, lưu `python --version`, kết quả `python -m pip freeze`, hệ điều hành và commit (`git rev-parse HEAD`). File danh sách phiên bản đã cài là bằng chứng môi trường, chưa bảo đảm tái lập trên mọi nền tảng.

## Lệnh kiểm tra đã có

Chạy từ root repository, sau khi cài package:

```text
python -c "import network_anomaly"
python scripts/check_environment.py
python -m pytest -q
python scripts/validate_data.py
python scripts/run_experiments.py --step baseline   # exit 3 = NOT IMPLEMENTED
```

Validator mặc định tìm `data/raw/UNSW_NB15_training-set.csv` và
`data/raw/UNSW_NB15_testing-set.csv`; khi cả hai thiếu, in SKIPPED và exit 0.
Đó không phải bằng chứng dữ liệu thật đã đạt. `--file` chỉ định tên file dưới
`data/raw/` hoặc đường dẫn rõ ràng; file thiếu và dữ liệu sai trả exit 1.
Profile kiểm tra 45 cột, kiểu dữ liệu, nhãn, attack category, missing, duplicate và dòng trống. Dòng CSV không có delimiter và không có giá trị là lỗi chặn (exit 1) với số dòng và vị trí, không bị bỏ qua âm thầm; dòng có delimiter nhưng giá trị rỗng vẫn thuộc kiểm tra missing/độ rộng hàng. Báo cáo trên cặp CSV đã đối chiếu mirror nằm trong `reports/data_quality/unsw_nb15_validation.json`. Leakage audit thuộc #7.

Tests CSV dùng dữ liệu tổng hợp tạo trong thư mục tạm. Test constructor của RF/IF không chứng minh fit/predict hoặc kết quả trên UNSW-NB15. SKIPPED và fixture không thay thế thực nghiệm thật.

## Seed và cấu hình

- Giá trị mặc định `RANDOM_SEED = 42` nằm trong `src/network_anomaly/config.py`, được dùng cho `random_state` của model constructors.
- Chưa có training/split pipeline hoàn chỉnh; không mặc định rằng seed NumPy/Python hoặc mọi bước chia dữ liệu đã được thiết lập. Khi triển khai phải ghi rõ seed thực sự được sử dụng.
- Cấu hình hiện lấy từ module Python; chưa có cơ chế đọc seed từ biến môi trường hoặc `pyproject.toml`.

## Thực nghiệm và artifact (chưa hoàn thành)

Training, đánh giá end-to-end và Inference CSV chưa có entrypoint hoàn chỉnh. `scripts/run_experiments.py`
chỉ thực sự chạy bước `check-data` (gọi `validate_data.py`); các bước `baseline`, `evaluate`, `inference`
in trạng thái NOT IMPLEMENTED và **trả exit 3** để không ai đọc nhầm là đã chạy thành công. Exit 2 dành riêng
cho lỗi dòng lệnh, nên gõ sai `--step` không bị nhầm với bước "đã lên kế hoạch".

Khi được giao triển khai, mỗi lần chạy cần lưu: run ID, commit, checksum/phiên bản dữ liệu, split/seed, danh sách feature, cấu hình, phiên bản thư viện, model/preprocessing đã fit và metric/confusion matrix có nguồn gốc rõ ràng. Không ghi đè artifact âm thầm và không commit dataset/artifact lớn.

## Ghi nhận dataset

Manifest version-control tại `data/UNSW_NB15_MANIFEST.json` ghi nguồn chính thức,
mirror revision-pinned, thời điểm UTC, kích thước, SHA-256 và các nguồn đối chiếu.
UNSW không công bố SHA-256 và endpoint SharePoint yêu cầu xác thực trong lần kiểm tra,
vì vậy manifest không gọi checksum local là checksum chính thức.

```text
python scripts/fetch_unsw_nb15.py
python scripts/dataset_manifest.py verify
python scripts/validate_data.py --manifest data/UNSW_NB15_MANIFEST.json --report reports/data_quality/unsw_nb15_validation.json
```

Script fetch tái sử dụng cache local: file trong `data/raw/` chỉ được giữ khi khớp
SHA-256 và kích thước theo manifest, nên chạy lại không tải lại (`CACHE_HIT`). File thiếu
hoặc sai được tải lại từ mirror revision-pinned vào staging tạm cùng thư mục đích, kiểm tra
HTTP response, size và SHA-256 trước khi thay thế nguyên tử; staging luôn được dọn kể cả
khi lỗi. Trước lần thay đầu tiên script sao lưu bản cũ của mọi file sẽ bị thay, và nếu
`os.replace` thất bại ở file nào thì các file **đã thay** được hoàn nguyên về byte trước đó,
rồi lỗi gốc được ném lại. Rollback không xóa file đích trước: `os.replace` ghi đè nguyên tử
nên nếu khôi phục lỗi, file đích giữ byte mới đã verify và bản sao lưu được giữ lại kèm
dòng `RECOVERY` để phục hồi thủ công. File mới tạo trong lần chạy đó được giữ vì không có
bản cũ để khôi phục. Lỗi khi dọn staging/backup được ghi `CLEANUP WARNING` và không ném lỗi
mới đè lên lỗi đang báo. Tên staging và backup có kèm PID nên hai lần chạy đồng thời không
dùng chung file tạm. Raw CSV bị `.gitignore` loại khỏi Git. Báo cáo thật
lưu aggregate row/schema/blank/missing/duplicate và checksum, không chứa dòng raw.
Fixture test chỉ kiểm tra hành vi validator.

Khi cả hai CSV vắng mặt, `validate_data.py` in `SKIPPED`, in rõ `SKIPPED is not PASS` và
exit 0; khi chạy trong GitHub Actions nó ghi thêm annotation `::warning::SKIPPED is not a
PASS` để CI không bị đọc nhầm là đã kiểm chứng dữ liệu thật.

Timestamp trong manifest là ISO 8601 nguyên giây kèm offset tường minh
(`YYYY-MM-DDTHH:MM:SSZ` hoặc `±HH:MM`), không dùng naive datetime. `record` chuẩn hóa
`--downloaded-at` về UTC trước khi ghi; `verify` kiểm tra mọi timestamp tìm thấy trong
manifest và chỉ đọc, nên chạy verify không đổi file manifest.

Cập nhật: 2026-10-17.
