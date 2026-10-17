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
python scripts/run_experiments.py --step baseline   # exit 2 = NOT IMPLEMENTED
```

Validator tự kiểm tra cả `data/raw/UNSW-NB15.csv` và `data/raw/UNSW-NB15_training_set.csv` nếu tồn tại. File có tên khác: `python scripts/validate_data.py --file <ten-file.csv>`. Có thể truyền đường dẫn tuyệt đối. Chỉ file mặc định chưa có mới được SKIPPED với exit 0; `--file` trỏ đến file thiếu hoặc CSV không hợp lệ phải thất bại.

Phạm vi validation hiện tại: header có `label` và `proto`, tên cột không trống/trùng, có dữ liệu, cấu trúc/số cột các bản ghi nhất quán và UTF-8 đọc được. CSV không header chưa hỗ trợ. Kiểu dữ liệu, giá trị nhãn, missing values, duplicates và leakage chưa được xác minh đầy đủ.

Tests CSV dùng dữ liệu tổng hợp tạo trong thư mục tạm. Test constructor của RF/IF không chứng minh fit/predict hoặc kết quả trên UNSW-NB15. SKIPPED và fixture không thay thế thực nghiệm thật.

## Seed và cấu hình

- Giá trị mặc định `RANDOM_SEED = 42` nằm trong `src/network_anomaly/config.py`, được dùng cho `random_state` của model constructors.
- Chưa có training/split pipeline hoàn chỉnh; không mặc định rằng seed NumPy/Python hoặc mọi bước chia dữ liệu đã được thiết lập. Khi triển khai phải ghi rõ seed thực sự được sử dụng.
- Cấu hình hiện lấy từ module Python; chưa có cơ chế đọc seed từ biến môi trường hoặc `pyproject.toml`.

## Thực nghiệm và artifact (chưa hoàn thành)

Training, đánh giá end-to-end và Inference CSV chưa có entrypoint hoàn chỉnh. `scripts/run_experiments.py`
chỉ thực sự chạy bước `check-data` (uỏ quyền `validate_data.py`); các bước `baseline`, `evaluate`, `inference`
in trạng thái NOT IMPLEMENTED và **trả exit 2** để không ai đọc nhầm là đã chạy thành công.

Khi được giao triển khai, mỗi lần chạy cần lưu: run ID, commit, checksum/phiên bản dữ liệu, split/seed, danh sách feature, cấu hình, phiên bản thư viện, model/preprocessing đã fit và metric/confusion matrix có nguồn gốc rõ ràng. Không ghi đè artifact âm thầm và không commit dataset/artifact lớn.

## Ghi nhận dataset

UNSW-NB15 chưa được tải/xác minh trong giai đoạn Setup & Audit. Khi tải ở nhiệm vụ riêng, ghi nguồn, điều kiện sử dụng, ngày tải, biến thể, tên file và SHA-256. Hướng dẫn nguồn ở `docs/DATASET.md`; không tuyên bố có benchmark trước khi thực nghiệm thật hoàn thành.

Cập nhật: 2026-10-17.
