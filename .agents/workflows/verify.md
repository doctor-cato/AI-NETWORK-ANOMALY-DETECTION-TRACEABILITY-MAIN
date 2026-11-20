# Kiểm thử — workflows/verify.md

Sau implement (đối chiếu với `.github/workflows/ci.yml`):

1. **Lint, Format & Repo Hygiene:**
   - `git diff --check`
   - `python -m ruff check src scripts tests`
   - `python -m black --check src scripts tests`
2. **Environment, Contracts & Artifacts:**
   - `python scripts/check_environment.py`
   - `python scripts/export_openapi_spec.py --check`
   - `python scripts/check_desktop_version.py --check`
   - `python scripts/parse_dag.py --check`
   - `python scripts/fetch_multi_source_dataset.py --verify-only`
   - `python scripts/verify_companion_artifacts.py --verify-distribution-permission research-only --target-channel local_offline`
3. **Python Tests:** `python -m pytest tests -q -rs --tb=short` (hoặc subset scoped trước rồi full suite; chú ý rõ lý do skip từ `-rs` giữa platform Windows/DPAPI và `.gitignore`-d model/demo binaries trên CI).
4. **Desktop Frontend & Rust/Tauri (khi sửa UI/API types/Rust):**
   - `npm --prefix desktop run check`, `npm --prefix desktop test`, `npm --prefix desktop run build`
   - `cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check`, `cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings`, `cargo test --manifest-path desktop/src-tauri/Cargo.toml --lib`
5. **Kiểm tra dữ liệu & ML:** Xác minh provenance/checksum, split boundary (`V2_SPLIT_MANIFEST.json`), preprocessor fit-boundary, OOD gate fail-closed (`deployment` vs `research`), score semantics/threshold provenance (`ait_val`, không `test`), và metric order (Binary vs Multiclass Macro-F1/FPR).
6. **Kiểm tra runtime/tích hợp:** Xác minh hành vi thực tế và đường lỗi (HTTP status, fail-closed `UNAVAILABLE`, DB rollback, UDP loopback/replay, `executed=false` dry-run), không chỉ dừng ở constructor/import. Phân biệt rạch ròi `synthetic` / `real-dataset loopback replay` với `physical switch/router lab` (`#137`).
7. **Quy ước báo cáo kết quả:** Báo từng kiểm tra với một trong 4 trạng thái bắt buộc: `PASS` (đã chạy sau chỉnh sửa cuối và đạt), `FAIL` (đã chạy và lỗi), `SKIPPED` (chủ đích bỏ qua vì thiếu dataset/binary/OS đặc thù — ghi rõ lý do; exit code `0` khi thiếu dataset vẫn là `SKIPPED`), `NOT VERIFIED` (chưa chạy/không đủ bằng chứng).
8. Không gọi local test PASS là remote GitHub Actions CI PASS; chỉ kết luận sau khi chạy thật lệnh tương ứng sau lần sửa cuối.

Input: diff thực tế, yêu cầu và danh sách check bắt buộc. Output: bảng/danh sách check kèm lệnh, exit code, trạng thái, số lượng cụ thể và giới hạn. `VERIFY-only` không sửa code sản phẩm.
