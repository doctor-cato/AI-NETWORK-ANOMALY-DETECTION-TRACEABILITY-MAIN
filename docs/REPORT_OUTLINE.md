# Report Outline (PDF / document for course assignment)

1. Title page — project title, authors, institution, date, license
2. Abstract — problem, method, key results (to be filled after experiments), limitations
3. Introduction — motivation, problem statement, objectives, non-goals
4. Dataset — UNSW-NB15 source, structure, download instructions, version, limitations
5. Methodology — pipeline, split strategy, preprocessing, Random Forest, Isolation Forest (if implemented), evaluation protocols clearly separated
6. Experimental Setup — environment, seeds, hyperparameters, metrics definitions
7. Results — metrics, confusion matrices (images), comparison table, error analysis
8. Discussion — interpretation, false positives/negatives, data limitations, comparison validity (note different evaluation protocols if both models used)
9. Conclusion — summary, what works, what is limited, next steps
10. References — dataset sources, scikit-learn, papers
11. Appendices — configuration files, pipeline diagrams, reproducibility steps

## Gói nộp bộ (submission package)

Yêu cầu nộp bài gồm mã nguồn, tài liệu và dữ liệu. Ràng buộc bắt buộc của gói:

- **Mã nguồn:** toàn bộ repo tại commit đã ghi trong báo cáo; không cần thao tác sửa tay sau khi clone.
- **Tài liệu:** `README.md` + `docs/` (báo cáo này, dàn ý trình bày, phân công nhóm, hướng dẫn tái lập).
- **Dữ liệu:** UNSW-NB15 **không** commit và **không** phát tán lại trong gói nếu điều khoản sử dụng chưa
  cho phép. Gói chỉ ghi kèm: tên file, phiên bản, checksum và lệnh tải từ nguồn chính thức
  (`docs/DATASET.md`, `docs/REPRODUCIBILITY.md`). Nếu giảng viên yêu cầu kèm dữ liệu, phải ghi rõ điều khoản
  áp dụng trước khi đóng gói.
- **Không kèm:** secret, artifact model lớn, cache, notebook output; `.gitignore` đã chặn các nhóm này.
- Kiểm tra trước khi nộp: `python scripts/check_environment.py`, `python -m pytest tests -q`,
  `git diff --check`, và CI xanh trên đúng commit.

Updated: 2026-10-17 — to be filled with verified results after M3.
