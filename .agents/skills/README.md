# .agents/skills/ — Skill tích hợp

## Skills local (portable)

- [repo-workflow](repo-workflow/SKILL.md) — điều phối `PLAN` / `IMPLEMENT` / `VERIFY` / `REVIEW`.
- [network-intrusion-detection](network-intrusion-detection/SKILL.md) — semantics network flow (`canonical-flow-v2-18`), L4 payload vs probe features, FP/FN và giới hạn benchmark.
- [unsw-nb15-protocol](unsw-nb15-protocol/SKILL.md) — protocol dữ liệu & provenance v2 (`AIT-NDS-v2`, `CTU-SME-11`, `UWF-ZeekData24`, cách ly `AIT-LDS-v2.1`, `UGR'16 BLOCKED`) và tham chiếu di sản v1 `UNSW-NB15` (`historical/`).
- [ml-experiment-audit](ml-experiment-audit/SKILL.md) — leakage/OOD/threshold/calibration/evaluation audit với `PASS`/`FAIL` criteria.
- [model-experiment](model-experiment/SKILL.md) — thí nghiệm `Random Forest`, `XGBoost`, `Isolation Forest`, `Autoencoder`, manifest và tính tái lập (tách bạch `E0` đóng băng).

Chỉ mục `name`/`description` phục vụ discovery; nội dung được đọc khi skill áp dụng. Domain skill không lặp lại workflow chung và không được nạp đồng loạt. Xem [hướng dẫn dùng](../README.md).

Phân biệt bốn trạng thái:

1. folder/`SKILL.md` tồn tại trong repository;
2. frontmatter/link hợp lệ theo validator;
3. runtime hiện tại khám phá skill (phụ thuộc host/session);
4. skill thực sự được kích hoạt/đọc cho task (cần bằng chứng của lượt chạy).

## OpenCode (`INTEGRATION.md` tham chiếu)

Các thư mục bên dưới chỉ có `INTEGRATION.md`, dùng làm hướng dẫn tham chiếu nhanh cho repo hiện tại:

| Skill | Đường dẫn | Mục đích trong repo v2.0 |
|---|---|---|
| `python-pro` | `.agents/skills/python-pro/` | Python 3.11+, `ruff`/`black`, async/FastAPI, typing cho `src/` & `scripts/` |
| `scikit-learn` | `.agents/skills/scikit-learn/` | `TrainOnlyPreprocessor`, 4 model families (`RF/XGB/IF/AE`), calibration & evaluation |
| `pytest-skill` | `.agents/skills/pytest-skill/` | Unit/integration fixtures, CI-safe mocking khi thiếu `artifacts/`, stress tests |
| `git-workflow-and-versioning` | `.agents/skills/git-workflow-and-versioning/` | Branch `feat/v2-integration`, PR checks, Conventional Commits không dấu ấn AI |
