# Báo cáo migration workflow và audit quản lý dự án

Ngày kiểm tra: 2026-10-17
Repository: `doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`

> **Phạm vi file này.** Mục 2–5 và 7–8 ghi lại lượt migration workflow trước đó và giữ nguyên như lịch sử.
> Mục 1 và 6 được cập nhật theo lượt hoàn thiện M0 (Issue #2 và #3) và là phần cần đọc trước.
> Ma trận yêu cầu → issue → cách kiểm chứng nằm ở `docs/TRACEABILITY_MATRIX.md`.

## 1. Trạng thái Git

Nhánh làm việc: `main`. Không tạo nhánh tạm, không force push, không reset/clean, không rewrite history.

Mốc trước lượt M0:

- `origin/main` = `53471ab` (`docs(audit): refresh migration report`).
- Working tree sạch trước khi bắt đầu.

Mốc sau lượt M0:

- `5de5587` `fix(repo): make unimplemented steps fail loudly and harden M0 setup` (Issue #3).
- `4970d4c` `docs(scope): add requirement traceability matrix and resolve scope contradictions` (Issue #2).
- `8504556` `fix(repo): address review findings on the M0 exit-code contract` (review round cho #2 và #3).
- `origin/main` = `8504556` sau khi push; CI run `38999810930` PASS 4/4 job.
- Lịch sử trước đó giữ nguyên; nhánh `dev` từng có đã bị xóa ở lượt trước, remote không có nhánh `dev`.

## 2. Workflow OpenCode tìm thấy

Bốn workflow đang hoạt động trong `.agents/workflows/`:

- `plan.md`: phân tích yêu cầu, phạm vi, dependency, rủi ro và kế hoạch kiểm chứng.
- `implement.md`: thay đổi tối thiểu theo kế hoạch, bảo vệ thay đổi của người dùng.
- `verify.md`: chạy kiểm tra thực tế và phân loại PASS, FAIL, SKIPPED, NOT VERIFIED.
- `review.md`: review độc lập, ưu tiên bug, regression, security, compatibility và thiếu test.

Các rule và hướng dẫn dùng chung nằm trong `.agents/rules/`, `.agents/README.md` và
`.agents/skills/README.md`. Không tìm thấy bằng chứng cần loại bỏ workflow nào trong bốn workflow cốt lõi.

## 3. Mapping OpenCode → Codex

| Thành phần hiện có | Cách Codex sử dụng | Quyết định |
|---|---|---|
| `.agents/workflows/*.md` | Tài liệu quy trình chi tiết | Giữ nguyên đường dẫn để OpenCode tiếp tục dùng |
| Rule dùng chung | `AGENTS.md` ở root | Tập trung guardrail lâu dài, giảm lặp giữa workflow |
| PLAN/IMPLEMENT/VERIFY/REVIEW | `.agents/skills/repo-workflow/SKILL.md` | Tạo một skill Codex tái sử dụng, định nghĩa input/output và chuyển trạng thái |
| Kiểm tra cấu trúc thủ công | `check_workflows.py` | Tự động kiểm tra metadata, link local và trạng thái verification |
| Agent riêng của OpenCode | Subagent Codex khi tác vụ độc lập và đủ phức tạp | Không giả định cú pháp agent/command riêng của OpenCode tương thích |

Không cài plugin, MCP hoặc dependency mới. Cấu trúc `.agents/` được tái sử dụng thay vì sao chép
một cây cấu hình Codex riêng.

## 4. Cải thiện workflow

- `AGENTS.md` chứa quy tắc chung về phạm vi ML, Git, bảo vệ dữ liệu và kiểm chứng.
- Skill `repo-workflow` định nghĩa rõ input, output và điều kiện chuyển
  PLAN → IMPLEMENT → VERIFY → REVIEW.
- VERIFY hoặc REVIEW có finding sẽ quay lại IMPLEMENT với phạm vi cụ thể; workflow giới hạn vòng lặp
  và dừng bằng trạng thái rõ ràng thay vì lặp vô hạn.
- REVIEW yêu cầu bằng chứng độc lập và không tự sửa khi được giao review-only.
- Lệnh kiểm tra dùng Python để chạy được trên Windows; không phụ thuộc Bash/Make.
- Không workflow nào tự commit hoặc push khi chưa có yêu cầu trực tiếp.

## 5. File migration và sửa P2

Các file workflow được tạo hoặc cập nhật trong `61d0a62`:

- `AGENTS.md`
- `.agents/README.md`
- `.agents/rules/coding-standards.md`
- `.agents/skills/README.md`
- `.agents/skills/repo-workflow/SKILL.md`
- `.agents/skills/repo-workflow/scripts/check_workflows.py`
- `.agents/workflows/plan.md`
- `.agents/workflows/implement.md`
- `.agents/workflows/verify.md`
- `.agents/workflows/review.md`
- `.gitignore`

Các file sửa P2 trong `f11ccba`:

- `.github/workflows/ci.yml`
- `README.md`
- `docs/DATASET.md`
- `docs/REPRODUCIBILITY.md`
- `docs/REQUIREMENTS.md`
- `requirements.txt`
- `scripts/validate_data.py`
- `tests/unit/test_validate_data.py`

Validator hiện stream CSV, kiểm tra UTF-8, header, cột bắt buộc, hàng dữ liệu và độ rộng hàng;
CI truyền đúng exit code khi dữ liệu có mặt nhưng không hợp lệ. Khi không có dataset, validator báo
SKIPPED rõ ràng và không tuyên bố đã kiểm chứng UNSW-NB15 thật.

## 6. Kết quả kiểm chứng

Lượt hoàn thiện M0 (Issue #2 và #3). Mọi lệnh chạy từ root trên Windows, Python 3.14.6, venv sạch tại
`%TEMP%\opencode\m0venv` cài bằng `python -m pip install -e .`. Phiên bản thực tế: pandas 3.0.6,
numpy 2.5.4, scikit-learn 1.9.1, joblib 1.6.0, matplotlib 3.11.2, seaborn 0.13.2.

| Hạng mục | Kết quả | Bằng chứng / exit code | Giới hạn |
|---|---|---|---|
| Cài package trong venv sạch | PASS | `python -m pip install -e .` → 0 | Chỉ 3.14.6 local; 3.11/3.12 phải chờ CI |
| Environment imports + phiên bản Python | PASS | `python scripts/check_environment.py` → 0 | Không kiểm tra model |
| Compile + import mọi mô-đun lõi | PASS | `python -m compileall -q src scripts tests` → 0; `python -c "import network_anomaly, ..."` → 0 | `compileall` trả 0 cả khi thư mục không tồn tại |
| Unit + Integration Test | PASS | `python -m pytest tests -q` → 0, **36 test** | Fixture tổng hợp; không có UNSW-NB15 |
| Validator với fixture hợp lệ | PASS | `--file valid.csv` → 0, in `FOUND` | Chỉ kiểm tra cấu trúc CSV |
| Validator với fixture sai | PASS | `no_label.csv`, `ragged.csv`, `empty.csv`, file thiếu → 1 | Chưa kiểm tra kiểu dữ liệu/nhãn |
| Validator không có dataset | SKIPPED | `python scripts/validate_data.py` → 0, in `SKIPPED` | SKIPPED không phải validation PASS |
| Bước thí nghiệm chưa triển khai | PASS | `--step baseline/evaluate/inference` → **3** + `NOT IMPLEMENTED` | Chưa có bước nào thật sự chạy |
| Sai cú pháp dòng lệnh | PASS | `--step train` → **2**, `invalid choice` | — |
| Cấu trúc workflow và link nội bộ | PASS | `python .agents/skills/repo-workflow/scripts/check_workflows.py` → 0 | Chỉ kiểm link trong `AGENTS.md` và `.agents/**` |
| Whitespace | PASS | `git diff --check` → 0 | — |
| `.gitignore` chặn dataset/artifact/secret/cache/audit | PASS | `git check-ignore -v` trên các đường dẫn đại diện | — |
| YAML workflow và template | PASS | `yaml.safe_load` cho `ci.yml` và 3 file template | Template không kiểm tra bằng GitHub API |
| Dataset thật | SKIPPED | UNSW-NB15 chưa tải theo ràng buộc nhiệm vụ | R01–R06, R08 NOT VERIFIED |
| GitHub Actions trên commit `8504556` | PASS | Run [38999810930](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/runs/38999810930) — 4/4 job success | Chỉ chứng minh setup, không chứng minh ML |
| Runtime discovery trong phiên Codex khác | NOT VERIFIED | Chỉ xác nhận được cấu trúc skill hợp lệ | Phụ thuộc host |
| Hành vi subagent trên mọi Codex host | NOT VERIFIED | Không chạy được ngoài môi trường hiện tại | Phụ thuộc khả năng host |
| Pipeline ML end-to-end | NOT VERIFIED | Chưa được phép triển khai hoặc huấn luyện trong giai đoạn setup | — |

Chi tiết CI trên commit `8504556`:

| Job | Python | Kết quả |
|---|---|---|
| `test (ubuntu-latest, 3.11)` | 3.11.17 | success — 36 test, validate_data SKIPPED |
| `test (ubuntu-latest, 3.12)` | 3.12.15 | success — 36 test, validate_data SKIPPED |
| `test (windows-latest, 3.11)` | 3.11.9 | success — 36 test, validate_data SKIPPED |
| `test (windows-latest, 3.12)` | 3.12.10 | success — 36 test, validate_data SKIPPED |

Mỗi job chạy: `pip install -e .` → `check_environment.py` → `compileall src scripts tests` → import mọi mô-đun
lõi → `pytest tests` → `validate_data.py`. Bước dataset in `SKIPPED` kèm `::notice::` "SKIPPED is not a
PASS", nên CI không thể bị đọc là đã kiểm chứng dữ liệu thật.

Lượt trước (tại `f11ccba`) có 22 test và CI run `38946563304` chỉ trên ubuntu + Python 3.12; con số đó còn
đúng với lượt đó nhưng không còn mô tả trạng thái hiện tại.

Không huấn luyện mô hình, không tải dataset và không sửa pipeline ML trong lượt này.

## 7. Audit Issues và Milestones

- Đã đọc 20 issue: 19 mở (#2–#20) và một issue test đã đóng (#1).
- Đã kiểm tra 6 milestone M0–M5.
- Không thay đổi issue number, state, labels, assignees hoặc milestone assignment.
- Không tạo, đóng hoặc xóa issue/milestone.
- Đã mở rộng cả 19 issue đang mở bằng hai phần theo nội dung thực tế:
  `Trạng thái hiện tại (2026-10-17)` và `Trình tự thực hiện đề xuất`.
- Đã sửa mô tả lỗi thời ở #5, #14 và #17 để phản ánh validator, tài liệu reproducibility,
  22 Unit Test và CI hiện tại.
- Dependency graph không có vòng lặp; Isolation Forest #11 vẫn là tùy chọn và không chặn đường core.
- Bản sao trước cập nhật, proposal và bản đọc lại sau cập nhật được lưu trong thư mục audit local đã ignore.

Các issue chịu ảnh hưởng trực tiếp từ sửa P2:

- #5 — kiểm tra schema, nhãn và chất lượng UNSW-NB15.
- #14 — Traceability và Reproducibility.
- #17 — Unit Test và Integration Test.
- #20 — xác minh tổng thể và điều kiện bàn giao.

## 8. Hạn chế và trạng thái sẵn sàng

Codex đã sẵn sàng thay OpenCode cho bốn workflow PLAN, IMPLEMENT, VERIFY và REVIEW ở cấp repository.
OpenCode vẫn có thể dùng các file workflow cũ tại cùng đường dẫn. Cấu trúc này không giả định Codex hiểu
cú pháp command hoặc agent riêng của OpenCode.

Repository đã sẵn sàng cho giai đoạn setup và phân công công việc qua Issues. Hệ thống ML chưa sẵn sàng
bàn giao: chưa có UNSW-NB15 thật, preprocessing/training/evaluation artifact, Inference hoặc demo. Random
Forest vẫn là baseline bắt buộc; Isolation Forest là hướng mở rộng tùy chọn.

Working tree sau commit/push không có thay đổi tracked chưa commit. Các snapshot audit local được giữ ngoài
Git theo `.gitignore` để có thể đối chiếu hoặc khôi phục nội dung quản lý dự án.
