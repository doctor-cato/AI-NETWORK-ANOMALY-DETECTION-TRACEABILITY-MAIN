# Sổ checkpoint triển khai

## Quy ước

Mỗi checkpoint C0–C11 trong `docs/ROADMAP_FULL_SYSTEM.md` có đúng một mục được bổ sung
khi đến điểm bàn giao. Không thay `PLANNED` thành `IMPLEMENTED`, `TESTED` hoặc
`EXPERIMENTALLY VALIDATED` nếu thiếu code, kết quả test, hoặc evidence phù hợp. PR #22
được review như workstream riêng và không là dependency của checkpoint tài liệu.

Mẫu bắt buộc:

```text
Checkpoint:
Branch:
HEAD:
Completed:
Tests:
Issues:
PR:
Remaining:
Blockers:
Next Action:
```

## C0 — Governance & documentation

```text
Checkpoint: C0
Branch: codex/c0-governance-after-revert (base khôi phục dce80bf)
HEAD: xác minh bằng git/PR readback tại bàn giao; không nhúng self-hash vào commit
Completed: IMPLEMENTED — scope, charter, requirements, architecture, traceability,
  5-role mapping, M6/M7 và backlog #23–#32 đã đồng bộ.
Tests: PASS — workflow validator; environment check; targeted 4 passed; full 36 passed;
  git diff --check. PR #22 worktree: 105 passed; manifest/real validation/diff-check PASS.
  Remote CI cho C0: NOT VERIFIED cho đến khi PR chạy.
Issues: #23 (C0); #24–#32; cập nhật #11, #16, #18–#20; #4/#5 giữ OPEN.
PR: chờ PR khôi phục #33 được maintainer merge; không merge tự động.
Remaining: Sau #33, mở PR C0 từ branch này vào main và đọc lại CI.
Blockers: DOCX layout NOT VERIFIED vì runtime không có LibreOffice bundled; không chặn
  mapping nội dung. C1 real-data workstream vẫn phụ thuộc quyết định PR #22/#7.
Next Action: Maintainer review/merge #33; sau đó tạo PR C0 và chỉ tiếp tục C1 khi CI C0 đạt.
```

## C1–C11

C1 đã có provenance/schema và real-data quality audit cho NF-UNSW-NB15-v3, nhưng quality status
là `FAIL`; EDA và split thật vẫn `NOT VERIFIED`. C2 chỉ có feature/split contract và synthetic
guard tests; chưa có fitted preprocessing artifact. C3–C11 vẫn `PLANNED`.

## Migration NF-UNSW-NB15-v3 — A–H

```text
Checkpoint: A — research/source verification
Branch: feat/migrate-nf-unsw-nb15-v3
HEAD: 017f32b
Completed: VERIFIED — decision, provenance, 55-column schema, source discrepancy, impact.
Tests: PASS — source/package/CSV inspection; git diff --check.
Remaining: none trong phạm vi A.
```

```text
Checkpoint: B — migration architecture
HEAD: 74b6d4e
Completed: IMPLEMENTED — component classification, canonical paths, historical boundary.
Tests: PASS — git diff --check.
Remaining: implementation C–H.
```

```text
Checkpoint: C — acquisition and manifest
HEAD: 3259d3b
Completed: IMPLEMENTED / TESTED — official fetch, bounded streaming, safe ZIP, checksums,
  cache, lock, transaction marker, rollback/recovery; legacy artifacts preserved.
Tests: PASS — 138 synthetic tests; official 110825147-byte archive verified and installed;
  manifest verify PASS; second fetch CACHE_HIT.
Remaining: raw package stays ignored and subject to UQRDM license.
```

```text
Checkpoint: D — validation and quality
HEAD: 9015e58
Completed: IMPLEMENTED / TESTED — streaming validation and disk-backed duplicate audit.
Tests: FAIL on real data — missing/Inf/duplicate findings in
  reports/data_quality/nf_unsw_nb15_v3_validation.json; synthetic validator tests PASS.
Blockers: raw CSV is not model-ready; preprocessing policy must be train-only and audited.
```

```text
Checkpoint: E — split/leakage contract
HEAD: c6004d7
Completed: feature/metadata/target contract and bounded overlap guards IMPLEMENTED / TESTED.
Tests: PASS — 10 synthetic split tests.
Remaining: real split PLANNED / NOT VERIFIED; no model training authorized.
```

```text
Checkpoint: F — architecture/documentation
HEAD: recorded by commit/PR readback at handoff.
Completed: NF-UNSW-NB15-v3 is the documented default; 2015 dataset is historical only.
Tests: pending documentation/link/full-suite gate in G.
Remaining: G tests/CI and H Issues/PR.
```

```text
Checkpoint: G — tests and CI
HEAD: recorded by commit/PR readback at handoff.
Completed: migration regression tests and current-checkout pytest import boundary IMPLEMENTED.
Tests: PASS — environment, compileall, workflow validator, migration Ruff scope, 183 pytest,
  YAML parse, secret/raw tracking scan, branch-wide git diff --check.
Tests: FAIL — repository-wide Ruff has 5 pre-existing findings; repository-wide Black has 11
  pre-existing files requiring formatting. These files are outside the migration implementation
  except historical test wiring, and are not reformatted in this scoped PR.
Remote CI: NOT VERIFIED until branch is pushed and PR checks complete.
Remaining: H Issues/PR; all-gates merge remains blocked while required lint gates fail.
```
