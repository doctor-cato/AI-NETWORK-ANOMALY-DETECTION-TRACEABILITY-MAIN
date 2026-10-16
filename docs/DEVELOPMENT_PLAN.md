# Development Plan (5–6 weeks)

| Week | Focus | Milestone | Key deliverables |
|---|---|---|---|
| 1 | Repo, docs, environment, CI | M0 | Structure; README; docs; CI; labels |
| 2 | Data validation, EDA, leakage audit | M1 | Dataset instructions; validation script; EDA; leakage audit doc |
| 3 | Preprocessing pipeline; Random Forest; baseline | M2 | Pipeline; RF model; metrics recorded; reproducibility notes |
| 4 | Isolation Forest (if time); evaluation; comparison; error analysis | M3 | IF protocol; comparison table; confusion matrices; analysis |
| 5 | Inference; demo; visualization; integration tests | M4 | Inference module; demo script; tests; visualizations |
| 6 | Final documentation; report; presentation; verification | M5 | Report outline complete; presentation outline; final check |

Dependencies: M2 depends on M1 (preprocessing needs validated data). M3 depends on M2 (evaluation needs trained model). M4 depends on M3 (demo uses results). M5 depends on M4 (final verification uses all prior outputs).

Updated: 2026-10-16
