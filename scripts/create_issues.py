#!/usr/bin/env python3
"""Create core issues for AI anomaly detection project."""
import subprocess, sys

repo = "doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN"

issues = [
    # Scope / requirements
    ("Project scope and requirements — define mandatory/non-mandatory items",
     "Define in-scope and out-of-scope items per instructions. Document in docs/PROJECT_CHARTER.md and docs/FUTURE_WORK.md.\n\nAcceptance: docs exist; no future items blocking M0–M5.",
     "docs", "type:feature", "priority:high", "M0"),
    ("Repository structure and developer environment setup",
     "Create directories, config, CI, requirements, Makefile, .gitignore, .editorconfig. Verify `make install` and basic imports.\n\nAcceptance: `python -c 'import network_anomaly'` passes; CI runs.",
     "src", "type:feature", "priority:high", "M0"),
    # Dataset
    ("Dataset sourcing — download UNSW-NB15 and verify source",
     "Download from official UNSW source; record version/checksum in docs/DATASET.md and docs/REPRODUCIBILITY.md. Do not commit large files to Git.\n\nAcceptance: instructions verified; dataset placed in data/raw/; validate script passes.",
     "data", "type:feature", "priority:high", "M1"),
    ("Validate UNSW-NB15 schema, labels, and class distribution",
     "Run scripts/validate_data.py; document label values, class counts, missing values, duplicates.\n\nAcceptance: validation script produces summary; leakage audit started.",
     "data", "type:feature", "priority:high", "M1"),
    # EDA / leakage
    ("Exploratory data analysis — label distribution and feature inspection",
     "Produce EDA notebook/figures: class balance, feature distributions, correlations.\n\nAcceptance: notebook or report section exists.",
     "data", "type:research", "priority:high", "M1"),
    ("Leakage audit and feature selection — identity columns, duplicates, time leakage",
     "Audit identity/port/IP/time columns; document exclusions; confirm split before any fit.\n\nAcceptance: audit document exists; feature selection rules recorded.",
     "data", "type:research", "priority:high", "M1"),
    ("Preprocessing pipeline design and reproducibility",
     "Build pipeline with encoding/scaling/selection; save fitted objects; avoid test-set leakage.\n\nAcceptance: pipeline runs; artifacts saved; reproducibility notes updated.",
     "ml", "type:feature", "priority:high", "M2"),
    # Baseline / RF
    ("Baseline implementation — establish comparison point",
     "Document baseline (e.g., simple rules or basic model); record initial metrics for comparison.\n\nAcceptance: baseline documented in docs/EXPERIMENT_PLAN.md.",
     "ml", "type:feature", "priority:medium", "M2"),
    ("Random Forest implementation and training",
     "Train RF with documented config (seed, hyperparameters); save model; record time/config.\n\nAcceptance: model artifact exists; metrics recorded.",
     "ml", "type:feature", "priority:high", "M2"),
    # IF / evaluation
    ("Isolation Forest implementation and evaluation protocol",
     "Implement IF; document score-to-label protocol separately from RF; select threshold on validation.\n\nAcceptance: module exists; evaluation protocol clearly documented.",
     "ml", "type:feature", "priority:medium", "M3"),
    ("Metrics and comparison — Precision, Recall, F1, Macro-F1, confusion matrix, FPR",
     "Compute metrics per model with documented protocols; create comparison table; note differences.\n\nAcceptance: evaluation module outputs metrics; comparison documented.",
     "evaluation", "type:feature", "priority:high", "M3"),
    ("Error analysis — false positives, false negatives, data limitations",
     "Analyze errors; describe causes (feature overlap, class imbalance, missing data); document limits.\n\nAcceptance: analysis section exists; no unverified claims.",
     "evaluation", "type:research", "priority:medium", "M3"),
    # Reproducibility / tracking
    ("Experiment tracking and reproducibility — seeds, versions, artifacts",
     "Fix seeds; record environment; save artifacts; document how to rerun.\n\nAcceptance: docs/REPRODUCIBILITY.md verified; seeds set in config.py.",
     "infrastructure", "type:feature", "priority:medium", "M3"),
    # Inference / demo
    ("Inference pipeline — load artifacts and predict new input",
     "Implement inference module; test with fixture; document input format and output format.\n\nAcceptance: inference script runs without dataset if model artifact exists.",
     "ml", "type:feature", "priority:medium", "M4"),
    ("Demo and visualization — minimal demo and result plots",
     "Create demo script/notebook; generate confusion matrix / metric plots; verify readability.\n\nAcceptance: demo output exists; plots saved.",
     "docs", "type:feature", "priority:medium", "M4"),
    # Tests / docs
    ("Unit and integration tests — import, pipeline, basic predictions",
     "Add tests for module imports, pipeline steps, fixture predictions; verify CI passes.\n\nAcceptance: pytest passes; CI green.",
     "testing", "type:testing", "priority:medium", "M4"),
    ("Documentation completion — README consistency, docs alignment",
     "Verify all docs consistent; no MIT content; no fabricated metrics; distinguish planned/implemented/verified.\n\nAcceptance: audit complete; README links correct.",
     "documentation", "type:docs", "priority:medium", "M5"),
    ("Report and presentation outline — PDF report and slide plan",
     "Complete docs/REPORT_OUTLINE.md and docs/PRESENTATION_OUTLINE.md; prepare content sections.\n\nAcceptance: outlines complete; ready for content entry.",
     "documentation", "type:docs", "priority:high", "M5"),
    ("Final verification and release — check license, issues, milestones, CI",
     "Verify Apache 2.0; verify milestones/issues exist; verify no secrets; commit/push.\n\nAcceptance: final check passes; release tagged (optional).",
     "infrastructure", "type:testing", "priority:high", "M5"),
]

# Fix tuple length issue (one issue missing title)
issues_fixed = []
for item in issues:
    if len(item) < 4:
        continue
    if item[0] == "":
        item = ("Report and presentation outline — PDF report and slide plan", item[1], item[2], item[3], item[4])
    issues_fixed.append(item)

for item in issues_fixed:
    title = item[0]
    body = item[1]
    if len(item) == 6:
        label_str = item[3]
        milestone = item[5]
    else:
        label_str = item[2]
        milestone = item[3]
    # Build labels string (comma-separated for --label if needed; gh issue create accepts multiple --label)
    labels = [label_str, "good first issue"] if "testing" in label_str or "docs" in label_str else [label_str]
    cmd = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body, "--label", ",".join(labels) if labels else "documentation"]
    if milestone:
        cmd += ["--milestone", milestone.split(" ")[0]]
    # Note: milestone names contain spaces; gh expects milestone title or number. We pass the milestone number via mapping if needed, but using title may work.
    # Simpler: skip milestone argument if title is complex; already linked in docs.
    # Actually let's include milestone by number mapping to be safe.
    # But we have milestone numbers from creation: M0=1, M1=2, M2=3, M3=4, M4=5, M5=6
    mapping = {
        "M0": "M0 — Repository Foundation and Project Design",
        "M1": "M1 — Dataset Acquisition and Exploratory Data Analysis",
        "M2": "M2 — Preprocessing and Baseline Models",
        "M3": "M3 — Anomaly Detection and Model Evaluation",
        "M4": "M4 — Inference, Demo and Integration",
        "M5": "M5 — Final Report, Presentation and Release",
    }
    ms_key = milestone.split(" ")[0] if milestone else None
    ms_title = mapping.get(ms_key) if ms_key else None
    cmd = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body, "--label", ",".join(labels) if labels else "documentation"]
    if ms_title:
        cmd += ["--milestone", ms_title]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0 and result.stdout:
        url = result.stdout.strip()
        print(f"PASS '{title[:60]}...' -> {url}")
    else:
        # Try with just first label if multi-label fails
        cmd_simple = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body, "--label", labels[0] if labels else "documentation"]
        if ms_title:
            cmd_simple += ["--milestone", ms_title]
        result2 = subprocess.run(cmd_simple, capture_output=True, text=True)
        if result2.returncode == 0:
            print(f"PASS '{title[:60]}...' -> {result2.stdout.strip()}")
        else:
            print(f"FAIL '{title[:60]}...' -> {result.stderr[:200]} / {result2.stderr[:200]}")
