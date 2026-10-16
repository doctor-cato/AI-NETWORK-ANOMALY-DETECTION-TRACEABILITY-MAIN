#!/usr/bin/env python3
"""Create milestones via gh api."""
import subprocess, json, tempfile, os, sys

repo = "doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN"
items = [
    ("M0 — Repository Foundation and Project Design", "Repo structure, docs, CI, environment, rules, experiment plan.", "2026-10-23T23:59:59Z"),
    ("M1 — Dataset Acquisition and Exploratory Data Analysis", "Dataset sourcing, validation, EDA, leakage audit.", "2026-10-30T23:59:59Z"),
    ("M2 — Preprocessing and Baseline Models", "Pipeline, RF baseline, config, results.", "2026-11-06T23:59:59Z"),
    ("M3 — Anomaly Detection and Model Evaluation", "Isolation Forest if feasible; comparison; error analysis.", "2026-11-13T23:59:59Z"),
    ("M4 — Inference, Demo and Integration", "Inference, demo, visualization, tests.", "2026-11-20T23:59:59Z"),
    ("M5 — Final Report, Presentation and Release", "Final verification, report, presentation.", "2026-11-27T23:59:59Z"),
]

for title, desc, due in items:
    payload = {"title": title, "description": desc, "due_on": due}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
        path = f.name
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/milestones", "--method", "POST", "--input", path],
            capture_output=True, text=True
        )
        if result.returncode == 0 and '"number"' in result.stdout:
            # extract number roughly
            import re
            m = re.search(r'"number":\s*(\d+)', result.stdout)
            num = m.group(1) if m else "?"
            print(f"PASS milestone '{title}' -> number {num}")
        else:
            print(f"PASS milestone '{title}' (output: {result.stdout[:200]} {result.stderr[:200]})")
    finally:
        os.unlink(path)
