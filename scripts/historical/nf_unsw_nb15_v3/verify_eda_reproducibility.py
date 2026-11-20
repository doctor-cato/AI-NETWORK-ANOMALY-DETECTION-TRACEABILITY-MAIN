#!/usr/bin/env python3
"""Run the NF-UNSW-NB15-v3 EDA twice and prove that the results reproduce.

The script executes ``scripts/eda_nf_unsw_nb15_v3.py`` twice on the same verified
source file, captures the real stdout and stderr of each run and writes one
retrievable evidence bundle per run under ``reports/eda/evidence/``. It then
compares the two machine-readable summaries and the two evidence bundles and
writes a PASS/FAIL reproducibility report.

The comparison excludes only the metadata that is allowed to differ between two
runs of the same command: the run timestamp and the environment description.

Exit codes:
  0 - both runs succeeded and the deterministic content is identical, or the raw
      package is absent and the check was skipped. A skip is not a PASS and is
      reported as SKIPPED, like the validator and the EDA command.
  1 - a run failed or the two runs disagree.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    # Prefer this checkout over any editable install of the same package name.
    sys.path.insert(0, str(LOCAL_SOURCE))

from network_anomaly.eda.evidence import (  # noqa: E402
    COMPARISON_SCHEMA_VERSION,
    build_run_evidence,
    compare_evidence,
    compare_summaries,
    dataset_identity,
    environment_metadata,
    git_metadata,
    manifest_verification,
    render_comparison_report,
    sha256_file,
    utc_now,
    write_evidence_bundle,
)

DEFAULT_DATASET = PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json"
DEFAULT_EVIDENCE = PROJECT_ROOT / "reports" / "eda" / "evidence"
DEFAULT_FIGURES = PROJECT_ROOT / "reports" / "figures" / "nf_unsw_nb15_v3"
EDA_SCRIPT = PROJECT_ROOT / "scripts" / "eda_nf_unsw_nb15_v3.py"
SKIPPED_MESSAGE = (
    "NF-UNSW-NB15-v3 bytes are absent; the reproducibility check is SKIPPED, not PASS. "
    "Run python scripts/fetch_nf_unsw_nb15_v3.py first."
)
EXIT_OK = 0
EXIT_FAILED = 1


def run_eda(arguments: list[str]) -> tuple[int, str, str, float, str, str]:
    """Execute the EDA command and capture its real output."""
    started = utc_now()
    started_monotonic = time.monotonic()
    result = subprocess.run(
        [sys.executable, str(EDA_SCRIPT), *arguments],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    duration = time.monotonic() - started_monotonic
    finished = utc_now()
    return (
        result.returncode,
        result.stdout,
        result.stderr,
        duration,
        started,
        finished,
    )


def collect_run(label: str, directory: Path, arguments: list[str], dataset: Path) -> dict:
    """Run the EDA once and build the evidence bundle of that run."""
    directory.mkdir(parents=True, exist_ok=True)
    exit_code, stdout, stderr, duration, started, finished = run_eda(arguments)
    (directory / "stdout.log").write_text(stdout, encoding="utf-8")
    (directory / "stderr.log").write_text(stderr, encoding="utf-8")
    if exit_code != 0:
        raise RuntimeError(
            f"the EDA run '{label}' failed with exit code {exit_code}; see {directory}"
        )
    summary = json.loads((directory / "eda_summary.json").read_text(encoding="utf-8"))
    observed_sha256 = sha256_file(dataset)
    manifest = manifest_verification(
        arguments[arguments.index("--manifest") + 1],
        dataset,
        observed_sha256,
        summary["rows"],
        summary["expected_rows"],
        len(summary["contract"]["baseline_ml_features"])
        + len(summary["contract"]["trace_metadata_columns"])
        + len(summary["contract"]["target_columns"]),
    )
    figure_directory = Path(arguments[arguments.index("--figures") + 1])
    figure_files = sorted(path.name for path in figure_directory.glob("*.png"))
    evidence = build_run_evidence(
        summary,
        label=label,
        directory=directory,
        command=f"python scripts/eda_nf_unsw_nb15_v3.py {' '.join(arguments)}",
        exit_code=exit_code,
        started_at_utc=started,
        finished_at_utc=finished,
        duration_seconds=round(duration, 3),
        git=git_metadata(PROJECT_ROOT),
        environment=environment_metadata(),
        dataset=dataset_identity(dataset, observed_sha256),
        manifest=manifest,
        stdout_log=str(directory / "stdout.log"),
        stderr_log=str(directory / "stderr.log"),
        figure_directory=str(figure_directory),
        figure_files=figure_files,
    )
    write_evidence_bundle(directory, evidence, stdout, stderr)
    return evidence


def main(argv=None):
    """Run the two executions and write the reproducibility comparison."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--figure-root", type=Path, default=DEFAULT_FIGURES)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--sample-size", type=int, default=200_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--chunk-size", type=int, default=100_000)
    parser.add_argument("--max-rows", type=int)
    args = parser.parse_args(argv)

    if not args.dataset.is_file():
        print(f"[verify_eda_reproducibility] REPRODUCIBILITY: SKIPPED - {SKIPPED_MESSAGE}")
        print("[verify_eda_reproducibility] SOURCE_INTEGRITY: SKIPPED")
        print("[verify_eda_reproducibility] ML_READY: BLOCKED")
        if os.getenv("GITHUB_ACTIONS") == "true":
            print(f"::warning::{SKIPPED_MESSAGE}")
        return EXIT_OK
    if args.runs < 2:
        print("[verify_eda_reproducibility] ERROR: at least two runs are required")
        return EXIT_FAILED

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    evidence_runs = []
    for index in range(1, args.runs + 1):
        label = f"run-{index}"
        directory = output / label
        arguments = [
            "--dataset",
            str(args.dataset),
            "--manifest",
            str(args.manifest),
            "--summary",
            str(directory / "eda_summary.json"),
            "--report",
            str(directory / "eda_report.md"),
            "--figures",
            str(Path(args.figure_root) / f"repro-{label}"),
            "--sample-size",
            str(args.sample_size),
            "--seed",
            str(args.seed),
            "--chunk-size",
            str(args.chunk_size),
        ]
        if args.max_rows is not None:
            arguments.extend(["--max-rows", str(args.max_rows)])
        try:
            evidence = collect_run(label, directory, arguments, Path(args.dataset))
        except RuntimeError as error:
            print("[verify_eda_reproducibility] REPRODUCIBILITY: FAIL")
            print(f"[verify_eda_reproducibility] ERROR: {error}")
            return EXIT_FAILED
        evidence_runs.append(evidence)
        print(
            f"[verify_eda_reproducibility] {label}: exit={evidence['exit_code']} "
            f"rows={evidence['key_aggregates']['rows']} "
            f"summary_sha256={evidence['summary_artifact']['sha256']}"
        )

    left, right = evidence_runs[0], evidence_runs[1]
    left_summary = json.loads(
        (Path(left["directory"]) / "eda_summary.json").read_text(encoding="utf-8")
    )
    right_summary = json.loads(
        (Path(right["directory"]) / "eda_summary.json").read_text(encoding="utf-8")
    )
    comparison = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "runs": [
            {
                "label": run["label"],
                "directory": run["directory"],
                "started_at_utc": run["started_at_utc"],
                "finished_at_utc": run["finished_at_utc"],
                "duration_seconds": run["duration_seconds"],
                "exit_code": run["exit_code"],
                "summary_sha256": run["summary_artifact"]["sha256"],
                "git_head": run["git"]["head"],
                "dataset_sha256": run["dataset"]["sha256"],
            }
            for run in evidence_runs
        ],
        "summaries": compare_summaries(left_summary, right_summary),
        "evidence": compare_evidence(left, right),
    }
    summaries_ok = comparison["summaries"]["overall"] == "PASS"
    evidence_ok = comparison["evidence"]["overall"] == "PASS"
    overall = "PASS" if summaries_ok and evidence_ok else "FAIL"
    comparison["overall"] = overall
    (output / "reproducibility_comparison.json").write_text(
        json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "reproducibility_comparison.md").write_text(
        render_comparison_report(comparison, left, right), encoding="utf-8"
    )
    print(f"[verify_eda_reproducibility] REPRODUCIBILITY: {overall}")
    for row in comparison["summaries"]["metrics"]:
        if row["status"] != "PASS":
            print(
                f"[verify_eda_reproducibility] DIFFERENCE in {row['metric']}: "
                f"{row['difference_count']}"
            )
    print(
        f"[verify_eda_reproducibility] report={output / 'reproducibility_comparison.md'} "
        f"json={output / 'reproducibility_comparison.json'}"
    )
    return EXIT_OK if overall == "PASS" else EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
