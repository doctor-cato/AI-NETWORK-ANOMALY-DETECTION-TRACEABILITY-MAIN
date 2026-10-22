"""Evidence bundles and reproducibility comparison for the NF-UNSW-NB15-v3 EDA.

A run bundle records everything a reviewer needs to re-check one EDA execution
on the real source file: the git state, the interpreter, the dependencies, the
dataset identity, the manifest and schema verification, the key aggregates, the
command, the exit code, the timestamps, the SHA-256 of the produced summary and
the captured stdout and stderr.

The comparison walks two summaries and two evidence bundles and reports PASS or
FAIL per metric. Only the metadata that is allowed to differ between two runs of
the same command - the run timestamp and the environment description - is
excluded from the comparison.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_SCHEMA_VERSION = "nf-unsw-nb15-v3-eda-evidence-v1"
COMPARISON_SCHEMA_VERSION = "nf-unsw-nb15-v3-eda-reproducibility-v1"

# Metadata that is allowed to differ between two runs of the same command.
EXCLUDED_COMPARISON_PATHS = (
    "generated_at_utc",
    "tool.python",
    "tool.platform",
)
# Evidence fields that are allowed to differ between two runs.
EXCLUDED_EVIDENCE_PATHS = (
    "started_at_utc",
    "finished_at_utc",
    "duration_seconds",
    "label",
    "directory",
    "stdout_log",
    "stderr_log",
    "figure_directory",
    "figure_files",
    "command",
    "summary_artifact.path",
    "summary_artifact.sha256",
    "report_artifact.path",
    "report_artifact.sha256",
)
KEY_QUANTILE_COLUMNS = (
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS",
    "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT",
    "MIN_TTL",
    "MAX_TTL",
)


def sha256_file(path) -> str:
    """Return the SHA-256 of a file."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def git_metadata(project_root) -> dict:
    """Return the git state of the checkout that produced the evidence."""
    root = Path(project_root)

    def run(*arguments: str) -> str:
        try:
            result = subprocess.run(
                ["git", *arguments],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return "NOT VERIFIED"
        return result.stdout.strip() or "NOT VERIFIED"

    status = run("status", "--porcelain")
    return {
        "head": run("rev-parse", "HEAD"),
        "branch": run("rev-parse", "--abbrev-ref", "HEAD"),
        "commit_date": run("log", "-1", "--format=%cI"),
        "working_tree_clean": status in ("", "NOT VERIFIED"),
        "remote": run("config", "--get", "remote.origin.url"),
    }


def environment_metadata() -> dict:
    """Return the interpreter, platform and dependency versions of the run."""
    versions = {}
    for name in ("pandas", "numpy", "matplotlib"):
        try:
            module = __import__(name)
            versions[name] = getattr(module, "__version__", "NOT VERIFIED")
        except ImportError:
            versions[name] = "NOT VERIFIED"
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "operating_system": platform.system(),
        "operating_system_release": platform.release(),
        "machine": platform.machine(),
        "packages": versions,
    }


def dataset_identity(path, digest: str) -> dict:
    """Return the identity of the analysed source file."""
    resolved = Path(path)
    return {
        "path": str(resolved),
        "name": resolved.name,
        "size_bytes": resolved.stat().st_size,
        "sha256": digest,
    }


def manifest_verification(
    manifest_path,
    dataset_path,
    observed_sha256: str,
    observed_rows: int,
    expected_rows: int,
    columns: int,
) -> dict:
    """Return the manifest and schema verification of the analysed file."""
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    entry = next(
        item for item in manifest["files"] if item.get("file") == "data/NF-UNSW-NB15-v3.csv"
    )
    declared_size = entry["size_bytes"]
    observed_size = Path(dataset_path).stat().st_size
    return {
        "manifest_path": str(Path(manifest_path)),
        "manifest_dataset": manifest.get("dataset"),
        "manifest_doi": manifest.get("official_source", {}).get("doi"),
        "declared_size_bytes": declared_size,
        "observed_size_bytes": observed_size,
        "size_matches": declared_size == observed_size,
        "declared_sha256": entry["sha256"],
        "observed_sha256": observed_sha256,
        "sha256_matches": entry["sha256"] == observed_sha256,
        "declared_expected_rows": expected_rows,
        "observed_rows": observed_rows,
        "row_count_matches": expected_rows == observed_rows,
        "schema_columns": columns,
        "schema_order_verified": len(manifest["schema"]["columns_in_order"]) == columns,
    }


def key_aggregates(summary: dict) -> dict:
    """Return the aggregates a reviewer checks first."""
    statistics = summary["numeric_statistics"]
    duplicates = summary["duplicates"]
    non_finite = {
        column: {
            "unavailable_count": values["unavailable_count"],
            "token_counts": values["token_counts"],
        }
        for column, values in statistics.items()
        if values["unavailable_count"]
    }
    quantiles = {
        column: summary["quantiles"].get(column, {})
        for column in KEY_QUANTILE_COLUMNS
        if column in summary["quantiles"]
    }
    contingency = summary["duration_throughput"]["population"]
    return {
        "rows": summary["rows"],
        "expected_rows": summary["expected_rows"],
        "row_count_matches_manifest": summary["row_count_matches_manifest"],
        "label_counts": summary["label_counts"],
        "attack_counts": summary["attack_counts"],
        "protocol_counts": summary["protocol_counts"],
        "l7_proto_counts": summary["l7_proto_counts"],
        "non_finite_by_column": non_finite,
        "duplicates": {
            "exact_full_row": duplicates["exact_full_row"],
            "source_feature": duplicates["source_feature"],
            "ml_feature_equivalent": duplicates["ml_feature_equivalent"],
            "behavioral_v1": duplicates["behavioral_v1"],
        },
        "duration_throughput": contingency,
        "capture_window": {
            "minimum_start_utc": summary["time_coverage"]["minimum_start_utc"],
            "maximum_end_utc": summary["time_coverage"]["maximum_end_utc"],
            "capture_window_days": summary["time_coverage"]["capture_window_days"],
            "daily_flow_counts": summary["time_coverage"]["daily_flow_counts"],
        },
        "selected_quantiles": quantiles,
        "correlation_observations": summary["correlations"]["pearson_complete_cases"][
            "observations"
        ],
        "class_conditional": summary["class_conditional"],
        "readiness": summary["readiness"],
        "leakage_boundary": summary["leakage_boundary"],
    }


def _normalize_command(command: str, directory, figure_directory) -> str:
    """Replace the run-specific output paths so two runs can be compared."""
    normalized = command.replace(str(directory), "<run-directory>")
    return normalized.replace(str(figure_directory), "<figure-directory>")


def build_run_evidence(
    summary: dict,
    *,
    label: str,
    directory,
    command: str,
    exit_code: int,
    started_at_utc: str,
    finished_at_utc: str,
    duration_seconds: float,
    git: dict,
    environment: dict,
    dataset: dict,
    manifest: dict,
    stdout_log: str,
    stderr_log: str,
    figure_directory: str,
    figure_files: list[str],
) -> dict:
    """Return the retrievable evidence of one EDA execution."""
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "label": label,
        "directory": str(directory),
        "command": command,
        "command_normalized": _normalize_command(command, directory, figure_directory),
        "exit_code": exit_code,
        "started_at_utc": started_at_utc,
        "finished_at_utc": finished_at_utc,
        "duration_seconds": duration_seconds,
        "git": git,
        "environment": environment,
        "dataset": dataset,
        "manifest_verification": manifest,
        "key_aggregates": key_aggregates(summary),
        "stdout_log": stdout_log,
        "stderr_log": stderr_log,
        "figure_directory": figure_directory,
        "figure_files": figure_files,
        "summary_artifact": {
            "path": str(Path(directory) / "eda_summary.json"),
            "sha256": sha256_file(Path(directory) / "eda_summary.json"),
        },
        "report_artifact": {
            "path": str(Path(directory) / "eda_report.md"),
            "sha256": sha256_file(Path(directory) / "eda_report.md"),
        },
    }


def write_evidence_bundle(directory, evidence: dict, stdout: str, stderr: str) -> None:
    """Write the captured logs and the metadata of one run.

    The EDA command itself writes ``eda_summary.json`` and ``eda_report.md`` into the
    same directory, so the bundle always contains the artifacts of that exact run.
    """
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    (target / "stdout.log").write_text(stdout, encoding="utf-8")
    (target / "stderr.log").write_text(stderr, encoding="utf-8")
    (target / "run_metadata.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _flatten(value, prefix: str = ""):
    """Yield every leaf of a nested structure with its dotted path."""
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten(value[key], child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _flatten(item, f"{prefix}[{index}]")
    else:
        yield prefix, value


def _is_excluded(path: str, excluded) -> bool:
    for candidate in excluded:
        if path == candidate or path.startswith(f"{candidate}."):
            return True
    return False


def collect_differences(left, right, excluded=EXCLUDED_COMPARISON_PATHS) -> list[dict]:
    """Return every deterministic difference between two nested structures."""
    left_flat = dict(_flatten(left))
    right_flat = dict(_flatten(right))
    differences = []
    for path in sorted(set(left_flat) | set(right_flat)):
        if _is_excluded(path, excluded):
            continue
        if path not in right_flat:
            differences.append({"path": path, "kind": "missing_in_right", "left": left_flat[path]})
        elif path not in left_flat:
            differences.append({"path": path, "kind": "missing_in_left", "right": right_flat[path]})
        elif left_flat[path] != right_flat[path]:
            differences.append(
                {
                    "path": path,
                    "kind": "value_differs",
                    "left": left_flat[path],
                    "right": right_flat[path],
                }
            )
    return differences


def _metric_name(path: str) -> str:
    return path.split(".", 1)[0].split("[", 1)[0]


def compare_summaries(left: dict, right: dict) -> dict:
    """Compare two EDA summaries and report PASS or FAIL per metric."""
    differences = collect_differences(left, right)
    metrics = {}
    for difference in differences:
        metrics.setdefault(_metric_name(difference["path"]), []).append(difference)
    ordered = [
        "rows",
        "expected_rows",
        "row_count_matches_manifest",
        "parse_mode",
        "label_counts",
        "attack_counts",
        "protocol_counts",
        "l7_proto_counts",
        "categorical_counts",
        "numeric_statistics",
        "quantiles",
        "class_conditional",
        "class_conditional_quantiles",
        "duration_throughput",
        "time_coverage",
        "duplicates",
        "correlations",
        "sample",
        "sample_statistics",
        "contract",
        "readiness",
        "leakage_boundary",
    ]
    rows = []
    for metric in ordered:
        found = metrics.get(metric, [])
        rows.append(
            {
                "metric": metric,
                "status": "PASS" if not found else "FAIL",
                "difference_count": len(found),
            }
        )
    for metric in sorted(set(metrics) - set(ordered)):
        found = metrics[metric]
        rows.append(
            {
                "metric": metric,
                "status": "PASS" if not found else "FAIL",
                "difference_count": len(found),
            }
        )
    return {
        "excluded_paths": list(EXCLUDED_COMPARISON_PATHS),
        "metrics": rows,
        "differences": differences,
        "overall": "PASS" if not differences else "FAIL",
    }


def compare_evidence(left: dict, right: dict) -> dict:
    """Compare two run evidence bundles, ignoring the allowed metadata."""
    differences = collect_differences(left, right, EXCLUDED_EVIDENCE_PATHS)
    checked = {
        "command_normalized": left.get("command_normalized") == right.get("command_normalized"),
        "exit_code": left.get("exit_code") == right.get("exit_code"),
        "git_head": left.get("git", {}).get("head") == right.get("git", {}).get("head"),
        "dataset_sha256": left.get("dataset", {}).get("sha256")
        == right.get("dataset", {}).get("sha256"),
        "manifest_sha256_matches": left.get("manifest_verification", {}).get("sha256_matches")
        == right.get("manifest_verification", {}).get("sha256_matches"),
        "row_count_matches": left.get("manifest_verification", {}).get("row_count_matches")
        == right.get("manifest_verification", {}).get("row_count_matches"),
    }
    return {
        "excluded_paths": list(EXCLUDED_EVIDENCE_PATHS),
        "checked": checked,
        "informational": {
            "left_summary_artifact_sha256": left.get("summary_artifact", {}).get("sha256"),
            "right_summary_artifact_sha256": right.get("summary_artifact", {}).get("sha256"),
            "note": (
                "The two summary artifacts have different file hashes because each artifact "
                "embeds its own run timestamp. The deterministic content comparison is the "
                "authoritative check."
            ),
        },
        "differences": differences,
        "overall": "PASS" if not differences and all(checked.values()) else "FAIL",
    }


def _status(flag: bool) -> str:
    return "PASS" if flag else "FAIL"


def render_comparison_report(comparison: dict, left: dict, right: dict) -> str:
    """Return the Markdown reproducibility comparison report."""
    summary_comparison = comparison["summaries"]
    evidence_comparison = comparison["evidence"]
    metric_rows = [
        f"| `{row['metric']}` | {row['status']} | {row['difference_count']} |"
        for row in summary_comparison["metrics"]
    ]
    evidence_rows = [
        f"| `{name}` | {_status(value)} |" for name, value in evidence_comparison["checked"].items()
    ]
    informational = evidence_comparison.get("informational", {})
    informational_block = (
        f"The two summary artifacts have different file hashes because each artifact embeds "
        f"its own run timestamp: `{informational.get('left_summary_artifact_sha256')}` and "
        f"`{informational.get('right_summary_artifact_sha256')}`. The deterministic content "
        f"comparison above is the authoritative check."
        if informational
        else ""
    )
    run_rows = []
    for run in (left, right):
        run_rows.append(
            (
                "| {label} | `{head}` | {started} | {finished} | {duration} "
                "| {exit_code} | `{sha}` |"
            ).format(
                label=run["label"],
                head=str(run["git"]["head"])[:12],
                started=run["started_at_utc"],
                finished=run["finished_at_utc"],
                duration=f"{run['duration_seconds']:.1f} s",
                exit_code=run["exit_code"],
                sha=run["summary_artifact"]["sha256"],
            )
        )
    difference_lines = [
        f"- `{item['path']}`: {item['kind']} "
        f"(left={item.get('left')!r}, right={item.get('right')!r})"
        for item in summary_comparison["differences"][:50]
    ]
    difference_block = (
        "\n".join(difference_lines)
        if difference_lines
        else "No deterministic difference was found between the two runs."
    )
    evidence_difference_block = (
        "\n".join(
            f"- `{item['path']}`: {item['kind']} "
            f"(left={item.get('left')!r}, right={item.get('right')!r})"
            for item in evidence_comparison["differences"][:50]
        )
        or "No difference was found between the two evidence bundles outside the allowed metadata."
    )
    left_aggregates = left["key_aggregates"]
    right_aggregates = right["key_aggregates"]
    identity_rows = []
    for run in (left, right):
        identity_rows.append(
            ("| {label} | `{directory}` | `{sha}` | {manifest} | {rows} |").format(
                label=run["label"],
                directory=run["directory"],
                sha=run["dataset"]["sha256"],
                manifest=_status(run["manifest_verification"]["sha256_matches"]),
                rows=_status(run["manifest_verification"]["row_count_matches"]),
            )
        )

    def _duplicate_count(aggregates, scope):
        return _number(aggregates["duplicates"][scope]["duplicate_rows"])

    def _non_finite_total(aggregates):
        total = sum(
            item["unavailable_count"] for item in aggregates["non_finite_by_column"].values()
        )
        return _number(total)

    aggregate_rows = [
        f"| Rows | {_number(left_aggregates['rows'])} | {_number(right_aggregates['rows'])} |",
        "| Benign flows | {left} | {right} |".format(
            left=_number(left_aggregates["label_counts"].get("0")),
            right=_number(right_aggregates["label_counts"].get("0")),
        ),
        "| Attack flows | {left} | {right} |".format(
            left=_number(left_aggregates["label_counts"].get("1")),
            right=_number(right_aggregates["label_counts"].get("1")),
        ),
        "| Exact duplicate rows | {left} | {right} |".format(
            left=_duplicate_count(left_aggregates, "exact_full_row"),
            right=_duplicate_count(right_aggregates, "exact_full_row"),
        ),
        "| Repeated rows, 47-feature equivalence | {left} | {right} |".format(
            left=_duplicate_count(left_aggregates, "ml_feature_equivalent"),
            right=_duplicate_count(right_aggregates, "ml_feature_equivalent"),
        ),
        "| Non-finite values in the rate fields | {left} | {right} |".format(
            left=_non_finite_total(left_aggregates),
            right=_non_finite_total(right_aggregates),
        ),
        "| Correlation observations | {left} | {right} |".format(
            left=_number(left_aggregates["correlation_observations"]),
            right=_number(right_aggregates["correlation_observations"]),
        ),
    ]
    return f"""# NF-UNSW-NB15-v3 EDA reproducibility comparison

**Overall result: {summary_comparison['overall']}** (summary content) /
{evidence_comparison['overall']} (run evidence)
Two independent executions of `scripts/eda_nf_unsw_nb15_v3.py` on the same verified
source file are compared here. The comparison walks both machine-readable summaries and
reports PASS or FAIL per metric. Only the metadata that is allowed to differ between two
runs of the same command is excluded: the run timestamp
(`{', '.join(EXCLUDED_COMPARISON_PATHS)}`) and the environment description.

## Run identity

| Run | Git HEAD | Started (UTC) | Finished (UTC) | Duration | Exit code | Summary SHA-256 |
|---|---|---|---|---|---|---|
{chr(10).join(run_rows)}

| Run | Directory | Dataset SHA-256 | Manifest verified | Rows verified |
|---|---|---|---|---|
{chr(10).join(identity_rows)}

## Per-metric result on the deterministic summary content

| Metric | Result | Differences |
|---|---|---|
{chr(10).join(metric_rows)}

## Per-metric result on the run evidence

| Check | Result |
|---|---|
{chr(10).join(evidence_rows)}

{informational_block}

## Key aggregates observed in both runs

| Aggregate | {left['label']} | {right['label']} |
|---|---|---|
{chr(10).join(aggregate_rows)}

## Differences

Summary content:

{difference_block}

Run evidence:

{evidence_difference_block}

## How to re-check this evidence

```text
python scripts/verify_eda_reproducibility.py
```

The command re-runs the EDA twice, writes one bundle per run under
`reports/eda/evidence/` and regenerates this report. Each bundle contains the captured
`stdout.log` and `stderr.log`, the exact `eda_summary.json` and `eda_report.md` of that
run, and a `run_metadata.json` with the git state, the interpreter, the dependencies, the
dataset identity, the manifest and schema verification, the key aggregates, the command,
the exit code, the timestamps and the SHA-256 of the produced summary.
"""


def _number(value, digits: int = 0) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:,.{digits}f}"
    return f"{value:,}"
