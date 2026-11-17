#!/usr/bin/env python3
"""Reproducible exploratory data analysis for the verified NF-UNSW-NB15-v3 CSV.

The script reuses the approved manifest contract and byte verification of
``scripts/validate_data.py`` instead of duplicating them, profiles the source
population in bounded memory and writes:

* ``reports/eda/nf_unsw_nb15_v3_eda_summary.json`` - machine-readable summary;
* ``docs/dataset/NF_UNSW_NB15_V3_EDA.md`` - the generated Markdown report;
* ``reports/figures/nf_unsw_nb15_v3/*.png`` - labelled figures (not committed).

Exit codes:
  0 - EDA completed on the real file, or was intentionally skipped because the
      raw package is absent. A skip is not a result.
  2 - source-integrity failure or an unexpected execution error.

The analysis never fits a transformer, never selects features, never removes a
row and never changes the readiness gates: ``ML_READY`` stays ``BLOCKED`` until
Issue #7 provides a verified split and Issue #8 provides a train-only fitted
preprocessing artifact.
"""

import argparse
import importlib.util
import json
import os
import platform
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    # Prefer this checkout over any editable install of the same package name.
    sys.path.insert(0, str(LOCAL_SOURCE))

from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
    validate_semantic_column_roles,
)
from network_anomaly.eda import (  # noqa: E402
    EDA_SCHEMA_VERSION,
    DatasetProfiler,
    render_figures,
    render_report,
)

DEFAULT_DATASET = PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json"
DEFAULT_VALIDATION_REPORT = (
    PROJECT_ROOT / "reports" / "data_quality" / "nf_unsw_nb15_v3_validation.json"
)
DEFAULT_SUMMARY = PROJECT_ROOT / "reports" / "eda" / "nf_unsw_nb15_v3_eda_summary.json"
DEFAULT_REPORT = PROJECT_ROOT / "docs" / "dataset" / "NF_UNSW_NB15_V3_EDA.md"
DEFAULT_FIGURES = PROJECT_ROOT / "reports" / "figures" / "nf_unsw_nb15_v3"
SPLIT_MANIFEST_PATH = PROJECT_ROOT / "data" / "processed" / "nf_unsw_nb15_v3_split_manifest.json"
SKIPPED_MESSAGE = (
    "NF-UNSW-NB15-v3 bytes are absent; the EDA is SKIPPED, not executed. "
    "Run python scripts/fetch_nf_unsw_nb15_v3.py first."
)
EXIT_OK = 0
EXIT_FAILURE = 2


def load_validator_module():
    """Load the approved validator so its manifest contract is reused, not copied."""
    path = PROJECT_ROOT / "scripts" / "validate_data.py"
    spec = importlib.util.spec_from_file_location("validate_data", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def split_manifest_status(path: Path) -> dict:
    """Report whether a verified split manifest exists, without creating one."""
    if not path.is_file():
        return {
            "present": False,
            "path": display_path(path),
            "status": "PENDING ISSUE #7",
            "detail": (
                "No verified train/validation/test split manifest exists. Train-dependent "
                "analysis must not be performed and no split may be created to bypass "
                "Issue #7."
            ),
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {
            "present": True,
            "path": display_path(path),
            "status": "PENDING ISSUE #7",
            "detail": f"Split manifest could not be read: {error}",
        }
    return {
        "present": True,
        "path": display_path(path),
        "status": "PENDING ISSUE #7",
        "detail": (
            "A split manifest file exists but it has not been validated by the Issue #7 "
            "leakage audit, so no train partition may be used for design decisions."
        ),
        "keys": sorted(payload)[:20],
    }


def inherited_evidence(path: Path, digest: str) -> dict:
    """Load the verified quality report of the migration as inherited evidence."""
    status = {
        "report": display_path(path),
        "available": False,
        "dataset_sha256": None,
        "sha256_matches": False,
        "inherited_rows": None,
        "inherited_benign": None,
        "inherited_attack": None,
        "inherited_exact_duplicates": None,
        "inherited_repeated_rows": None,
    }
    if not path.is_file():
        status["detail"] = "No inherited quality report is available."
        return status
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        status["detail"] = f"Inherited quality report could not be read: {error}"
        return status
    labels = payload.get("labels", {})
    duplicates = payload.get("duplicate_analysis", {})
    status.update(
        {
            "available": True,
            "dataset_sha256": payload.get("dataset_sha256"),
            "sha256_matches": payload.get("dataset_sha256") == digest,
            "inherited_rows": payload.get("rows"),
            "inherited_benign": labels.get("0"),
            "inherited_attack": labels.get("1"),
            "inherited_exact_duplicates": duplicates.get("exact", {}).get("duplicate_rows"),
            "inherited_repeated_rows": duplicates.get("ml_feature_equivalent", {}).get(
                "duplicate_rows"
            ),
        }
    )
    return status


def build_leakage_boundary() -> dict:
    """Describe the analysis boundary that the missing split imposes."""
    return {
        "split_manifest": split_manifest_status(SPLIT_MANIFEST_PATH),
        "permitted_now": [
            "Full-dataset source profiling of the verified population.",
            "Data quality audits that do not modify the source bytes.",
            "Descriptive label and attack-category distributions.",
            "Clearly labelled exploratory visualisations.",
        ],
        "not_permitted_now": [
            "Selecting final ML features with held-out or test labels.",
            "Fitting imputers, encoders, scalers or selectors on the full dataset.",
            "Choosing thresholds or hyper-parameters with test information.",
            "Claiming that cross-split leakage has been verified.",
            "Creating an undocumented random split to bypass Issue #7.",
            "Automatic de-duplication or label-dependent row filtering.",
        ],
        "train_dependent_recommendations": "PENDING ISSUE #7",
        "target_columns_in_baseline_x": bool(set(TARGET_COLUMNS) & set(ML_FEATURE_COLUMNS)),
        "metadata_columns_in_baseline_x": bool(
            set(TRACE_METADATA_COLUMNS) & set(ML_FEATURE_COLUMNS)
        ),
    }


def build_readiness(analysis: dict, source_integrity: str) -> dict:
    """Derive the three independent gates from the executed analysis."""
    quality_findings = [
        f"{column}: {values['unavailable_count']} non-finite values"
        for column, values in analysis["numeric_statistics"].items()
        if values["unavailable_count"]
    ]
    duplicates = analysis["duplicates"]
    if duplicates["exact_full_row"]["duplicate_rows"]:
        quality_findings.append(
            f"exact duplicate rows: {duplicates['exact_full_row']['duplicate_rows']}"
        )
    if duplicates["ml_feature_equivalent"]["duplicate_rows"]:
        quality_findings.append(
            "repeated rows under 47-feature equivalence: "
            f"{duplicates['ml_feature_equivalent']['duplicate_rows']}"
        )
    blockers = [
        "real split and leakage audit are NOT VERIFIED (Issue #7)",
        "train-only fitted preprocessing artifact is NOT VERIFIED (Issue #8)",
    ]
    if quality_findings:
        blockers.insert(0, "raw quality findings require an approved train-only handling policy")
    return {
        "SOURCE_INTEGRITY": source_integrity,
        "RAW_QUALITY": "FINDINGS_RECORDED" if quality_findings else "PASS",
        "ML_READY": "BLOCKED",
        "raw_quality_findings": quality_findings,
        "ml_readiness_blockers": blockers,
    }


def write_text(path: Path, content: str) -> None:
    """Write a text artifact atomically where the filesystem allows it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f"{path.name}.{os.getpid()}.partial")
    try:
        staged.write_text(content, encoding="utf-8")
        os.replace(staged, path)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def display_path(path: Path) -> str:
    """Return a repository-relative path when possible, otherwise the absolute one."""
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def main(argv=None):
    """Run the EDA and write the summary, the report and the figures."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--validation-report", type=Path, default=DEFAULT_VALIDATION_REPORT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--figures", type=Path, default=DEFAULT_FIGURES)
    parser.add_argument("--chunk-size", type=int, default=100_000)
    parser.add_argument("--sample-size", type=int, default=200_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-rows", type=int)
    parser.add_argument("--skip-figures", action="store_true")
    parser.add_argument(
        "--no-byte-verification",
        action="store_true",
        help="Skip the source SHA-256 check; the result is then not source-verified.",
    )
    args = parser.parse_args(argv)

    if not args.dataset.is_file():
        print(f"[eda_nf_unsw_nb15_v3] EDA: SKIPPED - {SKIPPED_MESSAGE}")
        print("[eda_nf_unsw_nb15_v3] SOURCE_INTEGRITY: SKIPPED")
        print("[eda_nf_unsw_nb15_v3] RAW_QUALITY: NOT VERIFIED")
        print("[eda_nf_unsw_nb15_v3] ML_READY: BLOCKED")
        if os.getenv("GITHUB_ACTIONS") == "true":
            print(f"::warning::{SKIPPED_MESSAGE}")
        return EXIT_OK

    try:
        validator = load_validator_module()
        _manifest, columns, entry = validator.load_contract(args.manifest)
        digest = None
        if not args.no_byte_verification:
            digest = validator.verify_dataset_bytes(args.dataset, entry)
        validate_feature_selection(ML_FEATURE_COLUMNS)
        validate_semantic_column_roles()
        profiler = DatasetProfiler(
            columns=columns,
            expected_rows=entry["expected_rows"],
            chunk_size=args.chunk_size,
            sample_size=args.sample_size,
            seed=args.seed,
            max_rows=args.max_rows,
        )
        analysis = profiler.profile(args.dataset)
        inherited = inherited_evidence(args.validation_report, digest)
        duplicates = analysis["duplicates"]
        labels = analysis["label_counts"]
        evidence_basis = {
            "real_data_executed": True,
            "source_sha256_verified": not args.no_byte_verification,
            "inherited_report": inherited["report"],
            "inherited_report_available": inherited["available"],
            "inherited_sha256_matches": inherited["sha256_matches"],
            "inherited_rows": inherited["inherited_rows"],
            "inherited_benign": inherited["inherited_benign"],
            "inherited_attack": inherited["inherited_attack"],
            "inherited_exact_duplicates": inherited["inherited_exact_duplicates"],
            "inherited_repeated_rows": inherited["inherited_repeated_rows"],
            "recomputed_rows": analysis["rows"],
            "recomputed_benign": labels.get("0"),
            "recomputed_attack": labels.get("1"),
            "recomputed_exact_duplicates": duplicates["exact_full_row"]["duplicate_rows"],
            "recomputed_repeated_rows": duplicates["ml_feature_equivalent"]["duplicate_rows"],
            "rows_agreement": _agreement(inherited["inherited_rows"], analysis["rows"]),
            "labels_agreement": _agreement(
                (inherited["inherited_benign"], inherited["inherited_attack"]),
                (labels.get("0"), labels.get("1")),
            ),
            "duplicates_agreement": _agreement(
                (inherited["inherited_exact_duplicates"], inherited["inherited_repeated_rows"]),
                (
                    duplicates["exact_full_row"]["duplicate_rows"],
                    duplicates["ml_feature_equivalent"]["duplicate_rows"],
                ),
            ),
        }
        readiness = build_readiness(
            analysis, "PASS" if not args.no_byte_verification else "NOT VERIFIED"
        )
        figures = []
        if not args.skip_figures:
            figures = render_figures(analysis, profiler.sample, args.figures)
        document = {
            **analysis,
            "tool": {
                "script": "scripts/eda_nf_unsw_nb15_v3.py",
                "schema_version": EDA_SCHEMA_VERSION,
                "python": platform.python_version(),
                "platform": platform.platform(),
                "pandas": __import__("pandas").__version__,
                "numpy": __import__("numpy").__version__,
                "seed": args.seed,
            },
            "dataset": {
                "name": "NF-UNSW-NB15-v3",
                "path": display_path(args.dataset),
                "size_bytes": args.dataset.stat().st_size,
                "sha256": digest,
                "manifest": display_path(args.manifest),
                "doi": "10.48610/6E0EDA1",
            },
            "contract": {
                "baseline_ml_features": list(ML_FEATURE_COLUMNS),
                "trace_metadata_columns": list(TRACE_METADATA_COLUMNS),
                "target_columns": list(TARGET_COLUMNS),
                "categorical_coded_columns": list(CATEGORICAL_CODED_COLUMNS),
                "quantitative_columns": list(QUANTITATIVE_ML_COLUMNS),
            },
            "evidence_basis": evidence_basis,
            "readiness": readiness,
            "leakage_boundary": build_leakage_boundary(),
            "figures": figures,
        }
        context = {
            "dataset": document["dataset"],
            "readiness": readiness,
            "leakage_boundary": document["leakage_boundary"],
            "evidence_basis": evidence_basis,
            "environment": (
                f"Python {platform.python_version()} on {platform.system()} "
                f"{platform.release()}, pandas {document['tool']['pandas']}, "
                f"numpy {document['tool']['numpy']}"
            ),
        }
        report = render_report(document, figures, context)
        write_text(args.summary, json.dumps(document, indent=2, sort_keys=True) + "\n")
        write_text(args.report, report)
        print(f"[eda_nf_unsw_nb15_v3] SOURCE_INTEGRITY: {readiness['SOURCE_INTEGRITY']}")
        print(f"[eda_nf_unsw_nb15_v3] RAW_QUALITY: {readiness['RAW_QUALITY']}")
        print(f"[eda_nf_unsw_nb15_v3] ML_READY: {readiness['ML_READY']}")
        print(
            f"[eda_nf_unsw_nb15_v3] EDA: COMPLETE rows={analysis['rows']} "
            f"summary={args.summary} report={args.report} figures={args.figures}"
        )
        return EXIT_OK
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print("[eda_nf_unsw_nb15_v3] EDA: FAILED")
        print("[eda_nf_unsw_nb15_v3] SOURCE_INTEGRITY: FAIL")
        print("[eda_nf_unsw_nb15_v3] RAW_QUALITY: NOT EVALUATED")
        print("[eda_nf_unsw_nb15_v3] ML_READY: BLOCKED")
        print(f"[eda_nf_unsw_nb15_v3] ERROR: {error}")
        return EXIT_FAILURE


def _agreement(inherited, recomputed) -> str:
    if inherited is None or recomputed is None:
        return "NOT VERIFIED"
    if isinstance(inherited, tuple) or isinstance(recomputed, tuple):
        inherited = tuple(inherited or ())
        recomputed = tuple(recomputed or ())
        if None in inherited or None in recomputed:
            return "NOT VERIFIED"
        return "MATCH" if inherited == recomputed else "DIFFERENT"
    return "MATCH" if inherited == recomputed else "DIFFERENT"


if __name__ == "__main__":
    raise SystemExit(main())
