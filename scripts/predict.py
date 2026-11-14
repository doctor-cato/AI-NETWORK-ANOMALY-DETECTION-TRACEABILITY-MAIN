#!/usr/bin/env python3
"""CLI entrypoint for NF-UNSW-NB15-v3 CSV Inference Pipeline.

Performs verified, reproducible inference on new network flows:
1. Validates input CSV existence, non-emptiness, and NF-UNSW-NB15-v3 contract.
2. Loads verified train-only preprocessing artifact from Issue #8 (fail-closed).
3. Loads verified model artifact with SHA-256 and companion manifest provenance.
4. Executes preprocessing transform and model prediction without refitting.
5. Exports predictions preserving input row identity.
6. Writes comprehensive traceability metadata JSON.

Usage:
    python scripts/predict.py --input data/new_flows.csv --output results/predictions.csv
    python scripts/predict.py --input data/new_flows.csv --output results/predictions.csv \\
        --model random_forest
    python scripts/predict.py --input data/new_flows.csv --output results/predictions.csv \\
        --model-artifact artifacts/models/random_forest/random_forest_baseline.joblib \\
        --model-manifest reports/models/random_forest_manifest.json

Exit codes:
    0: Inference completed successfully with output CSV and metadata generated.
    1: Runtime, schema validation, artifact missing, hash mismatch, or processing error.
    2: Command-line syntax error (handled by argparse).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from network_anomaly.inference import run_inference


def _resolve_model_paths(
    model_arg: Optional[str],
    model_artifact_arg: Optional[str],
    model_manifest_arg: Optional[str],
) -> Tuple[Path, Optional[Path]]:
    """Resolve model artifact and manifest paths based on CLI arguments."""
    # 1. Explicit --model-artifact takes highest priority
    if model_artifact_arg:
        model_artifact_path = Path(model_artifact_arg)
        model_manifest_path = Path(model_manifest_arg) if model_manifest_arg else None
        return model_artifact_path, model_manifest_path

    # 2. Inspect --model argument
    if model_arg:
        norm = model_arg.strip().lower()
        if norm in {"random_forest", "rf", "random-forest"}:
            artifact = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
            manifest = PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
            return artifact, manifest
        elif norm in {"isolation_forest", "if", "isolation-forest"}:
            artifact = ARTIFACTS / "models" / "isolation_forest" / "isolation_forest.joblib"
            manifest = PROJECT_ROOT / "reports" / "models" / "isolation_forest_manifest.json"
            return artifact, manifest
        elif Path(model_arg).suffix in {".joblib", ".pkl"}:
            artifact = Path(model_arg)
            manifest = Path(model_manifest_arg) if model_manifest_arg else None
            return artifact, manifest
        else:
            # Treat as path or custom model identifier
            artifact = Path(model_arg)
            manifest = Path(model_manifest_arg) if model_manifest_arg else None
            return artifact, manifest

    # 3. Default fallback is canonical Random Forest baseline
    default_artifact = ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
    default_manifest = PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
    return default_artifact, default_manifest


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="NF-UNSW-NB15-v3 CSV Network Flow Inference Pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        type=str,
        help="Path to input CSV file containing network flows to classify",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=True,
        type=str,
        help="Path where output predictions CSV will be written",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        default="random_forest",
        help="Model selector ('random_forest', 'isolation_forest', or path to model .joblib)",
    )
    parser.add_argument(
        "--model-artifact",
        type=str,
        default=None,
        help="Explicit path to model artifact .joblib file",
    )
    parser.add_argument(
        "--model-manifest",
        type=str,
        default=None,
        help="Explicit path to companion model manifest .json file",
    )
    parser.add_argument(
        "--preprocessor-artifact",
        "-p",
        type=str,
        default=str(ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"),
        help="Path to verified preprocessor artifact .joblib file",
    )
    parser.add_argument(
        "--preprocessor-manifest",
        type=str,
        default=str(
            PROJECT_ROOT
            / "reports"
            / "preprocessing"
            / "nf_unsw_nb15_v3_preprocessing_manifest.json"
        ),
        help="Path to preprocessor companion manifest .json file",
    )
    parser.add_argument(
        "--metadata-output",
        type=str,
        default=None,
        help="Optional path for metadata JSON output (defaults to <output_stem>.metadata.json)",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Optional custom run ID for traceability tracking",
    )
    parser.add_argument(
        "--eligibility-gate",
        action="store_true",
        help="Enable source and OOD eligibility checks before model prediction",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI main entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_path = Path(args.output)

    # 1. Early input check
    if not input_path.is_file():
        sys.stderr.write(f"Error: Input file does not exist at '{input_path}'\n")
        return 1

    if input_path.stat().st_size == 0:
        sys.stderr.write(f"Error: Input CSV file is empty (0 bytes) at '{input_path}'\n")
        return 1

    # 2. Resolve model artifact and manifest
    model_artifact_path, model_manifest_path = _resolve_model_paths(
        model_arg=args.model,
        model_artifact_arg=args.model_artifact,
        model_manifest_arg=args.model_manifest,
    )

    if not model_artifact_path.is_file():
        sys.stderr.write(
            f"Error: Model artifact not found at '{model_artifact_path}'. "
            "A trained model artifact is required for inference. "
            "To use an existing trained artifact, specify --model-artifact <path>.\n"
        )
        return 1

    # 3. Resolve preprocessor artifact and manifest
    prep_artifact_path = Path(args.preprocessor_artifact)
    prep_manifest_path = Path(args.preprocessor_manifest) if args.preprocessor_manifest else None

    if not prep_artifact_path.is_file():
        sys.stderr.write(
            f"Error: Preprocessor artifact not found at '{prep_artifact_path}'. "
            "Train-only preprocessing artifact from Issue #8 is required.\n"
        )
        return 1

    # 4. Execute inference pipeline
    try:
        gate = None
        if args.eligibility_gate:
            from network_anomaly.ingestion.gate import InferenceEligibilityGate

            gate = InferenceEligibilityGate()
        result = run_inference(
            input_path=input_path,
            output_path=output_path,
            model_artifact_path=model_artifact_path,
            preprocessor_artifact_path=prep_artifact_path,
            model_manifest_path=model_manifest_path,
            preprocessor_manifest_path=prep_manifest_path,
            metadata_path=args.metadata_output,
            eligibility_gate=gate,
            run_id=args.run_id,
        )
    except Exception as e:
        sys.stderr.write(f"Error during inference execution: {e}\n")
        return 1

    # Print success report
    status_label = "Success" if result.metadata["execution_status"] == "SUCCESS" else "ABSTAINED"
    print(
        f"[INFERENCE] {status_label}: "
        f"generated {result.metadata['prediction_count']} predictions.\n"
        f"  Input:    {result.metadata['input_file_path']} "
        f"({result.metadata['input_row_count']} rows)\n"
        f"  Output:   {result.metadata['output_file_path']}\n"
        f"  Metadata: {result.metadata_path}\n"
        f"  Run ID:   {result.metadata['run_id']}\n"
        f"  Model:    {result.metadata['model_type']} "
        f"(SHA-256: {result.metadata['model_artifact_sha256'][:16]}...)\n"
        f"  Prep:     SHA-256: {result.metadata['preprocessor_artifact_sha256'][:16]}..."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
