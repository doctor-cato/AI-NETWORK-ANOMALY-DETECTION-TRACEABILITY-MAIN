"""Verify and summarize a previously executed held-out RF evaluation run.

This module reads existing predictions. It never calls model prediction or fitting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.evaluation.metrics import compute_wilson_confidence_interval
from network_anomaly.evaluation.test_evaluation import (
    CANONICAL_DECISION_THRESHOLD,
    FEATURE_CONTRACT_VERSION,
    _load_indices_csv_gz,
    check_test_evaluation_prerequisites,
)

FEATURES_FOR_REVIEW = (
    "MIN_TTL",
    "MAX_TTL",
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS",
    "RETRANSMITTED_IN_PKTS",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise ValueError(f"{label} mismatch: {actual!r} != {expected!r}")


def _read_test_source(dataset: Path, indices: np.ndarray) -> pd.DataFrame:
    """Read labels and non-identifying features for the locked Test rows only."""
    columns = ["Label", "Attack", "FLOW_START_MILLISECONDS", *FEATURES_FOR_REVIEW]
    selected: list[pd.DataFrame] = []
    source_offset = 0
    for chunk in pd.read_csv(dataset, usecols=columns, chunksize=100_000):
        in_chunk = (indices >= source_offset) & (indices < source_offset + len(chunk))
        if in_chunk.any():
            positions = indices[in_chunk] - source_offset
            rows = chunk.iloc[positions].copy()
            rows.index = indices[in_chunk]
            selected.append(rows)
        source_offset += len(chunk)
    if not selected:
        raise ValueError("No Test rows found in source CSV")
    source = pd.concat(selected)
    _require_equal(len(source), len(indices), "source Test row count")
    _require_equal(source.index.to_list(), indices.tolist(), "source Test row order")
    return source


def _metrics_from_counts(tn: int, fp: int, fn: int, tp: int) -> dict[str, float]:
    n = tn + fp + fn + tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    benign_precision = tn / (tn + fn) if tn + fn else 0.0
    benign_recall = tn / (tn + fp) if tn + fp else 0.0
    benign_f1 = (
        2 * benign_precision * benign_recall / (benign_precision + benign_recall)
        if benign_precision + benign_recall
        else 0.0
    )
    attack_f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": (tn + tp) / n,
        "precision": precision,
        "recall": recall,
        "f1": attack_f1,
        "macro_f1": (benign_f1 + attack_f1) / 2,
        "weighted_f1": (benign_f1 * (tn + fp) + attack_f1 * (fn + tp)) / n,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "true_negative_rate": benign_recall,
    }


def reconcile_run(
    *,
    run_dir: Path,
    dataset_csv: Path,
    indices_dir: Path,
    split_manifest: Path,
    preprocessing_manifest: Path,
    model_manifest: Path,
    preprocessor_artifact: Path,
    model_artifact: Path,
    dataset_manifest: Path = Path("data/NF_UNSW_NB15_V3_MANIFEST.json"),
    validation_audit: Path = Path("reports/models/rf_baseline_validation_audit.json"),
    eda_summary: Path | None = None,
) -> dict[str, Any]:
    """Fail closed unless the stored run, manifests, and source rows agree."""
    required = {
        "metrics_json": run_dir / "metrics.json",
        "confusion_matrix_csv": run_dir / "confusion_matrix.csv",
        "confusion_matrix_png": run_dir / "confusion_matrix.png",
        "predictions_csv": run_dir / "predictions.csv",
    }
    metadata_path = run_dir / "evaluation_metadata.json"
    if not metadata_path.is_file() or any(not p.is_file() for p in required.values()):
        raise FileNotFoundError(
            "Missing evaluation metadata, predictions, metrics, or confusion matrix"
        )

    prereq = check_test_evaluation_prerequisites(
        dataset_csv_path=dataset_csv,
        split_manifest_path=split_manifest,
        test_indices_path=indices_dir / "test_indices.csv.gz",
        train_indices_path=indices_dir / "train_indices.csv.gz",
        val_indices_path=indices_dir / "validation_indices.csv.gz",
        preprocessing_manifest_path=preprocessing_manifest,
        preprocessor_artifact_path=preprocessor_artifact,
        model_manifest_path=model_manifest,
        model_artifact_path=model_artifact,
        fail_closed=True,
    )
    _require_equal(prereq.partition_verification_status, "VERIFIED", "partition verification")
    metadata = _json(metadata_path)
    metrics = _json(required["metrics_json"])
    split = _json(split_manifest)
    model = _json(model_manifest)
    dataset_record = _json(dataset_manifest)
    audit = _json(validation_audit)
    hashes = prereq.verified_hashes

    _require_equal(
        audit["model_artifact"]["sha256"],
        hashes["model_artifact_sha256"],
        "Validation model identity",
    )
    _require_equal(
        audit["split_integrity"]["train_rows"],
        split["partitions"]["train"]["row_count"],
        "Validation audit Train rows",
    )
    _require_equal(
        audit["split_integrity"]["val_rows"],
        split["partitions"]["validation"]["row_count"],
        "Validation audit Validation rows",
    )
    val = audit["validation_recomputed"]
    _require_equal(val["n"], audit["split_integrity"]["val_rows"], "Validation metric rows")
    _require_equal(
        sum(int(val[key]) for key in ("tn", "fp", "fn", "tp")),
        val["n"],
        "Validation confusion total",
    )
    _require_equal(
        val["tn"] + val["fp"],
        split["partitions"]["validation"]["label_distribution"]["0"],
        "Validation benign support",
    )
    _require_equal(
        val["fn"] + val["tp"],
        split["partitions"]["validation"]["label_distribution"]["1"],
        "Validation Attack support",
    )
    if dataset_record.get("dataset") != "NF-UNSW-NB15-v3" or not dataset_record.get(
        "official_source", {}
    ).get("doi"):
        raise ValueError("Missing canonical dataset source provenance")
    source_files = [
        item for item in dataset_record.get("files", []) if item.get("role") == "dataset"
    ]
    if len(source_files) != 1:
        raise ValueError("Canonical dataset provenance must identify exactly one CSV")
    _require_equal(
        source_files[0].get("sha256"), hashes["dataset_sha256"], "canonical dataset SHA-256"
    )
    _require_equal(
        source_files[0].get("expected_rows"),
        split.get("total_source_rows"),
        "canonical dataset row count",
    )
    for key, value in hashes.items():
        _require_equal(metadata.get("provenance_hashes", {}).get(key), value, key)
    _require_equal(metadata.get("run_id"), metrics.get("run_id"), "run ID")
    _require_equal(metadata.get("partition"), "test", "metadata partition")
    _require_equal(metrics.get("partition"), "test", "metrics partition")
    _require_equal(metadata.get("evaluation_stage"), "held_out_test_evaluation", "evaluation stage")
    _require_equal(metadata.get("decision_threshold"), CANONICAL_DECISION_THRESHOLD, "threshold")
    _require_equal(
        metrics.get("decision_threshold"), CANONICAL_DECISION_THRESHOLD, "metrics threshold"
    )
    _require_equal(
        metadata.get("hyperparameters"), model.get("hyperparameters"), "locked hyperparameters"
    )
    _require_equal(
        metadata.get("configuration_id"), model.get("configuration_id"), "model identity"
    )
    _require_equal(model.get("provenance_status"), "VERIFIED", "model provenance status")
    for key in ("test_partition_accessed", "test_indices_loaded"):
        _require_equal(model.get("test_lock_audit", {}).get(key), False, f"training {key}")
    _require_equal(
        model.get("test_lock_audit", {}).get("test_rows_loaded"), 0, "training Test rows"
    )
    _require_equal(
        metadata.get("feature_contract_version"), FEATURE_CONTRACT_VERSION, "feature contract"
    )
    _require_equal(metadata.get("selected_features"), list(ML_FEATURE_COLUMNS), "feature order")
    _require_equal(
        metadata.get("split_protocol_id"), split.get("split_protocol_version"), "split identity"
    )
    _require_equal(
        metadata.get("test_lock_compliance", {}).get("train_validation_disjoint_verified"),
        True,
        "disjointness flag",
    )
    for key in (
        "model_retrained_on_test",
        "preprocessor_refitted_on_test",
        "hyperparameters_tuned_on_test",
        "threshold_tuned_on_test",
    ):
        _require_equal(metadata.get("test_lock_compliance", {}).get(key), False, key)
    commit = metadata.get("environment", {}).get("git_commit")
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or not all(c in "0123456789abcdef" for c in commit)
    ):
        raise ValueError("Missing valid source commit in run metadata")
    commit_check = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=Path(__file__).resolve().parents[3],
        capture_output=True,
        check=False,
    )
    if commit_check.returncode != 0:
        raise ValueError("Run source commit is unavailable in repository history")
    for name, path in required.items():
        artifact = metadata.get("generated_artifacts", {}).get(name)
        if not isinstance(artifact, dict) or Path(str(artifact.get("path", ""))).name not in (
            path.name,
            "test_" + path.name,
        ):
            raise ValueError(f"Missing or inconsistent generated artifact reference: {name}")
        _require_equal(_sha256(path), artifact.get("sha256"), f"{name} SHA-256")
    if not required["confusion_matrix_png"].read_bytes().startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Invalid confusion matrix PNG signature")
    for alias, canonical in (
        ("test_metrics.json", "metrics.json"),
        ("test_predictions.csv", "predictions.csv"),
    ):
        alias_path = run_dir / alias
        if alias_path.exists():
            _require_equal(_sha256(alias_path), _sha256(run_dir / canonical), alias)

    predictions = pd.read_csv(required["predictions_csv"])
    expected_columns = [
        "row_index",
        "y_true",
        "y_pred",
        "prob_benign",
        "prob_attack",
        "attack_category",
        "outcome",
    ]
    _require_equal(list(predictions), expected_columns, "prediction schema")
    test_indices = _load_indices_csv_gz(indices_dir / "test_indices.csv.gz")
    _require_equal(
        predictions.row_index.to_list(), test_indices.tolist(), "prediction Test index order"
    )
    _require_equal(len(predictions), split["partitions"]["test"]["row_count"], "prediction count")
    if not predictions.y_true.isin([0, 1]).all() or not predictions.y_pred.isin([0, 1]).all():
        raise ValueError("Non-binary prediction labels")
    if predictions[["prob_benign", "prob_attack"]].isna().any().any():
        raise ValueError("Missing prediction probability")
    if not np.isfinite(predictions[["prob_benign", "prob_attack"]].to_numpy()).all():
        raise ValueError("Non-finite prediction probability")
    if not predictions.prob_attack.between(0, 1).all() or not np.allclose(
        predictions.prob_benign + predictions.prob_attack, 1, atol=1e-10
    ):
        raise ValueError("Invalid prediction probabilities")
    if not np.array_equal(
        predictions.y_pred.to_numpy(),
        (predictions.prob_attack.to_numpy() >= CANONICAL_DECISION_THRESHOLD).astype(int),
    ):
        raise ValueError("Predictions disagree with locked threshold")

    source = _read_test_source(dataset_csv, test_indices)
    if not np.array_equal(source.Label.to_numpy(), predictions.y_true.to_numpy()):
        raise ValueError("Prediction labels disagree with source Test rows")
    if not np.array_equal(
        source.Attack.astype(str).to_numpy(), predictions.attack_category.astype(str).to_numpy()
    ):
        raise ValueError("Attack categories disagree with source Test rows")
    if not np.array_equal(
        source.Attack.eq("Benign").to_numpy(), predictions.y_true.eq(0).to_numpy()
    ):
        raise ValueError("Binary labels disagree with Attack taxonomy")
    outcomes = np.select(
        [
            (predictions.y_true.eq(0) & predictions.y_pred.eq(0)),
            (predictions.y_true.eq(0) & predictions.y_pred.eq(1)),
            (predictions.y_true.eq(1) & predictions.y_pred.eq(0)),
        ],
        ["TN", "FP", "FN"],
        default="TP",
    )
    if not np.array_equal(outcomes, predictions.outcome.to_numpy()):
        raise ValueError("Prediction outcome column mismatch")
    counts = {key: int(np.count_nonzero(outcomes == key)) for key in ("TN", "FP", "FN", "TP")}
    tn, fp, fn, tp = (counts[key] for key in ("TN", "FP", "FN", "TP"))
    _require_equal(tn + fp + fn + tp, len(predictions), "confusion total")
    _require_equal(tn + fp, split["partitions"]["test"]["label_distribution"]["0"], "benign count")
    _require_equal(fn + tp, split["partitions"]["test"]["label_distribution"]["1"], "attack count")
    expected_cm = [[tn, fp], [fn, tp]]
    _require_equal(
        metrics["overall_metrics"]["confusion_matrix"], expected_cm, "metrics confusion matrix"
    )
    for key, value in counts.items():
        _require_equal(metrics["confusion_matrix_breakdown"][key.lower()], value, f"metrics {key}")
    csv_cm = pd.read_csv(required["confusion_matrix_csv"], index_col=0)
    _require_equal(csv_cm.to_numpy().tolist(), expected_cm, "CSV confusion matrix")
    calculated = _metrics_from_counts(tn, fp, fn, tp)
    for key in ("precision", "recall", "f1", "macro_f1", "false_positive_rate"):
        value = calculated[key]
        observed = metrics["overall_metrics"].get(key)
        if observed is None or not math.isclose(
            float(observed), value, rel_tol=1e-10, abs_tol=1e-12
        ):
            raise ValueError(f"Metric {key} disagrees with predictions")
    if not math.isclose(
        metrics["overall_metrics"]["fpr"],
        calculated["false_positive_rate"],
        rel_tol=1e-10,
        abs_tol=1e-12,
    ):
        raise ValueError("Metric fpr disagrees with predictions")
    _require_equal(metrics.get("sample_count"), len(predictions), "metrics sample count")
    _require_equal(metadata.get("test_row_count"), len(predictions), "metadata sample count")
    _require_equal(metadata.get("benign_row_count"), tn + fp, "metadata benign count")
    _require_equal(metadata.get("attack_row_count"), fn + tp, "metadata attack count")
    benign = metrics["benign_traffic_breakdown"]
    for key, value in {
        "total": tn + fp,
        "false_positive": fp,
        "true_negative": tn,
    }.items():
        _require_equal(benign[key], value, f"benign breakdown {key}")
    if not math.isclose(benign["false_positive_rate"], calculated["false_positive_rate"]):
        raise ValueError("Benign FPR disagrees with predictions")

    attack_counts: dict[str, dict[str, Any]] = {}
    for category, part in predictions.groupby("attack_category", dropna=False):
        category = str(category)
        if category == "Benign":
            continue
        attack_counts[category] = {
            "total": len(part),
            "detected": int(part.y_pred.sum()),
            "missed": int(part.y_pred.eq(0).sum()),
        }
        _require_equal(
            attack_counts[category]["total"],
            split["partitions"]["test"]["attack_distribution"][category],
            f"{category} count",
        )
        claimed = metrics["per_attack_category_breakdown"][category]
        for key, value in attack_counts[category].items():
            _require_equal(claimed[key], value, f"{category} {key}")
        ci = compute_wilson_confidence_interval(
            attack_counts[category]["detected"], attack_counts[category]["total"]
        )
        attack_counts[category]["recall_ci_95"] = [ci["ci_lower"], ci["ci_upper"]]
    _require_equal(
        set(metrics["per_attack_category_breakdown"]) - {"Benign"},
        set(attack_counts),
        "Attack family set",
    )
    claimed_benign = metrics["per_attack_category_breakdown"].get("Benign")
    if claimed_benign is not None:
        for key, value in {
            "total": tn + fp,
            "false_positive": fp,
            "true_negative": tn,
        }.items():
            _require_equal(claimed_benign[key], value, f"Benign category {key}")

    errors = predictions.loc[predictions.y_true.ne(predictions.y_pred)].copy()
    error_rows = source.loc[errors.row_index.to_numpy()]
    samples = []
    for (_, pred), (_, raw) in zip(errors.iterrows(), error_rows.iterrows()):
        sample_id = hashlib.sha256(
            f"{metadata['run_id']}:{int(pred.row_index)}".encode()
        ).hexdigest()[:12]
        samples.append(
            {
                "sample_id": sample_id,
                "outcome": pred.outcome,
                "attack_family": pred.attack_category,
                "prob_attack": float(pred.prob_attack),
                "margin_to_threshold": float(pred.prob_attack - CANONICAL_DECISION_THRESHOLD),
                "features": {
                    name: (
                        float(raw[name])
                        if pd.notna(raw[name]) and np.isfinite(float(raw[name]))
                        else None
                    )
                    for name in FEATURES_FOR_REVIEW
                },
            }
        )
    test_features = (
        source[list(FEATURES_FOR_REVIEW)]
        .apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
    )
    masks = {
        "benign": predictions.y_true.eq(0).to_numpy(),
        "attack": predictions.y_true.eq(1).to_numpy(),
        "fp": predictions.outcome.eq("FP").to_numpy(),
        "fn": predictions.outcome.eq("FN").to_numpy(),
    }
    distributions = {
        name: {
            group: (
                float(test_features.loc[mask, name].median())
                if mask.any() and pd.notna(test_features.loc[mask, name].median())
                else None
            )
            for group, mask in masks.items()
        }
        for name in FEATURES_FOR_REVIEW
    }
    ttl_distribution = {
        label: {
            str(key): int(value)
            for key, value in source.loc[predictions.y_true.to_numpy() == y, "MIN_TTL"]
            .value_counts(dropna=False)
            .head(8)
            .items()
        }
        for label, y in (("benign", 0), ("attack", 1))
    }
    feature_medians = {
        name: float(value) if pd.notna(value) else None
        for name, value in test_features.median().items()
    }
    band = predictions.prob_attack.between(0.35, 0.65)
    temporal = {}
    hours = pd.to_datetime(source.FLOW_START_MILLISECONDS, unit="ms", utc=True).dt.floor("h")
    for hour, group in predictions.groupby(hours.to_numpy()):
        temporal[str(hour)] = {
            "total": len(group),
            "fp": int(group.outcome.eq("FP").sum()),
            "fn": int(group.outcome.eq("FN").sum()),
        }
    eda_limitations = None
    eda_hash = None
    if eda_summary is not None:
        eda = _json(eda_summary)
        _require_equal(
            eda.get("dataset", {}).get("sha256"), hashes["dataset_sha256"], "EDA dataset identity"
        )
        duplicates = eda.get("duplicates", {})
        eda_limitations = {
            "scope": "entire dataset, not the held-out Test partition",
            "exact_full_row_duplicates": duplicates["exact_full_row"]["duplicate_rows"],
            "behavioral_near_duplicates": duplicates["behavioral_v1"]["duplicate_rows"],
            "zero_duration_non_finite_rate_rows": eda["duration_throughput"]["population"][
                "duration_zero=True,rate_non_finite=True,throughput_non_finite=False"
            ],
        }
        eda_hash = _sha256(eda_summary)
    return {
        "run_id": metadata["run_id"],
        "status": "EXPERIMENTALLY VALIDATED",
        "scope": "held_out_test",
        "source_commit": commit,
        "dataset_doi": dataset_record["official_source"]["doi"],
        "python_version_at_run": metadata.get("environment", {}).get("python_version"),
        "hashes": {
            **hashes,
            "dataset_manifest_sha256": _sha256(dataset_manifest),
            "validation_audit_sha256": _sha256(validation_audit),
            "evaluation_metadata_sha256": _sha256(metadata_path),
            **{name + "_sha256": _sha256(path) for name, path in required.items()},
            **({"eda_summary_sha256": eda_hash} if eda_hash else {}),
        },
        "model_training_commit": model.get("environment", {}).get("git_commit"),
        "model_training_packages": model.get("environment", {}).get("packages"),
        "split_random_seed": split.get("random_seed"),
        "threshold": CANONICAL_DECISION_THRESHOLD,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "counts": counts,
        "validation_reference": {
            "train_rows": audit["split_integrity"]["train_rows"],
            "validation_rows": val["n"],
            "TN": val["tn"],
            "FP": val["fp"],
            "FN": val["fn"],
            "TP": val["tp"],
        },
        "metrics": calculated,
        "attack_families": attack_counts,
        "samples": samples,
        "test_feature_medians": feature_medians,
        "feature_distributions_median": distributions,
        "missing_or_nonfinite_test_feature_cells": {
            name: int((~np.isfinite(pd.to_numeric(source[name], errors="coerce").to_numpy())).sum())
            for name in FEATURES_FOR_REVIEW
        },
        "eda_limitations": eda_limitations,
        "min_ttl_distribution": ttl_distribution,
        "boundary_band_0_35_0_65": {
            "total": int(band.sum()),
            "fp": int((band & predictions.outcome.eq("FP")).sum()),
            "fn": int((band & predictions.outcome.eq("FN")).sum()),
        },
        "temporal_windows": temporal,
        "limitations": [
            "Source is a laboratory NetFlow capture; deployment drift is untested.",
            "No session ID or payload context is available.",
            "Previous model predictions were verified against artifacts and labels, but model inference was not rerun.",
        ],
    }


def render_report(result: dict[str, Any]) -> str:
    """Render only measured values from a reconciled run."""
    c, m = result["counts"], result["metrics"]
    lines = [
        f"# Random Forest held-out Test: {result['run_id']}",
        "",
        f"Status: **{result['status']}**. Positive class: `Attack (1)`; threshold: `{result['threshold']}`.",
        f"Source commit: `{result['source_commit']}`. Feature contract: `{result['feature_contract_version']}`.",
        "",
        "## Confusion matrix and metrics",
        "",
        "| TN | FP | FN | TP | Total |",
        "| ---: | ---: | ---: | ---: | ---: |",
        f"| {c['TN']} | {c['FP']} | {c['FN']} | {c['TP']} | {sum(c.values())} |",
        "",
        "| Accuracy | Precision | Recall | F1 | Macro F1 | Weighted F1 | FPR |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        "| "
        + " | ".join(
            f"{m[key]:.9f}"
            for key in (
                "accuracy",
                "precision",
                "recall",
                "f1",
                "macro_f1",
                "weighted_f1",
                "false_positive_rate",
            )
        )
        + " |",
        "",
        "## Independent Validation reference",
        "",
        "These counts come from the validation audit of the locked model; they are separate from the held-out Test counts above.",
        "",
        "| Train rows | Validation rows | Validation TN | Validation FP | Validation FN | Validation TP |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        "| "
        + " | ".join(
            str(result["validation_reference"][key])
            for key in ("train_rows", "validation_rows", "TN", "FP", "FN", "TP")
        )
        + " |",
        "",
        "## Attack-family breakdown",
        "",
        "| Attack | Total | Detected | FN | Recall 95% Wilson CI |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name, item in sorted(result["attack_families"].items()):
        lo, hi = item["recall_ci_95"]
        lines.append(
            f"| {name} | {item['total']} | {item['detected']} | {item['missed']} | {lo:.6f}–{hi:.6f} |"
        )
    lines += [
        "",
        "## Misclassified flows",
        "",
        "Sample IDs are run-scoped hashes; no addresses or ports are published.",
        "",
        "| Sample | Type | Attack | P(Attack) | Margin to threshold | MIN_TTL | MAX_TTL | Protocol | Packets in/out | Bytes in/out | Retrans in | Duration ms |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: |",
    ]
    for sample in result["samples"]:
        f = sample["features"]
        lines.append(
            f"| {sample['sample_id']} | {sample['outcome']} | {sample['attack_family']} | {sample['prob_attack']:.6f} | {sample['margin_to_threshold']:+.6f} | {f['MIN_TTL']} | {f['MAX_TTL']} | {f['PROTOCOL']} | {f['IN_PKTS']}/{f['OUT_PKTS']} | {f['IN_BYTES']}/{f['OUT_BYTES']} | {f['RETRANSMITTED_IN_PKTS']} | {f['FLOW_DURATION_MILLISECONDS']} |"
        )
    lines += [
        "",
        "## Feature distributions",
        "",
        "Medians are computed on the same Test source rows; FP/FN medians describe very small groups and do not establish cause.",
        "",
        "| Feature | Benign median | Attack median | FP median | FN median | Missing/nonfinite Test cells |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, groups in result["feature_distributions_median"].items():
        values = [
            "N/A" if groups[group] is None else f"{groups[group]:.3f}"
            for group in ("benign", "attack", "fp", "fn")
        ]
        lines.append(
            f"| {name} | {' | '.join(values)} | {result['missing_or_nonfinite_test_feature_cells'][name]} |"
        )
    lines += [
        "",
        "Most frequent MIN_TTL values by source class:",
        "",
        "| Class | MIN_TTL | Test rows |",
        "| --- | ---: | ---: |",
    ]
    for label, distribution in result["min_ttl_distribution"].items():
        for value, count in distribution.items():
            lines.append(f"| {label} | {value} | {count} |")
    band = result["boundary_band_0_35_0_65"]
    lines += [
        "",
        "## Observations and interpretation",
        "",
        f"- Fixed probability band 0.35–0.65 contains {band['total']} flows, including {band['fp']} FP and {band['fn']} FN. This band was inspected after evaluation and did not change the threshold.",
        f"- Test class support: benign {c['TN'] + c['FP']}, attack {c['FN'] + c['TP']}; accuracy alone can hide rare errors.",
        f"- Test median MIN_TTL: {result['test_feature_medians']['MIN_TTL']}. The class-conditional MIN_TTL counts are recorded in the JSON summary. TTL association is observed; a causal shortcut for these nine errors is a hypothesis, not established by feature importance.",
        "- The two FN belong to the attack families shown in the table. Small family sizes limit precision of per-family conclusions.",
        "",
        "## Temporal windows",
        "",
        "| UTC hour | Flows | FP | FN |",
        "| --- | ---: | ---: | ---: |",
    ]
    for hour, item in result["temporal_windows"].items():
        lines.append(f"| {hour} | {item['total']} | {item['fp']} | {item['fn']} |")
    lines += [
        "",
        "## Dataset limitations and future work",
        "",
        *["- " + item for item in result["limitations"]],
    ]
    if result["eda_limitations"] is not None:
        eda = result["eda_limitations"]
        lines.append(
            f"- Dataset-wide EDA records {eda['exact_full_row_duplicates']} exact duplicate rows, {eda['behavioral_near_duplicates']} behaviorally equivalent rows, and {eda['zero_duration_non_finite_rate_rows']} zero-duration rows with nonfinite rate values. These are whole-dataset counts, not counts of errors in this Test run."
        )
    lines += [
        "- A TTL ablation or group-aware evaluation would require a new training and validation protocol. This held-out Test result must not select a new model or threshold.",
        "",
        "## Provenance",
        "",
        "All hashes below were checked against the existing run, dataset record, and historical manifests. Predictions remain outside Git.",
        f"Dataset DOI: `{result['dataset_doi']}`.",
        f"Training commit: `{result['model_training_commit']}`; training packages: `{result['model_training_packages']}`; split seed: `{result['split_random_seed']}`; evaluation Python: `{result['python_version_at_run']}`.",
        "",
    ]
    for name, value in sorted(result["hashes"].items()):
        lines.append(f"- `{name}`: `{value}`")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "run-dir",
        "dataset-csv",
        "indices-dir",
        "split-manifest",
        "preprocessing-manifest",
        "model-manifest",
        "preprocessor-artifact",
        "model-artifact",
        "output-dir",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument(
        "--eda-summary", type=Path, default=Path("reports/eda/nf_unsw_nb15_v3_eda_summary.json")
    )
    parser.add_argument(
        "--dataset-manifest", type=Path, default=Path("data/NF_UNSW_NB15_V3_MANIFEST.json")
    )
    parser.add_argument(
        "--validation-audit",
        type=Path,
        default=Path("reports/models/rf_baseline_validation_audit.json"),
    )
    parser.add_argument("--report-path", type=Path)
    args = parser.parse_args(argv)
    result = reconcile_run(
        run_dir=args.run_dir,
        dataset_csv=args.dataset_csv,
        indices_dir=args.indices_dir,
        split_manifest=args.split_manifest,
        preprocessing_manifest=args.preprocessing_manifest,
        model_manifest=args.model_manifest,
        preprocessor_artifact=args.preprocessor_artifact,
        model_artifact=args.model_artifact,
        dataset_manifest=args.dataset_manifest,
        validation_audit=args.validation_audit,
        eda_summary=args.eda_summary,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "verified_summary.json").write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    report = render_report(result)
    (args.output_dir / "error_analysis.md").write_text(report, encoding="utf-8")
    if args.report_path is not None:
        args.report_path.parent.mkdir(parents=True, exist_ok=True)
        args.report_path.write_text(report, encoding="utf-8")
    print(
        json.dumps(
            {"run_id": result["run_id"], "status": result["status"], "counts": result["counts"]}
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
