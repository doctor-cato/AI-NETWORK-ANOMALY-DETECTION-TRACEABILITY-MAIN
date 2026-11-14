"""Failure-path tests for reconciling stored held-out predictions."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.evaluation import evidence_recovery as recovery


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _fixture(tmp_path: Path, monkeypatch) -> dict:
    run = tmp_path / "run"
    run.mkdir()
    indices = tmp_path / "indices"
    indices.mkdir()
    paths = {
        "run_dir": run,
        "dataset_csv": tmp_path / "source.csv",
        "indices_dir": indices,
        "split_manifest": tmp_path / "split.json",
        "preprocessing_manifest": tmp_path / "prep.json",
        "model_manifest": tmp_path / "model.json",
        "preprocessor_artifact": tmp_path / "prep.joblib",
        "model_artifact": tmp_path / "model.joblib",
        "dataset_manifest": tmp_path / "dataset.json",
        "validation_audit": tmp_path / "validation_audit.json",
        "eda_summary": None,
    }
    _write_json(
        paths["split_manifest"],
        {
            "split_protocol_version": "protocol-v1",
            "total_source_rows": 9,
            "partitions": {
                "train": {"row_count": 3},
                "validation": {"row_count": 2, "label_distribution": {"0": 1, "1": 1}},
                "test": {
                    "row_count": 4,
                    "label_distribution": {"0": 2, "1": 2},
                    "attack_distribution": {"Benign": 2, "DoS": 2},
                },
            },
        },
    )
    _write_json(
        paths["dataset_manifest"],
        {
            "dataset": "NF-UNSW-NB15-v3",
            "official_source": {"doi": "fixture-doi"},
            "files": [{"role": "dataset", "sha256": "a" * 64, "expected_rows": 9}],
        },
    )
    _write_json(
        paths["model_manifest"],
        {
            "configuration_id": "locked-v1",
            "hyperparameters": {"n_estimators": 2},
            "provenance_status": "VERIFIED",
            "test_lock_audit": {
                "test_partition_accessed": False,
                "test_indices_loaded": False,
                "test_rows_loaded": 0,
            },
        },
    )
    for name in ("preprocessing_manifest",):
        _write_json(paths[name], {})
    predictions = pd.DataFrame(
        {
            "row_index": [0, 1, 2, 3],
            "y_true": [0, 0, 1, 1],
            "y_pred": [0, 1, 0, 1],
            "prob_benign": [0.9, 0.3, 0.6, 0.1],
            "prob_attack": [0.1, 0.7, 0.4, 0.9],
            "attack_category": ["Benign", "Benign", "DoS", "DoS"],
            "outcome": ["TN", "FP", "FN", "TP"],
        }
    )
    predictions.to_csv(run / "predictions.csv", index=False)
    (run / "confusion_matrix.csv").write_text(
        ",Pred_Benign (0),Pred_Attack (1)\nTrue_Benign (0),1,1\nTrue_Attack (1),1,1\n",
        encoding="utf-8",
    )
    (run / "confusion_matrix.png").write_bytes(b"\x89PNG\r\n\x1a\nfixture")
    metrics = {
        "run_id": "synthetic-fixture",
        "partition": "test",
        "decision_threshold": 0.5,
        "sample_count": 4,
        "overall_metrics": {
            "precision": 0.5,
            "recall": 0.5,
            "f1": 0.5,
            "macro_f1": 0.5,
            "false_positive_rate": 0.5,
            "fpr": 0.5,
            "confusion_matrix": [[1, 1], [1, 1]],
        },
        "confusion_matrix_breakdown": {"tn": 1, "fp": 1, "fn": 1, "tp": 1},
        "benign_traffic_breakdown": {
            "total": 2,
            "false_positive": 1,
            "true_negative": 1,
            "false_positive_rate": 0.5,
        },
        "per_attack_category_breakdown": {"DoS": {"total": 2, "detected": 1, "missed": 1}},
    }
    _write_json(run / "metrics.json", metrics)
    hashes = {
        key: "a" * 64
        for key in (
            "dataset_sha256",
            "split_manifest_sha256",
            "preprocessing_manifest_sha256",
            "model_manifest_sha256",
            "test_indices_sha256",
            "preprocessor_artifact_sha256",
            "model_artifact_sha256",
        )
    }
    _write_json(
        paths["validation_audit"],
        {
            "model_artifact": {"sha256": hashes["model_artifact_sha256"]},
            "split_integrity": {"train_rows": 3, "val_rows": 2},
            "validation_recomputed": {"n": 2, "tn": 1, "fp": 0, "fn": 0, "tp": 1},
        },
    )
    metadata = {
        "run_id": "synthetic-fixture",
        "partition": "test",
        "evaluation_stage": "held_out_test_evaluation",
        "decision_threshold": 0.5,
        "hyperparameters": {"n_estimators": 2},
        "configuration_id": "locked-v1",
        "feature_contract_version": recovery.FEATURE_CONTRACT_VERSION,
        "selected_features": list(ML_FEATURE_COLUMNS),
        "split_protocol_id": "protocol-v1",
        "test_row_count": 4,
        "benign_row_count": 2,
        "attack_row_count": 2,
        "test_lock_compliance": {
            "train_validation_disjoint_verified": True,
            "model_retrained_on_test": False,
            "preprocessor_refitted_on_test": False,
            "hyperparameters_tuned_on_test": False,
            "threshold_tuned_on_test": False,
        },
        "environment": {
            "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        },
        "provenance_hashes": hashes,
        "generated_artifacts": {
            key: {"path": str(run / name), "sha256": recovery._sha256(run / name)}
            for key, name in (
                ("metrics_json", "metrics.json"),
                ("confusion_matrix_csv", "confusion_matrix.csv"),
                ("confusion_matrix_png", "confusion_matrix.png"),
                ("predictions_csv", "predictions.csv"),
            )
        },
    }
    _write_json(run / "evaluation_metadata.json", metadata)
    source = pd.DataFrame(
        {
            "Label": [0, 0, 1, 1],
            "Attack": ["Benign", "Benign", "DoS", "DoS"],
            "FLOW_START_MILLISECONDS": [1_000, 1_000, 2_000, 2_000],
            **{name: [1.0, 2.0, 3.0, 4.0] for name in recovery.FEATURES_FOR_REVIEW},
        }
    )
    monkeypatch.setattr(recovery, "_read_test_source", lambda *_: source)
    monkeypatch.setattr(
        recovery, "_load_indices_csv_gz", lambda *_: pd.Series([0, 1, 2, 3]).to_numpy()
    )
    monkeypatch.setattr(
        recovery,
        "check_test_evaluation_prerequisites",
        lambda **_: SimpleNamespace(
            partition_verification_status="VERIFIED", verified_hashes=hashes
        ),
    )
    return paths


def test_reconcile_stored_predictions_and_metrics(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    result = recovery.reconcile_run(**paths)
    assert result["counts"] == {"TN": 1, "FP": 1, "FN": 1, "TP": 1}
    assert result["attack_families"]["DoS"]["missed"] == 1
    assert len(result["samples"]) == 2


def test_reconcile_rejects_missing_predictions(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    (paths["run_dir"] / "predictions.csv").unlink()
    with pytest.raises(FileNotFoundError, match="predictions"):
        recovery.reconcile_run(**paths)


def test_reconcile_rejects_tampered_predictions(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    predictions = paths["run_dir"] / "predictions.csv"
    predictions.write_bytes(predictions.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="predictions_csv SHA-256"):
        recovery.reconcile_run(**paths)


def test_reconcile_rejects_wrong_model_manifest(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    model = paths["model_manifest"]
    payload = json.loads(model.read_text(encoding="utf-8"))
    payload["configuration_id"] = "wrong-model"
    _write_json(model, payload)
    with pytest.raises(ValueError, match="model identity"):
        recovery.reconcile_run(**paths)


def test_reconcile_rejects_wrong_validation_audit(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    audit = paths["validation_audit"]
    payload = json.loads(audit.read_text(encoding="utf-8"))
    payload["model_artifact"]["sha256"] = "b" * 64
    _write_json(audit, payload)
    with pytest.raises(ValueError, match="Validation model identity"):
        recovery.reconcile_run(**paths)


def test_reconcile_rejects_synthetic_dataset_provenance(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    manifest = paths["dataset_manifest"]
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["files"][0]["sha256"] = "b" * 64
    _write_json(manifest, payload)
    with pytest.raises(ValueError, match="canonical dataset SHA-256"):
        recovery.reconcile_run(**paths)


def test_reconcile_rejects_wrong_confusion_matrix(tmp_path: Path, monkeypatch) -> None:
    paths = _fixture(tmp_path, monkeypatch)
    matrix = paths["run_dir"] / "confusion_matrix.csv"
    matrix.write_text(matrix.read_text(encoding="utf-8").replace("1,1", "2,0"), encoding="utf-8")
    meta = paths["run_dir"] / "evaluation_metadata.json"
    payload = json.loads(meta.read_text(encoding="utf-8"))
    payload["generated_artifacts"]["confusion_matrix_csv"]["sha256"] = recovery._sha256(matrix)
    _write_json(meta, payload)
    with pytest.raises(ValueError, match="CSV confusion matrix"):
        recovery.reconcile_run(**paths)
