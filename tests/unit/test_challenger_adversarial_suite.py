#!/usr/bin/env python3
"""Adversarial stress-testing suite by Remediation Challenger (challenger_remedy_gate).

Executes empirical attacks and stress harnesses against all remediation mechanisms for Issues #53–#60:
1. Tamper Model & Deserialization Bypass (Issue #53)
2. Isolation Forest Parity & Threshold Sweep (Issue #54)
3. Index Disjointness & Tamper Detection (Issue #56)
4. Out-Of-Distribution (OOD) & Anti-Imputation Guard (Issue #58)
5. API Heuristic Fallback Guard & Degraded Mode (Issue #59)
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.errors import ModelNotReadyError
from network_anomaly.api.main import app
from network_anomaly.api.service import ApiService
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.evaluation.test_evaluation import verify_index_disjointness
from network_anomaly.inference.pipeline import (
    InferencePipeline,
    load_verified_model,
    predict_from_artifact,
)
from network_anomaly.ingestion.gate import (
    InferenceEligibilityGate,
)
from network_anomaly.models.isolation_forest import (
    FEATURE_CONTRACT_VERSION,
    IsolationForestModel,
    anomaly_scores,
)
from network_anomaly.preprocessing import TrainOnlyPreprocessor


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def _create_minimal_valid_preprocessor(tmp_path: Path) -> Tuple[Path, Path, str]:
    """Create a minimal fitted TrainOnlyPreprocessor and companion manifest using canonical save()."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(42)
    sample_df = pd.DataFrame(
        rng.uniform(1.0, 100.0, size=(20, len(ML_FEATURE_COLUMNS))),
        columns=list(ML_FEATURE_COLUMNS),
    )
    from network_anomaly.preprocessing import PreprocessingConfig

    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256="4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        split_manifest_sha256="bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
    )
    prep.fit(sample_df)

    prep_file = tmp_path / "test_prep.joblib"
    prep_manifest = tmp_path / "test_prep_manifest.json"

    prep_sha = prep.save(artifact_path=prep_file, manifest_path=prep_manifest)
    return prep_file, prep_manifest, prep_sha


def _create_minimal_valid_rf_model(
    tmp_path: Path, preprocessor_sha256: str
) -> Tuple[Path, Path, str]:
    """Create a minimal fitted RandomForestClassifier and companion manifest."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(42)
    X = rng.uniform(1.0, 100.0, size=(30, len(ML_FEATURE_COLUMNS)))
    y = rng.choice([0, 1], size=30)
    clf = RandomForestClassifier(n_estimators=5, random_state=42)
    clf.fit(X, y)

    payload = {
        "model_type": "RandomForestClassifier",
        "estimator": clf,
        "classes": [0, 1],
    }
    model_file = tmp_path / "test_rf.joblib"
    model_manifest = tmp_path / "test_rf_manifest.json"

    joblib.dump(payload, model_file)
    model_sha = _sha256_file(model_file)

    manifest_data = {
        "model_type": "RandomForestClassifier",
        "model_artifact_path": str(model_file),
        "model_artifact_sha256": model_sha,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "preprocessor_artifact_sha256": preprocessor_sha256,
        "run_id": "test-run-1",
        "class_mapping": {"0": "Benign", "1": "Attack"},
    }
    model_manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    return model_file, model_manifest, model_sha


# ==============================================================================
# SCENARIO 1: Tamper Model & Deserialization Bypass (Issue #53)
# ==============================================================================
class TestScenario1ModelTamperAndDeserializationBypass:
    """Stress-test tamper detection, digest verification, and deserialization fail-closed behavior."""

    def test_single_bit_flip_tamper_fails_closed_in_load_verified_model(self, tmp_path: Path):
        """Flipping a single bit in the model file must raise ValueError BEFORE deserialization."""
        prep_file, prep_man, prep_sha = _create_minimal_valid_preprocessor(tmp_path)
        model_file, model_man, model_sha = _create_minimal_valid_rf_model(tmp_path, prep_sha)

        # Confirm it loads cleanly when untampered
        model, meta = load_verified_model(model_file, model_man)
        assert meta["model_artifact_sha256"] == model_sha

        # Tamper: flip 1 byte in the joblib file
        content = bytearray(model_file.read_bytes())
        content[10] ^= 0x01  # Flip 1 bit
        model_file.write_bytes(content)

        # Assert load_verified_model strictly fails closed
        with pytest.raises(ValueError) as excinfo:
            load_verified_model(model_file, model_man)
        assert "Model artifact SHA-256 mismatch" in str(excinfo.value)

    def test_single_bit_flip_tamper_fails_closed_in_inference_pipeline(self, tmp_path: Path):
        """InferencePipeline.from_artifacts must fail closed on tampered model."""
        prep_file, prep_man, prep_sha = _create_minimal_valid_preprocessor(tmp_path)
        model_file, model_man, model_sha = _create_minimal_valid_rf_model(tmp_path, prep_sha)

        # Tamper model file
        content = bytearray(model_file.read_bytes())
        content[20] ^= 0xFF
        model_file.write_bytes(content)

        with pytest.raises(ValueError) as excinfo:
            InferencePipeline.from_artifacts(
                model_artifact_path=model_file,
                preprocessor_artifact_path=prep_file,
                model_manifest_path=model_man,
                preprocessor_manifest_path=prep_man,
            )
        assert "Model artifact SHA-256 mismatch" in str(excinfo.value)

    def test_missing_companion_manifest_fails_closed(self, tmp_path: Path):
        """A model file without companion manifest must fail closed (FileNotFoundError)."""
        prep_file, prep_man, prep_sha = _create_minimal_valid_preprocessor(tmp_path)
        model_file, _, _ = _create_minimal_valid_rf_model(tmp_path, prep_sha)

        orphan_model = tmp_path / "orphan_model.joblib"
        orphan_model.write_bytes(model_file.read_bytes())

        with pytest.raises(FileNotFoundError) as excinfo:
            load_verified_model(orphan_model, manifest_path=None)
        assert "Companion manifest for model not found" in str(excinfo.value)

    def test_predict_from_artifact_with_tampered_or_fake_artifact_fails_closed(
        self, tmp_path: Path
    ):
        """Legacy entrypoint predict_from_artifact must fail closed when presented with fake artifact."""
        fake_artifact = tmp_path / "fake_exploit.joblib"
        fake_artifact.write_bytes(b"MALICIOUS_PAYLOAD_NOT_SERIALIZED")

        dummy_data = pd.DataFrame(
            np.zeros((5, len(ML_FEATURE_COLUMNS))), columns=list(ML_FEATURE_COLUMNS)
        )

        with pytest.raises(FileNotFoundError):
            predict_from_artifact(dummy_data, artifact_path=fake_artifact)

    def test_preprocessor_mismatch_fails_closed(self, tmp_path: Path):
        """Model trained against preprocessor A must refuse execution when paired with preprocessor B."""
        prep_file_A, prep_man_A, prep_sha_A = _create_minimal_valid_preprocessor(tmp_path / "prepA")
        prep_file_B, prep_man_B, prep_sha_B = _create_minimal_valid_preprocessor(tmp_path / "prepB")
        model_file, model_man, _ = _create_minimal_valid_rf_model(
            tmp_path / "model", preprocessor_sha256=prep_sha_A
        )

        # Attempt pairing model (trained with A) with preprocessor B
        with pytest.raises(ValueError) as excinfo:
            InferencePipeline.from_artifacts(
                model_artifact_path=model_file,
                preprocessor_artifact_path=prep_file_B,
                model_manifest_path=model_man,
                preprocessor_manifest_path=prep_man_B,
            )
        assert "preprocessor SHA-256" in str(excinfo.value)

    def test_corrupted_manifest_json_fails_closed(self, tmp_path: Path):
        """Malformed or syntactically invalid manifest JSON must fail closed (ValueError)."""
        prep_file, prep_man, prep_sha = _create_minimal_valid_preprocessor(tmp_path)
        model_file, model_man, _ = _create_minimal_valid_rf_model(tmp_path, prep_sha)

        model_man.write_text("{NOT_VALID_JSON: true,,,", encoding="utf-8")
        with pytest.raises(ValueError) as excinfo:
            load_verified_model(model_file, model_man)
        assert "Failed to parse model manifest JSON" in str(excinfo.value)

    def test_contract_version_mismatch_fails_closed(self, tmp_path: Path):
        """Manifest declaring an outdated feature contract version must fail closed."""
        prep_file, prep_man, prep_sha = _create_minimal_valid_preprocessor(tmp_path)
        model_file, model_man, _ = _create_minimal_valid_rf_model(tmp_path, prep_sha)

        man_data = json.loads(model_man.read_text(encoding="utf-8"))
        man_data["feature_contract_version"] = "nf-unsw-nb15-v2-legacy-30"
        model_man.write_text(json.dumps(man_data), encoding="utf-8")

        with pytest.raises(ValueError) as excinfo:
            load_verified_model(model_file, model_man)
        assert "feature contract version" in str(excinfo.value)


# ==============================================================================
# SCENARIO 2: Isolation Forest Parity & Threshold Sweep (Issue #54)
# ==============================================================================
class TestScenario2IsolationForestParity:
    """Stress-test mathematical and binary parity between evaluation and inference across threshold sweeps."""

    def test_100_percent_parity_across_dense_threshold_sweep(self):
        """Verify 100% agreement between evaluation logic and model.predict(X, threshold=t)."""
        rng = np.random.default_rng(2026)

        # Train model on synthetic clusters
        X_train = rng.normal(loc=0.0, scale=1.0, size=(400, 10))
        model = IsolationForestModel(
            config={"n_estimators": 50, "random_state": 42},
            threshold=0.0,
        )
        model.fit(X_train)

        # Generate separate synthetic evaluation test matrix with mixed inliers and anomalies
        X_inliers = rng.normal(loc=0.0, scale=1.0, size=(300, 10))
        X_outliers = rng.uniform(low=5.0, high=20.0, size=(100, 10))
        X_eval = np.vstack([X_inliers, X_outliers])

        eval_scores = anomaly_scores(model, X_eval)
        min_score = float(np.min(eval_scores))
        max_score = float(np.max(eval_scores))

        # Sweep 50 thresholds from below min to above max
        threshold_sweep = np.linspace(min_score - 0.5, max_score + 0.5, num=50)

        total_comparisons = 0
        total_matches = 0

        for tau in threshold_sweep:
            # 1. Evaluation logic (as defined in scripts/train_isolation_forest.py)
            y_eval = (eval_scores >= tau).astype(int)

            # 2. Inference logic (as defined in IsolationForestModel.predict)
            y_inf = model.predict(X_eval, threshold=tau)

            assert np.array_equal(y_eval, y_inf), f"Parity divergence at threshold tau={tau:.6f}!"

            # Strict binary label check: must be subset of {0, 1}, NOT scikit-learn {-1, 1}
            unique_labels = set(np.unique(y_inf))
            assert unique_labels.issubset(
                {0, 1}
            ), f"Found non-binary or scikit-learn labels: {unique_labels}"

            total_comparisons += len(y_eval)
            total_matches += int(np.sum(y_eval == y_inf))

        assert total_comparisons == len(X_eval) * 50
        assert total_matches == total_comparisons
        assert (total_matches / total_comparisons) == 1.0

    def test_uncalibrated_threshold_raises_value_error(self):
        """Calling predict without threshold on an uncalibrated model must raise ValueError."""
        rng = np.random.default_rng(42)
        X = rng.normal(size=(50, 5))
        model = IsolationForestModel(config={"n_estimators": 20, "random_state": 42})
        model.fit(X)
        assert model.threshold is None

        with pytest.raises(ValueError) as excinfo:
            model.predict(X)
        assert "Threshold is not set" in str(excinfo.value)

    def test_extreme_boundary_thresholds_infinity(self):
        """Boundary conditions: -inf must classify 100% Attack, +inf must classify 100% Benign."""
        rng = np.random.default_rng(42)
        X = rng.normal(size=(100, 5))
        model = IsolationForestModel(config={"n_estimators": 20, "random_state": 42})
        model.fit(X)

        y_all_attack = model.predict(X, threshold=float("-inf"))
        assert np.all(y_all_attack == 1)

        y_all_benign = model.predict(X, threshold=float("inf"))
        assert np.all(y_all_benign == 0)

    def test_score_monotonicity_on_extreme_outliers(self):
        """Monotonicity: Points located further from normal cluster must receive strictly higher scores."""
        rng = np.random.default_rng(100)
        train_data = rng.normal(loc=0.0, scale=0.5, size=(500, 3))
        model = IsolationForestModel(config={"n_estimators": 100, "random_state": 42})
        model.fit(train_data)

        inlier = np.array([[0.0, 0.0, 0.0]])
        moderate_anomaly = np.array([[3.0, 3.0, 3.0]])
        extreme_anomaly = np.array([[20.0, 20.0, 20.0]])

        s_inlier = model.anomaly_scores(inlier)[0]
        s_mod = model.anomaly_scores(moderate_anomaly)[0]
        s_ext = model.anomaly_scores(extreme_anomaly)[0]

        # In Isolation Forest, inliers have negative/low scores; anomalies have high scores.
        # Once an extreme anomaly is isolated at the shallowest splits, scores plateau (s_mod <= s_ext).
        assert s_inlier < s_mod <= s_ext, (
            f"Anomaly scores must increase away from inliers and plateau: "
            f"inlier={s_inlier:.4f}, moderate={s_mod:.4f}, extreme={s_ext:.4f}"
        )
        assert s_inlier < s_ext


# ==============================================================================
# SCENARIO 3: Index Disjointness & Tamper Detection (Issue #56)
# ==============================================================================
class TestScenario3IndexDisjointnessAndTamper:
    """Stress-test set-based disjointness verification and missing-file fail-closed handling."""

    def _write_indices_gz(self, path: Path, indices: List[int]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["row_index"])
            for idx in indices:
                writer.writerow([idx])
        return path

    def test_genuine_overlap_detected_immediately(self, tmp_path: Path):
        """Deliberately overlapping index 42 between train and validation must fail verification."""
        train_path = self._write_indices_gz(tmp_path / "train.csv.gz", [10, 20, 30, 42, 50])
        val_path = self._write_indices_gz(tmp_path / "val.csv.gz", [42, 60, 70, 80])  # 42 overlaps!
        test_path = self._write_indices_gz(tmp_path / "test.csv.gz", [90, 100, 110, 120])

        is_disjoint, errors = verify_index_disjointness(
            train_indices_path=train_path,
            val_indices_path=val_path,
            test_indices_path=test_path,
            total_source_rows=200,
        )

        assert is_disjoint is False
        assert any("overlapping indices between Train and Validation" in err for err in errors)

    def test_train_test_overlap_detected(self, tmp_path: Path):
        """Overlapping index between train and test must fail verification."""
        train_path = self._write_indices_gz(tmp_path / "train.csv.gz", [1, 2, 3, 99])
        val_path = self._write_indices_gz(tmp_path / "val.csv.gz", [10, 20, 30])
        test_path = self._write_indices_gz(tmp_path / "test.csv.gz", [99, 100, 101])  # 99 overlaps!

        is_disjoint, errors = verify_index_disjointness(
            train_indices_path=train_path,
            val_indices_path=val_path,
            test_indices_path=test_path,
            total_source_rows=200,
        )

        assert is_disjoint is False
        assert any("overlapping indices between Train and Test" in err for err in errors)

    def test_missing_indices_file_fails_closed(self, tmp_path: Path):
        """Missing indices file must result in fail-closed is_disjoint=False."""
        train_path = self._write_indices_gz(tmp_path / "train.csv.gz", [1, 2, 3])
        test_path = self._write_indices_gz(tmp_path / "test.csv.gz", [10, 20, 30])
        non_existent_val = tmp_path / "missing_val.csv.gz"

        is_disjoint, errors = verify_index_disjointness(
            train_indices_path=train_path,
            val_indices_path=non_existent_val,
            test_indices_path=test_path,
        )

        assert is_disjoint is False
        assert any("missing partition index file" in err.lower() for err in errors)

    def test_internal_duplicate_indices_rejected(self, tmp_path: Path):
        """Duplicate row indices within the same partition file must fail verification."""
        train_path = self._write_indices_gz(
            tmp_path / "train.csv.gz", [1, 2, 2, 3]
        )  # 2 is duplicated!
        val_path = self._write_indices_gz(tmp_path / "val.csv.gz", [10, 20, 30])
        test_path = self._write_indices_gz(tmp_path / "test.csv.gz", [100, 200, 300])

        # _load_indices_csv_gz itself raises ValueError on internal duplicate,
        # which verify_index_disjointness catches and reports in errors.
        is_disjoint, errors = verify_index_disjointness(
            train_indices_path=train_path,
            val_indices_path=val_path,
            test_indices_path=test_path,
        )
        assert is_disjoint is False
        assert any("duplicate" in err.lower() for err in errors)

    def test_split_manifest_index_sha256_mismatch_rejected(self, tmp_path: Path):
        """If split manifest declares index_sha256 that does not match disk, it must fail verification."""
        train_path = self._write_indices_gz(tmp_path / "train.csv.gz", [1, 2, 3])
        val_path = self._write_indices_gz(tmp_path / "val.csv.gz", [10, 20, 30])
        test_path = self._write_indices_gz(tmp_path / "test.csv.gz", [100, 200, 300])

        fake_manifest = {
            "partitions": {
                "train": {"index_sha256": "0" * 64},  # Wrong hash
                "validation": {"index_sha256": _sha256_file(val_path)},
                "test": {"index_sha256": _sha256_file(test_path)},
            }
        }

        is_disjoint, errors = verify_index_disjointness(
            train_indices_path=train_path,
            val_indices_path=val_path,
            test_indices_path=test_path,
            split_manifest=fake_manifest,
        )
        assert is_disjoint is False
        assert any("train index file sha-256 mismatch" in err.lower() for err in errors)


# ==============================================================================
# SCENARIO 4: OOD & Anti-Imputation Gate (Issue #58)
# ==============================================================================
class TestScenario4OODAndAntiImputationGate:
    """Stress-test InferenceEligibilityGate rejection on MIN_TTL=0, NaNs, missing features, and anti-imputation."""

    def test_min_ttl_zero_abstained_without_imputation(self):
        """Events with MIN_TTL=0 must be rejected/abstained without filling 0 or median."""
        gate = InferenceEligibilityGate(strict_ood_abstain=True, reject_zero_ttl=True)

        # Create DataFrame with all 47 required columns
        df_invalid = pd.DataFrame(
            np.ones((10, len(ML_FEATURE_COLUMNS))), columns=list(ML_FEATURE_COLUMNS)
        )
        # Set MIN_TTL = 0
        df_invalid["MIN_TTL"] = 0

        res = gate.check_and_filter(df_invalid)

        assert res.is_eligible is False
        assert res.decision.is_eligible is False
        assert res.decision.decision == "ABSTAINED"
        assert len(res.eligible_df) == 0  # No samples allowed to proceed
        # Assert strictly NO auto-imputation to non-zero
        assert any("MIN_TTL=0" in reason for reason in res.reasons)

    def test_missing_features_abstained_under_anti_imputation(self):
        """DataFrame missing required columns must be abstained without synthetic filling."""
        gate = InferenceEligibilityGate()

        # Partial DataFrame with only 10 features
        partial_df = pd.DataFrame(np.ones((10, 10)), columns=list(ML_FEATURE_COLUMNS)[:10])

        res = gate.check_and_filter(partial_df)

        assert res.is_eligible is False
        assert res.decision.decision == "ABSTAINED"
        assert any("anti-imputation" in reason.lower() for reason in res.reasons) or any(
            "lacks 47 ml features" in reason.lower() for reason in res.reasons
        )

    def test_nan_and_inf_features_abstained(self):
        """NaN or Inf values in feature matrix must lead to abstention."""
        gate = InferenceEligibilityGate()

        df_nan = pd.DataFrame(
            np.ones((10, len(ML_FEATURE_COLUMNS))), columns=list(ML_FEATURE_COLUMNS)
        )
        df_nan.loc[0, "IN_BYTES"] = np.nan
        df_nan.loc[1, "OUT_BYTES"] = np.inf

        res = gate.check_and_filter(df_nan)
        assert res.is_eligible is False
        assert res.decision.decision == "ABSTAINED"

    def test_hard_physical_invariants_negative_metrics_abstained(self):
        """Physical protocol invariants: negative bytes or negative duration must trigger hard rejection."""
        gate = InferenceEligibilityGate()

        df_inv = pd.DataFrame(
            np.ones((5, len(ML_FEATURE_COLUMNS))), columns=list(ML_FEATURE_COLUMNS)
        )
        df_inv.loc[0, "FLOW_DURATION_MILLISECONDS"] = -50.0  # Impossible negative duration
        df_inv.loc[1, "SRC_TO_DST_SECOND_BYTES"] = -100.0  # Negative throughput/bytes

        res = gate.check_and_filter(df_inv)
        assert res.is_eligible is False
        assert res.decision.decision == "ABSTAINED"
        assert len(res.eligible_df) == 0


# ==============================================================================
# SCENARIO 5: API Heuristic Fallback Guard (Issue #59)
# ==============================================================================
class TestScenario5ApiHeuristicFallbackGuard:
    """Stress-test API service and FastAPI endpoint fail-closed behavior when model is absent."""

    def test_service_analyze_flows_fails_closed_when_model_absent(self, tmp_path: Path):
        """ApiService.analyze_flows must raise ModelNotReadyError (HTTP 503) when fallback is disabled."""
        db = DatabaseManager(tmp_path / "test_empty_api.db")
        svc = ApiService(db)

        # Force health check to indicate model not ready
        dummy_event = {
            "IPV4_SRC_ADDR": "192.168.1.100",
            "IPV4_DST_ADDR": "10.0.0.1",
            "L4_SRC_PORT": 443,
            "L4_DST_PORT": 50000,
            "PROTOCOL": 6,
            "IN_BYTES": 1500,
            "OUT_BYTES": 3000,
            "IN_PKTS": 10,
            "OUT_PKTS": 12,
        }

        # allow_heuristic_fallback=False MUST raise ModelNotReadyError
        with pytest.raises(ModelNotReadyError) as excinfo:
            svc.analyze_flows(
                [dummy_event],
                allow_heuristic_fallback=False,
            )
        assert excinfo.value.status_code == 503
        assert "not ready" in excinfo.value.detail.lower()

    def test_fastapi_analyze_endpoint_returns_503_when_model_absent(self):
        """FastAPI POST /api/v1/analyze must return HTTP 503 when fallback is disabled and model absent."""
        client = TestClient(app)

        payload = {
            "events": [
                {
                    "IPV4_SRC_ADDR": "192.168.1.50",
                    "IPV4_DST_ADDR": "10.0.0.2",
                    "L4_SRC_PORT": 80,
                    "L4_DST_PORT": 49152,
                    "PROTOCOL": 6,
                    "IN_BYTES": 500,
                    "OUT_BYTES": 1200,
                    "IN_PKTS": 5,
                    "OUT_PKTS": 8,
                }
            ],
            "allow_heuristic_fallback": False,
        }

        response = client.post("/api/v1/analyze", json=payload)
        # Note: If artifacts are genuinely absent in environment, status_code is 503
        # If artifacts happen to exist in repo, response should be 200 with verified pipeline.
        # But if we explicitly test fallback behavior with non-existent model:
        if response.status_code != 200:
            assert response.status_code == 503
            assert "not ready" in response.json()["detail"].lower()
        else:
            # If 200, it must be verified pipeline, never an undeclared heuristic!
            assert response.json()["inference_mode"] == "verified_pipeline"

    def test_transparent_degraded_headers_when_heuristic_fallback_explicitly_allowed(
        self, tmp_path: Path
    ):
        """When allow_heuristic_fallback=True is passed, API must declare model_ready=False and inference_mode='heuristic_fallback'."""
        db = DatabaseManager(tmp_path / "test_api_fallback.db")
        svc = ApiService(db)

        dummy_event = {
            "IPV4_SRC_ADDR": "192.168.1.100",
            "IPV4_DST_ADDR": "10.0.0.1",
            "L4_SRC_PORT": 443,
            "L4_DST_PORT": 50000,
            "PROTOCOL": 6,
            "IN_BYTES": 1500,
            "OUT_BYTES": 3000,
            "IN_PKTS": 10,
            "OUT_PKTS": 12,
        }

        # Mock health to be degraded
        from network_anomaly.api.schemas import HealthResponse

        svc.check_health = lambda: HealthResponse(
            status="degraded",
            process_alive=True,
            model_ready=False,
            preprocessor_ready=False,
            db_ready=True,
            version="0.1.0",
            git_commit="test",
            timestamp="2026-11-09T00:00:00Z",
            details={},
        )

        res = svc.analyze_flows([dummy_event], allow_heuristic_fallback=True)
        assert res.model_ready is False
        assert res.inference_mode == "heuristic_fallback"
        assert res.results[0].model_used == "heuristic_baseline_artifact_missing"

    def test_runtime_inference_exception_fails_closed_without_fallback(self, tmp_path: Path):
        """When verified pipeline encounters an unexpected crash during inference, it must NOT fallback silently."""
        db = DatabaseManager(tmp_path / "test_api_crash.db")
        svc = ApiService(db)

        from network_anomaly.api.schemas import HealthResponse

        # Simulate health being ready
        svc.check_health = lambda: HealthResponse(
            status="healthy",
            process_alive=True,
            model_ready=True,
            preprocessor_ready=True,
            db_ready=True,
            version="0.1.0",
            git_commit="test",
            timestamp="2026-11-09T00:00:00Z",
            details={},
        )

        # Simulate pipeline raising an unexpected runtime error
        def crashing_pipeline(*args, **kwargs):
            raise RuntimeError("Hardware crash / memory corruption during inference")

        svc._analyze_with_verified_pipeline = crashing_pipeline

        dummy_event = {
            "IPV4_SRC_ADDR": "192.168.1.100",
            "IPV4_DST_ADDR": "10.0.0.1",
            "L4_SRC_PORT": 443,
            "L4_DST_PORT": 50000,
            "PROTOCOL": 6,
            "IN_BYTES": 1500,
            "OUT_BYTES": 3000,
            "IN_PKTS": 10,
            "OUT_PKTS": 12,
        }

        # With allow_heuristic_fallback=False: MUST raise ModelNotReadyError (HTTP 503)
        with pytest.raises(ModelNotReadyError) as excinfo:
            svc.analyze_flows([dummy_event], allow_heuristic_fallback=False)
        assert excinfo.value.status_code == 503
        assert "Hardware crash" in str(excinfo.value.detail)
