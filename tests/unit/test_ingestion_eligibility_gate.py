"""Tests for InferenceEligibilityGate, OOD abstention, and anti-imputation."""

from __future__ import annotations

import numpy as np
import pandas as pd

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.adapters import ZeekConnAdapter
from network_anomaly.ingestion.gate import (
    ContentChecksum,
    DatasetIdentity,
    InferenceEligibilityGate,
    verify_provenance_binding,
)
from network_anomaly.ingestion.schemas import InferenceEligibility


def _create_clean_df(n_rows: int = 5) -> pd.DataFrame:
    """Helper to create a clean DataFrame with all 18 v2 features and valid values."""
    data = {col: [0.5] * n_rows for col in ML_FEATURE_COLUMNS}
    data["duration_ms"] = [100.0] * n_rows
    data["bytes_in"] = [500.0] * n_rows
    data["bytes_out"] = [1000.0] * n_rows
    data["pkts_in"] = [5.0] * n_rows
    data["pkts_out"] = [6.0] * n_rows
    data["protocol_num"] = [6.0] * n_rows
    return pd.DataFrame(data)


def test_gate_anti_imputation_rejects_missing_features():
    """Missing mandatory baseline features must NOT be imputed; gate must ABSTAIN."""
    gate = InferenceEligibilityGate()
    df = _create_clean_df(3)
    df = df.drop(columns=["protocol_num", "bytes_in", "duration_ms"])

    decision = gate.evaluate(df=df)
    assert not decision.can_proceed_to_ml
    assert not decision.is_eligible
    assert decision.decision == "ABSTAINED"
    assert decision.eligibility_status == InferenceEligibility.FEATURE_INCOMPATIBLE
    assert any("missing" in r.lower() for r in decision.abstention_reasons)
    assert any("anti-imputation" in r.lower() for r in decision.abstention_reasons)


def test_gate_anti_imputation_rejects_nan_and_infinite_values():
    """Features with NaN or infinite values must NOT be filled synthetically."""
    gate = InferenceEligibilityGate()
    df = _create_clean_df(4)
    df.loc[1, "bytes_in"] = np.nan
    df.loc[2, "duration_ms"] = np.inf

    decision = gate.evaluate(df=df)
    assert not decision.can_proceed_to_ml
    assert not decision.is_eligible
    assert decision.decision == "ABSTAINED"
    assert decision.eligibility_status == InferenceEligibility.FEATURE_INCOMPLETE
    assert any("non-finite" in r.lower() or "nan" in r.lower() for r in decision.abstention_reasons)
    assert any("anti-imputation" in r.lower() for r in decision.abstention_reasons)


def test_gate_detects_ood_negative_bytes_and_negative_duration():
    """Physical protocol invariant violations must fail closed with ABSTAINED decision."""
    gate = InferenceEligibilityGate(strict_ood_abstain=True)
    df = _create_clean_df(3)
    df.loc[0, "duration_ms"] = -150.0  # Illegal negative duration
    df.loc[1, "bytes_in"] = -50.0  # Illegal negative byte counter

    decision = gate.evaluate(df=df)
    assert not decision.can_proceed_to_ml
    assert not decision.is_eligible
    assert decision.decision == "ABSTAINED"
    assert decision.ood_report is not None
    assert decision.ood_report.hard_violation_count >= 2
    assert any("hard constraint violation" in r.lower() for r in decision.abstention_reasons)


def test_gate_detects_ratio_out_of_bounds_and_abstains():
    """Ratio outside [0, 1] violates flow physical invariant."""
    gate = InferenceEligibilityGate(strict_ood_abstain=True)
    df = _create_clean_df(5)
    df["bytes_in_ratio"] = [1.5, 1.5, 1.5, 1.5, 1.5]

    decision = gate.evaluate(df=df)
    assert not decision.can_proceed_to_ml
    assert not decision.is_eligible
    assert decision.decision == "ABSTAINED"
    assert decision.ood_report is not None
    assert decision.ood_report.hard_violation_count == 5


def test_gate_check_and_filter_clean_data():
    """gate.check_and_filter(df) approves clean records and supports tuple unpacking."""
    gate = InferenceEligibilityGate()
    df = _create_clean_df(5)

    eligible_df, decision = gate.check_and_filter(df)
    assert len(eligible_df) == 5
    assert decision.can_proceed_to_ml
    assert decision.is_eligible
    assert decision.decision == "PROCEED"

    result = gate.check_and_filter(df)
    assert result.is_eligible
    assert result.decision.decision == "PROCEED"
    assert len(result.eligible_df) == 5
    assert len(result.reasons) == 0


def test_gate_check_and_filter_ineligible_data():
    """Ineligible data returns empty DataFrame and decision='ABSTAINED'."""
    gate = InferenceEligibilityGate()
    df = _create_clean_df(4)
    df = df.drop(columns=["bytes_in", "protocol_num"])

    eligible_df, decision = gate.check_and_filter(df)
    assert len(eligible_df) == 0
    assert not decision.is_eligible
    assert decision.decision == "ABSTAINED"
    assert len(decision.abstention_reasons) > 0


def test_dataset_identity_decoupled_from_content_checksum():
    """A slice sample's SHA-256 differs from full dataset; must verify via provenance."""
    identity = DatasetIdentity(
        name="AIT-NDS-v2",
        doi="10.5281/zenodo.13168643",
        format="Tstat-v2-Canonical-18",
        column_count=18,
    )
    # Checksum of a 100k sample slice (not full 4.2GB file)
    sample_sha = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    checksum = ContentChecksum(
        sha256=sample_sha,
        size_bytes=24500123,
        row_count=100000,
        slice_type="sample_slice",
    )
    manifest = {
        "dataset_name": "AIT-NDS-v2",
        "sample_sha256": sample_sha,
        "sample_rows_extracted": 100000,
        "full_dataset_sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
    }

    ok, msg = verify_provenance_binding(identity, checksum, manifest)
    assert ok
    assert "slice content checksum verified" in msg.lower()

    # If sample sha mismatches, fail closed
    corrupt_checksum = ContentChecksum(
        sha256="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        size_bytes=24500123,
        row_count=100000,
        slice_type="sample_slice",
    )
    bad_ok, bad_msg = verify_provenance_binding(identity, corrupt_checksum, manifest)
    assert not bad_ok
    assert "checksum mismatch" in bad_msg.lower()


def test_gate_blocks_unsupported_and_unverified_sources():
    """Zeek and metadata-only telemetry sources are routed to Trace/Risk but blocked from ML."""
    gate = InferenceEligibilityGate()
    adapter = ZeekConnAdapter()
    event = adapter.adapt_record(
        {"id.orig_h": "10.0.0.1", "id.orig_p": 443, "id.resp_h": "10.0.0.2", "id.resp_p": 53}
    )

    decision = gate.evaluate([event])
    assert not decision.can_proceed_to_ml
    assert decision.decision == "ABSTAINED"
    assert decision.eligibility_status == InferenceEligibility.FEATURE_INCOMPATIBLE
    assert decision.route_to_trace_engine is True
    assert decision.route_to_risk_engine is True
