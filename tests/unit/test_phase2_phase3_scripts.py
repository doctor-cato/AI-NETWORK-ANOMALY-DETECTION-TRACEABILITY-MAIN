"""CI-safe integration & contract tests for Phase 2 real-replay & deployment trust anchor."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_replay_mod():
    path = PROJECT_ROOT / "scripts" / "replay_real_netflow_udp.py"
    spec = importlib.util.spec_from_file_location("replay_real_netflow_udp", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["replay_real_netflow_udp"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_real_udp_replay_pipeline_and_encrypt_flag(tmp_path: Path, monkeypatch) -> None:
    """Verify replay_real_netflow_udp runs end-to-end on CSV rows without needing artifacts."""
    from datetime import datetime, timezone

    from network_anomaly.canonical.event import (
        CanonicalSecurityEvent,
        EventKind,
        FlowMetrics,
        RawProvenance,
    )
    from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS, compute_flow_features_from_base
    from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator

    # 1. Verify encrypt_at_rest=False vs True toggle on LiveSystemOrchestrator
    feats = compute_flow_features_from_base(
        duration_ms=25.0,
        bytes_in=1200.0,
        bytes_out=2400.0,
        pkts_in=10.0,
        pkts_out=12.0,
        protocol_num=6,
    )
    ev = CanonicalSecurityEvent(
        event_timestamp=datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc),
        event_kind=EventKind.FLOW,
        source_id="test:toggle",
        entity_id="host:10.0.0.5",
        source_ip="10.0.0.5",
        dest_ip="192.168.1.10",
        source_port=50000,
        dest_port=443,
        protocol="TCP",
        flow_metrics=FlowMetrics(
            duration_ms=25.0, bytes_in=1200, bytes_out=2400, pkts_in=10, pkts_out=12
        ),
        raw_provenance=RawProvenance(source_file="toggle", adapter_name="test"),
        ml_features=dict(feats),
        is_ml_complete=True,
    )
    orch_plain = LiveSystemOrchestrator(
        db_path=tmp_path / "plain.db",
        keystore_dir=tmp_path / "ks_plain",
        encrypt_at_rest=False,
    )
    res_plain = orch_plain.process_event(ev)
    assert res_plain.behavioral_vector_id is not None
    assert res_plain.behavioral_vector_encrypted is False

    orch_enc = LiveSystemOrchestrator(
        db_path=tmp_path / "enc.db",
        keystore_dir=tmp_path / "ks_enc",
        encrypt_at_rest=True,
    )
    res_enc = orch_enc.process_event(ev)
    assert res_enc.behavioral_vector_id is not None
    assert res_enc.behavioral_vector_encrypted is True

    # 2. Verify real_udp_replay runs fail-closed in deployment without trusted anchor
    rows = []
    for idx, cat in enumerate(["Reconnaissance", "Data_Exfiltration", "Benign"]):
        r = {col: float(feats[col]) for col in ML_FEATURE_COLUMNS}
        r.update(
            {
                "source_ip": f"192.0.2.{10 + idx}",
                "dest_ip": "198.51.100.5",
                "source_port": 51000 + idx,
                "dest_port": 445 if idx == 1 else 80,
                "attack_category": cat,
            }
        )
        rows.append(r)
    src_csv = tmp_path / "sample_real_replay.csv"
    pd.DataFrame(rows).to_csv(src_csv, index=False)

    monkeypatch.delenv("NETFLOW_OOD_GATE_SHA256", raising=False)
    monkeypatch.delenv("NETFLOW_EMBEDDED_OOD_GATE_SHA256", raising=False)
    mod = _load_replay_mod()
    monkeypatch.setattr(mod, "DEFAULT_OOD_GATE_PATH", tmp_path / "missing_ood_gate.json")
    rep = mod.run_real_udp_replay(
        runtime_mode="deployment",
        expected_ood_gate_sha256=None,
        source_csv=src_csv,
        max_per_category=1,
        write_outputs=False,
    )
    assert rep["real_hardware_switch"] is False
    assert rep["replay_metrics"]["flows_decoded"] == 3
    assert rep["replay_metrics"]["events_processed"] == 3
    assert rep["replay_metrics"]["encrypted_behavioral_vectors"] == 3
    assert rep["runtime_policy"]["inference_mode"] == "UNAVAILABLE"


def test_trusted_ood_sha_anchor_resolution_accepts_matching_fixture(tmp_path: Path) -> None:
    """Verify resolve_expected_ood_gate_sha256 + persisted OOD gate verification passes when SHA matches."""
    from network_anomaly.ml.ood_gate import resolve_expected_ood_gate_sha256

    gate_file = tmp_path / "ood_reference_gate.json"
    gate_file.write_text(json.dumps({"schema_version": 1, "status": "FITTED"}), encoding="utf-8")
    digest = hashlib.sha256(gate_file.read_bytes()).hexdigest().lower()
    resolved, src = resolve_expected_ood_gate_sha256(digest)
    assert resolved == digest
    assert src == "explicit_expected_sha256"
