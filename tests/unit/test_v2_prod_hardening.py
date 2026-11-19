"""Unit tests for v2 production hardening remediations (PROD-01..04 & ModelRegistry)."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from network_anomaly.api.db import DatabaseManager
from network_anomaly.behavioral import (
    BehavioralVectorBuilder,
    EntityBaselineProfiler,
    SessionSummary,
)
from network_anomaly.crypto.key_manager import KeyManager
from network_anomaly.crypto.rotation import KeyRotationPolicy, RotationDecision, RotationTrigger
from network_anomaly.ingestion.adapters.v2_adapter import (
    ApplicationWebAdapter,
    IdentityAuthAdapter,
    parse_timestamp_utc,
)
from network_anomaly.ingestion.registry import SourceRegistry
from network_anomaly.models.registry import ModelReadiness, ModelStatus


def test_parse_timestamp_utc_fails_closed_on_invalid_input():
    with pytest.raises(ValueError, match="Invalid or missing timestamp"):
        parse_timestamp_utc(None)
    with pytest.raises(ValueError, match="Invalid or missing timestamp"):
        parse_timestamp_utc("   ")
    with pytest.raises(ValueError, match="Invalid or missing timestamp"):
        parse_timestamp_utc("not-a-valid-ts")


def test_web_adapter_strips_sensitive_query_params_and_fails_closed():
    adapter = ApplicationWebAdapter()
    line = (
        "192.168.1.50 - - [05/Nov/2020:08:15:30 +0000] "
        '"GET /login?token=secret123&next=%2Fdash&api_key=k99 HTTP/1.1" 200 512 "-" "curl/8.0"'
    )
    ev = adapter.adapt_line(line)
    assert ev.http_data is not None
    assert "secret123" not in ev.http_data.url
    assert "k99" not in ev.http_data.url
    assert "next=%2Fdash" in ev.http_data.url

    with pytest.raises(ValueError, match="Malformed HTTP log line"):
        adapter.adapt_line("completely invalid apache line")


def test_auth_adapter_parses_syslog_dates_and_fails_closed():
    adapter = IdentityAuthAdapter(default_year=2026)
    line = "Dec 14 13:22:05 auth01 sshd[42]: Failed password for alice from 10.20.30.40 port 50000 ssh2"
    ev = adapter.adapt_line(line)
    assert ev.event_timestamp == datetime(2026, 12, 14, 13, 22, 5, tzinfo=timezone.utc)
    assert ev.source_ip == "10.20.30.40"
    assert ev.auth_data is not None and ev.auth_data.username == "alice"

    iso_line = "2026-03-15T10:00:00Z auth01 sshd[99]: Accepted publickey for bob from 10.1.2.3 port 22 ssh2"
    ev_iso = adapter.adapt_line(iso_line)
    assert ev_iso.event_timestamp == datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)

    with pytest.raises(ValueError):
        adapter.adapt_line("random malformed log without timestamp or auth fields")


def test_source_registry_resolves_and_instantiates_v2_adapters():
    registry = SourceRegistry()
    for sid in ("v2_netflow", "v2_dns", "v2_web", "v2_auth", "v2_audit"):
        source_def = registry.get_source(sid)
        assert source_def.trace_supported is True
        adapter = registry.create_adapter(sid)
        assert adapter.source_id == sid


def test_behavioral_missing_tracking_and_entity_profiler():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    session_ok = SessionSummary(
        session_id="s1",
        entity_key="host:10.0.0.1",
        start_time=now,
        end_time=now + timedelta(seconds=10),
        event_count=5,
        duration_seconds=10.0,
        bytes_in=500,
        bytes_out=1500,
        pkts_in=5,
        pkts_out=10,
        bytes_ratio=0.33,
        pkts_ratio=0.5,
        unique_ports=2,
        unique_protocols=1,
        syn_flag_count=1,
        rst_flag_count=0,
        dns_query_count=1,
        http_request_count=2,
        auth_failure_count=0,
        mean_iat_ms=50.0,
        std_iat_ms=10.0,
    )
    builder = BehavioralVectorBuilder()
    vec1 = builder.build_vector(session_ok)
    assert vec1.missing_feature_count == 0
    assert vec1.missing_feature_names == ()

    session_nan = SessionSummary(
        **{**session_ok.__dict__, "session_id": "s2", "bytes_ratio": float("nan")}
    )
    vec2 = builder.build_vector(session_nan)
    assert vec2.missing_feature_count == 1
    assert "bytes_ratio_clipped" in vec2.missing_feature_names

    profiler = EntityBaselineProfiler(window_size=5)
    assert profiler.score_deviation(vec1)["has_baseline"] is False
    profiler.update(vec1)
    score = profiler.score_deviation(vec1)
    assert score["has_baseline"] is True
    assert score["cosine_similarity"] == pytest.approx(1.0, abs=1e-5)
    assert score["deviation_score"] == pytest.approx(0.0, abs=1e-5)


def test_db_manager_initializes_v2_tables_and_persists_unified_events(tmp_path: Path):
    db_file = tmp_path / "v2.db"
    db = DatabaseManager(db_file)
    with sqlite3.connect(str(db_file)) as conn:
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        }
    assert {"unified_security_events", "behavioral_vectors", "encrypted_vault"}.issubset(tables)

    db.insert_unified_security_event(
        {
            "event_id": "evt-v2-1",
            "event_timestamp": "2026-01-01T00:00:00+00:00",
            "event_kind": "FLOW",
            "source_id": "v2_netflow",
            "entity_id": "host:192.168.1.10",
            "source_ip": "192.168.1.10",
            "dest_ip": "10.0.0.1",
            "source_port": 44444,
            "dest_port": 443,
            "protocol": "TCP",
            "is_ml_complete": True,
        }
    )
    rows = db.query_unified_security_events(entity_id="host:192.168.1.10")
    assert len(rows) == 1
    assert rows[0]["event_id"] == "evt-v2-1"
    assert rows[0]["is_ml_complete"] is True


def test_key_rotation_policy_persists_cooldown_and_rate_limit_across_restarts(tmp_path: Path):
    db_file = tmp_path / "rot.db"
    DatabaseManager(db_file)
    km = KeyManager(keystore_dir=tmp_path / "keys")

    current_time = [datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)]

    def fake_clock() -> datetime:
        return current_time[0]

    policy1 = KeyRotationPolicy(
        key_manager=km,
        db_path=db_file,
        cooldown_seconds=300,
        max_rotations_per_hour=2,
        clock_fn=fake_clock,
    )
    dec1, _ = policy1.execute_rotation(RotationTrigger.MANUAL_ADMIN, domain="behavioral")
    assert dec1 == RotationDecision.EXECUTED

    # Simulate process restart 60s later -> still inside 300s cooldown
    current_time[0] = current_time[0] + timedelta(seconds=60)
    km2 = KeyManager(keystore_dir=tmp_path / "keys")
    policy2 = KeyRotationPolicy(
        key_manager=km2,
        db_path=db_file,
        cooldown_seconds=300,
        max_rotations_per_hour=2,
        clock_fn=fake_clock,
    )
    dec_cool, _ = policy2.execute_rotation(RotationTrigger.MANUAL_ADMIN, domain="behavioral")
    assert dec_cool == RotationDecision.REJECTED_COOLDOWN

    # Advance past cooldown (400s total) -> second rotation allowed
    current_time[0] = current_time[0] + timedelta(seconds=340)
    dec2, _ = policy2.execute_rotation(RotationTrigger.MANUAL_ADMIN, domain="behavioral")
    assert dec2 == RotationDecision.EXECUTED

    # Advance past cooldown again (still inside 1hr window -> rate limit 2/hr must reject)
    current_time[0] = current_time[0] + timedelta(seconds=350)
    policy3 = KeyRotationPolicy(
        key_manager=KeyManager(keystore_dir=tmp_path / "keys"),
        db_path=db_file,
        cooldown_seconds=300,
        max_rotations_per_hour=2,
        clock_fn=fake_clock,
    )
    dec_rate, _ = policy3.execute_rotation(RotationTrigger.MANUAL_ADMIN, domain="behavioral")
    assert dec_rate == RotationDecision.REJECTED_RATE_LIMIT


def test_model_status_exposes_capabilities_and_deployment_tier():
    status = ModelStatus(
        model_key="random_forest",
        display_name="Random Forest",
        model_type="RandomForest",
        readiness=ModelReadiness.VALIDATED,
        artifact_path="artifacts/models/random_forest/random_forest_baseline.joblib",
        capabilities=["binary_classification", "probability_scoring"],
        deployment_tier="PRODUCTION_ELIGIBLE",
    )
    payload = status.to_dict()
    assert payload["deployment_tier"] == "PRODUCTION_ELIGIBLE"
    assert payload["capabilities"] == ["binary_classification", "probability_scoring"]


def test_query_unified_security_events_supports_time_range_filters(tmp_path: Path):
    db = DatabaseManager(tmp_path / "events_time.db")
    timestamps = [
        ("evt-t1", "2026-05-01T10:00:00+00:00"),
        ("evt-t2", "2026-05-01T12:00:00+00:00"),
        ("evt-t3", "2026-05-01T14:00:00+00:00"),
    ]
    for eid, ts in timestamps:
        db.insert_unified_security_event(
            {
                "event_id": eid,
                "event_timestamp": ts,
                "event_kind": "FLOW",
                "source_id": "v2_netflow",
                "entity_id": "host:10.0.0.5",
            }
        )

    assert [e["event_id"] for e in db.query_unified_security_events()] == [
        "evt-t3",
        "evt-t2",
        "evt-t1",
    ]
    ranged = db.query_unified_security_events(
        start_time="2026-05-01T12:00:00+00:00",
        end_time="2026-05-01T14:00:00+00:00",
    )
    assert [e["event_id"] for e in ranged] == ["evt-t3", "evt-t2"]
    start_only = db.query_unified_security_events(start_time="2026-05-01T12:00:00+00:00")
    assert [e["event_id"] for e in start_only] == ["evt-t3", "evt-t2"]
    end_only = db.query_unified_security_events(end_time="2026-05-01T12:00:00+00:00")
    assert [e["event_id"] for e in end_only] == ["evt-t2", "evt-t1"]


def test_key_rotation_policy_persists_and_reloads_risk_score_including_legacy_db(tmp_path: Path):
    legacy_db = tmp_path / "legacy_rot.db"
    conn = sqlite3.connect(str(legacy_db))
    conn.execute("""
        CREATE TABLE rotation_audit (
            rotation_id TEXT PRIMARY KEY,
            triggered_by TEXT NOT NULL,
            old_key_id TEXT,
            new_key_id TEXT NOT NULL,
            dry_run INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'SUCCESS',
            reason TEXT,
            created_at TEXT NOT NULL
        );
        """)
    conn.commit()
    conn.close()

    current_time = [datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)]
    km = KeyManager(keystore_dir=tmp_path / "keys")
    policy1 = KeyRotationPolicy(
        key_manager=km,
        db_path=legacy_db,
        cooldown_seconds=60,
        clock_fn=lambda: current_time[0],
    )
    dec1, _ = policy1.evaluate_adaptive_rotation(
        risk_score=91.25,
        domain="behavioral",
        context={"event_id": "evt-high-risk"},
    )
    assert dec1 == RotationDecision.EXECUTED

    current_time[0] = current_time[0] + timedelta(seconds=120)
    dec2, _ = policy1.execute_rotation(
        trigger=RotationTrigger.MANUAL_ADMIN,
        domain="behavioral",
        risk_score=0.0,
        reason="Zero risk manual rotation",
    )
    assert dec2 == RotationDecision.EXECUTED

    current_time[0] = current_time[0] + timedelta(seconds=120)
    dec3, _ = policy1.execute_rotation(
        trigger=RotationTrigger.MANUAL_ADMIN,
        domain="behavioral",
        reason="No risk score provided",
    )
    assert dec3 == RotationDecision.EXECUTED

    policy_reloaded = KeyRotationPolicy(
        key_manager=KeyManager(keystore_dir=tmp_path / "keys"),
        db_path=legacy_db,
        cooldown_seconds=60,
        clock_fn=lambda: current_time[0],
    )
    history = policy_reloaded.get_audit_history()
    assert len(history) == 3
    assert history[0].risk_score == pytest.approx(91.25)
    assert history[1].risk_score == pytest.approx(0.0)
    assert history[2].risk_score is None

    # Also verify DatabaseManager idempotently handles rotation_audit migration
    legacy_db_2 = tmp_path / "legacy_db_mgr.db"
    conn2 = sqlite3.connect(str(legacy_db_2))
    conn2.execute("""
        CREATE TABLE rotation_audit (
            rotation_id TEXT PRIMARY KEY,
            triggered_by TEXT NOT NULL,
            old_key_id TEXT,
            new_key_id TEXT NOT NULL,
            dry_run INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'SUCCESS',
            reason TEXT,
            created_at TEXT NOT NULL
        );
        """)
    conn2.commit()
    conn2.close()
    db_mgr = DatabaseManager(legacy_db_2)
    with db_mgr.transaction() as c:
        cols = {row["name"] for row in c.execute("PRAGMA table_info(rotation_audit);").fetchall()}
    assert "risk_score" in cols
