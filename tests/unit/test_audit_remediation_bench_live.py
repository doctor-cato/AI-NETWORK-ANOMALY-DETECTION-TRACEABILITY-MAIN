"""Regression tests for audit remediations: compatibility tiers, multi-source linkage,
v2 adapter line parsing/anti-imputation, unified_security_events persistence, and live log tailing.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from network_anomaly.api.db import DatabaseManager
from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    DNSData,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS, compute_flow_features_from_base
from network_anomaly.ingestion.adapters import CanonicalFlowV2Adapter
from network_anomaly.ingestion.adapters.v2_adapter import (
    ApplicationDNSAdapter,
    ApplicationWebAdapter,
    IdentityAuthAdapter,
    SystemAuditAdapter,
)
from network_anomaly.ingestion.compatibility import (
    FeatureCompatibilityEvaluator,
    load_v2_benchmark_registry,
)
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus
from network_anomaly.pipeline.multi_source import MultiSourcePipeline
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator
from network_anomaly.streaming.live_service import LiveTelemetryService


def test_compatibility_rf_explicit_tier_and_scope_note() -> None:
    """Option 2A: RF dry-run keeps MODEL_VALIDATED while explicitly exposing RESEARCH_ONLY tier."""
    reg = load_v2_benchmark_registry()
    rf_ev = reg["source:ait-nds-v2::random_forest"]
    assert rf_ev.deployment_tier == "RESEARCH_ONLY"
    assert rf_ev.scope_note == "in_domain_csv_dry_run_only_not_production_certified"
    assert "response_policy.py" in rf_ev.reason

    evaluator = FeatureCompatibilityEvaluator(benchmark_registry=reg)
    rec = {col: 1.0 for col in ML_FEATURE_COLUMNS}
    rec["protocol_num"] = 6.0
    event = CanonicalFlowV2Adapter(source_id="source:ait-nds-v2").adapt_record(rec)
    report = evaluator.evaluate_events([event])
    assert report.validation_status == ValidationStatus.MODEL_VALIDATED
    assert report.inference_eligibility == InferenceEligibility.PREDICTION_AVAILABLE
    assert report.deployment_tier == "RESEARCH_ONLY"
    assert report.scope_note == "in_domain_csv_dry_run_only_not_production_certified"


def test_multi_source_pipeline_reports_ait_linkage_not_verified() -> None:
    pipeline = MultiSourcePipeline(time_window_sec=3.0)
    flow_records = [
        {
            "timestamp_ms": 1604563200000,
            "duration_ms": 100.0,
            "source_ip": "192.168.1.100",
            "source_port": 52314,
            "dest_ip": "192.168.1.10",
            "dest_port": 80,
            "protocol_num": 6,
            "bytes_in": 1240,
            "bytes_out": 4520,
            "pkts_in": 10,
            "pkts_out": 12,
        }
    ]
    dns_records = [
        {
            "ts": 1604563200.1,
            "id.orig_h": "192.168.1.100",
            "id.resp_h": "192.168.1.1",
            "query": "example.internal",
        }
    ]
    _, _, report = pipeline.run_pipeline(flow_records=flow_records, dns_records=dns_records)
    assert report.ait_linkage_status == "NOT_VERIFIED"
    assert any(
        "AIT-NDS-v2 <-> AIT-LDS-v2.1 direct UID linkage NOT VERIFIED" in w for w in report.warnings
    )
    as_dict = report.to_dict()
    assert as_dict["ait_linkage_status"] == "NOT_VERIFIED"
    assert as_dict["warnings"] == report.warnings


def test_v2_adapters_adapt_line_dns_system_and_avoid_fake_fallbacks() -> None:
    dns_adapter = ApplicationDNSAdapter()
    suricata_line = json.dumps(
        {
            "timestamp": "2026-11-18T12:00:00Z",
            "event_type": "dns",
            "src_ip": "10.0.0.25",
            "dest_ip": "1.1.1.1",
            "src_port": 53001,
            "dest_port": 53,
            "dns": {"rrname": "c2.example.org", "rrtype": "TXT", "rcode": "NXDOMAIN", "ttl": 60},
        }
    )
    ev_dns_json = dns_adapter.adapt_line(suricata_line, filename="eve.json", line_idx=1)
    assert ev_dns_json.event_kind == EventKind.DNS
    assert ev_dns_json.source_ip == "10.0.0.25"
    assert ev_dns_json.dns_data is not None
    assert ev_dns_json.dns_data.query_name == "c2.example.org"
    assert ev_dns_json.dns_data.rcode == 3
    assert ev_dns_json.dns_data.ttl_answer == 60

    zeek_tsv = (
        "1604563200.5\tC123abc\t192.168.1.55\t51234\t8.8.8.8\t53\tudp\t42\t0.01\t"
        "api.example.net\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t1.2.3.4\t300.0\tF"
    )
    ev_dns_tsv = dns_adapter.adapt_line(zeek_tsv, filename="dns.log", line_idx=2)
    assert ev_dns_tsv.source_ip == "192.168.1.55"
    assert ev_dns_tsv.dest_ip == "8.8.8.8"
    assert ev_dns_tsv.dns_data is not None
    assert ev_dns_tsv.dns_data.query_name == "api.example.net"
    assert ev_dns_tsv.dns_data.ttl_answer == 300

    # No fake "0.0.0.0" when IP omitted
    ev_dns_no_ip = dns_adapter.adapt_record({"ts": 1604563200.0, "query": "noip.example"})
    assert ev_dns_no_ip.source_ip is None
    assert ev_dns_no_ip.dest_ip is None
    assert ev_dns_no_ip.entity_id is None

    with pytest.raises(ValueError):
        dns_adapter.adapt_line("#fields\tts\tuid")

    web_adapter = ApplicationWebAdapter()
    ev_web = web_adapter.adapt_line(
        '10.1.2.3 - - [05/Nov/2020:08:00:00 +0000] "GET /health HTTP/1.1" 200 12 "-" "curl"'
    )
    assert ev_web.dest_ip is None

    auth_adapter = IdentityAuthAdapter(default_year=2026)
    ev_auth = auth_adapter.adapt_record(
        {"timestamp": "2026-11-18T12:00:00Z", "user": "alice", "result": "Accepted"}
    )
    assert ev_auth.source_ip is None
    assert ev_auth.entity_id == "user:alice"

    sys_adapter = SystemAuditAdapter(default_year=2026)
    ev_sys_json = sys_adapter.adapt_line(
        json.dumps(
            {
                "UtcTime": "2026-11-18T12:05:00Z",
                "Image": "/usr/bin/curl",
                "ProcessId": 4242,
                "RuleName": "EXECVE",
            }
        )
    )
    assert ev_sys_json.event_kind == EventKind.SYSTEM
    assert ev_sys_json.entity_id is None
    assert ev_sys_json.system_data is not None
    assert ev_sys_json.system_data.process_name == "/usr/bin/curl"
    assert ev_sys_json.system_data.process_id == 4242

    ev_sys_auditd = sys_adapter.adapt_line(
        'type=SYSCALL msg=audit(1604563200.123:456): arch=c000003e pid=999 comm="python3" node=web01 res=success'
    )
    assert ev_sys_auditd.entity_id == "host:web01"
    assert ev_sys_auditd.system_data is not None
    assert ev_sys_auditd.system_data.process_name == "python3"
    assert ev_sys_auditd.system_data.return_code == 0

    ev_sys_syslog = sys_adapter.adapt_line(
        "2026-11-18T12:10:00Z db01 systemd[1]: Started NetFlow collector."
    )
    assert ev_sys_syslog.entity_id == "host:db01"
    assert ev_sys_syslog.system_data is not None
    assert ev_sys_syslog.system_data.process_name == "systemd"
    assert ev_sys_syslog.system_data.process_id == 1

    with pytest.raises(ValueError):
        sys_adapter.adapt_line("unparseable audit line")


def test_live_orchestrator_persists_unified_security_events(tmp_path: Path) -> None:
    db_file = tmp_path / "orchestrator.db"
    orch = LiveSystemOrchestrator(db_path=db_file, keystore_dir=tmp_path / "keys")

    feats = compute_flow_features_from_base(
        duration_ms=40.0,
        bytes_in=800.0,
        bytes_out=1600.0,
        pkts_in=6.0,
        pkts_out=8.0,
        protocol_num=6,
    )
    flow_ev = CanonicalSecurityEvent(
        event_timestamp=datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc),
        event_kind=EventKind.FLOW,
        source_id="test:live",
        entity_id="host:10.0.0.8",
        source_ip="10.0.0.8",
        dest_ip="192.168.1.20",
        source_port=51000,
        dest_port=443,
        protocol="TCP",
        flow_metrics=FlowMetrics(
            duration_ms=40.0, bytes_in=800, bytes_out=1600, pkts_in=6, pkts_out=8
        ),
        raw_provenance=RawProvenance(source_file="live.csv", adapter_name="test"),
        ml_features=dict(feats),
        is_ml_complete=True,
    )
    dns_ev = CanonicalSecurityEvent(
        event_timestamp=datetime(2026, 11, 18, 12, 1, tzinfo=timezone.utc),
        event_kind=EventKind.DNS,
        source_id="source:zeek-dns",
        entity_id="host:10.0.0.8",
        source_ip="10.0.0.8",
        dest_ip="1.1.1.1",
        dns_data=DNSData(query_name="lookup.example", query_type="A", rcode=0),
        raw_provenance=RawProvenance(source_file="dns.log", adapter_name="ApplicationDNSAdapter"),
        is_ml_complete=False,
    )

    orch.process_event(flow_ev)
    orch.process_event(dns_ev)

    db = DatabaseManager(db_file)
    rows = db.query_unified_security_events(entity_id="host:10.0.0.8", limit=10)
    assert len(rows) == 2
    by_id = {r["event_id"]: r for r in rows}
    assert by_id[flow_ev.event_id]["is_ml_complete"] is True
    assert by_id[dns_ev.event_id]["is_ml_complete"] is False
    assert by_id[dns_ev.event_id]["event_kind"] == "dns"


def test_live_telemetry_service_tails_log_paths_into_pipeline_and_db(tmp_path: Path) -> None:
    log_file = tmp_path / "eve_and_auth.log"
    log_file.write_text("", encoding="utf-8")
    db_file = tmp_path / "live_tail.db"

    service = LiveTelemetryService(
        host="127.0.0.1",
        port=0,
        db_path=db_file,
        keystore_dir=tmp_path / "keys",
        log_paths=[log_file],
        batch_size=4,
    )
    service.start()
    try:
        dns_eve = json.dumps(
            {
                "timestamp": "2026-11-18T13:00:00Z",
                "event_type": "dns",
                "src_ip": "10.20.30.40",
                "dest_ip": "8.8.8.8",
                "src_port": 55000,
                "dest_port": 53,
                "dns": {"rrname": "beacon.example.com", "rrtype": "A", "rcode": 0},
            }
        )
        auth_line = "Nov 18 13:00:05 srv01 sshd[1234]: Failed password for invalid user admin from 10.20.30.40 port 44444 ssh2"
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(dns_eve + "\n")
            fh.write(auth_line + "\n")

        processed = service.wait_until_processed(2, timeout_s=5.0)
        assert processed == 2
        st = service.status()
        assert len(st["log_tailers"]) == 1
        assert st["log_tailers"][0]["lines_read"] == 2
        assert st["log_tailers"][0]["error_lines"] == 0

        results = service.recent_results(limit=10)
        assert len(results) == 2
        db = DatabaseManager(db_file)
        persisted = db.query_unified_security_events(limit=10)
        assert len(persisted) == 2
        assert {r["event_kind"] for r in persisted} == {"dns", "auth"}
    finally:
        service.stop()
