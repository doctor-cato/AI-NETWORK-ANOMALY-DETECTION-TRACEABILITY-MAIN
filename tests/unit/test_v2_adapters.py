"""Unit tests for Multi-source V2 Adapters and Attack Taxonomy.

Validates Issues #86, #87, #88, #89, #90 for NetFlow Sentinel v2.0.
"""

from datetime import datetime, timezone
import pytest

from network_anomaly.canonical.event import EventKind, ValidationStatus
from network_anomaly.data.taxonomy import (
    CANONICAL_ATTACK_CATEGORIES,
    harmonize_attack_label,
)
from network_anomaly.ingestion.adapters.v2_adapter import (
    ApplicationDNSAdapter,
    ApplicationWebAdapter,
    IdentityAuthAdapter,
    SystemAuditAdapter,
    UnifiedNetFlowAdapter,
    parse_timestamp_utc,
)


class TestTimestampNormalization:
    def test_epoch_seconds_and_milliseconds(self):
        # Epoch seconds (1600000000 -> 2020-09-13T12:26:40Z)
        dt_s = parse_timestamp_utc(1600000000)
        assert dt_s.year == 2020
        assert dt_s.tzinfo == timezone.utc

        # Epoch milliseconds (1600000000000)
        dt_ms = parse_timestamp_utc(1600000000000)
        assert dt_ms.year == 2020
        assert dt_ms.tzinfo == timezone.utc
        assert dt_s == dt_ms

    def test_iso_string_and_timezones(self):
        iso_str = "2026-11-17T15:00:00Z"
        dt = parse_timestamp_utc(iso_str)
        assert dt.year == 2026
        assert dt.month == 11
        assert dt.tzinfo == timezone.utc

        # Offset timezone (+07:00)
        iso_offset = "2026-11-17T22:00:00+07:00"
        dt_off = parse_timestamp_utc(iso_offset)
        assert dt_off.hour == 22 or dt_off.astimezone(timezone.utc).hour == 15


class TestAttackTaxonomy:
    def test_taxonomy_harmonization(self):
        assert harmonize_attack_label("benign") == "Benign"
        assert harmonize_attack_label("0") == "Benign"
        assert harmonize_attack_label("portscan") == "Reconnaissance"
        assert harmonize_attack_label("sqli") == "Exploits"
        assert harmonize_attack_label("dos") == "DoS"
        assert harmonize_attack_label("worm") == "Worms"
        assert harmonize_attack_label("backdoor") == "Backdoors"
        assert harmonize_attack_label("unknown_strange_traffic") == "Suspicious"

    def test_label_not_in_ml_input_vector(self):
        adapter = UnifiedNetFlowAdapter()
        raw = {
            "FLOW_START_MILLISECONDS": 1604563200000,
            "IPV4_SRC_ADDR": "192.168.1.100",
            "IPV4_DST_ADDR": "10.0.0.1",
            "Attack": "Reconnaissance",
            "Label": 1,
        }
        event = adapter.adapt_record(raw)
        if event.ml_features:
            assert "Attack" not in event.ml_features
            assert "Label" not in event.ml_features


class TestAdapters:
    def test_unified_netflow_adapter(self):
        adapter = UnifiedNetFlowAdapter()
        raw = {
            "FLOW_START_MILLISECONDS": 1604563200000,
            "FLOW_DURATION_MILLISECONDS": 120.0,
            "IPV4_SRC_ADDR": "192.168.1.100",
            "IPV4_DST_ADDR": "192.168.1.10",
            "L4_SRC_PORT": 44321,
            "L4_DST_PORT": 80,
            "PROTOCOL": 6,
            "IN_BYTES": 1500,
            "OUT_BYTES": 4200,
            "IN_PKTS": 10,
            "OUT_PKTS": 12,
            "TCP_FLAGS": 24,
        }
        event = adapter.adapt_record(raw)
        assert event.event_kind == EventKind.FLOW
        assert event.source_ip == "192.168.1.100"
        assert event.dest_port == 80
        assert event.flow_metrics is not None
        assert event.flow_metrics.bytes_in == 1500
        assert event.flow_metrics.tcp_flags == 24

    def test_application_dns_adapter(self):
        adapter = ApplicationDNSAdapter()
        raw = {
            "ts": 1604563200.123,
            "id.orig_h": "192.168.1.100",
            "id.resp_h": "1.1.1.1",
            "query": "malicious-c2.example.com",
            "qtype_name": "A",
            "rcode": 0,
            "TTL": 300,
        }
        event = adapter.adapt_record(raw)
        assert event.event_kind == EventKind.DNS
        assert event.is_ml_complete is False  # Route-only
        assert event.dns_data is not None
        assert event.dns_data.query_name == "malicious-c2.example.com"

    def test_application_web_adapter(self):
        adapter = ApplicationWebAdapter()
        log_line = '192.168.1.105 - - [05/Nov/2020:08:00:10 +0000] "POST /api/upload.action HTTP/1.1" 200 240 "-" "Python-requests"'
        event = adapter.adapt_line(log_line)
        assert event.event_kind == EventKind.WEB
        assert event.source_ip == "192.168.1.105"
        assert event.is_ml_complete is False
        assert event.http_data is not None
        assert event.http_data.method == "POST"
        assert event.http_data.status_code == 200

    def test_identity_auth_adapter(self):
        adapter = IdentityAuthAdapter()
        log_line = "Nov  5 08:00:08 server01 sshd[1288]: Failed password for invalid user root from 192.168.1.105 port 44120 ssh2"
        event = adapter.adapt_line(log_line)
        assert event.event_kind == EventKind.AUTH
        assert event.source_ip == "192.168.1.105"
        assert event.auth_data is not None
        assert event.auth_data.username == "root"
        assert event.auth_data.auth_result == "FAILURE"
