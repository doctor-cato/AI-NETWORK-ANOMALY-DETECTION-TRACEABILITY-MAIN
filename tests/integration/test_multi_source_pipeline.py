"""Integration tests for Multi-Source Pipeline and Alignment.

Validates Issue #93 for NetFlow Sentinel v2.0.
"""

from pathlib import Path

from network_anomaly.canonical.event import EventKind, ValidationStatus
from network_anomaly.pipeline.multi_source import MultiSourcePipeline

AIT_SAMPLE_DIR = Path("data/raw/ait")


class TestMultiSourcePipelineIntegration:
    def test_pipeline_on_ait_sample_ground_truth(self):
        flow_records = [
            {
                "FLOW_START_MILLISECONDS": 1604563200000,
                "FLOW_DURATION_MILLISECONDS": 150.0,
                "IPV4_SRC_ADDR": "192.168.1.100",
                "L4_SRC_PORT": 52314,
                "IPV4_DST_ADDR": "192.168.1.10",
                "L4_DST_PORT": 80,
                "PROTOCOL": 6,
                "IN_BYTES": 1240,
                "OUT_BYTES": 4520,
                "IN_PKTS": 10,
                "OUT_PKTS": 12,
                "TCP_FLAGS": 24,
                "Attack": "Benign",
            },
            {
                "FLOW_START_MILLISECONDS": 1604563210000,
                "FLOW_DURATION_MILLISECONDS": 12.0,
                "IPV4_SRC_ADDR": "192.168.1.105",
                "L4_SRC_PORT": 44124,
                "IPV4_DST_ADDR": "192.168.1.10",
                "L4_DST_PORT": 80,
                "PROTOCOL": 6,
                "IN_BYTES": 890,
                "OUT_BYTES": 240,
                "IN_PKTS": 6,
                "OUT_PKTS": 4,
                "TCP_FLAGS": 24,
                "Attack": "Exploits",
            },
        ]

        dns_records = [
            {
                "ts": 1604563200.100,
                "id.orig_h": "192.168.1.100",
                "id.orig_p": 53412,
                "id.resp_h": "192.168.1.1",
                "id.resp_p": 53,
                "query": "intranet.corp",
                "qtype_name": "A",
                "rcode": 0,
                "TTL": 300,
            }
        ]

        web_lines = [
            '192.168.1.100 - - [05/Nov/2020:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"',
            '192.168.1.105 - - [05/Nov/2020:08:00:10 +0000] "POST /api/upload.action HTTP/1.1" 200 240 "-" "Python-requests"',
        ]

        auth_lines = [
            "Nov  5 08:00:00 server01 sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 52314 ssh2"
        ]

        pipeline = MultiSourcePipeline(time_window_sec=3.0)
        bundles, route_only_events, report = pipeline.run_pipeline(
            flow_records=flow_records,
            dns_records=dns_records,
            web_lines=web_lines,
            auth_lines=auth_lines,
            fail_closed=True,
        )

        assert report.total_events_ingested == 6
        assert report.flow_events_count == 2
        assert report.dns_events_count == 1
        assert report.web_events_count == 2
        assert report.auth_events_count == 1

        # Check alignment: Both flows should be correlated with matching IP events in time window
        assert report.aligned_flows_count == 2
        assert report.alignment_rate_pct == 100.0

        # Verify zero imputation on route_only events
        for ev in route_only_events:
            assert ev.is_ml_complete is False
            assert ev.ml_features is None
            if ev.event_kind == EventKind.FLOW:
                assert ev.validation_status == ValidationStatus.FEATURE_INCOMPLETE
            else:
                assert ev.event_kind in (
                    EventKind.DNS,
                    EventKind.WEB,
                    EventKind.AUTH,
                    EventKind.SYSTEM,
                )

    def test_pipeline_determinism(self):
        pipeline = MultiSourcePipeline(time_window_sec=2.0)
        flow_records = [
            {
                "FLOW_START_MILLISECONDS": 1604563200000,
                "IPV4_SRC_ADDR": "10.0.0.5",
                "IPV4_DST_ADDR": "10.0.0.1",
            }
        ]
        bundles_1, _, rep_1 = pipeline.run_pipeline(flow_records=flow_records)
        bundles_2, _, rep_2 = pipeline.run_pipeline(flow_records=flow_records)

        assert rep_1.to_dict() == rep_2.to_dict()
        assert len(bundles_1) == len(bundles_2)
