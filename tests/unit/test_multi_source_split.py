"""Unit tests for Multi-source Temporal Splitter and Leakage Audit."""

from dataclasses import dataclass
from datetime import datetime, timezone

from network_anomaly.data.split import MultiSourceTemporalSplitter


@dataclass
class _StubEvent:
    event_timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str


class TestMultiSourceSplit:
    def test_chronological_split_with_zero_overlap(self):
        base_ts = 1600000000
        # 100 sessions across 1000 events
        events = [
            _StubEvent(
                event_timestamp=datetime.fromtimestamp(base_ts + i * 10, tz=timezone.utc),
                source_ip=f"10.0.0.{(i // 10) % 200 + 1}",
                dest_ip="192.168.1.10",
                source_port=40000 + (i // 10),
                dest_port=443,
                protocol="6",
            )
            for i in range(1000)
        ]

        splitter = MultiSourceTemporalSplitter(purge_window_sec=60.0)
        res = splitter.split_events(events, train_ratio=0.70, val_ratio=0.15)

        assert len(res.train_indices) > 0
        assert len(res.val_indices) > 0
        assert len(res.test_indices) > 0
        assert res.overlap_group_count == 0
        assert res.manifest["overlap_group_count"] == 0

    def test_synthetic_leakage_detection_and_purging(self):
        # Create an artificial case where flow group A appears in both Train and Test
        events = [
            _StubEvent(
                event_timestamp=datetime.fromtimestamp(1600000000 + i, tz=timezone.utc),
                source_ip="10.0.0.1",
                dest_ip="192.168.1.10",
                source_port=51000,
                dest_port=443,
                protocol="6",
            )
            for i in range(50)
        ]
        for i in range(50, 80):
            events.append(
                _StubEvent(
                    event_timestamp=datetime.fromtimestamp(1600000000 + i * 100, tz=timezone.utc),
                    source_ip=f"10.0.1.{i}",
                    dest_ip="192.168.1.10",
                    source_port=52000 + i,
                    dest_port=443,
                    protocol="6",
                )
            )
        for i in range(80, 100):
            events.append(
                _StubEvent(
                    event_timestamp=datetime.fromtimestamp(1600000000 + i * 200, tz=timezone.utc),
                    source_ip="10.0.0.1" if i % 2 == 0 else f"10.0.2.{i}",
                    dest_ip="192.168.1.10",
                    source_port=51000 if i % 2 == 0 else 53000 + i,
                    dest_port=443,
                    protocol="6",
                )
            )

        splitter = MultiSourceTemporalSplitter(purge_window_sec=10.0)
        res = splitter.split_events(events, train_ratio=0.50, val_ratio=0.25)

        assert res.purged_rows_count > 0
        assert res.overlap_group_count == 0
        assert all(events[i].source_ip != "10.0.0.1" for i in res.test_indices)
