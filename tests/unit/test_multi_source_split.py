"""Unit tests for Multi-source Temporal Splitter and Leakage Audit.

Validates Issue #92 for NetFlow Sentinel v2.0.
"""

from datetime import datetime, timezone

import pandas as pd

from network_anomaly.data.split import MultiSourceTemporalSplitter


class TestMultiSourceSplit:
    def test_chronological_split_with_zero_overlap(self):
        # Create synthetic time-series data with group identifiers
        records = []
        base_ts = 1600000000
        # 100 sessions across 1000 events
        for i in range(1000):
            session_id = f"session_{i // 10}"
            records.append(
                {
                    "timestamp": datetime.fromtimestamp(base_ts + i * 10, tz=timezone.utc),
                    "group_key": session_id,
                    "val": i,
                }
            )
        df = pd.DataFrame(records)

        splitter = MultiSourceTemporalSplitter(
            train_ratio=0.70,
            val_ratio=0.15,
            test_ratio=0.15,
            purge_gap_sec=60.0,
            group_key_col="group_key",
        )

        res = splitter.split(df, timestamp_col="timestamp")

        assert len(res.train_indices) > 0
        assert len(res.val_indices) > 0
        assert len(res.test_indices) > 0
        assert res.manifest["leakage_audit"]["zero_leakage_verified"] is True
        assert res.manifest["leakage_audit"]["train_val_group_overlap"] == 0
        assert res.manifest["leakage_audit"]["train_test_group_overlap"] == 0

    def test_synthetic_leakage_detection_and_purging(self):
        # Create an artificial case where session_A appears in both Train and Test
        records = [
            {
                "timestamp": datetime.fromtimestamp(1600000000 + i, tz=timezone.utc),
                "group_key": "session_A",
                "val": i,
            }
            for i in range(50)
        ]
        # Middle records (Val)
        for i in range(50, 80):
            records.append(
                {
                    "timestamp": datetime.fromtimestamp(1600000000 + i * 100, tz=timezone.utc),
                    "group_key": f"session_val_{i}",
                    "val": i,
                }
            )
        # Test records, intentionally injecting session_A in the test timeframe!
        for i in range(80, 100):
            records.append(
                {
                    "timestamp": datetime.fromtimestamp(1600000000 + i * 200, tz=timezone.utc),
                    "group_key": "session_A" if i % 2 == 0 else f"session_test_{i}",
                    "val": i,
                }
            )

        df = pd.DataFrame(records)
        splitter = MultiSourceTemporalSplitter(
            train_ratio=0.50,
            val_ratio=0.25,
            test_ratio=0.25,
            purge_gap_sec=10.0,
            group_key_col="group_key",
        )

        res = splitter.split(df, timestamp_col="timestamp")

        # The injected session_A events in the test partition MUST be purged
        assert len(res.purged_group_overlap_indices) > 0
        test_df = df.iloc[res.test_indices]
        assert "session_A" not in test_df["group_key"].values
        assert res.manifest["leakage_audit"]["zero_leakage_verified"] is True
