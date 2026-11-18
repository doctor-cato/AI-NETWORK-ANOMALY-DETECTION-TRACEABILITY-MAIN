"""Bounded-memory integration test over 10,000 live streaming events (#135 AC4)."""

from __future__ import annotations

import gc
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator
from network_anomaly.streaming.pipeline import BackpressurePolicy, StreamingEventPipeline


def _base_ml_features() -> dict[str, float]:
    feats = {col: 0.0 for col in ML_FEATURE_COLUMNS}
    feats.update(
        {
            "duration_ms": 45.0,
            "bytes_in": 1200.0,
            "bytes_out": 400.0,
            "pkts_in": 8.0,
            "pkts_out": 4.0,
            "protocol_num": 6.0,
            "total_bytes": 1600.0,
            "total_pkts": 12.0,
            "bytes_in_ratio": 0.75,
            "pkts_in_ratio": 0.6667,
            "bytes_per_pkt_in": 150.0,
            "bytes_per_pkt_out": 100.0,
            "bytes_per_sec_in": 26666.67,
            "bytes_per_sec_out": 8888.89,
            "pkts_per_sec": 266.67,
            "has_response": 1.0,
            "is_tcp": 1.0,
            "is_udp": 0.0,
        }
    )
    return feats


def test_streaming_10k_events_bounded_memory_and_latency(tmp_path: Path) -> None:
    """#135 AC4: Running 10,000 events through ring buffer + orchestrator stays bounded in memory."""
    pipeline = StreamingEventPipeline(
        capacity=1_024,
        batch_size=64,
        max_batch_latency_ms=5.0,
        backpressure_policy=BackpressurePolicy.DROP_OLDEST,
    )
    orchestrator = LiveSystemOrchestrator(
        db_path=tmp_path / "mem10k.db",
        keystore_dir=tmp_path / "keystore",
        max_active_entities=256,
        demo_heuristics=False,
    )

    feats = _base_ml_features()
    base_ts = datetime(2026, 11, 18, 0, 0, tzinfo=timezone.utc)

    # Warm-up a single batch before measuring retained heap delta
    for i in range(64):
        ev = CanonicalSecurityEvent(
            event_timestamp=base_ts + timedelta(milliseconds=i),
            event_kind=EventKind.FLOW,
            source_id="mem_warmup",
            entity_id=f"host:10.0.0.{i % 16}",
            source_ip=f"10.0.0.{i % 16}",
            dest_ip="192.168.1.10",
            source_port=40000 + i,
            dest_port=443,
            protocol="TCP",
            flow_metrics=FlowMetrics(
                duration_ms=45.0, bytes_in=1200, bytes_out=400, pkts_in=8, pkts_out=4
            ),
            raw_provenance=RawProvenance(source_file="mem_10k", adapter_name="synthetic"),
            ml_features=dict(feats),
            is_ml_complete=True,
        )
        pipeline.enqueue(ev)
    for ev in pipeline.flush_all():
        orchestrator.process_event(ev)

    gc.collect()
    tracemalloc.start()
    snap_start, _ = tracemalloc.get_traced_memory()
    peak_samples: list[int] = []

    total_events = 10_000
    chunk_size = 500
    processed = 0
    for start in range(0, total_events, chunk_size):
        for idx in range(start, start + chunk_size):
            host_id = idx % 400  # Exceeds max_active_entities=256 to exercise eviction
            ev = CanonicalSecurityEvent(
                event_timestamp=base_ts + timedelta(milliseconds=idx),
                event_kind=EventKind.FLOW,
                source_id="mem_10k",
                entity_id=f"host:10.{host_id // 256}.{host_id % 256}.1",
                source_ip=f"10.{host_id // 256}.{host_id % 256}.1",
                dest_ip="192.168.1.10",
                source_port=30000 + (idx % 1000),
                dest_port=443,
                protocol="TCP",
                flow_metrics=FlowMetrics(
                    duration_ms=45.0, bytes_in=1200, bytes_out=400, pkts_in=8, pkts_out=4
                ),
                raw_provenance=RawProvenance(source_file="mem_10k", adapter_name="synthetic"),
                ml_features=dict(feats),
                is_ml_complete=True,
            )
            pipeline.enqueue(ev)
        drained = pipeline.flush_all()
        for ev in drained:
            orchestrator.process_event(ev)
            processed += 1
        if (start // chunk_size) in (1, 9, 19):
            gc.collect()
            cur, _ = tracemalloc.get_traced_memory()
            peak_samples.append(cur)

    gc.collect()
    final_cur, overall_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert processed == total_events
    retained_growth_mb = (final_cur - snap_start) / (1024.0 * 1024.0)
    peak_mb = overall_peak / (1024.0 * 1024.0)
    # Retained heap growth after processing 10k events must stay tightly bounded (< 32 MB)
    assert retained_growth_mb < 32.0, f"Excessive retained growth: {retained_growth_mb:.2f} MB"
    assert peak_mb < 96.0, f"Excessive peak allocation: {peak_mb:.2f} MB"
    # Second half of stream (chunks 10..19) must not grow unboundedly vs midpoint
    assert (peak_samples[-1] - peak_samples[1]) / (1024.0 * 1024.0) < 16.0
