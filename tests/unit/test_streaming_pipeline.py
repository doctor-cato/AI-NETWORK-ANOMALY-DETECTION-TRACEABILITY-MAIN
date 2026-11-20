"""Unit tests for Streaming Event Pipeline and Micro-Batching.

Validates Issue #131 for NetFlow Sentinel v2.0.
"""

from datetime import datetime, timezone

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind, RawProvenance
from network_anomaly.streaming.pipeline import BackpressurePolicy, StreamingEventPipeline


def make_dummy_event(idx: int) -> CanonicalSecurityEvent:
    return CanonicalSecurityEvent(
        event_timestamp=datetime.now(timezone.utc),
        event_kind=EventKind.FLOW,
        source_id="test_stream",
        source_ip=f"10.0.0.{idx % 250}",
        raw_provenance=RawProvenance(source_file="stream.log", adapter_name="TestStreamAdapter"),
    )


class TestStreamingPipeline:
    def test_enqueue_and_fetch_micro_batch(self):
        pipeline = StreamingEventPipeline(capacity=100, batch_size=10, max_batch_latency_ms=10.0)
        for i in range(25):
            pipeline.enqueue(make_dummy_event(i))

        batch_1 = pipeline.fetch_micro_batch(timeout_sec=0.1)
        assert len(batch_1) == 10

        batch_2 = pipeline.fetch_micro_batch(timeout_sec=0.1)
        assert len(batch_2) == 10

        batch_3 = pipeline.fetch_micro_batch(timeout_sec=0.1)
        assert len(batch_3) == 5

        # Empty queue returns empty list after timeout
        empty_batch = pipeline.fetch_micro_batch(timeout_sec=0.01)
        assert len(empty_batch) == 0

    def test_backpressure_drop_oldest(self):
        # Small capacity buffer
        pipeline = StreamingEventPipeline(
            capacity=5, backpressure_policy=BackpressurePolicy.DROP_OLDEST
        )
        # Push 10 events
        for i in range(10):
            pipeline.enqueue(make_dummy_event(i))

        metrics = pipeline.get_metrics()
        assert metrics.total_enqueued == 10
        assert metrics.total_dropped == 5

        flushed = pipeline.flush_all()
        assert len(flushed) == 5
        # Remaining items should be the latest (5, 6, 7, 8, 9)
        assert flushed[-1].source_ip == "10.0.0.9"
