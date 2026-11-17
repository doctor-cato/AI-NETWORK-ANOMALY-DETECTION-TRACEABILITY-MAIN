"""Streaming Event Pipeline with Buffering, Micro-Batching, and Backpressure Management.

Implements Issue #131 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import collections
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from network_anomaly.canonical.event import CanonicalSecurityEvent


class BackpressurePolicy(str, Enum):
    DROP_OLDEST = "DROP_OLDEST"
    BLOCK = "BLOCK"


@dataclass
class StreamingPipelineMetrics:
    total_enqueued: int = 0
    total_processed: int = 0
    total_dropped: int = 0
    queue_utilization_pct: float = 0.0
    avg_batch_size: float = 0.0
    throughput_events_per_sec: float = 0.0
    avg_latency_ms: float = 0.0


class StreamingEventPipeline:
    """Bounded, thread-safe streaming ring buffer with dynamic micro-batching and backpressure."""

    def __init__(
        self,
        capacity: int = 10_000,
        batch_size: int = 64,
        max_batch_latency_ms: float = 50.0,
        backpressure_policy: BackpressurePolicy = BackpressurePolicy.DROP_OLDEST,
    ):
        self.capacity = capacity
        self.batch_size = batch_size
        self.max_batch_latency_ms = max_batch_latency_ms
        self.backpressure_policy = backpressure_policy

        self._queue: collections.deque[Tuple[CanonicalSecurityEvent, float]] = collections.deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._is_running = False

        self.total_enqueued = 0
        self.total_processed = 0
        self.total_dropped = 0
        self._batch_sizes: List[int] = []
        self._latencies: List[float] = []
        self._start_time = time.perf_counter()

    def enqueue(self, event: CanonicalSecurityEvent) -> bool:
        """Enqueue an event into the bounded ring buffer with backpressure policy."""
        now = time.perf_counter()
        with self._lock:
            if len(self._queue) >= self.capacity:
                if self.backpressure_policy == BackpressurePolicy.DROP_OLDEST:
                    self._queue.popleft()
                    self.total_dropped += 1
                elif self.backpressure_policy == BackpressurePolicy.BLOCK:
                    return False  # Producer must back off

            self._queue.append((event, now))
            self.total_enqueued += 1
            self._not_empty.notify()
            return True

    def enqueue_batch(self, events: List[CanonicalSecurityEvent]) -> int:
        """Enqueue a batch of events."""
        enqueued_count = 0
        for ev in events:
            if self.enqueue(ev):
                enqueued_count += 1
        return enqueued_count

    def fetch_micro_batch(self, timeout_sec: float = 0.1) -> List[CanonicalSecurityEvent]:
        """Fetch up to batch_size events, waiting at most max_batch_latency_ms."""
        batch: List[CanonicalSecurityEvent] = []
        start_wait = time.perf_counter()

        with self._lock:
            # Wait until at least 1 item is available or timeout
            while not self._queue:
                remaining = timeout_sec - (time.perf_counter() - start_wait)
                if remaining <= 0:
                    return []
                self._not_empty.wait(timeout=remaining)

            # Pop up to batch_size items
            now = time.perf_counter()
            while self._queue and len(batch) < self.batch_size:
                ev, enq_time = self._queue.popleft()
                batch.append(ev)
                self._latencies.append((now - enq_time) * 1000.0)

            self.total_processed += len(batch)
            self._batch_sizes.append(len(batch))

        return batch

    def flush_all(self) -> List[CanonicalSecurityEvent]:
        """Flush and return all remaining events in the buffer."""
        flushed: List[CanonicalSecurityEvent] = []
        with self._lock:
            while self._queue:
                ev, _ = self._queue.popleft()
                flushed.append(ev)
            self.total_processed += len(flushed)
        return flushed

    def get_metrics(self) -> StreamingPipelineMetrics:
        """Calculate live streaming pipeline performance and resource metrics."""
        with self._lock:
            q_len = len(self._queue)
            utilization = round((q_len / self.capacity) * 100.0, 2)

        elapsed = max(0.001, time.perf_counter() - self._start_time)
        throughput = round(self.total_processed / elapsed, 2)
        avg_batch = round(sum(self._batch_sizes) / len(self._batch_sizes), 1) if self._batch_sizes else 0.0
        avg_lat = round(sum(self._latencies[-1000:]) / len(self._latencies[-1000:]), 2) if self._latencies else 0.0

        return StreamingPipelineMetrics(
            total_enqueued=self.total_enqueued,
            total_processed=self.total_processed,
            total_dropped=self.total_dropped,
            queue_utilization_pct=utilization,
            avg_batch_size=avg_batch,
            throughput_events_per_sec=throughput,
            avg_latency_ms=avg_lat,
        )
