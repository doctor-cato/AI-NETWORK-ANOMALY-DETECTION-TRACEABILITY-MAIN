"""Live telemetry service: UDP collector → streaming pipeline → orchestrator.

Implements the execution path required by Issues #131–#137: a real UDP socket
feeds decoded NetFlow v9 / IPFIX events into the bounded streaming pipeline,
and a worker thread runs each event through the :class:`LiveSystemOrchestrator`
(feature contract → AI inference → risk → alerts → behavioral vector → trace).

The service reports what actually happened. ``mode`` is ``LIVE`` only while the
collector socket is bound and the worker thread is alive. Readiness exposes the
per-model registry state so a client can show ``UNAVAILABLE`` instead of
inventing an "AI ready" badge.
"""

from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from network_anomaly.canonical.event import CanonicalSecurityEvent
from network_anomaly.streaming.live_orchestrator import (
    LiveProcessingResult,
    LiveSystemOrchestrator,
)
from network_anomaly.streaming.pipeline import StreamingEventPipeline
from network_anomaly.streaming.realtime_inference import RealtimeInferenceEngine
from network_anomaly.telemetry.collector import UDPFlowCollector

SERVICE_MODE_LIVE = "LIVE"
SERVICE_MODE_STOPPED = "STOPPED"


@dataclass
class ServiceMetrics:
    events_received: int = 0
    events_processed: int = 0
    ml_ready_events: int = 0
    inference_errors: int = 0
    alerts_raised: int = 0
    total_inference_latency_us: float = 0.0
    max_inference_latency_us: float = 0.0
    last_event_at_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        avg = (
            self.total_inference_latency_us / self.events_processed
            if self.events_processed
            else 0.0
        )
        return {
            "events_received": self.events_received,
            "events_processed": self.events_processed,
            "ml_ready_events": self.ml_ready_events,
            "inference_errors": self.inference_errors,
            "alerts_raised": self.alerts_raised,
            "avg_inference_latency_us": round(avg, 3),
            "max_inference_latency_us": round(self.max_inference_latency_us, 3),
            "last_event_at_utc": self.last_event_at_utc,
        }


class LiveTelemetryService:
    """Owns the UDP collector, the streaming pipeline and the processing worker."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        orchestrator: Optional[LiveSystemOrchestrator] = None,
        pipeline: Optional[StreamingEventPipeline] = None,
        inference_engine: Optional[RealtimeInferenceEngine] = None,
        db_path: Optional[Path] = None,
        keystore_dir: Optional[Path] = None,
        demo_heuristics: bool = False,
        queue_capacity: int = 10_000,
        batch_size: int = 32,
        history_capacity: int = 500,
    ) -> None:
        self.collector = UDPFlowCollector(host=host, port=port, queue_capacity=queue_capacity)
        self.pipeline = pipeline or StreamingEventPipeline(
            capacity=queue_capacity, batch_size=batch_size
        )
        self.orchestrator = orchestrator or LiveSystemOrchestrator(
            db_path=db_path,
            keystore_dir=keystore_dir,
            inference_engine=inference_engine,
            demo_heuristics=demo_heuristics,
        )
        self.history_capacity = max(1, int(history_capacity))

        self._results: Deque[LiveProcessingResult] = collections.deque(maxlen=self.history_capacity)
        self._alerts: Deque[Dict[str, Any]] = collections.deque(maxlen=self.history_capacity)
        self._metrics = ServiceMetrics()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._started_at_utc: Optional[str] = None

    # ------------------------------------------------------------- lifecycle
    def start(self) -> Dict[str, Any]:
        if self.is_running:
            return self.status()
        self._stop.clear()
        self.collector.start()
        self._started_at_utc = datetime.now(timezone.utc).isoformat()
        self._worker = threading.Thread(
            target=self._process_loop, name="live-telemetry-worker", daemon=True
        )
        self._worker.start()
        return self.status()

    def stop(self, flush: bool = True, join_timeout_s: float = 5.0) -> Dict[str, Any]:
        self._stop.set()
        self.collector.stop(join_timeout_s=join_timeout_s)
        worker = self._worker
        if worker is not None and worker.is_alive():
            worker.join(timeout=join_timeout_s)
        self._worker = None
        if flush:
            self._drain_collector()
            self._process_batch(self.pipeline.flush_all())
        return self.status()

    @property
    def is_running(self) -> bool:
        return self.collector.is_running and bool(self._worker and self._worker.is_alive())

    @property
    def bound_port(self) -> int:
        return self.collector.bound_port

    # --------------------------------------------------------------- worker
    def _process_loop(self) -> None:
        while not self._stop.is_set():
            self._drain_collector()
            batch = self.pipeline.fetch_micro_batch(timeout_sec=0.05)
            if batch:
                self._process_batch(batch)
        # Final drain so accepted datagrams are not silently lost on shutdown.
        self._drain_collector()
        self._process_batch(self.pipeline.flush_all())

    def _drain_collector(self) -> None:
        pending = self.collector.drain()
        if not pending:
            return
        with self._lock:
            self._metrics.events_received += len(pending)
        self.pipeline.enqueue_batch(pending)

    def _process_batch(self, batch: List[CanonicalSecurityEvent]) -> None:
        for event in batch:
            result = self.orchestrator.process_event(event)
            decision = result.inference_decision
            latency = decision.total_inference_latency_us if decision else 0.0
            with self._lock:
                self._metrics.events_processed += 1
                if result.is_ml_flow:
                    self._metrics.ml_ready_events += 1
                if decision is not None and decision.inference_mode == "UNAVAILABLE":
                    self._metrics.inference_errors += 1
                if decision is not None:
                    self._metrics.total_inference_latency_us += float(latency)
                    self._metrics.max_inference_latency_us = max(
                        self._metrics.max_inference_latency_us, float(latency)
                    )
                if result.alert_generated is not None:
                    self._metrics.alerts_raised += 1
                    self._alerts.append(result.alert_generated.to_dict())
                self._metrics.last_event_at_utc = datetime.now(timezone.utc).isoformat()
                self._results.append(result)

    # --------------------------------------------------------------- queries
    def wait_until_processed(self, minimum: int, timeout_s: float = 5.0) -> int:
        deadline = time.monotonic() + max(0.0, timeout_s)
        while time.monotonic() < deadline:
            with self._lock:
                if self._metrics.events_processed >= minimum:
                    return self._metrics.events_processed
            time.sleep(0.01)
        with self._lock:
            return self._metrics.events_processed

    def recent_results(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._results)[-max(0, limit) :]
        return [item.to_dict() for item in items]

    def recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._alerts)[-max(0, limit) :]

    def status(self) -> Dict[str, Any]:
        pipeline_metrics = self.pipeline.get_metrics()
        collector_stats = self.collector.stats()
        running = self.is_running
        readiness = self.orchestrator.inference_engine.readiness()
        with self._lock:
            metrics = self._metrics.to_dict()
            alert_count = len(self._alerts)
        return {
            "mode": SERVICE_MODE_LIVE if running else SERVICE_MODE_STOPPED,
            "running": running,
            "started_at_utc": self._started_at_utc,
            "bound_port": self.bound_port,
            "collector": collector_stats,
            "pipeline": {
                "total_enqueued": pipeline_metrics.total_enqueued,
                "total_processed": pipeline_metrics.total_processed,
                "total_dropped": pipeline_metrics.total_dropped,
                "queue_utilization_pct": pipeline_metrics.queue_utilization_pct,
                "avg_batch_size": pipeline_metrics.avg_batch_size,
                "throughput_events_per_sec": pipeline_metrics.throughput_events_per_sec,
                "avg_latency_ms": pipeline_metrics.avg_latency_ms,
            },
            "metrics": metrics,
            "alerts_buffered": alert_count,
            "inference": readiness,
        }
