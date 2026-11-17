"""Multi-Mode Execution Manager: Offline, Replay, and Live Monitoring Modes.

Implements Issue #136 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple

from network_anomaly.canonical.event import CanonicalSecurityEvent
from network_anomaly.streaming.live_orchestrator import LiveProcessingResult, LiveSystemOrchestrator
from network_anomaly.telemetry.pcap_reader import LocalPCAPReader


class MonitoringMode(str, Enum):
    OFFLINE = "OFFLINE"
    REPLAY = "REPLAY"
    LIVE = "LIVE"


@dataclass
class ModeExecutionSummary:
    mode: MonitoringMode
    source_name: str
    total_events_processed: int
    anomalies_detected: int
    alerts_raised: int
    adaptive_rotations_triggered: int
    elapsed_seconds: float
    throughput_events_per_sec: float
    started_at_utc: str
    completed_at_utc: str
    speed_factor: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["mode"] = self.mode.value
        return d


class ModeOrchestrator:
    """Manages system execution under OFFLINE, REPLAY, or LIVE operation with identical canonical contracts."""

    def __init__(self, orchestrator: Optional[LiveSystemOrchestrator] = None):
        self.orchestrator = orchestrator or LiveSystemOrchestrator()
        self.pcap_reader = LocalPCAPReader()

    def run_replay_scenario(
        self,
        events: List[CanonicalSecurityEvent],
        source_name: str = "benchmark_replay",
        speed_factor: float = float("inf"),
        callback: Optional[Callable[[LiveProcessingResult], None]] = None,
    ) -> ModeExecutionSummary:
        """Replay recorded security events with controlled temporal pacing."""
        start_utc = datetime.now(timezone.utc).isoformat()
        start_perf = time.perf_counter()

        anomalies = 0
        alerts = 0
        rotations = 0

        # Sort chronologically for realistic replay
        sorted_events = sorted(events, key=lambda e: e.event_timestamp)
        last_event_ts = sorted_events[0].event_timestamp.timestamp() if sorted_events else 0.0

        for ev in sorted_events:
            curr_ts = ev.event_timestamp.timestamp()
            delta_sec = curr_ts - last_event_ts

            if speed_factor != float("inf") and speed_factor > 0 and delta_sec > 0:
                sleep_time = min(0.5, delta_sec / speed_factor)
                time.sleep(sleep_time)

            last_event_ts = curr_ts

            # Process through unified live orchestrator
            res = self.orchestrator.process_event(ev)
            if res.inference_decision and res.inference_decision.ensemble_is_anomaly:
                anomalies += 1
            if res.alert_generated:
                alerts += 1
            if res.key_rotated:
                rotations += 1

            if callback:
                callback(res)

        elapsed = max(0.001, time.perf_counter() - start_perf)
        throughput = round(len(sorted_events) / elapsed, 2)
        end_utc = datetime.now(timezone.utc).isoformat()

        return ModeExecutionSummary(
            mode=MonitoringMode.REPLAY,
            source_name=source_name,
            total_events_processed=len(sorted_events),
            anomalies_detected=anomalies,
            alerts_raised=alerts,
            adaptive_rotations_triggered=rotations,
            elapsed_seconds=round(elapsed, 3),
            throughput_events_per_sec=throughput,
            started_at_utc=start_utc,
            completed_at_utc=end_utc,
            speed_factor=speed_factor,
        )

    def run_pcap_replay(
        self,
        pcap_path: Path,
        speed_factor: float = float("inf"),
    ) -> Tuple[ModeExecutionSummary, List[CanonicalSecurityEvent]]:
        """Synthesize flows from PCAP capture and replay through live stack."""
        events, summary = self.pcap_reader.parse_pcap(pcap_path)
        exec_summary = self.run_replay_scenario(
            events=events,
            source_name=f"pcap:{pcap_path.name}",
            speed_factor=speed_factor,
        )
        return exec_summary, events
