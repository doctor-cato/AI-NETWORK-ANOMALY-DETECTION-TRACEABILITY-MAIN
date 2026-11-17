"""Cross-Source Event Alignment and Multi-Source Ingestion Pipeline.

Implements Issue #93 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind
from network_anomaly.data.quality_gate import MultiSourceQualityGate
from network_anomaly.ingestion.adapters.v2_adapter import (
    ApplicationDNSAdapter,
    ApplicationWebAdapter,
    IdentityAuthAdapter,
    SystemAuditAdapter,
    UnifiedNetFlowAdapter,
)


@dataclass
class AlignedEventBundle:
    primary_flow: CanonicalSecurityEvent
    correlated_logs: List[CanonicalSecurityEvent] = field(default_factory=list)
    alignment_delta_sec: Optional[float] = None
    alignment_key: Optional[str] = None


@dataclass
class PipelineCoverageReport:
    total_events_ingested: int
    flow_events_count: int
    dns_events_count: int
    web_events_count: int
    auth_events_count: int
    system_events_count: int
    ml_ready_flow_count: int
    route_only_log_count: int
    aligned_flows_count: int
    unaligned_flows_count: int
    alignment_rate_pct: float
    unaligned_reasons: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MultiSourcePipeline:
    """Orchestrates multi-source ingestion, validation gate, and temporal event alignment."""

    def __init__(
        self,
        time_window_sec: float = 3.0,
        quality_gate: Optional[MultiSourceQualityGate] = None,
    ):
        self.time_window_sec = time_window_sec
        self.quality_gate = quality_gate or MultiSourceQualityGate()
        self.netflow_adapter = UnifiedNetFlowAdapter()
        self.dns_adapter = ApplicationDNSAdapter()
        self.web_adapter = ApplicationWebAdapter()
        self.auth_adapter = IdentityAuthAdapter()
        self.system_adapter = SystemAuditAdapter()

    def run_pipeline(
        self,
        flow_records: Optional[List[Dict[str, Any]]] = None,
        dns_records: Optional[List[Dict[str, Any]]] = None,
        web_lines: Optional[List[str]] = None,
        auth_lines: Optional[List[str]] = None,
        system_records: Optional[List[Dict[str, Any]]] = None,
        fail_closed: bool = True,
    ) -> Tuple[List[AlignedEventBundle], List[CanonicalSecurityEvent], PipelineCoverageReport]:
        """Ingest, validate, and align multi-source events with strict no-imputation routing."""
        all_events: List[CanonicalSecurityEvent] = []
        flow_events: List[CanonicalSecurityEvent] = []
        log_events: List[CanonicalSecurityEvent] = []

        # 1. Adapt Flow records
        if flow_records:
            for idx, r in enumerate(flow_records):
                ev = self.netflow_adapter.adapt_record(
                    r, filename="netflow_source.csv", line_idx=idx + 1
                )
                all_events.append(ev)
                flow_events.append(ev)

        # 2. Adapt DNS records
        if dns_records:
            for idx, r in enumerate(dns_records):
                ev = self.dns_adapter.adapt_record(r, filename="dns_source.log", line_idx=idx + 1)
                all_events.append(ev)
                log_events.append(ev)

        # 3. Adapt Web lines
        if web_lines:
            for idx, line in enumerate(web_lines):
                if line.strip():
                    ev = self.web_adapter.adapt_line(line, filename="access.log", line_idx=idx + 1)
                    all_events.append(ev)
                    log_events.append(ev)

        # 4. Adapt Auth lines
        if auth_lines:
            for idx, line in enumerate(auth_lines):
                if line.strip():
                    ev = self.auth_adapter.adapt_line(line, filename="auth.log", line_idx=idx + 1)
                    all_events.append(ev)
                    log_events.append(ev)

        # 5. Adapt System records
        if system_records:
            for idx, r in enumerate(system_records):
                ev = self.system_adapter.adapt_record(r, filename="sysmon.json", line_idx=idx + 1)
                all_events.append(ev)
                log_events.append(ev)

        # Quality Gate validation
        q_report = self.quality_gate.evaluate_events(
            all_events, source_id="multi_source_orchestration"
        )
        if q_report.status == "FAIL" and fail_closed:
            raise ValueError(f"Multi-source Quality Gate REJECTED: {q_report.rejection_reason}")

        # Sort all chronologically
        all_events.sort(key=lambda x: x.event_timestamp)
        flow_events.sort(key=lambda x: x.event_timestamp)
        log_events.sort(key=lambda x: x.event_timestamp)

        # 6. Cross-source Alignment (Sliding Temporal Window)
        aligned_bundles: List[AlignedEventBundle] = []
        unaligned_reasons: Dict[str, int] = {
            "NO_LOG_WITH_MATCHING_IP": 0,
            "TIME_OUT_OF_BOUNDS": 0,
        }
        aligned_count = 0

        for f_ev in flow_events:
            matched_logs: List[CanonicalSecurityEvent] = []
            f_sec = f_ev.event_timestamp.timestamp()
            min_delta: Optional[float] = None

            for l_ev in log_events:
                l_sec = l_ev.event_timestamp.timestamp()
                delta = abs(f_sec - l_sec)

                # Match criteria: IP overlap and temporal proximity
                ip_match = (
                    f_ev.source_ip == l_ev.source_ip
                    or (f_ev.dest_ip and f_ev.dest_ip == l_ev.source_ip)
                    or (l_ev.dest_ip and f_ev.dest_ip == l_ev.dest_ip)
                )

                if ip_match:
                    if delta <= self.time_window_sec:
                        matched_logs.append(l_ev)
                        if min_delta is None or delta < min_delta:
                            min_delta = delta
                    else:
                        unaligned_reasons["TIME_OUT_OF_BOUNDS"] += 1

            if matched_logs:
                aligned_count += 1
                aligned_bundles.append(
                    AlignedEventBundle(
                        primary_flow=f_ev,
                        correlated_logs=matched_logs,
                        alignment_delta_sec=min_delta,
                        alignment_key=f_ev.source_ip,
                    )
                )
            else:
                unaligned_reasons["NO_LOG_WITH_MATCHING_IP"] += 1
                aligned_bundles.append(
                    AlignedEventBundle(
                        primary_flow=f_ev,
                        correlated_logs=[],
                    )
                )

        # 7. Zero Imputation Classification
        ml_ready_flows = [f for f in flow_events if f.is_ml_complete]
        route_only_events = [e for e in all_events if not e.is_ml_complete]

        total_flows = len(flow_events)
        align_rate = round((aligned_count / total_flows) * 100.0, 2) if total_flows > 0 else 0.0

        report = PipelineCoverageReport(
            total_events_ingested=len(all_events),
            flow_events_count=len(flow_events),
            dns_events_count=sum(1 for e in all_events if e.event_kind == EventKind.DNS),
            web_events_count=sum(1 for e in all_events if e.event_kind == EventKind.WEB),
            auth_events_count=sum(1 for e in all_events if e.event_kind == EventKind.AUTH),
            system_events_count=sum(1 for e in all_events if e.event_kind == EventKind.SYSTEM),
            ml_ready_flow_count=len(ml_ready_flows),
            route_only_log_count=len(route_only_events),
            aligned_flows_count=aligned_count,
            unaligned_flows_count=total_flows - aligned_count,
            alignment_rate_pct=align_rate,
            unaligned_reasons=unaligned_reasons,
        )

        return aligned_bundles, route_only_events, report
