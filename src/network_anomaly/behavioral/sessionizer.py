"""Time-window sessionization and behavioral feature extraction.

Implements Issue #101 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

import numpy as np

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind


@dataclass
class SessionSummary:
    session_id: str
    entity_key: str
    start_time: datetime
    end_time: datetime
    event_count: int
    duration_seconds: float
    bytes_in: int
    bytes_out: int
    pkts_in: int
    pkts_out: int
    bytes_ratio: float
    pkts_ratio: float
    unique_ports: int
    unique_protocols: int
    syn_flag_count: int
    rst_flag_count: int
    dns_query_count: int
    http_request_count: int
    auth_failure_count: int
    mean_iat_ms: float
    std_iat_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "entity_key": self.entity_key,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "event_count": self.event_count,
            "duration_seconds": self.duration_seconds,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "pkts_in": self.pkts_in,
            "pkts_out": self.pkts_out,
            "bytes_ratio": self.bytes_ratio,
            "pkts_ratio": self.pkts_ratio,
            "unique_ports": self.unique_ports,
            "unique_protocols": self.unique_protocols,
            "syn_flag_count": self.syn_flag_count,
            "rst_flag_count": self.rst_flag_count,
            "dns_query_count": self.dns_query_count,
            "http_request_count": self.http_request_count,
            "auth_failure_count": self.auth_failure_count,
            "mean_iat_ms": self.mean_iat_ms,
            "std_iat_ms": self.std_iat_ms,
        }


class EventSessionizer:
    """Aggregates a stream of CanonicalSecurityEvents into discrete behavioral sessions."""

    def __init__(self, session_timeout_seconds: float = 300.0):
        self.session_timeout_seconds = session_timeout_seconds

    def sessionize(self, events: List[CanonicalSecurityEvent]) -> List[SessionSummary]:
        """Group events by entity key and partition into sessions by inactivity gap."""
        if not events:
            return []

        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: e.event_timestamp)

        # Group by entity_key (entity_id if available, else fingerprint from source/service)
        entity_groups: Dict[str, List[CanonicalSecurityEvent]] = {}
        for ev in sorted_events:
            key = (
                ev.entity_id or f"flow:{ev.source_ip}:{ev.source_port}->{ev.dest_ip}:{ev.dest_port}"
            )
            entity_groups.setdefault(key, []).append(ev)

        summaries: List[SessionSummary] = []
        for key, grp in entity_groups.items():
            # Partition into sub-sessions based on timeout gap
            current_subgroup: List[CanonicalSecurityEvent] = [grp[0]]
            for ev in grp[1:]:
                prev_ts = current_subgroup[-1].event_timestamp
                gap = (ev.event_timestamp - prev_ts).total_seconds()
                if gap > self.session_timeout_seconds:
                    summaries.append(self._aggregate_session(key, current_subgroup))
                    current_subgroup = [ev]
                else:
                    current_subgroup.append(ev)
            if current_subgroup:
                summaries.append(self._aggregate_session(key, current_subgroup))

        return summaries

    def _aggregate_session(self, key: str, events: List[CanonicalSecurityEvent]) -> SessionSummary:
        start_time = events[0].event_timestamp
        end_time = events[-1].event_timestamp
        duration = max((end_time - start_time).total_seconds(), 0.001)

        bytes_in = 0
        bytes_out = 0
        pkts_in = 0
        pkts_out = 0
        ports = set()
        protocols = set()
        syn_count = 0
        rst_count = 0
        dns_count = 0
        http_count = 0
        auth_fail_count = 0

        # Compute Inter-Arrival Times (IAT)
        iats = []
        for i in range(1, len(events)):
            iat = (
                events[i].event_timestamp - events[i - 1].event_timestamp
            ).total_seconds() * 1000.0
            iats.append(iat)

        mean_iat = float(np.mean(iats)) if iats else 0.0
        std_iat = float(np.std(iats)) if iats else 0.0

        for ev in events:
            if ev.dest_port is not None:
                ports.add(ev.dest_port)
            if ev.protocol is not None:
                protocols.add(ev.protocol)

            if ev.flow_metrics:
                bytes_in += ev.flow_metrics.bytes_in or 0
                bytes_out += ev.flow_metrics.bytes_out or 0
                pkts_in += ev.flow_metrics.pkts_in or 0
                pkts_out += ev.flow_metrics.pkts_out or 0
                flags = ev.flow_metrics.tcp_flags or 0
                if flags & 0x02:  # SYN
                    syn_count += 1
                if flags & 0x04:  # RST
                    rst_count += 1

            if ev.event_kind == EventKind.DNS:
                dns_count += 1
            elif ev.event_kind == EventKind.WEB:
                http_count += 1
            elif ev.event_kind == EventKind.AUTH:
                if ev.auth_data and ev.auth_data.auth_result == "FAILURE":
                    auth_fail_count += 1

        b_ratio = float(bytes_in) / float(bytes_out) if bytes_out > 0 else 0.0
        p_ratio = float(pkts_in) / float(pkts_out) if pkts_out > 0 else 0.0

        session_id = f"sess-{abs(hash(key)) % 1000000}-{int(start_time.timestamp())}"
        return SessionSummary(
            session_id=session_id,
            entity_key=key,
            start_time=start_time,
            end_time=end_time,
            event_count=len(events),
            duration_seconds=round(duration, 3),
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            pkts_in=pkts_in,
            pkts_out=pkts_out,
            bytes_ratio=round(b_ratio, 4),
            pkts_ratio=round(p_ratio, 4),
            unique_ports=len(ports),
            unique_protocols=len(protocols),
            syn_flag_count=syn_count,
            rst_flag_count=rst_count,
            dns_query_count=dns_count,
            http_request_count=http_count,
            auth_failure_count=auth_fail_count,
            mean_iat_ms=round(mean_iat, 2),
            std_iat_ms=round(std_iat, 2),
        )
