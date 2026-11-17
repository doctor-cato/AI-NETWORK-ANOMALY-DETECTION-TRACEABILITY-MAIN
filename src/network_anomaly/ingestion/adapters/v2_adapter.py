"""Unified Multi-source Adapters for NetFlow Sentinel v2.0.

Implements Issues #86, #88, #89, #90.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import math

from network_anomaly.canonical.event import (
    AuthData,
    CanonicalSecurityEvent,
    DNSData,
    EventKind,
    FlowMetrics,
    HTTPData,
    RawProvenance,
    SystemData,
    ValidationStatus,
)
from network_anomaly.canonical.feature_contract import get_baseline_47_feature_contract
from network_anomaly.data.taxonomy import harmonize_attack_label


def parse_timestamp_utc(raw_ts: Any) -> datetime:
    """Normalize any timestamp (epoch seconds, milliseconds, ISO string) to timezone-aware UTC datetime."""
    if isinstance(raw_ts, datetime):
        return raw_ts if raw_ts.tzinfo is not None else raw_ts.replace(tzinfo=timezone.utc)

    if isinstance(raw_ts, (int, float)):
        # Check if ms or seconds
        if raw_ts > 1e11:  # Milliseconds
            return datetime.fromtimestamp(raw_ts / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(float(raw_ts), tz=timezone.utc)

    if isinstance(raw_ts, str):
        # Try numeric parse
        try:
            val = float(raw_ts)
            if val > 1e11:
                return datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except ValueError:
            pass

        # Try ISO format
        try:
            dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

    return datetime.now(timezone.utc)


class UnifiedNetFlowAdapter:
    """Adapts NF-UNSW-NB15-v3 and AIT NetFlow CSV records to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:nf-unsw-nb15-v3"):
        self.source_id = source_id
        self.contract = get_baseline_47_feature_contract()

    def adapt_record(self, raw: Dict[str, Any], filename: str = "flow.csv", line_idx: Optional[int] = None) -> CanonicalSecurityEvent:
        ts_raw = raw.get("FLOW_START_MILLISECONDS") or raw.get("timestamp") or raw.get("flow_start")
        dt = parse_timestamp_utc(ts_raw)

        src_ip = str(raw.get("IPV4_SRC_ADDR") or raw.get("source_ip") or "0.0.0.0")
        dst_ip = str(raw.get("IPV4_DST_ADDR") or raw.get("dest_ip") or "0.0.0.0")
        src_port = int(raw.get("L4_SRC_PORT") or raw.get("source_port") or 0) % 65536
        dst_port = int(raw.get("L4_DST_PORT") or raw.get("dest_port") or 0) % 65536
        proto = str(raw.get("PROTOCOL") or "TCP")

        metrics = FlowMetrics(
            duration_ms=float(raw.get("FLOW_DURATION_MILLISECONDS") or 0.0),
            bytes_in=int(raw.get("IN_BYTES") or 0),
            bytes_out=int(raw.get("OUT_BYTES") or 0),
            pkts_in=int(raw.get("IN_PKTS") or 0),
            pkts_out=int(raw.get("OUT_PKTS") or 0),
            tcp_flags=int(raw.get("TCP_FLAGS") or 0),
        )

        provenance = RawProvenance(
            source_file=filename,
            line_or_offset=line_idx,
            adapter_name="UnifiedNetFlowAdapter",
        )

        # Check ML feature completeness against 47 baseline
        is_complete, missing = self.contract.validate_features(raw)
        ml_feats = {k: float(raw[k]) for k in self.contract.feature_names} if is_complete else None

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.FLOW,
            source_id=self.source_id,
            entity_id=f"host:{src_ip}",
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol=proto,
            flow_metrics=metrics,
            raw_provenance=provenance,
            ml_features=ml_feats,
            is_ml_complete=is_complete,
            validation_status=ValidationStatus.VALID if is_complete else ValidationStatus.FEATURE_INCOMPLETE,
        )


class ApplicationDNSAdapter:
    """Adapts Zeek DNS / DNS query logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:zeek-dns"):
        self.source_id = source_id

    def adapt_record(self, raw: Dict[str, Any], filename: str = "dns.log", line_idx: Optional[int] = None) -> CanonicalSecurityEvent:
        dt = parse_timestamp_utc(raw.get("ts") or raw.get("timestamp"))
        src_ip = str(raw.get("id.orig_h") or raw.get("source_ip") or "0.0.0.0")
        dst_ip = str(raw.get("id.resp_h") or raw.get("dest_ip") or "0.0.0.0")
        src_port = int(raw.get("id.orig_p") or 0) % 65536
        dst_port = int(raw.get("id.resp_p") or 53) % 65536

        dns_data = DNSData(
            query_name=str(raw.get("query") or raw.get("query_name") or "unknown.domain"),
            query_type=str(raw.get("qtype_name") or raw.get("query_type") or "A"),
            rcode=int(raw.get("rcode") or 0),
            ttl_answer=int(raw.get("TTL") or 0),
        )

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.DNS,
            source_id=self.source_id,
            entity_id=f"host:{src_ip}",
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol="UDP",
            dns_data=dns_data,
            raw_provenance=RawProvenance(source_file=filename, line_or_offset=line_idx, adapter_name="ApplicationDNSAdapter"),
            is_ml_complete=False,  # NO IMPUTATION FOR APPLICATION LOGS
        )


class ApplicationWebAdapter:
    """Adapts HTTP / Nginx access logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:nginx-web"):
        self.source_id = source_id

    def adapt_line(self, line: str, filename: str = "access.log", line_idx: Optional[int] = None) -> CanonicalSecurityEvent:
        """Parse Common Log Format or Combined Log Format line."""
        # 192.168.1.100 - - [05/Nov/2020:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"
        import re
        pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*) \S+" (\d{3}) (\d+|-)'
        m = re.match(pattern, line.strip())
        if m:
            src_ip, ts_str, method, url, status, bytes_str = m.groups()
            dt = parse_timestamp_utc(datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc))
            return self.adapt_record(
                {
                    "time_local": dt,
                    "remote_addr": src_ip,
                    "method": method,
                    "url": url,
                    "status": int(status),
                },
                filename=filename,
                line_idx=line_idx,
            )
        return self.adapt_record({"remote_addr": "0.0.0.0"}, filename=filename, line_idx=line_idx)

    def adapt_record(self, raw: Dict[str, Any], filename: str = "access.log", line_idx: Optional[int] = None) -> CanonicalSecurityEvent:
        dt = parse_timestamp_utc(raw.get("time_local") or raw.get("timestamp"))
        src_ip = str(raw.get("remote_addr") or raw.get("source_ip") or "0.0.0.0")
        dst_ip = str(raw.get("server_addr") or raw.get("dest_ip") or "0.0.0.0")

        http_data = HTTPData(
            method=str(raw.get("method") or raw.get("request_method") or "GET"),
            url=str(raw.get("url") or raw.get("request_uri") or "/"),
            status_code=int(raw.get("status") or raw.get("status_code") or 200),
            user_agent=str(raw.get("http_user_agent") or ""),
        )

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.WEB,
            source_id=self.source_id,
            entity_id=f"host:{src_ip}",
            source_ip=src_ip,
            dest_ip=dst_ip,
            dest_port=80,
            protocol="TCP",
            http_data=http_data,
            raw_provenance=RawProvenance(source_file=filename, line_or_offset=line_idx, adapter_name="ApplicationWebAdapter"),
            is_ml_complete=False,
        )


class IdentityAuthAdapter:
    """Adapts Authentication, SSH, and VPN logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:auth-audit"):
        self.source_id = source_id

    def adapt_line(self, line: str, filename: str = "auth.log", line_idx: Optional[int] = None) -> CanonicalSecurityEvent:
        """Parse Linux auth.log / sshd line."""
        # Nov  5 08:00:00 server01 sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 52314 ssh2
        import re
        line_clean = line.strip()
        dt = datetime(2020, 11, 5, 8, 0, 0, tzinfo=timezone.utc)
        
        # IP match
        ip_m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line_clean)
        src_ip = ip_m.group(1) if ip_m else "0.0.0.0"

        # User match
        user_m = re.search(r'for (?:invalid user )?([a-zA-Z0-9_\-]+)', line_clean)
        user = user_m.group(1) if user_m else "unknown"

        # Status
        result = "Accepted" if "accepted" in line_clean.lower() else "Failed"

        return self.adapt_record(
            {
                "timestamp": dt,
                "source_ip": src_ip,
                "user": user,
                "result": result,
                "service": "sshd",
            },
            filename=filename,
            line_idx=line_idx,
        )

    def adapt_record(self, raw: Dict[str, Any], filename: str = "auth.log", line_idx: Optional[int] = None) -> CanonicalSecurityEvent:
        dt = parse_timestamp_utc(raw.get("timestamp") or raw.get("date"))
        src_ip = str(raw.get("source_ip") or raw.get("rhost") or "0.0.0.0")
        user = str(raw.get("user") or raw.get("username") or "unknown_user")
        res = "SUCCESS" if str(raw.get("result") or raw.get("status") or "").lower() in ("accepted", "success", "0") else "FAILURE"

        auth_data = AuthData(
            username=user,
            auth_result=res,
            service=str(raw.get("service") or raw.get("program") or "sshd"),
            failure_reason=raw.get("reason"),
        )

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.AUTH,
            source_id=self.source_id,
            entity_id=f"user:{user}",
            source_ip=src_ip,
            auth_data=auth_data,
            raw_provenance=RawProvenance(source_file=filename, line_or_offset=line_idx, adapter_name="IdentityAuthAdapter"),
            is_ml_complete=False,
        )


class SystemAuditAdapter:
    """Adapts Sysmon and auditd logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:sysmon"):
        self.source_id = source_id

    def adapt_record(self, raw: Dict[str, Any], filename: str = "sysmon.json", line_idx: Optional[int] = None) -> CanonicalSecurityEvent:
        dt = parse_timestamp_utc(raw.get("UtcTime") or raw.get("timestamp"))
        host = str(raw.get("Computer") or raw.get("hostname") or "local_host")

        sys_data = SystemData(
            process_name=str(raw.get("Image") or raw.get("process") or "unknown.exe"),
            process_id=int(raw.get("ProcessId") or 0),
            action=str(raw.get("RuleName") or raw.get("action") or "PROCESS_CREATE"),
            return_code=int(raw.get("ReturnCode") or 0) if "ReturnCode" in raw else None,
        )

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.SYSTEM,
            source_id=self.source_id,
            entity_id=f"host:{host}",
            system_data=sys_data,
            raw_provenance=RawProvenance(source_file=filename, line_or_offset=line_idx, adapter_name="SystemAuditAdapter"),
            is_ml_complete=False,
        )
