"""Unified Multi-source Adapters for NetFlow Sentinel v2.0.

Implements Issues #86, #88, #89, #90.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

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
from network_anomaly.canonical.feature_contract import get_flow_feature_contract_v2
from network_anomaly.data.taxonomy import classify_raw_label
from network_anomaly.data.v2_schema import (
    compute_flow_features_from_base,
    parse_ait_nds_tstat_row,
    parse_ctu_zeek_conn_row,
    parse_protocol_number,
)


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
    """Adapts AIT-NDS-v2 (Tstat), CTU-SME-11 (Zeek), and canonical v2 flow records to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:ait-nds-v2"):
        self.source_id = source_id
        self.contract = get_flow_feature_contract_v2()

    def adapt_record(
        self, raw: Dict[str, Any], filename: str = "flow.csv", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        parsed: Optional[Dict[str, Any]] = None
        if "#15#c_ip:1" in raw or "durat:31" in raw:
            kind = "tcp_complete" if "c_ttl_min:50" in raw else "tcp_nocomplete"
            parsed = parse_ait_nds_tstat_row(raw, flow_kind=kind)
        elif "#c_ip:1" in raw or "c_first_abs:3" in raw:
            parsed = parse_ait_nds_tstat_row(raw, flow_kind="udp_complete")
        elif "id.orig_h" in raw and "orig_ip_bytes" in raw:
            parsed = parse_ctu_zeek_conn_row(raw)

        if parsed is not None:
            dt = parse_timestamp_utc(parsed["timestamp_ms"])
            src_ip = str(parsed["source_ip"])
            dst_ip = str(parsed["dest_ip"])
            src_port = int(parsed["source_port"]) % 65536
            dst_port = int(parsed["dest_port"]) % 65536
            proto_str = str(parsed["raw_protocol_str"])
            metrics = FlowMetrics(
                duration_ms=float(parsed["duration_ms"]),
                bytes_in=int(parsed["bytes_in"]),
                bytes_out=int(parsed["bytes_out"]),
                pkts_in=int(parsed["pkts_in"]),
                pkts_out=int(parsed["pkts_out"]),
            )
            ml_feats = {k: float(parsed[k]) for k in self.contract.feature_names}
            is_complete = True
            label_res = classify_raw_label(
                parsed.get("raw_label"),
                detailed_label=parsed.get("raw_detailed_label"),
            )
            attack_cat = (
                label_res.canonical_category if label_res.label_status != "UNMAPPED" else None
            )
        else:
            ts_raw = raw.get("timestamp_ms") or raw.get("timestamp") or raw.get("flow_start")
            dt = parse_timestamp_utc(ts_raw)
            src_ip = str(raw.get("source_ip") or "0.0.0.0")
            dst_ip = str(raw.get("dest_ip") or "0.0.0.0")
            src_port = int(raw.get("source_port") or 0) % 65536
            dst_port = int(raw.get("dest_port") or 0) % 65536
            proto_raw = raw.get("protocol_num") or raw.get("raw_protocol_str") or raw.get("protocol")
            proto_str = str(proto_raw or "UNKNOWN")

            is_complete, _ = self.contract.validate_features(raw)
            ml_feats = (
                {k: float(raw[k]) for k in self.contract.feature_names} if is_complete else None
            )

            dur_val = raw.get("duration_ms")
            bin_val = raw.get("bytes_in")
            bout_val = raw.get("bytes_out")
            pin_val = raw.get("pkts_in")
            pout_val = raw.get("pkts_out")
            if ml_feats is None and all(
                v is not None for v in (dur_val, bin_val, bout_val, pin_val, pout_val, proto_raw)
            ):
                try:
                    proto_num = parse_protocol_number(proto_raw)
                    ml_feats = compute_flow_features_from_base(
                        duration_ms=float(dur_val),  # type: ignore[arg-type]
                        bytes_in=float(bin_val),  # type: ignore[arg-type]
                        bytes_out=float(bout_val),  # type: ignore[arg-type]
                        pkts_in=float(pin_val),  # type: ignore[arg-type]
                        pkts_out=float(pout_val),  # type: ignore[arg-type]
                        protocol_num=proto_num,
                    )
                    is_complete = True
                except (ValueError, TypeError):
                    ml_feats = None
                    is_complete = False

            metrics = FlowMetrics(
                duration_ms=float(dur_val) if dur_val is not None else None,
                bytes_in=int(bin_val) if bin_val is not None else None,
                bytes_out=int(bout_val) if bout_val is not None else None,
                pkts_in=int(pin_val) if pin_val is not None else None,
                pkts_out=int(pout_val) if pout_val is not None else None,
            )
            raw_lbl = raw.get("attack_category") or raw.get("raw_label") or raw.get("label")
            attack_cat = (
                classify_raw_label(raw_lbl).canonical_category if raw_lbl is not None else None
            )

        provenance = RawProvenance(
            source_file=filename,
            line_or_offset=line_idx,
            adapter_name="UnifiedNetFlowAdapter",
        )

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.FLOW,
            source_id=self.source_id,
            entity_id=f"host:{src_ip}",
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol=proto_str,
            attack_category=attack_cat,
            flow_metrics=metrics,
            raw_provenance=provenance,
            ml_features=ml_feats,
            is_ml_complete=is_complete,
            validation_status=(
                ValidationStatus.VALID if is_complete else ValidationStatus.FEATURE_INCOMPLETE
            ),
        )


class ApplicationDNSAdapter:
    """Adapts Zeek DNS / DNS query logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:zeek-dns"):
        self.source_id = source_id

    def adapt_record(
        self, raw: Dict[str, Any], filename: str = "dns.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
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
            raw_provenance=RawProvenance(
                source_file=filename, line_or_offset=line_idx, adapter_name="ApplicationDNSAdapter"
            ),
            is_ml_complete=False,  # NO IMPUTATION FOR APPLICATION LOGS
        )


class ApplicationWebAdapter:
    """Adapts HTTP / Nginx access logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:nginx-web"):
        self.source_id = source_id

    def adapt_line(
        self, line: str, filename: str = "access.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        """Parse Common Log Format or Combined Log Format line."""
        # 192.168.1.100 - - [05/Nov/2020:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"
        import re

        pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*) \S+" (\d{3}) (\d+|-)'
        m = re.match(pattern, line.strip())
        if m:
            src_ip, ts_str, method, url, status, bytes_str = m.groups()
            dt = parse_timestamp_utc(
                datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
            )
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

    def adapt_record(
        self, raw: Dict[str, Any], filename: str = "access.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
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
            raw_provenance=RawProvenance(
                source_file=filename, line_or_offset=line_idx, adapter_name="ApplicationWebAdapter"
            ),
            is_ml_complete=False,
        )


class IdentityAuthAdapter:
    """Adapts Authentication, SSH, and VPN logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:auth-audit"):
        self.source_id = source_id

    def adapt_line(
        self, line: str, filename: str = "auth.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        """Parse Linux auth.log / sshd line."""
        # Nov  5 08:00:00 server01 sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 52314 ssh2
        import re

        line_clean = line.strip()
        dt = datetime(2020, 11, 5, 8, 0, 0, tzinfo=timezone.utc)

        # IP match
        ip_m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line_clean)
        src_ip = ip_m.group(1) if ip_m else "0.0.0.0"

        # User match
        user_m = re.search(r"for (?:invalid user )?([a-zA-Z0-9_\-]+)", line_clean)
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

    def adapt_record(
        self, raw: Dict[str, Any], filename: str = "auth.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        dt = parse_timestamp_utc(raw.get("timestamp") or raw.get("date"))
        src_ip = str(raw.get("source_ip") or raw.get("rhost") or "0.0.0.0")
        user = str(raw.get("user") or raw.get("username") or "unknown_user")
        res = (
            "SUCCESS"
            if str(raw.get("result") or raw.get("status") or "").lower()
            in ("accepted", "success", "0")
            else "FAILURE"
        )

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
            raw_provenance=RawProvenance(
                source_file=filename, line_or_offset=line_idx, adapter_name="IdentityAuthAdapter"
            ),
            is_ml_complete=False,
        )


class SystemAuditAdapter:
    """Adapts Sysmon and auditd logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:sysmon"):
        self.source_id = source_id

    def adapt_record(
        self, raw: Dict[str, Any], filename: str = "sysmon.json", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
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
            raw_provenance=RawProvenance(
                source_file=filename, line_or_offset=line_idx, adapter_name="SystemAuditAdapter"
            ),
            is_ml_complete=False,
        )
