"""Unified Multi-source Adapters for NetFlow Sentinel v2.0.

Implements Issues #86, #88, #89, #90.
"""

from __future__ import annotations

import json
import re
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


def _sanitize_url(url: str) -> str:
    """Strip sensitive credential/token query parameters while keeping benign URL path."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    sensitive_keys = {
        "token",
        "key",
        "password",
        "passwd",
        "pwd",
        "secret",
        "auth",
        "session",
        "jwt",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "credential",
        "signature",
    }
    try:
        parts = urlsplit(str(url))
    except Exception:
        return str(url)
    if not parts.query:
        return str(url)
    filtered = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in sensitive_keys
    ]
    new_query = urlencode(filtered)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def parse_timestamp_utc(raw_ts: Any) -> datetime:
    """Normalize any timestamp (epoch seconds, milliseconds, ISO string) to timezone-aware UTC datetime (fail closed)."""
    if raw_ts is None or (isinstance(raw_ts, str) and not raw_ts.strip()):
        raise ValueError(f"Invalid or missing timestamp: {raw_ts!r}")

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

    raise ValueError(f"Invalid or missing timestamp: {raw_ts!r}")


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
            raw_src = raw.get("source_ip")
            raw_dst = raw.get("dest_ip")
            src_ip = str(raw_src).strip() if raw_src is not None and str(raw_src).strip() else None
            dst_ip = str(raw_dst).strip() if raw_dst is not None and str(raw_dst).strip() else None
            src_port = int(raw.get("source_port") or 0) % 65536
            dst_port = int(raw.get("dest_port") or 0) % 65536
            proto_raw = (
                raw.get("protocol_num") or raw.get("raw_protocol_str") or raw.get("protocol")
            )
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
            entity_id=f"host:{src_ip}" if src_ip else None,
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


_DNS_RCODE_MAP: Dict[str, int] = {
    "NOERROR": 0,
    "FORMERR": 1,
    "SERVFAIL": 2,
    "NXDOMAIN": 3,
    "NOTIMP": 4,
    "REFUSED": 5,
}


def _parse_dns_rcode(raw_rcode: Any) -> Optional[int]:
    if raw_rcode is None:
        return None
    if isinstance(raw_rcode, int):
        return raw_rcode
    text = str(raw_rcode).strip()
    if not text or text == "-":
        return None
    if text.upper() in _DNS_RCODE_MAP:
        return _DNS_RCODE_MAP[text.upper()]
    try:
        return int(text)
    except ValueError:
        return None


def _parse_dns_ttl(raw_ttl: Any) -> Optional[int]:
    if raw_ttl is None:
        return None
    if isinstance(raw_ttl, (int, float)):
        return int(raw_ttl)
    text = str(raw_ttl).strip()
    if not text or text in ("-", "(empty)"):
        return None
    first = text.split(",")[0].strip()
    try:
        return int(float(first))
    except ValueError:
        return None


class ApplicationDNSAdapter:
    """Adapts Zeek DNS / Suricata EVE DNS logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:zeek-dns"):
        self.source_id = source_id

    def adapt_line(
        self, line: str, filename: str = "dns.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        """Parse Suricata EVE JSON, Zeek JSON, or Zeek TSV DNS log line."""
        line_clean = line.strip()
        if not line_clean:
            raise ValueError("Empty DNS log line")
        if line_clean.startswith("#"):
            raise ValueError("Comment or header line in DNS log")

        if line_clean.startswith("{") and line_clean.endswith("}"):
            try:
                record = json.loads(line_clean)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in DNS log line: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError("DNS JSON line must decode to an object")
            dns_sub = record.get("dns") if isinstance(record.get("dns"), dict) else {}
            normalized = {
                "ts": record.get("ts") or record.get("timestamp"),
                "id.orig_h": (
                    record.get("id.orig_h") or record.get("src_ip") or record.get("source_ip")
                ),
                "id.resp_h": (
                    record.get("id.resp_h") or record.get("dest_ip") or record.get("dst_ip")
                ),
                "id.orig_p": (
                    record.get("id.orig_p")
                    if record.get("id.orig_p") is not None
                    else record.get("src_port", record.get("source_port"))
                ),
                "id.resp_p": (
                    record.get("id.resp_p")
                    if record.get("id.resp_p") is not None
                    else record.get("dest_port", record.get("dst_port"))
                ),
                "query": dns_sub.get("rrname") or record.get("query") or record.get("query_name"),
                "qtype_name": (
                    dns_sub.get("rrtype") or record.get("qtype_name") or record.get("query_type")
                ),
                "rcode": (
                    dns_sub.get("rcode")
                    if dns_sub.get("rcode") is not None
                    else record.get("rcode")
                ),
                "TTL": (
                    dns_sub.get("ttl")
                    if dns_sub.get("ttl") is not None
                    else record.get("TTL", record.get("TTLs"))
                ),
            }
            return self.adapt_record(normalized, filename=filename, line_idx=line_idx)

        if "\t" in line_clean:
            parts = line_clean.split("\t")
            # Standard Zeek dns.log TSV:
            # ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, trans_id, rtt, query, ...
            if len(parts) >= 10 and (parts[3].isdigit() or parts[3] == "-"):
                raw_rec: Dict[str, Any] = {
                    "ts": parts[0],
                    "id.orig_h": parts[2] if parts[2] != "-" else None,
                    "id.orig_p": parts[3] if parts[3] != "-" else None,
                    "id.resp_h": parts[4] if parts[4] != "-" else None,
                    "id.resp_p": parts[5] if parts[5] != "-" else None,
                    "query": parts[9] if parts[9] != "-" else None,
                    "qtype_name": parts[13] if len(parts) > 13 and parts[13] != "-" else None,
                    "rcode": parts[14] if len(parts) > 14 and parts[14] != "-" else None,
                    "TTL": parts[22] if len(parts) > 22 and parts[22] != "-" else None,
                }
                return self.adapt_record(raw_rec, filename=filename, line_idx=line_idx)
            # Compact TSV without uid: ts, orig_h, orig_p, resp_h, resp_p, query[, qtype, rcode, ttl]
            if len(parts) >= 6 and (parts[2].isdigit() or parts[2] == "-"):
                raw_rec = {
                    "ts": parts[0],
                    "id.orig_h": parts[1] if parts[1] != "-" else None,
                    "id.orig_p": parts[2] if parts[2] != "-" else None,
                    "id.resp_h": parts[3] if parts[3] != "-" else None,
                    "id.resp_p": parts[4] if parts[4] != "-" else None,
                    "query": parts[5] if parts[5] != "-" else None,
                    "qtype_name": parts[6] if len(parts) > 6 and parts[6] != "-" else None,
                    "rcode": parts[7] if len(parts) > 7 and parts[7] != "-" else None,
                    "TTL": parts[8] if len(parts) > 8 and parts[8] != "-" else None,
                }
                return self.adapt_record(raw_rec, filename=filename, line_idx=line_idx)

        raise ValueError(f"Malformed DNS log line (expected JSON or Zeek TSV): {line!r}")

    def adapt_record(
        self, raw: Dict[str, Any], filename: str = "dns.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        dt = parse_timestamp_utc(raw.get("ts") or raw.get("timestamp"))
        raw_src = raw.get("id.orig_h") or raw.get("source_ip") or raw.get("src_ip")
        raw_dst = raw.get("id.resp_h") or raw.get("dest_ip") or raw.get("dst_ip")
        src_ip = (
            str(raw_src).strip()
            if raw_src is not None and str(raw_src).strip() not in ("", "-")
            else None
        )
        dst_ip = (
            str(raw_dst).strip()
            if raw_dst is not None and str(raw_dst).strip() not in ("", "-")
            else None
        )
        raw_src_p = (
            raw.get("id.orig_p") if raw.get("id.orig_p") is not None else raw.get("source_port")
        )
        raw_dst_p = (
            raw.get("id.resp_p") if raw.get("id.resp_p") is not None else raw.get("dest_port")
        )
        src_port = (
            int(raw_src_p) % 65536
            if raw_src_p is not None and str(raw_src_p).strip() not in ("", "-")
            else None
        )
        dst_port = (
            int(raw_dst_p) % 65536
            if raw_dst_p is not None and str(raw_dst_p).strip() not in ("", "-")
            else 53
        )
        query_raw = raw.get("query") or raw.get("query_name")
        query_name = (
            str(query_raw).strip()
            if query_raw is not None and str(query_raw).strip() not in ("", "-")
            else ""
        )
        qtype_raw = raw.get("qtype_name") or raw.get("query_type")
        qtype_name = (
            str(qtype_raw).strip()
            if qtype_raw is not None and str(qtype_raw).strip() not in ("", "-")
            else None
        )

        dns_data = DNSData(
            query_name=query_name,
            query_type=qtype_name,
            rcode=_parse_dns_rcode(raw.get("rcode")),
            ttl_answer=_parse_dns_ttl(raw.get("TTL") if "TTL" in raw else raw.get("TTLs")),
        )

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.DNS,
            source_id=self.source_id,
            entity_id=f"host:{src_ip}" if src_ip else None,
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
                    "url": _sanitize_url(url),
                    "status": int(status),
                },
                filename=filename,
                line_idx=line_idx,
            )
        raise ValueError(f"Malformed HTTP log line (expected CLF/Combined format): {line!r}")

    def adapt_record(
        self, raw: Dict[str, Any], filename: str = "access.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        dt = parse_timestamp_utc(raw.get("time_local") or raw.get("timestamp"))
        src_raw = raw.get("remote_addr") or raw.get("source_ip")
        if not src_raw or not str(src_raw).strip():
            raise ValueError("Missing source_ip / remote_addr in web log record")
        src_ip = str(src_raw).strip()
        dst_raw = raw.get("server_addr") or raw.get("dest_ip")
        dst_ip = str(dst_raw).strip() if dst_raw is not None and str(dst_raw).strip() else None

        http_data = HTTPData(
            method=str(raw.get("method") or raw.get("request_method") or "GET"),
            url=_sanitize_url(str(raw.get("url") or raw.get("request_uri") or "/")),
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

    def __init__(self, source_id: str = "source:auth-audit", default_year: int = 2020):
        self.source_id = source_id
        self.default_year = int(default_year)

    def adapt_line(
        self, line: str, filename: str = "auth.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        """Parse Linux auth.log / sshd line (ISO8601 or RFC3164 syslog timestamp)."""
        # Nov  5 08:00:00 server01 sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 52314 ssh2
        import re

        line_clean = line.strip()
        if not line_clean:
            raise ValueError("Empty auth log line")

        iso_m = re.match(
            r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\b",
            line_clean,
        )
        rfc_m = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b", line_clean)
        if iso_m:
            dt = parse_timestamp_utc(iso_m.group(1))
        elif rfc_m:
            normalized_ts = " ".join(rfc_m.group(1).split())
            dt = datetime.strptime(
                f"{self.default_year} {normalized_ts}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        else:
            raise ValueError(f"Missing or unparseable syslog timestamp in auth line: {line!r}")

        # IP match
        ip_m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line_clean)
        # User match
        user_m = re.search(r"(?:for (?:invalid user )?|user=)([a-zA-Z0-9_.\-]+)", line_clean)
        if not ip_m and not user_m:
            raise ValueError(f"Unrecognized auth log line (no user or source IP): {line!r}")

        src_ip = ip_m.group(1) if ip_m else None
        user = user_m.group(1) if user_m else None

        # Status
        lower_line = line_clean.lower()
        if "accepted" in lower_line or "session opened" in lower_line:
            result = "Accepted"
        elif (
            "failed" in lower_line
            or "invalid user" in lower_line
            or "authentication failure" in lower_line
        ):
            result = "Failed"
        else:
            raise ValueError(f"Unrecognized auth status in log line: {line!r}")

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
        raw_ip = raw.get("source_ip") or raw.get("rhost")
        raw_user = raw.get("user") or raw.get("username")
        if (not raw_ip or not str(raw_ip).strip()) and (not raw_user or not str(raw_user).strip()):
            raise ValueError("Auth record must provide at least one of 'source_ip' or 'user'")
        src_ip = str(raw_ip).strip() if raw_ip is not None and str(raw_ip).strip() else None
        user_clean = (
            str(raw_user).strip() if raw_user is not None and str(raw_user).strip() else None
        )
        res = (
            "SUCCESS"
            if str(raw.get("result") or raw.get("status") or "").lower()
            in ("accepted", "success", "0")
            else "FAILURE"
        )

        auth_data = AuthData(
            username=user_clean or "",
            auth_result=res,
            service=str(raw.get("service") or raw.get("program") or "sshd"),
            failure_reason=raw.get("reason"),
        )

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.AUTH,
            source_id=self.source_id,
            entity_id=(
                f"user:{user_clean}" if user_clean else (f"host:{src_ip}" if src_ip else None)
            ),
            source_ip=src_ip,
            auth_data=auth_data,
            raw_provenance=RawProvenance(
                source_file=filename, line_or_offset=line_idx, adapter_name="IdentityAuthAdapter"
            ),
            is_ml_complete=False,
        )


class SystemAuditAdapter:
    """Adapts Sysmon and auditd logs to CanonicalSecurityEvent."""

    def __init__(self, source_id: str = "source:sysmon", default_year: int = 2020):
        self.source_id = source_id
        self.default_year = int(default_year)

    def adapt_line(
        self, line: str, filename: str = "audit.log", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        """Parse JSON (Sysmon/audit) or syslog/auditd text line."""
        line_clean = line.strip()
        if not line_clean:
            raise ValueError("Empty system audit log line")

        if line_clean.startswith("{") and line_clean.endswith("}"):
            try:
                record = json.loads(line_clean)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in system audit line: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError("System audit JSON line must decode to an object")
            return self.adapt_record(record, filename=filename, line_idx=line_idx)

        # Auditd line: type=SYSCALL msg=audit(1604563200.123:456): ... pid=1234 ... comm="curl"
        audit_ts_m = re.search(r"msg=audit\((\d+(?:\.\d+)?):\d+\)", line_clean)
        if audit_ts_m:
            dt = parse_timestamp_utc(float(audit_ts_m.group(1)))
            type_m = re.search(r"\btype=([A-Z0-9_]+)", line_clean)
            node_m = re.search(r"\bnode=([^\s]+)", line_clean)
            pid_m = re.search(r"\bpid=(\d+)", line_clean)
            comm_m = re.search(r'\b(?:comm|exe)="([^"]+)"', line_clean)
            res_m = re.search(r"\bres=([a-zA-Z0-9_]+)", line_clean)
            ret_code: Optional[int] = None
            if res_m:
                ret_code = 0 if res_m.group(1).lower() in ("success", "1") else 1
            return self.adapt_record(
                {
                    "timestamp": dt,
                    "hostname": node_m.group(1) if node_m else None,
                    "process": comm_m.group(1) if comm_m else None,
                    "pid": int(pid_m.group(1)) if pid_m else None,
                    "action": type_m.group(1) if type_m else "AUDIT_EVENT",
                    "ReturnCode": ret_code,
                },
                filename=filename,
                line_idx=line_idx,
            )

        # Syslog line: ISO8601 or RFC3164 <ts> <host> <proc>[<pid>]: <msg>
        iso_m = re.match(
            r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s*(.+)$",
            line_clean,
        )
        if iso_m:
            ts_str, host, proc, pid_str, msg = iso_m.groups()
            dt = parse_timestamp_utc(ts_str)
            return self.adapt_record(
                {
                    "timestamp": dt,
                    "hostname": host,
                    "process": proc,
                    "pid": int(pid_str) if pid_str else None,
                    "action": msg.strip()[:120] or "SYSTEM_LOG",
                },
                filename=filename,
                line_idx=line_idx,
            )

        rfc_m = re.match(
            r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s*(.+)$",
            line_clean,
        )
        if rfc_m:
            ts_str, host, proc, pid_str, msg = rfc_m.groups()
            normalized_ts = " ".join(ts_str.split())
            dt = datetime.strptime(
                f"{self.default_year} {normalized_ts}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            return self.adapt_record(
                {
                    "timestamp": dt,
                    "hostname": host,
                    "process": proc,
                    "pid": int(pid_str) if pid_str else None,
                    "action": msg.strip()[:120] or "SYSTEM_LOG",
                },
                filename=filename,
                line_idx=line_idx,
            )

        raise ValueError(f"Malformed system audit log line: {line!r}")

    def adapt_record(
        self, raw: Dict[str, Any], filename: str = "sysmon.json", line_idx: Optional[int] = None
    ) -> CanonicalSecurityEvent:
        dt = parse_timestamp_utc(raw.get("UtcTime") or raw.get("timestamp"))
        raw_host = raw.get("Computer") or raw.get("hostname") or raw.get("host")
        host = str(raw_host).strip() if raw_host is not None and str(raw_host).strip() else None
        raw_src = raw.get("source_ip") or raw.get("src_ip")
        src_ip = str(raw_src).strip() if raw_src is not None and str(raw_src).strip() else None
        raw_proc = raw.get("Image") or raw.get("process") or raw.get("process_name")
        proc_name = (
            str(raw_proc).strip() if raw_proc is not None and str(raw_proc).strip() else None
        )
        raw_pid = raw.get("ProcessId") if raw.get("ProcessId") is not None else raw.get("pid")
        pid = int(raw_pid) if raw_pid is not None and str(raw_pid).strip() != "" else None
        raw_rc = raw.get("ReturnCode") if "ReturnCode" in raw else raw.get("return_code")
        return_code = int(raw_rc) if raw_rc is not None and str(raw_rc).strip() != "" else None

        sys_data = SystemData(
            process_name=proc_name,
            process_id=pid,
            action=str(raw.get("RuleName") or raw.get("action") or "PROCESS_CREATE"),
            return_code=return_code,
        )

        return CanonicalSecurityEvent(
            event_timestamp=dt,
            event_kind=EventKind.SYSTEM,
            source_id=self.source_id,
            entity_id=f"host:{host}" if host else (f"host:{src_ip}" if src_ip else None),
            source_ip=src_ip,
            system_data=sys_data,
            raw_provenance=RawProvenance(
                source_file=filename, line_or_offset=line_idx, adapter_name="SystemAuditAdapter"
            ),
            is_ml_complete=False,
        )
