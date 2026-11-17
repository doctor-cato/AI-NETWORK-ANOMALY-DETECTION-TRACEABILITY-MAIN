"""NetFlow v9 and IPFIX Binary Collector with Template Decoding.

Implements Issue #128 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
    ValidationStatus,
)


# Standard NetFlow v9 & IPFIX Information Element Field Types
FIELD_IN_BYTES = 1
FIELD_IN_PKTS = 2
FIELD_FLOWS = 3
FIELD_PROTOCOL = 4
FIELD_TCP_FLAGS = 6
FIELD_L4_SRC_PORT = 7
FIELD_IPV4_SRC_ADDR = 8
FIELD_L4_DST_PORT = 11
FIELD_IPV4_DST_ADDR = 12
FIELD_OUT_BYTES = 23
FIELD_OUT_PKTS = 24
FIELD_FLOW_START_MS = 152
FIELD_FLOW_END_MS = 153


@dataclass
class FlowTemplate:
    template_id: int
    fields: List[Tuple[int, int]]  # List of (field_type, length_bytes)


class NetFlowIPFIXDecoder:
    """Robust binary parser for NetFlow v9 and IPFIX datagrams."""

    def __init__(self):
        # Cache templates by (exporter_ip, template_id)
        self.template_cache: Dict[Tuple[str, int], FlowTemplate] = {}
        self.unresolved_template_count: int = 0
        self.malformed_packet_count: int = 0
        self.total_flows_decoded: int = 0

    def decode_datagram(
        self,
        data: bytes,
        exporter_ip: str = "127.0.0.1",
        exporter_port: int = 2055,
    ) -> List[CanonicalSecurityEvent]:
        """Decode a raw UDP payload containing NetFlow v9 or IPFIX datagrams."""
        if len(data) < 16:
            self.malformed_packet_count += 1
            return []

        version = struct.unpack("!H", data[:2])[0]
        events: List[CanonicalSecurityEvent] = []

        try:
            if version == 9:
                events = self._decode_netflow_v9(data, exporter_ip)
            elif version == 10:
                events = self._decode_ipfix(data, exporter_ip)
            else:
                self.malformed_packet_count += 1
        except Exception:
            # Resilient to corrupt datagrams: never panic
            self.malformed_packet_count += 1

        self.total_flows_decoded += len(events)
        return events

    def _decode_netflow_v9(self, data: bytes, exporter_ip: str) -> List[CanonicalSecurityEvent]:
        # Header: Version (2B), Count (2B), SysUptime (4B), UnixSecs (4B), SeqNum (4B), SourceID (4B)
        count, uptime, unix_secs = struct.unpack("!HII", data[2:12])
        offset = 20
        events: List[CanonicalSecurityEvent] = []

        while offset + 4 <= len(data):
            flowset_id, length = struct.unpack("!HH", data[offset : offset + 4])
            if length < 4 or offset + length > len(data):
                break

            flowset_data = data[offset + 4 : offset + length]

            if flowset_id == 0:
                # Template FlowSet
                self._parse_v9_templates(flowset_data, exporter_ip)
            elif flowset_id >= 256:
                # Data FlowSet
                evs = self._parse_data_flowset(flowset_id, flowset_data, exporter_ip, unix_secs, "NetFlow-v9")
                events.extend(evs)

            offset += length

        return events

    def _decode_ipfix(self, data: bytes, exporter_ip: str) -> List[CanonicalSecurityEvent]:
        # Header: Version (2B), Length (2B), ExportTime (4B), SeqNum (4B), ObsDomainID (4B)
        total_len, export_time = struct.unpack("!HI", data[2:8])
        offset = 16
        events: List[CanonicalSecurityEvent] = []

        while offset + 4 <= len(data):
            set_id, length = struct.unpack("!HH", data[offset : offset + 4])
            if length < 4 or offset + length > len(data):
                break

            set_data = data[offset + 4 : offset + length]

            if set_id == 2:
                # IPFIX Template Set
                self._parse_v9_templates(set_data, exporter_ip)
            elif set_id >= 256:
                evs = self._parse_data_flowset(set_id, set_data, exporter_ip, export_time, "IPFIX")
                events.extend(evs)

            offset += length

        return events

    def _parse_v9_templates(self, data: bytes, exporter_ip: str) -> None:
        idx = 0
        while idx + 4 <= len(data):
            template_id, field_count = struct.unpack("!HH", data[idx : idx + 4])
            idx += 4
            fields = []
            for _ in range(field_count):
                if idx + 4 > len(data):
                    break
                ftype, flen = struct.unpack("!HH", data[idx : idx + 4])
                fields.append((ftype, flen))
                idx += 4
            self.template_cache[(exporter_ip, template_id)] = FlowTemplate(template_id, fields)

    def _parse_data_flowset(
        self,
        template_id: int,
        data: bytes,
        exporter_ip: str,
        base_timestamp: int,
        proto_name: str,
    ) -> List[CanonicalSecurityEvent]:
        key = (exporter_ip, template_id)
        if key not in self.template_cache:
            self.unresolved_template_count += 1
            return []

        template = self.template_cache[key]
        record_len = sum(flen for _, flen in template.fields)
        if record_len == 0:
            return []

        events: List[CanonicalSecurityEvent] = []
        offset = 0

        while offset + record_len <= len(data):
            rec_bytes = data[offset : offset + record_len]
            parsed_fields = self._unpack_record(rec_bytes, template.fields)

            src_ip = parsed_fields.get("src_ip", "0.0.0.0")
            dst_ip = parsed_fields.get("dst_ip", "0.0.0.0")
            src_port = parsed_fields.get("src_port", 0)
            dst_port = parsed_fields.get("dst_port", 0)
            protocol = parsed_fields.get("protocol", "TCP")

            metrics = FlowMetrics(
                duration_ms=parsed_fields.get("duration_ms", 10.0),
                bytes_in=parsed_fields.get("bytes_in", 0),
                bytes_out=parsed_fields.get("bytes_out", 0),
                pkts_in=parsed_fields.get("pkts_in", 0),
                pkts_out=parsed_fields.get("pkts_out", 0),
                tcp_flags=parsed_fields.get("tcp_flags", 0),
            )

            ts = datetime.fromtimestamp(base_timestamp, tz=timezone.utc)

            events.append(
                CanonicalSecurityEvent(
                    event_timestamp=ts,
                    event_kind=EventKind.FLOW,
                    source_id=f"collector:{proto_name.lower()}:{exporter_ip}",
                    entity_id=f"host:{src_ip}",
                    source_ip=src_ip,
                    source_port=src_port,
                    dest_ip=dst_ip,
                    dest_port=dst_port,
                    protocol=protocol,
                    flow_metrics=metrics,
                    raw_provenance=RawProvenance(
                        source_file=f"udp://{exporter_ip}:2055",
                        adapter_name=f"{proto_name}Collector",
                    ),
                    is_ml_complete=False,  # Raw flow metrics only; requires full 47-feature enrichment
                    validation_status=ValidationStatus.VALID,
                )
            )

            offset += record_len

        return events

    def _unpack_record(self, data: bytes, fields: List[Tuple[int, int]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        idx = 0
        for ftype, flen in fields:
            chunk = data[idx : idx + flen]
            idx += flen

            if ftype == FIELD_IPV4_SRC_ADDR and flen == 4:
                result["src_ip"] = socket.inet_ntoa(chunk)
            elif ftype == FIELD_IPV4_DST_ADDR and flen == 4:
                result["dst_ip"] = socket.inet_ntoa(chunk)
            elif ftype == FIELD_L4_SRC_PORT:
                result["src_port"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_L4_DST_PORT:
                result["dst_port"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_PROTOCOL:
                proto_num = int.from_bytes(chunk, "big")
                result["protocol"] = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else str(proto_num))
            elif ftype == FIELD_IN_BYTES:
                result["bytes_in"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_OUT_BYTES:
                result["bytes_out"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_IN_PKTS:
                result["pkts_in"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_OUT_PKTS:
                result["pkts_out"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_TCP_FLAGS:
                result["tcp_flags"] = int.from_bytes(chunk, "big")

        return result
