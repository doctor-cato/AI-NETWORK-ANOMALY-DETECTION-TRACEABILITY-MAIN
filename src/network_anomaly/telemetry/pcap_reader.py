"""Local PCAP file parser and packet-to-flow synthesizer.

Implements Issue #129 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
    ValidationStatus,
)

PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
PCAP_MAGIC_NANOSECONDS = 0xA1B23C4D
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1


@dataclass
class PacketMetadata:
    timestamp_sec: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length_bytes: int
    tcp_flags: int = 0


@dataclass
class FlowAccumulator:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_ts: float
    last_ts: float
    bytes_in: int = 0
    bytes_out: int = 0
    pkts_in: int = 0
    pkts_out: int = 0
    tcp_flags: int = 0

    def add_packet(self, pkt: PacketMetadata, is_forward: bool) -> None:
        self.last_ts = max(self.last_ts, pkt.timestamp_sec)
        self.tcp_flags |= pkt.tcp_flags
        if is_forward:
            self.bytes_out += pkt.length_bytes
            self.pkts_out += 1
        else:
            self.bytes_in += pkt.length_bytes
            self.pkts_in += 1


class LocalPCAPReader:
    """Reads standard libpcap capture files and aggregates raw packets into CanonicalSecurityEvents."""

    def __init__(self, max_packets: int = 100_000, idle_timeout_sec: float = 30.0):
        self.max_packets = max_packets
        self.idle_timeout_sec = idle_timeout_sec

    def parse_pcap(self, pcap_path: Path) -> Tuple[List[CanonicalSecurityEvent], Dict[str, Any]]:
        """Parse PCAP file and return synthesized flow events and ingestion summary."""
        if not pcap_path.exists():
            return [], {"status": "ERROR", "reason": f"File not found: {pcap_path}"}

        summary = {
            "file": pcap_path.name,
            "total_packets_read": 0,
            "valid_ip_packets": 0,
            "synthesized_flows": 0,
            "truncated": False,
        }

        packets: List[PacketMetadata] = []

        try:
            with open(pcap_path, "rb") as f:
                header = f.read(24)
                if len(header) < 24:
                    return [], {
                        "status": "ERROR",
                        "reason": "PCAP file smaller than 24-byte global header",
                    }

                magic = struct.unpack("!I", header[:4])[0]
                is_little_endian = magic in (PCAP_MAGIC_SWAPPED, 0x4D3CB2A1)

                endian = "<" if is_little_endian else "!"

                while True:
                    if summary["total_packets_read"] >= self.max_packets:
                        summary["truncated"] = True
                        break

                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break

                    summary["total_packets_read"] += 1
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_header)
                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < incl_len:
                        break

                    pkt_meta = self._parse_ethernet_ip_packet(pkt_data, ts_sec + ts_usec / 1e6)
                    if pkt_meta:
                        packets.append(pkt_meta)
                        summary["valid_ip_packets"] += 1

        except Exception as e:
            return [], {
                "status": "CORRUPT_PCAP",
                "reason": str(e),
                "packets_recovered": len(packets),
            }

        # Aggregate packets into flows by 5-tuple
        flow_table: Dict[Tuple, FlowAccumulator] = {}
        for pkt in packets:
            forward_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
            reverse_key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)

            if forward_key in flow_table:
                flow_table[forward_key].add_packet(pkt, is_forward=True)
            elif reverse_key in flow_table:
                flow_table[reverse_key].add_packet(pkt, is_forward=False)
            else:
                acc = FlowAccumulator(
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    start_ts=pkt.timestamp_sec,
                    last_ts=pkt.timestamp_sec,
                )
                acc.add_packet(pkt, is_forward=True)
                flow_table[forward_key] = acc

        events: List[CanonicalSecurityEvent] = []
        for flow in flow_table.values():
            duration_ms = max(1.0, (flow.last_ts - flow.start_ts) * 1000.0)
            metrics = FlowMetrics(
                duration_ms=duration_ms,
                bytes_in=flow.bytes_in,
                bytes_out=flow.bytes_out,
                pkts_in=flow.pkts_in,
                pkts_out=flow.pkts_out,
                tcp_flags=flow.tcp_flags,
            )

            ts_dt = datetime.fromtimestamp(flow.start_ts, tz=timezone.utc)
            events.append(
                CanonicalSecurityEvent(
                    event_timestamp=ts_dt,
                    event_kind=EventKind.FLOW,
                    source_id=f"pcap:{pcap_path.name}",
                    entity_id=f"host:{flow.src_ip}",
                    source_ip=flow.src_ip,
                    source_port=flow.src_port,
                    dest_ip=flow.dst_ip,
                    dest_port=flow.dst_port,
                    protocol=flow.protocol,
                    flow_metrics=metrics,
                    raw_provenance=RawProvenance(
                        source_file=str(pcap_path),
                        adapter_name="LocalPCAPReader",
                    ),
                    is_ml_complete=False,  # Flow metrics synthesized from PCAP; route-only or enriched
                    validation_status=ValidationStatus.VALID,
                )
            )

        summary["synthesized_flows"] = len(events)
        summary["status"] = "SUCCESS"
        return events, summary

    def _parse_ethernet_ip_packet(
        self, data: bytes, timestamp_sec: float
    ) -> Optional[PacketMetadata]:
        # Minimal Ethernet (14B) + IPv4 (20B) parser
        if len(data) < 34:
            return None

        # Check Ethernet Type (bytes 12-14) == 0x0800 (IPv4)
        eth_type = struct.unpack("!H", data[12:14])[0]
        if eth_type != 0x0800:
            return None

        ip_hdr = data[14:34]
        proto_num = ip_hdr[9]
        src_ip = socket.inet_ntoa(ip_hdr[12:16])
        dst_ip = socket.inet_ntoa(ip_hdr[16:20])

        src_port = 0
        dst_port = 0
        tcp_flags = 0
        protocol = "OTHER"

        payload_offset = 34
        if proto_num == 6 and len(data) >= payload_offset + 14:  # TCP
            protocol = "TCP"
            src_port, dst_port = struct.unpack("!HH", data[payload_offset : payload_offset + 4])
            tcp_flags = data[payload_offset + 13]
        elif proto_num == 17 and len(data) >= payload_offset + 8:  # UDP
            protocol = "UDP"
            src_port, dst_port = struct.unpack("!HH", data[payload_offset : payload_offset + 4])

        return PacketMetadata(
            timestamp_sec=timestamp_sec,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length_bytes=len(data),
            tcp_flags=tcp_flags,
        )
