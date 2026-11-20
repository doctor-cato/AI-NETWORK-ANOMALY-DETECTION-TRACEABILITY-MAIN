"""NetFlow v9 and IPFIX decoding plus a live UDP collector.

Implements Issues #128 and #137 for NetFlow Sentinel v2.0.

The decoder accepts standard NetFlow v9 / IPFIX templates and exposes the
private lab enterprise convention used by the synthetic exporter in the
acceptance test: ``PEN 50000`` (IPFIX) or IE ``50000 + index`` (NetFlow v9)
carries the canonical v2 model features in contract order.

Nothing is synthesised here. A standard router template yields the flow tuples
and counters a router actually exports; the remaining model features stay
absent and the feature extractor rejects the event as ``NOT_MODEL_READY``.
"""

from __future__ import annotations

import collections
import socket
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from network_anomaly.canonical.event import (
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
    ValidationStatus,
)
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS

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
FIELD_FLOW_START_MS = 152  # IPFIX absolute epoch milliseconds
FIELD_FLOW_END_MS = 153  # IPFIX absolute epoch milliseconds
FIELD_V9_FLOW_END_SYS_UP = 21  # relative to header sysUptime, milliseconds
FIELD_V9_FLOW_START_SYS_UP = 22  # relative to header sysUptime, milliseconds

# Private lab convention: model feature N is exported as IE 50000 + N.
LAB_ENTERPRISE_NUMBER = 50000
LAB_ENTERPRISE_FIELD_BASE = 50000
MAX_U32 = 0xFFFFFFFF


def lab_enterprise_field_for(feature_name: str) -> int:
    """Return the private lab IE number that carries ``feature_name``."""
    return LAB_ENTERPRISE_FIELD_BASE + ML_FEATURE_COLUMNS.index(feature_name)


def _lab_feature_value(chunk: bytes) -> float:
    """Decode a lab feature IE: float64 when 8 bytes, unsigned integer otherwise."""
    if len(chunk) == 8:
        return float(struct.unpack("!d", chunk)[0])
    return float(int.from_bytes(chunk, "big", signed=False))


@dataclass
class FlowTemplate:
    template_id: int
    # (field_type, length_bytes, enterprise_number) - enterprise number is 0 for IANA fields
    fields: List[Tuple[int, int, int]]
    min_data_record_length: int = 0

    @property
    def record_length(self) -> int:
        return sum(length for _, length, _ in self.fields)


class NetFlowIPFIXDecoder:
    """Robust binary parser for NetFlow v9 and IPFIX datagrams."""

    def __init__(self) -> None:
        # Cache templates by (exporter_ip, template_id)
        self.template_cache: Dict[Tuple[str, int], FlowTemplate] = {}
        self.unresolved_template_count: int = 0
        self.malformed_packet_count: int = 0
        self.unsupported_template_count: int = 0
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
                events = self._decode_netflow_v9(data, exporter_ip, exporter_port)
            elif version == 10:
                events = self._decode_ipfix(data, exporter_ip, exporter_port)
            else:
                self.malformed_packet_count += 1
        except Exception:
            # Resilient to corrupt datagrams: never panic
            self.malformed_packet_count += 1
            events = []

        self.total_flows_decoded += len(events)
        return events

    # ----------------------------------------------------------------- header
    def _decode_netflow_v9(
        self, data: bytes, exporter_ip: str, exporter_port: int
    ) -> List[CanonicalSecurityEvent]:
        # Header: Version (2B), Count (2B), SysUptime (4B), UnixSecs (4B), SeqNum (4B), SourceID (4B)
        _count, sys_uptime, unix_secs = struct.unpack("!HII", data[2:12])
        offset = 20
        events: List[CanonicalSecurityEvent] = []

        while offset + 4 <= len(data):
            flowset_id, length = struct.unpack("!HH", data[offset : offset + 4])
            if length < 4 or offset + length > len(data):
                break

            flowset_data = data[offset + 4 : offset + length]

            if flowset_id == 0:
                # Template FlowSet (NetFlow v9 has no enterprise bit)
                self._parse_templates(flowset_data, exporter_ip, allow_enterprise=False)
            elif flowset_id >= 256:
                # Data FlowSet
                events.extend(
                    self._parse_data_flowset(
                        flowset_id,
                        flowset_data,
                        exporter_ip,
                        exporter_port,
                        unix_secs,
                        "NetFlow-v9",
                        sys_uptime=sys_uptime,
                    )
                )

            offset += length

        return events

    def _decode_ipfix(
        self, data: bytes, exporter_ip: str, exporter_port: int
    ) -> List[CanonicalSecurityEvent]:
        # Header: Version (2B), Length (2B), ExportTime (4B), SeqNum (4B), ObsDomainID (4B)
        _total_len, export_time = struct.unpack("!HI", data[2:8])
        offset = 16
        events: List[CanonicalSecurityEvent] = []

        while offset + 4 <= len(data):
            set_id, length = struct.unpack("!HH", data[offset : offset + 4])
            if length < 4 or offset + length > len(data):
                break

            set_data = data[offset + 4 : offset + length]

            if set_id == 2:
                # IPFIX Template Set (enterprise-specific IEs supported)
                self._parse_templates(set_data, exporter_ip, allow_enterprise=True)
            elif set_id == 3:
                # Options Template Set: not needed for flow records; skip explicitly.
                pass
            elif set_id >= 256:
                events.extend(
                    self._parse_data_flowset(
                        set_id,
                        set_data,
                        exporter_ip,
                        exporter_port,
                        export_time,
                        "IPFIX",
                    )
                )

            offset += length

        return events

    # -------------------------------------------------------------- templates
    def _parse_templates(self, data: bytes, exporter_ip: str, allow_enterprise: bool) -> None:
        idx = 0
        while idx + 4 <= len(data):
            template_id, field_count = struct.unpack("!HH", data[idx : idx + 4])
            idx += 4

            if template_id == 0 and field_count == 0:
                self.template_cache.clear()
                continue

            fields: List[Tuple[int, int, int]] = []
            unsupported = False
            for _ in range(field_count):
                if idx + 4 > len(data):
                    unsupported = True
                    break
                ftype, flen = struct.unpack("!HH", data[idx : idx + 4])
                idx += 4
                enterprise = 0
                if allow_enterprise and (ftype & 0x8000):
                    # IPFIX enterprise-specific IE: 4-byte enterprise number follows.
                    if idx + 4 > len(data):
                        unsupported = True
                        break
                    enterprise = struct.unpack("!I", data[idx : idx + 4])[0]
                    idx += 4
                    ftype = ftype & 0x7FFF
                if flen == 0 or flen == 0xFFFF:
                    # Variable-length fields are not modelled; refuse the template
                    # instead of guessing record boundaries.
                    unsupported = True
                fields.append((ftype, flen, enterprise))

            if unsupported or not fields:
                self.unsupported_template_count += 1
                self.template_cache.pop((exporter_ip, template_id), None)
                continue

            self.template_cache[(exporter_ip, template_id)] = FlowTemplate(
                template_id=template_id, fields=fields
            )

    # ------------------------------------------------------------ data records
    def _parse_data_flowset(
        self,
        template_id: int,
        data: bytes,
        exporter_ip: str,
        exporter_port: int,
        base_timestamp: int,
        proto_name: str,
        sys_uptime: Optional[int] = None,
    ) -> List[CanonicalSecurityEvent]:
        key = (exporter_ip, template_id)
        if key not in self.template_cache:
            self.unresolved_template_count += 1
            return []

        template = self.template_cache[key]
        record_len = template.record_length
        if record_len <= 0:
            return []

        events: List[CanonicalSecurityEvent] = []
        offset = 0

        while offset + record_len <= len(data):
            rec_bytes = data[offset : offset + record_len]
            parsed_fields = self._unpack_record(rec_bytes, template.fields)
            offset += record_len

            src_ip = parsed_fields.get("src_ip")
            dst_ip = parsed_fields.get("dst_ip")
            if not src_ip or not dst_ip:
                # A flow record without both endpoint addresses cannot be traced.
                continue

            event_ts, duration_ms = self._derive_timing(parsed_fields, base_timestamp, sys_uptime)
            metrics = FlowMetrics(
                duration_ms=duration_ms,
                bytes_in=parsed_fields.get("bytes_in", 0),
                bytes_out=parsed_fields.get("bytes_out", 0),
                pkts_in=parsed_fields.get("pkts_in", 0),
                pkts_out=parsed_fields.get("pkts_out", 0),
                tcp_flags=parsed_fields.get("tcp_flags", 0),
            )

            ml_features = parsed_fields.get("ml_features") or None

            events.append(
                CanonicalSecurityEvent(
                    event_timestamp=event_ts,
                    event_kind=EventKind.FLOW,
                    source_id=f"collector:{proto_name.lower()}:{exporter_ip}",
                    entity_id=f"host:{src_ip}",
                    source_ip=src_ip,
                    source_port=parsed_fields.get("src_port"),
                    dest_ip=dst_ip,
                    dest_port=parsed_fields.get("dst_port"),
                    protocol=parsed_fields.get("protocol", "TCP"),
                    flow_metrics=metrics,
                    ml_features=ml_features,
                    raw_provenance=RawProvenance(
                        source_file=f"udp://{exporter_ip}:{exporter_port}",
                        adapter_name=f"{proto_name}Collector",
                        source_checksum=None,
                    ),
                    is_ml_complete=False,
                    validation_status=ValidationStatus.VALID,
                )
            )

        return events

    @staticmethod
    def _derive_timing(
        parsed_fields: Dict[str, Any],
        base_timestamp: int,
        sys_uptime: Optional[int],
    ) -> Tuple[datetime, float]:
        """Resolve flow timestamp and duration only from fields the exporter sent."""
        start_ms = parsed_fields.get("flow_start_epoch_ms")
        end_ms = parsed_fields.get("flow_end_epoch_ms")
        duration = parsed_fields.get("duration_ms")

        if start_ms is not None and end_ms is not None and end_ms >= start_ms:
            duration = float(end_ms - start_ms)
            return datetime.fromtimestamp(start_ms / 1000.0, tz=timezone.utc), duration

        start_up = parsed_fields.get("flow_start_sys_up")
        end_up = parsed_fields.get("flow_end_sys_up")
        if sys_uptime is not None and start_up is not None:
            # Convert monotonic sysUptime milliseconds into wall-clock time.
            delta_ms = (sys_uptime - start_up) & MAX_U32
            start_epoch = float(base_timestamp) - (delta_ms / 1000.0)
            ts = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
            if end_up is not None:
                duration = float((end_up - start_up) & MAX_U32)
            elif duration is None:
                duration = 0.0
            return ts, float(duration if duration is not None else 0.0)

        ts = datetime.fromtimestamp(base_timestamp, tz=timezone.utc)
        return ts, float(duration if duration is not None else 0.0)

    # ------------------------------------------------------------- field parse
    def _unpack_record(self, data: bytes, fields: List[Tuple[int, int, int]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        ml_features: Dict[str, float] = {}
        idx = 0
        for ftype, flen, enterprise in fields:
            chunk = data[idx : idx + flen]
            idx += flen
            if len(chunk) != flen:
                break

            if enterprise:
                if enterprise == LAB_ENTERPRISE_NUMBER and 0 <= ftype < len(ML_FEATURE_COLUMNS):
                    ml_features[ML_FEATURE_COLUMNS[ftype]] = _lab_feature_value(chunk)
                continue

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
                result["protocol"] = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP",
                    58: "ICMPV6",
                }.get(proto_num, str(proto_num))
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
            elif ftype == FIELD_FLOW_START_MS:
                result["flow_start_epoch_ms"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_FLOW_END_MS:
                result["flow_end_epoch_ms"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_V9_FLOW_START_SYS_UP:
                result["flow_start_sys_up"] = int.from_bytes(chunk, "big")
            elif ftype == FIELD_V9_FLOW_END_SYS_UP:
                result["flow_end_sys_up"] = int.from_bytes(chunk, "big")
            elif (
                LAB_ENTERPRISE_FIELD_BASE
                <= ftype
                < (LAB_ENTERPRISE_FIELD_BASE + len(ML_FEATURE_COLUMNS))
            ):
                # NetFlow v9 has no enterprise bit; the lab exporter uses the
                # bare 50000+i IE numbers. Documented convention, not IANA.
                name = ML_FEATURE_COLUMNS[ftype - LAB_ENTERPRISE_FIELD_BASE]
                ml_features[name] = _lab_feature_value(chunk)

        if ml_features:
            result["ml_features"] = ml_features
        return result


@dataclass
class UDPCollectorStats:
    datagrams_received: int = 0
    datagrams_rejected: int = 0
    flows_decoded: int = 0
    events_dropped: int = 0
    queue_depth: int = 0
    queue_capacity: int = 0
    last_datagram_at_utc: Optional[str] = None
    last_error: Optional[str] = None
    running: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "datagrams_received": self.datagrams_received,
            "datagrams_rejected": self.datagrams_rejected,
            "flows_decoded": self.flows_decoded,
            "events_dropped": self.events_dropped,
            "queue_depth": self.queue_depth,
            "queue_capacity": self.queue_capacity,
            "last_datagram_at_utc": self.last_datagram_at_utc,
            "last_error": self.last_error,
            "running": self.running,
        }


class UDPFlowCollector:
    """Threaded UDP listener that decodes NetFlow v9 / IPFIX into a bounded queue.

    The socket lives in its own daemon thread, so an exporter that stops sending
    never blocks the process. Decoded events are held in a bounded deque; when
    the queue is full the oldest event is dropped and counted, which keeps the
    process responsive under backpressure while making the loss observable.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        decoder: Optional[NetFlowIPFIXDecoder] = None,
        queue_capacity: int = 10_000,
        recv_buffer_bytes: int = 65_507,
        socket_timeout_s: float = 0.25,
        on_event: Optional[Callable[[CanonicalSecurityEvent], None]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.decoder = decoder or NetFlowIPFIXDecoder()
        self.queue_capacity = max(1, int(queue_capacity))
        self.recv_buffer_bytes = recv_buffer_bytes
        self.socket_timeout_s = socket_timeout_s
        self.on_event = on_event

        self._queue: collections.deque[CanonicalSecurityEvent] = collections.deque(
            maxlen=self.queue_capacity
        )
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._socket: Optional[socket.socket] = None
        self._stats = UDPCollectorStats(queue_capacity=self.queue_capacity)

    # ------------------------------------------------------------- lifecycle
    def start(self) -> int:
        """Bind the socket and start the listener thread. Returns the bound port."""
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("UDPFlowCollector is already running")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.socket_timeout_s)
            sock.bind((self.host, self.port))
        except OSError as exc:
            sock.close()
            self._stats.last_error = f"bind failed: {exc}"
            raise
        self._socket = sock
        self.port = sock.getsockname()[1]
        self._stop.clear()
        self._stats.running = True
        self._thread = threading.Thread(target=self._run, name="udp-flow-collector", daemon=True)
        self._thread.start()
        return self.port

    def stop(self, join_timeout_s: float = 5.0) -> None:
        """Stop the listener thread and close the socket. Safe to call twice."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=join_timeout_s)
        sock = self._socket
        self._socket = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        self._thread = None
        self._stats.running = False

    def __enter__(self) -> "UDPFlowCollector":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def bound_port(self) -> int:
        return self.port

    # --------------------------------------------------------------- receive
    def _run(self) -> None:
        while not self._stop.is_set():
            sock = self._socket
            if sock is None:
                break
            try:
                payload, address = sock.recvfrom(self.recv_buffer_bytes)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    self._stats.last_error = f"recv failed: {exc}"
                break

            self._stats.datagrams_received += 1
            self._stats.last_datagram_at_utc = datetime.now(timezone.utc).isoformat()
            try:
                events = self.decoder.decode_datagram(
                    payload, exporter_ip=address[0], exporter_port=address[1]
                )
            except Exception as exc:  # pragma: no cover - decoder is defensive
                self._stats.datagrams_rejected += 1
                self._stats.last_error = f"decode failed: {type(exc).__name__}: {exc}"
                continue

            if not events:
                self._stats.datagrams_rejected += 1
                continue

            self._stats.flows_decoded += len(events)
            self._push(events)

    def _push(self, events: List[CanonicalSecurityEvent]) -> None:
        callback = self.on_event
        with self._lock:
            for event in events:
                if len(self._queue) == self.queue_capacity:
                    self._stats.events_dropped += 1
                self._queue.append(event)
            self._stats.queue_depth = len(self._queue)
        if callback is not None:
            for event in events:
                callback(event)

    def drain(self, max_events: Optional[int] = None) -> List[CanonicalSecurityEvent]:
        """Remove and return queued events in arrival order."""
        with self._lock:
            if max_events is None or max_events >= len(self._queue):
                events = list(self._queue)
                self._queue.clear()
            else:
                events = [self._queue.popleft() for _ in range(max(0, max_events))]
            self._stats.queue_depth = len(self._queue)
            return events

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            self._stats.queue_depth = len(self._queue)
        payload = self._stats.to_dict()
        payload["bound_port"] = self.port
        payload["decoder"] = {
            "malformed_packet_count": self.decoder.malformed_packet_count,
            "unresolved_template_count": self.decoder.unresolved_template_count,
            "unsupported_template_count": self.decoder.unsupported_template_count,
            "total_flows_decoded": self.decoder.total_flows_decoded,
            "templates_cached": len(self.decoder.template_cache),
        }
        return payload

    def wait_for_events(self, minimum: int, timeout_s: float = 5.0) -> int:
        """Block until ``minimum`` events are queued or the timeout expires."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        while time.monotonic() < deadline:
            with self._lock:
                depth = len(self._queue)
            if depth >= minimum:
                return depth
            time.sleep(0.01)
        with self._lock:
            return len(self._queue)
