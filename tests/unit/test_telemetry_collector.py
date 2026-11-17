"""Unit tests for NetFlow/IPFIX Collector, UDP listener, PCAP Reader, and Log Tailer.

Validates Issues #128, #129, #130, #137 for NetFlow Sentinel v2.0.
"""

import socket
import struct
import tempfile
import time
from pathlib import Path

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.telemetry.collector import (
    LAB_ENTERPRISE_FIELD_BASE,
    LAB_ENTERPRISE_NUMBER,
    NetFlowIPFIXDecoder,
    UDPFlowCollector,
)
from network_anomaly.telemetry.log_tailer import LiveLogTailer
from network_anomaly.telemetry.pcap_reader import LocalPCAPReader


def _standard_fields():
    return [
        (8, 4),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 4),
        (23, 4),
        (2, 4),
        (24, 4),
        (6, 1),
        (22, 4),
        (21, 4),
    ]


def build_v9_packet(
    features_list,
    include_template=True,
    template_id=256,
    sys_uptime_ms=1_000_000,
    unix_secs=1_700_000_000,
):
    fields = _standard_fields() + [
        (LAB_ENTERPRISE_FIELD_BASE + i, 8) for i in range(len(ML_FEATURE_COLUMNS))
    ]
    payload = bytearray()
    if include_template:
        template = struct.pack("!HH", template_id, len(fields))
        for ftype, flen in fields:
            template += struct.pack("!HH", ftype, flen)
        payload += struct.pack("!HH", 0, 4 + len(template)) + template

    records = bytearray()
    for index, features in enumerate(features_list):
        start = sys_uptime_ms - 50_000 - index
        records += (
            socket.inet_aton("192.0.2.10")
            + socket.inet_aton("192.0.2.20")
            + struct.pack(
                "!HHBIIIIBII",
                40000 + index,
                443,
                int(features["protocol_num"]),
                int(features["bytes_in"]),
                int(features["bytes_out"]),
                int(features["pkts_in"]),
                int(features["pkts_out"]),
                24,
                start,
                start + int(features["duration_ms"]),
            )
        )
        records += b"".join(struct.pack("!d", features[name]) for name in ML_FEATURE_COLUMNS)
    payload += struct.pack("!HH", template_id, 4 + len(records)) + bytes(records)
    return struct.pack("!HHIIII", 9, 1, sys_uptime_ms, unix_secs, 1, 1) + bytes(payload)


def build_ipfix_packet(features, template_id=300):
    standard = _standard_fields()[:10] + [(152, 8), (153, 8)]
    now_ms = 1_700_000_000_000
    template = struct.pack("!HH", template_id, len(standard) + len(ML_FEATURE_COLUMNS))
    for ftype, flen in standard:
        template += struct.pack("!HH", ftype, flen)
    for index in range(len(ML_FEATURE_COLUMNS)):
        template += struct.pack("!HHI", 0x8000 | index, 8, LAB_ENTERPRISE_NUMBER)
    payload = struct.pack("!HH", 2, 4 + len(template)) + template

    record = (
        socket.inet_aton("192.0.2.30")
        + socket.inet_aton("192.0.2.40")
        + struct.pack(
            "!HHBIIIIBQQ",
            41000,
            8443,
            int(features["protocol_num"]),
            int(features["bytes_in"]),
            int(features["bytes_out"]),
            int(features["pkts_in"]),
            int(features["pkts_out"]),
            24,
            now_ms,
            now_ms + 25,
        )
    )
    record += b"".join(struct.pack("!d", features[name]) for name in ML_FEATURE_COLUMNS)
    payload += struct.pack("!HH", template_id, 4 + len(record)) + record
    return struct.pack("!HHIII", 10, 16 + len(payload), 1_700_000_000, 1, 1) + bytes(payload)


class TestNetFlowIPFIXDecoder:
    def test_corrupt_datagram_fails_gracefully_without_panic(self):
        decoder = NetFlowIPFIXDecoder()
        # Less than 16 bytes
        events = decoder.decode_datagram(b"\x00\x09\x00")
        assert len(events) == 0
        assert decoder.malformed_packet_count == 1

        # Corrupt payload with version 9
        corrupt_v9 = struct.pack("!HHIIII", 9, 1, 1000, 1600000000, 1, 1) + b"\xff\xff\x00\x02"
        events = decoder.decode_datagram(corrupt_v9)
        assert len(events) == 0

    def test_unresolved_template_handling(self):
        decoder = NetFlowIPFIXDecoder()
        # NetFlow v9 with Data FlowSet ID 300 (not in template cache)
        v9_hdr = struct.pack("!HHIIII", 9, 1, 1000, 1600000000, 1, 1)
        data_flowset = struct.pack("!HH", 300, 12) + b"\x00" * 8
        events = decoder.decode_datagram(v9_hdr + data_flowset)
        assert len(events) == 0
        assert decoder.unresolved_template_count == 1


class TestEnterpriseFeatureMapping:
    def test_v9_lab_ies_carry_all_18_features(self, baseline_features):
        features = baseline_features()
        decoder = NetFlowIPFIXDecoder()
        events = decoder.decode_datagram(build_v9_packet([features]))

        assert len(events) == 1
        event = events[0]
        assert event.ml_features is not None
        assert list(event.ml_features) == list(ML_FEATURE_COLUMNS)
        assert event.ml_features == features
        assert event.source_ip == "192.0.2.10"
        assert event.dest_port == 443
        assert event.flow_metrics.duration_ms == 34.0
        assert event.raw_provenance.adapter_name == "NetFlow-v9Collector"

    def test_ipfix_enterprise_pen_carries_all_18_features(self, baseline_features):
        features = baseline_features()
        events = NetFlowIPFIXDecoder().decode_datagram(build_ipfix_packet(features))

        assert len(events) == 1
        assert events[0].ml_features == features
        assert events[0].raw_provenance.source_file.startswith("udp://")

    def test_template_cache_allows_data_only_datagram(self, baseline_features):
        features = baseline_features()
        decoder = NetFlowIPFIXDecoder()
        first = decoder.decode_datagram(build_v9_packet([features]))
        second = decoder.decode_datagram(
            build_v9_packet([features], include_template=False, sys_uptime_ms=1_002_000)
        )

        assert len(first) == 1
        assert len(second) == 1
        assert len(decoder.template_cache) == 1
        assert decoder.unresolved_template_count == 0

    def test_standard_router_template_does_not_invent_model_features(self):
        # A plain v9 template without the lab IEs must yield partial flow data only.
        fields = _standard_fields()
        template = struct.pack("!HH", 256, len(fields))
        for ftype, flen in fields:
            template += struct.pack("!HH", ftype, flen)
        record = (
            socket.inet_aton("203.0.113.5")
            + socket.inet_aton("203.0.113.9")
            + struct.pack("!HHBIIIIBII", 1234, 80, 6, 500, 700, 5, 6, 24, 10_000, 10_100)
        )
        packet = (
            struct.pack("!HHIIII", 9, 1, 20_000, 1_700_000_000, 1, 1)
            + struct.pack("!HH", 0, 4 + len(template))
            + template
            + struct.pack("!HH", 256, 4 + len(record))
            + record
        )
        events = NetFlowIPFIXDecoder().decode_datagram(packet)

        assert len(events) == 1
        assert events[0].ml_features is None
        assert events[0].flow_metrics.bytes_in == 500


class TestUDPFlowCollector:
    def test_udp_loopback_receives_decodes_and_stops(self, baseline_features):
        collector = UDPFlowCollector(host="127.0.0.1", port=0, queue_capacity=16)
        port = collector.start()
        try:
            assert collector.is_running is True
            assert port > 0

            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sender.sendto(build_v9_packet([baseline_features()]), ("127.0.0.1", port))
            finally:
                sender.close()

            assert collector.wait_for_events(1, timeout_s=3.0) == 1
            events = collector.drain()
            assert len(events) == 1
            assert events[0].ml_features is not None
            assert len(events[0].ml_features) == 18

            stats = collector.stats()
            assert stats["datagrams_received"] == 1
            assert stats["flows_decoded"] == 1
            assert stats["decoder"]["malformed_packet_count"] == 0
        finally:
            collector.stop()
        assert collector.is_running is False
        assert collector.stats()["running"] is False

    def test_malformed_datagram_is_counted_not_fatal(self, baseline_features):
        collector = UDPFlowCollector(host="127.0.0.1", port=0)
        port = collector.start()
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sender.sendto(b"\x00\x09\x00", ("127.0.0.1", port))
                sender.sendto(build_v9_packet([baseline_features()]), ("127.0.0.1", port))
            finally:
                sender.close()

            assert collector.wait_for_events(1, timeout_s=3.0) == 1
            stats = collector.stats()
            assert stats["datagrams_received"] == 2
            assert stats["datagrams_rejected"] >= 1
            assert stats["decoder"]["malformed_packet_count"] == 1
            assert stats["flows_decoded"] == 1
        finally:
            collector.stop()

    def test_backpressure_drops_oldest_and_counts_it(self, baseline_features):
        collector = UDPFlowCollector(host="127.0.0.1", port=0, queue_capacity=1)
        port = collector.start()
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sender.sendto(
                    build_v9_packet([baseline_features(), baseline_features()]),
                    ("127.0.0.1", port),
                )
            finally:
                sender.close()

            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if collector.stats()["flows_decoded"] >= 2:
                    break
                time.sleep(0.01)

            stats = collector.stats()
            assert stats["flows_decoded"] == 2
            assert stats["events_dropped"] == 1
            assert stats["queue_depth"] == 1
        finally:
            collector.stop()

    def test_restart_binds_a_new_socket(self, baseline_features):
        collector = UDPFlowCollector(host="127.0.0.1", port=0)
        first_port = collector.start()
        collector.stop()
        collector.port = 0
        second_port = collector.start()
        try:
            assert second_port > 0
            assert collector.is_running is True
            assert first_port != second_port
        finally:
            collector.stop()


class TestLocalPCAPReader:
    def test_missing_pcap_file(self):
        reader = LocalPCAPReader()
        events, summary = reader.parse_pcap(Path("non_existent_file.pcap"))
        assert len(events) == 0
        assert summary["status"] == "ERROR"

    def test_corrupt_pcap_header(self):
        reader = LocalPCAPReader()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(b"SHORT_CORRUPT_BYTES")
            tmp_path = Path(tmp.name)

        try:
            events, summary = reader.parse_pcap(tmp_path)
            assert len(events) == 0
            assert summary["status"] == "ERROR"
        finally:
            tmp_path.unlink()


class TestLiveLogTailer:
    def test_tail_and_offset_persistence(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(
                '192.168.1.100 - - [05/Nov/2020:08:00:00 +0000] "GET /test HTTP/1.1" 200 120 "-" "-"\n'
            )
            tmp_path = Path(tmp.name)

        state_path = tmp_path.with_suffix(".state.json")
        try:
            tailer = LiveLogTailer(target_log_path=tmp_path, state_file_path=state_path)
            events = tailer.tail_available_events()
            assert len(events) == 1
            assert events[0].source_ip == "192.168.1.100"
            assert state_path.exists()

            # Second read without new lines returns 0 events
            events_2 = tailer.tail_available_events()
            assert len(events_2) == 0

            # Append new line
            with open(tmp_path, "a", encoding="utf-8") as f:
                f.write(
                    '192.168.1.105 - - [05/Nov/2020:08:00:05 +0000] "POST /api HTTP/1.1" 200 450 "-" "-"\n'
                )

            events_3 = tailer.tail_available_events()
            assert len(events_3) == 1
            assert events_3[0].source_ip == "192.168.1.105"

        finally:
            if tmp_path.exists():
                tmp_path.unlink()
            if state_path.exists():
                state_path.unlink()
