"""Unit tests for NetFlow/IPFIX Collector, PCAP Reader, and Log Tailer.

Validates Issues #128, #129, #130 for NetFlow Sentinel v2.0.
"""

import json
import struct
import tempfile
from pathlib import Path
import pytest

from network_anomaly.canonical.event import EventKind
from network_anomaly.telemetry.collector import NetFlowIPFIXDecoder
from network_anomaly.telemetry.log_tailer import LiveLogTailer
from network_anomaly.telemetry.pcap_reader import LocalPCAPReader


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
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8") as tmp:
            tmp.write('192.168.1.100 - - [05/Nov/2020:08:00:00 +0000] "GET /test HTTP/1.1" 200 120 "-" "-"\n')
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
                f.write('192.168.1.105 - - [05/Nov/2020:08:00:05 +0000] "POST /api HTTP/1.1" 200 450 "-" "-"\n')

            events_3 = tailer.tail_available_events()
            assert len(events_3) == 1
            assert events_3[0].source_ip == "192.168.1.105"

        finally:
            if tmp_path.exists():
                tmp_path.unlink()
            if state_path.exists():
                state_path.unlink()
