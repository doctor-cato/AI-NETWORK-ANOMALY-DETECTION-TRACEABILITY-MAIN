"""Contract tests validating Rust netflow-rs NDJSON output against CanonicalSecurityEvent."""

import shutil
import subprocess
from pathlib import Path

import pytest

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind

REPO_ROOT = Path(__file__).resolve().parents[2]
NETFLOW_MANIFEST = REPO_ROOT / "telemetry" / "netflow-rs" / "Cargo.toml"


def test_netflow_rs_self_test_canonical_contract() -> None:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not available on PATH")

    proc = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(NETFLOW_MANIFEST),
            "--",
            "--self-test",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 1

    events = [CanonicalSecurityEvent.model_validate_json(line) for line in lines]
    event = events[0]
    assert event.schema_version == "2.0.0"
    assert event.event_kind == EventKind.FLOW
    assert event.source_id == "source:netflow-v9-ipfix"
    assert event.source_ip == "10.0.1.15"
    assert event.dest_ip == "192.168.1.20"
    assert event.source_port == 51514
    assert event.dest_port == 443
    assert event.protocol == "TCP"
    assert event.raw_provenance.source_file == "udp://127.0.0.1"
    assert event.raw_provenance.adapter_name == "RustNetFlowIPFIXCollector"
    assert event.flow_metrics is not None
    assert event.flow_metrics.bytes_in == 12800
    assert event.flow_metrics.bytes_out == 64200
    assert event.flow_metrics.pkts_in == 18
    assert event.flow_metrics.pkts_out == 42
    assert event.flow_metrics.duration_ms == 1250
    assert event.flow_metrics.tcp_flags == 0x18
