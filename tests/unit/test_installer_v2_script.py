"""Unit tests for v2.0 Windows standalone installer and sidecar packaging configuration."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.build_backend_sidecar import HIDDEN_IMPORTS
from scripts.build_installer_v2 import build_installer_v2, inspect_packaging_prerequisites, main


def test_sidecar_hidden_imports_include_v2_subsystems():
    """Verify PyInstaller sidecar hidden imports include v2 crypto, trace, and streaming modules."""
    required_v2_modules = {
        "network_anomaly.canonical.event",
        "network_anomaly.crypto.key_manager",
        "network_anomaly.crypto.aead",
        "network_anomaly.behavioral.vector",
        "network_anomaly.risk.scoring",
        "network_anomaly.trace.timeline",
        "network_anomaly.trace.investigation",
        "network_anomaly.telemetry.collector",
        "network_anomaly.streaming.live_orchestrator",
        "cryptography",
    }
    missing = required_v2_modules - set(HIDDEN_IMPORTS)
    assert not missing, f"Missing v2 hidden imports in sidecar builder: {sorted(missing)}"


def test_installer_v2_check_only_reports_structured_readiness(tmp_path: Path):
    """Verify inspect_packaging_prerequisites and --check-only CLI return valid JSON structure."""
    report = build_installer_v2(check_only=True)
    assert report["mode"] == "check_only"
    assert "tools" in report
    assert "required_files" in report
    assert "readiness" in report
    assert report["required_files"]["run_api"] is True
    assert report["required_files"]["build_backend_sidecar"] is True
    assert report["required_files"]["tauri_standalone_conf"] is True

    out_json = tmp_path / "installer_check.json"
    rc = main(["--check-only", "--output-json", str(out_json)])
    assert rc == 0
    assert out_json.is_file()
    parsed = json.loads(out_json.read_text(encoding="utf-8"))
    assert parsed["mode"] == "check_only"
    assert parsed == inspect_packaging_prerequisites() or set(parsed.keys()) >= {
        "checked_at_utc",
        "tools",
        "required_files",
        "readiness",
        "mode",
        "status",
    }
