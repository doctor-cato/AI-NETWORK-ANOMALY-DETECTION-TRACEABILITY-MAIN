"""Unit tests for companion artifact verification and staging helper."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.verify_companion_artifacts import (
    main as verify_companion_main,
)
from scripts.verify_companion_artifacts import (
    run_four_model_e2e_verification,
    stage_companion_bundle,
    verify_companion_artifacts,
    verify_e2e_attestation,
)


def test_verify_companion_artifacts_blocks_when_missing(tmp_path: Path):
    summary = verify_companion_artifacts(root=tmp_path)
    assert summary["overall_status"] == "BLOCKED / NOT READY"
    assert summary["ready_models"] == []
    assert summary["preprocessor"]["ready"] is False
    for key in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
        assert summary["models"][key]["status"] == "BLOCKED / NOT READY"


def test_stage_companion_bundle_fails_closed_when_incomplete(tmp_path: Path):
    empty_src = tmp_path / "src_repo"
    empty_src.mkdir()
    stage_out = tmp_path / "staged"

    import pytest

    with pytest.raises(RuntimeError, match="Cannot stage companion bundle"):
        stage_companion_bundle(destination=stage_out, root=empty_src)


def test_run_four_model_e2e_verification_fails_closed_when_artifacts_missing(tmp_path: Path):
    import pytest

    with pytest.raises(RuntimeError, match="Mandatory 4-model E2E gate BLOCKED"):
        run_four_model_e2e_verification(root=tmp_path)

    exit_code = verify_companion_main(["--root", str(tmp_path), "--verify-e2e"])
    assert exit_code == 1


def test_verify_e2e_attestation_rejects_tampered_model_hash(tmp_path: Path):
    import pytest

    repo_root = Path(__file__).resolve().parents[2]
    att_src = repo_root / "reports" / "releases" / "v0.6.0_e2e_verification.json"
    if not att_src.is_file():
        pytest.skip("Release attestation not yet generated")

    payload = json.loads(att_src.read_text(encoding="utf-8"))
    payload["models"]["xgboost"]["artifact_sha256"] = "0" * 64
    tampered = tmp_path / "tampered_att.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match="artifact_sha256 mismatch"):
        verify_e2e_attestation(tampered, root=repo_root)


def test_verify_shipped_v060_e2e_attestation_passes():
    repo_root = Path(__file__).resolve().parents[2]
    att_path = repo_root / "reports" / "releases" / "v0.6.0_e2e_verification.json"
    result = verify_e2e_attestation(att_path, root=repo_root)
    assert result["attestation_status"] == "PASS"
    assert len(result["verified_models"]) == 4
