"""Unit tests for companion artifact verification and staging helper."""

from __future__ import annotations

from pathlib import Path

from scripts.verify_companion_artifacts import (
    stage_companion_bundle,
    verify_companion_artifacts,
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
