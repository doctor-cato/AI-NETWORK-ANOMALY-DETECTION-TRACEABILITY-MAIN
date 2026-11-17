"""Unit tests verifying separation of synthetic fixtures and official AIT manifests."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "fetch_multi_source_dataset.py"
_SPEC = importlib.util.spec_from_file_location("fetch_multi_source_dataset", _SCRIPT_PATH)
assert _SPEC and _SPEC.loader
_MOD = importlib.util.module_from_spec(_SPEC)
sys.modules["fetch_multi_source_dataset"] = _MOD
_SPEC.loader.exec_module(_MOD)


def test_synthetic_fixtures_are_marked_synthetic_and_separate(tmp_path):
    fixture_dir = tmp_path / "ait_synthetic"
    manifest_path = fixture_dir / "SYNTHETIC_FIXTURE_MANIFEST.json"
    generated = _MOD.generate_synthetic_fixtures(fixture_dir, manifest_path=manifest_path)
    assert len(generated) == 4
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["synthetic"] is True
    assert "doi" not in manifest
    assert all(entry["synthetic"] is True for entry in manifest["files"])


def test_verify_only_skips_when_official_raw_missing(tmp_path):
    raw_dir = tmp_path / "raw_ait"
    manifest_path = tmp_path / "AIT_DATASETS_MANIFEST.json"
    assert (
        _MOD.verify_and_generate_manifest(
            data_dir=raw_dir,
            manifest_path=manifest_path,
            verify_only=True,
            require_data=False,
        )
        is True
    )
    assert not manifest_path.exists()

    # require_data=True must fail closed
    assert (
        _MOD.verify_and_generate_manifest(
            data_dir=raw_dir,
            manifest_path=manifest_path,
            verify_only=True,
            require_data=True,
        )
        is False
    )


def test_official_ait_manifest_is_not_synthetic():
    manifest = json.loads(Path("data/AIT_DATASETS_MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["synthetic"] is False
    assert manifest["official_source"]["doi_netflow"] == "10.5281/zenodo.13168643"
    assert manifest["official_source"]["doi_log"] == "10.5281/zenodo.19483937"
    assert manifest["files"] == []
