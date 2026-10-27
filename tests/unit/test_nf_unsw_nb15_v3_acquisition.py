"""Synthetic acquisition fixtures; they are not NF-UNSW-NB15-v3 observations."""

import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FETCH_SCRIPT = ROOT / "scripts" / "fetch_nf_unsw_nb15_v3.py"
MANIFEST_SCRIPT = ROOT / "scripts" / "dataset_manifest.py"


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fetcher(monkeypatch):
    module = load_script("fetch_nf_unsw_nb15_v3", FETCH_SCRIPT)
    members = {
        "bagit.txt": b"BagIt-Version: 1.0\n",
        "data/NF-UNSW-NB15-v3.csv": b"feature,Label,Attack\n1,0,Benign\n",
    }
    expected = {
        name: (len(payload), hashlib.sha256(payload).hexdigest())
        for name, payload in members.items()
    }
    monkeypatch.setattr(module, "EXPECTED_MEMBERS", expected)
    monkeypatch.setattr(module, "MAX_EXTRACTED_BYTES", sum(v[0] for v in expected.values()))
    return module, members


class Headers:
    def __init__(self, content_type="application/zip"):
        self.content_type = content_type

    def get_content_type(self):
        return self.content_type


class Response(io.BytesIO):
    status = 200

    def __init__(self, payload, content_type="application/zip"):
        super().__init__(payload)
        self.headers = Headers(content_type)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def archive_bytes(fetcher, members, names=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        for relative, payload in members.items():
            archive_name = names.get(relative, relative) if names is not None else relative
            bundle.writestr(f"{fetcher.PACKAGE_PREFIX}/{archive_name}", payload)
    return output.getvalue()


def serve_archive(fetcher, monkeypatch, payload, content_type="application/zip"):
    monkeypatch.setattr(fetcher, "get_download_url", lambda: "https://example.amazonaws.com/x")
    monkeypatch.setattr(
        fetcher,
        "urlopen",
        lambda *_args, **_kwargs: Response(payload, content_type),
    )
    monkeypatch.setattr(fetcher, "ARCHIVE_SIZE", len(payload))
    monkeypatch.setattr(fetcher, "ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())


def write_valid_package(fetcher, directory, members):
    directory.mkdir(parents=True)
    for relative, payload in members.items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def test_fetch_installs_verified_archive_and_cache_hit(fetcher, tmp_path, monkeypatch, capsys):
    module, members = fetcher
    payload = archive_bytes(module, members)
    serve_archive(module, monkeypatch, payload)

    module.fetch(tmp_path)
    final = tmp_path / module.DATASET_NAME
    assert module.package_is_valid(final)

    monkeypatch.setattr(module, "urlopen", lambda *_a, **_k: pytest.fail("network used"))
    module.fetch(tmp_path)
    assert "CACHE_HIT" in capsys.readouterr().out


def test_cache_mismatch_is_replaced_only_after_verification(fetcher, tmp_path, monkeypatch):
    module, members = fetcher
    final = tmp_path / module.DATASET_NAME
    final.mkdir()
    (final / "bagit.txt").write_bytes(b"corrupt")
    payload = archive_bytes(module, members)
    serve_archive(module, monkeypatch, payload)

    module.fetch(tmp_path)

    assert module.package_is_valid(final)


def test_download_over_pinned_limit_is_rejected(fetcher, tmp_path, monkeypatch):
    module, _members = fetcher
    monkeypatch.setattr(module, "get_download_url", lambda: "https://example.amazonaws.com/x")
    monkeypatch.setattr(module, "ARCHIVE_SIZE", 3)
    monkeypatch.setattr(module, "urlopen", lambda *_a, **_k: Response(b"1234"))

    with pytest.raises(ValueError, match="exceeds the pinned size"):
        module.download_archive(tmp_path / "download.zip")


def test_html_download_is_rejected(fetcher, tmp_path, monkeypatch):
    module, _members = fetcher
    serve_archive(module, monkeypatch, b"<html>error</html>", "text/html")

    with pytest.raises(ValueError, match="Content-Type"):
        module.download_archive(tmp_path / "download.zip")


def test_invalid_archive_checksum_is_rejected(fetcher, tmp_path, monkeypatch):
    module, members = fetcher
    payload = archive_bytes(module, members)
    serve_archive(module, monkeypatch, payload)
    monkeypatch.setattr(module, "ARCHIVE_SHA256", "0" * 64)

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        module.download_archive(tmp_path / "download.zip")


def test_corrupted_zip_is_rejected_after_byte_verification(fetcher, tmp_path, monkeypatch):
    module, _members = fetcher
    payload = b"PK-not-a-zip"
    serve_archive(module, monkeypatch, payload)
    archive = tmp_path / "download.zip"
    module.download_archive(archive)

    with pytest.raises(zipfile.BadZipFile):
        module.extract_verified_archive(archive, tmp_path / "staging")


def test_archive_path_traversal_is_rejected(fetcher, tmp_path):
    module, members = fetcher
    payload = archive_bytes(
        module,
        members,
        names={"bagit.txt": "../escape.txt", "data/NF-UNSW-NB15-v3.csv": "data/x.csv"},
    )
    archive = tmp_path / "download.zip"
    archive.write_bytes(payload)

    with pytest.raises(ValueError, match="unsafe archive path"):
        module.extract_verified_archive(archive, tmp_path / "staging")


def test_publish_failure_restores_cache_and_next_run_recovers(fetcher, tmp_path, monkeypatch):
    module, members = fetcher
    final = tmp_path / module.DATASET_NAME
    staging = tmp_path / ".nf-staging-package"
    write_valid_package(module, final, members)
    write_valid_package(module, staging, members)
    original_replace = module.os.replace
    failed = False

    def fail_publish(source, destination):
        nonlocal failed
        if Path(source) == staging and Path(destination) == final and not failed:
            failed = True
            raise OSError("synthetic publish failure")
        return original_replace(source, destination)

    monkeypatch.setattr(module.os, "replace", fail_publish)
    with pytest.raises(OSError, match="synthetic publish failure"):
        module.publish_package(tmp_path, staging)

    assert module.package_is_valid(final)
    assert (tmp_path / module.TXN_NAME).is_file()
    assert staging.is_dir()

    module.recover_interrupted_transaction(tmp_path)
    assert module.package_is_valid(final)
    assert not (tmp_path / module.TXN_NAME).exists()
    assert not staging.exists()


def test_destination_lock_times_out_for_concurrent_holder(fetcher, tmp_path):
    module, _members = fetcher
    with module.destination_lock(tmp_path):
        with pytest.raises(OSError, match="another fetch is running"):
            with module.destination_lock(tmp_path, timeout=0, poll=0):
                pass


def test_manifest_verifies_local_bytes_and_detects_tamper(tmp_path):
    verifier = load_script("dataset_manifest", MANIFEST_SCRIPT)
    source = json.loads((ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json").read_text())
    package = tmp_path / source["package"]["local_directory"]
    package.mkdir()
    for index, entry in enumerate(source["files"]):
        payload = f"synthetic-{index}".encode()
        target = package / entry["file"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        entry["size_bytes"] = len(payload)
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(source), encoding="utf-8")

    verifier.verify(manifest, tmp_path)
    (package / source["files"][0]["file"]).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="size mismatch|SHA-256 mismatch"):
        verifier.verify(manifest, tmp_path)


def test_manifest_rejects_unsafe_member_path(tmp_path):
    verifier = load_script("dataset_manifest_unsafe", MANIFEST_SCRIPT)
    source = json.loads((ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json").read_text())
    source["files"][0]["file"] = "../escape"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(source), encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe manifest file path"):
        verifier.verify(manifest, tmp_path)
