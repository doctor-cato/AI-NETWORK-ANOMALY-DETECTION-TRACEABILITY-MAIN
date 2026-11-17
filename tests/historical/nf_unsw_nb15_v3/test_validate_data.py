"""Synthetic CSV fixtures only; these are not UNSW-NB15 observations."""

import csv
import errno
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import threading
import time
from email.message import Message
from pathlib import Path
from urllib.error import URLError

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "historical" / "validate_unsw_nb15_2015.py"
)
MANIFEST_SCRIPT = SCRIPT.with_name("dataset_manifest_unsw_nb15_2015.py")
FETCH_SCRIPT = SCRIPT.with_name("fetch_unsw_nb15_2015.py")


@pytest.fixture
def validator(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("validate_data", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "DATA_RAW", tmp_path)
    return module


def row(module, **changes):
    values = {name: "1" for name in module.COLUMNS}
    values.update(proto="tcp", service="http", state="FIN", attack_cat="Normal", label="0")
    values.update(changes)
    return [values[name] for name in module.COLUMNS]


def write_csv(path, header, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)


def test_default_missing_is_skip(validator, capsys):
    assert validator.main([]) == 0
    assert "SKIPPED" in capsys.readouterr().out


def test_default_incomplete_split_fails(validator, tmp_path, capsys):
    target = tmp_path / validator.DEFAULT_FILES[0]
    write_csv(target, validator.COLUMNS, [row(validator)])
    assert validator.main([]) == 1
    assert "incomplete split" in capsys.readouterr().out


def test_valid_split_files_and_report(validator, tmp_path, capsys):
    for name in validator.DEFAULT_FILES:
        write_csv(
            tmp_path / name,
            validator.COLUMNS,
            [
                row(validator),
                row(validator, id="2", label="1", attack_cat="Generic"),
            ],
        )
    report_path = tmp_path / "report.json"
    # --no-row-count keeps this fixture below the published count of the real splits.
    assert validator.main(["--report", str(report_path), "--no-row-count"]) == 0
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert len(data["files"]) == 2
    assert data["files"][0]["rows"] == 2
    assert data["files"][0]["label_distribution"] == {"0": 1, "1": 1}
    assert data["files"][0]["attack_category_distribution"] == {"Generic": 1, "Normal": 1}
    assert data["files"][0]["columns"] == 45
    assert data["files"][0]["invalid_labels"] == 0
    assert data["files"][0]["invalid_attack_categories"] == 0
    assert data["cross_file_schema_consistent"] is True
    assert "PASS" in capsys.readouterr().out


def write_split(validator, directory, rows_per_file):
    for name in validator.DEFAULT_FILES:
        write_csv(directory / name, validator.COLUMNS, rows_per_file)


def test_default_split_row_count_is_enforced_without_a_manifest(validator, tmp_path, capsys):
    """A truncated but well-formed split must not pass the documented default validation."""
    write_split(validator, tmp_path, [row(validator)])
    assert validator.main([]) == 1
    out = capsys.readouterr().out
    assert "row count mismatch: expected 175341, got 1" in out


def test_no_row_count_flag_skips_the_published_row_count(validator, tmp_path, capsys):
    write_split(validator, tmp_path, [row(validator)])
    assert validator.main(["--no-row-count"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_non_default_file_has_no_published_row_count(validator, tmp_path, capsys):
    write_csv(tmp_path / "subset.csv", validator.COLUMNS, [row(validator)])
    assert validator.main(["--file", "subset.csv"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_manifest_row_count_is_recorded_in_the_report(validator, tmp_path):
    target = tmp_path / validator.DEFAULT_FILES[0]
    write_csv(target, validator.COLUMNS, [row(validator)])
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file": target.name,
                        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        "size_bytes": target.stat().st_size,
                        "expected_rows": 1,
                    }
                ]
            }
        )
    )
    report_path = tmp_path / "report.json"
    assert (
        validator.main(
            ["--file", target.name, "--manifest", str(manifest), "--report", str(report_path)]
        )
        == 0
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))["files"][0]
    assert report["expected_rows"] == 1
    assert report["row_count_matches_expected"] is True


def test_manifest_without_row_count_falls_back_to_the_published_count(validator, tmp_path, capsys):
    """A manifest that stays silent about row counts must not disable the default check."""
    target = tmp_path / validator.DEFAULT_FILES[0]
    write_csv(target, validator.COLUMNS, [row(validator)])
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file": target.name,
                        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        "size_bytes": target.stat().st_size,
                    }
                ]
            }
        )
    )
    assert validator.main(["--file", target.name, "--manifest", str(manifest)]) == 1
    assert "row count mismatch: expected 175341, got 1" in capsys.readouterr().out


@pytest.mark.parametrize(
    "defect, expected",
    [
        ("header", "schema mismatch"),
        ("label", "invalid label"),
        ("empty", "no data rows"),
        ("width", "wrong column count"),
        ("numeric", "invalid numeric value"),
        ("infinite", "non-finite value"),
        ("required", "missing required value"),
        ("label_category", "inconsistent label/attack_cat"),
        ("attack_category", "invalid attack_cat"),
    ],
)
def test_invalid_data_fails(validator, tmp_path, capsys, defect, expected):
    header = list(validator.COLUMNS)
    records = [row(validator)]
    if defect == "header":
        header[1] = "duration"
    elif defect == "label":
        records = [row(validator, label="2")]
    elif defect == "empty":
        records = []
    elif defect == "width":
        records = [records[0][:-1]]
    elif defect == "numeric":
        records = [row(validator, spkts="bad")]
    elif defect == "infinite":
        records = [row(validator, dur="inf")]
    elif defect == "label_category":
        records = [row(validator, label="1", attack_cat="Normal")]
    elif defect == "attack_category":
        records = [row(validator, label="1", attack_cat="Exploitss")]
    else:
        records = [row(validator, proto="")]
    write_csv(tmp_path / "bad.csv", header, records)
    assert validator.main(["--file", "bad.csv"]) == 1
    assert expected in capsys.readouterr().out


def test_missing_and_duplicates_are_reported_without_mutation(validator, tmp_path):
    target = tmp_path / "input.csv"
    record = row(validator, service="")
    write_csv(target, validator.COLUMNS, [record, record])
    before = target.read_bytes()
    result = validator.validate_file(target)
    assert result["missing_by_column"] == {"service": 2}
    assert result["duplicate_rows"] == 1
    assert len(result["warnings"]) >= 2
    assert target.read_bytes() == before


def test_explicit_missing_file_fails(validator, capsys):
    assert validator.main(["--file", "absent.csv"]) == 1
    assert "ERROR" in capsys.readouterr().out


def test_invalid_encoding_fails(validator, tmp_path, capsys):
    target = tmp_path / "bad.csv"
    target.write_bytes(b"label,proto\n0,\xff\n")
    assert validator.main(["--file", str(target)]) == 1
    assert "ERROR" in capsys.readouterr().out


@pytest.mark.parametrize(
    "header",
    [
        [],
        ["proto", "label"],
        ["id"] + ["proto"] * 44,
    ],
)
def test_missing_or_duplicate_header_fails(validator, tmp_path, header, capsys):
    target = tmp_path / "bad.csv"
    write_csv(target, header, [row(validator)])
    assert validator.main(["--file", str(target)]) == 1
    assert "schema mismatch" in capsys.readouterr().out


def test_quoted_field_and_bom(validator, tmp_path):
    target = tmp_path / "valid.csv"
    write_csv(target, validator.COLUMNS, [row(validator, service="a,b")])
    target.write_bytes(b"\xef\xbb\xbf" + target.read_bytes())
    assert validator.validate_file(target)["rows"] == 1


def test_manifest_mismatch_fails(validator, tmp_path, capsys):
    target = tmp_path / validator.DEFAULT_FILES[0]
    write_csv(target, validator.COLUMNS, [row(validator)])
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file": target.name,
                        "sha256": "0" * 64,
                        "size_bytes": target.stat().st_size,
                    }
                ]
            }
        )
    )
    assert validator.main(["--file", target.name, "--manifest", str(manifest)]) == 1
    assert "SHA-256 mismatch" in capsys.readouterr().out


def test_cli_exit_status(validator, tmp_path):
    target = tmp_path / "input.csv"
    write_csv(target, validator.COLUMNS, [row(validator)])
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--file", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    target.write_text("label,proto\n2,tcp\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--file", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1


def test_manifest_record_verify_and_tamper(validator, tmp_path):
    paths = [tmp_path / name for name in validator.DEFAULT_FILES]
    for target in paths:
        write_csv(target, validator.COLUMNS, [row(validator)])
    target = paths[0]
    manifest = tmp_path / "manifest.json"
    recorded = subprocess.run(
        [
            sys.executable,
            str(MANIFEST_SCRIPT),
            "record",
            "--file",
            str(target),
            "--file",
            str(paths[1]),
            "--acquired-from",
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "--downloaded-at",
            "2026-10-17T00:00:00Z",
            "--manifest",
            str(manifest),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert recorded.returncode == 0, recorded.stdout + recorded.stderr
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["files"][0]["sha256"] == validator.sha256_file(target)
    verified = subprocess.run(
        [
            sys.executable,
            str(MANIFEST_SCRIPT),
            "verify",
            "--manifest",
            str(manifest),
            "--directory",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    # The fixture holds one row per file, so the published row count is opted out of.
    assert (
        validator.main(["--file", str(target), "--manifest", str(manifest), "--no-row-count"]) == 0
    )
    target.write_bytes(target.read_bytes().replace(b"tcp", b"udp", 1))
    tampered = subprocess.run(
        [
            sys.executable,
            str(MANIFEST_SCRIPT),
            "verify",
            "--manifest",
            str(manifest),
            "--directory",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert tampered.returncode == 1
    assert "SHA-256 mismatch" in tampered.stdout
    assert validator.main(["--file", str(target), "--manifest", str(manifest)]) == 1


def test_manifest_rejects_incomplete_split(validator, tmp_path):
    target = tmp_path / validator.DEFAULT_FILES[0]
    write_csv(target, validator.COLUMNS, [row(validator)])
    result = subprocess.run(
        [
            sys.executable,
            str(MANIFEST_SCRIPT),
            "record",
            "--file",
            str(target),
            "--acquired-from",
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "--downloaded-at",
            "2026-10-17T00:00:00Z",
            "--manifest",
            str(tmp_path / "manifest.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "requires both" in result.stdout


def test_manifest_rejects_credentials_in_source_url(validator, tmp_path):
    paths = [tmp_path / name for name in validator.DEFAULT_FILES]
    for target in paths:
        write_csv(target, validator.COLUMNS, [row(validator)])
    result = subprocess.run(
        [
            sys.executable,
            str(MANIFEST_SCRIPT),
            "record",
            "--file",
            str(paths[0]),
            "--file",
            str(paths[1]),
            "--acquired-from",
            "https://user:secret@example.org/data",
            "--downloaded-at",
            "2026-10-17T00:00:00Z",
            "--manifest",
            str(tmp_path / "manifest.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert not (tmp_path / "manifest.json").exists()


@pytest.fixture
def fetcher():
    spec = importlib.util.spec_from_file_location("fetch_unsw_nb15", FETCH_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "payload",
    [
        b"<!doctype html><title>login</title>",
        b"version https://git-lfs.github.com/spec/v1\n",
    ],
)
def test_fetch_rejects_html_and_lfs_pointer(fetcher, tmp_path, payload):
    target = tmp_path / "dataset.csv"
    target.write_bytes(payload)
    with pytest.raises(ValueError, match="unexpected HTML or Git LFS pointer"):
        fetcher.verify_download(
            target,
            {
                "size_bytes": len(payload),
                "sha256": fetcher.sha256_file(target),
            },
        )


def test_fetch_rejects_checksum_mismatch(fetcher, tmp_path):
    target = tmp_path / "dataset.csv"
    target.write_bytes(b"id,label\r\n1,0\r\n")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        fetcher.verify_download(
            target,
            {
                "size_bytes": target.stat().st_size,
                "sha256": "0" * 64,
            },
        )


# --- fetch_unsw_nb15.py: safe local cache reuse ---------------------------------


class FakeResponse:
    """Minimal urlopen context manager returning fixed bytes."""

    def __init__(self, payload, content_type="text/plain", status=200):
        self._buffer = io.BytesIO(payload)
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def read(self, size=-1):
        return self._buffer.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


PAYLOAD = b"id,dur,proto,label\r\n1,0.1,tcp,0\r\n"


def entry_for(payload):
    return {"size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def serve(fetcher, monkeypatch, response):
    """Route every fetch to `response`; a callable response is invoked per call."""
    calls = []

    def fake_urlopen(request, timeout=None):
        calls.append(request.full_url)
        return response() if callable(response) else response

    monkeypatch.setattr(fetcher, "urlopen", fake_urlopen)
    return calls


def serve_files(monkeypatch, fetcher, payloads, fail_on=None):
    """Serve per-file bytes; `fail_on` makes that download raise instead."""
    calls = []

    def fake_urlopen(request, timeout=None):
        name = request.full_url.rsplit("/", 1)[-1]
        calls.append(name)
        if name == fail_on:
            raise URLError(f"offline: {name}")
        return FakeResponse(payloads[name])

    monkeypatch.setattr(fetcher, "urlopen", fake_urlopen)
    return calls


def fail_replace_on(monkeypatch, fetcher, destination_name):
    """Make os.replace fail when the destination has this file name; record the sources."""
    sources = []
    real_replace = os.replace

    def flaky_replace(src, dst):
        if Path(dst).name == destination_name:
            raise OSError(f"simulated replace failure for {destination_name}")
        sources.append(Path(src).name)
        return real_replace(src, dst)

    monkeypatch.setattr(fetcher.os, "replace", flaky_replace)
    return sources


def scratch_files(directory):
    """Staging and backup files; the lock file is a marker, not a leftover."""
    return sorted(
        path.name for path in directory.glob(".unsw-nb15-*") if path.name != fetch_lock_name()
    )


def fetch_lock_name():
    return ".unsw-nb15.lock"


def destination_entries(directory):
    """Destination contents a fetch is allowed to leave; the lock file is not one."""
    return sorted(path.name for path in directory.iterdir() if path.name != fetch_lock_name())


def test_fetch_cache_hit_avoids_network(fetcher, tmp_path, monkeypatch, capsys):
    def explode(*args, **kwargs):
        raise AssertionError("cache hit must not open a network connection")

    monkeypatch.setattr(fetcher, "urlopen", explode)
    (tmp_path / "a.csv").write_bytes(PAYLOAD)
    fetcher.fetch(tmp_path, files={"a.csv": entry_for(PAYLOAD)})
    out = capsys.readouterr().out
    assert "CACHE_HIT" in out
    assert "DOWNLOAD" not in out
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD


MIRROR = "https://example.test/mirror"


def fetch_one(fetcher, tmp_path, files, monkeypatch):
    fetcher.fetch(tmp_path, files=files, base_url=MIRROR)


def test_fetch_missing_file_downloads_verifies_and_installs(fetcher, tmp_path, monkeypatch, capsys):
    calls = serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    out = capsys.readouterr().out
    assert calls == [f"{MIRROR}/a.csv"]
    assert "CACHE_INVALID" in out and "DOWNLOAD" in out and "VERIFIED" in out
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD
    assert scratch_files(tmp_path) == []


def test_fetch_is_all_or_nothing_across_files(fetcher, tmp_path, monkeypatch, capsys):
    """A failure on the second file must not leave a half-populated destination."""
    payloads = {"a.csv": PAYLOAD, "b.csv": b"id,dur,label\r\n2,0.2,1\r\n"}
    seen = []

    def fake_urlopen(request, timeout=None):
        seen.append(request.full_url)
        if request.full_url.endswith("b.csv"):
            raise URLError("offline")
        return FakeResponse(payloads["a.csv"])

    monkeypatch.setattr(fetcher, "urlopen", fake_urlopen)
    with pytest.raises(URLError):
        fetch_one(fetcher, tmp_path, {k: entry_for(v) for k, v in payloads.items()}, monkeypatch)
    assert len(seen) == 2
    assert destination_entries(tmp_path) == []
    assert "CACHE_INVALID" in capsys.readouterr().out


def test_fetch_corrupt_cache_is_replaced(fetcher, tmp_path, monkeypatch, capsys):
    (tmp_path / "a.csv").write_bytes(b"truncated")
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetcher.fetch(tmp_path, files={"a.csv": entry_for(PAYLOAD)})
    out = capsys.readouterr().out
    assert "CACHE_INVALID" in out and "size mismatch" in out
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD
    assert scratch_files(tmp_path) == []


def test_fetch_checksum_mismatch_cache_is_replaced(fetcher, tmp_path, monkeypatch, capsys):
    # Same length, different bytes: only the SHA-256 comparison can catch this.
    corrupt = bytes(len(PAYLOAD))
    assert len(corrupt) == len(PAYLOAD)
    (tmp_path / "a.csv").write_bytes(corrupt)
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetcher.fetch(tmp_path, files={"a.csv": entry_for(PAYLOAD)})
    out = capsys.readouterr().out
    assert "CACHE_INVALID" in out and "SHA-256 mismatch" in out
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD


def test_fetch_cached_html_is_treated_as_invalid(fetcher, tmp_path, monkeypatch, capsys):
    html = b"<!doctype html><title>login</title>\r\n" + b"0" * len(PAYLOAD)
    (tmp_path / "a.csv").write_bytes(html)
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetcher.fetch(tmp_path, files={"a.csv": entry_for(PAYLOAD)})
    out = capsys.readouterr().out
    assert "unexpected HTML or Git LFS pointer" in out
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD


def test_fetch_download_failure_keeps_cache_and_leaves_no_staging(
    fetcher, tmp_path, monkeypatch, capsys
):
    (tmp_path / "a.csv").write_bytes(b"corrupt")
    serve(fetcher, monkeypatch, lambda: (_ for _ in ()).throw(URLError("offline")))
    assert fetcher.main(["--destination", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "CACHE_INVALID" in out
    assert "ERROR" in out
    # The unusable cache is left untouched rather than replaced by partial bytes.
    assert (tmp_path / "a.csv").read_bytes() == b"corrupt"
    assert scratch_files(tmp_path) == []


def test_fetch_rejects_html_payload_and_leaves_no_staging(fetcher, tmp_path, monkeypatch, capsys):
    html = b"<!doctype html><title>login</title>"
    serve(fetcher, monkeypatch, FakeResponse(html, content_type="text/html"))
    assert fetcher.main(["--destination", str(tmp_path)]) == 1
    assert "ERROR" in capsys.readouterr().out
    assert not (tmp_path / "a.csv").exists()
    assert scratch_files(tmp_path) == []


def test_fetch_rejects_checksum_mismatch_in_downloaded_payload(fetcher, tmp_path, monkeypatch):
    # Same length, different bytes: only the SHA-256 comparison can catch this.
    wrong = bytes(len(PAYLOAD))
    assert len(wrong) == len(PAYLOAD)
    serve(fetcher, monkeypatch, FakeResponse(wrong))
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    assert not (tmp_path / "a.csv").exists()
    assert scratch_files(tmp_path) == []


# --- fetch_unsw_nb15.py: install rollback and concurrent-run safety -------------


TWO_FILES = {
    "a.csv": b"id,dur,proto,label\r\n1,0.1,tcp,0\r\n",
    "b.csv": b"id,dur,proto,label\r\n2,0.2,udp,1\r\n",
}
PREVIOUS = {
    "a.csv": b"id,dur,proto,label\r\n9,9.9,tcp,1\r\n",
    "b.csv": b"id,dur,proto,label\r\n8,8.8,udp,1\r\n",
}


def test_rollback_restores_previous_bytes_when_second_swap_fails(
    fetcher, tmp_path, monkeypatch, capsys
):
    for name, blob in PREVIOUS.items():
        (tmp_path / name).write_bytes(blob)
    serve_files(monkeypatch, fetcher, TWO_FILES)
    fail_replace_on(monkeypatch, fetcher, "b.csv")
    with pytest.raises(OSError, match="simulated replace failure"):
        fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    out = capsys.readouterr().out
    assert "ROLLBACK" in out
    # The already-swapped file must go back to the bytes it held before this run.
    assert (tmp_path / "a.csv").read_bytes() == PREVIOUS["a.csv"]
    assert (tmp_path / "b.csv").read_bytes() == PREVIOUS["b.csv"]
    assert scratch_files(tmp_path) == []


def test_rollback_restores_missing_previous_file_as_absent(fetcher, tmp_path, monkeypatch, capsys):
    # Only a.csv exists beforehand; after a failed install it must exist again and
    # b.csv must still be absent, so the directory is never half populated.
    (tmp_path / "a.csv").write_bytes(PREVIOUS["a.csv"])
    serve_files(monkeypatch, fetcher, TWO_FILES)
    fail_replace_on(monkeypatch, fetcher, "b.csv")
    with pytest.raises(OSError):
        fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    assert (tmp_path / "a.csv").read_bytes() == PREVIOUS["a.csv"]
    assert not (tmp_path / "b.csv").exists()
    assert scratch_files(tmp_path) == []
    assert "ROLLBACK" in capsys.readouterr().out


def test_failed_install_exits_one_and_reports_rollback(fetcher, tmp_path, monkeypatch, capsys):
    for name, blob in PREVIOUS.items():
        (tmp_path / name).write_bytes(blob)
    monkeypatch.setattr(
        fetcher, "FILES", {name: entry_for(blob) for name, blob in TWO_FILES.items()}
    )
    serve_files(monkeypatch, fetcher, TWO_FILES)
    fail_replace_on(monkeypatch, fetcher, "b.csv")
    assert fetcher.main(["--destination", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "ERROR" in out and "ROLLBACK" in out
    assert (tmp_path / "a.csv").read_bytes() == PREVIOUS["a.csv"]


def test_install_backs_up_before_the_first_swap(fetcher, tmp_path, monkeypatch):
    """A target must remain readable on its own path until its own swap succeeds."""
    (tmp_path / "a.csv").write_bytes(PREVIOUS["a.csv"])
    staging = tmp_path / "stage-a.csv"
    staging.write_bytes(TWO_FILES["a.csv"])
    copies = []
    real_copy = fetcher.copy_file

    def record_copy(src, dst):
        copies.append((Path(src).name, Path(dst).name))
        return real_copy(src, dst)

    monkeypatch.setattr(fetcher, "copy_file", record_copy)
    fetcher.install({"a.csv": staging}, tmp_path)
    assert copies == [("a.csv", f"{fetcher.BACKUP_PREFIX}{os.getpid()}-a.csv")]
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]
    assert scratch_files(tmp_path) == []


def test_scratch_names_are_process_unique(fetcher, tmp_path, monkeypatch):
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    sources = []
    real_replace = os.replace

    def capture(src, dst):
        sources.append(Path(src).name)
        return real_replace(src, dst)

    monkeypatch.setattr(fetcher.os, "replace", capture)
    fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    assert sources == [f"{fetcher.STAGING_PREFIX}{os.getpid()}-a.csv"]
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD
    assert scratch_files(tmp_path) == []


def test_scratch_path_is_stable_and_pid_tagged(fetcher, tmp_path):
    first = fetcher.scratch_path(tmp_path, fetcher.STAGING_PREFIX, "a.csv")
    assert first == fetcher.scratch_path(tmp_path, fetcher.STAGING_PREFIX, "a.csv")
    assert first.name == f"{fetcher.STAGING_PREFIX}{os.getpid()}-a.csv"
    assert first.parent == tmp_path


def test_two_concurrent_runs_do_not_share_scratch_files(fetcher, tmp_path, monkeypatch):
    """Different PIDs must yield different scratch names for the same destination file."""
    other_pid = os.getpid() + 1
    mine = fetcher.scratch_path(tmp_path, fetcher.STAGING_PREFIX, "a.csv").name
    theirs = f"{fetcher.STAGING_PREFIX}{other_pid}-a.csv"
    assert mine != theirs


# --- rollback must never destroy data when its own restore fails ---------------


def fail_replace_after(fetcher, monkeypatch, rule):
    """Fail os.replace for destinations chosen by `rule(name, attempt_number)`."""
    attempts = {}
    real_replace = os.replace

    def flaky(src, dst):
        name = Path(dst).name
        attempts[name] = attempts.get(name, 0) + 1
        if rule(name, attempts[name]):
            raise OSError(f"simulated replace failure for {name}")
        return real_replace(src, dst)

    monkeypatch.setattr(fetcher.os, "replace", flaky)
    return attempts


def fails_on_second_attempt(name, attempt):
    return name == "b.csv" or (name == "a.csv" and attempt > 1)


def test_restore_failure_keeps_valid_file_and_backup(fetcher, tmp_path, monkeypatch, capsys):
    """A failing restore must not delete the verified file or the only backup."""
    for name, blob in PREVIOUS.items():
        (tmp_path / name).write_bytes(blob)
    serve_files(monkeypatch, fetcher, TWO_FILES)
    # b.csv fails during install; a.csv installs fine but then fails to restore.
    fail_replace_after(fetcher, monkeypatch, fails_on_second_attempt)
    with pytest.raises(OSError, match="simulated replace failure for b.csv"):
        fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    out = capsys.readouterr().out
    assert "ROLLBACK WARNING" in out
    assert "RECOVERY" in out
    # The verified new bytes stay in place; nothing is deleted before a restore succeeds.
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]
    assert (tmp_path / "b.csv").read_bytes() == PREVIOUS["b.csv"]
    # The backup that could not be restored survives for manual recovery, and so does the
    # transaction marker, so the next run can retry what this one could not finish.
    survivors = scratch_files(tmp_path)
    assert survivors == [f"{fetcher.BACKUP_PREFIX}{os.getpid()}-a.csv", fetcher.TXN_NAME]
    assert (tmp_path / survivors[0]).read_bytes() == PREVIOUS["a.csv"]


def test_newly_installed_file_is_removed_on_rollback(fetcher, tmp_path, monkeypatch, capsys):
    """A file this run created has no earlier version, so rollback returns it to absent."""
    (tmp_path / "b.csv").write_bytes(PREVIOUS["b.csv"])
    serve_files(monkeypatch, fetcher, TWO_FILES)
    fail_replace_on(monkeypatch, fetcher, "b.csv")
    with pytest.raises(OSError):
        fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    out = capsys.readouterr().out
    assert "ROLLBACK" in out and "RECOVERY" not in out
    # The directory must hold exactly what it held before this run.
    assert destination_entries(tmp_path) == ["b.csv"]
    assert (tmp_path / "b.csv").read_bytes() == PREVIOUS["b.csv"]
    assert scratch_files(tmp_path) == []


def test_rollback_removal_failure_keeps_file_and_reports_recovery(
    fetcher, tmp_path, monkeypatch, capsys
):
    """If the rollback removal itself fails, keep the verified file and say so."""
    (tmp_path / "b.csv").write_bytes(PREVIOUS["b.csv"])
    serve_files(monkeypatch, fetcher, TWO_FILES)
    fail_replace_on(monkeypatch, fetcher, "b.csv")
    real_unlink = Path.unlink

    def flaky_unlink(self, missing_ok=False):
        if self.name == "a.csv":
            raise PermissionError(f"simulated lock on {self.name}")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)
    with pytest.raises(OSError, match="simulated replace failure"):
        fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    out = capsys.readouterr().out
    assert "ROLLBACK WARNING" in out and "RECOVERY" in out
    assert "a.csv" in out.split("RECOVERY:")[1]
    # Verified bytes are never discarded, and the original error is still the one reported.
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]
    assert (tmp_path / "b.csv").read_bytes() == PREVIOUS["b.csv"]


def test_download_stops_at_the_pinned_size(fetcher, tmp_path, monkeypatch, capsys):
    """A response longer than the pinned size must abort before the extra byte is written."""
    oversized = PAYLOAD + b"attacker payload\r\n" * 1024
    serve(fetcher, monkeypatch, FakeResponse(oversized))
    with pytest.raises(ValueError, match="exceeds the pinned size"):
        fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    out = capsys.readouterr().out
    assert "DOWNLOAD" in out and "VERIFIED" not in out
    # Nothing is installed and no scratch file survives the abort.
    assert not (tmp_path / "a.csv").exists()
    assert scratch_files(tmp_path) == []


def test_download_does_not_write_past_the_pinned_size(fetcher, tmp_path):
    """The staging file never grows beyond the pinned size, so a huge body cannot fill disk."""
    limit = len(PAYLOAD)
    oversized = PAYLOAD + b"x" * (3 * fetcher.CHUNK_BYTES)
    staging = tmp_path / ".unsw-nb15-staging-probe.csv"
    with pytest.raises(ValueError, match="exceeds the pinned size"):
        with staging.open("wb") as output:
            fetcher.copy_up_to_limit(FakeResponse(oversized), output, limit, "a.csv")
    # The abort happens on the first byte past the limit, so nothing of the oversized
    # body is left behind.
    assert staging.stat().st_size <= limit


def lock_scratch_cleanup(monkeypatch, fetcher, prefix):
    """Make removing a scratch file fail, as a locked file does on Windows."""
    real_unlink = Path.unlink

    def flaky_unlink(self, missing_ok=False):
        if prefix in self.name:
            raise PermissionError(f"simulated lock on {self.name}")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)


def test_backup_cleanup_failure_keeps_the_install_error(fetcher, tmp_path, monkeypatch, capsys):
    """Double failure: the reported error must stay the install error, not the cleanup one."""
    for name, blob in PREVIOUS.items():
        (tmp_path / name).write_bytes(blob)
    serve_files(monkeypatch, fetcher, TWO_FILES)
    fail_replace_on(monkeypatch, fetcher, "b.csv")
    lock_scratch_cleanup(monkeypatch, fetcher, fetcher.BACKUP_PREFIX)
    with pytest.raises(OSError, match="simulated replace failure for b.csv"):
        fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    assert "CLEANUP WARNING" in capsys.readouterr().out
    assert (tmp_path / "a.csv").read_bytes() == PREVIOUS["a.csv"]


def test_staging_cleanup_failure_keeps_the_verify_error(fetcher, tmp_path, monkeypatch, capsys):
    wrong = bytes(len(PAYLOAD))
    serve(fetcher, monkeypatch, FakeResponse(wrong))
    lock_scratch_cleanup(monkeypatch, fetcher, fetcher.STAGING_PREFIX)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    out = capsys.readouterr().out
    assert "CLEANUP WARNING" in out
    assert not (tmp_path / "a.csv").exists()


def test_report_path_over_an_input_file_is_refused(validator, tmp_path, capsys):
    """The validator must never write its report over the dataset it just validated."""
    target = tmp_path / "input.csv"
    write_csv(target, validator.COLUMNS, [row(validator)])
    before = target.read_bytes()
    assert validator.main(["--file", str(target), "--report", str(target)]) == 1
    assert "refusing to overwrite" in capsys.readouterr().out
    assert target.read_bytes() == before


def test_report_path_reaching_an_input_file_by_relative_path_is_refused(
    validator, tmp_path, capsys
):
    target = tmp_path / "input.csv"
    write_csv(target, validator.COLUMNS, [row(validator)])
    indirect = tmp_path / "sub" / ".." / "input.csv"
    assert validator.main(["--file", str(target), "--report", str(indirect)]) == 1
    assert "refusing to overwrite" in capsys.readouterr().out


def test_report_path_next_to_the_input_is_allowed(validator, tmp_path):
    target = tmp_path / "input.csv"
    write_csv(target, validator.COLUMNS, [row(validator)])
    report = tmp_path / "report.json"
    assert validator.main(["--file", str(target), "--report", str(report), "--no-row-count"]) == 0
    assert json.loads(report.read_text(encoding="utf-8"))["files"][0]["rows"] == 1


def test_no_row_count_overrides_the_manifest_row_count(validator, tmp_path, capsys):
    """The documented escape hatch must also silence a row count read from a manifest."""
    target = tmp_path / validator.DEFAULT_FILES[0]
    write_csv(target, validator.COLUMNS, [row(validator)])
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file": target.name,
                        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        "size_bytes": target.stat().st_size,
                        "expected_rows": validator.EXPECTED_ROWS[target.name],
                    }
                ]
            }
        )
    )
    assert (
        validator.main(["--file", target.name, "--manifest", str(manifest), "--no-row-count"]) == 0
    )
    assert "PASS" in capsys.readouterr().out


# --- fetch_unsw_nb15.py: one lock per destination --------------------------------


def test_lock_is_held_for_the_transaction_and_released(fetcher, tmp_path, monkeypatch):
    """A concurrent run must find the lock held while this one is still swapping files."""
    seen = []
    real_replace = os.replace

    def capture(src, dst):
        seen.append((tmp_path / fetcher.LOCK_NAME).exists())
        return real_replace(src, dst)

    monkeypatch.setattr(fetcher.os, "replace", capture)
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    assert seen == [True]
    # The lock file stays on disk on purpose: deleting it would let another process
    # create a new inode and take the lock while this one still believes it holds it.
    assert (tmp_path / fetcher.LOCK_NAME).is_file()


def test_a_held_lock_stops_the_second_run_before_it_touches_the_cache(
    fetcher, tmp_path, monkeypatch, capsys
):
    """A run that cannot take the lock must fail instead of interleaving."""
    holding = threading.Event()
    release = threading.Event()

    def hold():
        with fetcher.destination_lock(tmp_path, timeout=5, poll=0.01):
            holding.set()
            release.wait(5)

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    try:
        assert holding.wait(5)
        monkeypatch.setattr(fetcher, "LOCK_TIMEOUT_SECONDS", 0)

        def explode(*args, **kwargs):
            raise AssertionError("a locked destination must not be read or written")

        monkeypatch.setattr(fetcher, "urlopen", explode)
        with pytest.raises(OSError, match="another fetch is running"):
            fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
        assert "LOCK" in capsys.readouterr().out
        assert not (tmp_path / "a.csv").exists()
    finally:
        release.set()
        holder.join(5)


def test_second_run_waits_for_the_lock_instead_of_failing(fetcher, tmp_path, monkeypatch):
    """A short overlap must serialise, not error: the waiter takes the lock afterwards."""
    holding = threading.Event()
    release = threading.Event()
    marks = {}

    def hold():
        with fetcher.destination_lock(tmp_path, timeout=5, poll=0.01):
            holding.set()
            release.wait(5)
            marks["released"] = time.monotonic()

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    try:
        assert holding.wait(5)
        monkeypatch.setattr(fetcher, "LOCK_TIMEOUT_SECONDS", 10)
        monkeypatch.setattr(fetcher, "LOCK_POLL_SECONDS", 0.01)
        timer = threading.Timer(0.2, release.set)
        timer.start()
        try:
            with fetcher.destination_lock(tmp_path, timeout=10, poll=0.01):
                marks["acquired"] = time.monotonic()
        finally:
            timer.cancel()
        # Compared as instants, not durations: the waiter may only enter after the
        # holder is out, and no wall-clock tolerance is needed for that.
        assert marks["acquired"] >= marks["released"]
    finally:
        release.set()
        holder.join(5)


def test_abandoned_lock_file_does_not_block_a_new_run(fetcher, tmp_path, monkeypatch):
    """A lock file left by a killed run must not hold the directory hostage."""
    (tmp_path / fetcher.LOCK_NAME).write_text("pid=1\n", encoding="utf-8")
    # Short timeout so a lock implementation that waits on a marker file fails fast
    # instead of stalling the suite for the full production timeout.
    monkeypatch.setattr(fetcher, "LOCK_TIMEOUT_SECONDS", 2)
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    started = time.monotonic()
    fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    assert time.monotonic() - started < 1.0
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD


def test_no_background_work_outlives_the_lock(fetcher, tmp_path):
    """Nothing may keep touching the lock file after this run has left the context.

    A heartbeat thread that outlives the release can touch the lock file of the next
    owner, which corrupts its staleness handling and the isolation of the transaction.
    """
    baseline = {thread.ident for thread in threading.enumerate()}
    lock = tmp_path / fetcher.LOCK_NAME
    with fetcher.destination_lock(tmp_path, timeout=5, poll=0.01):
        assert lock.is_file()
    stamp = lock.stat().st_mtime_ns
    time.sleep(0.2)
    assert lock.stat().st_mtime_ns == stamp
    assert {thread.ident for thread in threading.enumerate()} == baseline


def test_failed_backup_copy_leaves_no_partial_file(fetcher, tmp_path, monkeypatch, capsys):
    """A copy that fails halfway must not leave a backup nobody knows to clean up."""
    (tmp_path / "a.csv").write_bytes(PREVIOUS["a.csv"])
    staging = tmp_path / "stage-a.csv"
    staging.write_bytes(TWO_FILES["a.csv"])

    def failing_copy(src, dst):
        Path(dst).write_bytes(b"partial")
        raise OSError(f"simulated copy failure for {Path(dst).name}")

    monkeypatch.setattr(fetcher, "copy_file", failing_copy)
    with pytest.raises(OSError, match="simulated copy failure"):
        fetcher.install({"a.csv": staging}, tmp_path)
    assert "CLEANUP WARNING" not in capsys.readouterr().out
    assert scratch_files(tmp_path) == []
    # The destination still holds the bytes it had before the failed run.
    assert (tmp_path / "a.csv").read_bytes() == PREVIOUS["a.csv"]


def test_planted_symlink_at_the_staging_path_cannot_redirect_the_write(
    fetcher, tmp_path, monkeypatch
):
    """A predictable staging name must not be able to write outside the destination."""
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"must not be touched")
    staging = tmp_path / f"{fetcher.STAGING_PREFIX}{os.getpid()}-a.csv"
    try:
        os.symlink(outside, staging)
    except OSError:  # pragma: no cover - needs symlink privilege
        pytest.skip("symlinks are not available for this user")
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    assert outside.read_bytes() == b"must not be touched"
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD


def test_planted_symlink_at_the_backup_path_cannot_redirect_the_copy(
    fetcher, tmp_path, monkeypatch
):
    """The backup copy must not follow a symlink either."""
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"must not be touched")
    (tmp_path / "a.csv").write_bytes(PREVIOUS["a.csv"])
    try:
        os.symlink(outside, tmp_path / f"{fetcher.BACKUP_PREFIX}{os.getpid()}-a.csv")
    except OSError:  # pragma: no cover - needs symlink privilege
        pytest.skip("symlinks are not available for this user")
    staging = tmp_path / "stage-a.csv"
    staging.write_bytes(TWO_FILES["a.csv"])
    fetcher.install({"a.csv": staging}, tmp_path)
    assert outside.read_bytes() == b"must not be touched"
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]


def test_a_crash_between_swaps_is_recovered_on_the_next_run(fetcher, tmp_path, monkeypatch, capsys):
    """A process killed mid-swap must not leave the pair mixed until someone intervenes."""
    for name, blob in PREVIOUS.items():
        (tmp_path / name).write_bytes(blob)
    # State left by a run that swapped a.csv, then died before touching b.csv.
    (tmp_path / "a.csv").write_bytes(TWO_FILES["a.csv"])
    kept_backup = tmp_path / f"{fetcher.BACKUP_PREFIX}999-a.csv"
    kept_backup.write_bytes(PREVIOUS["a.csv"])
    (tmp_path / fetcher.TXN_NAME).write_text(
        json.dumps(
            {
                "pid": 999,
                "files": [
                    {"name": "a.csv", "backup": kept_backup.name},
                    {"name": "b.csv", "backup": None},
                ],
            }
        ),
        encoding="utf-8",
    )
    # b.csv vanished with the crash, so its pre-run state was absence.
    (tmp_path / "b.csv").unlink()
    serve_files(monkeypatch, fetcher, TWO_FILES)
    fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    # Recovery ran before the cache check, then the run installed both verified files.
    out = capsys.readouterr().out
    assert "RECOVERY: restored a.csv" in out
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]
    assert (tmp_path / "b.csv").read_bytes() == TWO_FILES["b.csv"]
    assert not (tmp_path / fetcher.TXN_NAME).exists()
    assert scratch_files(tmp_path) == []


def test_completed_transaction_leaves_no_marker(fetcher, tmp_path, monkeypatch):
    (tmp_path / "a.csv").write_bytes(PREVIOUS["a.csv"])
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    assert not (tmp_path / fetcher.TXN_NAME).exists()


def test_report_path_over_the_manifest_is_refused(validator, tmp_path, capsys):
    """The report must not overwrite the provenance manifest it was validated against."""
    target = tmp_path / validator.DEFAULT_FILES[0]
    write_csv(target, validator.COLUMNS, [row(validator)])
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "file": target.name,
                        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        "size_bytes": target.stat().st_size,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    before = manifest.read_bytes()
    args = ["--file", str(target), "--manifest", str(manifest), "--report", str(manifest)]
    assert validator.main(args + ["--no-row-count"]) == 1
    assert "refusing to overwrite" in capsys.readouterr().out
    assert manifest.read_bytes() == before


def test_a_failed_recovery_keeps_the_marker_and_the_backup(fetcher, tmp_path, monkeypatch, capsys):
    """A restore that cannot finish must keep the record of where the old bytes are."""
    (tmp_path / "a.csv").write_bytes(TWO_FILES["a.csv"])
    kept_backup = tmp_path / f"{fetcher.BACKUP_PREFIX}999-a.csv"
    kept_backup.write_bytes(PREVIOUS["a.csv"])
    (tmp_path / fetcher.TXN_NAME).write_text(
        json.dumps({"pid": 999, "files": [{"name": "a.csv", "backup": kept_backup.name}]}),
        encoding="utf-8",
    )

    def refuse_replace(src, dst):
        raise OSError(f"simulated restore failure for {Path(dst).name}")

    monkeypatch.setattr(fetcher.os, "replace", refuse_replace)
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    with pytest.raises(OSError, match="RECOVERY incomplete"):
        fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    out = capsys.readouterr().out
    assert "RECOVERY WARNING" in out
    # Deleting the marker here would orphan the only surviving copy of the old bytes.
    assert (tmp_path / fetcher.TXN_NAME).is_file()
    assert kept_backup.read_bytes() == PREVIOUS["a.csv"]
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]


def test_recovery_refuses_to_continue_on_a_marker_it_cannot_parse(
    fetcher, tmp_path, monkeypatch, capsys
):
    """An unreadable marker describes an unknown state; installing over it would hide it."""
    marker = tmp_path / fetcher.TXN_NAME
    marker.write_text("{not json", encoding="utf-8")

    def explode(*args, **kwargs):
        raise AssertionError("nothing may be downloaded while the state is unknown")

    monkeypatch.setattr(fetcher, "urlopen", explode)
    with pytest.raises(OSError, match="cannot interpret"):
        fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    assert marker.read_text(encoding="utf-8") == "{not json"
    assert not (tmp_path / "a.csv").exists()


def test_record_does_not_leave_a_partial_manifest(manifest_module, tmp_path, monkeypatch):
    """An interrupted record must not leave a truncated manifest record refuses to replace."""
    splits = []
    for name in manifest_module.DEFAULT_FILES:
        path = tmp_path / name
        path.write_bytes(b"id,label\r\n1,0\r\n")
        splits.append(path)
    manifest = tmp_path / "manifest.json"

    def refuse_publish(src, dst):
        raise OSError("simulated manifest publish failure")

    def refuse_claim(path, flags, *args, **kwargs):
        if Path(path) == manifest:
            raise OSError("simulated manifest publish failure")
        return os.open(path, flags, *args, **kwargs)

    # Every publish path: the hard link, the atomic swap and the exclusive claim.
    monkeypatch.setattr(manifest_module.os, "link", refuse_publish)
    monkeypatch.setattr(manifest_module.os, "replace", refuse_publish)
    monkeypatch.setattr(manifest_module.os, "open", refuse_claim)
    with pytest.raises(OSError, match="simulated manifest publish failure"):
        manifest_module.record(
            splits,
            manifest,
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "2026-10-17T00:00:00Z",
        )
    assert not manifest.exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(path.name for path in splits)


def test_recovery_retries_after_a_partly_completed_run(fetcher, tmp_path, monkeypatch, capsys):
    """A backup restored in an earlier attempt must not make the next attempt fail."""
    (tmp_path / "a.csv").write_bytes(TWO_FILES["a.csv"])
    (tmp_path / "b.csv").write_bytes(TWO_FILES["b.csv"])
    first_backup = tmp_path / f"{fetcher.BACKUP_PREFIX}999-a.csv"
    first_backup.write_bytes(PREVIOUS["a.csv"])
    second_backup = tmp_path / f"{fetcher.BACKUP_PREFIX}999-b.csv"
    second_backup.write_bytes(PREVIOUS["b.csv"])
    marker = tmp_path / fetcher.TXN_NAME
    marker.write_text(
        json.dumps(
            {
                "pid": 999,
                "files": [
                    {"name": "a.csv", "backup": first_backup.name},
                    {"name": "b.csv", "backup": second_backup.name},
                ],
            }
        ),
        encoding="utf-8",
    )
    real_replace = os.replace

    def refuse_b(src, dst):
        if Path(dst).name == "b.csv":
            raise OSError("simulated restore failure for b.csv")
        return real_replace(src, dst)

    monkeypatch.setattr(fetcher.os, "replace", refuse_b)
    serve_files(monkeypatch, fetcher, TWO_FILES)
    with pytest.raises(OSError, match="RECOVERY incomplete"):
        fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    capsys.readouterr()
    # a.csv was restored and its backup consumed; b.csv failed, so the marker stays.
    assert (tmp_path / "a.csv").read_bytes() == PREVIOUS["a.csv"]
    assert not first_backup.exists()
    assert second_backup.is_file()
    assert marker.is_file()

    # The next run must finish the job instead of tripping over the consumed backup.
    monkeypatch.setattr(fetcher.os, "replace", real_replace)
    serve_files(monkeypatch, fetcher, TWO_FILES)
    fetch_one(fetcher, tmp_path, {n: entry_for(v) for n, v in TWO_FILES.items()}, monkeypatch)
    out = capsys.readouterr().out
    assert "RECOVERY WARNING" not in out
    assert not marker.exists()
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]
    assert (tmp_path / "b.csv").read_bytes() == TWO_FILES["b.csv"]


def test_a_failed_recovery_blocks_the_run_before_touching_anything(
    fetcher, tmp_path, monkeypatch, capsys
):
    """If recovery cannot finish, no download and no install may follow it."""
    (tmp_path / "a.csv").write_bytes(TWO_FILES["a.csv"])
    kept_backup = tmp_path / f"{fetcher.BACKUP_PREFIX}999-a.csv"
    kept_backup.write_bytes(PREVIOUS["a.csv"])
    marker = tmp_path / fetcher.TXN_NAME
    marker.write_text(
        json.dumps({"pid": 999, "files": [{"name": "a.csv", "backup": kept_backup.name}]}),
        encoding="utf-8",
    )

    def refuse_replace(src, dst):
        raise OSError(f"simulated restore failure for {Path(dst).name}")

    def explode(*args, **kwargs):
        raise AssertionError("a blocked run must not download anything")

    monkeypatch.setattr(fetcher.os, "replace", refuse_replace)
    monkeypatch.setattr(fetcher, "urlopen", explode)
    with pytest.raises(OSError, match="RECOVERY"):
        fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    out = capsys.readouterr().out
    assert "RECOVERY WARNING" in out
    # Data and the evidence needed to repair it both survive.
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]
    assert kept_backup.read_bytes() == PREVIOUS["a.csv"]
    assert marker.is_file()
    assert scratch_files(tmp_path) == [kept_backup.name, fetcher.TXN_NAME]


def test_open_new_never_removes_what_is_already_there(fetcher, tmp_path):
    """The exclusive open must refuse, not clean up, whatever occupies the name."""
    existing = tmp_path / "scratch.bin"
    existing.write_bytes(b"an earlier run left this")
    with pytest.raises(FileExistsError):
        fetcher.open_new(existing)
    assert existing.read_bytes() == b"an earlier run left this"


def test_a_leftover_scratch_file_is_never_deleted_or_overwritten(fetcher, tmp_path, monkeypatch):
    """A scratch name that is already taken belongs to an earlier run; leave it alone."""
    leftover = tmp_path / f"{fetcher.STAGING_PREFIX}{os.getpid()}-a.csv"
    leftover.write_bytes(b"earlier run left this here")
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetch_one(fetcher, tmp_path, {"a.csv": entry_for(PAYLOAD)}, monkeypatch)
    assert leftover.read_bytes() == b"earlier run left this here"
    assert (tmp_path / "a.csv").read_bytes() == PAYLOAD
    # The run used a different staging name and cleaned up after itself.
    assert scratch_files(tmp_path) == [leftover.name]


def test_a_leftover_backup_name_is_never_overwritten(fetcher, tmp_path, monkeypatch):
    """Same rule for the backup name, which may hold the only copy of older bytes."""
    (tmp_path / "a.csv").write_bytes(PREVIOUS["a.csv"])
    kept = tmp_path / f"{fetcher.BACKUP_PREFIX}{os.getpid()}-a.csv"
    kept.write_bytes(b"only surviving copy")
    staging = tmp_path / "stage-a.csv"
    staging.write_bytes(TWO_FILES["a.csv"])
    fetcher.install({"a.csv": staging}, tmp_path)
    assert kept.read_bytes() == b"only surviving copy"
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]
    assert scratch_files(tmp_path) == [kept.name]


def test_record_refuses_an_existing_manifest_without_touching_it(manifest_module, tmp_path, capsys):
    """A second record must fail rather than replace provenance that is already there."""
    splits = []
    for name in manifest_module.DEFAULT_FILES:
        path = tmp_path / name
        path.write_bytes(b"id,label\r\n1,0\r\n")
        splits.append(path)
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"variant": "existing provenance"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="manifest already exists"):
        manifest_module.record(
            splits,
            manifest,
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "2026-10-17T00:00:00Z",
        )
    assert manifest.read_text(encoding="utf-8") == '{"variant": "existing provenance"}\n'
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(
        [path.name for path in splits] + ["manifest.json"]
    )


def test_recovery_refuses_unverified_bytes_when_the_backup_is_gone(fetcher, tmp_path, monkeypatch):
    """A missing backup plus an existing target is only accepted when the bytes check out."""
    name = "UNSW_NB15_training-set.csv"
    monkeypatch.setattr(fetcher, "FILES", {name: entry_for(PAYLOAD)})
    target = tmp_path / name
    target.write_bytes(b"not the bytes this pair should hold")
    marker = tmp_path / fetcher.TXN_NAME
    marker.write_text(
        json.dumps({"pid": 999, "files": [{"name": name, "backup": "gone-a.csv"}]}),
        encoding="utf-8",
    )

    def explode(*args, **kwargs):
        raise AssertionError("a blocked run must not download anything")

    monkeypatch.setattr(fetcher, "urlopen", explode)
    with pytest.raises(OSError, match="RECOVERY incomplete"):
        fetcher.fetch(tmp_path, files={name: entry_for(PAYLOAD)})
    assert target.read_bytes() == b"not the bytes this pair should hold"
    assert marker.is_file()


def test_recovery_accepts_already_restored_bytes_it_can_verify(fetcher, tmp_path, monkeypatch):
    """When the target matches the pinned checksum, the entry really was restored earlier."""
    name = "UNSW_NB15_training-set.csv"
    monkeypatch.setattr(fetcher, "FILES", {name: entry_for(PAYLOAD)})
    target = tmp_path / name
    target.write_bytes(PAYLOAD)
    marker = tmp_path / fetcher.TXN_NAME
    marker.write_text(
        json.dumps({"pid": 999, "files": [{"name": name, "backup": "gone-a.csv"}]}),
        encoding="utf-8",
    )
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    fetcher.fetch(tmp_path, files={name: entry_for(PAYLOAD)})
    assert not marker.exists()
    assert target.read_bytes() == PAYLOAD


def test_publish_new_claims_the_name_atomically_without_hardlinks(
    manifest_module, tmp_path, monkeypatch
):
    """Without hard links, a manifest that appears mid-publish must still not be replaced."""
    staged = tmp_path / "staged.json"
    staged.write_text("new provenance", encoding="utf-8")
    destination = tmp_path / "manifest.json"
    real_open = os.open

    def link_unsupported(*args, **kwargs):
        raise OSError(errno.ENOTSUP, "no hard links here")

    def racing_open(path, flags, *args, **kwargs):
        if Path(path) == destination:
            destination.write_text("someone else's manifest", encoding="utf-8")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(manifest_module.os, "link", link_unsupported)
    monkeypatch.setattr(manifest_module.os, "open", racing_open)
    with pytest.raises(FileExistsError):
        manifest_module.publish_new(staged, destination)
    assert destination.read_text(encoding="utf-8") == "someone else's manifest"


def test_publish_new_still_works_without_hardlinks(manifest_module, tmp_path, monkeypatch):
    """The fallback has to remain usable where hard links do not exist."""
    staged = tmp_path / "staged.json"
    staged.write_text("new provenance", encoding="utf-8")
    destination = tmp_path / "manifest.json"

    def link_unsupported(*args, **kwargs):
        raise OSError(errno.ENOTSUP, "no hard links here")

    monkeypatch.setattr(manifest_module.os, "link", link_unsupported)
    manifest_module.publish_new(staged, destination)
    assert destination.read_text(encoding="utf-8") == "new provenance"


def test_publish_new_refuses_an_existing_destination(manifest_module, tmp_path):
    """The publish step is the last line of defence: it must never overwrite."""
    staged = tmp_path / "staged.json"
    staged.write_text("new provenance", encoding="utf-8")
    destination = tmp_path / "manifest.json"
    destination.write_text("existing provenance", encoding="utf-8")
    with pytest.raises(FileExistsError):
        manifest_module.publish_new(staged, destination)
    assert destination.read_text(encoding="utf-8") == "existing provenance"
    assert staged.read_text(encoding="utf-8") == "new provenance"


def test_record_stages_beside_the_manifest_without_clobbering_it(manifest_module, tmp_path):
    """The staged file is process-unique, so two records cannot write the same one."""
    splits = []
    for name in manifest_module.DEFAULT_FILES:
        path = tmp_path / name
        path.write_bytes(b"id,label\r\n1,0\r\n")
        splits.append(path)
    manifest = tmp_path / "manifest.json"
    manifest_module.record(
        splits,
        manifest,
        "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "2026-10-17T00:00:00Z",
    )
    assert manifest.is_file()
    assert not list(tmp_path.glob(f"{manifest.name}.*.partial"))


def test_existing_backup_is_never_overwritten(fetcher, tmp_path, monkeypatch):
    """A backup kept for RECOVERY must survive a later run, including a reused PID."""
    (tmp_path / "a.csv").write_bytes(PREVIOUS["a.csv"])
    kept = tmp_path / f"{fetcher.BACKUP_PREFIX}{os.getpid()}-a.csv"
    kept.write_bytes(b"only surviving copy of the previous bytes")
    staging = tmp_path / "stage-a.csv"
    staging.write_bytes(TWO_FILES["a.csv"])
    fetcher.install({"a.csv": staging}, tmp_path)
    assert kept.read_bytes() == b"only surviving copy of the previous bytes"
    assert (tmp_path / "a.csv").read_bytes() == TWO_FILES["a.csv"]
    assert scratch_files(tmp_path) == [kept.name]


# --- validate_data.py: the SKIPPED contract must stay unmistakable -------------


def test_skipped_states_explicitly_that_it_is_not_a_pass(validator, capsys):
    assert validator.main([]) == 0
    out = capsys.readouterr().out
    assert "SKIPPED" in out
    assert "SKIPPED is not PASS" in out


def test_skipped_emits_ci_warning_annotation(validator, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert validator.main([]) == 0
    out = capsys.readouterr().out
    assert "::warning" in out
    assert "SKIPPED is not a PASS" in out


def test_no_ci_annotation_outside_github_actions(validator, monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert validator.main([]) == 0
    out = capsys.readouterr().out
    assert "::warning" not in out
    assert "SKIPPED is not PASS" in out


def test_fetch_is_repeatable_and_stable(fetcher, tmp_path, monkeypatch, capsys):
    serve(fetcher, monkeypatch, FakeResponse(PAYLOAD))
    files = {"a.csv": entry_for(PAYLOAD)}
    fetcher.fetch(tmp_path, files=files)
    first = (tmp_path / "a.csv").read_bytes()
    fetcher.fetch(tmp_path, files=files)
    assert (tmp_path / "a.csv").read_bytes() == first == PAYLOAD
    assert capsys.readouterr().out.count("CACHE_HIT") == 1


# --- validate_data.py: blank CSV lines are never skipped silently ---------------


@pytest.mark.parametrize(
    "row, blank",
    [
        ([], True),
        (["   "], True),
        (["\t"], True),
        (["", "", ""], False),
        (["", "", "", "", ""], False),
        (["1"], False),
    ],
)
def test_blank_line_classification(validator, row, blank):
    assert validator.is_blank_line(row) is blank


def write_lines(path, header, records):
    lines = [",".join(header)]
    lines.extend(record if isinstance(record, str) else ",".join(record) for record in records)
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write("\r\n".join(lines) + "\r\n")


def test_blank_line_fails_with_count_and_line_numbers(validator, tmp_path):
    target = tmp_path / "blank.csv"
    write_lines(
        target,
        validator.COLUMNS,
        [row(validator), "", row(validator, id="2"), "   ", row(validator, id="3")],
    )
    with pytest.raises(ValueError) as error:
        validator.validate_file(target)
    message = str(error.value)
    assert "2 blank CSV line(s)" in message
    assert "3, 5" in message


def test_blank_line_exit_code_and_message(validator, tmp_path, capsys):
    target = tmp_path / "blank.csv"
    write_lines(target, validator.COLUMNS, [row(validator), ""])
    assert validator.main(["--file", str(target)]) == 1
    assert "blank CSV line" in capsys.readouterr().out


def test_blank_line_does_not_reach_counters_on_valid_file(validator, tmp_path):
    target = tmp_path / "clean.csv"
    write_csv(target, validator.COLUMNS, [row(validator)])
    report = validator.validate_file(target)
    assert report["blank_lines"] == 0
    assert report["rows"] == 1
    assert report["duplicate_rows"] == 0


def test_empty_delimited_row_is_a_missing_value_not_a_blank_line(validator, tmp_path):
    target = tmp_path / "empty.csv"
    write_lines(target, validator.COLUMNS, [row(validator), [""] * len(validator.COLUMNS)])
    with pytest.raises(ValueError) as error:
        validator.validate_file(target)
    # Treated as a data row with empty values, never silently skipped as blank.
    assert "blank CSV line" not in str(error.value)
    assert "invalid label" in str(error.value)


def test_short_empty_delimited_row_is_a_width_defect(validator, tmp_path):
    target = tmp_path / "narrow.csv"
    write_lines(target, validator.COLUMNS, [row(validator), ",,"])
    with pytest.raises(ValueError, match="wrong column count"):
        validator.validate_file(target)


def test_trailing_newline_is_not_a_blank_line(validator, tmp_path):
    target = tmp_path / "trailing.csv"
    write_csv(target, validator.COLUMNS, [row(validator)])
    assert validator.validate_file(target)["rows"] == 1


# --- dataset_manifest.py: timezone-aware UTC timestamps -------------------------


@pytest.fixture
def manifest_module(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("dataset_manifest", MANIFEST_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-17T16:30:00Z",
        "2026-10-17T16:30:00+00:00",
        "2026-10-17T18:30:00+02:00",
        "2026-10-17T09:30:00-07:00",
    ],
)
def test_aware_timestamps_normalize_to_utc(manifest_module, value):
    moment = manifest_module.parse_utc(value, "downloaded_at")
    assert moment.tzinfo is not None
    assert manifest_module.format_utc(moment) == "2026-10-17T16:30:00Z"


def test_format_utc_round_trip_is_stable(manifest_module):
    once = manifest_module.format_utc(manifest_module.parse_utc("2026-10-17T18:30:00+02:00", "d"))
    twice = manifest_module.format_utc(manifest_module.parse_utc(once, "d"))
    assert once == twice == "2026-10-17T16:30:00Z"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-10-17T16:30:00", "naive"),
        ("2026-10-17 16:30", "naive"),
        ("2026-10-17", "naive"),
        ("17/10/2026 16:30", "not a valid ISO 8601"),
        ("", "not a valid ISO 8601"),
        (1750000000, "must be an ISO 8601 string"),
        (None, "must be an ISO 8601 string"),
        ("20261017T163000Z", "must use YYYY-MM-DDTHH:MM:SSZ"),
        ("2026-W42-4T00:00:00+00:00", "must use YYYY-MM-DDTHH:MM:SSZ"),
        ("2026-10-17 16:30:00+00:00", "must use YYYY-MM-DDTHH:MM:SSZ"),
        ("2026-10-17T16:30:00.500Z", "must use YYYY-MM-DDTHH:MM:SSZ"),
    ],
)
def test_parse_utc_rejects_naive_and_malformed(manifest_module, value, expected):
    with pytest.raises(ValueError, match=expected):
        manifest_module.parse_utc(value, "downloaded_at")


def test_iter_timestamps_finds_nested_provenance_fields(manifest_module):
    payload = {
        "downloaded_at": "2026-10-17T16:30:00Z",
        "recorded_at_utc": "2026-10-17T16:30:00Z",
        "official_source": {"accessed_at_utc": "2026-10-17T16:30:00Z", "url": "https://x.test"},
        "observations": [{"checked_at_utc": "2026-10-17T16:30:00Z"}, {"result": "ok"}],
    }
    fields = {field for field, _ in manifest_module.iter_timestamps(payload)}
    assert fields == {
        "downloaded_at",
        "recorded_at_utc",
        "official_source.accessed_at_utc",
        "observations[0].checked_at_utc",
    }


def write_manifest(path, files, **extra):
    path.write_text(json.dumps({"files": files, **extra}, indent=2) + "\n", encoding="utf-8")
    return path


def manifest_run(action, manifest, directory, extra_args=()):
    return subprocess.run(
        [
            sys.executable,
            str(MANIFEST_SCRIPT),
            action,
            "--manifest",
            str(manifest),
            "--directory",
            str(directory),
            *extra_args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def record_run(tmp_path, downloaded_at, manifest=None):
    paths = []
    for name in ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"):
        target = tmp_path / name
        write_csv(target, ["id", "proto", "label"], [["1", "tcp", "0"]])
        paths += ["--file", str(target)]
    target_manifest = manifest or (tmp_path / "manifest.json")
    result = subprocess.run(
        [
            sys.executable,
            str(MANIFEST_SCRIPT),
            "record",
            *paths,
            "--acquired-from",
            "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "--downloaded-at",
            downloaded_at,
            "--manifest",
            str(target_manifest),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result, target_manifest


def test_record_normalizes_offset_timestamp_to_utc(tmp_path):
    result, manifest = record_run(tmp_path, "2026-10-17T18:30:00+02:00")
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["downloaded_at"] == "2026-10-17T16:30:00Z"
    assert data["recorded_at_utc"].endswith("Z")


def test_record_rejects_naive_downloaded_at(tmp_path):
    result, manifest = record_run(tmp_path, "2026-10-17T16:30:00")
    assert result.returncode == 1
    assert "naive" in result.stdout
    assert not manifest.exists()


def test_record_rejects_malformed_downloaded_at(tmp_path):
    result, _ = record_run(tmp_path, "17/10/2026")
    assert result.returncode == 1
    assert "not a valid ISO 8601" in result.stdout


def test_verify_accepts_utc_manifest_without_rewriting(tmp_path):
    result, manifest = record_run(tmp_path, "2026-10-17T18:30:00+02:00")
    assert result.returncode == 0, result.stdout + result.stderr
    before = manifest.read_bytes()
    verified = manifest_run("verify", manifest, tmp_path)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "timezone-aware timestamp" in verified.stdout
    # verify must not rewrite provenance metadata or add a volatile timestamp.
    assert manifest.read_bytes() == before


@pytest.mark.parametrize(
    "stamp, expected",
    [
        ("2026-10-17T16:30:00", "naive"),
        ("not-a-timestamp", "not a valid ISO 8601"),
    ],
)
def test_verify_rejects_bad_manifest_timestamp(tmp_path, stamp, expected):
    result, manifest = record_run(tmp_path, "2026-10-17T16:30:00Z")
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["downloaded_at"] = stamp
    manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    verified = manifest_run("verify", manifest, tmp_path)
    assert verified.returncode == 1
    assert expected in verified.stdout


def test_verify_rejects_nested_naive_provenance_timestamp(tmp_path):
    result, manifest = record_run(tmp_path, "2026-10-17T16:30:00Z")
    assert result.returncode == 0, result.stdout + result.stderr
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["independent_observations"] = [
        {"source": "https://x.test", "checked_at_utc": "2026-10-17"}
    ]
    manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    verified = manifest_run("verify", manifest, tmp_path)
    assert verified.returncode == 1
    assert "naive" in verified.stdout
    assert "independent_observations[0].checked_at_utc" in verified.stdout


def test_shipped_manifest_timestamps_are_utc(manifest_module):
    root = Path(__file__).resolve().parents[2]
    manifest = json.loads(
        (root / "data" / "historical" / "UNSW_NB15_MANIFEST_2015.json").read_text(encoding="utf-8")
    )
    stamps = list(manifest_module.iter_timestamps(manifest))
    assert stamps, "shipped manifest must carry provenance timestamps"
    for field, value in stamps:
        assert manifest_module.format_utc(manifest_module.parse_utc(value, field)).endswith("Z")
