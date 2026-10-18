"""Synthetic CSV fixtures only; these are not UNSW-NB15 observations."""

import csv
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from email.message import Message
from pathlib import Path
from urllib.error import URLError

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "validate_data.py"
MANIFEST_SCRIPT = SCRIPT.with_name("dataset_manifest.py")
FETCH_SCRIPT = SCRIPT.with_name("fetch_unsw_nb15.py")


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
    assert validator.main(["--report", str(report_path)]) == 0
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
    assert validator.main(["--file", str(target), "--manifest", str(manifest)]) == 0
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
    return sorted(path.name for path in directory.glob(".unsw-nb15-*"))


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
    assert sorted(path.name for path in tmp_path.iterdir()) == []
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
    real_copyfile = shutil.copyfile

    def record_copy(src, dst, *args, **kwargs):
        copies.append((Path(src).name, Path(dst).name))
        return real_copyfile(src, dst, *args, **kwargs)

    monkeypatch.setattr(fetcher.shutil, "copyfile", record_copy)
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
    manifest = json.loads((root / "data" / "UNSW_NB15_MANIFEST.json").read_text(encoding="utf-8"))
    stamps = list(manifest_module.iter_timestamps(manifest))
    assert stamps, "shipped manifest must carry provenance timestamps"
    for field, value in stamps:
        assert manifest_module.format_utc(manifest_module.parse_utc(value, field)).endswith("Z")
