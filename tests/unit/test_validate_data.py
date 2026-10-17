"""Synthetic CSV fixtures only; these are not UNSW-NB15 observations."""

import csv
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

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
