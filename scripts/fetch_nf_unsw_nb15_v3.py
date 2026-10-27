#!/usr/bin/env python3
"""Fetch and safely publish the official UQ NF-UNSW-NB15-v3 BagIt package."""

import argparse
import hashlib
import json
import os
import shutil
import stat
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

try:  # Windows
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None  # type: ignore[assignment]

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESTINATION = PROJECT_ROOT / "data" / "raw"
DATASET_NAME = "NF-UNSW-NB15-v3"
RDM_UUID = "abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f"
DOWNLOAD_API = f"https://api.rdm.uq.edu.au/datasets/{RDM_UUID}/download"
PACKAGE_PREFIX = "f7546561558c07c5_NFV3DATA-A11964_A11964"
ARCHIVE_NAME = "f7546561558c07c5_NFV3DATA-A11964_A11964.zip"
ARCHIVE_SIZE = 110_825_147
ARCHIVE_SHA256 = "6d51554df43e324ba8d68fc31a02a83d860ba0a3a93d63320a4a6fc314c9cdfd"
MAX_EXTRACTED_BYTES = 600_000_000
MAX_ARCHIVE_ENTRIES = 32
CHUNK_BYTES = 1024 * 1024
LOCK_NAME = ".nf-unsw-nb15-v3.lock"
TXN_NAME = ".nf-unsw-nb15-v3-transaction.json"
STAGING_PREFIX = ".nf-unsw-nb15-v3-staging-"
BACKUP_PREFIX = ".nf-unsw-nb15-v3-backup-"
FAILED_PREFIX = ".nf-unsw-nb15-v3-failed-"
LOCK_TIMEOUT_SECONDS = 900
LOCK_POLL_SECONDS = 1.0

EXPECTED_MEMBERS = {
    "FurtherInformation.txt": (
        143,
        "2628f3a188deec265aa663e42035825da2dcd9137fd63b6821fc9a8c61cfecca",
    ),
    "bag-info.txt": (839, "b5d9904090ee469141a74296357b525ec10dc4ca6962c96986f6787b3de1c288"),
    "bagit.txt": (55, "133dce1caef7fc5544d815791265569a933ec658860821fdff8c157b561d0d39"),
    "manifest-sha1.txt": (
        136,
        "5916eef3fd5bf18cd5de296df04cbd63a1384fc8e21cbcac617fd86d8284e772",
    ),
    "tagmanifest-sha1.txt": (
        164,
        "d95bcb4b0a1e4753751d36f132f0e6db43eaf3c907ee14c7c102db26e71f506c",
    ),
    "data/NF-UNSW-NB15-v3.csv": (
        577_360_958,
        "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
    ),
    "data/NetFlow_v3_Features.csv": (
        2_935,
        "abe3ce6e6ff731d72d76e029b512585c0dbcbd8e03ff6dbe2bd04b560723bd67",
    ),
}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path, expected_size, expected_sha256):
    if not path.is_file():
        raise ValueError(f"missing file: {path}")
    if path.stat().st_size != expected_size:
        raise ValueError(
            f"size mismatch for {path.name}: expected {expected_size}, got {path.stat().st_size}"
        )
    digest = sha256_file(path)
    if digest != expected_sha256:
        raise ValueError(
            f"SHA-256 mismatch for {path.name}: expected {expected_sha256}, got {digest}"
        )
    return digest


def verify_archive(path):
    with path.open("rb") as stream:
        prefix = stream.read(256).lstrip()
    if prefix.lower().startswith((b"<!doctype html", b"<html")):
        raise ValueError("download returned an HTML page instead of a ZIP archive")
    if not prefix.startswith(b"PK"):
        raise ValueError("download does not have ZIP magic")
    return verify_file(path, ARCHIVE_SIZE, ARCHIVE_SHA256)


def package_is_valid(package):
    try:
        for relative, (size, digest) in EXPECTED_MEMBERS.items():
            verify_file(package / relative, size, digest)
    except (OSError, ValueError):
        return False
    return True


def copy_up_to_limit(response, output, limit, name):
    written = 0
    while True:
        chunk = response.read(min(CHUNK_BYTES, limit + 1 - written))
        if not chunk:
            break
        written += len(chunk)
        if written > limit:
            raise ValueError(f"response for {name} exceeds the pinned size of {limit} bytes")
        output.write(chunk)


def get_download_url():
    request = Request(DOWNLOAD_API, headers={"User-Agent": "nf-unsw-nb15-v3-fetch/1"})
    with urlopen(request, timeout=60) as response:
        if getattr(response, "status", 200) != 200:
            raise ValueError(f"metadata API returned HTTP {response.status}")
        payload = json.load(response)
    if payload.get("uuid") != RDM_UUID:
        raise ValueError("metadata API returned a different dataset UUID")
    if payload.get("packagingStatus") != 0 or payload.get("accessType") != "OPEN":
        raise ValueError("official package is not available for open download")
    url = payload.get("url")
    parsed = urlsplit(url) if isinstance(url, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith("amazonaws.com")
        or not parsed.query
    ):
        raise ValueError("metadata API did not return an expected signed HTTPS URL")
    return url


def download_archive(staging):
    url = get_download_url()
    request = Request(url, headers={"User-Agent": "nf-unsw-nb15-v3-fetch/1"})
    with urlopen(request, timeout=60) as response:
        status = getattr(response, "status", 200)
        content_type = response.headers.get_content_type()
        if status != 200:
            raise ValueError(f"archive download returned HTTP {status}")
        if content_type in {"text/html", "application/xhtml+xml"}:
            raise ValueError(f"unexpected Content-Type {content_type}")
        print(f"[fetch_nf_unsw_nb15_v3] DOWNLOAD: {ARCHIVE_NAME} from UQRDM signed URL")
        with staging.open("xb") as output:
            copy_up_to_limit(response, output, ARCHIVE_SIZE, ARCHIVE_NAME)
    digest = verify_archive(staging)
    print(f"[fetch_nf_unsw_nb15_v3] VERIFIED archive bytes={ARCHIVE_SIZE} sha256={digest}")


def _safe_member_name(info):
    expected_prefix = f"{PACKAGE_PREFIX}/"
    name = info.filename.replace("\\", "/")
    if not name.startswith(expected_prefix):
        raise ValueError(f"archive entry outside expected package root: {info.filename!r}")
    relative = name[len(expected_prefix) :]
    path = Path(relative)
    if not relative or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive path: {info.filename!r}")
    mode = (info.external_attr >> 16) & 0xFFFF
    if mode and stat.S_ISLNK(mode):
        raise ValueError(f"archive symlink is not allowed: {info.filename!r}")
    return path.as_posix()


def extract_verified_archive(archive, staging_directory):
    staging_directory.mkdir(parents=False, exist_ok=False)
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise ValueError("archive contains too many entries")
            mapped = {_safe_member_name(info): info for info in infos if not info.is_dir()}
            if set(mapped) != set(EXPECTED_MEMBERS):
                missing = sorted(set(EXPECTED_MEMBERS) - set(mapped))
                extra = sorted(set(mapped) - set(EXPECTED_MEMBERS))
                raise ValueError(f"archive member mismatch: missing={missing}, extra={extra}")
            total = sum(info.file_size for info in mapped.values())
            expected_total = sum(size for size, _ in EXPECTED_MEMBERS.values())
            if total != expected_total or total > MAX_EXTRACTED_BYTES:
                raise ValueError(
                    f"unexpected extracted size: expected {expected_total}, got {total}"
                )
            root = staging_directory.resolve()
            for relative, info in mapped.items():
                expected_size, expected_digest = EXPECTED_MEMBERS[relative]
                if info.file_size != expected_size:
                    raise ValueError(f"entry size mismatch for {relative}")
                target = staging_directory / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                resolved = target.resolve()
                if root not in resolved.parents:
                    raise ValueError(f"archive entry escapes staging directory: {relative}")
                digest = hashlib.sha256()
                written = 0
                with bundle.open(info) as source, target.open("xb") as output:
                    while True:
                        chunk = source.read(min(CHUNK_BYTES, expected_size + 1 - written))
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > expected_size:
                            raise ValueError(f"entry exceeds expected size: {relative}")
                        output.write(chunk)
                        digest.update(chunk)
                if written != expected_size or digest.hexdigest() != expected_digest:
                    raise ValueError(f"entry checksum mismatch: {relative}")
        if not package_is_valid(staging_directory):
            raise ValueError("extracted package did not pass final verification")
    except BaseException:
        remove_tree_quietly(staging_directory)
        raise


def free_path(parent, prefix, suffix=""):
    base = parent / f"{prefix}{os.getpid()}{suffix}"
    candidate = base
    counter = 0
    while candidate.exists() or candidate.is_symlink():
        counter += 1
        candidate = base.with_name(f"{base.name}.{counter}")
    return candidate


def remove_file_quietly(path):
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        print(f"[fetch_nf_unsw_nb15_v3] CLEANUP WARNING: cannot remove {path.name}: {error}")


def remove_tree_quietly(path):
    try:
        if path.exists():
            shutil.rmtree(path)
    except OSError as error:
        print(f"[fetch_nf_unsw_nb15_v3] CLEANUP WARNING: cannot remove {path.name}: {error}")


def _lock_handle(handle):
    if msvcrt is not None:
        os.lseek(handle, 0, os.SEEK_SET)
        msvcrt.locking(handle, msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)


@contextmanager
def destination_lock(destination, timeout=None, poll=None):
    timeout = LOCK_TIMEOUT_SECONDS if timeout is None else timeout
    poll = LOCK_POLL_SECONDS if poll is None else poll
    lock = destination / LOCK_NAME
    lock.touch(exist_ok=True)
    handle = os.open(lock, os.O_RDWR)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                _lock_handle(handle)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise OSError(
                        f"gave up waiting {timeout}s for {LOCK_NAME}; another fetch is running"
                    ) from None
                time.sleep(poll)
        yield
    finally:
        os.close(handle)


def _write_marker(destination, final, staging, backup):
    marker = destination / TXN_NAME
    record = {
        "dataset": DATASET_NAME,
        "final": final.name,
        "staging": staging.name,
        "backup": backup.name if backup else None,
    }
    with marker.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")


def _read_marker(destination):
    marker = destination / TXN_NAME
    if not marker.is_file():
        return None
    try:
        record = json.loads(marker.read_text(encoding="utf-8"))
        if record.get("dataset") != DATASET_NAME or record.get("final") != DATASET_NAME:
            raise ValueError("unexpected dataset/final")
        for key in ("staging", "backup"):
            value = record.get(key)
            if value is not None and (Path(value).name != value or not value.startswith(".nf-")):
                raise ValueError(f"unsafe {key} path")
        return record
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise OSError(
            f"cannot interpret {TXN_NAME}: {error}; inspect data/raw and recover manually"
        ) from None


def recover_interrupted_transaction(destination):
    record = _read_marker(destination)
    if record is None:
        return
    marker = destination / TXN_NAME
    final = destination / record["final"]
    staging = destination / record["staging"]
    backup = destination / record["backup"] if record.get("backup") else None
    if final.exists():
        if not package_is_valid(final):
            raise OSError(
                f"RECOVERY blocked: {final.name} exists but is invalid; marker/backup preserved"
            )
        if backup is not None:
            remove_tree_quietly(backup)
        remove_tree_quietly(staging)
        remove_file_quietly(marker)
        print("[fetch_nf_unsw_nb15_v3] RECOVERY: completed published package detected")
        return
    if backup is not None and backup.exists():
        os.replace(backup, final)
        remove_tree_quietly(staging)
        remove_file_quietly(marker)
        print("[fetch_nf_unsw_nb15_v3] RECOVERY: restored previous package")
        return
    if staging.exists() and package_is_valid(staging):
        os.replace(staging, final)
        remove_file_quietly(marker)
        print("[fetch_nf_unsw_nb15_v3] RECOVERY: published verified staging package")
        return
    raise OSError(f"RECOVERY blocked: {TXN_NAME} has no valid final, backup, or staging package")


def publish_package(destination, staging):
    final = destination / DATASET_NAME
    backup = free_path(destination, BACKUP_PREFIX) if final.exists() else None
    _write_marker(destination, final, staging, backup)
    try:
        if backup is not None:
            os.replace(final, backup)
        os.replace(staging, final)
        if not package_is_valid(final):
            raise OSError("published package failed post-publish verification")
    except OSError:
        if final.exists() and backup is not None and backup.exists():
            failed = free_path(destination, FAILED_PREFIX)
            os.replace(final, failed)
            os.replace(backup, final)
            print(
                f"[fetch_nf_unsw_nb15_v3] ROLLBACK: restored previous package; "
                f"failed replacement kept as {failed.name}"
            )
        elif not final.exists() and backup is not None and backup.exists():
            os.replace(backup, final)
            print("[fetch_nf_unsw_nb15_v3] ROLLBACK: restored previous package")
        raise
    else:
        if backup is not None:
            remove_tree_quietly(backup)
        remove_file_quietly(destination / TXN_NAME)
        print(f"[fetch_nf_unsw_nb15_v3] INSTALLED: {final}")


def fetch(destination):
    destination.mkdir(parents=True, exist_ok=True)
    archive = free_path(destination, STAGING_PREFIX, ".zip")
    extracted = free_path(destination, STAGING_PREFIX, "-package")
    try:
        with destination_lock(destination):
            recover_interrupted_transaction(destination)
            final = destination / DATASET_NAME
            if package_is_valid(final):
                print(f"[fetch_nf_unsw_nb15_v3] CACHE_HIT: {final}")
                return
            if final.exists():
                print(f"[fetch_nf_unsw_nb15_v3] CACHE_MISMATCH: {final}")
            download_archive(archive)
            extract_verified_archive(archive, extracted)
            publish_package(destination, extracted)
    finally:
        remove_file_quietly(archive)
        # Preserve verified staging while a transaction marker exists. The
        # next invocation needs it to complete or roll back the interrupted
        # publish without destroying the previously installed package.
        if not (destination / TXN_NAME).exists():
            remove_tree_quietly(extracted)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args(argv)
    try:
        fetch(args.destination)
    except (OSError, HTTPError, URLError, ValueError, zipfile.BadZipFile) as error:
        print(f"[fetch_nf_unsw_nb15_v3] ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
