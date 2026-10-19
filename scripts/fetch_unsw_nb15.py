#!/usr/bin/env python3
"""Download the selected UNSW-NB15 train/test mirror without changing CSV bytes."""

import argparse
import hashlib
import os
import shutil
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESTINATION = PROJECT_ROOT / "data" / "raw"
REVISION = "44bbd02b9e70f74dd915218d5eb702f125341ffc"
BASE_URL = (
    "https://raw.githubusercontent.com/Nir-J/ML-Projects/"
    f"{REVISION}/UNSW-Network_Packet_Classification"
)
FILES = {
    "UNSW_NB15_training-set.csv": {
        "size_bytes": 32293018,
        "sha256": "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
    },
    "UNSW_NB15_testing-set.csv": {
        "size_bytes": 15380800,
        "sha256": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    },
}
# Scratch files live beside the destination so the verified bytes can be swapped in atomically.
STAGING_PREFIX = ".unsw-nb15-staging-"
BACKUP_PREFIX = ".unsw-nb15-backup-"
# Download chunk size; it only bounds memory, never the number of bytes accepted.
CHUNK_BYTES = 1024 * 1024
# One lock per destination serialises the whole fetch/install transaction.
LOCK_NAME = ".unsw-nb15.lock"
LOCK_TIMEOUT_SECONDS = 900
LOCK_POLL_SECONDS = 1.0
# A lock older than this was left behind by a killed run and is safe to break.
LOCK_STALE_SECONDS = 3600
# The owner refreshes the lock this often, so staleness means "nobody is refreshing".
LOCK_HEARTBEAT_SECONDS = 30.0


def scratch_path(destination, prefix, name):
    """Process-unique scratch path so concurrent fetch runs never share a file."""
    return destination / f"{prefix}{os.getpid()}-{name}"


def free_backup_path(destination, name):
    """First backup path that does not exist yet.

    A backup left behind by a failed restore is the only surviving copy of those bytes,
    and PIDs are reused, so the same PID can reach a kept backup again. Taking the next
    free name keeps that copy intact instead of overwriting or deleting it.
    """
    base = scratch_path(destination, BACKUP_PREFIX, name)
    candidate = base
    suffix = 0
    while candidate.exists():
        suffix += 1
        candidate = base.with_name(f"{base.name}.{suffix}")
    return candidate


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_download(path, expected):
    """Raise unless the local bytes match the pinned size and SHA-256 exactly."""
    with path.open("rb") as stream:
        prefix = stream.read(256).lstrip()
    if prefix.lower().startswith((b"<!doctype html", b"<html", b"version https://git-lfs")):
        raise ValueError(f"unexpected HTML or Git LFS pointer: {path.name}")
    size = path.stat().st_size
    if size != expected["size_bytes"]:
        raise ValueError(
            f"size mismatch for {path.name}: expected {expected['size_bytes']}, got {size}"
        )
    digest = sha256_file(path)
    if digest != expected["sha256"]:
        raise ValueError(
            f"SHA-256 mismatch for {path.name}: expected {expected['sha256']}, got {digest}"
        )
    return digest


def copy_up_to_limit(response, output, limit, name):
    """Write at most `limit` bytes and abort on the first byte beyond it.

    The response is read in bounded chunks instead of being copied to EOF, so an
    endpoint or intermediary that never ends its body cannot fill the destination
    filesystem before the pinned size is checked.
    """
    written = 0
    while True:
        chunk = response.read(min(CHUNK_BYTES, limit + 1 - written))
        if not chunk:
            break
        written += len(chunk)
        if written > limit:
            raise ValueError(
                f"response for {name} exceeds the pinned size of {limit} bytes; "
                f"the download was stopped before the extra byte was written"
            )
        output.write(chunk)


def download_to_staging(name, expected, staging, base_url):
    """Fetch one revision-pinned file into `staging`; returns the verified digest."""
    request = Request(f"{base_url}/{name}", headers={"User-Agent": "unsw-nb15-fetch/1"})
    with urlopen(request, timeout=60) as response:
        status = getattr(response, "status", 200)
        content_type = response.headers.get_content_type()
        if status != 200:
            raise ValueError(f"HTTP {status} for {name}")
        if content_type in {"text/html", "application/vnd.git-lfs+json"}:
            raise ValueError(f"unexpected Content-Type {content_type} for {name}")
        print(f"[fetch_unsw_nb15] DOWNLOAD: {name} <- {base_url}/{name}")
        with staging.open("wb") as output:
            copy_up_to_limit(response, output, expected["size_bytes"], name)
    digest = verify_download(staging, expected)
    print(f"[fetch_unsw_nb15] VERIFIED: {name} bytes={expected['size_bytes']} sha256={digest}")
    return digest


def cache_is_valid(target, expected):
    """Return True only for a byte-exact local cache; never trust the name or size alone."""
    if not target.is_file():
        print(f"[fetch_unsw_nb15] CACHE_INVALID: {target.name}: absent at {target}")
        return False
    try:
        digest = verify_download(target, expected)
    except (ValueError, FileNotFoundError) as error:
        print(f"[fetch_unsw_nb15] CACHE_INVALID: {target.name}: {error}")
        return False
    print(
        f"[fetch_unsw_nb15] CACHE_HIT: {target.name} "
        f"bytes={expected['size_bytes']} sha256={digest}"
    )
    return True


def remove_quietly(path):
    """Drop a scratch file without ever masking the error that is being reported."""
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        print(f"[fetch_unsw_nb15] CLEANUP WARNING: cannot remove {path.name}: {error}")


def rollback(destination, installed, backups):
    """Undo this run's swaps so the destination holds the bytes it held before.

    A file with a backup is restored with `os.replace`, which overwrites its
    destination atomically, so the restore never passes through an absent state. If
    that restore fails, the verified new bytes stay in place and the backup is kept
    for manual recovery rather than discarded.

    A file this run created had no earlier version, so it is removed again to keep the
    pair install all or nothing. Only bytes this run downloaded are dropped, and a
    later run fetches them again. If that removal fails the file is left in place and
    reported, because keeping verified bytes is safer than a failed install.

    Returns the paths that could not be returned to their pre-run state.
    """
    leftovers = []
    for name in installed:
        backup = backups.get(name)
        if backup is None:
            target = destination / name
            try:
                target.unlink(missing_ok=True)
            except OSError as error:
                leftovers.append(target)
                print(
                    f"[fetch_unsw_nb15] ROLLBACK WARNING: cannot remove {name}, which this "
                    f"run created: {error}. Leaving it in place for manual cleanup."
                )
            continue
        try:
            os.replace(backup, destination / name)
        except OSError as error:
            leftovers.append(backup)
            print(
                f"[fetch_unsw_nb15] ROLLBACK WARNING: cannot restore {name} from "
                f"{backup.name}: {error}. Keeping {destination / name} and the backup "
                f"for manual recovery."
            )
    return leftovers


def install(pending, destination):
    """Swap verified staging files into place, restoring previous bytes if any swap fails.

    Backups are copies rather than moves, so a destination file stays readable until its
    own replacement succeeds. Every file is backed up before the first swap, so a failure
    on any file returns every file this run touched to its pre-run state: the bytes it
    held before, or absence when it did not exist before.
    """
    backups = {}
    leftovers = []
    installed = []
    try:
        for name in pending:
            target = destination / name
            if target.is_file():
                backup = free_backup_path(destination, name)
                try:
                    shutil.copyfile(target, backup)
                except OSError:
                    # Record the path first: a copy that fails halfway would otherwise
                    # leave a partial backup nobody knows to clean up.
                    remove_quietly(backup)
                    raise
                backups[name] = backup
        for name, staging in pending.items():
            os.replace(staging, destination / name)
            installed.append(name)
            print(f"[fetch_unsw_nb15] INSTALLED unchanged bytes: {destination / name}")
    except OSError as error:
        leftovers = rollback(destination, installed, backups)
        print(
            f"[fetch_unsw_nb15] ROLLBACK: returned {len(installed) - len(leftovers)} of "
            f"{len(installed)} installed file(s) to their pre-run state after a failed "
            f"install: {error}"
        )
        if leftovers:
            print(
                f"[fetch_unsw_nb15] RECOVERY: kept {len(leftovers)} file(s) for manual "
                f"recovery: {', '.join(path.name for path in leftovers)}"
            )
        raise
    finally:
        # A backup that could not be restored is the only surviving copy of those bytes,
        # so it must outlive this run; every other backup is now redundant.
        for backup in backups.values():
            if backup not in leftovers:
                remove_quietly(backup)


@contextmanager
def _refresh_mtime(lock, interval):
    """Keep `lock` visibly fresh for as long as this run owns it.

    Reclaiming a lock on mtime alone would take it from a live but slow run, which
    then interleaves its backups and swaps with the reclaiming run. The heartbeat is
    what separates "owner is silent" from "owner is dead".
    """
    stop = threading.Event()

    def refresh():
        while not stop.wait(interval):
            try:
                os.utime(lock, None)
            except OSError:
                # The lock is gone; the owning run is about to fail its own work.
                return

    thread = threading.Thread(target=refresh, name="unsw-nb15-lock-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()


@contextmanager
def destination_lock(destination, timeout=None, poll=None, heartbeat=None):
    """Hold an exclusive lock on `destination` for the whole fetch/install transaction.

    PID-tagged scratch names stop two runs from sharing a temporary file, but they do
    not stop them from interleaving backups, swaps and rollback: one run can restore an
    old file over the pair another run has just installed. The lock covers the cache
    check, the download, the backups, every swap and the rollback, so only one run
    touches the destination at a time.

    A lock older than LOCK_STALE_SECONDS is treated as abandoned by a killed run and is
    removed, so a hard kill cannot block the directory forever. The owner refreshes the
    lock while it works, so that reclaim path only triggers on a lock nobody is
    refreshing. Defaults are read at call time so a caller or a test can shorten them.
    """
    if timeout is None:
        timeout = LOCK_TIMEOUT_SECONDS
    if poll is None:
        poll = LOCK_POLL_SECONDS
    if heartbeat is None:
        heartbeat = LOCK_HEARTBEAT_SECONDS
    lock = destination / LOCK_NAME
    deadline = time.monotonic() + timeout
    announced = False
    while True:
        try:
            handle = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                age = time.time() - lock.stat().st_mtime
            except FileNotFoundError:
                # The owner released the lock between O_EXCL failing and stat(); that is
                # a normal handoff, so take it instead of aborting the whole fetch.
                continue
            if age > LOCK_STALE_SECONDS:
                print(
                    f"[fetch_unsw_nb15] LOCK: removing stale lock {lock.name}, "
                    f"unchanged for {age:.0f}s"
                )
                remove_quietly(lock)
                if lock.exists():
                    if time.monotonic() >= deadline:
                        raise OSError(
                            f"gave up after {timeout}s on stale lock {lock.name}; "
                            f"it cannot be removed"
                        )
                    time.sleep(poll)
                continue
            if not announced:
                print(
                    f"[fetch_unsw_nb15] LOCK: another run holds {lock.name}; "
                    f"waiting up to {timeout}s"
                )
                announced = True
            if time.monotonic() >= deadline:
                raise OSError(
                    f"gave up waiting {timeout}s for {lock.name}; another fetch is running"
                )
            time.sleep(poll)
            continue
        break
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(f"pid={os.getpid()} acquired={datetime.now(timezone.utc).isoformat()}")
        with _refresh_mtime(lock, heartbeat):
            yield lock
    finally:
        remove_quietly(lock)


def fetch(destination, files=None, base_url=None):
    files = FILES if files is None else files
    base_url = BASE_URL if base_url is None else base_url
    destination.mkdir(parents=True, exist_ok=True)
    staging = {name: scratch_path(destination, STAGING_PREFIX, name) for name in files}
    try:
        with destination_lock(destination):
            pending = {}
            for name, expected in files.items():
                if cache_is_valid(destination / name, expected):
                    continue
                pending[name] = staging[name]
                download_to_staging(name, expected, staging[name], base_url)
            # Install only once every needed file is staged and verified, so a failed run
            # never leaves a half-populated data/raw/ directory: any file this run installed
            # is returned to its pre-run state when a later swap fails.
            if pending:
                install(pending, destination)
    finally:
        for path in staging.values():
            remove_quietly(path)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args(argv)
    try:
        fetch(args.destination)
    except (OSError, HTTPError, URLError, ValueError) as error:
        print(f"[fetch_unsw_nb15] ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
