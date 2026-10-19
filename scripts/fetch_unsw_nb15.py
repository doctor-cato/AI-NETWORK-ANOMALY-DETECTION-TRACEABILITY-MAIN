#!/usr/bin/env python3
"""Download the selected UNSW-NB15 train/test mirror without changing CSV bytes."""

import argparse
import hashlib
import json
import os
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.error import HTTPError, URLError
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
# One lock per destination serialises the whole fetch/install transaction. The kernel
# releases it when the owning process exits, so there is no stale threshold to tune.
LOCK_NAME = ".unsw-nb15.lock"
# Written before the first swap so a process killed mid-install can be undone later.
TXN_NAME = ".unsw-nb15-transaction.json"
LOCK_TIMEOUT_SECONDS = 900
LOCK_POLL_SECONDS = 1.0


def scratch_path(destination, prefix, name):
    """Process-unique scratch path so concurrent fetch runs never share a file."""
    return destination / f"{prefix}{os.getpid()}-{name}"


def free_scratch_path(destination, prefix, name):
    """First free scratch path for this run; anything already there is left alone.

    Staging and backup names are predictable and PIDs are reused, so a name may still
    belong to an earlier run: a leftover backup can be the only surviving copy of older
    bytes. Taking the next free name keeps that file intact.
    """
    base = scratch_path(destination, prefix, name)
    candidate = base
    suffix = 0
    while candidate.exists() or candidate.is_symlink():
        suffix += 1
        candidate = base.with_name(f"{base.name}.{suffix}")
    return candidate


def open_new(path):
    """Create `path` exclusively: never follow and never remove what is there.

    O_EXCL fails for anything already at that name, including a symlink, so a planted
    symlink cannot redirect the write outside the destination and no earlier file is
    destroyed. This is the portable form of O_NOFOLLOW, which Windows lacks.
    """
    return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)


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
        with os.fdopen(open_new(staging), "wb") as output:
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


def copy_file(source, destination_path):
    """Copy `source` to a path that cannot already be pointing somewhere else.

    A copy that fails halfway leaves a partial file, so the path is recorded by the
    caller and cleaned up; the exclusive open keeps a planted symlink from
    redirecting the copy outside the destination.
    """
    with os.fdopen(open_new(destination_path), "wb") as output:
        with source.open("rb") as stream:
            shutil.copyfileobj(stream, output)


def matches_pinned(path, expected):
    """True only when the local bytes are exactly the pinned ones."""
    try:
        verify_download(path, expected)
    except (OSError, ValueError):
        return False
    return True


def recover_interrupted_transaction(destination):
    """Undo a transaction whose process died between swaps, before anything else runs.

    Rollback only runs while the process is alive, so a hard kill between two swaps
    used to leave one new file beside one missing or old file. The marker written
    before the first swap records the pre-run state of every file in the install, so
    the next run can put that state back before it trusts the cache.
    """
    marker = destination / TXN_NAME
    if not marker.is_file():
        return
    try:
        record = json.loads(marker.read_text(encoding="utf-8"))
        files = record["files"]
        if not isinstance(files, list) or not all("name" in entry for entry in files):
            raise ValueError("no usable file list")
    except (OSError, KeyError, TypeError, ValueError) as error:
        # The marker is the only record of where the pre-run bytes are, so it is never
        # removed on the way past and no new install is allowed to overwrite it.
        raise OSError(
            f"cannot interpret {marker.name}: {error}. It describes an interrupted "
            f"install; inspect data/raw/ and remove the marker by hand once the pair "
            f"is what it should be"
        ) from None
    failed = False
    for entry in files:
        name = entry["name"]
        target = destination / name
        backup = entry.get("backup")
        if backup:
            backup_path = destination / backup
            if not backup_path.exists():
                # A restore in an earlier attempt consumed this backup. Treating that as a
                # failure would strand the marker forever, but accepting the file without
                # looking at it would accept whatever happens to sit there, so the bytes
                # are checked against the pinned ones before the entry counts as restored.
                expected = FILES.get(name)
                if (
                    target.is_file()
                    and expected is not None
                    and not matches_pinned(target, expected)
                ):
                    failed = True
                    print(
                        f"[fetch_unsw_nb15] RECOVERY WARNING: {name} has no backup and its "
                        f"bytes do not match the pinned checksum; the pair cannot be "
                        f"trusted and nothing was changed"
                    )
                    continue
                if target.exists():
                    print(
                        f"[fetch_unsw_nb15] RECOVERY: {name} was already restored by an "
                        f"earlier attempt"
                    )
                    continue
                failed = True
                print(
                    f"[fetch_unsw_nb15] RECOVERY WARNING: {name} has neither {backup} nor "
                    f"a file to keep; the previous bytes are lost"
                )
                continue
            try:
                os.replace(backup_path, target)
                print(f"[fetch_unsw_nb15] RECOVERY: restored {name} from {backup}")
            except OSError as error:
                failed = True
                print(
                    f"[fetch_unsw_nb15] RECOVERY WARNING: cannot restore {name} from "
                    f"{backup}: {error}. The backup and {marker.name} are kept."
                )
        elif target.exists():
            try:
                target.unlink()
                print(f"[fetch_unsw_nb15] RECOVERY: removed {name}, created by the lost run")
            except OSError as error:
                failed = True
                print(
                    f"[fetch_unsw_nb15] RECOVERY WARNING: cannot remove {name}: {error}. "
                    f"{marker.name} is kept."
                )
    if failed:
        # Blocking here is the point: installing on top of a pair this run could not put
        # back would destroy the evidence needed to repair it.
        raise OSError(
            f"RECOVERY incomplete for {marker.name}; nothing was downloaded or installed. "
            f"The marker and its backups are kept for the next attempt"
        )
    remove_quietly(marker)


def write_transaction_marker(destination, pending, backups):
    """Record the pre-run state of an install so a crash can be undone later."""
    marker = destination / TXN_NAME
    record = {
        "pid": os.getpid(),
        "files": [
            {"name": name, "backup": backups[name].name if name in backups else None}
            for name in pending
        ],
    }
    with os.fdopen(open_new(marker), "w", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")


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
                backup = free_scratch_path(destination, BACKUP_PREFIX, name)
                try:
                    copy_file(target, backup)
                except OSError:
                    # A copy that fails halfway would otherwise leave a partial backup
                    # that no cleanup path knows about.
                    remove_quietly(backup)
                    raise
                backups[name] = backup
        # Recorded before the first swap: if this process dies mid-install, the next
        # run finds the marker and puts the pair back the way it was.
        write_transaction_marker(destination, pending, backups)
        for name, staging in pending.items():
            os.replace(staging, destination / name)
            installed.append(name)
            print(f"[fetch_unsw_nb15] INSTALLED unchanged bytes: {destination / name}")
        remove_quietly(destination / TXN_NAME)
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
        else:
            # The pair is back to its pre-run state, so there is nothing left to undo.
            remove_quietly(destination / TXN_NAME)
        raise
    finally:
        # A backup that could not be restored is the only surviving copy of those bytes,
        # so it must outlive this run; every other backup is now redundant.
        for backup in backups.values():
            if backup not in leftovers:
                remove_quietly(backup)


def _lock_handle(handle):
    """Take an exclusive OS lock on `handle`, raising OSError when it is held."""
    if msvcrt is not None:
        os.lseek(handle, 0, os.SEEK_SET)
        msvcrt.locking(handle, msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)


@contextmanager
def destination_lock(destination, timeout=None, poll=None):
    """Hold an exclusive OS lock on `destination` for the whole fetch/install transaction.

    PID-tagged scratch names stop two runs from sharing a temporary file, but they do
    not stop them from interleaving backups, swaps and rollback: one run can restore an
    old file over the pair another run has just installed. The lock covers the cache
    check, the download, the backups, every swap and the rollback, so only one run
    touches the destination at a time.

    The lock is an OS byte-range lock rather than a marker file with a staleness rule.
    The kernel releases it when the owning process exits, including a hard kill, so
    there is no abandoned-lock state to guess at and no reclaim step that could delete
    the lock of a run that is merely slow or that replaced the file in between. The
    lock file itself stays on disk for the same reason: unlinking it would let another
    process create a new inode and take the lock while this run still holds the old
    one. Defaults are read at call time so a caller or a test can shorten them.
    """
    if timeout is None:
        timeout = LOCK_TIMEOUT_SECONDS
    if poll is None:
        poll = LOCK_POLL_SECONDS
    lock = destination / LOCK_NAME
    lock.touch(exist_ok=True)
    handle = os.open(lock, os.O_RDWR)
    try:
        deadline = time.monotonic() + timeout
        announced = False
        while True:
            try:
                _lock_handle(handle)
                break
            except OSError:
                if not announced:
                    print(
                        f"[fetch_unsw_nb15] LOCK: another run holds {lock.name}; "
                        f"waiting up to {timeout}s"
                    )
                    announced = True
                if time.monotonic() >= deadline:
                    raise OSError(
                        f"gave up waiting {timeout}s for {lock.name}; " f"another fetch is running"
                    ) from None
                time.sleep(poll)
        yield lock
    finally:
        # Closing the handle is what releases the lock.
        os.close(handle)


def fetch(destination, files=None, base_url=None):
    files = FILES if files is None else files
    base_url = BASE_URL if base_url is None else base_url
    destination.mkdir(parents=True, exist_ok=True)
    staging = {name: free_scratch_path(destination, STAGING_PREFIX, name) for name in files}
    try:
        with destination_lock(destination):
            recover_interrupted_transaction(destination)
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
