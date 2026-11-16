"""Shared Git provenance collection helpers for model training scripts."""

from __future__ import annotations

import string
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

_HEX_CHARS = frozenset(string.hexdigits)
_MAX_RECORDED_DIRTY_PATHS = 50


def collect_git_provenance(
    project_root: Path,
    *,
    require_clean_git: bool = False,
) -> Dict[str, Any]:
    """Collect commit SHA, dirty-worktree state, and provenance metadata.

    Parameters
    ----------
    project_root:
        Repository root directory used as the ``cwd`` for git commands.
    require_clean_git:
        When True, fail closed if HEAD cannot be resolved or the working tree
        contains uncommitted changes.
    """
    git_commit = "UNKNOWN"
    try:
        raw_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(project_root),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if len(raw_commit) == 40 and all(ch in _HEX_CHARS for ch in raw_commit):
            git_commit = raw_commit.lower()
    except Exception:
        git_commit = "UNKNOWN"

    git_dirty: Optional[bool] = None
    dirty_paths: List[str] = []
    try:
        raw_status = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(project_root),
            stderr=subprocess.DEVNULL,
            text=True,
        )
        dirty_paths = [line.strip() for line in raw_status.splitlines() if line.strip()]
        git_dirty = bool(dirty_paths)
    except Exception:
        git_dirty = None
        dirty_paths = []

    if require_clean_git:
        if git_commit == "UNKNOWN":
            raise RuntimeError(
                "Clean git provenance required (--require-clean-git), "
                "but git HEAD commit could not be resolved."
            )
        if git_dirty is not False:
            raise RuntimeError(
                "Clean git worktree required (--require-clean-git), "
                f"but git_dirty={git_dirty!r} "
                f"(uncommitted/untracked entries: {dirty_paths[:10]})."
            )

    provenance_complete = git_commit != "UNKNOWN" and len(git_commit) == 40
    provenance_status = "VERIFIED" if provenance_complete else "INCOMPLETE"

    if git_dirty is False:
        worktree_provenance = "CLEAN"
        git_clean: Optional[bool] = True
        git_dirty_disclosure: Optional[str] = None
    elif git_dirty is True:
        worktree_provenance = "DIRTY_DISCLOSED"
        git_clean = False
        git_dirty_disclosure = (
            f"Trained from commit {git_commit[:7]} with uncommitted worktree changes "
            f"({len(dirty_paths)} modified/untracked path(s))."
        )
    else:
        worktree_provenance = "UNVERIFIED_WORKTREE"
        git_clean = None
        git_dirty_disclosure = "Git working tree cleanliness could not be verified."

    return {
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "git_clean": git_clean,
        "git_dirty_paths": dirty_paths[:_MAX_RECORDED_DIRTY_PATHS],
        "git_dirty_disclosure": git_dirty_disclosure,
        "worktree_provenance": worktree_provenance,
        "provenance_complete": provenance_complete,
        "provenance_status": provenance_status,
    }
