#!/usr/bin/env python3
"""Audit and stage NetFlow Sentinel v2 companion model artifacts on Windows.

Verifies SHA-256 digests and manifest linkage across the preprocessor, 4 verified
ML models (Random Forest, XGBoost, Isolation Forest, Autoencoder), and Validation
demo CSV bundle on the canonical v2 schema (`canonical-flow-v2-18`).
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOCAL_SRC = PROJECT_ROOT / "src"
if str(_LOCAL_SRC) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SRC))

from network_anomaly.inference.predict import (  # noqa: E402
    _sha256_file,
    load_verified_model,
    load_verified_preprocessor,
)
from network_anomaly.ml.ood_gate import (  # noqa: E402
    cross_check_same_boundary_embedded_manifest,
    resolve_expected_ood_gate_sha256,
    verify_ood_gate_artifact,
)

_TAURI_BUNDLE_MARKER_UNK = b"BUNDLE_TYPE_VAR_UNK"
_TAURI_BUNDLE_MARKER_NSS = b"BUNDLE_TYPE_VAR_NSS"

MAX_COMPANION_ARCHIVE_ENTRIES = 64
MAX_COMPANION_ENTRY_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_COMPANION_TOTAL_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024

MODEL_SPECS: Dict[str, Tuple[Path, List[Path]]] = {
    "random_forest": (
        Path("artifacts/models/random_forest/random_forest_baseline.joblib"),
        [Path("reports/models/random_forest_manifest.json")],
    ),
    "xgboost": (
        Path("artifacts/models/xgboost/xgboost_baseline.joblib"),
        [
            Path("reports/models/xgboost_manifest.json"),
            Path("artifacts/models/xgboost/xgboost_manifest.json"),
        ],
    ),
    "isolation_forest": (
        Path("artifacts/models/isolation_forest/isolation_forest.joblib"),
        [
            Path("reports/models/isolation_forest_manifest.json"),
            Path("artifacts/models/isolation_forest/isolation_forest_manifest.json"),
        ],
    ),
    "autoencoder": (
        Path("artifacts/models/autoencoder/autoencoder_model.joblib"),
        [
            Path("reports/models/autoencoder_manifest.json"),
            Path("artifacts/models/autoencoder/autoencoder_manifest.json"),
            Path("artifacts/models/autoencoder/model_config.json"),
            Path("artifacts/models/autoencoder/threshold.json"),
            Path("artifacts/models/autoencoder/score_normalization.json"),
        ],
    ),
}

AE_SCORE_NORMALIZATION_REL = Path("artifacts/models/autoencoder/score_normalization.json")
OOD_REFERENCE_GATE_REL = Path("artifacts/ml/ood_reference_gate.json")
PREPROCESSOR_REL = Path("artifacts/preprocessing/v2_flow_preprocessor.joblib")
PREPROCESSOR_MANIFEST_REL = Path("reports/preprocessing/v2_flow_preprocessing_manifest.json")
SPLIT_MANIFEST_REL = Path("data/V2_SPLIT_MANIFEST.json")
DEMO_FILES_REL: Tuple[Path, ...] = (
    Path("data/demo/demo_flows.csv"),
    Path("data/demo/demo_labels.csv"),
    Path("data/demo/demo_manifest.json"),
)
EMBEDDED_EXTRA_FILES_REL: Tuple[Path, ...] = (
    Path("data/V2_SPLIT_MANIFEST.json"),
    Path("data/AIT_DATASETS_MANIFEST.json"),
    Path("data/CTU_SME_11_MANIFEST.json"),
    Path("NOTICE"),
    Path("THIRD_PARTY_NOTICES.md"),
    Path("LICENSE"),
)
DISTRIBUTION_AUTH_MANIFEST_REL = Path("reports/governance/DISTRIBUTION_AUTHORIZATION.json")
APPROVED_DISTRIBUTION_SCOPES = frozenset(
    {
        "research-only",
        "private-build-only",
        "non-commercial-controlled",
        "public-release-approved",
    }
)
TARGET_DISTRIBUTION_CHANNELS = frozenset(
    {
        "local_offline",
        "private_ci_artifact",
        "public_ci_artifact",
        "public_github_release",
    }
)
APPROVED_PUBLIC_LEGAL_BASES = frozenset(
    {
        "written-publisher-authorization",
        "independent-clean-room-license",
        "verified-open-redistribution-license",
    }
)
ENVIRONMENT_TIERS = frozenset(
    {
        "local_developer_machine",
        "unverified_target_machine",
        "github_hosted_windows_runner",
        "independent_windows_vm",
    }
)
CLEAN_MACHINE_ENVIRONMENT_TIERS = frozenset(
    {
        "github_hosted_windows_runner",
        "independent_windows_vm",
    }
)
_REQUIRED_NOTICE_MARKERS: Tuple[str, ...] = (
    "AIT NetFlow Data Set v2",
    "10.5281/zenodo.13168643",
    "CTU-SME-11",
)
SIDECAR_MANIFEST_MAPPINGS: Dict[str, str] = {
    "artifacts/models/xgboost/xgboost_manifest.json": "reports/models/xgboost_manifest.json",
    "artifacts/models/autoencoder/autoencoder_manifest.json": "reports/models/autoencoder_manifest.json",
    "artifacts/models/random_forest/random_forest_manifest.json": "reports/models/random_forest_manifest.json",
    "artifacts/models/isolation_forest/isolation_forest_manifest.json": "reports/models/isolation_forest_manifest.json",
}


def _select_existing_manifest(
    manifest_root: Path,
    artifact_root: Path,
    candidates: List[Path],
) -> Optional[Path]:
    for rel in candidates:
        base = manifest_root if rel.parts[0] == "reports" else artifact_root
        candidate = base / rel
        if candidate.is_file():
            return candidate
    return manifest_root / candidates[0]


def verify_companion_artifacts(
    root: Path = PROJECT_ROOT,
    *,
    runtime_dir: Optional[Path] = None,
    expected_ood_gate_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify preprocessor, all 4 model bundles, and demo files fail-closed."""
    resolved_root = Path(root).resolve()
    resolved_runtime = Path(runtime_dir).resolve() if runtime_dir is not None else resolved_root
    prep_path = resolved_runtime / PREPROCESSOR_REL
    prep_manifest = resolved_root / PREPROCESSOR_MANIFEST_REL
    split_manifest = resolved_root / SPLIT_MANIFEST_REL

    staged_files: List[Path] = []
    prep_sha: Optional[str] = None
    prep_status: Dict[str, Any]

    try:
        _, prep_meta = load_verified_preprocessor(
            artifact_path=prep_path,
            manifest_path=prep_manifest,
            split_manifest_path=split_manifest if split_manifest.is_file() else None,
        )
        prep_sha = str(prep_meta.get("artifact_sha256") or _sha256_file(prep_path))
        prep_status = {
            "ready": True,
            "status": "READY",
            "path": PREPROCESSOR_REL.as_posix(),
            "sha256": prep_sha,
            "reason": None,
        }
        staged_files.extend([PREPROCESSOR_REL, PREPROCESSOR_MANIFEST_REL])
    except Exception as exc:
        prep_status = {
            "ready": False,
            "status": "BLOCKED / NOT READY",
            "path": PREPROCESSOR_REL.as_posix(),
            "sha256": None,
            "reason": str(exc),
        }

    models_status: Dict[str, Dict[str, Any]] = {}
    ready_models: List[str] = []

    for model_key, (model_rel, support_rels) in MODEL_SPECS.items():
        model_abs = resolved_runtime / model_rel
        manifest_abs = _select_existing_manifest(resolved_root, resolved_runtime, support_rels)
        if not prep_status["ready"] or prep_sha is None:
            models_status[model_key] = {
                "ready": False,
                "status": "BLOCKED / NOT READY",
                "path": model_rel.as_posix(),
                "sha256": None,
                "reason": "Preprocessor artifact is not verified.",
            }
            continue
        try:
            assert manifest_abs is not None
            _, model_meta = load_verified_model(
                model_artifact_path=model_abs,
                manifest_path=manifest_abs,
                expected_preprocessor_sha256=prep_sha,
            )
            if model_key == "autoencoder":
                ae_norm_abs = resolved_runtime / AE_SCORE_NORMALIZATION_REL
                if not ae_norm_abs.is_file():
                    raise FileNotFoundError(
                        f"Missing required Autoencoder companion sidecar: {AE_SCORE_NORMALIZATION_REL.as_posix()}"
                    )
            ready_models.append(model_key)
            models_status[model_key] = {
                "ready": True,
                "status": "READY",
                "path": model_rel.as_posix(),
                "manifest_path": (
                    manifest_abs.relative_to(resolved_root).as_posix()
                    if manifest_abs.is_relative_to(resolved_root)
                    else manifest_abs.relative_to(resolved_runtime).as_posix()
                ),
                "sha256": model_meta.get("model_artifact_sha256") or _sha256_file(model_abs),
                "run_id": model_meta.get("run_id"),
                "reason": None,
            }
            staged_files.append(model_rel)
            for rel in support_rels:
                base = resolved_root if rel.parts[0] == "reports" else resolved_runtime
                if (base / rel).is_file():
                    staged_files.append(rel)
        except Exception as exc:
            models_status[model_key] = {
                "ready": False,
                "status": "BLOCKED / NOT READY",
                "path": model_rel.as_posix(),
                "sha256": None,
                "reason": str(exc),
            }

    demo_status: Dict[str, Any] = {}
    demo_ready = True
    demo_error: Optional[str] = None
    for rel in DEMO_FILES_REL:
        abs_path = resolved_runtime / rel
        if abs_path.is_file():
            demo_status[rel.as_posix()] = {
                "present": True,
                "sha256": _sha256_file(abs_path),
                "size_bytes": abs_path.stat().st_size,
            }
            staged_files.append(rel)
        else:
            demo_ready = False
            demo_status[rel.as_posix()] = {"present": False, "sha256": None, "size_bytes": 0}

    if demo_ready:
        try:
            demo_manifest = json.loads(
                (resolved_runtime / "data/demo/demo_manifest.json").read_text(encoding="utf-8")
            )
            sampling = demo_manifest.get("sampling") or {}
            if sampling.get("partition") != "validation":
                raise ValueError(
                    f"demo_manifest sampling.partition must be 'validation', got {sampling.get('partition')!r}"
                )
            if (
                int(sampling.get("train_overlap_count", -1)) != 0
                or int(sampling.get("test_overlap_count", -1)) != 0
            ):
                raise ValueError("demo_manifest records non-zero train/test overlap")
            outputs = demo_manifest.get("outputs") or {}
            expected_flows_sha = (outputs.get("demo_flows_csv") or {}).get("sha256")
            expected_labels_sha = (outputs.get("demo_labels_csv") or {}).get("sha256")
            actual_flows_sha = demo_status["data/demo/demo_flows.csv"]["sha256"]
            actual_labels_sha = demo_status["data/demo/demo_labels.csv"]["sha256"]
            if not expected_flows_sha or actual_flows_sha != expected_flows_sha:
                raise ValueError("demo_flows.csv SHA-256 mismatch with demo_manifest.json")
            if not expected_labels_sha or actual_labels_sha != expected_labels_sha:
                raise ValueError("demo_labels.csv SHA-256 mismatch with demo_manifest.json")
            if split_manifest.is_file():
                expected_split_sha = demo_manifest.get("split_manifest_sha256")
                if expected_split_sha and expected_split_sha != _sha256_file(split_manifest):
                    raise ValueError(
                        "demo_manifest split_manifest_sha256 mismatch with split manifest"
                    )
        except Exception as exc:
            demo_ready = False
            demo_error = str(exc)

    ood_gate_abs = resolved_runtime / OOD_REFERENCE_GATE_REL
    ood_gate_status: Dict[str, Any]
    try:
        trusted_ood_sha, ood_trust_source = resolve_expected_ood_gate_sha256(
            expected_ood_gate_sha256
        )
        ood_anchor_err: Optional[str] = None
    except Exception as exc:
        trusted_ood_sha = None
        ood_trust_source = "invalid_expected_sha256"
        ood_anchor_err = str(exc)

    if not ood_gate_abs.is_file():
        ood_gate_status = {
            "ready": False,
            "status": "NOT_FITTED",
            "path": OOD_REFERENCE_GATE_REL.as_posix(),
            "sha256": None,
            "expected_sha256": trusted_ood_sha,
            "fit_rows": None,
            "feature_count": 0,
            "preprocessor_artifact_sha256": None,
            "structural_schema_verified": False,
            "preprocessor_linkage_verified": False,
            "trusted_digest_verified": False,
            "integrity_verification_status": "FAIL",
            "trust_anchor_source": ood_trust_source or "none",
            "same_boundary_cross_check": "none",
            "reason": ood_anchor_err
            or f"Missing OOD reference gate artifact: {OOD_REFERENCE_GATE_REL.as_posix()}",
        }
    elif ood_anchor_err is not None:
        ood_gate_status = {
            "ready": False,
            "status": "ERROR",
            "path": OOD_REFERENCE_GATE_REL.as_posix(),
            "sha256": _sha256_file(ood_gate_abs).lower(),
            "expected_sha256": None,
            "fit_rows": None,
            "feature_count": 0,
            "preprocessor_artifact_sha256": None,
            "structural_schema_verified": False,
            "preprocessor_linkage_verified": False,
            "trusted_digest_verified": False,
            "integrity_verification_status": "FAIL",
            "trust_anchor_source": ood_trust_source,
            "same_boundary_cross_check": "none",
            "reason": ood_anchor_err,
        }
    elif not prep_status["ready"] or prep_sha is None:
        ood_gate_status = {
            "ready": False,
            "status": "ERROR",
            "path": OOD_REFERENCE_GATE_REL.as_posix(),
            "sha256": _sha256_file(ood_gate_abs).lower(),
            "expected_sha256": trusted_ood_sha,
            "fit_rows": None,
            "feature_count": 0,
            "preprocessor_artifact_sha256": None,
            "structural_schema_verified": False,
            "preprocessor_linkage_verified": False,
            "trusted_digest_verified": False,
            "integrity_verification_status": "FAIL",
            "trust_anchor_source": ood_trust_source or "none",
            "same_boundary_cross_check": "none",
            "reason": "Preprocessor artifact is not verified.",
        }
    else:
        try:
            _, ood_meta = verify_ood_gate_artifact(
                ood_gate_abs,
                expected_preprocessor_sha256=prep_sha,
                expected_sha256=trusted_ood_sha,
            )
            same_boundary = cross_check_same_boundary_embedded_manifest(
                ood_gate_abs, str(ood_meta["sha256"])
            )
            trusted_verified = trusted_ood_sha is not None
            ood_gate_status = {
                "ready": True,
                "status": "FITTED",
                "path": OOD_REFERENCE_GATE_REL.as_posix(),
                "sha256": ood_meta["sha256"],
                "expected_sha256": trusted_ood_sha,
                "fit_rows": ood_meta["fit_rows"],
                "feature_count": ood_meta["feature_count"],
                "preprocessor_artifact_sha256": ood_meta["preprocessor_artifact_sha256"],
                "structural_schema_verified": True,
                "preprocessor_linkage_verified": True,
                "trusted_digest_verified": trusted_verified,
                "integrity_verification_status": (
                    "PASS" if trusted_verified else "PARTIAL_UNANCHORED"
                ),
                "trust_anchor_source": ood_trust_source or "none",
                "same_boundary_cross_check": same_boundary or "none",
                "reason": None,
            }
            staged_files.append(OOD_REFERENCE_GATE_REL)
        except Exception as exc:
            ood_gate_status = {
                "ready": False,
                "status": "ERROR",
                "path": OOD_REFERENCE_GATE_REL.as_posix(),
                "sha256": None,
                "expected_sha256": trusted_ood_sha,
                "fit_rows": None,
                "feature_count": 0,
                "preprocessor_artifact_sha256": None,
                "structural_schema_verified": False,
                "preprocessor_linkage_verified": False,
                "trusted_digest_verified": False,
                "integrity_verification_status": "FAIL",
                "trust_anchor_source": ood_trust_source or "none",
                "same_boundary_cross_check": "none",
                "reason": str(exc),
            }

    all_four_ready = (
        prep_status["ready"]
        and len(ready_models) == len(MODEL_SPECS)
        and demo_ready
        and ood_gate_status["ready"]
    )
    unique_staged = sorted({p.as_posix() for p in staged_files})

    return {
        "overall_status": "READY" if all_four_ready else "BLOCKED / NOT READY",
        "ready_models": ready_models,
        "preprocessor": prep_status,
        "models": models_status,
        "ood_gate": ood_gate_status,
        "demo": demo_status,
        "demo_ready": demo_ready,
        "demo_verification_error": demo_error,
        "companion_files": unique_staged,
    }


def stage_companion_bundle(
    destination: Path,
    root: Path = PROJECT_ROOT,
    *,
    runtime_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Copy verified runtime companion artifacts (no raw dataset) + SHA256SUMS.

    Synchronizes any sidecar model manifest (e.g. XGBoost/Autoencoder sidecars)
    with the authoritative tracked manifest in ``reports/models/`` before
    emitting ``COMPANION_SHA256SUMS.txt``.
    """
    summary = (
        verify_companion_artifacts(root=root)
        if runtime_dir is None
        else verify_companion_artifacts(root=root, runtime_dir=runtime_dir)
    )
    if summary["overall_status"] != "READY":
        raise RuntimeError(
            "Cannot stage companion bundle while artifacts are incomplete or unverified: "
            f"ready_models={summary['ready_models']}, demo_ready={summary['demo_ready']}"
        )

    resolved_root = Path(root).resolve()
    resolved_runtime = Path(runtime_dir).resolve() if runtime_dir is not None else resolved_root
    dest_dir = Path(destination).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    staged_set = list(summary["companion_files"])
    for sidecar_rel, tracked_rel in SIDECAR_MANIFEST_MAPPINGS.items():
        if (resolved_root / tracked_rel).is_file() and sidecar_rel not in staged_set:
            staged_set.append(sidecar_rel)
    staged_set = sorted(set(staged_set))

    checksum_lines: List[str] = []
    synced_sidecars: List[str] = []
    for rel_str in staged_set:
        if rel_str in SIDECAR_MANIFEST_MAPPINGS:
            tracked_src = resolved_root / SIDECAR_MANIFEST_MAPPINGS[rel_str]
            src = tracked_src if tracked_src.is_file() else (resolved_runtime / rel_str)
            if tracked_src.is_file():
                synced_sidecars.append(rel_str)
        elif rel_str.startswith("reports/"):
            src = resolved_root / rel_str
        else:
            src = resolved_runtime / rel_str
        dst = dest_dir / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        checksum = _sha256_file(dst)
        checksum_lines.append(f"{checksum}  {rel_str}")

    sums_path = dest_dir / "COMPANION_SHA256SUMS.txt"
    sums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    return {
        **summary,
        "companion_files": staged_set,
        "synced_sidecars": synced_sidecars,
        "destination": str(dest_dir),
        "checksums_file": str(sums_path),
        "staged_file_count": len(checksum_lines),
    }


def _check_git_tree_clean(root: Path) -> Optional[bool]:
    if not (root / ".git").exists():
        return None
    proc = subprocess.run(  # noqa: S603 - fixed local git status query
        ["git", "status", "--porcelain"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() == ""


def verify_distribution_permission(
    scope: str,
    *,
    is_public_release: bool = False,
    target_channel: Optional[str] = None,
    repo_is_private: Optional[bool] = None,
    root: Path = PROJECT_ROOT,
    expected_evidence_sha256: Optional[str] = None,
    require_evidence_hash: bool = False,
) -> Dict[str, Any]:
    """Enforce evidence-based distribution & repository visibility gates fail-closed.

    Distinguishes 4 tiers:
    - research-only: local academic research only (no CI upload, no release)
    - private-build-only: local offline or strictly private repository/runner CI testing
    - non-commercial-controlled: private controlled channels only (no public upload/release)
    - public-release-approved: public Actions artifact or GitHub Release ONLY when backed
      by verifiable evidence in reports/governance/DISTRIBUTION_AUTHORIZATION.json.
    """
    resolved_root = Path(root).resolve()
    norm_scope = (scope or "").strip().lower()
    effective_channel = (
        (target_channel or "").strip().lower()
        if target_channel is not None
        else ("public_github_release" if is_public_release else "local_offline")
    )
    if effective_channel not in TARGET_DISTRIBUTION_CHANNELS:
        raise RuntimeError(
            "BLOCKED — DISTRIBUTION PERMISSION: Invalid target_channel "
            f"{effective_channel!r}; expected one of {sorted(TARGET_DISTRIBUTION_CHANNELS)}."
        )

    missing_notices = [
        rel.as_posix()
        for rel in (Path("NOTICE"), Path("THIRD_PARTY_NOTICES.md"), Path("LICENSE"))
        if not (resolved_root / rel).is_file()
    ]
    if missing_notices:
        raise RuntimeError(
            "BLOCKED — DISTRIBUTION PERMISSION: Missing mandatory attribution/license notices: "
            f"{missing_notices}"
        )

    for rel in (Path("NOTICE"), Path("THIRD_PARTY_NOTICES.md")):
        notice_text = (resolved_root / rel).read_text(encoding="utf-8", errors="replace")
        missing_markers = [m for m in _REQUIRED_NOTICE_MARKERS if m not in notice_text]
        if not notice_text.strip() or missing_markers:
            raise RuntimeError(
                f"BLOCKED — DISTRIBUTION PERMISSION: {rel.as_posix()} is missing required "
                f"v2 dataset attribution markers {missing_markers}."
            )
    if not (resolved_root / "LICENSE").read_text(encoding="utf-8", errors="replace").strip():
        raise RuntimeError("BLOCKED — DISTRIBUTION PERMISSION: LICENSE file must not be empty.")

    auth_manifest_path = resolved_root / DISTRIBUTION_AUTH_MANIFEST_REL
    if not auth_manifest_path.is_file():
        raise RuntimeError(
            "BLOCKED — DISTRIBUTION PERMISSION: Missing governance authorization manifest "
            f"{DISTRIBUTION_AUTH_MANIFEST_REL.as_posix()}."
        )
    auth_doc = _read_json_dict(auth_manifest_path, "DISTRIBUTION_AUTHORIZATION.json")
    if (
        auth_doc.get("schema_version") not in (1, 2)
        or auth_doc.get("dataset") != "NetFlow-Sentinel-v2-MultiSource"
        or str(auth_doc.get("dataset_license_id", "")).strip() not in {"CC-BY-4.0", "CC BY 4.0"}
        or str(auth_doc.get("dataset_doi", "")).strip() != "10.5281/zenodo.13168643"
    ):
        raise RuntimeError(
            "BLOCKED — DISTRIBUTION PERMISSION: Invalid v2 DISTRIBUTION_AUTHORIZATION.json header."
        )

    if norm_scope == "non-commercial-academic-approved":
        raise RuntimeError(
            "BLOCKED — DISTRIBUTION PERMISSION: Legacy string 'non-commercial-academic-approved' "
            "is NOT legal evidence for public redistribution of derived models/demo CSV. "
            "Use 'private-build-only' on a verified private repository/runner for internal builds, "
            "or provide verifiable authorization evidence for 'public-release-approved'."
        )

    if norm_scope not in APPROVED_DISTRIBUTION_SCOPES:
        raise RuntimeError(
            "BLOCKED — DISTRIBUTION PERMISSION: Unrecognized distribution scope "
            f"{scope!r}. Expected one of {sorted(APPROVED_DISTRIBUTION_SCOPES)}."
        )

    is_public_channel = is_public_release or effective_channel in {
        "public_ci_artifact",
        "public_github_release",
    }

    if norm_scope == "research-only" and effective_channel != "local_offline":
        raise RuntimeError(
            "BLOCKED — DISTRIBUTION PERMISSION: Scope 'research-only' is restricted to "
            f"target_channel='local_offline', cannot target {effective_channel!r}."
        )

    if norm_scope in {"private-build-only", "non-commercial-controlled"}:
        if is_public_channel:
            raise RuntimeError(
                f"BLOCKED — DISTRIBUTION PERMISSION: Scope {norm_scope!r} forbids public "
                f"channel {effective_channel!r} (no public workflow artifact upload, cache, or release)."
            )
        if effective_channel == "private_ci_artifact" and repo_is_private is not True:
            raise RuntimeError(
                f"BLOCKED — DISTRIBUTION PERMISSION: Refusing {norm_scope!r} artifact upload "
                f"because repository privacy is not verified private (repo_is_private={repo_is_private!r})."
            )

    evidence_verified = False
    public_release_allowed = False
    evidence_ref: Optional[str] = None
    maintainer_approver: Optional[str] = None
    legal_basis: Optional[str] = None

    if norm_scope == "public-release-approved" or is_public_channel:
        pub_auth = auth_doc.get("public_release_authorization")
        if not isinstance(pub_auth, dict):
            raise RuntimeError(
                "BLOCKED — DISTRIBUTION PERMISSION: Missing public_release_authorization block."
            )
        if pub_auth.get("approved") is not True or pub_auth.get("status") != "APPROVED":
            raise RuntimeError(
                "BLOCKED — DISTRIBUTION PERMISSION: Public distribution of v2 "
                "derived models/demo CSV is NOT authorized "
                f"(status={pub_auth.get('status')!r}, approved={pub_auth.get('approved')!r}). "
                "Requires verifiable authorization evidence and maintainer signoff."
            )
        legal_basis = pub_auth.get("legal_basis")
        if not isinstance(legal_basis, str) or legal_basis not in APPROVED_PUBLIC_LEGAL_BASES:
            raise RuntimeError(
                "BLOCKED — DISTRIBUTION PERMISSION: Invalid public authorization legal_basis: "
                f"{legal_basis!r}"
            )
        maintainer_approver = pub_auth.get("maintainer_approver")
        approved_at_utc = pub_auth.get("approved_at_utc")
        evidence_ref = pub_auth.get("evidence_ref")
        evidence_sha = pub_auth.get("evidence_sha256")
        if (
            not isinstance(maintainer_approver, str)
            or not maintainer_approver.strip()
            or not isinstance(approved_at_utc, str)
            or not approved_at_utc.strip()
            or not isinstance(evidence_ref, str)
            or not evidence_ref.strip()
            or not _is_hex_sha256(evidence_sha)
        ):
            raise RuntimeError(
                "BLOCKED — DISTRIBUTION PERMISSION: Incomplete public authorization metadata "
                "(requires maintainer_approver, approved_at_utc, evidence_ref, and 64-hex evidence_sha256)."
            )
        try:
            datetime.fromisoformat(approved_at_utc.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuntimeError(
                f"BLOCKED — DISTRIBUTION PERMISSION: Invalid approved_at_utc timestamp: {approved_at_utc!r}"
            ) from exc

        if pub_auth.get("requires_attribution_notices") is not True or not isinstance(
            pub_auth.get("forbids_commercial_use"), bool
        ):
            raise RuntimeError(
                "BLOCKED — DISTRIBUTION PERMISSION: Authorization must preserve attribution "
                "requirements and explicit commercial-use policy boolean."
            )

        covered = pub_auth.get("covered_artifacts")
        required_covered = {
            PREPROCESSOR_REL.as_posix(),
            *(spec[0].as_posix() for spec in MODEL_SPECS.values()),
            *(rel.as_posix() for rel in DEMO_FILES_REL),
        }
        if not isinstance(covered, list) or not required_covered.issubset(set(covered)):
            raise RuntimeError(
                "BLOCKED — DISTRIBUTION PERMISSION: public_release_authorization.covered_artifacts "
                "does not cover all embedded models, preprocessor, and demo files."
            )

        norm_expected = (
            expected_evidence_sha256.strip().lower()
            if isinstance(expected_evidence_sha256, str) and expected_evidence_sha256.strip()
            else None
        )
        if require_evidence_hash and norm_expected is None:
            raise RuntimeError(
                "BLOCKED — DISTRIBUTION PERMISSION: Missing expected evidence SHA-256 secret "
                "(DISTRIBUTION_EVIDENCE_SHA256) for CI public release verification."
            )
        if norm_expected is not None:
            if not _is_hex_sha256(norm_expected) or not hmac.compare_digest(
                norm_expected, str(evidence_sha).lower()
            ):
                raise RuntimeError(
                    "BLOCKED — DISTRIBUTION PERMISSION: Authorization evidence SHA-256 verification failed."
                )
            evidence_verified = True
        else:
            evidence_verified = True

        public_release_allowed = True

    upload_allowed = (
        effective_channel == "private_ci_artifact"
        and repo_is_private is True
        and norm_scope
        in {"private-build-only", "non-commercial-controlled", "public-release-approved"}
    ) or (
        effective_channel in {"public_ci_artifact", "public_github_release"}
        and public_release_allowed
    )

    return {
        "status": "APPROVED",
        "distribution_scope": norm_scope,
        "target_channel": effective_channel,
        "repo_is_private": repo_is_private,
        "is_public_release": bool(
            is_public_release or effective_channel == "public_github_release"
        ),
        "upload_allowed": upload_allowed,
        "public_release_allowed": public_release_allowed,
        "evidence_verified": evidence_verified,
        "legal_basis": legal_basis,
        "maintainer_approver": maintainer_approver,
        "evidence_ref": evidence_ref,
        "dataset_license": str(auth_doc.get("dataset_license_id") or "CC-BY-4.0"),
        "citation_doi": str(auth_doc.get("dataset_doi") or "10.5281/zenodo.13168643"),
        "notices_verified": ["NOTICE", "THIRD_PARTY_NOTICES.md", "LICENSE"],
        "governance_manifest": DISTRIBUTION_AUTH_MANIFEST_REL.as_posix(),
    }


def stage_embedded_bundle(
    destination: Path,
    root: Path = PROJECT_ROOT,
    *,
    runtime_dir: Optional[Path] = None,
    distribution_scope: str = "private-build-only",
    target_channel: str = "local_offline",
    repo_is_private: Optional[bool] = None,
    expected_evidence_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Stage all 4 verified models, preprocessor, manifests, demo CSV, and notices for NSIS embedding."""
    resolved_root = Path(root).resolve()
    perm = verify_distribution_permission(
        distribution_scope,
        is_public_release=(target_channel == "public_github_release"),
        target_channel=target_channel,
        repo_is_private=repo_is_private,
        root=resolved_root,
        expected_evidence_sha256=expected_evidence_sha256,
        require_evidence_hash=(target_channel in {"public_ci_artifact", "public_github_release"}),
    )
    dest_dir = Path(destination).resolve()
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    staged = stage_companion_bundle(
        destination=dest_dir,
        root=resolved_root,
        runtime_dir=runtime_dir,
    )

    extra_checksum_lines: List[str] = []
    extra_rels: List[str] = []
    for rel in EMBEDDED_EXTRA_FILES_REL:
        src = resolved_root / rel
        if not src.is_file():
            raise RuntimeError(f"Missing required embedded resource file: {src}")
        dst = dest_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        rel_posix = rel.as_posix()
        extra_rels.append(rel_posix)
        extra_checksum_lines.append(f"{_sha256_file(dst).lower()}  {rel_posix}")

    companion_sums_path = dest_dir / "COMPANION_SHA256SUMS.txt"
    existing_lines = [
        line.strip()
        for line in companion_sums_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    all_lines = sorted(set(existing_lines + extra_checksum_lines))
    embedded_sums_path = dest_dir / "EMBEDDED_SHA256SUMS.txt"
    embedded_sums_path.write_text("\n".join(all_lines) + "\n", encoding="utf-8", newline="\n")
    companion_sums_path.unlink(missing_ok=True)

    source_commit: Optional[str] = None
    if (resolved_root / ".git").exists():
        try:
            source_commit = _get_git_head_commit(resolved_root)
        except Exception:
            source_commit = None

    split_path = resolved_root / SPLIT_MANIFEST_REL
    embedded_files = sorted(set(staged["companion_files"] + extra_rels))
    manifest_payload: Dict[str, Any] = {
        "format": "netflow-sentinel-embedded-bundle-v1",
        "source_commit": source_commit,
        "desktop_version": (
            _read_desktop_version(resolved_root)
            if (resolved_root / "desktop/package.json").is_file()
            else None
        ),
        "distribution_scope": perm["distribution_scope"],
        "dataset_license": perm["dataset_license"],
        "citation_doi": perm["citation_doi"],
        "split_manifest_sha256": (
            _sha256_file(split_path).lower() if split_path.is_file() else None
        ),
        "preprocessor_sha256": staged["preprocessor"]["sha256"],
        "models": {
            key: {"sha256": info["sha256"], "run_id": info["run_id"]}
            for key, info in staged["models"].items()
        },
        "ood_gate": {
            "status": (staged.get("ood_gate") or {}).get("status"),
            "sha256": (staged.get("ood_gate") or {}).get("sha256"),
            "fit_rows": (staged.get("ood_gate") or {}).get("fit_rows"),
            "preprocessor_artifact_sha256": (staged.get("ood_gate") or {}).get(
                "preprocessor_artifact_sha256"
            ),
        },
        "demo_sha256": {key: info["sha256"] for key, info in staged["demo"].items()},
        "files": embedded_files,
    }
    manifest_path = dest_dir / "EMBEDDED_ARTIFACTS_MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8", newline="\n"
    )

    return {
        "stage_status": "READY",
        "destination": str(dest_dir),
        "distribution_permission": perm,
        "embedded_file_count": len(embedded_files),
        "embedded_files": embedded_files,
        "checksums_file": str(embedded_sums_path),
        "manifest_file": str(manifest_path),
        "preprocessor": staged["preprocessor"],
        "models": staged["models"],
        "ood_gate": staged.get("ood_gate"),
        "demo": staged["demo"],
    }


def verify_installed_standalone_layout(
    install_dir: Path,
    *,
    expected_sidecar_sha256: Optional[str] = None,
    expected_ood_gate_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify an installed NSIS directory has sidecar, notices, and all 4 embedded models."""
    resolved_install = Path(install_dir).resolve()
    sidecar_exe = resolved_install / "netflow-sentinel-backend.exe"
    desktop_exe = resolved_install / "netflow-sentinel-desktop.exe"
    uninstaller_exe = resolved_install / "uninstall.exe"
    for req_bin, label in (
        (desktop_exe, "installed desktop executable"),
        (sidecar_exe, "embedded PyInstaller backend sidecar"),
        (uninstaller_exe, "NSIS uninstaller"),
    ):
        if not req_bin.is_file() or req_bin.stat().st_size <= 0:
            raise RuntimeError(f"Missing {label} inside installed directory: {req_bin}")

    sidecar_sha = _sha256_file(sidecar_exe).lower()
    if expected_sidecar_sha256 is not None:
        exp = expected_sidecar_sha256.strip().lower()
        if not _is_hex_sha256(exp) or sidecar_sha != exp:
            raise RuntimeError(
                f"Installed backend sidecar SHA-256 mismatch: {sidecar_sha} != {exp}"
            )

    for notice_rel in EMBEDDED_EXTRA_FILES_REL:
        if not (resolved_install / notice_rel).is_file():
            raise RuntimeError(
                f"Missing required embedded notice/manifest in install dir: {notice_rel.as_posix()}"
            )

    sums_file = resolved_install / "EMBEDDED_SHA256SUMS.txt"
    sums_map = _parse_sha256_sums_file(sums_file)
    for rel_str, expected_sha in sums_map.items():
        candidate = (resolved_install / rel_str).resolve()
        if not candidate.is_relative_to(resolved_install) or not candidate.is_file():
            raise RuntimeError(
                f"Installed standalone bundle missing file {rel_str!r} listed in EMBEDDED_SHA256SUMS.txt"
            )
        actual_sha = _sha256_file(candidate).lower()
        if actual_sha != expected_sha:
            raise RuntimeError(
                f"Installed embedded file SHA-256 mismatch for {rel_str}: {actual_sha} != {expected_sha}"
            )

    manifest_data = _read_json_dict(
        resolved_install / "EMBEDDED_ARTIFACTS_MANIFEST.json",
        "installed EMBEDDED_ARTIFACTS_MANIFEST.json",
    )
    for req_companion in (OOD_REFERENCE_GATE_REL.as_posix(), AE_SCORE_NORMALIZATION_REL.as_posix()):
        if req_companion not in sums_map:
            raise RuntimeError(
                f"Installed standalone bundle missing {req_companion!r} in EMBEDDED_SHA256SUMS.txt"
            )
    summary = verify_companion_artifacts(
        root=resolved_install,
        runtime_dir=resolved_install,
        expected_ood_gate_sha256=expected_ood_gate_sha256,
    )
    ood_gate_info = summary.get("ood_gate") or {}
    if not ood_gate_info.get("ready") or ood_gate_info.get("status") != "FITTED":
        raise RuntimeError(
            "Installed standalone OOD gate verification failed (must be FITTED): "
            f"{ood_gate_info}"
        )
    expected_ood_sha = (manifest_data.get("ood_gate") or {}).get("sha256")
    if (
        not expected_ood_sha
        or not _is_hex_sha256(str(expected_ood_sha))
        or str(expected_ood_sha).lower() != str(ood_gate_info.get("sha256", "")).lower()
    ):
        raise RuntimeError(
            "Installed standalone OOD gate SHA-256 missing or mismatch with EMBEDDED_ARTIFACTS_MANIFEST.json"
        )
    sums_ood_sha = sums_map.get(OOD_REFERENCE_GATE_REL.as_posix())
    if not sums_ood_sha or sums_ood_sha.lower() != str(expected_ood_sha).lower():
        raise RuntimeError(
            "Installed standalone OOD gate SHA-256 mismatch between EMBEDDED_ARTIFACTS_MANIFEST.json and EMBEDDED_SHA256SUMS.txt"
        )
    if summary["overall_status"] != "READY" or len(summary["ready_models"]) != len(MODEL_SPECS):
        raise RuntimeError(
            "Installed standalone artifacts verification failed: "
            f"ready_models={summary['ready_models']}, demo_ready={summary['demo_ready']}, "
            f"ood_gate={ood_gate_info.get('status')}"
        )

    return {
        "status": "READY",
        "install_dir": str(resolved_install),
        "sidecar_sha256": sidecar_sha,
        "sidecar_size_bytes": sidecar_exe.stat().st_size,
        "embedded_file_count": len(sums_map),
        "distribution_scope": manifest_data.get("distribution_scope"),
        "ood_gate": ood_gate_info,
        "summary": summary,
    }


_COMPANION_ALLOWED_PREFIXES = ("artifacts/", "data/demo/", "reports/")
_COMPANION_ROOT_META_FILES = frozenset(
    {"COMPANION_SHA256SUMS.txt", "COMPANION_BUNDLE_MANIFEST.json"}
)
_DEFAULT_ALLOWED_BUNDLE_HOSTS = frozenset(
    {
        "github.com",
        "api.github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)
_GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GITHUB_TOKEN_ENV_NAMES = frozenset({"GH_TOKEN", "GITHUB_TOKEN"})


def _normalize_allowed_hosts(allowed_hosts: Optional[List[str]]) -> Optional[frozenset[str]]:
    if not allowed_hosts:
        return None
    normalized: set[str] = set()
    for raw in allowed_hosts:
        for part in str(raw).split(","):
            host = part.strip().lower()
            if host:
                normalized.add(host)
    return frozenset(normalized) if normalized else None


def _is_valid_github_api_url(url: str, github_repo: Optional[str] = None) -> bool:
    """Return True strictly for HTTPS GitHub REST API repository endpoints."""
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() != "https" or parsed.username or parsed.password:
        return False
    host = (parsed.hostname or "").strip().lower()
    if host != "api.github.com":
        return False
    if github_repo is not None:
        repo_norm = github_repo.strip()
        if not _GITHUB_REPO_RE.fullmatch(repo_norm):
            return False
        return parsed.path.startswith(f"/repos/{repo_norm}/")
    return bool(re.match(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/", parsed.path))


def _is_github_actions_storage_redirect_host(host: str) -> bool:
    return host in _DEFAULT_ALLOWED_BUNDLE_HOSTS or host.endswith(
        (".actions.githubusercontent.com", ".blob.core.windows.net")
    )


def _validate_companion_url(
    url: str,
    *,
    allowed_hosts: Optional[List[str]] = None,
    github_repo: Optional[str] = None,
    allow_github_actions_storage_redirects: bool = False,
) -> str:
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() != "https":
        raise RuntimeError(f"Disallowed companion URL scheme (HTTPS required): {url!r}")
    if parsed.username or parsed.password:
        raise RuntimeError("Companion URL must not contain embedded credentials.")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise RuntimeError(f"Invalid companion URL missing hostname: {url!r}")

    custom_hosts = _normalize_allowed_hosts(allowed_hosts)
    if custom_hosts is not None:
        effective_hosts = custom_hosts
        host_allowed = host in effective_hosts
    else:
        effective_hosts = _DEFAULT_ALLOWED_BUNDLE_HOSTS
        host_allowed = (
            _is_github_actions_storage_redirect_host(host)
            if allow_github_actions_storage_redirects
            else host in effective_hosts
        )
    if not host_allowed:
        raise RuntimeError(
            f"Disallowed companion URL host {host!r} (allowed: {sorted(effective_hosts)})"
        )

    if custom_hosts is None and github_repo:
        repo_norm = github_repo.strip()
        if not _GITHUB_REPO_RE.fullmatch(repo_norm):
            raise RuntimeError(f"Invalid github_repo identifier: {github_repo!r}")
        if host == "github.com" and not parsed.path.startswith(f"/{repo_norm}/"):
            raise RuntimeError(
                f"GitHub companion URL path must belong to repository {repo_norm!r}: {parsed.path!r}"
            )
        if host == "api.github.com" and not parsed.path.startswith(f"/repos/{repo_norm}/"):
            raise RuntimeError(
                f"GitHub API companion URL path must belong to repository {repo_norm!r}: {parsed.path!r}"
            )
    return parsed.geturl()


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Enforce HTTPS + allowlist on HTTP redirects and always strip Auth headers."""

    def __init__(
        self,
        allowed_hosts: Optional[List[str]],
        github_repo: Optional[str],
        *,
        allow_actions_storage_redirects: bool = False,
    ) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts
        self.github_repo = github_repo
        self.allow_actions_storage_redirects = allow_actions_storage_redirects

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        validated = _validate_companion_url(
            newurl,
            allowed_hosts=self.allowed_hosts,
            github_repo=self.github_repo,
            allow_github_actions_storage_redirects=self.allow_actions_storage_redirects,
        )
        redirected = super().redirect_request(req, fp, code, msg, headers, validated)
        if redirected is not None:
            for hdr in list(redirected.headers.keys()):
                if hdr.lower() == "authorization":
                    redirected.headers.pop(hdr, None)
            for hdr in list(redirected.unredirected_hdrs.keys()):
                if hdr.lower() == "authorization":
                    redirected.unredirected_hdrs.pop(hdr, None)
        return redirected


def _build_allowlisted_opener(
    allowed_hosts: Optional[List[str]],
    github_repo: Optional[str],
    *,
    allow_actions_storage_redirects: bool = False,
) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        _AllowlistedRedirectHandler(
            allowed_hosts,
            github_repo,
            allow_actions_storage_redirects=allow_actions_storage_redirects,
        )
    )


def _resolve_token_for_url(
    url: str,
    *,
    github_repo: Optional[str],
    token_env_var: Optional[str],
    require_token_if_github_api: bool = False,
) -> Optional[str]:
    """Scope GH_TOKEN strictly to valid GitHub API URLs; require explicit token_env_var for external URLs."""
    is_github_api = _is_valid_github_api_url(url, github_repo)
    cleaned_env = token_env_var.strip() if token_env_var and token_env_var.strip() else None

    if cleaned_env is not None:
        if cleaned_env in _GITHUB_TOKEN_ENV_NAMES and not is_github_api:
            raise RuntimeError(f"Refusing to send {cleaned_env} to non-GitHub-API URL: {url!r}")
        val = os.environ.get(cleaned_env)
        if not val or not val.strip():
            raise RuntimeError(
                f"Configured token environment variable {cleaned_env!r} is missing or empty."
            )
        return val.strip()

    if is_github_api:
        val = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if val and val.strip():
            return val.strip()
        if require_token_if_github_api:
            raise RuntimeError(
                "GH_TOKEN or GITHUB_TOKEN is required in environment to query GitHub Actions API."
            )
        return None

    return None


def _download_allowlisted_bytes(
    url: str,
    *,
    allowed_hosts: Optional[List[str]] = None,
    github_repo: Optional[str] = None,
    token: Optional[str] = None,
    token_source_is_github: bool = False,
    allow_actions_storage_redirects: bool = False,
    accept: str = "application/octet-stream",
    timeout: float = 60.0,
) -> bytes:
    validated_url = _validate_companion_url(
        url,
        allowed_hosts=allowed_hosts,
        github_repo=github_repo,
        allow_github_actions_storage_redirects=False,
    )
    if (
        token
        and token_source_is_github
        and not _is_valid_github_api_url(validated_url, github_repo)
    ):
        raise RuntimeError(
            f"Refusing to attach GitHub token to non-GitHub-API URL: {validated_url!r}"
        )

    opener = _build_allowlisted_opener(
        allowed_hosts,
        github_repo,
        allow_actions_storage_redirects=allow_actions_storage_redirects,
    )
    headers = {
        "User-Agent": "netflow-sentinel-companion-installer/0.6.0",
        "Accept": accept,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(validated_url, headers=headers, method="GET")  # noqa: S310
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310
        final_url = resp.geturl()
        if final_url:
            _validate_companion_url(
                final_url,
                allowed_hosts=allowed_hosts,
                github_repo=github_repo,
                allow_github_actions_storage_redirects=allow_actions_storage_redirects,
            )
        return bytes(resp.read())


def package_companion_bundle(
    archive_path: Path,
    root: Path = PROJECT_ROOT,
    *,
    runtime_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Create a deterministic ZIP of verified companion files + manifest & checksums."""
    resolved_root = Path(root).resolve()
    out_zip = Path(archive_path).resolve()
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="nf_pkg_companion_") as tmp_dir:
        stage_dir = Path(tmp_dir) / "staged"
        staged = stage_companion_bundle(
            destination=stage_dir,
            root=resolved_root,
            runtime_dir=runtime_dir,
        )

        source_commit: Optional[str] = None
        if (resolved_root / ".git").exists():
            try:
                source_commit = _get_git_head_commit(resolved_root)
            except Exception:
                source_commit = None

        split_path = resolved_root / SPLIT_MANIFEST_REL
        manifest_payload: Dict[str, Any] = {
            "format": "netflow-sentinel-companion-bundle-v1",
            "source_commit": source_commit,
            "desktop_version": (
                _read_desktop_version(resolved_root)
                if (resolved_root / "desktop/package.json").is_file()
                else None
            ),
            "split_manifest_sha256": (
                _sha256_file(split_path).lower() if split_path.is_file() else None
            ),
            "preprocessor_sha256": staged["preprocessor"]["sha256"],
            "models": {
                key: {"sha256": info["sha256"], "run_id": info["run_id"]}
                for key, info in staged["models"].items()
            },
            "ood_gate": {
                "status": (staged.get("ood_gate") or {}).get("status"),
                "sha256": (staged.get("ood_gate") or {}).get("sha256"),
                "fit_rows": (staged.get("ood_gate") or {}).get("fit_rows"),
                "preprocessor_artifact_sha256": (staged.get("ood_gate") or {}).get(
                    "preprocessor_artifact_sha256"
                ),
            },
            "demo_sha256": {key: info["sha256"] for key, info in staged["demo"].items()},
            "files": sorted(staged["companion_files"]),
        }
        (stage_dir / "COMPANION_BUNDLE_MANIFEST.json").write_text(
            json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8", newline="\n"
        )

        all_rels = sorted(
            [
                *staged["companion_files"],
                "COMPANION_SHA256SUMS.txt",
                "COMPANION_BUNDLE_MANIFEST.json",
            ]
        )
        tmp_zip = out_zip.with_suffix(".zip.tmp")
        with zipfile.ZipFile(tmp_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel_str in all_rels:
                zinfo = zipfile.ZipInfo(filename=rel_str, date_time=(2026, 1, 1, 0, 0, 0))
                zinfo.external_attr = 0o644 << 16
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zinfo, (stage_dir / rel_str).read_bytes())
        tmp_zip.replace(out_zip)

    bundle_sha256 = _sha256_file(out_zip).lower()
    return {
        "package_status": "READY",
        "bundle_path": str(out_zip),
        "bundle_sha256": bundle_sha256,
        "bundle_size_bytes": out_zip.stat().st_size,
        "staged_file_count": staged["staged_file_count"],
        "companion_files": staged["companion_files"],
    }


def _copy_zip_entry_bounded(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    dst: Path,
    *,
    max_entry_bytes: int,
    remaining_total_bytes: int,
) -> int:
    """Stream one ZIP entry to dst while enforcing header and actual decompressed byte limits."""
    if info.file_size > max_entry_bytes:
        raise RuntimeError(
            f"Archive entry {info.filename!r} declared uncompressed size {info.file_size} bytes "
            f"exceeds limit ({max_entry_bytes} bytes)."
        )
    if info.file_size > remaining_total_bytes:
        raise RuntimeError(
            f"Archive entry {info.filename!r} declared size {info.file_size} bytes "
            f"exceeds total archive extraction budget ({remaining_total_bytes} bytes remaining)."
        )
    written = 0
    try:
        with zf.open(info, "r") as src_fh, dst.open("wb") as dst_fh:
            while True:
                chunk = src_fh.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_entry_bytes:
                    raise RuntimeError(
                        f"Archive entry {info.filename!r} decompressed stream exceeded "
                        f"per-entry limit ({max_entry_bytes} bytes)."
                    )
                if written > remaining_total_bytes:
                    raise RuntimeError(
                        f"Archive extraction exceeded total uncompressed byte limit "
                        f"({MAX_COMPANION_TOTAL_UNCOMPRESSED_BYTES} bytes)."
                    )
                dst_fh.write(chunk)
    except Exception:
        if dst.exists():
            dst.unlink(missing_ok=True)
        raise
    return written


def _extract_safe_companion_zip(archive_path: Path, extract_dir: Path) -> None:
    """Extract companion ZIP fail-closed against traversal, symlinks, disallowed prefixes, and zip bombs."""
    resolved_extract = extract_dir.resolve()
    seen: set[str] = set()
    remaining_total_bytes = MAX_COMPANION_TOTAL_UNCOMPRESSED_BYTES
    entry_count = 0
    with zipfile.ZipFile(archive_path, mode="r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            entry_count += 1
            if entry_count > MAX_COMPANION_ARCHIVE_ENTRIES:
                raise RuntimeError(
                    f"Companion archive exceeds maximum entry count ({MAX_COMPANION_ARCHIVE_ENTRIES})."
                )
            raw_name = info.filename.replace("\\", "/")
            if not raw_name or raw_name.startswith("/") or re.match(r"^[A-Za-z]:", raw_name):
                raise RuntimeError(f"Unsafe archive entry path rejected: {info.filename!r}")
            parts = Path(raw_name).parts
            if ".." in parts or "." in parts:
                raise RuntimeError(f"Path traversal archive entry rejected: {info.filename!r}")
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                raise RuntimeError(f"Symlink archive entry rejected: {info.filename!r}")
            norm_rel = Path(*parts).as_posix()
            if norm_rel in seen:
                raise RuntimeError(f"Duplicate archive entry rejected: {norm_rel!r}")
            seen.add(norm_rel)
            if norm_rel not in _COMPANION_ROOT_META_FILES and not any(
                norm_rel.startswith(p) for p in _COMPANION_ALLOWED_PREFIXES
            ):
                raise RuntimeError(f"Disallowed companion archive entry prefix: {norm_rel!r}")
            dst = (resolved_extract / norm_rel).resolve()
            if not dst.is_relative_to(resolved_extract):
                raise RuntimeError(f"Archive entry escapes extraction root: {norm_rel!r}")
            dst.parent.mkdir(parents=True, exist_ok=True)
            copied = _copy_zip_entry_bounded(
                zf,
                info,
                dst,
                max_entry_bytes=MAX_COMPANION_ENTRY_UNCOMPRESSED_BYTES,
                remaining_total_bytes=remaining_total_bytes,
            )
            remaining_total_bytes -= copied


def _unpack_and_verify_companion_archive(
    archive_file: Path,
    staged_root: Path,
    norm_expected_sha: Optional[str],
    *,
    allow_actions_zip_wrapper: bool = False,
) -> Tuple[str, Optional[str]]:
    """Verify archive SHA-256 and extract, safely unwrapping 1-level GitHub Actions ZIP wrapper."""
    downloaded_sha = _sha256_file(archive_file).lower()
    if allow_actions_zip_wrapper:
        with zipfile.ZipFile(archive_file, mode="r") as outer_zf:
            file_infos: List[Tuple[str, zipfile.ZipInfo]] = []
            seen_outer: set[str] = set()
            for info in outer_zf.infolist():
                if info.is_dir():
                    continue
                raw_name = info.filename.replace("\\", "/")
                if not raw_name or raw_name.startswith("/") or re.match(r"^[A-Za-z]:", raw_name):
                    raise RuntimeError(f"Unsafe archive entry path rejected: {info.filename!r}")
                parts = Path(raw_name).parts
                if ".." in parts or "." in parts:
                    raise RuntimeError(f"Path traversal archive entry rejected: {info.filename!r}")
                unix_mode = (info.external_attr >> 16) & 0o170000
                if unix_mode == 0o120000:
                    raise RuntimeError(f"Symlink archive entry rejected: {info.filename!r}")
                norm_rel = Path(*parts).as_posix()
                if norm_rel in seen_outer:
                    raise RuntimeError(f"Duplicate archive entry rejected: {norm_rel!r}")
                seen_outer.add(norm_rel)
                file_infos.append((norm_rel, info))

            is_single_wrapped_zip = (
                "COMPANION_SHA256SUMS.txt" not in seen_outer
                and len(file_infos) == 1
                and len(Path(file_infos[0][0]).parts) == 1
                and file_infos[0][0].lower().endswith(".zip")
            )
            if is_single_wrapped_zip:
                _, inner_info = file_infos[0]
                inner_archive = (archive_file.parent / "unwrapped_companion.zip").resolve()
                _copy_zip_entry_bounded(
                    outer_zf,
                    inner_info,
                    inner_archive,
                    max_entry_bytes=MAX_COMPANION_TOTAL_UNCOMPRESSED_BYTES,
                    remaining_total_bytes=MAX_COMPANION_TOTAL_UNCOMPRESSED_BYTES,
                )
                inner_sha = _sha256_file(inner_archive).lower()
                if norm_expected_sha is not None and norm_expected_sha not in {
                    inner_sha,
                    downloaded_sha,
                }:
                    raise RuntimeError(
                        f"Companion bundle archive SHA-256 mismatch: "
                        f"inner={inner_sha}, outer={downloaded_sha} != {norm_expected_sha}"
                    )
                _extract_safe_companion_zip(inner_archive, staged_root)
                return inner_sha, downloaded_sha

    if norm_expected_sha is not None and downloaded_sha != norm_expected_sha:
        raise RuntimeError(
            f"Companion bundle archive SHA-256 mismatch: {downloaded_sha} != {norm_expected_sha}"
        )
    _extract_safe_companion_zip(archive_file, staged_root)
    return downloaded_sha, None


def _verify_companion_bundle_manifest(
    bundle_manifest: Dict[str, Any],
    sums_map: Dict[str, str],
    resolved_root: Path,
) -> None:
    """Validate optional COMPANION_BUNDLE_MANIFEST.json provenance against HEAD manifests."""
    fmt = bundle_manifest.get("format")
    if fmt != "netflow-sentinel-companion-bundle-v1":
        raise RuntimeError(f"Unsupported COMPANION_BUNDLE_MANIFEST format: {fmt!r}")

    split_path = resolved_root / SPLIT_MANIFEST_REL
    if split_path.is_file():
        actual_split = _sha256_file(split_path).lower()
        if bundle_manifest.get("split_manifest_sha256") != actual_split:
            raise RuntimeError(
                "COMPANION_BUNDLE_MANIFEST split_manifest_sha256 mismatch with HEAD."
            )

    prep_manifest_path = resolved_root / PREPROCESSOR_MANIFEST_REL
    if prep_manifest_path.is_file():
        prep_manifest = _read_json_dict(prep_manifest_path, str(PREPROCESSOR_MANIFEST_REL))
        expected_prep_sha = str(prep_manifest.get("artifact_sha256") or "").lower()
        if bundle_manifest.get("preprocessor_sha256") != expected_prep_sha:
            raise RuntimeError(
                "COMPANION_BUNDLE_MANIFEST preprocessor_sha256 mismatch with HEAD manifest."
            )

    models_block = bundle_manifest.get("models")
    if not isinstance(models_block, dict) or set(models_block.keys()) != set(MODEL_SPECS.keys()):
        raise RuntimeError(
            f"COMPANION_BUNDLE_MANIFEST models keys mismatch: {list(models_block or [])}"
        )
    for model_key, (_, manifest_candidates) in MODEL_SPECS.items():
        manifest_file = resolved_root / manifest_candidates[0]
        if not manifest_file.is_file():
            continue
        tracked_manifest = _read_json_dict(manifest_file, str(manifest_candidates[0]))
        tracked_sha = str(
            tracked_manifest.get("model_artifact_sha256")
            or tracked_manifest.get("model_sha256")
            or tracked_manifest.get("artifact_sha256")
            or ""
        ).lower()
        entry = models_block.get(model_key) or {}
        if entry.get("sha256") != tracked_sha or entry.get("run_id") != tracked_manifest.get(
            "run_id"
        ):
            raise RuntimeError(
                f"COMPANION_BUNDLE_MANIFEST provenance mismatch for {model_key}: "
                f"entry={entry!r}, expected_sha={tracked_sha!r}, expected_run={tracked_manifest.get('run_id')!r}"
            )

    manifest_files = bundle_manifest.get("files")
    if isinstance(manifest_files, list):
        normalized_manifest_files = {str(p).strip().replace("\\", "/") for p in manifest_files}
        normalized_sum_keys = {str(p).strip().replace("\\", "/") for p in sums_map.keys()}
        if normalized_manifest_files != normalized_sum_keys:
            raise RuntimeError(
                "COMPANION_BUNDLE_MANIFEST files list does not match COMPANION_SHA256SUMS.txt."
            )

    ood_rel = OOD_REFERENCE_GATE_REL.as_posix()
    ood_block = bundle_manifest.get("ood_gate")
    if ood_rel in sums_map:
        if not isinstance(ood_block, dict) or not ood_block.get("sha256"):
            raise RuntimeError(
                "COMPANION_BUNDLE_MANIFEST missing ood_gate metadata for packaged OOD gate."
            )
        if str(ood_block.get("status") or "") != "FITTED":
            raise RuntimeError(
                f"COMPANION_BUNDLE_MANIFEST ood_gate status must be 'FITTED', got {ood_block.get('status')!r}."
            )
        if str(ood_block.get("sha256") or "").lower() != str(sums_map[ood_rel]).lower():
            raise RuntimeError(
                "COMPANION_BUNDLE_MANIFEST ood_gate sha256 mismatch with COMPANION_SHA256SUMS.txt."
            )
        prep_manifest_path = resolved_root / PREPROCESSOR_MANIFEST_REL
        if prep_manifest_path.is_file():
            prep_manifest = _read_json_dict(prep_manifest_path, str(PREPROCESSOR_MANIFEST_REL))
            expected_prep_sha = str(prep_manifest.get("artifact_sha256") or "").lower()
            ood_prep_sha = str(ood_block.get("preprocessor_artifact_sha256") or "").lower()
            if expected_prep_sha and ood_prep_sha != expected_prep_sha:
                raise RuntimeError(
                    "COMPANION_BUNDLE_MANIFEST ood_gate preprocessor_artifact_sha256 mismatch with HEAD manifest."
                )
    elif isinstance(ood_block, dict) and (
        ood_block.get("sha256") is not None or str(ood_block.get("status") or "") == "FITTED"
    ):
        raise RuntimeError(
            "COMPANION_BUNDLE_MANIFEST ood_gate sha256 mismatch: artifact missing from COMPANION_SHA256SUMS.txt."
        )


def _has_symlink_ancestor(path: Path, stop_at: Path) -> bool:
    """Return True if path or any parent directory below stop_at is a symlink."""
    cur = path
    while True:
        if cur.is_symlink():
            return True
        if cur == stop_at or cur.parent == cur:
            return False
        cur = cur.parent


def install_companion_bundle(
    root: Path = PROJECT_ROOT,
    *,
    runtime_dir: Optional[Path] = None,
    bundle_dir: Optional[Path] = None,
    bundle_archive: Optional[Path] = None,
    bundle_url: Optional[str] = None,
    artifact_run_id: Optional[str] = None,
    artifact_name: str = "netflow-sentinel-companion-bundle",
    github_repo: Optional[str] = None,
    expected_bundle_sha256: Optional[str] = None,
    allowed_hosts: Optional[List[str]] = None,
    token_env_var: Optional[str] = None,
    require_checksum_for_remote: bool = True,
) -> Dict[str, Any]:
    """Fetch, verify SHA-256 & provenance, and install companion files into repo or runtime dir."""
    resolved_root = Path(root).resolve()
    resolved_runtime = Path(runtime_dir).resolve() if runtime_dir is not None else resolved_root
    provided_sources = [
        name
        for name, val in (
            ("bundle_dir", bundle_dir),
            ("bundle_archive", bundle_archive),
            ("bundle_url", bundle_url),
            ("artifact_run_id", artifact_run_id),
        )
        if val is not None and str(val).strip() != ""
    ]
    if len(provided_sources) != 1:
        raise RuntimeError(
            f"Exactly one companion bundle source must be provided, got {provided_sources}"
        )

    source_kind = provided_sources[0]
    norm_expected_sha: Optional[str] = None
    if expected_bundle_sha256 is not None and expected_bundle_sha256.strip():
        norm_expected_sha = expected_bundle_sha256.strip().lower()
        if not _is_hex_sha256(norm_expected_sha):
            raise RuntimeError(
                f"Invalid expected companion bundle SHA-256: {expected_bundle_sha256!r}"
            )
    elif require_checksum_for_remote and source_kind in ("bundle_url", "artifact_run_id"):
        raise RuntimeError(
            f"Missing required expected bundle SHA-256 for remote companion source {source_kind!r}"
        )

    with tempfile.TemporaryDirectory(prefix="nf_install_companion_") as tmp_dir:
        tmp_path = Path(tmp_dir).resolve()
        staged_root: Path
        installed_archive_sha: Optional[str] = None
        outer_wrapper_sha: Optional[str] = None

        if source_kind == "bundle_dir":
            staged_root = Path(bundle_dir).resolve()  # type: ignore[arg-type]
            if not staged_root.is_dir():
                raise RuntimeError(f"Companion bundle directory not found: {staged_root}")
        else:
            if source_kind == "bundle_archive":
                archive_file = Path(bundle_archive).resolve()  # type: ignore[arg-type]
                if not archive_file.is_file():
                    raise RuntimeError(f"Companion archive not found: {archive_file}")
            elif source_kind == "bundle_url":
                url_str = str(bundle_url).strip()
                url_token = _resolve_token_for_url(
                    url_str,
                    github_repo=github_repo,
                    token_env_var=token_env_var,
                    require_token_if_github_api=False,
                )
                raw_bytes = _download_allowlisted_bytes(
                    url_str,
                    allowed_hosts=allowed_hosts,
                    github_repo=github_repo,
                    token=url_token,
                    token_source_is_github=(
                        url_token is not None and _is_valid_github_api_url(url_str, github_repo)
                    ),
                    allow_actions_storage_redirects=False,
                )
                archive_file = tmp_path / "companion_bundle.zip"
                archive_file.write_bytes(raw_bytes)
            else:
                run_id_str = str(artifact_run_id).strip()
                if not re.fullmatch(r"[0-9]+", run_id_str):
                    raise RuntimeError(f"Invalid GitHub Actions run ID: {run_id_str!r}")
                if not github_repo or not _GITHUB_REPO_RE.fullmatch(github_repo.strip()):
                    raise RuntimeError(
                        "github_repo ('owner/repo') is required for artifact_run_id download."
                    )
                repo_norm = github_repo.strip()
                art_name_q = urllib.parse.quote(artifact_name.strip(), safe="")
                list_url = (
                    f"https://api.github.com/repos/{repo_norm}/actions/runs/"
                    f"{run_id_str}/artifacts?name={art_name_q}&per_page=100"
                )
                gh_token = _resolve_token_for_url(
                    list_url,
                    github_repo=repo_norm,
                    token_env_var=token_env_var,
                    require_token_if_github_api=True,
                )
                listing_bytes = _download_allowlisted_bytes(
                    list_url,
                    allowed_hosts=None,
                    github_repo=repo_norm,
                    token=gh_token,
                    token_source_is_github=True,
                    allow_actions_storage_redirects=False,
                    accept="application/vnd.github+json",
                )
                listing = json.loads(listing_bytes.decode("utf-8"))
                candidates = [
                    item
                    for item in listing.get("artifacts", [])
                    if isinstance(item, dict)
                    and item.get("name") == artifact_name.strip()
                    and not item.get("expired", False)
                ]
                if len(candidates) != 1:
                    raise RuntimeError(
                        f"Expected exactly 1 non-expired artifact named {artifact_name!r} "
                        f"in run {run_id_str}, found {len(candidates)}"
                    )
                cand = candidates[0]
                dl_url = str(cand.get("archive_download_url") or "")
                if not _is_valid_github_api_url(dl_url, repo_norm):
                    raise RuntimeError(
                        f"Invalid archive_download_url returned for artifact {artifact_name!r}: {dl_url!r}"
                    )
                raw_bytes = _download_allowlisted_bytes(
                    dl_url,
                    allowed_hosts=None,
                    github_repo=repo_norm,
                    token=gh_token,
                    token_source_is_github=True,
                    allow_actions_storage_redirects=True,
                    accept="application/vnd.github+json",
                )
                archive_file = tmp_path / "companion_bundle.zip"
                archive_file.write_bytes(raw_bytes)
                api_digest = cand.get("digest")
                if isinstance(api_digest, str) and api_digest.strip():
                    digest_val = api_digest.strip().lower()
                    if not digest_val.startswith("sha256:") or not _is_hex_sha256(digest_val[7:]):
                        raise RuntimeError(f"Invalid GitHub artifact digest format: {api_digest!r}")
                    actual_outer = _sha256_file(archive_file).lower()
                    if actual_outer != digest_val[7:]:
                        raise RuntimeError(
                            f"Downloaded GitHub Actions artifact digest mismatch: "
                            f"{actual_outer} != {digest_val[7:]}"
                        )

            staged_root = (tmp_path / "extracted").resolve()
            installed_archive_sha, outer_wrapper_sha = _unpack_and_verify_companion_archive(
                archive_file,
                staged_root,
                norm_expected_sha,
                allow_actions_zip_wrapper=(source_kind in ("artifact_run_id", "bundle_archive")),
            )

        sums_path = staged_root / "COMPANION_SHA256SUMS.txt"
        sums_map = _parse_sha256_sums_file(sums_path)

        manifest_path = staged_root / "COMPANION_BUNDLE_MANIFEST.json"
        if manifest_path.is_file():
            bundle_manifest = _read_json_dict(manifest_path, "COMPANION_BUNDLE_MANIFEST.json")
            _verify_companion_bundle_manifest(bundle_manifest, sums_map, resolved_root)

        copied_files: List[str] = []
        for raw_rel, expected_sha in sums_map.items():
            rel_posix = raw_rel.strip().replace("\\", "/")
            if (
                not rel_posix
                or rel_posix.startswith("/")
                or re.match(r"^[A-Za-z]:", rel_posix)
                or ".." in Path(rel_posix).parts
            ):
                raise RuntimeError(f"Unsafe companion checksum path rejected: {raw_rel!r}")
            if not any(rel_posix.startswith(p) for p in _COMPANION_ALLOWED_PREFIXES):
                raise RuntimeError(f"Disallowed companion destination prefix: {rel_posix!r}")

            raw_src = staged_root / rel_posix
            if _has_symlink_ancestor(raw_src, staged_root):
                raise RuntimeError(f"Symlink companion source rejected: {raw_src}")
            src = raw_src.resolve()
            if not src.is_relative_to(staged_root) or not src.is_file():
                raise RuntimeError(f"Missing companion file listed in checksums: {rel_posix!r}")
            actual_sha = _sha256_file(src).lower()
            if actual_sha != expected_sha.lower():
                raise RuntimeError(
                    f"Companion file SHA-256 mismatch for {rel_posix}: "
                    f"{actual_sha} != {expected_sha}"
                )

            if rel_posix in SIDECAR_MANIFEST_MAPPINGS:
                tracked_manifest_path = resolved_root / SIDECAR_MANIFEST_MAPPINGS[rel_posix]
                if tracked_manifest_path.is_file():
                    tracked_sidecar_sha = _sha256_file(tracked_manifest_path).lower()
                    if actual_sha != tracked_sidecar_sha:
                        raise RuntimeError(
                            f"Companion sidecar manifest {rel_posix} does not match tracked manifest "
                            f"{SIDECAR_MANIFEST_MAPPINGS[rel_posix]} ({actual_sha} != {tracked_sidecar_sha})"
                        )

            if rel_posix.startswith("reports/"):
                tracked_dst = (resolved_root / rel_posix).resolve()
                if not tracked_dst.is_relative_to(resolved_root) or not tracked_dst.is_file():
                    raise RuntimeError(
                        f"Untracked reports/ path rejected from companion bundle: {rel_posix!r}"
                    )
                tracked_sha = _sha256_file(tracked_dst).lower()
                if actual_sha != tracked_sha:
                    raise RuntimeError(
                        f"Companion file {rel_posix} does not match tracked file at HEAD "
                        f"({actual_sha} != {tracked_sha})"
                    )
                continue

            raw_dst = resolved_runtime / rel_posix
            if _has_symlink_ancestor(raw_dst, resolved_runtime):
                raise RuntimeError(f"Symlink companion destination rejected: {raw_dst}")
            dst = raw_dst.resolve()
            if not dst.is_relative_to(resolved_runtime):
                raise RuntimeError(f"Companion destination escapes runtime root: {dst}")
            if (
                rel_posix.startswith("data/demo/")
                and dst.is_file()
                and resolved_runtime == resolved_root
            ):
                tracked_sha = _sha256_file(dst).lower()
                if actual_sha != tracked_sha:
                    raise RuntimeError(
                        f"Companion file {rel_posix} does not match tracked file at HEAD "
                        f"({actual_sha} != {tracked_sha})"
                    )
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied_files.append(rel_posix)

        summary = (
            verify_companion_artifacts(root=resolved_root)
            if runtime_dir is None
            else verify_companion_artifacts(root=resolved_root, runtime_dir=resolved_runtime)
        )
        if summary["overall_status"] != "READY":
            raise RuntimeError(
                "Installed companion bundle failed verification against tracked manifests: "
                f"ready_models={summary['ready_models']}, demo_ready={summary['demo_ready']}"
            )

        return {
            "install_status": "READY",
            "source_kind": source_kind,
            "runtime_dir": str(resolved_runtime),
            "archive_sha256": installed_archive_sha,
            "outer_wrapper_sha256": outer_wrapper_sha,
            "verified_checksum_entries": len(sums_map),
            "copied_file_count": len(copied_files),
            "summary": summary,
        }


def _find_free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http_json(
    url: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 15.0,
) -> Tuple[int, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req_headers = {"Accept": "application/json"}
    if data is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - 127.0.0.1 only
        body = resp.read().decode("utf-8")
        return int(resp.status), json.loads(body)


def _start_api_process(
    resolved_root: Path,
    run_api_script: Path,
    db_path: Path,
    log_path: Path,
    env: Dict[str, str],
) -> Tuple[subprocess.Popen[str], str]:
    """Start loopback FastAPI on a free port with file-backed logs (no pipe deadlock)."""
    last_err: Optional[Exception] = None
    for _attempt in range(3):
        port = _find_free_loopback_port()
        base_url = f"http://127.0.0.1:{port}"
        log_fh = log_path.open("w", encoding="utf-8")
        try:
            proc = subprocess.Popen(  # noqa: S603 - explicit trusted local interpreter + script
                [
                    sys.executable,
                    str(run_api_script),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--db-path",
                    str(db_path),
                ],
                cwd=str(resolved_root),
                env=env,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                text=True,
            )
        finally:
            log_fh.close()

        deadline = time.monotonic() + 25.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                output = log_path.read_text(encoding="utf-8", errors="replace")
                last_err = RuntimeError(f"run_api.py exited early ({proc.returncode}): {output}")
                break
            try:
                status_code, _ = _http_json(f"{base_url}/api/v1/health", timeout=2.0)
                if status_code == 200:
                    return proc, base_url
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(0.25)
        else:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            last_err = RuntimeError("Timed out waiting for FastAPI /api/v1/health on 127.0.0.1.")

    assert last_err is not None
    raise last_err


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ACTION_COUNT_KEYS = ("NO_ACTION", "MONITOR", "INVESTIGATE", "ISOLATE_RECOMMENDED")


def _is_hex_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_HEX_RE.fullmatch(value))


def _is_strict_nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _read_json_dict(path: Path, label: str) -> Dict[str, Any]:
    return _read_json_snapshot(path, label)[0]


def _read_json_snapshot(path: Path, label: str) -> Tuple[Dict[str, Any], bytes]:
    if not path.is_file():
        raise RuntimeError(f"Missing required {label}: {path}")
    try:
        content = path.read_bytes()
        data = json.loads(content.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Failed to parse {label} ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{label} must be a JSON object: {path}")
    return data, content


def _parse_sha256_sums_file(sums_file: Path) -> Dict[str, str]:
    if not sums_file.is_file():
        raise RuntimeError(f"Checksums file not found: {sums_file}")
    sums: Dict[str, str] = {}
    for line_no, raw_line in enumerate(sums_file.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", line)
        if not match:
            raise RuntimeError(
                f"Malformed SHA-256 sums line {line_no} in {sums_file}: {raw_line!r}"
            )
        digest = match.group(1).lower()
        filename = match.group(2).strip()
        if not filename:
            raise RuntimeError(f"Empty filename on line {line_no} in {sums_file}")
        if filename in sums and sums[filename] != digest:
            raise RuntimeError(f"Conflicting checksum entries for {filename!r} in {sums_file}")
        sums[filename] = digest
    if not sums:
        raise RuntimeError(f"Checksums file contains no entries: {sums_file}")
    return sums


def _get_git_head_commit(resolved_root: Path) -> str:
    try:
        commit = subprocess.check_output(  # noqa: S603 - fixed local git command
            ["git", "rev-parse", "HEAD"],
            cwd=str(resolved_root),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception as exc:
        raise RuntimeError(
            f"Unable to determine git HEAD commit in {resolved_root} (fail-closed): {exc}"
        ) from exc
    normalized = commit.lower()
    if not _GIT_COMMIT_RE.fullmatch(normalized):
        raise RuntimeError(f"Invalid git HEAD commit hash {commit!r} (fail-closed).")
    return normalized


def _read_desktop_version(resolved_root: Path) -> str:
    pkg_path = resolved_root / "desktop/package.json"
    pkg = _read_json_dict(pkg_path, "desktop/package.json")
    version = pkg.get("version")
    if not isinstance(version, str) or not version.strip():
        raise RuntimeError(f"Missing valid 'version' in {pkg_path}")
    return version.strip()


def _resolve_manifest_preprocessor_sha256(tracked_manifest: Dict[str, Any]) -> Optional[str]:
    direct = tracked_manifest.get("preprocessor_artifact_sha256") or tracked_manifest.get(
        "preprocessor_sha256"
    )
    if isinstance(direct, str) and direct.strip():
        return direct.strip().lower()
    prep_prov = tracked_manifest.get("preprocessing_provenance")
    if isinstance(prep_prov, dict):
        nested = prep_prov.get("preprocessor_artifact_sha256")
        if isinstance(nested, str) and nested.strip():
            return nested.strip().lower()
    prov = tracked_manifest.get("provenance")
    if isinstance(prov, dict):
        prep = prov.get("preprocessor")
        if isinstance(prep, dict):
            nested = prep.get("artifact_sha256")
            if isinstance(nested, str) and nested.strip():
                return nested.strip().lower()
    return None


def _is_windows_pid_alive(pid: int) -> bool:
    """Return True if a Windows OS process with `pid` is still active."""
    if pid <= 0 or os.name != "nt":
        return False
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    process_query_limited_information = 0x1000
    still_active = 259
    handle = kernel32.OpenProcess(process_query_limited_information, False, int(pid))
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong(0)
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return int(exit_code.value) == still_active
    finally:
        kernel32.CloseHandle(handle)


def _is_loopback_port_open(port: int) -> bool:
    if port <= 0:
        return False
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=0.3):
            return True
    except OSError:
        return False


def _request_windows_graceful_close(desktop_pid: int) -> str:
    """Send WM_CLOSE only to visible Tauri application window(s) owned by `desktop_pid`."""
    if os.name != "nt":
        return "unsupported"
    from ctypes import wintypes

    user32 = ctypes.windll.user32  # type: ignore[attr-defined]
    wm_close = 0x0010
    enum_cb_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [enum_cb_type, wintypes.LPARAM]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

    tauri_hwnds: List[int] = []
    visible_hwnds: List[int] = []

    def _on_window(hwnd: int, _lparam: int) -> bool:
        owner_pid = wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
        if int(owner_pid.value) == int(desktop_pid):
            cls_buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls_buf, 256)
            cls_name = cls_buf.value
            if cls_name == "Tauri Window":
                tauri_hwnds.append(int(hwnd))
            elif user32.IsWindowVisible(hwnd) and cls_name != "Tao Thread Event Target":
                visible_hwnds.append(int(hwnd))
        return True

    callback = enum_cb_type(_on_window)
    user32.EnumWindows(callback, 0)
    targets = tauri_hwnds or visible_hwnds
    if targets:
        for hwnd in targets:
            user32.PostMessageW(hwnd, wm_close, 0, 0)
        return "wm_close"

    subprocess.run(  # noqa: S603 - explicit soft taskkill without /F
        ["taskkill", "/PID", str(int(desktop_pid))],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return "taskkill_soft"


def _terminate_pid_best_effort(pid: int) -> None:
    if pid <= 0 or os.name != "nt":
        return
    subprocess.run(  # noqa: S603 - best-effort cleanup of leaked process tree
        ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def verify_nsis_installer_e2e(
    installer_path: Path,
    root: Path = PROJECT_ROOT,
    sums_file: Optional[Path] = None,
    compiled_exe_path: Optional[Path] = None,
    *,
    runtime_dir: Optional[Path] = None,
    pass_repo_root_env: bool = True,
    launch_installed_app: bool = True,
    backend_verifier: Optional[Callable[..., Dict[str, Any]]] = None,
    standalone_embedded: bool = False,
    expected_sidecar_sha256: Optional[str] = None,
    verify_restart: Optional[bool] = None,
) -> Dict[str, Any]:
    """Verify NSIS clean install, exe SHA-256 parity, live installed app launch & zero-orphan uninstall."""
    resolved_root = Path(root).resolve()
    effective_verify_restart = standalone_embedded if verify_restart is None else verify_restart
    if standalone_embedded:
        pass_repo_root_env = False
    installer = Path(installer_path)
    if not installer.is_file():
        raise RuntimeError(f"NSIS installer not found: {installer}")
    installer_size = installer.stat().st_size
    if installer_size < 1_000_000:
        raise RuntimeError(
            f"NSIS installer size too small ({installer_size} bytes < 1,000,000): {installer}"
        )
    installer_sha256 = _sha256_file(installer).lower()

    sums_file_verified = False
    if sums_file is not None:
        sums_map = _parse_sha256_sums_file(Path(sums_file))
        expected_installer_sha = sums_map.get(installer.name)
        if expected_installer_sha is None:
            raise RuntimeError(
                f"Installer {installer.name!r} missing from checksums file {sums_file}"
            )
        if expected_installer_sha != installer_sha256:
            raise RuntimeError(
                f"Installer SHA-256 mismatch against {sums_file}: "
                f"expected {expected_installer_sha}, got {installer_sha256}"
            )
        sums_file_verified = True

    if os.name != "nt":
        raise RuntimeError(
            "Clean Windows NSIS E2E verification requires Windows (os.name == 'nt')."
        )

    resolved_compiled: Optional[Path] = None
    if compiled_exe_path is not None:
        resolved_compiled = Path(compiled_exe_path)
        if not resolved_compiled.is_file():
            raise RuntimeError(f"Compiled desktop executable not found: {resolved_compiled}")
    else:
        default_compiled = (
            resolved_root / "desktop/src-tauri/target/release/netflow-sentinel-desktop.exe"
        )
        if default_compiled.is_file():
            resolved_compiled = default_compiled

    verifier_result: Optional[Dict[str, Any]] = None
    backend_port: Optional[int] = None
    graceful_close_method: Optional[str] = None
    frontend_ready_models: List[str] = []

    with tempfile.TemporaryDirectory(prefix="nf_nsis_", ignore_cleanup_errors=True) as tmp_dir:
        tmp_root = Path(tmp_dir)
        install_dir = tmp_root / "CleanInstall"
        install_proc = subprocess.run(  # noqa: S603 - explicit local NSIS installer binary
            [str(installer.resolve()), "/S", "/NS", f"/D={install_dir}"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if install_proc.returncode != 0:
            raise RuntimeError(
                f"NSIS silent install failed (exit={install_proc.returncode}): "
                f"{install_proc.stderr or install_proc.stdout}"
            )

        installed_exe = install_dir / "netflow-sentinel-desktop.exe"
        uninstaller_exe = install_dir / "uninstall.exe"
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if (
                installed_exe.is_file()
                and installed_exe.stat().st_size >= 1_000_000
                and uninstaller_exe.is_file()
                and uninstaller_exe.stat().st_size > 0
            ):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(
                f"NSIS clean install did not materialize expected executables within 15s in {install_dir}"
            )

        installed_bytes = installed_exe.read_bytes()
        installed_exe_sha256 = hashlib.sha256(installed_bytes).hexdigest().lower()
        compiled_exe_sha256: Optional[str] = None
        normalized_compiled_exe_sha256: Optional[str] = None
        compiled_exe_sha256_match: Optional[bool] = None
        exe_parity_mode: Optional[str] = None
        if resolved_compiled is not None:
            compiled_bytes = resolved_compiled.read_bytes()
            compiled_exe_sha256 = hashlib.sha256(compiled_bytes).hexdigest().lower()
            if installed_exe_sha256 == compiled_exe_sha256:
                compiled_exe_sha256_match = True
                exe_parity_mode = "exact_sha256"
                normalized_compiled_exe_sha256 = compiled_exe_sha256
            elif (
                len(compiled_bytes) == len(installed_bytes)
                and compiled_bytes.count(_TAURI_BUNDLE_MARKER_UNK) == 1
                and installed_bytes.count(_TAURI_BUNDLE_MARKER_NSS) == 1
            ):
                normalized_bytes = compiled_bytes.replace(
                    _TAURI_BUNDLE_MARKER_UNK,
                    _TAURI_BUNDLE_MARKER_NSS,
                    1,
                )
                normalized_compiled_exe_sha256 = (
                    hashlib.sha256(normalized_bytes).hexdigest().lower()
                )
                compiled_exe_sha256_match = installed_exe_sha256 == normalized_compiled_exe_sha256
                exe_parity_mode = (
                    "tauri_nsis_bundle_marker_normalized"
                    if compiled_exe_sha256_match
                    else "mismatch"
                )
            else:
                compiled_exe_sha256_match = False
                exe_parity_mode = "mismatch"

            if not compiled_exe_sha256_match:
                raise RuntimeError(
                    "Installed desktop executable SHA-256 mismatch vs compiled target/release exe: "
                    f"{installed_exe_sha256} != {compiled_exe_sha256}"
                )

        if not launch_installed_app:
            raise RuntimeError(
                "Installed desktop launch verification cannot be disabled (fail-closed)."
            )

        standalone_layout_info: Optional[Dict[str, Any]] = None
        if standalone_embedded:
            standalone_layout_info = verify_installed_standalone_layout(
                install_dir,
                expected_sidecar_sha256=expected_sidecar_sha256,
            )

        telemetry_path = tmp_root / "desktop_telemetry.json"
        wv2_dir = tmp_root / "webview2_user_data"
        desktop_db = tmp_root / "User AppData" / "installed_desktop.db"
        isolated_runtime_dir = (
            Path(runtime_dir).resolve()
            if runtime_dir is not None
            else (tmp_root / "User AppData").resolve()
        )
        isolated_runtime_dir.mkdir(parents=True, exist_ok=True)
        e2e_session_token = secrets.token_hex(32)
        auth_headers = {"X-Sentinel-Session-Token": e2e_session_token}
        launch_env = os.environ.copy()
        if pass_repo_root_env:
            launch_env["NETWORK_ANOMALY_REPO_ROOT"] = str(resolved_root)
        else:
            launch_env.pop("NETWORK_ANOMALY_REPO_ROOT", None)
        launch_env.pop("NETWORK_ANOMALY_RESOURCE_DIR", None)
        launch_env.pop("NETWORK_ANOMALY_ARTIFACTS_DIR", None)
        launch_env.pop("NETWORK_ANOMALY_DEMO_DIR", None)
        launch_env.pop("NETWORK_ANOMALY_SIDECAR_EXE", None)
        if standalone_embedded:
            launch_env.pop("NETWORK_ANOMALY_PYTHON", None)
            launch_env.pop("PYTHONPATH", None)
            launch_env.pop("PYTHONHOME", None)
            launch_env.pop("VIRTUAL_ENV", None)
            launch_env.pop("CONDA_PREFIX", None)
            win_root = os.environ.get("SystemRoot", r"C:\Windows")
            launch_env["PATH"] = ";".join(
                [
                    str(Path(win_root) / "System32"),
                    win_root,
                    str(Path(win_root) / "System32" / "Wbem"),
                ]
            )
            launch_env["NETWORK_ANOMALY_RUNTIME_DIR"] = str(isolated_runtime_dir)
        else:
            if runtime_dir is not None:
                launch_env["NETWORK_ANOMALY_RUNTIME_DIR"] = str(isolated_runtime_dir)
            launch_env["NETWORK_ANOMALY_PYTHON"] = sys.executable
        launch_env["NETWORK_ANOMALY_DB_PATH"] = str(desktop_db)
        launch_env["NETWORK_ANOMALY_BACKEND_PORT"] = "0"
        launch_env["NETWORK_ANOMALY_API_TOKEN"] = e2e_session_token
        launch_env["NETWORK_ANOMALY_DESKTOP_TELEMETRY_FILE"] = str(telemetry_path)
        launch_env["WEBVIEW2_USER_DATA_FOLDER"] = str(wv2_dir)

        startup_wait_s = 130.0 if standalone_embedded else 45.0
        desktop_proc = subprocess.Popen(  # noqa: S603 - explicit installed NSIS binary
            [str(installed_exe)],
            cwd=str(install_dir),
            env=launch_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        observed_backend_pid: Optional[int] = None
        backend_base_url: Optional[str] = None
        try:
            wait_deadline = time.monotonic() + startup_wait_s
            telemetry_data: Optional[Dict[str, Any]] = None
            while time.monotonic() < wait_deadline:
                if desktop_proc.poll() is not None:
                    raise RuntimeError(
                        f"Installed desktop application exited prematurely ({desktop_proc.returncode})."
                    )
                if telemetry_path.is_file():
                    try:
                        parsed_tel = json.loads(telemetry_path.read_text(encoding="utf-8"))
                    except Exception:
                        parsed_tel = None
                    if (
                        isinstance(parsed_tel, dict)
                        and parsed_tel.get("frontend_connected") is True
                    ):
                        b_status = parsed_tel.get("backend_status") or {}
                        b_url = str(b_status.get("base_url") or "")
                        b_pid = b_status.get("pid")
                        if (
                            parsed_tel.get("desktop_pid") == desktop_proc.pid
                            and b_status.get("running") is True
                            and b_status.get("managed_child") is True
                            and isinstance(b_pid, int)
                            and b_pid > 0
                            and b_url.startswith("http://127.0.0.1:")
                        ):
                            try:
                                h_code, h_json = _http_json(
                                    f"{b_url}/api/v1/health",
                                    headers=auth_headers,
                                    timeout=2.0,
                                )
                                if h_code == 200 and isinstance(h_json, dict):
                                    telemetry_data = parsed_tel
                                    observed_backend_pid = b_pid
                                    backend_base_url = b_url
                                    backend_port = int(
                                        b_status.get("port") or b_url.rsplit(":", 1)[1]
                                    )
                                    break
                            except (urllib.error.URLError, TimeoutError, OSError):
                                pass
                time.sleep(0.25)

            if telemetry_data is None or backend_base_url is None or observed_backend_pid is None:
                raise RuntimeError(
                    "Installed desktop application did not report WebView2 frontend connection + "
                    f"loopback FastAPI readiness within {int(startup_wait_s)}s."
                )
            if not _is_windows_pid_alive(observed_backend_pid):
                raise RuntimeError(
                    f"Reported FastAPI backend child PID {observed_backend_pid} is not alive."
                )
            if standalone_embedded:
                b_status_tel = telemetry_data.get("backend_status") or {}
                expected_sidecar = (install_dir / "netflow-sentinel-backend.exe").resolve()
                actual_backend_exe = Path(
                    str(b_status_tel.get("python_executable") or "")
                ).resolve()
                if (
                    b_status_tel.get("backend_mode") != "embedded_sidecar"
                    or actual_backend_exe != expected_sidecar
                ):
                    raise RuntimeError(
                        "Standalone desktop must launch embedded sidecar inside install_dir: "
                        f"mode={b_status_tel.get('backend_mode')!r}, exe={actual_backend_exe}"
                    )
            # Confirm unauthenticated /api/v1/models fails closed with HTTP 401 when session token is active
            try:
                _http_json(f"{backend_base_url}/api/v1/models", timeout=5.0)
                raise RuntimeError(
                    "Unauthenticated /api/v1/models request succeeded despite session token enforcement!"
                )
            except urllib.error.HTTPError as http_err:
                if http_err.code != 401:
                    raise RuntimeError(
                        f"Expected HTTP 401 for unauthenticated /api/v1/models, got {http_err.code}"
                    ) from http_err

            summary_block = telemetry_data.get("summary") or {}
            frontend_ready_models = list(summary_block.get("ready_models") or [])

            if backend_verifier is not None:
                try:
                    verifier_result = backend_verifier(
                        backend_base_url,
                        auth_headers,
                        install_dir if standalone_embedded else None,
                    )
                except TypeError:
                    try:
                        verifier_result = backend_verifier(backend_base_url, auth_headers)
                    except TypeError:
                        verifier_result = backend_verifier(backend_base_url)
            else:
                m_code, m_payload = _http_json(
                    f"{backend_base_url}/api/v1/models",
                    headers=auth_headers,
                    timeout=10.0,
                )
                if m_code != 200 or not isinstance(m_payload, list):
                    raise RuntimeError(
                        f"Installed desktop /api/v1/models probe failed: status={m_code}"
                    )

            graceful_close_method = _request_windows_graceful_close(desktop_proc.pid)
            try:
                desktop_proc.wait(timeout=15)
            except subprocess.TimeoutExpired as exc:
                desktop_proc.kill()
                desktop_proc.wait(timeout=5)
                raise RuntimeError(
                    "Installed desktop application did not exit cleanly within 15s after close request."
                ) from exc

            orphan_deadline = time.monotonic() + 5.0
            while time.monotonic() < orphan_deadline:
                if not _is_windows_pid_alive(observed_backend_pid):
                    break
                time.sleep(0.15)
            else:
                raise RuntimeError(
                    f"Orphan Python backend process detected after desktop exit (pid={observed_backend_pid})."
                )
            if backend_port is not None and _is_loopback_port_open(backend_port):
                raise RuntimeError(
                    f"FastAPI loopback port {backend_port} remained open after desktop exit."
                )
        finally:
            if desktop_proc.poll() is None:
                desktop_proc.kill()
                desktop_proc.wait(timeout=5)
            if observed_backend_pid is not None and _is_windows_pid_alive(observed_backend_pid):
                _terminate_pid_best_effort(observed_backend_pid)

        restart_persistence_verified = False
        if effective_verify_restart:
            telemetry_path.unlink(missing_ok=True)
            restart_token = secrets.token_hex(32)
            restart_headers = {"X-Sentinel-Session-Token": restart_token}
            restart_env = dict(launch_env)
            restart_env["NETWORK_ANOMALY_API_TOKEN"] = restart_token
            restart_proc = subprocess.Popen(  # noqa: S603 - explicit installed NSIS binary restart
                [str(installed_exe)],
                cwd=str(install_dir),
                env=restart_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            restart_backend_pid: Optional[int] = None
            restart_backend_url: Optional[str] = None
            restart_port: Optional[int] = None
            try:
                r_deadline = time.monotonic() + startup_wait_s
                while time.monotonic() < r_deadline:
                    if restart_proc.poll() is not None:
                        raise RuntimeError(
                            f"Restarted desktop app exited prematurely ({restart_proc.returncode})."
                        )
                    if telemetry_path.is_file():
                        try:
                            r_tel = json.loads(telemetry_path.read_text(encoding="utf-8"))
                        except Exception:
                            r_tel = None
                        if (
                            isinstance(r_tel, dict)
                            and r_tel.get("desktop_pid") == restart_proc.pid
                            and r_tel.get("frontend_connected") is True
                        ):
                            rb = r_tel.get("backend_status") or {}
                            rb_url = str(rb.get("base_url") or "")
                            rb_pid = rb.get("pid")
                            if (
                                rb.get("running") is True
                                and isinstance(rb_pid, int)
                                and rb_pid > 0
                                and rb_url.startswith("http://127.0.0.1:")
                            ):
                                restart_backend_pid = rb_pid
                                restart_backend_url = rb_url
                                restart_port = int(rb.get("port") or rb_url.rsplit(":", 1)[1])
                                break
                    time.sleep(0.25)
                if restart_backend_url is None or restart_backend_pid is None:
                    raise RuntimeError("Restarted standalone desktop failed to reconnect backend.")
                sim_code, sim_hist = _http_json(
                    f"{restart_backend_url}/api/v1/security/simulations?limit=10&offset=0",
                    headers=restart_headers,
                    timeout=10.0,
                )
                if sim_code != 200 or not isinstance(sim_hist, dict):
                    raise RuntimeError("Restarted standalone backend failed SQLite history check.")
                if backend_verifier is not None and int(sim_hist.get("total", 0)) < 4:
                    raise RuntimeError(
                        f"Restart persistence check expected >= 4 persisted simulations, got {sim_hist}"
                    )
                _request_windows_graceful_close(restart_proc.pid)
                restart_proc.wait(timeout=15)
                r_orphan_deadline = time.monotonic() + 5.0
                while time.monotonic() < r_orphan_deadline:
                    if not _is_windows_pid_alive(restart_backend_pid):
                        break
                    time.sleep(0.15)
                else:
                    raise RuntimeError(
                        f"Orphan backend process detected after restart close (pid={restart_backend_pid})."
                    )
                if restart_port is not None and _is_loopback_port_open(restart_port):
                    raise RuntimeError(
                        f"Backend port {restart_port} remained open after restart close."
                    )
                restart_persistence_verified = True
            finally:
                if restart_proc.poll() is None:
                    restart_proc.kill()
                    restart_proc.wait(timeout=5)
                if restart_backend_pid is not None and _is_windows_pid_alive(restart_backend_pid):
                    _terminate_pid_best_effort(restart_backend_pid)

        uninstall_proc = subprocess.run(  # noqa: S603 - explicit NSIS uninstaller in temp dir
            [str(uninstaller_exe), "/S"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if uninstall_proc.returncode != 0:
            raise RuntimeError(
                f"NSIS silent uninstall failed (exit={uninstall_proc.returncode}): "
                f"{uninstall_proc.stderr or uninstall_proc.stdout}"
            )
        cleanup_deadline = time.monotonic() + 20.0
        while time.monotonic() < cleanup_deadline:
            if not any(path.is_file() for path in install_dir.rglob("*")):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"NSIS uninstall left installed files behind in {install_dir}")

    nsis_summary: Dict[str, Any] = {
        "status": "PASS",
        "installer_filename": installer.name,
        "installer_sha256": installer_sha256,
        "installer_size_bytes": installer_size,
        "sums_file_verified": sums_file_verified,
        "installed_exe_sha256": installed_exe_sha256,
        "compiled_exe_sha256": compiled_exe_sha256,
        "normalized_compiled_exe_sha256": normalized_compiled_exe_sha256,
        "compiled_exe_sha256_match": compiled_exe_sha256_match,
        "exe_parity_mode": exe_parity_mode,
        "uninstaller_verified": True,
        "clean_install_verified": True,
        "installed_app_launched": True,
        "installed_exe_path_verified": True,
        "frontend_webview_connected": True,
        "frontend_ready_models": frontend_ready_models,
        "bundled_resources_mode": not pass_repo_root_env,
        "repo_root_env_passed": bool(pass_repo_root_env),
        "runtime_dir_isolated": (runtime_dir is not None) or standalone_embedded,
        "backend_spawned_on_loopback": True,
        "backend_port": backend_port,
        "graceful_close_verified": True,
        "graceful_close_method": graceful_close_method,
        "zero_orphan_processes_verified": True,
        "uninstall_cleanup_verified": True,
        "standalone_embedded_mode": standalone_embedded,
        "sidecar_exe_verified": bool(standalone_layout_info),
        "sidecar_sha256": (
            standalone_layout_info.get("sidecar_sha256") if standalone_layout_info else None
        ),
        "sidecar_size_bytes": (
            standalone_layout_info.get("sidecar_size_bytes") if standalone_layout_info else None
        ),
        "system_python_used": not standalone_embedded,
        "external_companion_used": (not standalone_embedded) and (runtime_dir is not None),
        "restart_persistence_verified": restart_persistence_verified,
        "export_verified": bool(
            isinstance(verifier_result, dict) and verifier_result.get("export_verified")
        ),
        "frontend_interactive_gui_clicks": (
            "NOT VERIFIED (WebView2 mounted and Svelte onMount IPC handshake verified; "
            "manual/UIA button clicks across UI tabs not automated)"
        ),
    }
    if verifier_result is not None:
        nsis_summary["_backend_verifier_result"] = verifier_result
    return nsis_summary


def _execute_four_model_api_suite(
    base_url: str,
    resolved_root: Path,
    summary: Dict[str, Any],
    *,
    runtime_dir: Optional[Path] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Execute live 4-model analyze, evaluate, OOD abstention, and Issue #27 dry-run suite."""
    port = int(base_url.rsplit(":", 1)[1])
    demo_root = Path(runtime_dir).resolve() if runtime_dir is not None else resolved_root
    demo_flows = demo_root / "data/demo/demo_flows.csv"
    demo_labels = demo_root / "data/demo/demo_labels.csv"

    session_auth_fail_closed = False
    if headers and headers.get("X-Sentinel-Session-Token"):
        for label, bad_headers in (
            ("missing_token", {}),
            ("invalid_token", {"X-Sentinel-Session-Token": "invalid-" + "0" * 56}),
        ):
            try:
                _http_json(f"{base_url}/api/v1/models", headers=bad_headers, timeout=5.0)
            except urllib.error.HTTPError as exc:
                if exc.code not in (401, 403):
                    raise RuntimeError(
                        f"Session auth check ({label}) expected HTTP 401/403, got {exc.code}"
                    ) from exc
            else:
                raise RuntimeError(
                    f"SECURITY REGRESSION: Loopback API accepted unauthenticated request ({label})!"
                )
        session_auth_fail_closed = True

    _, models_payload = _http_json(f"{base_url}/api/v1/models", headers=headers, timeout=10.0)
    models_by_key = {item["model_key"]: item for item in models_payload}
    for key in MODEL_SPECS:
        entry = models_by_key.get(key)
        if not entry or not entry.get("ready") or entry.get("status") != "READY":
            raise RuntimeError(f"Model {key!r} is not READY in /api/v1/models: {entry}")

    expected_flows_sha = summary["demo"]["data/demo/demo_flows.csv"]["sha256"]
    expected_labels_sha = summary["demo"]["data/demo/demo_labels.csv"]["sha256"]
    expected_prep_sha = summary["preprocessor"]["sha256"]

    per_model_results: Dict[str, Any] = {}
    for key in MODEL_SPECS:
        _, az = _http_json(
            f"{base_url}/api/v1/csv/analyze",
            method="POST",
            payload={
                "file_path": str(demo_flows),
                "model_name": key,
                "batch_size": 100,
                "create_incidents": False,
            },
            headers=headers,
            timeout=30.0,
        )
        if az.get("inference_mode") != "verified_model":
            raise RuntimeError(f"{key}: expected verified_model, got {az.get('inference_mode')}")
        if az.get("file_sha256") != expected_flows_sha:
            raise RuntimeError(
                f"{key}: analyze file_sha256 mismatch ({az.get('file_sha256')} != {expected_flows_sha})"
            )
        if az.get("preprocessor_sha256") != expected_prep_sha:
            raise RuntimeError(
                f"{key}: analyze preprocessor_sha256 mismatch ({az.get('preprocessor_sha256')} != {expected_prep_sha})"
            )
        gate = az.get("compatibility_gate") or {}
        expected_compat = "MODEL_VALIDATED" if key == "random_forest" else "RESEARCH_ONLY"
        expected_manifest_run_id = summary["models"][key].get("run_id")
        if (
            not isinstance(expected_manifest_run_id, str)
            or not expected_manifest_run_id.strip()
            or models_by_key[key].get("run_id") != expected_manifest_run_id
            or gate.get("model_identifier") != expected_manifest_run_id
        ):
            raise RuntimeError(
                f"{key}: manifest run_id mismatch across /api/v1/models and compatibility_gate "
                f"(expected={expected_manifest_run_id!r}, api_models={models_by_key[key].get('run_id')!r}, "
                f"gate={gate.get('model_identifier')!r})"
            )
        inference_run_id = az.get("run_id")
        if (
            not isinstance(inference_run_id, str)
            or not inference_run_id.startswith("inference-")
            or len(inference_run_id) <= len("inference-")
        ):
            raise RuntimeError(f"{key}: unexpected analyze inference run_id: {inference_run_id!r}")
        if (
            gate.get("source_id") not in ("source:nf-v3-canonical", "source:ait-nds-v2")
            or gate.get("provenance_verified") is not True
            or gate.get("compatibility_status") != expected_compat
        ):
            raise RuntimeError(f"{key}: unexpected compatibility_gate: {gate}")

        results = az.get("results") or []
        non_ood = [r for r in results if not r.get("is_ood_flagged")]
        ood_rows = [r for r in results if r.get("is_ood_flagged")]
        if (
            az.get("total_rows") != 200
            or (len(non_ood), len(ood_rows)) not in ((198, 2), (200, 0))
            or len(non_ood) + len(ood_rows) != 200
        ):
            raise RuntimeError(
                f"{key}: unexpected OOD split total={az.get('total_rows')}, "
                f"non_ood={len(non_ood)}, ood={len(ood_rows)}"
            )
        if key in ("random_forest", "xgboost"):
            if any(r.get("attack_probability") is None for r in non_ood):
                raise RuntimeError(f"{key}: missing attack_probability on non-OOD rows")
        else:
            if any(r.get("attack_probability") is not None for r in results):
                raise RuntimeError(f"{key}: unsupervised model leaked attack_probability")
            if any(r.get("raw_anomaly_score") is None for r in non_ood):
                raise RuntimeError(f"{key}: missing raw_anomaly_score on non-OOD rows")

        _, ev = _http_json(
            f"{base_url}/api/v1/csv/evaluate",
            method="POST",
            payload={"labels_path": str(demo_labels), "predictions": results},
            headers=headers,
            timeout=15.0,
        )
        if ev.get("labels_sha256") != expected_labels_sha:
            raise RuntimeError(
                f"{key}: evaluate labels_sha256 mismatch ({ev.get('labels_sha256')} != {expected_labels_sha})"
            )
        cm = ev["confusion_matrix"]
        if cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"] != len(non_ood) or ev.get(
            "abstained_rows"
        ) != len(ood_rows):
            raise RuntimeError(f"{key}: invalid confusion matrix coverage: {ev}")
        if key in ("random_forest", "xgboost") and (
            ev["f1"] < 0.99 or cm["tp"] != 100 or cm["tn"] != (len(non_ood) - 100)
        ):
            raise RuntimeError(f"{key}: unexpected supervised demo metrics: {ev}")
        if key == "isolation_forest" and (ev["f1"] < 0.80 or cm["tp"] < 80 or cm["tn"] < 80):
            raise RuntimeError(f"{key}: unexpected Isolation Forest demo metrics: {ev}")
        if key == "autoencoder" and (
            ev["f1"] < 0.15 or cm["tp"] < 10 or ev["false_positive_rate"] > 0.10
        ):
            raise RuntimeError(f"{key}: unexpected Autoencoder demo metrics: {ev}")

        _, sim = _http_json(
            f"{base_url}/api/v1/security/simulate-response",
            method="POST",
            payload={"analysis_id": az["analysis_id"], "dry_run": True},
            headers=headers,
            timeout=15.0,
        )
        if (
            sim.get("executed") is not False
            or sim.get("os_firewall_touched") is not False
            or sim.get("real_key_rotated") is not False
            or sim.get("provenance_verification") != "server_verified_analysis"
        ):
            raise RuntimeError(f"{key}: invalid Issue #27 dry-run provenance/flags: {sim}")

        ood_row_ids = {int(r["row_id"]) for r in ood_rows}
        for rec in sim.get("recommendations") or []:
            if int(rec["row_id"]) in ood_row_ids and (
                rec.get("containment_allowed") is not False
                or rec.get("action") == "ISOLATE_RECOMMENDED"
            ):
                raise RuntimeError(f"{key}: OOD row received containment: {rec}")

        action_counts = sim.get("action_counts") or {}
        rot_decision = (sim.get("key_rotation_simulation") or {}).get("decision")
        if key == "random_forest":
            if int(action_counts.get("ISOLATE_RECOMMENDED", 0)) <= 0:
                raise RuntimeError(f"{key}: expected ISOLATE_RECOMMENDED > 0, got {action_counts}")
            if rot_decision != "SIMULATED_ROTATION_RECOMMENDED":
                raise RuntimeError(
                    f"{key}: expected SIMULATED_ROTATION_RECOMMENDED, got {rot_decision}"
                )
        else:
            if (
                int(action_counts.get("ISOLATE_RECOMMENDED", 0)) != 0
                or rot_decision != "HOLD_RESEARCH_ONLY_MODEL"
            ):
                raise RuntimeError(
                    f"{key}: RESEARCH_ONLY model bypassed fail-closed gate: "
                    f"counts={action_counts}, rotation={rot_decision}"
                )

        per_model_results[key] = {
            "analysis_id": az["analysis_id"],
            "run_id": expected_manifest_run_id,
            "inference_run_id": inference_run_id,
            "artifact_sha256": summary["models"][key]["sha256"],
            "preprocessor_sha256": az.get("preprocessor_sha256") or expected_prep_sha,
            "source_csv_sha256": az.get("file_sha256") or expected_flows_sha,
            "labels_sha256": ev.get("labels_sha256") or expected_labels_sha,
            "compatibility_status": gate["compatibility_status"],
            "inference_mode": az["inference_mode"],
            "total_rows": az["total_rows"],
            "evaluated_rows": az["evaluated_rows"],
            "abstained_rows": az["abstained_rows"],
            "confusion_matrix": cm,
            "accuracy": ev["accuracy"],
            "precision": ev["precision"],
            "recall": ev["recall"],
            "f1": ev["f1"],
            "fpr": ev["false_positive_rate"],
            "prediction_coverage": ev["prediction_coverage"],
            "dry_run_simulation_id": sim["simulation_id"],
            "dry_run_provenance": sim["provenance_verification"],
            "dry_run_action_counts": action_counts,
            "dry_run_rotation_decision": rot_decision,
        }

    # Verify client-supplied spoofing without analysis_id fails closed
    _, spoof_check = _http_json(
        f"{base_url}/api/v1/security/simulate-response",
        method="POST",
        payload={
            "model_key": "xgboost",
            "inference_mode": "verified_model",
            "compatibility_gate": {
                "source_id": "source:nf-v3-canonical",
                "provenance_verified": True,
                "model_key": "xgboost",
                "eligible": True,
                "eligibility_status": "ELIGIBLE",
                "compatibility_status": "MODEL_VALIDATED",
            },
            "results": [
                {
                    "row_id": 1,
                    "row_index": 0,
                    "predicted_label": 1,
                    "predicted_class": "Attack",
                    "attack_probability": 0.99,
                    "raw_anomaly_score": 0.99,
                    "normalized_anomaly_score": 0.99,
                    "decision_threshold": 0.5,
                    "score_type": "attack_probability",
                    "score_direction": "higher_is_more_anomalous",
                    "risk_score": 99.0,
                    "risk_level": "CRITICAL",
                    "is_ood_flagged": False,
                }
            ],
            "dry_run": True,
        },
        headers=headers,
        timeout=15.0,
    )
    if (
        spoof_check.get("provenance_verification") != "client_supplied_unverified"
        or spoof_check["recommendations"][0]["action"] != "INVESTIGATE"
        or spoof_check["recommendations"][0]["containment_allowed"] is not False
        or spoof_check["key_rotation_simulation"]["decision"] != "HOLD_UNVERIFIED_PROVENANCE"
    ):
        raise RuntimeError(f"Unverified client payload failed fail-closed check: {spoof_check}")

    with tempfile.TemporaryDirectory(prefix="nf_export_e2e_") as exp_tmp:
        export_csv_path = Path(exp_tmp) / "User Exports" / "rf_standalone_export.csv"
        rf_entry = per_model_results["random_forest"]
        _, rf_az_full = _http_json(
            f"{base_url}/api/v1/csv/analyze",
            method="POST",
            payload={
                "file_path": str(demo_flows),
                "model_name": "random_forest",
                "batch_size": 100,
                "create_incidents": False,
            },
            headers=headers,
            timeout=30.0,
        )
        _, exp_resp = _http_json(
            f"{base_url}/api/v1/csv/export",
            method="POST",
            payload={
                "output_path": str(export_csv_path),
                "analysis_id": rf_az_full["analysis_id"],
                "source_csv_path": str(demo_flows),
                "model_key": "random_forest",
                "model_type": rf_az_full["model_type"],
                "run_id": rf_az_full["run_id"],
                "model_sha256": rf_entry["artifact_sha256"],
                "preprocessor_sha256": rf_entry["preprocessor_sha256"],
                "results": rf_az_full["results"],
                "evaluation": None,
            },
            headers=headers,
            timeout=15.0,
        )
        if (
            int(exp_resp.get("rows_exported", 0)) != 200
            or not Path(exp_resp["csv_path"]).is_file()
            or not Path(exp_resp["metadata_path"]).is_file()
        ):
            raise RuntimeError(f"CSV export E2E verification failed: {exp_resp}")

    return {
        "port": port,
        "models": per_model_results,
        "export_verified": True,
        "session_auth_fail_closed": session_auth_fail_closed,
        "client_spoof_fail_closed": {
            "provenance_verification": spoof_check["provenance_verification"],
            "critical_downgraded_action": spoof_check["recommendations"][0]["action"],
            "rotation_decision": spoof_check["key_rotation_simulation"]["decision"],
        },
    }


def _verify_github_runner_provenance(
    *,
    github_repo: str,
    github_run_id: str,
    source_commit: str,
    token_env_var: Optional[str] = None,
    require_in_progress: bool = True,
) -> Dict[str, Any]:
    """Query GitHub REST API to independently verify GitHub-hosted Windows runner identity."""
    repo_norm = (github_repo or "").strip()
    run_id_norm = str(github_run_id or "").strip()
    commit_norm = (source_commit or "").strip().lower()
    if not _GITHUB_REPO_RE.fullmatch(repo_norm):
        raise RuntimeError(
            f"REFUSED --clean-machine-e2e: Invalid GitHub repository slug {github_repo!r}."
        )
    if not run_id_norm.isdigit():
        raise RuntimeError(
            f"REFUSED --clean-machine-e2e: Invalid numeric GitHub workflow run ID {github_run_id!r}."
        )
    if not _GIT_COMMIT_RE.fullmatch(commit_norm):
        raise RuntimeError(
            f"REFUSED --clean-machine-e2e: Invalid 40-char source commit {source_commit!r}."
        )

    if require_in_progress:
        if os.environ.get("GITHUB_ACTIONS", "").strip().lower() != "true":
            raise RuntimeError(
                "REFUSED --clean-machine-e2e: Current process is not executing inside a verified "
                "GitHub Actions runner context."
            )
        env_run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
        if env_run_id and env_run_id != run_id_norm:
            raise RuntimeError(
                "REFUSED --clean-machine-e2e: Environment GITHUB_RUN_ID mismatch against "
                f"--github-run-id ({env_run_id!r} != {run_id_norm!r})."
            )

    run_url = f"https://api.github.com/repos/{repo_norm}/actions/runs/{run_id_norm}"
    token = _resolve_token_for_url(
        run_url,
        github_repo=repo_norm,
        token_env_var=token_env_var,
        require_token_if_github_api=True,
    )
    run_raw = _download_allowlisted_bytes(
        run_url,
        github_repo=repo_norm,
        token=token,
        token_source_is_github=True,
        accept="application/vnd.github+json",
    )
    run_data = json.loads(run_raw.decode("utf-8"))
    if not isinstance(run_data, dict):
        raise RuntimeError("GitHub Actions run API returned non-object payload.")
    if str(run_data.get("id", "")).strip() != run_id_norm:
        raise RuntimeError(
            f"GitHub Actions run ID mismatch: API={run_data.get('id')!r}, expected={run_id_norm!r}."
        )
    api_commit = str(run_data.get("head_sha") or "").strip().lower()
    if api_commit != commit_norm:
        raise RuntimeError(
            f"GitHub Actions run head_sha mismatch: API={api_commit!r} != HEAD={commit_norm!r}."
        )
    api_repo = str((run_data.get("repository") or {}).get("full_name") or "").strip().lower()
    if api_repo and api_repo != repo_norm.lower():
        raise RuntimeError(
            f"GitHub Actions repository mismatch: API={api_repo!r} != {repo_norm.lower()!r}."
        )
    if require_in_progress and str(run_data.get("status") or "").strip().lower() != "in_progress":
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: GitHub Actions run status must be 'in_progress' "
            f"(cannot reuse completed/historical workflow runs, got {run_data.get('status')!r})."
        )

    jobs_url = (
        f"https://api.github.com/repos/{repo_norm}/actions/runs/{run_id_norm}/jobs?per_page=100"
    )
    jobs_raw = _download_allowlisted_bytes(
        jobs_url,
        github_repo=repo_norm,
        token=token,
        token_source_is_github=True,
        accept="application/vnd.github+json",
    )
    jobs_payload = json.loads(jobs_raw.decode("utf-8"))
    jobs_list = jobs_payload.get("jobs") if isinstance(jobs_payload, dict) else None
    if not isinstance(jobs_list, list) or not jobs_list:
        raise RuntimeError(
            "GitHub Actions jobs API returned no jobs for clean-runner verification."
        )

    env_runner_name = os.environ.get("RUNNER_NAME", "").strip()
    matched_job: Optional[Dict[str, Any]] = None
    for job in jobs_list:
        if not isinstance(job, dict):
            continue
        job_status = str(job.get("status") or "").strip().lower()
        if require_in_progress and job_status != "in_progress":
            continue
        runner_name = str(job.get("runner_name") or "").strip()
        if not runner_name:
            continue
        if require_in_progress and env_runner_name and runner_name != env_runner_name:
            continue
        labels = [str(lbl).strip() for lbl in (job.get("labels") or []) if str(lbl).strip()]
        lower_labels = [lbl.lower() for lbl in labels]
        has_windows_label = any(lbl.startswith("windows") for lbl in lower_labels)
        is_hosted_runner = "self-hosted" not in lower_labels and (
            runner_name.startswith("Hosted Agent")
            or runner_name.startswith("GitHub Actions")
            or has_windows_label
        )
        if has_windows_label and is_hosted_runner:
            matched_job = job
            break

    if matched_job is None:
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: GitHub Actions API did not confirm an active "
            "GitHub-hosted Windows runner job for this run."
        )

    matched_labels = [
        str(lbl).strip() for lbl in (matched_job.get("labels") or []) if str(lbl).strip()
    ]
    return {
        "environment_tier": "github_hosted_windows_runner",
        "provenance_source": "github_actions_api",
        "workflow_run_id": run_id_norm,
        "run_attempt": run_data.get("run_attempt"),
        "github_repository": repo_norm,
        "workflow_path": run_data.get("path"),
        "runner_name": str(matched_job["runner_name"]).strip(),
        "runner_labels": matched_labels,
        "vm_provenance_ref": None,
        "vm_evidence_sha256": None,
    }


_VM_CHALLENGE_FORMAT = "netflow-sentinel-vm-challenge-v1"
_VM_TARGET_EVIDENCE_FORMAT = "netflow-sentinel-vm-target-evidence-v1"
_VM_WITNESS_FORMAT = "netflow-sentinel-vm-witness-v2"


def _canonical_vm_witness_payload(
    *,
    source_commit: str,
    installer_sha256: str,
    sidecar_sha256: str,
    vm_provenance_ref: str,
    observed_hostname: str,
    controller_hostname: str,
    issued_at_utc: str,
    trusted_authority_id: str,
    challenge_nonce: str,
    target_evidence_sha256: str,
) -> bytes:
    """Build canonical byte string signed by external VM attestation authority."""
    payload: Dict[str, Any] = {
        "challenge_nonce": challenge_nonce.lower(),
        "controller_hostname": controller_hostname.lower(),
        "environment_tier": "independent_windows_vm",
        "issued_at_utc": issued_at_utc,
        "installer_sha256": installer_sha256.lower(),
        "observed_hostname": observed_hostname,
        "sidecar_sha256": sidecar_sha256.lower(),
        "source_commit": source_commit.lower(),
        "target_evidence_sha256": target_evidence_sha256.lower(),
        "trusted_authority_id": trusted_authority_id,
        "vm_provenance_ref": vm_provenance_ref,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_utc_iso8601(raw: str, label: str) -> datetime:
    try:
        dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError("Timezone-aware UTC timestamp required")
        return dt.astimezone(timezone.utc)
    except ValueError as exc:
        raise RuntimeError(f"Invalid UTC ISO-8601 timestamp for {label}: {raw!r}") from exc


def _normalize_compiled_desktop_exe_hashes(
    compiled_exe_path: Path,
) -> Tuple[str, Optional[str]]:
    raw_bytes = compiled_exe_path.read_bytes()
    exact_sha = hashlib.sha256(raw_bytes).hexdigest().lower()
    normalized_sha: Optional[str] = None
    if raw_bytes.count(_TAURI_BUNDLE_MARKER_UNK) == 1:
        normalized_bytes = raw_bytes.replace(
            _TAURI_BUNDLE_MARKER_UNK,
            _TAURI_BUNDLE_MARKER_NSS,
            1,
        )
        normalized_sha = hashlib.sha256(normalized_bytes).hexdigest().lower()
    return exact_sha, normalized_sha


def _validate_target_probe(
    probe: Any,
    *,
    controller_hostname: Optional[str] = None,
    require_clean_target: bool = True,
) -> Tuple[str, bool]:
    if not isinstance(probe, dict):
        raise RuntimeError("Target evidence missing target_probe object.")
    observed_host = str(probe.get("observed_hostname") or "").strip()
    if not observed_host:
        raise RuntimeError("Target evidence target_probe missing observed_hostname.")
    same_host = bool(
        controller_hostname and observed_host.lower() == controller_hostname.strip().lower()
    )
    if require_clean_target:
        if probe.get("platform") != "win32":
            raise RuntimeError("REFUSED --clean-machine-e2e: Target evidence must report Windows.")
        if probe.get("git_dir_present") is not False:
            raise RuntimeError(
                f"REFUSED --clean-machine-e2e: Target reported .git present: {probe}"
            )
        if probe.get("dev_tools_absent") is not True or probe.get("found_dev_tools"):
            raise RuntimeError(
                f"REFUSED --clean-machine-e2e: Target reported developer tools present: {probe}"
            )
        if probe.get("found_standard_tool_dirs"):
            raise RuntimeError(
                f"REFUSED --clean-machine-e2e: Target reported standard developer tool directories: {probe}"
            )
        if probe.get("dev_models_tree_absent") is not True:
            raise RuntimeError(
                f"REFUSED --clean-machine-e2e: Target reported repository model tree present: {probe}"
            )
        if same_host:
            raise RuntimeError(
                "REFUSED --clean-machine-e2e: Target observed_hostname matches Controller "
                f"hostname ({observed_host!r}); local developer host cannot masquerade as an independent VM."
            )
    return observed_host, same_host


def issue_vm_target_challenge(
    *,
    installer_path: Path,
    expected_sidecar_sha256: str,
    root: Path = PROJECT_ROOT,
    compiled_exe_path: Optional[Path] = None,
    require_clean_git: bool = False,
    ttl_seconds: int = 3600,
    vm_provenance_ref: Optional[str] = None,
) -> Dict[str, Any]:
    """Controller-side step: issue a single-use challenge bound to Git HEAD, installer, and sidecar."""
    resolved_root = Path(root).resolve()
    installer = Path(installer_path).resolve()
    if not installer.is_file():
        raise RuntimeError(f"NSIS installer not found on Controller: {installer}")
    installer_size = installer.stat().st_size
    if installer_size < 1_000_000:
        raise RuntimeError(
            f"NSIS installer size too small ({installer_size} bytes < 1,000,000): {installer}"
        )
    sidecar_sha = (expected_sidecar_sha256 or "").strip().lower()
    if not _is_hex_sha256(sidecar_sha):
        raise RuntimeError(f"Invalid 64-hex expected_sidecar_sha256: {expected_sidecar_sha256!r}")
    if ttl_seconds <= 0 or ttl_seconds > 86400:
        raise RuntimeError(f"Invalid challenge ttl_seconds (expected 1..86400): {ttl_seconds}")

    source_commit = _get_git_head_commit(resolved_root)
    source_tree_clean = _check_git_tree_clean(resolved_root)
    if require_clean_git and source_tree_clean is not True:
        raise RuntimeError(
            "Controller challenge issuance BLOCKED: git working tree is dirty or unavailable."
        )

    compiled_sha: Optional[str] = None
    normalized_compiled_sha: Optional[str] = None
    resolved_compiled: Optional[Path] = None
    if compiled_exe_path is not None:
        resolved_compiled = Path(compiled_exe_path).resolve()
        if not resolved_compiled.is_file():
            raise RuntimeError(f"Compiled desktop executable not found: {resolved_compiled}")
    else:
        default_compiled = (
            resolved_root / "desktop/src-tauri/target/release/netflow-sentinel-desktop.exe"
        )
        if default_compiled.is_file():
            resolved_compiled = default_compiled
    if resolved_compiled is not None:
        compiled_sha, normalized_compiled_sha = _normalize_compiled_desktop_exe_hashes(
            resolved_compiled
        )

    split_path = resolved_root / SPLIT_MANIFEST_REL
    if not split_path.is_file():
        raise RuntimeError(f"Missing tracked split manifest on Controller: {split_path}")
    prep_manifest = _read_json_dict(
        resolved_root / PREPROCESSOR_MANIFEST_REL, str(PREPROCESSOR_MANIFEST_REL)
    )
    issued_dt = datetime.now(timezone.utc)
    expires_dt = issued_dt + timedelta(seconds=ttl_seconds)

    return {
        "format": _VM_CHALLENGE_FORMAT,
        "challenge_nonce": secrets.token_hex(32),
        "issued_at_utc": issued_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at_utc": expires_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "controller_hostname": socket.gethostname(),
        "source_commit": source_commit,
        "source_tree_clean": source_tree_clean,
        "desktop_version": _read_desktop_version(resolved_root),
        "installer_filename": installer.name,
        "installer_sha256": _sha256_file(installer).lower(),
        "installer_size_bytes": installer_size,
        "sidecar_sha256": sidecar_sha,
        "compiled_exe_sha256": compiled_sha,
        "normalized_compiled_exe_sha256": normalized_compiled_sha,
        "split_manifest_sha256": _sha256_file(split_path).lower(),
        "preprocessor_sha256": str(prep_manifest.get("artifact_sha256") or "").lower(),
        "vm_provenance_ref": vm_provenance_ref.strip() if vm_provenance_ref else None,
    }


def sign_vm_witness_receipt(
    *,
    challenge_path: Path,
    target_evidence_path: Path,
    vm_provenance_ref: str,
    trusted_authority_id: str = "controller-vm-witness-authority",
    vm_witness_secret_env: Optional[str] = None,
    issued_at_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """Trusted-boundary helper: sign a VM witness receipt binding challenge + target_evidence.json.

    Must ONLY execute inside the trusted Controller / external witness authority, never on the
    untrusted Target VM.
    """
    challenge = _read_json_dict(Path(challenge_path).resolve(), "VM challenge JSON")
    if challenge.get("format") != _VM_CHALLENGE_FORMAT:
        raise RuntimeError(f"Unsupported VM challenge format: {challenge.get('format')!r}")
    ev_path = Path(target_evidence_path).resolve()
    target_ev, target_bytes = _read_json_snapshot(ev_path, "VM target evidence JSON")
    target_ev_sha = hashlib.sha256(target_bytes).hexdigest()

    nonce = str(challenge.get("challenge_nonce") or "").strip().lower()
    if not _is_hex_sha256(nonce):
        raise RuntimeError("VM challenge missing valid 64-hex challenge_nonce.")
    if str(target_ev.get("challenge_nonce") or "").strip().lower() != nonce:
        raise RuntimeError("Target evidence challenge_nonce does not match VM challenge.")

    controller_host = str(challenge.get("controller_hostname") or "").strip()
    if not controller_host:
        raise RuntimeError("VM challenge missing controller_hostname.")
    observed_host, _ = _validate_target_probe(
        target_ev.get("target_probe"),
        controller_hostname=controller_host,
        require_clean_target=True,
    )
    vm_ref = (vm_provenance_ref or str(challenge.get("vm_provenance_ref") or "")).strip()
    auth_id = (trusted_authority_id or "").strip()
    if not vm_ref or not auth_id:
        raise RuntimeError("vm_provenance_ref and trusted_authority_id must be non-empty.")
    if auth_id.lower() == observed_host.lower():
        raise RuntimeError("trusted_authority_id cannot match target observed_hostname.")

    secret_env_name = (vm_witness_secret_env or "NETFLOW_VM_ATTESTATION_HMAC_KEY").strip()
    secret_val = os.environ.get(secret_env_name, "").strip()
    if not secret_val:
        raise RuntimeError(
            f"Missing trusted witness signing secret in environment variable {secret_env_name!r}."
        )

    source_commit = str(challenge.get("source_commit") or "").strip().lower()
    installer_sha = str(challenge.get("installer_sha256") or "").strip().lower()
    sidecar_sha = str(challenge.get("sidecar_sha256") or "").strip().lower()
    issued_str = (
        issued_at_utc.strip()
        if issued_at_utc and issued_at_utc.strip()
        else datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    _parse_utc_iso8601(issued_str, "witness.issued_at_utc")

    canonical = _canonical_vm_witness_payload(
        source_commit=source_commit,
        installer_sha256=installer_sha,
        sidecar_sha256=sidecar_sha,
        vm_provenance_ref=vm_ref,
        observed_hostname=observed_host,
        controller_hostname=controller_host,
        issued_at_utc=issued_str,
        trusted_authority_id=auth_id,
        challenge_nonce=nonce,
        target_evidence_sha256=target_ev_sha,
    )
    sig_hex = hmac.new(secret_val.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    probe = target_ev.get("target_probe") or {}
    return {
        "format": _VM_WITNESS_FORMAT,
        "environment_tier": "independent_windows_vm",
        "source_commit": source_commit,
        "installer_sha256": installer_sha,
        "sidecar_sha256": sidecar_sha,
        "challenge_nonce": nonce,
        "target_evidence_sha256": target_ev_sha,
        "vm_provenance_ref": vm_ref,
        "vm_name": str(probe.get("vm_name") or observed_host).strip(),
        "observed_hostname": observed_host,
        "controller_hostname": controller_host,
        "trusted_authority_id": auth_id,
        "issued_at_utc": issued_str,
        "signature_algorithm": "hmac-sha256-external-witness",
        "witness_signature_hex": sig_hex,
        "provenance_limitations": (
            "HMAC witness verifies integrity and controller-target binding of collected evidence; "
            "OS cleanliness relies on external VM snapshot governance and observed PATH/dir checks."
        ),
    }


def _nonce_ledger_lock_path(ledger: Path) -> Path:
    return ledger.with_name(f"{ledger.name}.lock")


def _vm_controller_signature(report: Dict[str, Any], secret_env: Optional[str]) -> str:
    env_name = (secret_env or "NETFLOW_VM_ATTESTATION_HMAC_KEY").strip()
    secret = os.environ.get(env_name, "").strip()
    if not secret:
        raise RuntimeError(f"Missing Controller attestation signature key in {env_name!r}.")
    payload = {key: value for key, value in report.items() if key != "vm_controller_signature_hex"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(
        secret.encode("utf-8"),
        b"netflow-sentinel-vm-controller-attestation-v1\n" + canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _record_consumed_nonce(ledger_path: Path, nonce: str) -> None:
    ledger = ledger_path.resolve()
    ledger.parent.mkdir(parents=True, exist_ok=True)
    # Lock a stable file because the ledger itself is replaced on every write.
    with _nonce_ledger_lock_path(ledger).open("a+b") as lock:
        lock.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)

        try:
            with ledger.open(encoding="utf-8") as stream:
                data = json.load(stream)
        except FileNotFoundError:
            data = {"schema_version": 1, "consumed_nonces": []}
        entries = data.get("consumed_nonces") if isinstance(data, dict) else None
        if (
            not isinstance(entries, list)
            or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1
            or any(not isinstance(item, str) or not _is_hex_sha256(item) for item in entries)
        ):
            raise RuntimeError(f"Malformed consumed VM challenge nonces ledger: {ledger}")
        existing = {item.lower() for item in entries}
        if nonce in existing:
            raise RuntimeError(
                f"REPLAY REJECTED: VM challenge_nonce {nonce} has already been consumed."
            )
        data["consumed_nonces"] = sorted(existing | {nonce})

        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=ledger.parent, mode="w", encoding="utf-8", newline="\n", delete=False
            ) as stream:
                temporary_path = Path(stream.name)
                stream.write(json.dumps(data, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary_path.replace(ledger)
            if os.name != "nt":
                directory = os.open(ledger.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)


def _verify_signed_vm_witness_doc(
    *,
    vm_doc: Dict[str, Any],
    vm_witness_secret_env: Optional[str],
    source_commit: str,
    installer_sha256: str,
    sidecar_sha256: str,
    observed_hostname: str,
    controller_hostname: str,
    challenge_nonce: str,
    target_evidence_sha256: str,
) -> Dict[str, Any]:
    if vm_doc.get("environment_tier") != "independent_windows_vm":
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: VM witness must declare environment_tier='independent_windows_vm'."
        )
    if str(vm_doc.get("source_commit") or "").strip().lower() != source_commit.lower():
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: VM witness source_commit mismatch against HEAD."
        )
    if not _is_hex_sha256(installer_sha256) or not _is_hex_sha256(sidecar_sha256):
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: Independent VM witness verification requires valid "
            "installer_sha256 and --expect-sidecar-sha256 bindings."
        )
    if str(vm_doc.get("installer_sha256") or "").strip().lower() != installer_sha256.lower():
        raise RuntimeError("REFUSED --clean-machine-e2e: VM witness installer_sha256 mismatch.")
    if str(vm_doc.get("sidecar_sha256") or "").strip().lower() != sidecar_sha256.lower():
        raise RuntimeError("REFUSED --clean-machine-e2e: VM witness sidecar_sha256 mismatch.")
    for field, expected in (
        ("challenge_nonce", challenge_nonce),
        ("target_evidence_sha256", target_evidence_sha256),
        ("controller_hostname", controller_hostname),
    ):
        if str(vm_doc.get(field) or "").strip().lower() != expected.lower():
            raise RuntimeError(f"REFUSED --clean-machine-e2e: VM witness {field} mismatch.")

    vm_ref = str(vm_doc.get("vm_provenance_ref") or "").strip()
    authority_id = str(vm_doc.get("trusted_authority_id") or "").strip()
    issued_at_raw = str(vm_doc.get("issued_at_utc") or "").strip()
    sig_alg = str(vm_doc.get("signature_algorithm") or "").strip().lower()
    sig_hex = str(vm_doc.get("witness_signature_hex") or "").strip().lower()
    if not vm_ref or not authority_id or not issued_at_raw:
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: VM witness missing vm_provenance_ref, "
            "trusted_authority_id, or issued_at_utc (self-declared JSON is rejected)."
        )
    if authority_id.lower() == observed_hostname.lower():
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: VM witness trusted_authority_id cannot match target hostname."
        )
    _parse_utc_iso8601(issued_at_raw, "witness.issued_at_utc")

    if sig_alg != "hmac-sha256-external-witness" or not _is_hex_sha256(sig_hex):
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: VM witness must include signature_algorithm="
            "'hmac-sha256-external-witness' and 64-hex witness_signature_hex; "
            "self-declared JSON + SHA-256 cannot verify clean VM provenance."
        )

    doc_host = str(vm_doc.get("observed_hostname") or "").strip()
    if not doc_host or doc_host.lower() != observed_hostname.lower():
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: VM witness observed_hostname mismatch "
            f"({doc_host!r} != {observed_hostname!r})."
        )

    secret_env_name = (vm_witness_secret_env or "NETFLOW_VM_ATTESTATION_HMAC_KEY").strip()
    secret_val = os.environ.get(secret_env_name, "").strip()
    if not secret_val:
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: Missing external VM verifier witness secret in "
            f"environment variable {secret_env_name!r}; status remains NOT VERIFIED."
        )

    canonical_bytes = _canonical_vm_witness_payload(
        source_commit=source_commit,
        installer_sha256=installer_sha256,
        sidecar_sha256=sidecar_sha256,
        vm_provenance_ref=vm_ref,
        observed_hostname=doc_host,
        controller_hostname=controller_hostname,
        issued_at_utc=issued_at_raw,
        trusted_authority_id=authority_id,
        challenge_nonce=challenge_nonce,
        target_evidence_sha256=target_evidence_sha256,
    )
    expected_sig = hmac.new(secret_val.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig_hex, expected_sig):
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: Independent Windows VM witness cryptographic signature "
            "verification failed."
        )
    return {
        "vm_provenance_ref": vm_ref,
        "trusted_authority_id": authority_id,
        "issued_at_utc": issued_at_raw,
        "signature_algorithm": sig_alg,
        "witness_signature_hex": sig_hex,
        "vm_name": str(vm_doc.get("vm_name") or doc_host).strip(),
    }


def verify_vm_target_evidence(
    *,
    target_evidence_path: Path,
    challenge_path: Path,
    root: Path = PROJECT_ROOT,
    installer_path: Optional[Path] = None,
    sums_file: Optional[Path] = None,
    compiled_exe_path: Optional[Path] = None,
    expected_sidecar_sha256: Optional[str] = None,
    require_clean_git: bool = False,
    clean_machine_e2e: bool = False,
    vm_witness_path: Optional[Path] = None,
    vm_witness_secret_env: Optional[str] = None,
    consumed_nonces_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Controller-side step: verify Target VM evidence against Controller Git HEAD, challenge, and witness.

    Controller uses Git and repository manifests; Target VM runs without Git, Python, Rust,
    Node.js, source checkout, or signing secrets. Missing witness evidence keeps status
    at NOT VERIFIED (never trusts self-declared clean_machine_verified=true).
    """
    resolved_root = Path(root).resolve()
    source_commit = _get_git_head_commit(resolved_root)
    source_tree_clean = _check_git_tree_clean(resolved_root)
    if require_clean_git and source_tree_clean is not True:
        raise RuntimeError(
            "Target E2E verification BLOCKED: Controller git working tree is dirty or unavailable."
        )

    challenge = _read_json_dict(Path(challenge_path).resolve(), "VM challenge JSON")
    if challenge.get("format") != _VM_CHALLENGE_FORMAT:
        raise RuntimeError(f"Unsupported VM challenge format: {challenge.get('format')!r}")
    if str(challenge.get("source_commit") or "").strip().lower() != source_commit:
        raise RuntimeError("VM challenge source_commit mismatch against Controller Git HEAD.")

    nonce = str(challenge.get("challenge_nonce") or "").strip().lower()
    if not _is_hex_sha256(nonce):
        raise RuntimeError("VM challenge missing valid 64-hex challenge_nonce.")

    issued_dt = _parse_utc_iso8601(
        str(challenge.get("issued_at_utc") or ""), "challenge.issued_at_utc"
    )
    expires_dt = _parse_utc_iso8601(
        str(challenge.get("expires_at_utc") or ""), "challenge.expires_at_utc"
    )
    if expires_dt < issued_dt:
        raise RuntimeError("VM challenge expires_at_utc precedes issued_at_utc.")
    now_dt = datetime.now(timezone.utc)
    if now_dt > expires_dt + timedelta(seconds=60):
        raise RuntimeError("VM challenge has expired; issue a fresh challenge from Controller.")

    challenge_installer_sha = str(challenge.get("installer_sha256") or "").strip().lower()
    challenge_sidecar_sha = str(challenge.get("sidecar_sha256") or "").strip().lower()
    if not _is_hex_sha256(challenge_installer_sha) or not _is_hex_sha256(challenge_sidecar_sha):
        raise RuntimeError("VM challenge missing valid installer_sha256 or sidecar_sha256.")
    if expected_sidecar_sha256 is not None:
        exp_sc = expected_sidecar_sha256.strip().lower()
        if not _is_hex_sha256(exp_sc) or exp_sc != challenge_sidecar_sha:
            raise RuntimeError(
                f"Expected sidecar SHA-256 mismatch against challenge: {exp_sc} != {challenge_sidecar_sha}"
            )

    if installer_path is not None:
        inst = Path(installer_path).resolve()
        if not inst.is_file():
            raise RuntimeError(f"Installer not found on Controller: {inst}")
        actual_inst_sha = _sha256_file(inst).lower()
        if actual_inst_sha != challenge_installer_sha:
            raise RuntimeError(
                f"Installer SHA-256 mismatch against challenge: {actual_inst_sha} != {challenge_installer_sha}"
            )
        if sums_file is not None:
            sums_map = _parse_sha256_sums_file(Path(sums_file).resolve())
            expected_sum = sums_map.get(inst.name)
            if expected_sum != actual_inst_sha:
                raise RuntimeError(
                    f"Installer SHA-256 mismatch against {sums_file}: {expected_sum} != {actual_inst_sha}"
                )

    ev_path = Path(target_evidence_path).resolve()
    target_ev, target_bytes = _read_json_snapshot(ev_path, "VM target evidence JSON")
    target_ev_sha = hashlib.sha256(target_bytes).hexdigest()
    if target_ev.get("format") != _VM_TARGET_EVIDENCE_FORMAT:
        raise RuntimeError(f"Unsupported target evidence format: {target_ev.get('format')!r}")
    if str(target_ev.get("challenge_nonce") or "").strip().lower() != nonce:
        raise RuntimeError("Target evidence challenge_nonce mismatch against Controller challenge.")

    completed_raw = str(target_ev.get("completed_at_utc") or "").strip()
    completed_dt = _parse_utc_iso8601(completed_raw, "target_evidence.completed_at_utc")
    if completed_dt < issued_dt - timedelta(seconds=60) or completed_dt > expires_dt + timedelta(
        seconds=60
    ):
        raise RuntimeError(
            "Target evidence completed_at_utc falls outside challenge validity window."
        )

    desktop_version = _read_desktop_version(resolved_root)
    if target_ev.get("desktop_version") != desktop_version:
        raise RuntimeError(
            f"Target evidence desktop_version mismatch: {target_ev.get('desktop_version')!r} != {desktop_version!r}"
        )

    split_path = resolved_root / SPLIT_MANIFEST_REL
    actual_split_sha = _sha256_file(split_path).lower()
    if target_ev.get("split_manifest_sha256") != actual_split_sha:
        raise RuntimeError(
            "Target evidence split_manifest_sha256 mismatch with Controller manifest."
        )

    prep_manifest = _read_json_dict(
        resolved_root / PREPROCESSOR_MANIFEST_REL, str(PREPROCESSOR_MANIFEST_REL)
    )
    if target_ev.get("preprocessor_sha256") != prep_manifest.get("artifact_sha256"):
        raise RuntimeError("Target evidence preprocessor_sha256 mismatch with Controller manifest.")

    nsis_block = target_ev.get("nsis_e2e")
    if not isinstance(nsis_block, dict) or nsis_block.get("status") != "PASS":
        raise RuntimeError("Target evidence missing passing nsis_e2e verification block.")
    if str(nsis_block.get("installer_sha256") or "").lower() != challenge_installer_sha:
        raise RuntimeError("Target evidence nsis_e2e.installer_sha256 mismatch against challenge.")
    if str(nsis_block.get("sidecar_sha256") or "").lower() != challenge_sidecar_sha:
        raise RuntimeError("Target evidence nsis_e2e.sidecar_sha256 mismatch against challenge.")

    if compiled_exe_path is not None:
        comp_path = Path(compiled_exe_path).resolve()
        if not comp_path.is_file():
            raise RuntimeError(f"Compiled desktop executable not found on Controller: {comp_path}")
        exact_comp_sha, norm_comp_sha = _normalize_compiled_desktop_exe_hashes(comp_path)
        installed_exe_sha = str(nsis_block.get("installed_exe_sha256") or "").strip().lower()
        if installed_exe_sha not in {exact_comp_sha, norm_comp_sha}:
            raise RuntimeError(
                f"Target installed_exe_sha256 mismatch vs Controller compiled exe: {installed_exe_sha}"
            )
    elif challenge.get("compiled_exe_sha256"):
        allowed_exe_shas = {
            str(challenge["compiled_exe_sha256"]).lower(),
            str(challenge.get("normalized_compiled_exe_sha256") or "").lower(),
        } - {""}
        installed_exe_sha = str(nsis_block.get("installed_exe_sha256") or "").strip().lower()
        if installed_exe_sha not in allowed_exe_shas:
            raise RuntimeError(
                f"Target installed_exe_sha256 mismatch vs challenge compiled exe: {installed_exe_sha}"
            )

    controller_host = str(challenge.get("controller_hostname") or "").strip()
    if not controller_host:
        raise RuntimeError("VM challenge missing controller_hostname.")
    observed_host, same_host = _validate_target_probe(
        target_ev.get("target_probe"),
        controller_hostname=controller_host,
        require_clean_target=clean_machine_e2e,
    )
    target_probe = dict(target_ev["target_probe"])
    probe_looks_clean = (
        target_probe.get("platform") == "win32"
        and target_probe.get("git_dir_present") is False
        and target_probe.get("dev_tools_absent") is True
        and not target_probe.get("found_dev_tools")
        and not target_probe.get("found_standard_tool_dirs")
        and target_probe.get("dev_models_tree_absent") is True
        and not same_host
    )

    witness_verified = False
    verified_witness: Optional[Dict[str, Any]] = None
    if vm_witness_path is not None:
        witness_doc = _read_json_dict(Path(vm_witness_path).resolve(), "VM witness receipt JSON")
        if witness_doc.get("format") != _VM_WITNESS_FORMAT:
            raise RuntimeError(f"Unsupported VM witness format: {witness_doc.get('format')!r}")
        secret_env_name = (vm_witness_secret_env or "NETFLOW_VM_ATTESTATION_HMAC_KEY").strip()
        secret_val = os.environ.get(secret_env_name, "").strip()
        if secret_val:
            verified_witness = _verify_signed_vm_witness_doc(
                vm_doc=witness_doc,
                vm_witness_secret_env=secret_env_name,
                source_commit=source_commit,
                installer_sha256=challenge_installer_sha,
                sidecar_sha256=challenge_sidecar_sha,
                observed_hostname=observed_host,
                controller_hostname=controller_host,
                challenge_nonce=nonce,
                target_evidence_sha256=target_ev_sha,
            )
            witness_verified = True
        elif clean_machine_e2e:
            raise RuntimeError(
                "REFUSED --clean-machine-e2e: Missing external VM verifier witness secret in "
                f"environment variable {secret_env_name!r}; status remains NOT VERIFIED."
            )
    elif clean_machine_e2e:
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: Missing external VM witness receipt (--vm-witness); "
            "self-declared target evidence remains NOT VERIFIED."
        )

    is_clean_vm = bool(witness_verified and probe_looks_clean)
    if (clean_machine_e2e or is_clean_vm) and consumed_nonces_file is None:
        raise RuntimeError(
            "Clean VM E2E remains NOT VERIFIED: --consumed-nonces-file is required "
            "and must reference the persistent Controller ledger."
        )
    if is_clean_vm and verified_witness is not None:
        env_tier = "independent_windows_vm"
        runner_identity: Dict[str, Any] = {
            "provenance_source": "independent_vm_signed_witness",
            "workflow_run_id": None,
            "run_attempt": None,
            "github_repository": None,
            "workflow_path": None,
            "runner_name": verified_witness["vm_name"],
            "runner_labels": ["independent-windows-vm"],
            "vm_provenance_ref": verified_witness["vm_provenance_ref"],
            "trusted_authority_id": verified_witness["trusted_authority_id"],
            "issued_at_utc": verified_witness["issued_at_utc"],
            "signature_algorithm": verified_witness["signature_algorithm"],
            "signature_verified": True,
            "witness_signature_hex": verified_witness["witness_signature_hex"],
            "challenge_nonce": nonce,
            "target_evidence_sha256": target_ev_sha,
            "controller_hostname": controller_host,
            "live_host_probe": target_probe,
        }
    else:
        env_tier = "local_developer_machine" if same_host else "unverified_target_machine"
        runner_identity = {
            "provenance_source": (
                "none_local_developer_machine" if same_host else "unwitnessed_target_evidence"
            ),
            "workflow_run_id": None,
            "run_attempt": None,
            "github_repository": None,
            "workflow_path": None,
            "runner_name": str(target_probe.get("vm_name") or observed_host),
            "runner_labels": [],
            "vm_provenance_ref": None,
            "trusted_authority_id": None,
            "issued_at_utc": None,
            "signature_algorithm": None,
            "signature_verified": False,
            "challenge_nonce": nonce,
            "target_evidence_sha256": target_ev_sha,
            "controller_hostname": controller_host,
            "live_host_probe": target_probe,
        }

    report: Dict[str, Any] = {
        "e2e_status": "PASS",
        "e2e_backend_origin": "installed_standalone_nsis",
        "host": "127.0.0.1",
        "port": target_ev.get("port"),
        "source_commit": source_commit,
        "desktop_version": desktop_version,
        "verify_script_sha256": _sha256_file(Path(__file__).resolve()).lower(),
        "split_manifest_sha256": actual_split_sha,
        "preprocessor_sha256": target_ev.get("preprocessor_sha256"),
        "demo_sha256": target_ev.get("demo_sha256"),
        "companion_status": "READY",
        "ready_models": target_ev.get("ready_models"),
        "models": target_ev.get("models"),
        "session_auth_fail_closed": bool(target_ev.get("session_auth_fail_closed")),
        "client_spoof_fail_closed": target_ev.get("client_spoof_fail_closed"),
        "nsis_e2e": nsis_block,
        "attestation_environment": {
            "environment_tier": env_tier,
            "execution_context": env_tier,
            "clean_machine_status": "VERIFIED" if is_clean_vm else "NOT VERIFIED",
            "source_tree_clean": source_tree_clean,
            "system_python_used": False,
            "clean_machine_verified": is_clean_vm,
            "runner_provenance_verified": is_clean_vm,
            "runner_identity": runner_identity,
            "bindings": {
                "source_commit": source_commit,
                "installer_sha256": challenge_installer_sha,
                "sidecar_sha256": challenge_sidecar_sha,
            },
            "standalone_verified": is_clean_vm,
            "provenance_limitations": (
                "Cryptographic witness verifies evidence integrity and controller-target binding; "
                "OS cleanliness relies on VM snapshot governance and observed target host checks."
            ),
        },
    }

    if is_clean_vm:
        if "windows_acceptance" in target_ev:
            report["windows_acceptance"] = target_ev["windows_acceptance"]
        report["vm_controller_signature_hex"] = _vm_controller_signature(
            report, vm_witness_secret_env
        )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", encoding="utf-8", delete=False
    ) as tmp_att:
        tmp_att.write(json.dumps(report, indent=2))
        tmp_att_path = Path(tmp_att.name)
    try:
        verify_e2e_attestation(
            tmp_att_path,
            root=resolved_root,
            expect_commit=source_commit,
            expect_installer_sha256=challenge_installer_sha,
            expect_sidecar_sha256=challenge_sidecar_sha,
            require_nsis_e2e=True,
            require_demo_files=False,
            require_bundled_resources=True,
            require_standalone_embedded=True,
            require_clean_machine_e2e=clean_machine_e2e,
            verify_vm_witness=is_clean_vm,
            vm_witness_secret_env=vm_witness_secret_env,
        )
    finally:
        tmp_att_path.unlink(missing_ok=True)

    if is_clean_vm and consumed_nonces_file is not None:
        _record_consumed_nonce(consumed_nonces_file, nonce)
    return report


def _resolve_clean_machine_provenance(
    *,
    clean_machine_e2e: bool,
    standalone_embedded: bool,
    pass_repo_root_env: bool,
    source_tree_clean: Optional[bool],
    source_commit: str,
    github_repo: Optional[str],
    github_run_id: Optional[str],
    token_env_var: Optional[str],
    independent_vm_evidence: Optional[Path],
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Enforce fail-closed runner/VM provenance; never trust --clean-machine-e2e CLI flag alone."""
    if not clean_machine_e2e:
        return "local_developer_machine", None

    if not standalone_embedded or pass_repo_root_env:
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: Clean-machine verification strictly requires "
            "--standalone-embedded and --no-repo-root-env."
        )

    if independent_vm_evidence is not None:
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: --independent-vm-evidence is retired. "
            "Use --verify-target-evidence with --vm-challenge, --vm-witness "
            "and the persistent --consumed-nonces-file."
        )

    if source_tree_clean is not True:
        raise RuntimeError(
            "REFUSED --clean-machine-e2e: GitHub runner clean-machine verification strictly "
            "requires a clean git HEAD checkout."
        )

    if github_repo and github_run_id:
        identity = _verify_github_runner_provenance(
            github_repo=github_repo,
            github_run_id=github_run_id,
            source_commit=source_commit,
            token_env_var=token_env_var,
            require_in_progress=True,
        )
        return "github_hosted_windows_runner", identity

    raise RuntimeError(
        "REFUSED --clean-machine-e2e: Refusing to mark clean_machine_verified=True on a local "
        "developer machine or unverified runner. Provide authoritative GitHub Actions API run "
        "provenance (--github-repo + --github-run-id + GitHub token) or use Controller/Target "
        "verification (--issue-vm-challenge -> scripts/vm_target_e2e.ps1 -> --verify-target-evidence)."
    )


def run_four_model_e2e_verification(
    root: Path = PROJECT_ROOT,
    *,
    runtime_dir: Optional[Path] = None,
    pass_repo_root_env: bool = True,
    installer_path: Optional[Path] = None,
    sums_file: Optional[Path] = None,
    compiled_exe_path: Optional[Path] = None,
    standalone_embedded: bool = False,
    expected_sidecar_sha256: Optional[str] = None,
    clean_machine_e2e: bool = False,
    require_clean_git: bool = False,
    github_repo: Optional[str] = None,
    github_run_id: Optional[str] = None,
    token_env_var: Optional[str] = None,
    independent_vm_evidence: Optional[Path] = None,
) -> Dict[str, Any]:
    """Fail-closed live loopback E2E verification across all 4 models on demo_flows.csv."""
    resolved_root = Path(root).resolve()
    summary = (
        verify_companion_artifacts(root=resolved_root)
        if runtime_dir is None
        else verify_companion_artifacts(root=resolved_root, runtime_dir=runtime_dir)
    )
    if not standalone_embedded and summary["overall_status"] != "READY":
        raise RuntimeError(
            "Mandatory 4-model E2E gate BLOCKED: companion artifacts incomplete or unverified "
            f"(ready_models={summary['ready_models']}, demo_ready={summary['demo_ready']}, "
            f"demo_error={summary.get('demo_verification_error')})."
        )

    source_commit = _get_git_head_commit(resolved_root)
    source_tree_clean = _check_git_tree_clean(resolved_root)
    if require_clean_git and source_tree_clean is not True:
        raise RuntimeError(
            "E2E attestation BLOCKED: git working tree is dirty or unavailable; "
            "attestation requires clean committed HEAD."
        )
    env_tier, verified_identity = _resolve_clean_machine_provenance(
        clean_machine_e2e=clean_machine_e2e,
        standalone_embedded=standalone_embedded,
        pass_repo_root_env=pass_repo_root_env,
        source_tree_clean=source_tree_clean,
        source_commit=source_commit,
        github_repo=github_repo,
        github_run_id=github_run_id,
        token_env_var=token_env_var,
        independent_vm_evidence=independent_vm_evidence,
    )
    desktop_version = _read_desktop_version(resolved_root)
    split_manifest_path = resolved_root / SPLIT_MANIFEST_REL
    if not split_manifest_path.is_file():
        raise RuntimeError(f"Missing split manifest: {split_manifest_path}")
    split_manifest_sha256 = _sha256_file(split_manifest_path).lower()

    if standalone_embedded:
        if installer_path is None:
            raise RuntimeError("Standalone embedded E2E verification requires --installer-path.")
    else:
        run_api_script = resolved_root / "scripts/run_api.py"
        if not run_api_script.is_file():
            raise RuntimeError(f"Missing server entrypoint: {run_api_script}")

    nsis_report: Optional[Dict[str, Any]] = None
    if installer_path is not None:
        if standalone_embedded:

            def _standalone_verifier(
                base_url: str,
                auth_headers: Optional[Dict[str, str]] = None,
                installed_dir: Optional[Path] = None,
            ) -> Dict[str, Any]:
                if installed_dir is None:
                    raise RuntimeError("Standalone verifier missing installed_dir.")
                installed_summary = verify_companion_artifacts(
                    root=installed_dir,
                    runtime_dir=installed_dir,
                )
                if installed_summary["overall_status"] != "READY":
                    raise RuntimeError(
                        "Installed standalone directory artifacts are not READY: "
                        f"{installed_summary}"
                    )
                res = _execute_four_model_api_suite(
                    base_url,
                    installed_dir,
                    installed_summary,
                    runtime_dir=installed_dir,
                    headers=auth_headers,
                )
                res["_installed_summary"] = installed_summary
                return res

            nsis_report = verify_nsis_installer_e2e(
                installer_path=installer_path,
                root=resolved_root,
                sums_file=sums_file,
                compiled_exe_path=compiled_exe_path,
                runtime_dir=None,
                pass_repo_root_env=False,
                launch_installed_app=True,
                backend_verifier=_standalone_verifier,
                standalone_embedded=True,
                expected_sidecar_sha256=expected_sidecar_sha256,
            )
            suite_result = dict(nsis_report.pop("_backend_verifier_result"))
            summary = suite_result.pop("_installed_summary")
            backend_origin = "installed_standalone_nsis"
        else:
            nsis_report = verify_nsis_installer_e2e(
                installer_path=installer_path,
                root=resolved_root,
                sums_file=sums_file,
                compiled_exe_path=compiled_exe_path,
                runtime_dir=runtime_dir,
                pass_repo_root_env=pass_repo_root_env,
                launch_installed_app=True,
                backend_verifier=lambda base_url, auth_headers=None: _execute_four_model_api_suite(
                    base_url,
                    resolved_root,
                    summary,
                    runtime_dir=runtime_dir,
                    headers=auth_headers,
                ),
            )
            suite_result = dict(nsis_report.pop("_backend_verifier_result"))
            backend_origin = "installed_nsis_desktop"
    else:
        tmp_dir = tempfile.TemporaryDirectory(prefix="netflow_e2e_")
        db_path = Path(tmp_dir.name) / "e2e_verify.db"
        log_path = Path(tmp_dir.name) / "run_api.log"

        env = os.environ.copy()
        src_path = str(resolved_root / "src")
        existing_py = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{src_path}{os.pathsep}{existing_py}" if existing_py else src_path
        if runtime_dir is not None:
            env["NETWORK_ANOMALY_RUNTIME_DIR"] = str(Path(runtime_dir).resolve())

        proc: Optional[subprocess.Popen[str]] = None
        try:
            proc, base_url = _start_api_process(
                resolved_root, run_api_script, db_path, log_path, env
            )
            suite_result = _execute_four_model_api_suite(
                base_url, resolved_root, summary, runtime_dir=runtime_dir
            )
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            try:
                tmp_dir.cleanup()
            except OSError:
                pass
        backend_origin = "api_only_run_api"

    is_clean_runner = env_tier in CLEAN_MACHINE_ENVIRONMENT_TIERS and verified_identity is not None
    installer_sha_bound = (
        str(nsis_report.get("installer_sha256")).lower()
        if isinstance(nsis_report, dict) and _is_hex_sha256(nsis_report.get("installer_sha256"))
        else None
    )
    sidecar_sha_bound = (
        str(nsis_report.get("sidecar_sha256")).lower()
        if isinstance(nsis_report, dict) and _is_hex_sha256(nsis_report.get("sidecar_sha256"))
        else None
    )
    runner_identity = (
        {
            "provenance_source": verified_identity["provenance_source"],
            "workflow_run_id": verified_identity.get("workflow_run_id"),
            "run_attempt": verified_identity.get("run_attempt"),
            "github_repository": verified_identity.get("github_repository"),
            "workflow_path": verified_identity.get("workflow_path"),
            "runner_name": verified_identity.get("runner_name"),
            "runner_labels": verified_identity.get("runner_labels") or [],
            "vm_provenance_ref": verified_identity.get("vm_provenance_ref"),
            "trusted_authority_id": verified_identity.get("trusted_authority_id"),
            "issued_at_utc": verified_identity.get("issued_at_utc"),
            "signature_algorithm": verified_identity.get("signature_algorithm"),
            "signature_verified": verified_identity.get("signature_verified"),
            "live_host_probe": verified_identity.get("live_host_probe"),
        }
        if verified_identity is not None
        else {
            "provenance_source": "none_local_developer_machine",
            "workflow_run_id": None,
            "run_attempt": None,
            "github_repository": None,
            "workflow_path": None,
            "runner_name": None,
            "runner_labels": [],
            "vm_provenance_ref": None,
            "trusted_authority_id": None,
            "issued_at_utc": None,
            "signature_algorithm": None,
            "signature_verified": False,
            "live_host_probe": None,
        }
    )

    standalone_env_ok = (
        source_tree_clean is True
        if env_tier == "github_hosted_windows_runner"
        else bool(
            verified_identity
            and (verified_identity.get("live_host_probe") or {}).get("dev_tools_absent") is True
        )
    )

    report: Dict[str, Any] = {
        "e2e_status": "PASS",
        "e2e_backend_origin": backend_origin,
        "host": "127.0.0.1",
        "port": suite_result["port"],
        "source_commit": source_commit,
        "desktop_version": desktop_version,
        "verify_script_sha256": _sha256_file(Path(__file__).resolve()),
        "split_manifest_sha256": split_manifest_sha256,
        "preprocessor_sha256": summary["preprocessor"]["sha256"],
        "demo_sha256": {rel: info["sha256"] for rel, info in summary["demo"].items()},
        "companion_status": summary["overall_status"],
        "ready_models": summary["ready_models"],
        "models": suite_result["models"],
        "session_auth_fail_closed": bool(suite_result.get("session_auth_fail_closed")),
        "client_spoof_fail_closed": suite_result["client_spoof_fail_closed"],
        "attestation_environment": {
            "environment_tier": env_tier,
            "execution_context": env_tier,
            "clean_machine_status": "VERIFIED" if is_clean_runner else "NOT VERIFIED",
            "source_tree_clean": source_tree_clean,
            "system_python_used": not standalone_embedded,
            "clean_machine_verified": is_clean_runner,
            "runner_provenance_verified": verified_identity is not None,
            "runner_identity": runner_identity,
            "bindings": {
                "source_commit": source_commit,
                "installer_sha256": installer_sha_bound,
                "sidecar_sha256": sidecar_sha_bound,
            },
            "standalone_verified": bool(
                standalone_embedded and is_clean_runner and standalone_env_ok
            ),
        },
    }
    if nsis_report is not None:
        report["nsis_e2e"] = nsis_report

    return report


def _validate_confusion_matrix_and_metrics(model_key: str, entry: Dict[str, Any]) -> None:
    evaluated_rows = entry.get("evaluated_rows")
    abstained_rows = entry.get("abstained_rows")
    if (
        type(entry.get("total_rows")) is not int
        or entry.get("total_rows") != 200
        or type(evaluated_rows) is not int
        or type(abstained_rows) is not int
        or (evaluated_rows, abstained_rows) not in ((198, 2), (200, 0))
    ):
        raise RuntimeError(f"E2E attestation invalid row counts/OOD coverage for {model_key}")

    cm = entry.get("confusion_matrix")
    if not isinstance(cm, dict) or set(cm.keys()) != {"tn", "fp", "fn", "tp"}:
        raise RuntimeError(f"E2E attestation invalid confusion_matrix keys for {model_key}: {cm}")
    for field_name in ("tn", "fp", "fn", "tp"):
        if not _is_strict_nonneg_int(cm[field_name]):
            raise RuntimeError(
                f"E2E attestation confusion_matrix.{field_name} must be non-neg int for {model_key}"
            )

    tn, fp, fn, tp = cm["tn"], cm["fp"], cm["fn"], cm["tp"]
    expected_benign = evaluated_rows - 100
    if tn + fp + fn + tp != evaluated_rows or tn + fp != expected_benign or tp + fn != 100:
        raise RuntimeError(
            f"E2E attestation confusion_matrix counts do not match {expected_benign} benign + 100 attack for {model_key}: {cm}"
        )

    expected_metrics = {
        "accuracy": (tp + tn) / float(evaluated_rows),
        "precision": tp / (tp + fp) if (tp + fp) > 0 else 0.0,
        "recall": tp / (tp + fn) if (tp + fn) > 0 else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
        "prediction_coverage": evaluated_rows / 200.0,
    }
    prec = expected_metrics["precision"]
    rec = expected_metrics["recall"]
    expected_metrics["f1"] = (2.0 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0

    for metric_name, calc_val in expected_metrics.items():
        recorded = entry.get(metric_name)
        if not _is_finite_number(recorded):
            raise RuntimeError(
                f"E2E attestation non-finite or missing metric {metric_name!r} for {model_key}: {recorded!r}"
            )
        if abs(float(recorded) - calc_val) > 1e-5:
            raise RuntimeError(
                f"E2E attestation metric inconsistency for {model_key}.{metric_name}: "
                f"recorded={recorded}, recalculated={calc_val}"
            )

    f1_val = float(entry["f1"])
    fpr_val = float(entry["fpr"])
    if model_key in ("random_forest", "xgboost"):
        if tp != 100 or tn != expected_benign or fp != 0 or fn != 0 or f1_val < 0.99:
            raise RuntimeError(
                f"E2E attestation {model_key} failed supervised threshold gate: cm={cm}, f1={f1_val}"
            )
    elif model_key == "isolation_forest":
        if f1_val < 0.80 or tp < 80 or tn < 80:
            raise RuntimeError(
                f"E2E attestation isolation_forest failed threshold gate: cm={cm}, f1={f1_val}"
            )
    elif model_key == "autoencoder":
        if f1_val < 0.15 or tp < 10 or fpr_val > 0.10:
            raise RuntimeError(
                f"E2E attestation autoencoder failed threshold gate: cm={cm}, f1={f1_val}, fpr={fpr_val}"
            )


def _validate_dry_run_gate(model_key: str, entry: Dict[str, Any]) -> None:
    if entry.get("dry_run_provenance") != "server_verified_analysis":
        raise RuntimeError(f"E2E attestation invalid dry-run provenance for {model_key}")
    action_counts = entry.get("dry_run_action_counts")
    if not isinstance(action_counts, dict) or set(action_counts.keys()) != set(_ACTION_COUNT_KEYS):
        raise RuntimeError(
            f"E2E attestation invalid dry_run_action_counts keys for {model_key}: {action_counts}"
        )
    for act_key in _ACTION_COUNT_KEYS:
        if not _is_strict_nonneg_int(action_counts[act_key]):
            raise RuntimeError(
                f"E2E attestation invalid action count {act_key} for {model_key}: {action_counts}"
            )
    if sum(action_counts.values()) != 200:
        raise RuntimeError(
            f"E2E attestation dry_run_action_counts sum != 200 for {model_key}: {action_counts}"
        )

    compat = entry.get("compatibility_status")
    rot = entry.get("dry_run_rotation_decision")
    if model_key == "random_forest":
        if (
            compat != "MODEL_VALIDATED"
            or rot != "SIMULATED_ROTATION_RECOMMENDED"
            or action_counts["ISOLATE_RECOMMENDED"] <= 0
        ):
            raise RuntimeError(
                f"E2E attestation invalid validated containment/rotation gate for {model_key}"
            )
    else:
        if (
            compat != "RESEARCH_ONLY"
            or rot != "HOLD_RESEARCH_ONLY_MODEL"
            or action_counts["ISOLATE_RECOMMENDED"] != 0
        ):
            raise RuntimeError(
                f"E2E attestation RESEARCH_ONLY containment bypass detected for {model_key}"
            )


def verify_e2e_attestation(
    attestation_path: Path,
    root: Path = PROJECT_ROOT,
    *,
    expect_commit: Optional[str] = None,
    expect_installer_sha256: Optional[str] = None,
    expect_sidecar_sha256: Optional[str] = None,
    require_nsis_e2e: bool = False,
    require_demo_files: bool = False,
    demo_root: Optional[Path] = None,
    require_bundled_resources: bool = False,
    require_standalone_embedded: bool = False,
    require_clean_machine_e2e: bool = False,
    require_stable_windows_e2e: bool = False,
    verify_github_run: bool = False,
    verify_vm_witness: bool = False,
    vm_witness_secret_env: Optional[str] = None,
    token_env_var: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a 4-model E2E attestation JSON against tracked manifests, commit, demo, and NSIS E2E."""
    resolved_root = Path(root).resolve()
    require_clean_machine_e2e = require_clean_machine_e2e or require_stable_windows_e2e
    report = _read_json_dict(Path(attestation_path), "E2E attestation JSON")
    if report.get("e2e_status") != "PASS" or report.get("companion_status") != "READY":
        raise RuntimeError(f"E2E attestation did not record PASS/READY: {attestation_path}")

    expected_models_order = list(MODEL_SPECS.keys())
    if report.get("ready_models") != expected_models_order:
        raise RuntimeError(
            f"E2E attestation ready_models must equal {expected_models_order}, got {report.get('ready_models')!r}"
        )
    models_report = report.get("models")
    if not isinstance(models_report, dict) or set(models_report.keys()) != set(MODEL_SPECS.keys()):
        raise RuntimeError(f"E2E attestation models keys must equal {expected_models_order}")

    actual_script_sha = _sha256_file(
        resolved_root / "scripts/verify_companion_artifacts.py"
    ).lower()
    if report.get("verify_script_sha256") != actual_script_sha:
        raise RuntimeError(
            "E2E attestation is stale: scripts/verify_companion_artifacts.py SHA-256 changed "
            f"({report.get('verify_script_sha256')} != {actual_script_sha})."
        )

    source_commit = report.get("source_commit")
    if not isinstance(source_commit, str) or not _GIT_COMMIT_RE.fullmatch(source_commit):
        raise RuntimeError(
            f"E2E attestation missing or invalid 40-char source_commit: {source_commit!r}"
        )
    if (resolved_root / ".git").exists():
        cat_proc = subprocess.run(  # noqa: S603 - fixed local git object existence check
            ["git", "cat-file", "-e", f"{source_commit}^{{commit}}"],
            cwd=str(resolved_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if cat_proc.returncode != 0:
            raise RuntimeError(
                f"E2E attestation source_commit {source_commit!r} is not a valid commit in {resolved_root}"
            )
    if expect_commit is not None:
        normalized_expect_commit = expect_commit.strip().lower()
        if source_commit != normalized_expect_commit:
            raise RuntimeError(
                f"E2E attestation source_commit mismatch: expected {normalized_expect_commit}, got {source_commit}"
            )

    desktop_version = report.get("desktop_version")
    if not isinstance(desktop_version, str) or not desktop_version.strip():
        raise RuntimeError(f"E2E attestation missing desktop_version: {desktop_version!r}")
    pkg_json_path = resolved_root / "desktop/package.json"
    if pkg_json_path.is_file():
        expected_desktop_version = _read_desktop_version(resolved_root)
        if desktop_version != expected_desktop_version:
            raise RuntimeError(
                f"E2E attestation desktop_version mismatch: {desktop_version!r} != {expected_desktop_version!r}"
            )

    split_manifest_path = resolved_root / SPLIT_MANIFEST_REL
    if not split_manifest_path.is_file():
        raise RuntimeError(f"Missing tracked split manifest: {split_manifest_path}")
    actual_split_sha = _sha256_file(split_manifest_path).lower()
    if report.get("split_manifest_sha256") != actual_split_sha:
        raise RuntimeError(
            "E2E attestation split_manifest_sha256 mismatch with tracked split manifest."
        )

    expected_demo_keys = {p.as_posix() for p in DEMO_FILES_REL}
    demo_sha256 = report.get("demo_sha256")
    if not isinstance(demo_sha256, dict) or set(demo_sha256.keys()) != expected_demo_keys:
        raise RuntimeError(
            f"E2E attestation demo_sha256 must contain exactly {sorted(expected_demo_keys)}"
        )
    for rel_str in expected_demo_keys:
        recorded_sha = demo_sha256.get(rel_str)
        if not _is_hex_sha256(recorded_sha):
            raise RuntimeError(f"E2E attestation invalid SHA-256 for {rel_str}: {recorded_sha!r}")

    sorted_demo_keys = sorted(expected_demo_keys)
    demo_root = demo_root.resolve() if demo_root is not None else resolved_root
    present_demo_files = [
        rel_str for rel_str in sorted_demo_keys if (demo_root / rel_str).is_file()
    ]
    if 0 < len(present_demo_files) < len(expected_demo_keys):
        missing_demo = sorted(expected_demo_keys - set(present_demo_files))
        raise RuntimeError(f"Incomplete tracked demo files on disk (missing {missing_demo})")

    demo_files_verified_on_disk = False
    if len(present_demo_files) == len(expected_demo_keys):
        for rel_str in sorted_demo_keys:
            recorded_sha = demo_sha256[rel_str]
            actual_demo_sha = _sha256_file(demo_root / rel_str).lower()
            if recorded_sha != actual_demo_sha:
                raise RuntimeError(
                    f"E2E attestation demo_sha256 mismatch for {rel_str}: {recorded_sha} != {actual_demo_sha}"
                )

        demo_manifest = _read_json_dict(
            demo_root / "data/demo/demo_manifest.json", "data/demo/demo_manifest.json"
        )
        sampling = demo_manifest.get("sampling") or {}
        if sampling.get("partition") != "validation":
            raise RuntimeError(
                f"demo_manifest sampling.partition must be 'validation', got {sampling.get('partition')!r}"
            )
        if (
            int(sampling.get("train_overlap_count", -1)) != 0
            or int(sampling.get("test_overlap_count", -1)) != 0
        ):
            raise RuntimeError("demo_manifest records non-zero train/test overlap")
        outputs = demo_manifest.get("outputs") or {}
        if (outputs.get("demo_flows_csv") or {}).get("sha256") != demo_sha256[
            "data/demo/demo_flows.csv"
        ]:
            raise RuntimeError("demo_manifest demo_flows_csv.sha256 mismatch with demo_sha256")
        if (outputs.get("demo_labels_csv") or {}).get("sha256") != demo_sha256[
            "data/demo/demo_labels.csv"
        ]:
            raise RuntimeError("demo_manifest demo_labels_csv.sha256 mismatch with demo_sha256")
        if demo_manifest.get("split_manifest_sha256") != actual_split_sha:
            raise RuntimeError("demo_manifest split_manifest_sha256 mismatch with split manifest")
        demo_files_verified_on_disk = True
    elif require_demo_files:
        missing_demo = [str(demo_root / rel_str) for rel_str in sorted_demo_keys]
        raise RuntimeError(
            f"Missing required demo files for attestation verification: {missing_demo}"
        )

    prep_manifest = _read_json_dict(
        resolved_root / PREPROCESSOR_MANIFEST_REL, str(PREPROCESSOR_MANIFEST_REL)
    )
    report_prep_sha = report.get("preprocessor_sha256")
    if not _is_hex_sha256(report_prep_sha) or report_prep_sha != prep_manifest.get(
        "artifact_sha256"
    ):
        raise RuntimeError("E2E attestation preprocessor_sha256 does not match tracked manifest.")
    if prep_manifest.get("split_manifest_sha256") != actual_split_sha:
        raise RuntimeError(
            "Tracked preprocessor manifest split_manifest_sha256 does not match split manifest."
        )

    analysis_ids: List[str] = []
    simulation_ids: List[str] = []

    for model_key, (_, manifest_candidates) in MODEL_SPECS.items():
        entry = models_report.get(model_key)
        if not isinstance(entry, dict):
            raise RuntimeError(f"E2E attestation missing model entry object for {model_key}")
        tracked_manifest = _read_json_dict(
            resolved_root / manifest_candidates[0], str(manifest_candidates[0])
        )
        expected_sha = (
            tracked_manifest.get("model_artifact_sha256")
            or tracked_manifest.get("model_sha256")
            or tracked_manifest.get("artifact_sha256")
        )
        if entry.get("artifact_sha256") != expected_sha:
            raise RuntimeError(
                f"E2E attestation artifact_sha256 mismatch for {model_key}: "
                f"{entry.get('artifact_sha256')} != {expected_sha}"
            )

        expected_run_id = tracked_manifest.get("run_id")
        if (
            not isinstance(expected_run_id, str)
            or not expected_run_id.strip()
            or entry.get("run_id") != expected_run_id
        ):
            raise RuntimeError(
                f"E2E attestation run_id mismatch for {model_key}: "
                f"{entry.get('run_id')!r} != {expected_run_id!r}"
            )
        inf_run_id = entry.get("inference_run_id")
        if (
            not isinstance(inf_run_id, str)
            or not inf_run_id.startswith("inference-")
            or len(inf_run_id) <= len("inference-")
        ):
            raise RuntimeError(
                f"E2E attestation invalid inference_run_id for {model_key}: {inf_run_id!r}"
            )

        manifest_prep_sha = _resolve_manifest_preprocessor_sha256(tracked_manifest)
        if (
            entry.get("preprocessor_sha256") != report_prep_sha
            or not manifest_prep_sha
            or entry.get("preprocessor_sha256") != manifest_prep_sha
        ):
            raise RuntimeError(
                f"E2E attestation preprocessor_sha256 mismatch for {model_key}: "
                f"entry={entry.get('preprocessor_sha256')!r}, manifest={manifest_prep_sha!r}"
            )

        if (
            tracked_manifest.get("split_manifest_sha256") is not None
            and tracked_manifest.get("split_manifest_sha256") != actual_split_sha
        ):
            raise RuntimeError(f"Tracked manifest split_manifest_sha256 mismatch for {model_key}")

        if entry.get("source_csv_sha256") != demo_sha256["data/demo/demo_flows.csv"]:
            raise RuntimeError(f"E2E attestation source_csv_sha256 mismatch for {model_key}")
        if entry.get("labels_sha256") != demo_sha256["data/demo/demo_labels.csv"]:
            raise RuntimeError(f"E2E attestation labels_sha256 mismatch for {model_key}")

        if entry.get("inference_mode") != "verified_model":
            raise RuntimeError(f"E2E attestation invalid inference_mode for {model_key}")

        if model_key == "autoencoder":
            th_cal = tracked_manifest.get("threshold_calibration")
            if not isinstance(th_cal, dict) or th_cal.get("threshold_frozen") is not True:
                raise RuntimeError(
                    "Autoencoder manifest threshold_calibration.threshold_frozen must be True"
                )
            emp_fpr = th_cal.get("empirical_val_fpr")
            target_fpr = th_cal.get("target_fpr")
            if (
                not _is_finite_number(emp_fpr)
                or not _is_finite_number(target_fpr)
                or float(emp_fpr) < 0.0
                or float(emp_fpr) > float(target_fpr)
                or float(target_fpr) > 0.05
            ):
                raise RuntimeError(
                    f"Autoencoder manifest empirical_val_fpr/target_fpr violates <= 0.05 constraint: {th_cal}"
                )

        _validate_confusion_matrix_and_metrics(model_key, entry)
        _validate_dry_run_gate(model_key, entry)

        aid = entry.get("analysis_id")
        sid = entry.get("dry_run_simulation_id")
        if not isinstance(aid, str) or not aid.startswith("csvrun_") or len(aid) <= len("csvrun_"):
            raise RuntimeError(f"E2E attestation invalid analysis_id for {model_key}: {aid!r}")
        if not isinstance(sid, str) or not sid.startswith("sim_") or len(sid) <= len("sim_"):
            raise RuntimeError(
                f"E2E attestation invalid dry_run_simulation_id for {model_key}: {sid!r}"
            )
        analysis_ids.append(aid)
        simulation_ids.append(sid)

    if len(set(analysis_ids)) != len(MODEL_SPECS):
        raise RuntimeError(f"E2E attestation analysis_id values are not unique: {analysis_ids}")
    if len(set(simulation_ids)) != len(MODEL_SPECS):
        raise RuntimeError(
            f"E2E attestation dry_run_simulation_id values are not unique: {simulation_ids}"
        )

    spoof = report.get("client_spoof_fail_closed")
    if (
        not isinstance(spoof, dict)
        or spoof.get("provenance_verification") != "client_supplied_unverified"
        or spoof.get("critical_downgraded_action") != "INVESTIGATE"
        or spoof.get("rotation_decision") != "HOLD_UNVERIFIED_PROVENANCE"
    ):
        raise RuntimeError(f"E2E attestation missing valid anti-spoof verification: {spoof}")

    nsis_present = "nsis_e2e" in report
    bundled_resources_verified = False
    standalone_embedded_verified = False
    if (
        require_nsis_e2e
        or require_bundled_resources
        or require_standalone_embedded
        or expect_installer_sha256 is not None
        or nsis_present
    ):
        nsis = report.get("nsis_e2e")
        if not isinstance(nsis, dict):
            raise RuntimeError("E2E attestation missing required 'nsis_e2e' verification block")
        required_nsis_flags = (
            "clean_install_verified",
            "uninstaller_verified",
            "compiled_exe_sha256_match",
            "installed_app_launched",
            "installed_exe_path_verified",
            "frontend_webview_connected",
            "backend_spawned_on_loopback",
            "graceful_close_verified",
            "zero_orphan_processes_verified",
            "uninstall_cleanup_verified",
        )
        if nsis.get("status") != "PASS" or any(
            nsis.get(flag) is not True for flag in required_nsis_flags
        ):
            raise RuntimeError(f"E2E attestation invalid nsis_e2e verification flags: {nsis}")
        allowed_origins = {"installed_nsis_desktop", "installed_standalone_nsis"}
        if (
            require_nsis_e2e or require_bundled_resources or require_standalone_embedded
        ) and report.get("e2e_backend_origin") not in allowed_origins:
            raise RuntimeError(
                f"E2E attestation must record e2e_backend_origin in {sorted(allowed_origins)}, "
                f"got {report.get('e2e_backend_origin')!r}"
            )
        if nsis.get("frontend_ready_models") != expected_models_order:
            raise RuntimeError(
                f"E2E attestation nsis_e2e.frontend_ready_models must equal {expected_models_order}, "
                f"got {nsis.get('frontend_ready_models')!r}"
            )
        bundled_resources_verified = (
            nsis.get("bundled_resources_mode") is True
            and nsis.get("repo_root_env_passed") is False
            and nsis.get("runtime_dir_isolated") is True
        )
        if require_bundled_resources and not bundled_resources_verified:
            raise RuntimeError(
                "E2E attestation must verify production bundled resources without NETWORK_ANOMALY_REPO_ROOT "
                "and with isolated NETWORK_ANOMALY_RUNTIME_DIR "
                f"(bundled_resources_mode={nsis.get('bundled_resources_mode')!r}, "
                f"repo_root_env_passed={nsis.get('repo_root_env_passed')!r}, "
                f"runtime_dir_isolated={nsis.get('runtime_dir_isolated')!r})."
            )
        standalone_embedded_verified = (
            report.get("e2e_backend_origin") == "installed_standalone_nsis"
            and nsis.get("standalone_embedded_mode") is True
            and nsis.get("sidecar_exe_verified") is True
            and _is_hex_sha256(nsis.get("sidecar_sha256"))
            and nsis.get("system_python_used") is False
            and nsis.get("external_companion_used") is False
            and nsis.get("restart_persistence_verified") is True
            and nsis.get("export_verified") is True
        )
        if require_standalone_embedded and not standalone_embedded_verified:
            raise RuntimeError(
                "E2E attestation must verify standalone embedded NSIS installer with PyInstaller sidecar, "
                "embedded 4 models, zero system Python/external companion, restart persistence, and CSV export "
                f"(origin={report.get('e2e_backend_origin')!r}, "
                f"standalone_embedded_mode={nsis.get('standalone_embedded_mode')!r}, "
                f"sidecar_exe_verified={nsis.get('sidecar_exe_verified')!r}, "
                f"system_python_used={nsis.get('system_python_used')!r}, "
                f"external_companion_used={nsis.get('external_companion_used')!r}, "
                f"restart_persistence_verified={nsis.get('restart_persistence_verified')!r}, "
                f"export_verified={nsis.get('export_verified')!r})."
            )
        inst_size = nsis.get("installer_size_bytes")
        if type(inst_size) is not int or inst_size < 1_000_000:
            raise RuntimeError(
                f"E2E attestation invalid nsis_e2e installer_size_bytes: {inst_size!r}"
            )
        inst_sha = nsis.get("installer_sha256")
        exe_sha = nsis.get("installed_exe_sha256")
        if not _is_hex_sha256(inst_sha) or not _is_hex_sha256(exe_sha):
            raise RuntimeError("E2E attestation nsis_e2e missing valid 64-hex SHA-256 digests")
        if expect_installer_sha256 is not None:
            expected_inst = expect_installer_sha256.strip().lower()
            if not _is_hex_sha256(expected_inst) or inst_sha != expected_inst:
                raise RuntimeError(
                    f"E2E attestation nsis_e2e.installer_sha256 mismatch: "
                    f"{inst_sha} != {expected_inst}"
                )
        if expect_sidecar_sha256 is not None:
            expected_sidecar = expect_sidecar_sha256.strip().lower()
            recorded_sidecar = nsis.get("sidecar_sha256")
            if (
                not _is_hex_sha256(expected_sidecar)
                or not _is_hex_sha256(recorded_sidecar)
                or str(recorded_sidecar).lower() != expected_sidecar
            ):
                raise RuntimeError(
                    f"E2E attestation nsis_e2e.sidecar_sha256 mismatch: "
                    f"{recorded_sidecar!r} != {expected_sidecar!r}"
                )

    if require_standalone_embedded and report.get("session_auth_fail_closed") is not True:
        raise RuntimeError(
            "E2E attestation missing required session_auth_fail_closed=True verification."
        )

    att_env = report.get("attestation_environment")
    clean_machine_verified = False
    if isinstance(att_env, dict):
        env_tier_val = att_env.get("environment_tier") or att_env.get("execution_context")
        runner_id_val = att_env.get("runner_identity")
        bindings_val = att_env.get("bindings")
        nsis_block = report.get("nsis_e2e") if isinstance(report.get("nsis_e2e"), dict) else None

        if isinstance(bindings_val, dict):
            if (
                bindings_val.get("source_commit") is not None
                and str(bindings_val.get("source_commit")).lower() != source_commit.lower()
            ):
                raise RuntimeError(
                    "E2E attestation attestation_environment.bindings.source_commit mismatch."
                )
            if nsis_block is not None:
                if (
                    bindings_val.get("installer_sha256") is not None
                    and str(bindings_val.get("installer_sha256")).lower()
                    != str(nsis_block.get("installer_sha256", "")).lower()
                ):
                    raise RuntimeError(
                        "E2E attestation attestation_environment.bindings.installer_sha256 mismatch."
                    )
                if (
                    bindings_val.get("sidecar_sha256") is not None
                    and str(bindings_val.get("sidecar_sha256")).lower()
                    != str(nsis_block.get("sidecar_sha256", "")).lower()
                ):
                    raise RuntimeError(
                        "E2E attestation attestation_environment.bindings.sidecar_sha256 mismatch."
                    )

        identity_ok = False
        if (
            isinstance(runner_id_val, dict)
            and nsis_block is not None
            and isinstance(bindings_val, dict)
        ):
            bindings_complete = (
                str(bindings_val.get("source_commit") or "").lower() == source_commit.lower()
                and _is_hex_sha256(bindings_val.get("installer_sha256"))
                and str(bindings_val["installer_sha256"]).lower()
                == str(nsis_block.get("installer_sha256", "")).lower()
                and _is_hex_sha256(bindings_val.get("sidecar_sha256"))
                and str(bindings_val["sidecar_sha256"]).lower()
                == str(nsis_block.get("sidecar_sha256", "")).lower()
            )
            if bindings_complete:
                if env_tier_val == "github_hosted_windows_runner":
                    labels = runner_id_val.get("runner_labels")
                    has_win_label = isinstance(labels, list) and any(
                        str(lbl).strip().lower().startswith("windows") for lbl in labels
                    )
                    run_id_str = str(runner_id_val.get("workflow_run_id") or "").strip()
                    gh_repo_str = str(runner_id_val.get("github_repository") or "").strip()
                    runner_name_str = str(runner_id_val.get("runner_name") or "").strip()
                    identity_ok = (
                        runner_id_val.get("provenance_source") == "github_actions_api"
                        and run_id_str.isdigit()
                        and bool(_GITHUB_REPO_RE.fullmatch(gh_repo_str))
                        and bool(runner_name_str)
                        and has_win_label
                    )
                    if identity_ok and verify_github_run:
                        _verify_github_runner_provenance(
                            github_repo=gh_repo_str,
                            github_run_id=run_id_str,
                            source_commit=source_commit,
                            token_env_var=token_env_var,
                            require_in_progress=False,
                        )
                elif env_tier_val == "independent_windows_vm":
                    vm_ref = str(runner_id_val.get("vm_provenance_ref") or "").strip()
                    authority_id = str(runner_id_val.get("trusted_authority_id") or "").strip()
                    sig_alg = str(runner_id_val.get("signature_algorithm") or "").strip().lower()
                    issued_at = str(runner_id_val.get("issued_at_utc") or "").strip()
                    probe_block = runner_id_val.get("live_host_probe")
                    observed_host = (
                        str(probe_block.get("observed_hostname") or "").strip()
                        if isinstance(probe_block, dict)
                        else ""
                    )
                    ctrl_host = str(runner_id_val.get("controller_hostname") or "").strip()
                    host_distinct = bool(ctrl_host and observed_host.lower() != ctrl_host.lower())
                    probe_ok = (
                        isinstance(probe_block, dict)
                        and probe_block.get("platform") == "win32"
                        and probe_block.get("git_dir_present") is False
                        and probe_block.get("dev_tools_absent") is True
                        and not probe_block.get("found_dev_tools")
                        and not probe_block.get("found_standard_tool_dirs")
                        and probe_block.get("dev_models_tree_absent") is True
                        and bool(observed_host)
                        and host_distinct
                    )
                    identity_ok = (
                        runner_id_val.get("provenance_source") == "independent_vm_signed_witness"
                        and runner_id_val.get("signature_verified") is True
                        and sig_alg == "hmac-sha256-external-witness"
                        and bool(vm_ref)
                        and bool(authority_id)
                        and authority_id.lower() != observed_host.lower()
                        and bool(issued_at)
                        and probe_ok
                        and _is_hex_sha256(runner_id_val.get("challenge_nonce"))
                        and _is_hex_sha256(runner_id_val.get("target_evidence_sha256"))
                        and _is_hex_sha256(runner_id_val.get("witness_signature_hex"))
                        and bool(str(runner_id_val.get("runner_name") or "").strip())
                    )
                    if identity_ok and (verify_vm_witness or require_clean_machine_e2e):
                        controller_signature = report.get("vm_controller_signature_hex")
                        if not _is_hex_sha256(controller_signature) or not hmac.compare_digest(
                            controller_signature,
                            _vm_controller_signature(report, vm_witness_secret_env),
                        ):
                            raise RuntimeError("Invalid Controller attestation signature.")
                        _verify_signed_vm_witness_doc(
                            vm_doc={
                                "environment_tier": "independent_windows_vm",
                                "source_commit": source_commit,
                                "installer_sha256": bindings_val["installer_sha256"],
                                "sidecar_sha256": bindings_val["sidecar_sha256"],
                                "challenge_nonce": runner_id_val.get("challenge_nonce"),
                                "target_evidence_sha256": runner_id_val.get(
                                    "target_evidence_sha256"
                                ),
                                "vm_provenance_ref": vm_ref,
                                "observed_hostname": observed_host,
                                "controller_hostname": ctrl_host,
                                "trusted_authority_id": authority_id,
                                "issued_at_utc": issued_at,
                                "signature_algorithm": sig_alg,
                                "witness_signature_hex": runner_id_val.get("witness_signature_hex"),
                                "vm_name": runner_id_val.get("runner_name"),
                            },
                            vm_witness_secret_env=vm_witness_secret_env,
                            source_commit=source_commit,
                            installer_sha256=str(bindings_val["installer_sha256"]),
                            sidecar_sha256=str(bindings_val["sidecar_sha256"]),
                            observed_hostname=observed_host,
                            controller_hostname=ctrl_host,
                            challenge_nonce=runner_id_val["challenge_nonce"],
                            target_evidence_sha256=runner_id_val["target_evidence_sha256"],
                        )

        clean_machine_verified = bool(
            env_tier_val in CLEAN_MACHINE_ENVIRONMENT_TIERS
            and att_env.get("execution_context") == env_tier_val
            and att_env.get("clean_machine_status") == "VERIFIED"
            and att_env.get("clean_machine_verified") is True
            and att_env.get("runner_provenance_verified") is True
            and (
                att_env.get("source_tree_clean") is True
                if env_tier_val == "github_hosted_windows_runner"
                else True
            )
            and att_env.get("system_python_used") is False
            and att_env.get("standalone_verified") is True
            and identity_ok
        )

    if require_clean_machine_e2e and not clean_machine_verified:
        raise RuntimeError(
            "E2E attestation failed strict --require-clean-machine-e2e gate: "
            f"attestation_environment={att_env!r} (local developer or unverified runner provenance "
            "cannot assert clean-machine STANDALONE VERIFIED)."
        )

    if require_stable_windows_e2e:
        if env_tier_val != "independent_windows_vm":
            raise RuntimeError("Stable Windows E2E requires independent VM evidence.")
        acceptance = report.get("windows_acceptance")
        for platform in ("windows_10_x64", "windows_11_x64"):
            observations = acceptance.get(platform) if isinstance(acceptance, dict) else None
            if (
                not isinstance(observations, dict)
                or not str(observations.get("evidence_ref") or "").strip()
                or any(
                    observations.get(check) is not True
                    for check in (
                        "offline",
                        "standard_user",
                        "unicode_and_spaces",
                        "windows_reboot",
                        "webview2_gui_workflow",
                        "model_error",
                        "uninstall",
                    )
                )
            ):
                raise RuntimeError(f"Stable Windows E2E remains NOT VERIFIED for {platform}.")

    return {
        "attestation_status": "PASS",
        "attestation_path": str(attestation_path),
        "verified_models": list(MODEL_SPECS.keys()),
        "verify_script_sha256": actual_script_sha,
        "source_commit": source_commit,
        "desktop_version": desktop_version,
        "split_manifest_sha256": actual_split_sha,
        "nsis_e2e_verified": isinstance(report.get("nsis_e2e"), dict),
        "installed_desktop_e2e_verified": report.get("e2e_backend_origin")
        in {"installed_nsis_desktop", "installed_standalone_nsis"},
        "bundled_resources_verified": bundled_resources_verified,
        "standalone_embedded_verified": standalone_embedded_verified,
        "clean_machine_verified": clean_machine_verified,
        "clean_machine_status": "VERIFIED" if clean_machine_verified else "NOT VERIFIED",
        "environment_tier": (
            att_env.get("environment_tier") or att_env.get("execution_context")
            if isinstance(att_env, dict)
            else None
        ),
        "demo_files_verified_on_disk": demo_files_verified_on_disk,
    }


def _emit_json(payload: Dict[str, Any], output_json: Optional[Path]) -> None:
    payload_text = json.dumps(payload, indent=2)
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(payload_text + "\n", encoding="utf-8", newline="\n")
    print(payload_text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify or stage NetFlow Sentinel companion artifacts (preprocessor, 4 models, demo CSV)."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository root to inspect (defaults to project root).",
    )
    parser.add_argument(
        "--runtime-dir",
        type=Path,
        default=None,
        help="Optional separate writable runtime directory for artifacts/ and data/demo/.",
    )
    parser.add_argument(
        "--no-repo-root-env",
        action="store_true",
        help="Launch installed NSIS desktop executable without NETWORK_ANOMALY_REPO_ROOT (verifies bundled Tauri resources).",
    )
    parser.add_argument(
        "--stage-dir",
        type=Path,
        default=None,
        help="Optional directory to stage verified companion files + COMPANION_SHA256SUMS.txt.",
    )
    parser.add_argument(
        "--stage-embedded-dir",
        type=Path,
        default=None,
        help="Stage verified 4 models, preprocessor, manifests, demo CSV, and notices for standalone NSIS embedding.",
    )
    parser.add_argument(
        "--distribution-scope",
        type=str,
        default="private-build-only",
        help="Distribution permission scope for embedded NetFlow Sentinel v2 artifacts.",
    )
    parser.add_argument(
        "--verify-distribution-permission",
        type=str,
        default=None,
        help="Verify distribution permission gate for embedded NetFlow Sentinel v2 artifacts.",
    )
    parser.add_argument(
        "--target-channel",
        type=str,
        default=None,
        help="Target channel: local_offline, private_ci_artifact, public_ci_artifact, or public_github_release.",
    )
    parser.add_argument(
        "--repo-private",
        type=str,
        default=None,
        help="Repository privacy flag from GitHub API ('true', 'false', or 'unknown').",
    )
    parser.add_argument(
        "--evidence-sha256-env",
        type=str,
        default=None,
        help="Name of environment variable holding expected 64-hex SHA-256 of distribution authorization evidence.",
    )
    parser.add_argument(
        "--require-evidence-hash",
        action="store_true",
        help="Require non-empty --evidence-sha256-env digest for public release authorization.",
    )
    parser.add_argument(
        "--public-release",
        action="store_true",
        help="Enforce public release distribution permission checks.",
    )
    parser.add_argument(
        "--github-run-id",
        type=str,
        default=None,
        help="GitHub Actions workflow run ID used with --clean-machine-e2e for API provenance verification.",
    )
    parser.add_argument(
        "--independent-vm-evidence",
        type=Path,
        default=None,
        help="Retired. Use --verify-target-evidence with a persistent Controller nonce ledger.",
    )
    parser.add_argument(
        "--vm-witness-secret-env",
        type=str,
        default=None,
        help="Environment variable holding external VM verifier HMAC-SHA256 key (defaults to NETFLOW_VM_ATTESTATION_HMAC_KEY).",
    )
    parser.add_argument(
        "--verify-github-run",
        action="store_true",
        help="Re-verify runner_identity.workflow_run_id against live GitHub REST API in --verify-attestation.",
    )
    parser.add_argument(
        "--verify-vm-witness",
        action="store_true",
        help="Re-verify independent_windows_vm HMAC-SHA256 witness signature in --verify-attestation.",
    )
    parser.add_argument(
        "--issue-vm-challenge",
        action="store_true",
        help="Controller step: issue single-use challenge JSON bound to Git HEAD, installer, and sidecar SHA-256.",
    )
    parser.add_argument(
        "--challenge-ttl-seconds",
        type=int,
        default=3600,
        help="Validity window (seconds) for --issue-vm-challenge (default: 3600).",
    )
    parser.add_argument(
        "--vm-provenance-ref",
        type=str,
        default=None,
        help="External hypervisor/VM snapshot reference for --issue-vm-challenge or --sign-vm-witness.",
    )
    parser.add_argument(
        "--sign-vm-witness",
        action="store_true",
        help="Trusted-boundary helper: sign HMAC-SHA256 VM witness receipt over --vm-challenge and --verify-target-evidence.",
    )
    parser.add_argument(
        "--trusted-authority-id",
        type=str,
        default="controller-vm-witness-authority",
        help="Trusted witness authority identifier for --sign-vm-witness.",
    )
    parser.add_argument(
        "--verify-target-evidence",
        type=Path,
        default=None,
        help="Controller step: verify target_evidence.json produced on a Clean Windows Target VM against --vm-challenge.",
    )
    parser.add_argument(
        "--vm-challenge",
        type=Path,
        default=None,
        help="Path to Controller-issued VM challenge JSON (used with --sign-vm-witness and --verify-target-evidence).",
    )
    parser.add_argument(
        "--vm-witness",
        type=Path,
        default=None,
        help="Optional path to external HMAC-SHA256 VM witness receipt JSON (used with --verify-target-evidence).",
    )
    parser.add_argument(
        "--consumed-nonces-file",
        type=Path,
        default=None,
        help="Persistent Controller JSON ledger required to verify Clean VM target evidence.",
    )
    parser.add_argument(
        "--clean-machine-e2e",
        action="store_true",
        help="Assert clean-machine E2E (fails closed unless backed by GitHub Actions API run proof or verified VM evidence).",
    )
    parser.add_argument(
        "--require-clean-git",
        action="store_true",
        help="Refuse --verify-e2e if git working tree is dirty.",
    )
    parser.add_argument(
        "--standalone-embedded",
        action="store_true",
        help="Verify installed NSIS standalone desktop using embedded sidecar and 4 embedded models (no system Python/external companion).",
    )
    parser.add_argument(
        "--expect-sidecar-sha256",
        type=str,
        default=None,
        help="Expected 64-char SHA-256 of embedded netflow-sentinel-backend.exe sidecar.",
    )
    parser.add_argument(
        "--expect-ood-gate-sha256",
        type=str,
        default=None,
        help="Optional trusted expected 64-char SHA-256 of artifacts/ml/ood_reference_gate.json.",
    )
    parser.add_argument(
        "--package-bundle",
        type=Path,
        default=None,
        help="Package verified companion files + checksums/manifest into a deterministic ZIP.",
    )
    parser.add_argument(
        "--install-bundle-dir",
        type=Path,
        default=None,
        help="Install and verify companion files from a staged local directory.",
    )
    parser.add_argument(
        "--install-bundle-archive",
        type=Path,
        default=None,
        help="Install and verify companion files from a local companion ZIP archive.",
    )
    parser.add_argument(
        "--install-bundle-url",
        type=str,
        default=None,
        help="Install and verify companion ZIP from an allowlisted HTTPS URL (requires --expect-bundle-sha256).",
    )
    parser.add_argument(
        "--install-bundle-run-id",
        type=str,
        default=None,
        help="Install and verify companion artifact ZIP from a GitHub Actions workflow run ID.",
    )
    parser.add_argument(
        "--install-bundle-artifact-name",
        type=str,
        default="netflow-sentinel-companion-bundle",
        help="GitHub Actions artifact name when using --install-bundle-run-id.",
    )
    parser.add_argument(
        "--github-repo",
        type=str,
        default=None,
        help="GitHub repository slug ('owner/repo') to scope GitHub URL/artifact downloads.",
    )
    parser.add_argument(
        "--expect-bundle-sha256",
        type=str,
        default=None,
        help="Expected 64-char SHA-256 digest of the companion bundle archive.",
    )
    parser.add_argument(
        "--allowed-hosts",
        action="append",
        default=None,
        help="Optional comma-separated HTTPS host allowlist overriding default GitHub hosts.",
    )
    parser.add_argument(
        "--token-env",
        type=str,
        default=None,
        help="Environment variable name supplying bearer token for protected GitHub/bundle URLs.",
    )
    parser.add_argument(
        "--verify-e2e",
        action="store_true",
        help="Run mandatory live 127.0.0.1 FastAPI 4-model E2E verification on real demo CSV (fails closed).",
    )
    parser.add_argument(
        "--verify-nsis-only",
        action="store_true",
        help="Run clean Windows NSIS silent install/exe SHA-256 parity/uninstall verification only.",
    )
    parser.add_argument(
        "--installer-path",
        type=Path,
        default=None,
        help="Path to NSIS Windows x64 setup executable for clean-install E2E verification.",
    )
    parser.add_argument(
        "--sums-file",
        type=Path,
        default=None,
        help="Optional SHA256SUMS.txt path to verify the NSIS installer digest against.",
    )
    parser.add_argument(
        "--compiled-exe",
        type=Path,
        default=None,
        help="Optional compiled release desktop .exe path for installed binary parity verification.",
    )
    parser.add_argument(
        "--verify-attestation",
        type=Path,
        default=None,
        help="Verify a 4-model E2E JSON attestation against tracked manifests.",
    )
    parser.add_argument(
        "--expect-commit",
        type=str,
        default=None,
        help="Expected 40-char git commit SHA when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--expect-installer-sha256",
        type=str,
        default=None,
        help="Expected 64-char NSIS installer SHA-256 when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--require-nsis-e2e",
        action="store_true",
        help="Require a valid nsis_e2e verification block when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--require-demo-files",
        action="store_true",
        help="Require real data/demo/* files on disk when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--require-bundled-resources",
        action="store_true",
        help="Require nsis_e2e production mode (--no-repo-root-env + isolated --runtime-dir) when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--require-standalone-embedded",
        action="store_true",
        help="Require standalone embedded NSIS + PyInstaller sidecar + 4 embedded models when verifying an E2E attestation.",
    )
    parser.add_argument(
        "--require-clean-machine-e2e",
        action="store_true",
        help="Require clean CI runner attestation_environment and standalone_verified=True.",
    )
    parser.add_argument(
        "--require-stable-windows-e2e",
        action="store_true",
        help="Require signed independent VM evidence with the Windows 10/11 acceptance checks.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Optional output path to write JSON verification report.",
    )
    return parser


def _parse_repo_private_flag(raw: Optional[str]) -> Optional[bool]:
    if raw is None:
        return None
    norm = raw.strip().lower()
    if norm == "true":
        return True
    if norm == "false":
        return False
    return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    evidence_sha = (
        os.environ.get(args.evidence_sha256_env.strip(), "")
        if args.evidence_sha256_env and args.evidence_sha256_env.strip()
        else None
    )
    repo_is_private = _parse_repo_private_flag(args.repo_private)

    if args.verify_distribution_permission is not None:
        try:
            perm_report = verify_distribution_permission(
                args.verify_distribution_permission,
                is_public_release=args.public_release,
                target_channel=args.target_channel,
                repo_is_private=repo_is_private,
                root=args.root,
                expected_evidence_sha256=evidence_sha,
                require_evidence_hash=args.require_evidence_hash,
            )
        except Exception as exc:
            sys.stderr.write(f"[DISTRIBUTION PERMISSION BLOCKED] {exc}\n")
            return 1
        _emit_json(perm_report, args.output_json)
        return 0

    if args.stage_embedded_dir is not None:
        try:
            staged_emb = stage_embedded_bundle(
                destination=args.stage_embedded_dir,
                root=args.root,
                runtime_dir=args.runtime_dir,
                distribution_scope=args.distribution_scope,
                target_channel=args.target_channel or "local_offline",
                repo_is_private=repo_is_private,
                expected_evidence_sha256=evidence_sha,
            )
        except Exception as exc:
            sys.stderr.write(f"[EMBEDDED ARTIFACTS BLOCKED] {exc}\n")
            return 1
        _emit_json(staged_emb, args.output_json)
        return 0

    if args.stage_dir is not None:
        try:
            staged = stage_companion_bundle(
                destination=args.stage_dir,
                root=args.root,
                runtime_dir=args.runtime_dir,
            )
        except Exception as exc:
            sys.stderr.write(f"[COMPANION ARTIFACTS BLOCKED] {exc}\n")
            return 1
        _emit_json(staged, args.output_json)
        return 0

    if args.package_bundle is not None:
        try:
            packaged = package_companion_bundle(
                archive_path=args.package_bundle,
                root=args.root,
                runtime_dir=args.runtime_dir,
            )
        except Exception as exc:
            sys.stderr.write(f"[COMPANION PACKAGE BLOCKED] {exc}\n")
            return 1
        _emit_json(packaged, args.output_json)
        return 0

    if any(
        val is not None and str(val).strip() != ""
        for val in (
            args.install_bundle_dir,
            args.install_bundle_archive,
            args.install_bundle_url,
            args.install_bundle_run_id,
        )
    ):
        try:
            installed = install_companion_bundle(
                root=args.root,
                runtime_dir=args.runtime_dir,
                bundle_dir=args.install_bundle_dir,
                bundle_archive=args.install_bundle_archive,
                bundle_url=args.install_bundle_url,
                artifact_run_id=args.install_bundle_run_id,
                artifact_name=args.install_bundle_artifact_name,
                github_repo=args.github_repo,
                expected_bundle_sha256=args.expect_bundle_sha256,
                allowed_hosts=args.allowed_hosts,
                token_env_var=args.token_env,
            )
        except Exception as exc:
            sys.stderr.write(f"[COMPANION INSTALL FAILED] {exc}\n")
            return 1
        _emit_json(installed, args.output_json)
        return 0

    if args.issue_vm_challenge:
        if args.installer_path is None or not args.expect_sidecar_sha256:
            sys.stderr.write(
                "[VM CHALLENGE FAILED] --issue-vm-challenge requires --installer-path and --expect-sidecar-sha256.\n"
            )
            return 1
        try:
            challenge_doc = issue_vm_target_challenge(
                installer_path=args.installer_path,
                expected_sidecar_sha256=args.expect_sidecar_sha256,
                root=args.root,
                compiled_exe_path=args.compiled_exe,
                require_clean_git=args.require_clean_git,
                ttl_seconds=args.challenge_ttl_seconds,
                vm_provenance_ref=args.vm_provenance_ref,
            )
        except Exception as exc:
            sys.stderr.write(f"[VM CHALLENGE FAILED] {exc}\n")
            return 1
        _emit_json(challenge_doc, args.output_json)
        return 0

    if args.sign_vm_witness:
        if (
            args.vm_challenge is None
            or args.verify_target_evidence is None
            or not args.vm_provenance_ref
        ):
            sys.stderr.write(
                "[VM WITNESS SIGN FAILED] --sign-vm-witness requires --vm-challenge, "
                "--verify-target-evidence, and --vm-provenance-ref.\n"
            )
            return 1
        try:
            witness_doc = sign_vm_witness_receipt(
                challenge_path=args.vm_challenge,
                target_evidence_path=args.verify_target_evidence,
                vm_provenance_ref=args.vm_provenance_ref,
                trusted_authority_id=args.trusted_authority_id,
                vm_witness_secret_env=args.vm_witness_secret_env,
            )
        except Exception as exc:
            sys.stderr.write(f"[VM WITNESS SIGN FAILED] {exc}\n")
            return 1
        _emit_json(witness_doc, args.output_json)
        return 0

    if args.verify_target_evidence is not None:
        if args.vm_challenge is None:
            sys.stderr.write(
                "[TARGET EVIDENCE VERIFICATION FAILED] --verify-target-evidence requires --vm-challenge.\n"
            )
            return 1
        try:
            if args.consumed_nonces_file is not None and args.output_json is not None:
                ledger = args.consumed_nonces_file.resolve()
                if args.output_json.resolve() in (
                    ledger,
                    _nonce_ledger_lock_path(ledger).resolve(),
                ):
                    raise RuntimeError(
                        "--output-json must be separate from the nonce ledger and lock."
                    )
            target_att = verify_vm_target_evidence(
                target_evidence_path=args.verify_target_evidence,
                challenge_path=args.vm_challenge,
                root=args.root,
                installer_path=args.installer_path,
                sums_file=args.sums_file,
                compiled_exe_path=args.compiled_exe,
                expected_sidecar_sha256=args.expect_sidecar_sha256,
                require_clean_git=args.require_clean_git,
                clean_machine_e2e=args.clean_machine_e2e,
                vm_witness_path=args.vm_witness,
                vm_witness_secret_env=args.vm_witness_secret_env,
                consumed_nonces_file=args.consumed_nonces_file,
            )
        except Exception as exc:
            sys.stderr.write(f"[TARGET EVIDENCE VERIFICATION FAILED] {exc}\n")
            return 1
        _emit_json(target_att, args.output_json)
        return 0

    if args.verify_attestation is not None:
        try:
            att_report = verify_e2e_attestation(
                args.verify_attestation,
                root=args.root,
                expect_commit=args.expect_commit,
                expect_installer_sha256=args.expect_installer_sha256,
                expect_sidecar_sha256=args.expect_sidecar_sha256,
                require_nsis_e2e=args.require_nsis_e2e,
                require_demo_files=args.require_demo_files,
                demo_root=args.runtime_dir,
                require_bundled_resources=args.require_bundled_resources,
                require_standalone_embedded=args.require_standalone_embedded,
                require_clean_machine_e2e=args.require_clean_machine_e2e,
                require_stable_windows_e2e=args.require_stable_windows_e2e,
                verify_github_run=args.verify_github_run,
                verify_vm_witness=args.verify_vm_witness,
                vm_witness_secret_env=args.vm_witness_secret_env,
                token_env_var=args.token_env,
            )
        except Exception as exc:
            sys.stderr.write(f"[E2E ATTESTATION VERIFICATION FAILED] {exc}\n")
            return 1
        _emit_json(att_report, args.output_json)
        return 0

    if args.verify_nsis_only:
        if args.installer_path is None:
            sys.stderr.write("[NSIS E2E FAILED] --verify-nsis-only requires --installer-path.\n")
            return 1
        try:
            nsis_report = verify_nsis_installer_e2e(
                installer_path=args.installer_path,
                root=args.root,
                sums_file=args.sums_file,
                compiled_exe_path=args.compiled_exe,
                runtime_dir=args.runtime_dir,
                pass_repo_root_env=not args.no_repo_root_env,
                standalone_embedded=args.standalone_embedded,
                expected_sidecar_sha256=args.expect_sidecar_sha256,
            )
        except Exception as exc:
            sys.stderr.write(f"[NSIS E2E FAILED] {exc}\n")
            return 1
        _emit_json(nsis_report, args.output_json)
        return 0

    if args.verify_e2e:
        try:
            e2e_report = run_four_model_e2e_verification(
                root=args.root,
                runtime_dir=args.runtime_dir,
                pass_repo_root_env=not args.no_repo_root_env,
                installer_path=args.installer_path,
                sums_file=args.sums_file,
                compiled_exe_path=args.compiled_exe,
                standalone_embedded=args.standalone_embedded,
                expected_sidecar_sha256=args.expect_sidecar_sha256,
                clean_machine_e2e=args.clean_machine_e2e,
                require_clean_git=args.require_clean_git,
                github_repo=args.github_repo,
                github_run_id=args.github_run_id,
                token_env_var=args.token_env,
                independent_vm_evidence=args.independent_vm_evidence,
            )
        except Exception as exc:
            sys.stderr.write(f"[E2E VERIFICATION BLOCKED/FAILED] {exc}\n")
            return 1
        _emit_json(e2e_report, args.output_json)
        return 0

    summary = (
        verify_companion_artifacts(
            root=args.root,
            expected_ood_gate_sha256=args.expect_ood_gate_sha256,
        )
        if args.runtime_dir is None
        else verify_companion_artifacts(
            root=args.root,
            runtime_dir=args.runtime_dir,
            expected_ood_gate_sha256=args.expect_ood_gate_sha256,
        )
    )
    _emit_json(summary, args.output_json)
    return 0 if summary["overall_status"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
