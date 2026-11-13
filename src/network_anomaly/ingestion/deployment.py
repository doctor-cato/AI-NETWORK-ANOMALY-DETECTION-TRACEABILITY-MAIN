"""Model packaging, verification, and deployment readiness contract (Issue #46)."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from network_anomaly.config import ARTIFACTS, PROJECT_ROOT


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class DeploymentReadinessReport:
    """Report describing backend model and preprocessor startup readiness."""

    is_ready: bool
    model_artifact_path: str
    model_status: str  # "READY", "MISSING", "HASH_MISMATCH", "UNVERIFIED"
    preprocessor_status: str
    observed_model_sha256: Optional[str] = None
    expected_model_sha256: Optional[str] = None
    observed_prep_sha256: Optional[str] = None
    expected_prep_sha256: Optional[str] = None
    blockers: List[str] = field(default_factory=list)
    environment_info: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "is_ready": self.is_ready,
            "model_status": self.model_status,
            "preprocessor_status": self.preprocessor_status,
            "blockers": self.blockers,
            "observed_model_sha256": self.observed_model_sha256,
            "expected_model_sha256": self.expected_model_sha256,
            "observed_prep_sha256": self.observed_prep_sha256,
            "expected_prep_sha256": self.expected_prep_sha256,
            "environment_info": self.environment_info,
        }


def check_deployment_readiness(
    model_artifact_path: Optional[Path] = None,
    model_manifest_path: Optional[Path] = None,
    preprocessor_artifact_path: Optional[Path] = None,
    preprocessor_manifest_path: Optional[Path] = None,
) -> DeploymentReadinessReport:
    """Check startup readiness and artifact integrity for the inference deployment."""
    m_art = model_artifact_path or (
        ARTIFACTS / "models" / "random_forest" / "random_forest_baseline.joblib"
    )
    m_man = model_manifest_path or (
        PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
    )
    p_art = preprocessor_artifact_path or (
        ARTIFACTS / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    )
    p_man = preprocessor_manifest_path or (
        PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    )

    blockers: List[str] = []
    model_status = "READY"
    prep_status = "READY"
    obs_m_sha = None
    exp_m_sha = None
    obs_p_sha = None
    exp_p_sha = None

    # 1. Model check
    if not m_art.exists():
        model_status = "MISSING"
        blockers.append(f"Model artifact not found at {m_art}")
    elif not m_man.exists():
        model_status = "MANIFEST_MISSING"
        blockers.append(f"Model manifest not found at {m_man}")
    else:
        try:
            with open(m_man, "r", encoding="utf-8") as f:
                m_data = json.load(f)
            exp_m_sha = m_data.get("model_artifact_sha256")
            obs_m_sha = _sha256_file(m_art)
            if exp_m_sha and obs_m_sha != exp_m_sha:
                model_status = "HASH_MISMATCH"
                blockers.append(
                    f"Model SHA-256 mismatch: expected {exp_m_sha}, observed {obs_m_sha}"
                )
        except Exception as e:
            model_status = "ERROR"
            blockers.append(f"Error validating model manifest: {e}")

    # 2. Preprocessor check
    if not p_art.exists():
        prep_status = "MISSING"
        blockers.append(f"Preprocessor artifact not found at {p_art}")
    elif not p_man.exists():
        prep_status = "MANIFEST_MISSING"
        blockers.append(f"Preprocessor manifest not found at {p_man}")
    else:
        try:
            with open(p_man, "r", encoding="utf-8") as f:
                p_data = json.load(f)
            exp_p_sha = p_data.get("artifact_sha256") or p_data.get("preprocessor_artifact_sha256")
            obs_p_sha = _sha256_file(p_art)
            if exp_p_sha and obs_p_sha != exp_p_sha:
                prep_status = "HASH_MISMATCH"
                blockers.append(
                    f"Preprocessor SHA-256 mismatch: expected {exp_p_sha}, observed {obs_p_sha}"
                )
        except Exception as e:
            prep_status = "ERROR"
            blockers.append(f"Error validating preprocessor manifest: {e}")

    is_ready = len(blockers) == 0

    return DeploymentReadinessReport(
        is_ready=is_ready,
        model_artifact_path=str(m_art),
        model_status=model_status,
        preprocessor_status=prep_status,
        observed_model_sha256=obs_m_sha,
        expected_model_sha256=exp_m_sha,
        observed_prep_sha256=obs_p_sha,
        expected_prep_sha256=exp_p_sha,
        blockers=blockers,
        environment_info={
            "python_version": sys.version,
            "platform": sys.platform,
        },
    )
