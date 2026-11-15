#!/usr/bin/env python3
"""Audit and stage NetFlow Sentinel v0.6.0 companion model artifacts on Windows.

Verifies SHA-256 digests and manifest linkage across the preprocessor, 4 verified
ML models (Random Forest, XGBoost, Isolation Forest, Autoencoder), and Validation
demo CSV bundle without copying or bundling raw NF-UNSW-NB15-v3 dataset files.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOCAL_SRC = PROJECT_ROOT / "src"
if str(_LOCAL_SRC) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SRC))

from network_anomaly.inference.predict import (  # noqa: E402
    _sha256_file,
    load_verified_model,
    load_verified_preprocessor,
)

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
            Path("artifacts/models/isolation_forest/model_config.json"),
            Path("artifacts/models/isolation_forest/threshold.json"),
            Path("artifacts/models/isolation_forest/training_metadata.json"),
        ],
    ),
    "autoencoder": (
        Path("artifacts/models/autoencoder/autoencoder_model.joblib"),
        [
            Path("reports/models/autoencoder_manifest.json"),
            Path("artifacts/models/autoencoder/autoencoder_manifest.json"),
            Path("artifacts/models/autoencoder/model_config.json"),
            Path("artifacts/models/autoencoder/threshold.json"),
        ],
    ),
}

PREPROCESSOR_REL = Path("artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib")
PREPROCESSOR_MANIFEST_REL = Path(
    "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json"
)
SPLIT_MANIFEST_REL = Path("data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json")
DEMO_FILES_REL: Tuple[Path, ...] = (
    Path("data/demo/demo_flows.csv"),
    Path("data/demo/demo_labels.csv"),
    Path("data/demo/demo_manifest.json"),
)


def _select_existing_manifest(root: Path, candidates: List[Path]) -> Optional[Path]:
    for rel in candidates:
        candidate = root / rel
        if candidate.is_file():
            return candidate
    return root / candidates[0]


def verify_companion_artifacts(root: Path = PROJECT_ROOT) -> Dict[str, Any]:
    """Verify preprocessor, all 4 model bundles, and demo files fail-closed."""
    resolved_root = Path(root).resolve()
    prep_path = resolved_root / PREPROCESSOR_REL
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
        model_abs = resolved_root / model_rel
        manifest_abs = _select_existing_manifest(resolved_root, support_rels)
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
            ready_models.append(model_key)
            models_status[model_key] = {
                "ready": True,
                "status": "READY",
                "path": model_rel.as_posix(),
                "manifest_path": manifest_abs.relative_to(resolved_root).as_posix(),
                "sha256": model_meta.get("model_artifact_sha256") or _sha256_file(model_abs),
                "run_id": model_meta.get("run_id"),
                "reason": None,
            }
            staged_files.append(model_rel)
            for rel in support_rels:
                if (resolved_root / rel).is_file():
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
    for rel in DEMO_FILES_REL:
        abs_path = resolved_root / rel
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

    all_four_ready = prep_status["ready"] and len(ready_models) == len(MODEL_SPECS) and demo_ready
    unique_staged = sorted({p.as_posix() for p in staged_files})

    return {
        "overall_status": "READY" if all_four_ready else "BLOCKED / NOT READY",
        "ready_models": ready_models,
        "preprocessor": prep_status,
        "models": models_status,
        "demo": demo_status,
        "demo_ready": demo_ready,
        "companion_files": unique_staged,
    }


def stage_companion_bundle(
    destination: Path,
    root: Path = PROJECT_ROOT,
) -> Dict[str, Any]:
    """Copy verified runtime companion artifacts (no raw dataset) + SHA256SUMS."""
    summary = verify_companion_artifacts(root=root)
    if summary["overall_status"] != "READY":
        raise RuntimeError(
            "Cannot stage companion bundle while artifacts are incomplete or unverified: "
            f"ready_models={summary['ready_models']}, demo_ready={summary['demo_ready']}"
        )

    resolved_root = Path(root).resolve()
    dest_dir = Path(destination).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    checksum_lines: List[str] = []
    for rel_str in summary["companion_files"]:
        src = resolved_root / rel_str
        dst = dest_dir / rel_str
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        checksum = _sha256_file(dst)
        checksum_lines.append(f"{checksum}  {rel_str}")

    sums_path = dest_dir / "COMPANION_SHA256SUMS.txt"
    sums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    return {
        **summary,
        "destination": str(dest_dir),
        "checksums_file": str(sums_path),
        "staged_file_count": len(checksum_lines),
    }


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
        "--stage-dir",
        type=Path,
        default=None,
        help="Optional directory to stage verified companion files + COMPANION_SHA256SUMS.txt.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.stage_dir is not None:
        try:
            staged = stage_companion_bundle(destination=args.stage_dir, root=args.root)
        except Exception as exc:
            sys.stderr.write(f"[COMPANION ARTIFACTS BLOCKED] {exc}\n")
            return 1
        print(json.dumps(staged, indent=2))
        return 0

    summary = verify_companion_artifacts(root=args.root)
    print(json.dumps(summary, indent=2))
    return 0 if summary["overall_status"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
