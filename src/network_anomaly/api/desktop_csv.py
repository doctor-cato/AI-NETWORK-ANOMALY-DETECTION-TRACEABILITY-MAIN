"""Desktop CSV inspection, batch inference, Ground Truth evaluation, and export workflows.

Reuses ApiService, validate_inference_input, TrainOnlyPreprocessor, OODValidator,
FeatureCompatibilityEvaluator, InferenceEligibilityGate, and evaluation metrics
without reimplementing ML preprocessing or scoring logic.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import threading
import uuid
import zlib
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd

from network_anomaly.api.schemas import (
    CANONICAL_MODEL_KEYS,
    AttackBreakdownRow,
    BehavioralSummarySchema,
    BehavioralTopItem,
    CompatibilityGateSummarySchema,
    CsvAnalyzeResponse,
    CsvEvaluateResponse,
    CsvExportRequest,
    CsvExportResponse,
    CsvFlowPredictionItem,
    CsvInspectResponse,
    CsvTimelineItem,
    ModelStatusItem,
    OodSummarySchema,
    canonicalize_model_name,
)
from network_anomaly.api.service import ApiService, ModelNotReadyError
from network_anomaly.config import PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.evaluation.metrics import (
    compute_attack_category_breakdown,
    compute_metrics,
)
from network_anomaly.inference.predict import _sha256_file, validate_inference_input
from network_anomaly.ingestion.compatibility import (
    DEFAULT_BENCHMARK_REGISTRY,
    FeatureCompatibilityEvaluator,
)
from network_anomaly.ingestion.gate import InferenceEligibilityGate
from network_anomaly.ingestion.ood import OODReport, OODValidator
from network_anomaly.preprocessing.pipeline import audit_column_tokens

MAX_CSV_FILE_BYTES = 100 * 1024 * 1024

_NON_ATTRIBUTION_NOTICE = (
    "Behavioral statistics summarize NetFlow telemetry metadata only "
    "(IPV4_SRC_ADDR, IPV4_DST_ADDR, L4_SRC_PORT, L4_DST_PORT, FLOW_START_MILLISECONDS). "
    "These columns are strictly excluded from the 47 ML features and do not attribute "
    "attacker identity."
)

_SECURITY_NOTICE = (
    "Local security posture (#26): Localhost-only FastAPI (127.0.0.1), fail-closed "
    "SHA-256 artifact checks, and safe CSV path validation. "
    "Adaptive rotation & security response (#27) runs in DRY-RUN SIMULATION / RECOMMENDED "
    "mode only (executed=false; never invokes firewall, PowerShell, or OS commands), while "
    "production AES-256-GCM keyring encryption and live automatic rotation remain DEFERRED."
)

_MODEL_DISPLAY_META: Dict[str, Tuple[str, str, str]] = {
    "random_forest": ("Random Forest", "RandomForest", "attack_probability"),
    "xgboost": ("XGBoost", "XGBoost", "attack_probability"),
    "isolation_forest": ("Isolation Forest", "IsolationForest", "anomaly_score_unsupervised"),
    "autoencoder": ("Autoencoder", "Autoencoder", "reconstruction_error"),
}

_SENSITIVE_SYSTEM_PREFIXES = (
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\system",
    "c:\\windows\\boot",
    "c:\\program files",
    "/system",
    "/etc",
    "/usr/bin",
    "/bin",
    "/sbin",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_sensitive_system_path(resolved: Path) -> bool:
    norm = str(resolved).replace("/", os.sep).lower()
    for prefix in _SENSITIVE_SYSTEM_PREFIXES:
        pref_norm = prefix.replace("/", os.sep).lower()
        if norm == pref_norm or norm.startswith(pref_norm + os.sep):
            return True
    return False


def _is_unc_or_network_path(raw_path: str) -> bool:
    stripped = raw_path.strip()
    return stripped.startswith(("\\\\", "//"))


def _enforce_allowed_csv_roots(resolved: Path) -> None:
    """Enforce optional NETWORK_ANOMALY_ALLOWED_CSV_ROOTS allowlist when configured."""
    raw_roots = os.environ.get("NETWORK_ANOMALY_ALLOWED_CSV_ROOTS", "").strip()
    if not raw_roots:
        return
    roots = [
        Path(entry.strip()).expanduser().resolve(strict=False)
        for entry in raw_roots.split(os.pathsep)
        if entry.strip()
    ]
    if not roots:
        return
    if not any(resolved == root or resolved.is_relative_to(root) for root in roots):
        raise ValueError("CSV path is outside configured NETWORK_ANOMALY_ALLOWED_CSV_ROOTS.")


def validate_safe_csv_path(raw_path: str, *, max_bytes: int = MAX_CSV_FILE_BYTES) -> Path:
    """Validate an existing local CSV input path fail-closed (#26)."""
    if not isinstance(raw_path, str) or not raw_path.strip() or "\x00" in raw_path:
        raise ValueError("Invalid CSV file path.")
    if _is_unc_or_network_path(raw_path):
        raise ValueError("UNC or network share CSV paths are blocked (offline local-only policy).")

    candidate = Path(raw_path.strip()).expanduser()
    if candidate.suffix.lower() != ".csv":
        raise ValueError(f"Only .csv files are permitted, got {candidate.suffix!r}.")

    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"CSV file does not exist or cannot be resolved: {exc}") from exc

    if _is_sensitive_system_path(resolved):
        raise ValueError("Access to protected system directory is blocked.")
    _enforce_allowed_csv_roots(resolved)

    if not resolved.is_file():
        raise ValueError(f"Path is not a regular file: '{resolved}'")

    size = resolved.stat().st_size
    if size <= 0:
        raise ValueError("CSV file is empty (0 bytes).")
    if size > max_bytes:
        raise ValueError(f"CSV file exceeds maximum desktop limit ({size} > {max_bytes} bytes).")
    return resolved


def validate_safe_export_path(
    raw_path: str,
    source_csv_path: Optional[str] = None,
    *,
    expected_suffix: str = ".csv",
) -> Path:
    """Validate a destination path and companion metadata path without overwriting input (#26)."""
    if not isinstance(raw_path, str) or not raw_path.strip() or "\x00" in raw_path:
        raise ValueError("Invalid export file path.")
    if _is_unc_or_network_path(raw_path):
        raise ValueError(
            "UNC or network share export paths are blocked (offline local-only policy)."
        )

    candidate = Path(raw_path.strip()).expanduser()
    req_suffix = expected_suffix.lower()
    if candidate.suffix.lower() != req_suffix:
        raise ValueError(f"Export output path must end with '{req_suffix}'.")

    resolved = candidate.resolve(strict=False)
    parent_resolved = resolved.parent.resolve(strict=False)
    meta_resolved = resolved.with_suffix(".metadata.json").resolve(strict=False)
    for target in (resolved, meta_resolved, parent_resolved):
        if _is_sensitive_system_path(target):
            raise ValueError("Exporting into a protected system directory is blocked.")
    for target in (resolved, meta_resolved):
        if target.exists() and target.is_dir():
            raise ValueError(f"Export path resolves to a directory: '{target}'")
    _enforce_allowed_csv_roots(resolved)

    if source_csv_path:
        src_resolved = Path(source_csv_path.strip()).expanduser().resolve(strict=False)
        if resolved == src_resolved or meta_resolved == src_resolved:
            raise ValueError("Refusing to overwrite the input CSV file during export.")

    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def _atomic_write_text(target: Path, content: str) -> None:
    """Write text atomically to `target` using a same-directory temporary file and os.replace."""
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=target.parent,
            prefix=f".{target.stem}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
        tmp_path = None
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def _audit_and_coerce_ml_matrix(X_ordered: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """Audit ML columns via canonical token rules and count all non-finite cells (NaN, Inf, tokens)."""
    cleaned_df = X_ordered.copy()
    total_non_finite = 0
    for col in cleaned_df.columns:
        audit_counts, cleaned_array = audit_column_tokens(cleaned_df[col], str(col))
        total_non_finite += int(audit_counts["total_non_finite"])
        cleaned_df[col] = cleaned_array
    return cleaned_df, total_non_finite


def _optional_int(val: Any) -> Optional[int]:
    if val is None or isinstance(val, bool):
        return None
    try:
        num = float(val)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(num):
        return None
    return int(round(num))


def _optional_float(val: Any) -> Optional[float]:
    if val is None or isinstance(val, bool):
        return None
    try:
        num = float(val)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(num):
        return None
    return num


def _optional_str(val: Any) -> Optional[str]:
    if val is None or (isinstance(val, float) and not math.isfinite(val)):
        return None
    text = str(val).strip()
    if not text or text.lower() in {"nan", "none", "<na>"}:
        return None
    return text


def _format_ms_iso(ms: Optional[int]) -> Optional[str]:
    if ms is None:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _sanitize_row_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert numpy/pandas scalars and NaN/Inf into JSON-safe Python primitives."""
    cleaned: Dict[str, Any] = {}
    for k, v in row.items():
        key = str(k)
        if v is None:
            cleaned[key] = None
        elif isinstance(v, (bool, np.bool_)):
            cleaned[key] = bool(v)
        elif isinstance(v, (int, np.integer)):
            cleaned[key] = int(v)
        elif isinstance(v, (float, np.floating)):
            fv = float(v)
            cleaned[key] = fv if math.isfinite(fv) else None
        else:
            cleaned[key] = str(v) if pd.notna(v) else None
    return cleaned


def _top_counts(values: List[str], total_rows: int, limit: int = 5) -> List[BehavioralTopItem]:
    if not values or total_rows <= 0:
        return []
    counts = Counter(values)
    return [
        BehavioralTopItem(key=k, count=int(c), share=round(float(c) / float(total_rows), 4))
        for k, c in counts.most_common(limit)
    ]


def compute_netflow_behavioral_summary(df: pd.DataFrame) -> BehavioralSummarySchema:
    """Compute descriptive statistics solely from NetFlow metadata columns (#28)."""
    n_rows = len(df)
    src_ips = (
        [_optional_str(v) for v in df["IPV4_SRC_ADDR"].tolist()]
        if "IPV4_SRC_ADDR" in df.columns
        else []
    )
    dst_ips = (
        [_optional_str(v) for v in df["IPV4_DST_ADDR"].tolist()]
        if "IPV4_DST_ADDR" in df.columns
        else []
    )
    src_ports = (
        [_optional_int(v) for v in df["L4_SRC_PORT"].tolist()]
        if "L4_SRC_PORT" in df.columns
        else []
    )
    dst_ports = (
        [_optional_int(v) for v in df["L4_DST_PORT"].tolist()]
        if "L4_DST_PORT" in df.columns
        else []
    )
    protocols = (
        [_optional_int(v) for v in df["PROTOCOL"].tolist()] if "PROTOCOL" in df.columns else []
    )

    clean_src_ips = [s for s in src_ips if s is not None]
    clean_dst_ips = [s for s in dst_ips if s is not None]
    clean_src_ports = [str(p) for p in src_ports if p is not None]
    clean_dst_ports = [str(p) for p in dst_ports if p is not None]
    clean_protos = [str(p) for p in protocols if p is not None]

    start_vals = (
        [
            t
            for t in (_optional_int(v) for v in df["FLOW_START_MILLISECONDS"].tolist())
            if t is not None
        ]
        if "FLOW_START_MILLISECONDS" in df.columns
        else []
    )
    end_vals = (
        [
            t
            for t in (_optional_int(v) for v in df["FLOW_END_MILLISECONDS"].tolist())
            if t is not None
        ]
        if "FLOW_END_MILLISECONDS" in df.columns
        else []
    )

    win_start = min(start_vals) if start_vals else None
    win_end = max(end_vals) if end_vals else (max(start_vals) if start_vals else None)
    duration_ms = (
        max(0, win_end - win_start) if (win_start is not None and win_end is not None) else None
    )

    present_trace = [c for c in TRACE_METADATA_COLUMNS if c in df.columns]
    return BehavioralSummarySchema(
        total_flows=n_rows,
        unique_src_ips=len(set(clean_src_ips)),
        unique_dst_ips=len(set(clean_dst_ips)),
        unique_src_ports=len(set(clean_src_ports)),
        unique_dst_ports=len(set(clean_dst_ports)),
        time_window_start_ms=win_start,
        time_window_end_ms=win_end,
        duration_ms=duration_ms,
        top_src_ips=_top_counts(clean_src_ips, n_rows),
        top_dst_ips=_top_counts(clean_dst_ips, n_rows),
        top_dst_ports=_top_counts(clean_dst_ports, n_rows),
        protocol_counts=_top_counts(clean_protos, n_rows),
        excluded_from_ml_features=present_trace,
        non_attribution_notice=_NON_ATTRIBUTION_NOTICE,
    )


def compute_deterministic_risk_score(
    *,
    is_ood_flagged: bool,
    score_type: str,
    score_direction: str,
    attack_probability: Optional[float],
    raw_anomaly_score: Optional[float],
    decision_threshold: Optional[float],
    slope: float = 12.0,
) -> Tuple[Optional[float], str]:
    """Compute a deterministic risk priority score in [0, 100] fail-closed (#32).

    Returns (None, "ABSTAINED_OOD") for OOD-flagged rows so synthetic risk scores
    are never fabricated when telemetry violates invariants or abstains.
    Raises ValueError on non-finite numeric score/threshold inputs.
    """
    if is_ood_flagged:
        return None, "ABSTAINED_OOD"

    def _check_finite(val: float, name: str) -> float:
        if isinstance(val, bool) or not math.isfinite(float(val)):
            raise ValueError(f"Non-finite value for '{name}': {val!r}")
        return float(val)

    prob: Optional[float] = None
    if attack_probability is not None:
        p = _check_finite(attack_probability, "attack_probability")
        prob = max(0.0, min(1.0, p))
    elif raw_anomaly_score is not None and decision_threshold is not None:
        raw_val = _check_finite(raw_anomaly_score, "raw_anomaly_score")
        thresh_val = _check_finite(decision_threshold, "decision_threshold")
        # For Isolation Forest: lower raw score => more anomalous => threshold - raw > 0.
        if score_direction == "lower_is_more_anomalous":
            margin = thresh_val - raw_val
        else:
            margin = raw_val - thresh_val
        z = max(-30.0, min(30.0, slope * margin))
        prob = 1.0 / (1.0 + math.exp(-z))
    else:
        return None, "UNAVAILABLE"

    score = round(100.0 * prob, 2)
    if score >= 80.0:
        tier = "CRITICAL"
    elif score >= 50.0:
        tier = "HIGH"
    elif score >= 25.0:
        tier = "MEDIUM"
    else:
        tier = "LOW"
    return score, tier


def _audit_desktop_ood(df_for_ood: pd.DataFrame) -> Tuple[OODReport, OODReport]:
    """Return `(phys_ood_report, raw_ood_report)` separating physical violations from MIN_TTL == 0."""
    phys_report = OODValidator(check_shortcut_drift=True, reject_zero_ttl=False).audit_dataframe(
        df_for_ood
    )
    raw_report = OODValidator(check_shortcut_drift=True, reject_zero_ttl=True).audit_dataframe(
        df_for_ood
    )
    return phys_report, raw_report


def _ood_to_schema(
    phys_report: OODReport,
    abstain_report: Optional[OODReport] = None,
) -> OodSummarySchema:
    """Serialize OOD summary keeping physical invariant violations distinct from MIN_TTL == 0."""
    totals = abstain_report if abstain_report is not None else phys_report
    return OodSummarySchema(
        total_rows=phys_report.total_rows,
        has_ood_warning=totals.has_ood_warning,
        hard_violation_count=phys_report.hard_violation_count,
        shortcut_shift_count=phys_report.shortcut_shift_count,
        zero_ttl_count=totals.zero_ttl_count,
        affected_rows_count=totals.affected_rows_count,
        shortcut_drift_ratio=round(phys_report.shortcut_drift_ratio, 4),
        zero_ttl_ratio=round(totals.zero_ttl_ratio, 4),
        abstention_rate=round(totals.abstention_rate, 4),
        prediction_coverage=round(totals.prediction_coverage, 4),
        ood_flags=list(totals.ood_flags),
        hard_violation_indices=list(phys_report.hard_violation_indices),
        zero_ttl_indices=list(totals.zero_ttl_indices),
        out_of_range_details=dict(phys_report.out_of_range_details),
    )


def collect_models_status(service: ApiService) -> List[ModelStatusItem]:
    """Return genuine readiness, artifact SHA-256, and threshold metadata for all 4 M6 models."""
    items: List[ModelStatusItem] = []
    for key in CANONICAL_MODEL_KEYS:
        display_name, model_type, semantics = _MODEL_DISPLAY_META[key]
        model_path, _prep_path, model_manifest, _prep_manifest = service._resolve_artifact_paths(
            key
        )
        try:
            pipeline = service._load_inference_pipeline(key)
            meta = pipeline.model_metadata if isinstance(pipeline.model_metadata, dict) else {}
            raw_manifest = (
                meta.get("raw_manifest") if isinstance(meta.get("raw_manifest"), dict) else {}
            )
            thresh = (
                meta.get("threshold")
                if meta.get("threshold") is not None
                else raw_manifest.get("threshold")
            )
            items.append(
                ModelStatusItem(
                    model_key=key,
                    display_name=display_name,
                    model_type=str(meta.get("model_type") or model_type),
                    ready=True,
                    status="READY",
                    artifact_path=str(model_path),
                    manifest_path=str(model_manifest) if model_manifest else None,
                    artifact_sha256=meta.get("model_artifact_sha256"),
                    run_id=raw_manifest.get("run_id") or meta.get("run_id"),
                    decision_threshold=_optional_float(thresh),
                    score_semantics=semantics,
                    reason=None,
                )
            )
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            items.append(
                ModelStatusItem(
                    model_key=key,
                    display_name=display_name,
                    model_type=model_type,
                    ready=False,
                    status="BLOCKED / NOT READY",
                    artifact_path=str(model_path),
                    manifest_path=str(model_manifest) if model_manifest else None,
                    artifact_sha256=None,
                    run_id=None,
                    decision_threshold=None,
                    score_semantics=semantics,
                    reason=str(exc),
                )
            )
    return items


def inspect_csv_file(
    service: ApiService,
    file_path: str,
    preview_limit: int = 20,
) -> CsvInspectResponse:
    """Validate CSV contract, exclude leakage targets/trace cols, run OOD & behavioral preview."""
    resolved = validate_safe_csv_path(file_path)
    file_sha256 = _sha256_file(resolved)
    df = pd.read_csv(resolved)
    if len(df) == 0:
        raise ValueError("CSV file contains 0 data rows.")

    missing = [col for col in ML_FEATURE_COLUMNS if col not in df.columns]
    if missing:
        input_cols = [str(c) for c in df.columns]
        extra_cols = [c for c in input_cols if c not in ML_FEATURE_COLUMNS]
        target_excluded = [c for c in extra_cols if c in TARGET_COLUMNS]
        trace_excluded = [c for c in extra_cols if c in TRACE_METADATA_COLUMNS]
        other_extra = [
            c for c in extra_cols if c not in TARGET_COLUMNS and c not in TRACE_METADATA_COLUMNS
        ]
        present_ml_cols = [col for col in ML_FEATURE_COLUMNS if col in df.columns]
        X_cleaned, non_finite_cells = _audit_and_coerce_ml_matrix(df[present_ml_cols])
        ml_feature_count = len(present_ml_cols)
    else:
        X_ordered, val_summary = validate_inference_input(df)
        X_cleaned, non_finite_cells = _audit_and_coerce_ml_matrix(X_ordered)
        target_excluded = list(val_summary["target_columns_excluded"])
        trace_excluded = list(val_summary["trace_metadata_excluded"])
        other_extra = list(val_summary["other_extra_columns_excluded"])
        ml_feature_count = int(val_summary["feature_count"])

    df_for_ood = df.assign(**{str(col): X_cleaned[col] for col in X_cleaned.columns})
    phys_ood_report, raw_ood_report = _audit_desktop_ood(df_for_ood)
    behavioral = compute_netflow_behavioral_summary(df)
    models_status = collect_models_status(service)

    preview_df = df.head(preview_limit)
    preview_rows = [_sanitize_row_dict(rec) for rec in preview_df.to_dict(orient="records")]

    return CsvInspectResponse(
        file_path=str(resolved),
        file_name=resolved.name,
        file_sha256=file_sha256,
        file_size_bytes=int(resolved.stat().st_size),
        row_count=int(len(df)),
        column_count=int(len(df.columns)),
        ml_feature_count=ml_feature_count,
        ml_features_valid=len(missing) == 0,
        missing_ml_features=missing,
        target_columns_excluded=target_excluded,
        trace_metadata_excluded=trace_excluded,
        other_extra_columns_excluded=other_extra,
        non_finite_feature_cells=non_finite_cells,
        ood_report=_ood_to_schema(phys_ood_report, abstain_report=raw_ood_report),
        behavioral_summary=behavioral,
        models_status=models_status,
        preview_columns=[str(c) for c in df.columns],
        preview_rows=preview_rows,
    )


def _row_id_sort_key(val: Union[int, str]) -> Tuple[int, int, str]:
    """Sort numeric/integer-string row_ids numerically before non-numeric strings."""
    if isinstance(val, int) and not isinstance(val, bool):
        return (0, val, str(val))
    text = str(val).strip()
    if text.lstrip("-").isdigit():
        return (0, int(text), text)
    return (1, 0, text)


def build_deterministic_evidence_timeline(
    items: List[CsvFlowPredictionItem],
) -> List[CsvTimelineItem]:
    """Order analyzed flows deterministically by (flow_start_ms asc, row_id asc) (#24)."""
    indexed = sorted(
        items,
        key=lambda item: (
            item.flow_start_ms is None,
            item.flow_start_ms if item.flow_start_ms is not None else 0,
            _row_id_sort_key(item.row_id),
            item.row_index,
        ),
    )
    timeline: List[CsvTimelineItem] = []
    for seq_idx, item in enumerate(indexed):
        src = f"{item.src_ip or '?'}:{item.src_port if item.src_port is not None else '?'}"
        dst = f"{item.dst_ip or '?'}:{item.dst_port if item.dst_port is not None else '?'}"
        score_desc = (
            f"prob={item.attack_probability:.4f}"
            if item.attack_probability is not None
            else (
                f"raw_score={item.raw_anomaly_score:.4f}"
                if item.raw_anomaly_score is not None
                else "score=N/A"
            )
        )
        ood_suffix = " [OOD ABSTAINED]" if item.is_ood_flagged else ""
        timeline.append(
            CsvTimelineItem(
                sequence_index=seq_idx,
                row_id=item.row_id,
                flow_start_ms=item.flow_start_ms,
                flow_end_ms=item.flow_end_ms,
                timestamp_iso=_format_ms_iso(item.flow_start_ms),
                src_ip=item.src_ip,
                dst_ip=item.dst_ip,
                src_port=item.src_port,
                dst_port=item.dst_port,
                predicted_class=item.predicted_class,
                risk_score=item.risk_score,
                risk_level=item.risk_level,
                is_ood_flagged=item.is_ood_flagged,
                evidence_summary=(
                    f"{src} -> {dst} | {item.predicted_class} ({score_desc}) | "
                    f"risk={item.risk_level}{ood_suffix}"
                ),
            )
        )
    return timeline


CANONICAL_NF_UNSW_NB15_V3_SHA256 = (
    "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
)
CANONICAL_NF_UNSW_NB15_V3_ROW_COUNT = 2_365_424
CANONICAL_SPLIT_MANIFEST_PATH = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"
CANONICAL_SPLIT_MANIFEST_SHA256 = "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88"
CANONICAL_VALIDATION_TIME_START_MS = 1_424_238_433_382
CANONICAL_VALIDATION_TIME_END_MS = 1_424_250_496_133

# Repository-controlled trust anchor for canonical Validation-only demo subsets produced
# strictly by scripts/prepare_demo_dataset.py from the audited Validation partition.
TRUSTED_CANONICAL_VALIDATION_SUBSETS: Dict[str, Dict[str, Any]] = {
    "9fd2143223190e6c2b4bc6cf26b4a206cbd96baeb7242db5695c274ff8a4405b": {
        "dataset_name": "NF-UNSW-NB15-v3",
        "source_id": "source:nf-v3-canonical",
        "partition": "validation",
        "row_count": 200,
        "source_dataset_sha256": CANONICAL_NF_UNSW_NB15_V3_SHA256,
        "split_manifest_sha256": CANONICAL_SPLIT_MANIFEST_SHA256,
        "partition_indices_sha256": {
            "train": "a09ba1757484c65596a88fe22d5bd989a3cca60a01088364020e2f952b36c725",
            "validation": "7d41a71a2a154a46fec4a0095fb277007b6b1574727976ee6593e6d56b9400bf",
            "test": "63e2e081300955fe06835b0cf7405e07e53985ca3d84164e768be09116269d03",
        },
        "selected_indices_sha256": (
            "c95bf6a3c9270acc3b935a5a1394efa48cee4087b8bea9906f3e098c7680ea93"
        ),
        "train_overlap_count": 0,
        "test_overlap_count": 0,
    }
}


def _compute_indices_sha256(indices: Sequence[int]) -> str:
    """Compute canonical newline-terminated SHA-256 digest of 0-based source row indices."""
    payload = "\n".join(str(int(idx)) for idx in indices) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _has_untrusted_sibling_manifest(csv_path: Path) -> bool:
    """Return True if a self-declared manifest sits beside the CSV file."""
    parent = csv_path.parent
    candidates = [
        parent / "demo_manifest.json",
        parent / f"{csv_path.name}.manifest.json",
        parent / f"{csv_path.stem}.manifest.json",
        parent / f"{csv_path.stem}_manifest.json",
    ]
    return any(cand.is_file() for cand in candidates)


def _verify_canonical_demo_manifest(
    *,
    csv_path: Path,
    sha_norm: str,
    row_count: int,
    anchor: Dict[str, Any],
    split_manifest_path: Path,
    df: Optional[pd.DataFrame],
) -> Tuple[bool, str]:
    """Cross-verify a canonical demo_manifest.json against controlled repo trust anchors."""
    if int(row_count) != int(anchor["row_count"]):
        return (
            False,
            f"Canonical subset row count mismatch: expected {anchor['row_count']}, got {row_count}.",
        )

    if not split_manifest_path.is_file():
        return (
            False,
            f"Canonical split manifest trust anchor missing at '{split_manifest_path}'.",
        )
    actual_split_sha = _sha256_file(split_manifest_path).strip().lower()
    expected_split_sha = str(anchor["split_manifest_sha256"]).strip().lower()
    if actual_split_sha != expected_split_sha:
        return (
            False,
            "Canonical split manifest trust anchor SHA-256 mismatch; failing closed to unverified.",
        )

    demo_manifest_path = csv_path.parent / "demo_manifest.json"
    if not demo_manifest_path.is_file():
        return (
            False,
            "Missing companion demo_manifest.json required to verify Validation split lineage.",
        )
    try:
        manifest = json.loads(demo_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"Unreadable companion demo_manifest.json: {exc}"
    if not isinstance(manifest, dict):
        return False, "Companion demo_manifest.json is not a JSON object."

    if str(manifest.get("dataset_name", "")).strip() != str(anchor["dataset_name"]):
        return False, "Manifest dataset_name does not match canonical NF-UNSW-NB15-v3."

    if (
        str(manifest.get("source_dataset_sha256", "")).strip().lower()
        != str(anchor["source_dataset_sha256"]).lower()
    ):
        return False, "Manifest source_dataset_sha256 does not match canonical dataset digest."

    if str(manifest.get("split_manifest_sha256", "")).strip().lower() != expected_split_sha:
        return False, "Manifest split_manifest_sha256 does not match repository split manifest."

    anchor_part_hashes = anchor.get("partition_indices_sha256")
    manifest_part_hashes = manifest.get("partition_indices_sha256")
    if isinstance(anchor_part_hashes, dict):
        if not isinstance(manifest_part_hashes, dict):
            return False, "Manifest missing partition_indices_sha256 binding."
        for part_key, expected_part_sha in anchor_part_hashes.items():
            actual_part_sha = str(manifest_part_hashes.get(part_key, "")).strip().lower()
            if actual_part_sha != str(expected_part_sha).strip().lower():
                return (
                    False,
                    f"Manifest partition_indices_sha256[{part_key!r}] does not match trust anchor.",
                )

    outputs = manifest.get("outputs")
    demo_info = outputs.get("demo_flows_csv") if isinstance(outputs, dict) else None
    if not isinstance(demo_info, dict):
        return False, "Manifest missing outputs.demo_flows_csv section."

    manifest_csv_name = Path(str(demo_info.get("path", ""))).name
    if not manifest_csv_name or manifest_csv_name != csv_path.name:
        return (
            False,
            f"Manifest outputs.demo_flows_csv targets {manifest_csv_name!r}, not {csv_path.name!r}.",
        )
    if str(demo_info.get("sha256", "")).strip().lower() != sha_norm:
        return False, "Manifest outputs.demo_flows_csv.sha256 does not match CSV SHA-256."
    try:
        declared_rows = int(demo_info.get("row_count", -1))
    except (TypeError, ValueError):
        declared_rows = -1
    if declared_rows != int(row_count):
        return False, "Manifest outputs.demo_flows_csv.row_count does not match CSV row count."

    sampling = manifest.get("sampling")
    if not isinstance(sampling, dict):
        return False, "Manifest missing sampling provenance metadata."
    if str(sampling.get("partition", "")).strip().lower() != str(anchor["partition"]).lower():
        return (
            False,
            "Manifest sampling.partition must be 'validation' (Train/Test subsets prohibited).",
        )

    try:
        train_overlap = int(sampling.get("train_overlap_count"))
        test_overlap = int(sampling.get("test_overlap_count"))
    except (TypeError, ValueError):
        return False, "Manifest missing integer train_overlap_count / test_overlap_count."
    if train_overlap != 0 or test_overlap != 0:
        return False, "Manifest reports non-zero Train/Test partition overlap."

    raw_indices = sampling.get("source_row_indices")
    if not isinstance(raw_indices, list) or len(raw_indices) != int(row_count):
        return False, "Manifest source_row_indices length does not match CSV row count."
    parsed_indices: List[int] = []
    for item in raw_indices:
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            return False, "Manifest source_row_indices contains invalid row index."
        parsed_indices.append(item)
    if len(set(parsed_indices)) != len(parsed_indices):
        return False, "Manifest source_row_indices contains duplicate row indices."

    computed_indices_sha = _compute_indices_sha256(parsed_indices).lower()
    declared_indices_sha = str(sampling.get("selected_indices_sha256", "")).strip().lower()
    expected_indices_sha = str(anchor["selected_indices_sha256"]).strip().lower()
    if computed_indices_sha != declared_indices_sha or computed_indices_sha != expected_indices_sha:
        return False, "Manifest selected_indices_sha256 does not match trusted Validation indices."

    frame = df if df is not None else pd.read_csv(csv_path)
    if "row_id" not in frame.columns:
        return False, "Canonical subset CSV missing required 'row_id' trace column."
    try:
        csv_row_ids = [int(v) for v in frame["row_id"].tolist()]
    except (TypeError, ValueError):
        return False, "Canonical subset CSV contains non-integer 'row_id' values."
    if csv_row_ids != parsed_indices:
        return False, "CSV row_id sequence does not match manifest source_row_indices."

    if "FLOW_START_MILLISECONDS" in frame.columns:
        ts_vals = pd.to_numeric(frame["FLOW_START_MILLISECONDS"], errors="coerce")
        if ts_vals.isna().any():
            return False, "Canonical subset CSV has missing FLOW_START_MILLISECONDS timestamps."
        if bool(
            (ts_vals < CANONICAL_VALIDATION_TIME_START_MS).any()
            or (ts_vals > CANONICAL_VALIDATION_TIME_END_MS).any()
        ):
            return False, "CSV timestamps fall outside canonical Validation time boundaries."

    return (
        True,
        (
            "Verified canonical NF-UNSW-NB15-v3 Validation subset anchored to controlled "
            "provenance allowlist and repository split manifest (SHA-256, Validation row_id "
            "lineage, time bounds, and zero Train/Test overlap confirmed)."
        ),
    )


def resolve_csv_source_provenance(
    csv_path: Path,
    file_sha256: str,
    row_count: int,
    df: Optional[pd.DataFrame] = None,
    *,
    trusted_subsets: Optional[Dict[str, Dict[str, Any]]] = None,
    split_manifest_path: Optional[Path] = None,
) -> Tuple[str, bool, str]:
    """Verify CSV provenance against controlled trust anchors before granting benchmark identity.

    Separates file integrity, source dataset identity, partition identity, and benchmark evidence.
    A self-declared manifest sitting next to an arbitrary user-controlled CSV MUST NEVER elevate
    untrusted data to `source:nf-v3-canonical` or `MODEL_VALIDATED`.
    """
    sha_norm = file_sha256.strip().lower()
    if sha_norm == CANONICAL_NF_UNSW_NB15_V3_SHA256:
        if int(row_count) != CANONICAL_NF_UNSW_NB15_V3_ROW_COUNT:
            return (
                "source:nf-v3-unverified",
                False,
                (
                    f"Canonical dataset digest row count mismatch: expected "
                    f"{CANONICAL_NF_UNSW_NB15_V3_ROW_COUNT}, got {row_count}."
                ),
            )
        return (
            "source:nf-v3-canonical",
            True,
            "Verified full canonical NF-UNSW-NB15-v3 dataset SHA-256 and row count.",
        )

    eff_trusted = (
        TRUSTED_CANONICAL_VALIDATION_SUBSETS if trusted_subsets is None else trusted_subsets
    )
    eff_split_manifest = (
        CANONICAL_SPLIT_MANIFEST_PATH if split_manifest_path is None else split_manifest_path
    )

    anchor = eff_trusted.get(sha_norm)
    if anchor is not None:
        ok, reason = _verify_canonical_demo_manifest(
            csv_path=csv_path,
            sha_norm=sha_norm,
            row_count=row_count,
            anchor=anchor,
            split_manifest_path=eff_split_manifest,
            df=df,
        )
        if ok:
            return str(anchor.get("source_id", "source:nf-v3-canonical")), True, reason
        return (
            "source:nf-v3-unverified",
            False,
            f"Untrusted or tampered manifest rejected: {reason}",
        )

    if _has_untrusted_sibling_manifest(csv_path):
        return (
            "source:nf-v3-unverified",
            False,
            (
                "Unverified external CSV: self-declared sibling manifest ignored because CSV "
                f"SHA-256 ({sha_norm[:12]}...) is absent from the controlled canonical provenance "
                "trust anchor; MODEL_VALIDATED benchmark status is not granted."
            ),
        )

    return (
        "source:nf-v3-unverified",
        False,
        (
            f"Unverified external CSV ({sha_norm[:12]}...): no controlled canonical NF-UNSW-NB15-v3 "
            "SHA-256 or verified trust anchor found; MODEL_VALIDATED benchmark status is not granted."
        ),
    )


class _RawOodProxy(OODValidator):
    """Supplies pre-computed raw NetFlow OOD audit to InferenceEligibilityGate."""

    def __init__(self, report: OODReport) -> None:
        super().__init__(check_shortcut_drift=False, reject_zero_ttl=False)
        self._report = report

    def audit_dataframe(self, df: pd.DataFrame) -> OODReport:
        return self._report


def _evaluate_gate(
    *,
    canonical_model: str,
    pipeline: Any,
    df_raw: pd.DataFrame,
    X_ordered: pd.DataFrame,
    raw_ood_report: OODReport,
    allow_research_only: bool,
    source_id: str = "source:nf-v3-unverified",
    provenance_verified: bool = False,
    provenance_reason: str = "",
) -> Tuple[CompatibilityGateSummarySchema, bool]:
    """Run FeatureCompatibilityEvaluator and InferenceEligibilityGate (#46)."""
    model_meta = pipeline.model_metadata if isinstance(pipeline.model_metadata, dict) else {}
    raw_manifest = (
        model_meta.get("raw_manifest") if isinstance(model_meta.get("raw_manifest"), dict) else {}
    )
    prep_meta = (
        pipeline.preprocessor_metadata if isinstance(pipeline.preprocessor_metadata, dict) else {}
    )
    model_id = str(raw_manifest.get("run_id") or model_meta.get("run_id") or "")
    model_sha = model_meta.get("model_artifact_sha256")
    prep_sha = prep_meta.get("artifact_sha256")

    # Transform with frozen train-only preprocessor before statistical domain/NaN checks
    X_for_compat = (
        pipeline.preprocessor.transform(X_ordered, partition_name="inference")
        if hasattr(pipeline, "preprocessor") and pipeline.preprocessor is not None
        else X_ordered
    )

    is_unverified_source = source_id == "source:nf-v3-unverified" or not provenance_verified
    compat_allow_research = False if is_unverified_source else allow_research_only

    evaluator = FeatureCompatibilityEvaluator(benchmark_registry=DEFAULT_BENCHMARK_REGISTRY)
    compat_report = evaluator.evaluate_dataframe(
        X_for_compat,
        source_id=source_id,
        model_identifier=model_id or None,
        model_artifact_sha256=model_sha,
        preprocessor_artifact_sha256=prep_sha,
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_research_only=compat_allow_research,
    )
    # Audit true physical invariant violations fail-closed, while surfacing MIN_TTL=0
    # rows per-row with ABSTAINED_OOD inference/risk abstention (#32) without dropping valid rows.
    phys_ood = OODValidator(check_shortcut_drift=True, reject_zero_ttl=False).audit_dataframe(
        df_raw
    )
    batch_ood_for_gate = OODReport(
        total_rows=phys_ood.total_rows,
        has_ood_warning=raw_ood_report.has_ood_warning,
        hard_violation_count=phys_ood.hard_violation_count,
        shortcut_shift_count=phys_ood.shortcut_shift_count,
        zero_ttl_count=raw_ood_report.zero_ttl_count,
        affected_rows_count=phys_ood.hard_violation_count,
        shortcut_drift_ratio=phys_ood.shortcut_drift_ratio,
        zero_ttl_ratio=raw_ood_report.zero_ttl_ratio,
        ood_flags=list(raw_ood_report.ood_flags),
        out_of_range_details=dict(phys_ood.out_of_range_details),
        unseen_categories=dict(phys_ood.unseen_categories),
        hard_violation_indices=list(phys_ood.hard_violation_indices),
        zero_ttl_indices=[],
        shortcut_drift_indices=list(phys_ood.shortcut_drift_indices),
    )
    gate = InferenceEligibilityGate(
        evaluator=evaluator,
        ood_validator=_RawOodProxy(batch_ood_for_gate),
        strict_ood_abstain=False,
        reject_zero_ttl=False,
    )
    gate_decision = gate.evaluate(
        df=X_for_compat,
        source_id=source_id,
        model_identifier=model_id or None,
        model_artifact_sha256=model_sha,
        preprocessor_artifact_sha256=prep_sha,
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_unverified=allow_research_only if is_unverified_source else False,
        allow_research_only=compat_allow_research,
    )
    warnings = list(raw_ood_report.ood_flags)
    if not provenance_verified and provenance_reason:
        warnings.append(provenance_reason)

    summary = CompatibilityGateSummarySchema(
        source_id=source_id,
        provenance_verified=provenance_verified,
        model_key=canonical_model,
        model_identifier=model_id or None,
        eligible=bool(gate_decision.is_eligible),
        eligibility_status=str(gate_decision.eligibility_status.value),
        compatibility_status=str(compat_report.validation_status.value),
        reasons=list(gate_decision.abstention_reasons) or list(compat_report.rejection_reasons),
        warnings=warnings,
        missing_features=list(compat_report.missing_features),
    )
    return summary, bool(gate_decision.is_eligible)


_MAX_RECORDED_CSV_ANALYSES = 64
_MAX_CACHED_RESULTS_BYTES = 16 * 1024 * 1024
_MAX_SINGLE_RECORD_RESULTS_GZ_BYTES = 8 * 1024 * 1024

_TRACE_FIELD_SPEC: Tuple[Tuple[str, str, Any], ...] = (
    ("flow_start_ms", "FLOW_START_MILLISECONDS", _optional_int),
    ("flow_end_ms", "FLOW_END_MILLISECONDS", _optional_int),
    ("src_ip", "IPV4_SRC_ADDR", _optional_str),
    ("dst_ip", "IPV4_DST_ADDR", _optional_str),
    ("src_port", "L4_SRC_PORT", _optional_int),
    ("dst_port", "L4_DST_PORT", _optional_int),
    ("protocol", "PROTOCOL", _optional_int),
    ("flow_duration_ms", "FLOW_DURATION_MILLISECONDS", _optional_int),
    ("min_ttl", "MIN_TTL", _optional_float),
)


def _normalize_row_id(raw_rid: Any, fallback_idx: int) -> Union[int, str]:
    """Normalize row_id preserving ints even when pandas promotes a NaN column to float64."""
    if raw_rid is None or (isinstance(raw_rid, bool)):
        return f"row_{fallback_idx}"
    if isinstance(raw_rid, (int, np.integer)):
        return int(raw_rid)
    if isinstance(raw_rid, (float, np.floating)):
        fval = float(raw_rid)
        if not math.isfinite(fval):
            return f"row_{fallback_idx}"
        if fval.is_integer():
            return int(fval)
        return str(fval)
    if pd.isna(raw_rid):
        return f"row_{fallback_idx}"
    return str(raw_rid)


def _extract_trace_metadata_rows(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Extract normalized NetFlow trace metadata once per row across the batch."""
    n_rows = len(df)
    if n_rows == 0:
        return []
    present_cols = [
        (field, converter, df[col].tolist())
        for field, col, converter in _TRACE_FIELD_SPEC
        if col in df.columns
    ]
    rows: List[Dict[str, Any]] = [
        {field: None for field, _, _ in _TRACE_FIELD_SPEC} for _ in range(n_rows)
    ]
    for field, converter, col_vals in present_cols:
        for idx, raw_val in enumerate(col_vals):
            rows[idx][field] = converter(raw_val)
    return rows


def _canonical_results_sha256(results: Sequence[CsvFlowPredictionItem]) -> str:
    payload = json.dumps(
        [item.model_dump() for item in results],
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_analysis_store(
    service: ApiService,
) -> Tuple[threading.Lock, "OrderedDict[str, Dict[str, Any]]"]:
    lock = getattr(service, "_csv_analysis_lock", None)
    store = getattr(service, "_csv_analysis_records", None)
    if lock is None or store is None:
        lock = threading.Lock()
        store = OrderedDict()
        setattr(service, "_csv_analysis_lock", lock)
        setattr(service, "_csv_analysis_records", store)
    return lock, store


def _load_recorded_analysis_results(rec: Dict[str, Any]) -> Optional[List[CsvFlowPredictionItem]]:
    """Decode cached prediction rows from a server-recorded analysis entry if still retained."""
    raw_gz = rec.get("results_gz")
    if isinstance(raw_gz, (bytes, bytearray)) and raw_gz:
        decoded = json.loads(zlib.decompress(raw_gz).decode("utf-8"))
        return [CsvFlowPredictionItem.model_validate(item) for item in decoded]
    raw_items = rec.get("results")
    if isinstance(raw_items, list):
        return [CsvFlowPredictionItem.model_validate(item) for item in raw_items]
    return None


def _record_csv_analysis(service: ApiService, response: CsvAnalyzeResponse) -> None:
    lock, store = _get_analysis_store(service)
    serialized_results = json.dumps(
        [item.model_dump() for item in response.results],
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    compressed_results = zlib.compress(serialized_results, level=1)
    keep_results_gz = len(compressed_results) <= _MAX_SINGLE_RECORD_RESULTS_GZ_BYTES
    record = {
        "analysis_id": response.analysis_id,
        "source_csv_path": response.file_path,
        "source_csv_sha256": response.file_sha256,
        "model_key": response.model_key,
        "model_type": response.model_type,
        "run_id": response.run_id,
        "model_sha256": response.model_sha256,
        "preprocessor_sha256": response.preprocessor_sha256,
        "inference_mode": response.inference_mode,
        "compatibility_gate": response.compatibility_gate.model_dump(),
        "results_gz": compressed_results if keep_results_gz else None,
        "results_gz_bytes": len(compressed_results) if keep_results_gz else 0,
        "results_sha256": _canonical_results_sha256(response.results),
    }
    with lock:
        store[response.analysis_id] = record
        store.move_to_end(response.analysis_id)
        while len(store) > _MAX_RECORDED_CSV_ANALYSES:
            store.popitem(last=False)
        total_cached_bytes = sum(
            int(entry.get("results_gz_bytes") or 0) for entry in store.values()
        )
        if total_cached_bytes > _MAX_CACHED_RESULTS_BYTES:
            for existing_id, entry in store.items():
                if existing_id == response.analysis_id:
                    continue
                freed = int(entry.get("results_gz_bytes") or 0)
                if freed > 0:
                    entry["results_gz"] = None
                    entry["results_gz_bytes"] = 0
                    total_cached_bytes -= freed
                if total_cached_bytes <= _MAX_CACHED_RESULTS_BYTES:
                    break


def _safe_feature_value(val: Any) -> Optional[float]:
    if val is None or pd.isna(val):
        return None
    fval = float(val)
    return fval if math.isfinite(fval) else None


def _classify_abstained_ood(is_phys_hard: bool, is_zero_ttl: bool) -> Tuple[str, str]:
    """Return structured OOD classification (`ood_kind`) and human-readable reason."""
    if is_phys_hard and is_zero_ttl:
        return (
            "COMBINED_OOD",
            "Hard protocol invariant violation; MIN_TTL == 0 unobserved telemetry "
            "(anti-imputation abstention)",
        )
    if is_phys_hard:
        return ("PHYSICAL_INVARIANT", "Hard protocol invariant violation")
    return (
        "ZERO_TTL_DRIFT",
        "MIN_TTL == 0 unobserved telemetry (anti-imputation abstention)",
    )


def _build_abstained_ood_reason(is_phys_hard: bool, is_zero_ttl: bool) -> str:
    _, reason = _classify_abstained_ood(is_phys_hard, is_zero_ttl)
    return reason


def analyze_csv_file(
    service: ApiService,
    *,
    file_path: str,
    model_name: str = "random_forest",
    create_incidents: bool = False,
    batch_size: int = 500,
    include_timeline: bool = True,
    allow_research_only: bool = True,
) -> CsvAnalyzeResponse:
    """Validate CSV, verify provenance & OOD abstention before inference, and score eligible rows."""
    canonical_model = canonicalize_model_name(model_name)
    resolved = validate_safe_csv_path(file_path)
    file_sha256 = _sha256_file(resolved)
    df = pd.read_csv(resolved)
    if len(df) == 0:
        raise ValueError("CSV file contains 0 data rows.")

    X_ordered, val_summary = validate_inference_input(df)
    X_cleaned, _ = _audit_and_coerce_ml_matrix(X_ordered)
    df_for_ood = df.assign(**{str(col): X_cleaned[col] for col in X_cleaned.columns})
    row_ids = list(val_summary["row_ids"])

    # Pre-inference OOD audit separating true physical protocol violations from MIN_TTL == 0.
    phys_ood_report, raw_ood_report = _audit_desktop_ood(df_for_ood)
    phys_hard_set = set(phys_ood_report.hard_violation_indices)
    zero_ttl_set = set(raw_ood_report.zero_ttl_indices)
    abstained_set = phys_hard_set | zero_ttl_set
    accepted_indices = [idx for idx in range(len(df)) if idx not in abstained_set]

    if not accepted_indices:
        raise ModelNotReadyError(
            f"All {len(df)} rows in CSV were abstained before inference due to OOD invariant violations."
        )

    try:
        pipeline = service._load_inference_pipeline(canonical_model)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise ModelNotReadyError(str(exc)) from exc

    source_id, provenance_verified, provenance_reason = resolve_csv_source_provenance(
        resolved, file_sha256, len(df), df=df
    )
    X_accepted = X_cleaned.iloc[accepted_indices].reset_index(drop=True)
    df_accepted_ood = df_for_ood.iloc[accepted_indices].reset_index(drop=True)
    gate_summary, is_eligible = _evaluate_gate(
        canonical_model=canonical_model,
        pipeline=pipeline,
        df_raw=df_accepted_ood,
        X_ordered=X_accepted,
        raw_ood_report=raw_ood_report,
        allow_research_only=allow_research_only,
        source_id=source_id,
        provenance_verified=provenance_verified,
        provenance_reason=provenance_reason,
    )
    if not is_eligible:
        raise ModelNotReadyError(
            f"Inference eligibility gate blocked '{canonical_model}': {gate_summary.reasons}"
        )

    # Build model input events strictly for accepted (non-OOD) rows before calling analyze_flows.
    trace_rows = _extract_trace_metadata_rows(df)
    feature_records = X_cleaned.to_dict(orient="records")
    accepted_events: List[Dict[str, Any]] = []
    for idx in accepted_indices:
        feat_row = feature_records[idx]
        clean_feats = {col: _safe_feature_value(val) for col, val in feat_row.items()}
        trace = trace_rows[idx]
        accepted_events.append(
            {
                "event_id": f"csv_{file_sha256[:8]}_{idx}",
                "features": clean_feats,
                "source_ip": trace["src_ip"],
                "dest_ip": trace["dst_ip"],
                "source_port": trace["src_port"],
                "dest_port": trace["dst_port"],
            }
        )

    all_api_results = []
    first_batch_resp = None
    for start in range(0, len(accepted_events), batch_size):
        batch = accepted_events[start : start + batch_size]
        batch_resp = service.analyze_flows(
            batch,
            model_name=canonical_model,
            create_incidents=create_incidents,
            allow_heuristic_fallback=False,
        )
        if first_batch_resp is None:
            first_batch_resp = batch_resp
        all_api_results.extend(batch_resp.results)

    assert first_batch_resp is not None
    if len(all_api_results) != len(accepted_indices):
        raise RuntimeError(
            f"Inference result count mismatch: sent {len(accepted_indices)} eligible rows, "
            f"received {len(all_api_results)} results."
        )
    accepted_result_by_idx = dict(zip(accepted_indices, all_api_results))
    sample_item = all_api_results[0]

    prediction_items: List[CsvFlowPredictionItem] = []
    abstained_risk_count = 0
    ood_flagged_count = 0
    benign_count = 0
    attack_count = 0

    for idx in range(len(df)):
        row_id = _normalize_row_id(row_ids[idx], idx)
        trace = trace_rows[idx]
        if idx in abstained_set:
            is_phys_hard = idx in phys_hard_set
            is_zero_ttl = idx in zero_ttl_set
            ood_flagged_count += 1
            abstained_risk_count += 1
            pred_label: Optional[int] = None
            pred_class = "ABSTAINED_OOD"
            pred_attack_prob: Optional[float] = None
            pred_raw_score: Optional[float] = None
            risk_score: Optional[float] = None
            risk_level = "ABSTAINED_OOD"
            is_ood_flagged = True
            ood_kind: Optional[str]
            ood_reason: Optional[str]
            ood_kind, ood_reason = _classify_abstained_ood(is_phys_hard, is_zero_ttl)
            decision_threshold = sample_item.decision_threshold
            score_type = sample_item.score_type
            score_direction = sample_item.score_direction
        else:
            api_item = accepted_result_by_idx[idx]
            is_ood_flagged = False
            ood_kind = None
            ood_reason = None
            risk_score, risk_level = compute_deterministic_risk_score(
                is_ood_flagged=False,
                score_type=api_item.score_type,
                score_direction=api_item.score_direction,
                attack_probability=api_item.attack_probability,
                raw_anomaly_score=api_item.raw_anomaly_score,
                decision_threshold=api_item.decision_threshold,
            )
            if risk_score is None:
                abstained_risk_count += 1
            pred_label = 1 if int(api_item.prediction) == 1 else 0
            pred_class = "Attack" if pred_label == 1 else "Benign"
            pred_attack_prob = api_item.attack_probability
            pred_raw_score = api_item.raw_anomaly_score
            decision_threshold = api_item.decision_threshold
            score_type = api_item.score_type
            score_direction = api_item.score_direction
            if pred_label == 1:
                attack_count += 1
            else:
                benign_count += 1

        prediction_items.append(
            CsvFlowPredictionItem(
                row_id=row_id,
                row_index=idx,
                predicted_label=pred_label,
                predicted_class=pred_class,
                attack_probability=pred_attack_prob,
                raw_anomaly_score=pred_raw_score,
                decision_threshold=decision_threshold,
                score_type=score_type,
                score_direction=score_direction,
                risk_score=risk_score,
                risk_level=risk_level,
                is_ood_flagged=is_ood_flagged,
                ood_kind=ood_kind,
                ood_reason=ood_reason,
                **trace,
            )
        )

    timeline = build_deterministic_evidence_timeline(prediction_items) if include_timeline else []
    behavioral = compute_netflow_behavioral_summary(df)
    _, model_type_display, _ = _MODEL_DISPLAY_META[canonical_model]
    evaluated_rows = len(accepted_indices)
    abstained_rows = len(abstained_set)
    prediction_coverage = round(float(evaluated_rows) / float(len(prediction_items)), 4)

    response = CsvAnalyzeResponse(
        analysis_id=f"csvrun_{uuid.uuid4().hex[:12]}",
        analyzed_at_utc=_utc_now_iso(),
        file_path=str(resolved),
        file_sha256=file_sha256,
        model_key=canonical_model,
        model_type=model_type_display,
        run_id=first_batch_resp.run_id,
        model_sha256=first_batch_resp.model_sha256,
        preprocessor_sha256=first_batch_resp.preprocessor_sha256,
        inference_mode=first_batch_resp.inference_mode,
        total_rows=len(prediction_items),
        evaluated_rows=evaluated_rows,
        abstained_rows=abstained_rows,
        prediction_coverage=prediction_coverage,
        benign_count=benign_count,
        attack_count=attack_count,
        ood_flagged_count=ood_flagged_count,
        abstained_risk_count=abstained_risk_count,
        decision_threshold=sample_item.decision_threshold,
        score_type=sample_item.score_type,
        score_direction=sample_item.score_direction,
        compatibility_gate=gate_summary,
        ood_report=_ood_to_schema(phys_ood_report, abstain_report=raw_ood_report),
        behavioral_summary=behavioral,
        security_notice=_SECURITY_NOTICE,
        results=prediction_items,
        timeline=timeline,
    )
    _record_csv_analysis(service, response)
    return response


def _normalize_binary_label(raw: Any) -> int:
    if isinstance(raw, (bool, np.bool_)):
        raise ValueError(f"Boolean label not permitted: {raw!r}")
    if isinstance(raw, (int, np.integer)):
        iv = int(raw)
        if iv in (0, 1):
            return iv
    if isinstance(raw, (float, np.floating)):
        if math.isfinite(float(raw)) and float(raw) in (0.0, 1.0):
            return int(raw)
    if isinstance(raw, str):
        text = raw.strip()
        if text in {"0", "Benign", "benign"}:
            return 0
        if text in {"1", "Attack", "attack"}:
            return 1
    raise ValueError(f"Invalid binary ground truth label: {raw!r}")


def _normalize_row_id_key(raw: Any) -> str:
    """Normalize row_id values symmetrically across int/float/str CSV dtypes."""
    if raw is None:
        raise ValueError("Ground truth CSV contains missing row_id values.")
    if isinstance(raw, float) or isinstance(raw, np.floating):
        fval = float(raw)
        if not math.isfinite(fval):
            raise ValueError("Ground truth CSV contains non-finite row_id values.")
        return str(int(fval)) if fval.is_integer() else str(fval)
    if isinstance(raw, (int, np.integer)) and not isinstance(raw, bool):
        return str(int(raw))
    text = str(raw).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        raise ValueError("Ground truth CSV contains missing row_id values.")
    if text.endswith(".0"):
        prefix = text[:-2]
        if prefix.lstrip("-").isdigit():
            return prefix
    return text


def evaluate_predictions_with_ground_truth(
    *,
    labels_path: str,
    predictions: List[CsvFlowPredictionItem],
) -> CsvEvaluateResponse:
    """Align ground-truth CSV labels by row_id (or row order) and compute scientific metrics."""
    resolved = validate_safe_csv_path(labels_path)
    labels_sha256 = _sha256_file(resolved)
    labels_df = pd.read_csv(resolved)
    if len(labels_df) == 0:
        raise ValueError("Ground truth CSV contains 0 rows.")
    if "Label" not in labels_df.columns:
        raise ValueError("Ground truth CSV must contain a 'Label' column.")

    has_attack_col = "Attack" in labels_df.columns
    y_true: List[int] = []
    y_pred: List[int] = []
    attack_cats: List[str] = []
    unmatched = 0
    abstained = 0
    matched_total = 0

    if "row_id" in labels_df.columns:
        lbl_map: Dict[str, Tuple[int, str]] = {}
        # Iterate column lists instead of iterrows() so an all-NaN or float column
        # cannot upcast integer row_id values to floats (e.g. "2393.0").
        raw_row_ids = labels_df["row_id"].tolist()
        raw_labels = labels_df["Label"].tolist()
        raw_attacks = labels_df["Attack"].tolist() if has_attack_col else [None] * len(labels_df)
        for raw_rid, raw_lbl, raw_att in zip(raw_row_ids, raw_labels, raw_attacks):
            rid_key = _normalize_row_id_key(raw_rid)
            if rid_key in lbl_map:
                raise ValueError(f"Duplicate row_id {rid_key!r} in ground truth CSV.")
            lbl_val = _normalize_binary_label(raw_lbl)
            att_val = (
                _optional_str(raw_att) or ("Benign" if lbl_val == 0 else "Attack")
                if has_attack_col
                else ("Benign" if lbl_val == 0 else "Attack")
            )
            lbl_map[rid_key] = (lbl_val, att_val)

        for pred in predictions:
            key = _normalize_row_id_key(pred.row_id)
            if key not in lbl_map:
                unmatched += 1
                continue
            matched_total += 1
            if (
                pred.is_ood_flagged
                or pred.predicted_label is None
                or pred.predicted_class == "ABSTAINED_OOD"
            ):
                abstained += 1
                continue
            yt, att = lbl_map[key]
            y_true.append(yt)
            y_pred.append(int(pred.predicted_label))
            attack_cats.append(att)

        if matched_total == 0:
            raise ValueError("No prediction row_id values matched the ground truth CSV.")
        if not y_true:
            raise ValueError(
                "All matched prediction rows were abstained due to OOD invariant violations; "
                "cannot compute confusion matrix."
            )
    else:
        if len(labels_df) != len(predictions):
            raise ValueError(
                f"Ground truth row count ({len(labels_df)}) does not match prediction count "
                f"({len(predictions)}) and no 'row_id' column is present for alignment."
            )
        for idx, pred in enumerate(predictions):
            matched_total += 1
            if (
                pred.is_ood_flagged
                or pred.predicted_label is None
                or pred.predicted_class == "ABSTAINED_OOD"
            ):
                abstained += 1
                continue
            lbl_val = _normalize_binary_label(labels_df["Label"].iloc[idx])
            att_val = (
                _optional_str(labels_df["Attack"].iloc[idx])
                or ("Benign" if lbl_val == 0 else "Attack")
                if has_attack_col
                else ("Benign" if lbl_val == 0 else "Attack")
            )
            y_true.append(lbl_val)
            y_pred.append(int(pred.predicted_label))
            attack_cats.append(att_val)
        if not y_true:
            raise ValueError(
                "All prediction rows were abstained due to OOD invariant violations; "
                "cannot compute confusion matrix."
            )

    metrics = compute_metrics(y_true, y_pred, labels=[0, 1])
    breakdown_rows: List[AttackBreakdownRow] = []
    if has_attack_col:
        raw_bd = compute_attack_category_breakdown(y_true, y_pred, attack_cats)
        for cat, stats in raw_bd.items():
            if cat == "Benign":
                breakdown_rows.append(
                    AttackBreakdownRow(
                        attack_category=cat,
                        total_count=int(stats["total"]),
                        tp_count=int(stats["true_negative"]),
                        fn_count=int(stats["false_positive"]),
                        detection_rate=round(float(1.0 - float(stats["false_positive_rate"])), 4),
                    )
                )
            else:
                breakdown_rows.append(
                    AttackBreakdownRow(
                        attack_category=cat,
                        total_count=int(stats["total"]),
                        tp_count=int(stats["detected"]),
                        fn_count=int(stats["missed"]),
                        detection_rate=round(float(stats["detection_rate"]), 4),
                    )
                )

    total_pred_rows = len(predictions)
    label_match_rate = round(float(matched_total) / float(max(1, total_pred_rows)), 4)
    post_ood_coverage = round(float(len(y_true)) / float(max(1, matched_total)), 4)
    partial_match_note = (
        f" Partial label match: {matched_total}/{total_pred_rows} prediction rows matched "
        f"the ground truth CSV ({unmatched} unmatched rows excluded)."
        if unmatched > 0
        else ""
    )

    return CsvEvaluateResponse(
        labels_path=str(resolved),
        labels_sha256=labels_sha256,
        total_prediction_rows=total_pred_rows,
        matched_label_rows=matched_total,
        matched_rows=len(y_true),
        evaluated_rows=len(y_true),
        unmatched_rows=unmatched,
        abstained_rows=abstained,
        label_match_rate=label_match_rate,
        prediction_coverage=post_ood_coverage,
        accuracy=round(float(metrics["accuracy"]), 6),
        precision=round(float(metrics["precision"]), 6),
        recall=round(float(metrics["recall"]), 6),
        f1=round(float(metrics["f1"]), 6),
        false_positive_rate=round(float(metrics["false_positive_rate"]), 6),
        true_negative_rate=round(float(metrics["true_negative_rate"]), 6),
        confusion_matrix={k: int(v) for k, v in metrics["confusion_matrix_labeled"].items()},
        attack_breakdown=breakdown_rows,
        scientific_notice=(
            "Evaluation computed dynamically on user-supplied Ground Truth CSV via canonical "
            "compute_metrics() over label-matched, non-abstained predictions (OOD-abstained rows "
            "and unmatched rows are excluded from the confusion matrix; label_match_rate measures "
            "matched_label_rows/total_prediction_rows while prediction_coverage measures "
            "evaluated_rows/matched_label_rows after OOD abstention)."
            f"{partial_match_note} Demo balanced subset "
            "(~50% Attack) is for UI verification only and does not reflect production deployment "
            "prevalence or held-out Test benchmarks."
        ),
    )


def _resolve_export_provenance(
    request: CsvExportRequest,
    service: Optional[ApiService],
) -> Dict[str, Any]:
    """Verify export provenance against server analysis records or artifacts and hash source CSV."""
    canonical_model = canonicalize_model_name(request.model_key)
    source_csv_path = request.source_csv_path
    source_csv_sha256: Optional[str] = None
    if source_csv_path is not None:
        try:
            src_resolved = validate_safe_csv_path(source_csv_path)
            source_csv_path = str(src_resolved)
            source_csv_sha256 = _sha256_file(src_resolved)
        except ValueError:
            if request.analysis_id:
                raise
            source_csv_sha256 = None

    if request.analysis_id:
        if service is None:
            raise ValueError("Server service context required to verify analysis_id provenance.")
        lock, store = _get_analysis_store(service)
        with lock:
            rec = store.get(request.analysis_id)
        if rec is None:
            raise ValueError(
                f"Unknown or expired analysis_id {request.analysis_id!r}; re-run CSV analysis before export."
            )
        if canonical_model != rec["model_key"]:
            raise ValueError(
                f"Export model_key {canonical_model!r} does not match recorded analysis model {rec['model_key']!r}."
            )
        if request.source_csv_path is not None and source_csv_path != rec["source_csv_path"]:
            raise ValueError("Export source_csv_path does not match recorded analysis source CSV.")
        # Always verify the recorded source CSV file on disk against its inference-time SHA-256,
        # even when request.source_csv_path is omitted (#F-07).
        try:
            recorded_src_resolved = validate_safe_csv_path(rec["source_csv_path"])
            live_source_sha256 = _sha256_file(recorded_src_resolved)
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"Recorded source CSV for analysis {request.analysis_id!r} cannot be verified: {exc}"
            ) from exc
        if live_source_sha256 != rec["source_csv_sha256"]:
            raise ValueError(
                "Source CSV file on disk changed after inference; refusing verified export provenance."
            )
        if request.run_id is not None and request.run_id != rec["run_id"]:
            raise ValueError("Export run_id does not match server-verified analysis run_id.")
        if request.model_sha256 is not None and request.model_sha256 != rec["model_sha256"]:
            raise ValueError(
                "Export model_sha256 does not match server-verified model artifact digest."
            )
        if (
            request.preprocessor_sha256 is not None
            and request.preprocessor_sha256 != rec["preprocessor_sha256"]
        ):
            raise ValueError(
                "Export preprocessor_sha256 does not match server-verified preprocessor digest."
            )
        if _canonical_results_sha256(request.results) != rec["results_sha256"]:
            raise ValueError(
                "Export prediction rows do not match the server-recorded analysis results."
            )
        return {
            "analysis_id": rec["analysis_id"],
            "source_csv_path": rec["source_csv_path"],
            "source_csv_sha256": live_source_sha256,
            "model_key": rec["model_key"],
            "model_type": rec["model_type"],
            "run_id": rec["run_id"],
            "model_artifact_sha256": rec["model_sha256"],
            "preprocessor_artifact_sha256": rec["preprocessor_sha256"],
            "provenance_verification": "server_verified_analysis",
        }

    verification_status = "unverified_client_supplied"
    if service is not None:
        try:
            pipeline = service._load_inference_pipeline(canonical_model)
            meta = pipeline.model_metadata if isinstance(pipeline.model_metadata, dict) else {}
            prep_meta = (
                pipeline.preprocessor_metadata
                if isinstance(pipeline.preprocessor_metadata, dict)
                else {}
            )
            raw_manifest = (
                meta.get("raw_manifest") if isinstance(meta.get("raw_manifest"), dict) else {}
            )
            expected_model_sha = meta.get("model_artifact_sha256")
            expected_prep_sha = prep_meta.get("artifact_sha256")
            expected_run_id = raw_manifest.get("run_id") or meta.get("run_id")
            if (
                expected_model_sha
                and request.model_sha256 == expected_model_sha
                and expected_prep_sha
                and request.preprocessor_sha256 == expected_prep_sha
                and (expected_run_id is None or request.run_id == expected_run_id)
            ):
                verification_status = "server_verified_artifacts"
        except (FileNotFoundError, ValueError, RuntimeError):
            verification_status = "unverified_client_supplied"

    return {
        "analysis_id": None,
        "source_csv_path": source_csv_path,
        "source_csv_sha256": source_csv_sha256,
        "model_key": canonical_model,
        "model_type": request.model_type,
        "run_id": request.run_id,
        "model_artifact_sha256": request.model_sha256,
        "preprocessor_artifact_sha256": request.preprocessor_sha256,
        "provenance_verification": verification_status,
    }


def _resolve_evaluation_provenance(
    request: CsvExportRequest,
    verified_meta: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Verify Ground Truth evaluation against server computation or mark client-supplied."""
    if request.evaluation is None:
        return None, "none"

    if verified_meta.get("provenance_verification") != "server_verified_analysis":
        return request.evaluation.model_dump(), "client_supplied_unverified"

    recomputed = evaluate_predictions_with_ground_truth(
        labels_path=request.evaluation.labels_path,
        predictions=request.results,
    )
    if recomputed.labels_sha256 != request.evaluation.labels_sha256:
        raise ValueError(
            "Export evaluation labels_sha256 does not match the current Ground Truth CSV on disk."
        )
    if recomputed.model_dump() != request.evaluation.model_dump():
        raise ValueError(
            "Export evaluation summary does not match server-recomputed Ground Truth metrics."
        )
    return recomputed.model_dump(), "server_verified_evaluation"


def export_predictions_csv(
    request: CsvExportRequest,
    service: Optional[ApiService] = None,
) -> CsvExportResponse:
    """Write predictions CSV and companion .metadata.json provenance atomically."""
    verified_meta = _resolve_export_provenance(request, service)
    evaluation_summary, evaluation_verification = _resolve_evaluation_provenance(
        request, verified_meta
    )
    csv_out = validate_safe_export_path(
        request.output_path, source_csv_path=verified_meta["source_csv_path"]
    )
    meta_out = csv_out.with_suffix(".metadata.json")
    exported_at = _utc_now_iso()

    rows = [item.model_dump() for item in request.results]
    export_df = pd.DataFrame(rows)
    _atomic_write_text(csv_out, export_df.to_csv(index=False))
    csv_sha256 = _sha256_file(csv_out)

    provenance = {
        "schema_version": "1.0",
        "exported_at_utc": exported_at,
        "output_csv_path": str(csv_out),
        "output_csv_sha256": csv_sha256,
        "rows_exported": len(rows),
        **verified_meta,
        "evaluation_verification": evaluation_verification,
        "evaluation_summary": evaluation_summary,
        "security_notice": _SECURITY_NOTICE,
    }

    _atomic_write_text(meta_out, json.dumps(provenance, indent=2))
    meta_sha256 = _sha256_file(meta_out)

    return CsvExportResponse(
        csv_path=str(csv_out),
        metadata_path=str(meta_out),
        csv_sha256=csv_sha256,
        metadata_sha256=meta_sha256,
        rows_exported=len(rows),
        exported_at_utc=exported_at,
    )
