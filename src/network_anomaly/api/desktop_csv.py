"""Desktop CSV inspection, batch inference, Ground Truth evaluation, and export workflows.

Reuses ApiService, validate_inference_input, TrainOnlyPreprocessor, OODValidator,
FeatureCompatibilityEvaluator, InferenceEligibilityGate, and evaluation metrics
without reimplementing ML preprocessing or scoring logic.
"""

from __future__ import annotations

import math
import os
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

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
    "Local security posture (#26/#27): Localhost-only FastAPI (127.0.0.1), fail-closed "
    "SHA-256 artifact checks, safe CSV path validation, and read-only advisories. "
    "OS firewall automation, automated key rotation, and AES-256-GCM keyring encryption remain DEFERRED."
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


def validate_safe_csv_path(raw_path: str, *, max_bytes: int = MAX_CSV_FILE_BYTES) -> Path:
    """Validate an existing local CSV input path fail-closed (#26)."""
    if not isinstance(raw_path, str) or not raw_path.strip() or "\x00" in raw_path:
        raise ValueError("Invalid CSV file path.")

    candidate = Path(raw_path.strip()).expanduser()
    if candidate.suffix.lower() != ".csv":
        raise ValueError(f"Only .csv files are permitted, got {candidate.suffix!r}.")

    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"CSV file does not exist or cannot be resolved: {exc}") from exc

    if _is_sensitive_system_path(resolved):
        raise ValueError("Access to protected system directory is blocked.")

    if not resolved.is_file():
        raise ValueError(f"Path is not a regular file: '{resolved}'")

    size = resolved.stat().st_size
    if size <= 0:
        raise ValueError("CSV file is empty (0 bytes).")
    if size > max_bytes:
        raise ValueError(f"CSV file exceeds maximum desktop limit ({size} > {max_bytes} bytes).")
    return resolved


def validate_safe_export_path(raw_path: str, source_csv_path: Optional[str] = None) -> Path:
    """Validate a destination path and companion metadata path without overwriting input (#26)."""
    if not isinstance(raw_path, str) or not raw_path.strip() or "\x00" in raw_path:
        raise ValueError("Invalid export file path.")

    candidate = Path(raw_path.strip()).expanduser()
    if candidate.suffix.lower() != ".csv":
        raise ValueError("Export output path must end with '.csv'.")

    resolved = candidate.resolve(strict=False)
    meta_resolved = resolved.with_suffix(".metadata.json").resolve(strict=False)
    for target in (resolved, meta_resolved):
        if _is_sensitive_system_path(target):
            raise ValueError("Exporting into a protected system directory is blocked.")
        if target.exists() and target.is_dir():
            raise ValueError(f"Export path resolves to a directory: '{target}'")

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


def _ood_to_schema(report: OODReport) -> OodSummarySchema:
    return OodSummarySchema(
        total_rows=report.total_rows,
        has_ood_warning=report.has_ood_warning,
        hard_violation_count=report.hard_violation_count,
        shortcut_shift_count=report.shortcut_shift_count,
        zero_ttl_count=report.zero_ttl_count,
        affected_rows_count=report.affected_rows_count,
        shortcut_drift_ratio=round(report.shortcut_drift_ratio, 4),
        zero_ttl_ratio=round(report.zero_ttl_ratio, 4),
        abstention_rate=round(report.abstention_rate, 4),
        prediction_coverage=round(report.prediction_coverage, 4),
        ood_flags=list(report.ood_flags),
        hard_violation_indices=list(report.hard_violation_indices),
        zero_ttl_indices=list(report.zero_ttl_indices),
        out_of_range_details=dict(report.out_of_range_details),
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
    ood_report = OODValidator(check_shortcut_drift=True, reject_zero_ttl=True).audit_dataframe(
        df_for_ood
    )
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
        ood_report=_ood_to_schema(ood_report),
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

    evaluator = FeatureCompatibilityEvaluator(benchmark_registry=DEFAULT_BENCHMARK_REGISTRY)
    compat_report = evaluator.evaluate_dataframe(
        X_for_compat,
        source_id="source:nf-v3-canonical",
        model_identifier=model_id or None,
        model_artifact_sha256=model_sha,
        preprocessor_artifact_sha256=prep_sha,
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_research_only=allow_research_only,
    )
    # Audit true physical invariant violations fail-closed, while surfacing MIN_TTL=0
    # rows per-row with ABSTAINED_OOD risk scoring (#32) without dropping valid rows.
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
        source_id="source:nf-v3-canonical",
        model_identifier=model_id or None,
        model_artifact_sha256=model_sha,
        preprocessor_artifact_sha256=prep_sha,
        feature_contract_version="nf-unsw-nb15-v3-baseline-47",
        allow_research_only=allow_research_only,
    )
    summary = CompatibilityGateSummarySchema(
        model_key=canonical_model,
        model_identifier=model_id or None,
        eligible=bool(gate_decision.is_eligible),
        eligibility_status=str(gate_decision.eligibility_status.value),
        compatibility_status=str(compat_report.validation_status.value),
        reasons=list(gate_decision.abstention_reasons) or list(compat_report.rejection_reasons),
        warnings=list(raw_ood_report.ood_flags),
        missing_features=list(compat_report.missing_features),
    )
    return summary, bool(gate_decision.is_eligible)


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
    """Validate CSV, run OOD & compatibility gate, and execute batched verified inference."""
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
    raw_ood_report = OODValidator(check_shortcut_drift=True, reject_zero_ttl=True).audit_dataframe(
        df_for_ood
    )

    try:
        pipeline = service._load_inference_pipeline(canonical_model)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise ModelNotReadyError(str(exc)) from exc

    gate_summary, is_eligible = _evaluate_gate(
        canonical_model=canonical_model,
        pipeline=pipeline,
        df_raw=df_for_ood,
        X_ordered=X_cleaned,
        raw_ood_report=raw_ood_report,
        allow_research_only=allow_research_only,
    )
    if not is_eligible:
        raise ModelNotReadyError(
            f"Inference eligibility gate blocked '{canonical_model}': {gate_summary.reasons}"
        )

    # Convert features to plain Python floats/None while keeping exact row order & count
    feature_records = X_cleaned.to_dict(orient="records")
    events: List[Dict[str, Any]] = []
    for idx, feat_row in enumerate(feature_records):
        clean_feats = {col: (None if pd.isna(val) else float(val)) for col, val in feat_row.items()}
        src_ip = (
            _optional_str(df["IPV4_SRC_ADDR"].iloc[idx]) if "IPV4_SRC_ADDR" in df.columns else None
        )
        dst_ip = (
            _optional_str(df["IPV4_DST_ADDR"].iloc[idx]) if "IPV4_DST_ADDR" in df.columns else None
        )
        src_port = (
            _optional_int(df["L4_SRC_PORT"].iloc[idx]) if "L4_SRC_PORT" in df.columns else None
        )
        dst_port = (
            _optional_int(df["L4_DST_PORT"].iloc[idx]) if "L4_DST_PORT" in df.columns else None
        )
        events.append(
            {
                "event_id": f"csv_{file_sha256[:8]}_{idx}",
                "features": clean_feats,
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "source_port": src_port,
                "dest_port": dst_port,
            }
        )

    all_api_results = []
    first_batch_resp = None
    for start in range(0, len(events), batch_size):
        batch = events[start : start + batch_size]
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
    hard_set = set(raw_ood_report.hard_violation_indices)
    zero_ttl_set = set(raw_ood_report.zero_ttl_indices)

    prediction_items: List[CsvFlowPredictionItem] = []
    abstained_risk_count = 0
    ood_flagged_count = 0
    attack_count = 0

    for idx, api_item in enumerate(all_api_results):
        raw_rid = row_ids[idx]
        row_id: Union[int, str] = (
            int(raw_rid)
            if isinstance(raw_rid, (int, np.integer)) and not isinstance(raw_rid, bool)
            else str(raw_rid)
        )
        is_hard = idx in hard_set
        is_zero_ttl = idx in zero_ttl_set
        is_ood_flagged = is_hard or is_zero_ttl
        ood_reason = None
        if is_hard:
            ood_reason = "Hard protocol invariant violation"
        elif is_zero_ttl:
            ood_reason = "MIN_TTL == 0 unobserved telemetry (anti-imputation abstention)"

        if is_ood_flagged:
            ood_flagged_count += 1

        risk_score, risk_level = compute_deterministic_risk_score(
            is_ood_flagged=is_ood_flagged,
            score_type=api_item.score_type,
            score_direction=api_item.score_direction,
            attack_probability=api_item.attack_probability,
            raw_anomaly_score=api_item.raw_anomaly_score,
            decision_threshold=api_item.decision_threshold,
        )
        if risk_score is None:
            abstained_risk_count += 1

        pred_label = 1 if int(api_item.prediction) == 1 else 0
        if pred_label == 1:
            attack_count += 1

        prediction_items.append(
            CsvFlowPredictionItem(
                row_id=row_id,
                row_index=idx,
                predicted_label=pred_label,
                predicted_class="Attack" if pred_label == 1 else "Benign",
                attack_probability=api_item.attack_probability,
                raw_anomaly_score=api_item.raw_anomaly_score,
                decision_threshold=api_item.decision_threshold,
                score_type=api_item.score_type,
                score_direction=api_item.score_direction,
                risk_score=risk_score,
                risk_level=risk_level,
                is_ood_flagged=is_ood_flagged,
                ood_reason=ood_reason,
                flow_start_ms=(
                    _optional_int(df["FLOW_START_MILLISECONDS"].iloc[idx])
                    if "FLOW_START_MILLISECONDS" in df.columns
                    else None
                ),
                flow_end_ms=(
                    _optional_int(df["FLOW_END_MILLISECONDS"].iloc[idx])
                    if "FLOW_END_MILLISECONDS" in df.columns
                    else None
                ),
                src_ip=(
                    _optional_str(df["IPV4_SRC_ADDR"].iloc[idx])
                    if "IPV4_SRC_ADDR" in df.columns
                    else None
                ),
                dst_ip=(
                    _optional_str(df["IPV4_DST_ADDR"].iloc[idx])
                    if "IPV4_DST_ADDR" in df.columns
                    else None
                ),
                src_port=(
                    _optional_int(df["L4_SRC_PORT"].iloc[idx])
                    if "L4_SRC_PORT" in df.columns
                    else None
                ),
                dst_port=(
                    _optional_int(df["L4_DST_PORT"].iloc[idx])
                    if "L4_DST_PORT" in df.columns
                    else None
                ),
                protocol=(
                    _optional_int(df["PROTOCOL"].iloc[idx]) if "PROTOCOL" in df.columns else None
                ),
                flow_duration_ms=(
                    _optional_int(df["FLOW_DURATION_MILLISECONDS"].iloc[idx])
                    if "FLOW_DURATION_MILLISECONDS" in df.columns
                    else None
                ),
                min_ttl=(
                    _optional_float(df["MIN_TTL"].iloc[idx]) if "MIN_TTL" in df.columns else None
                ),
            )
        )

    timeline = build_deterministic_evidence_timeline(prediction_items) if include_timeline else []
    behavioral = compute_netflow_behavioral_summary(df)
    sample_item = all_api_results[0]
    _, model_type_display, _ = _MODEL_DISPLAY_META[canonical_model]

    return CsvAnalyzeResponse(
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
        benign_count=len(prediction_items) - attack_count,
        attack_count=attack_count,
        ood_flagged_count=ood_flagged_count,
        abstained_risk_count=abstained_risk_count,
        decision_threshold=sample_item.decision_threshold,
        score_type=sample_item.score_type,
        score_direction=sample_item.score_direction,
        compatibility_gate=gate_summary,
        ood_report=_ood_to_schema(raw_ood_report),
        behavioral_summary=behavioral,
        security_notice=_SECURITY_NOTICE,
        results=prediction_items,
        timeline=timeline,
    )


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

    if "row_id" in labels_df.columns:
        lbl_map: Dict[str, Tuple[int, str]] = {}
        for _, row in labels_df.iterrows():
            rid_key = str(row["row_id"])
            if rid_key in lbl_map:
                raise ValueError(f"Duplicate row_id {rid_key!r} in ground truth CSV.")
            lbl_val = _normalize_binary_label(row["Label"])
            att_val = (
                _optional_str(row["Attack"]) or ("Benign" if lbl_val == 0 else "Attack")
                if has_attack_col
                else ("Benign" if lbl_val == 0 else "Attack")
            )
            lbl_map[rid_key] = (lbl_val, att_val)

        for pred in predictions:
            key = str(pred.row_id)
            if key not in lbl_map:
                unmatched += 1
                continue
            yt, att = lbl_map[key]
            y_true.append(yt)
            y_pred.append(int(pred.predicted_label))
            attack_cats.append(att)

        if not y_true:
            raise ValueError("No prediction row_id values matched the ground truth CSV.")
    else:
        if len(labels_df) != len(predictions):
            raise ValueError(
                f"Ground truth row count ({len(labels_df)}) does not match prediction count "
                f"({len(predictions)}) and no 'row_id' column is present for alignment."
            )
        for idx, pred in enumerate(predictions):
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

    return CsvEvaluateResponse(
        labels_path=str(resolved),
        labels_sha256=labels_sha256,
        matched_rows=len(y_true),
        unmatched_rows=unmatched,
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
            "compute_metrics(). Demo balanced subset (~50% Attack) is for UI verification only "
            "and does not reflect production deployment prevalence or held-out Test benchmarks."
        ),
    )


def export_predictions_csv(request: CsvExportRequest) -> CsvExportResponse:
    """Write predictions CSV and companion .metadata.json provenance atomically."""
    csv_out = validate_safe_export_path(
        request.output_path, source_csv_path=request.source_csv_path
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
        "source_csv_path": request.source_csv_path,
        "model_key": request.model_key,
        "model_type": request.model_type,
        "run_id": request.run_id,
        "model_artifact_sha256": request.model_sha256,
        "preprocessor_artifact_sha256": request.preprocessor_sha256,
        "evaluation_summary": (
            request.evaluation.model_dump() if request.evaluation is not None else None
        ),
        "security_notice": _SECURITY_NOTICE,
    }
    import json

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
