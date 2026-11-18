#!/usr/bin/env python3
"""Read-only evaluation of Behavioral Vector Engine (#103) and Risk/Aggregation policies (#108/#109).

Evaluates frozen v2.0 E0 models, TrainOnlyPreprocessor, EventSessionizer, BehavioralVectorBuilder,
BehavioralSimilarityCalculator, EntityBaselineProfiler, MultiModelDecisionAggregator, and RiskScorer
across ait_val, ait_test, ctu_echo, and ctu_windows7ad without retraining or threshold recalibration.
"""

from __future__ import annotations

import json
import math
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = PROJECT_ROOT / "src"
_SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(_SRC_DIR), str(_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from _v2_train_common import (  # noqa: E402
    PREPROC_ARTIFACT_PATH,
    PREPROC_MANIFEST_PATH,
    PROCESSED_V2_DIR,
    SPLIT_MANIFEST_PATH,
    build_environment_block,
)

from network_anomaly.behavioral.sessionizer import EventSessionizer  # noqa: E402
from network_anomaly.behavioral.similarity import (  # noqa: E402
    BehavioralSimilarityCalculator,
    SimilarityMetric,
)
from network_anomaly.behavioral.vector import (  # noqa: E402
    BehavioralVector,
    BehavioralVectorBuilder,
    EntityBaselineProfiler,
)
from network_anomaly.canonical.event import (  # noqa: E402
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.models.registry import ModelRegistry  # noqa: E402
from network_anomaly.models.scoring import validate_score_normalization  # noqa: E402
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402
from network_anomaly.risk.aggregation import (  # noqa: E402
    AggregationPolicy,
    MultiModelDecisionAggregator,
)
from network_anomaly.risk.scoring import RiskScorer  # noqa: E402

OUT_JSON = (
    PROJECT_ROOT / "reports" / "experiments" / "risk" / "behavioral_risk_aggregation_eval.json"
)

PARTITIONS: Tuple[Tuple[str, Path], ...] = (
    ("ait_val", PROCESSED_V2_DIR / "ait_val.csv.gz"),
    ("ait_test", PROCESSED_V2_DIR / "ait_test.csv.gz"),
    ("ctu_echo", PROCESSED_V2_DIR / "ctu_echo.csv.gz"),
    ("ctu_windows7ad", PROCESSED_V2_DIR / "ctu_windows7ad.csv.gz"),
)


def _dist_summary(values: List[float], *, threshold_ge: Optional[float] = None) -> Dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "mean": None,
            "std": None,
            "median": None,
            "p10": None,
            "p90": None,
            "match_rate_ge_0_85": None,
        }
    arr = np.asarray(values, dtype=np.float64)
    out: Dict[str, Any] = {
        "count": int(arr.size),
        "mean": round(float(np.mean(arr)), 4),
        "std": round(float(np.std(arr)), 4),
        "median": round(float(np.median(arr)), 4),
        "p10": round(float(np.percentile(arr, 10)), 4),
        "p90": round(float(np.percentile(arr, 90)), 4),
    }
    if threshold_ge is not None:
        out["match_rate_ge_0_85"] = round(float(np.mean(arr >= threshold_ge)), 4)
    return out


def _select_behavioral_subset(df: pd.DataFrame, max_flows: int = 20_000) -> pd.DataFrame:
    """Select deterministic entity-grouped slice balancing benign and attack entities."""
    if len(df) <= max_flows:
        return df.copy()
    if "source_ip" not in df.columns:
        atk_df = df[df["label_binary"] == 1].iloc[: max_flows // 2]
        ben_df = df[df["label_binary"] == 0].iloc[: max_flows - len(atk_df)]
        return pd.concat([atk_df, ben_df], ignore_index=True)

    atk_rows = df[df["label_binary"] == 1]
    ben_rows = df[df["label_binary"] == 0]
    attack_ips = sorted(atk_rows["source_ip"].dropna().astype(str).unique().tolist())
    attack_ip_set = set(attack_ips)
    benign_ips = sorted(
        ip
        for ip in ben_rows["source_ip"].dropna().astype(str).unique().tolist()
        if ip not in attack_ip_set
    )

    half = max_flows // 2
    chosen_atk = attack_ips[:40]
    atk_slice = df[df["source_ip"].astype(str).isin(chosen_atk)]
    if len(atk_slice) > half:
        # Preserve contiguous windows per selected attack IP evenly
        parts = []
        per_ip = max(1, half // max(1, len(chosen_atk)))
        for ip in chosen_atk:
            parts.append(atk_slice[atk_slice["source_ip"].astype(str) == ip].iloc[:per_ip])
        atk_slice = pd.concat(parts, ignore_index=True).iloc[:half]

    rem = max_flows - len(atk_slice)
    chosen_ben = benign_ips[:40]
    ben_slice = df[df["source_ip"].astype(str).isin(chosen_ben)]
    if len(ben_slice) > rem:
        parts = []
        per_ip = max(1, rem // max(1, len(chosen_ben)))
        for ip in chosen_ben:
            parts.append(ben_slice[ben_slice["source_ip"].astype(str) == ip].iloc[:per_ip])
        ben_slice = pd.concat(parts, ignore_index=True).iloc[:rem]

    return pd.concat([atk_slice, ben_slice], ignore_index=True)


def _build_session_vectors(
    sub_df: pd.DataFrame,
    partition_name: str,
) -> Tuple[List[BehavioralVector], List[bool]]:
    """Sessionize flows into CanonicalSecurityEvents -> 16-D BehavioralVectors and attack labels."""
    n = len(sub_df)
    if n == 0:
        return [], []

    def _col(name: str) -> List[Any]:
        return sub_df[name].tolist() if name in sub_df.columns else [None] * n

    ts_vals = _col("timestamp_ms")
    src_ips = _col("source_ip")
    dst_ips = _col("dest_ip")
    sp_vals = _col("source_port")
    dp_vals = _col("dest_port")
    dur_vals = _col("duration_ms")
    bin_vals = _col("bytes_in")
    bout_vals = _col("bytes_out")
    pin_vals = _col("pkts_in")
    pout_vals = _col("pkts_out")
    proto_vals = _col("raw_protocol_str")
    pnum_vals = _col("protocol_num")
    y_vals = _col("label_binary")

    base_ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events: List[CanonicalSecurityEvent] = []
    entity_attack_ts: Dict[str, List[datetime]] = {}

    for i in range(n):
        ts_raw = ts_vals[i]
        try:
            ts_int = int(ts_raw) if ts_raw is not None and not pd.isna(ts_raw) else 0
        except (TypeError, ValueError):
            ts_int = 0
        ev_ts = (
            datetime.fromtimestamp(ts_int / 1000.0, tz=timezone.utc)
            if ts_int > 0
            else base_ts + timedelta(milliseconds=i)
        )
        src_ip = None if src_ips[i] is None or pd.isna(src_ips[i]) else str(src_ips[i])
        dst_ip = None if dst_ips[i] is None or pd.isna(dst_ips[i]) else str(dst_ips[i])

        def _port(v: Any) -> Optional[int]:
            if v is None or pd.isna(v):
                return None
            iv = int(v)
            return iv if 0 <= iv <= 65535 else None

        def _nonneg_int(v: Any) -> Optional[int]:
            if v is None or pd.isna(v):
                return None
            return max(0, int(v))

        dur_raw = dur_vals[i]
        dur = None
        if dur_raw is not None and not pd.isna(dur_raw):
            fd = float(dur_raw)
            if math.isfinite(fd) and fd >= 0.0:
                dur = fd

        entity_key = f"host:{src_ip}" if src_ip else f"{partition_name}:row_group"
        y_bin = int(y_vals[i]) if y_vals[i] is not None and not pd.isna(y_vals[i]) else 0
        if y_bin == 1:
            entity_attack_ts.setdefault(entity_key, []).append(ev_ts)

        proto = (
            str(proto_vals[i])
            if proto_vals[i] is not None and not pd.isna(proto_vals[i])
            else (
                str(int(pnum_vals[i]))
                if pnum_vals[i] is not None and not pd.isna(pnum_vals[i])
                else None
            )
        )

        events.append(
            CanonicalSecurityEvent(
                event_timestamp=ev_ts,
                event_kind=EventKind.FLOW,
                source_id=partition_name,
                entity_id=entity_key,
                source_ip=src_ip,
                source_port=_port(sp_vals[i]),
                dest_ip=dst_ip,
                dest_port=_port(dp_vals[i]),
                protocol=proto,
                flow_metrics=FlowMetrics(
                    duration_ms=dur,
                    bytes_in=_nonneg_int(bin_vals[i]),
                    bytes_out=_nonneg_int(bout_vals[i]),
                    pkts_in=_nonneg_int(pin_vals[i]),
                    pkts_out=_nonneg_int(pout_vals[i]),
                ),
                raw_provenance=RawProvenance(
                    source_file=f"{partition_name}.csv.gz",
                    line_or_offset=i + 1,
                    adapter_name="v2_parquet_or_csv",
                ),
                attack_category="Attack" if y_bin == 1 else None,
            )
        )

    sessions = EventSessionizer(session_timeout_seconds=300.0).sessionize(events)
    builder = BehavioralVectorBuilder()
    vectors: List[BehavioralVector] = []
    is_attack: List[bool] = []
    for sess in sessions:
        vectors.append(builder.build_vector(sess))
        atk_times = entity_attack_ts.get(sess.entity_key, [])
        has_atk = any(sess.start_time <= t <= sess.end_time for t in atk_times)
        is_attack.append(has_atk)
    return vectors, is_attack


def _evaluate_similarity(
    vectors: List[BehavioralVector],
    is_attack: List[bool],
    *,
    max_per_class: int = 40,
) -> Dict[str, Any]:
    """Compute pairwise Cosine / Euclidean / Manhattan distributions (#103 AC3)."""
    calc = BehavioralSimilarityCalculator()
    benign_vecs = [v for v, a in zip(vectors, is_attack) if not a][:max_per_class]
    attack_vecs = [v for v, a in zip(vectors, is_attack) if a][:max_per_class]

    def _pairwise(
        va: List[BehavioralVector], vb: List[BehavioralVector], same: bool
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for metric in (
            SimilarityMetric.COSINE,
            SimilarityMetric.NORMALIZED_EUCLIDEAN,
            SimilarityMetric.MANHATTAN,
        ):
            vals: List[float] = []
            for i in range(len(va)):
                j_start = i + 1 if same else 0
                for j in range(j_start, len(vb)):
                    vals.append(calc.compute_similarity(va[i], vb[j], metric=metric))
            out[metric.value] = _dist_summary(
                vals,
                threshold_ge=(
                    BehavioralSimilarityCalculator.DEFAULT_MATCH_THRESHOLD
                    if metric == SimilarityMetric.COSINE
                    else None
                ),
            )
        return out

    return {
        "total_sessions": len(vectors),
        "benign_sessions": sum(1 for a in is_attack if not a),
        "attack_sessions": sum(1 for a in is_attack if a),
        "sampled_benign_for_pairwise": len(benign_vecs),
        "sampled_attack_for_pairwise": len(attack_vecs),
        "intra_benign": _pairwise(benign_vecs, benign_vecs, same=True),
        "intra_attack": _pairwise(attack_vecs, attack_vecs, same=True),
        "cross_benign_vs_attack": _pairwise(benign_vecs, attack_vecs, same=False),
    }


def _vectorized_normalize_unsupervised(
    registry: ModelRegistry,
    model_key: str,
    raw_scores: np.ndarray,
) -> np.ndarray:
    backend = registry._backends[model_key]
    curve = validate_score_normalization(getattr(backend, "calibration", None))
    if curve is None:
        raise RuntimeError(f"Missing calibration curve for {model_key}")
    grid_f, value_f = curve
    return np.clip(np.interp(raw_scores, value_f, grid_f), 0.0, 1.0)


def _compute_policy_scores(
    policy: AggregationPolicy,
    rf_p: np.ndarray,
    xgb_p: np.ndarray,
    if_p: np.ndarray,
    ae_p: np.ndarray,
) -> Tuple[np.ndarray, np.ndarray]:
    """Exact vectorized equivalent of MultiModelDecisionAggregator.aggregate()."""
    if policy == AggregationPolicy.WEIGHTED_ENSEMBLE:
        prob = 0.40 * rf_p + 0.30 * xgb_p + 0.15 * if_p + 0.15 * ae_p
        pred = prob >= 0.50
        return prob, pred
    if policy == AggregationPolicy.RANDOM_FOREST_PRIMARY:
        prob = rf_p
        pred = prob >= 0.50
        return prob, pred
    if policy == AggregationPolicy.STRICT_CONSENSUS:
        stack = np.vstack([rf_p, xgb_p, if_p, ae_p])
        pred = np.all(stack >= 0.50, axis=0)
        prob = np.where(pred, np.min(stack, axis=0), np.mean(stack, axis=0))
        return prob, pred
    if policy == AggregationPolicy.MAX_SEVERITY:
        stack = np.vstack([rf_p, xgb_p, if_p, ae_p])
        prob = np.max(stack, axis=0)
        pred = prob >= 0.50
        return prob, pred
    raise ValueError(f"Unknown policy: {policy}")


def _verify_parity_with_domain_objects(
    rf_p: np.ndarray,
    xgb_p: np.ndarray,
    if_p: np.ndarray,
    ae_p: np.ndarray,
    dports: np.ndarray,
) -> None:
    """Cross-check vectorized formulas against MultiModelDecisionAggregator & RiskScorer on 25 flows."""
    scorer = RiskScorer()
    n_check = min(25, len(rf_p))
    for policy in AggregationPolicy:
        agg = MultiModelDecisionAggregator(policy=policy)
        vec_prob, vec_pred = _compute_policy_scores(
            policy, rf_p[:n_check], xgb_p[:n_check], if_p[:n_check], ae_p[:n_check]
        )
        for i in range(n_check):
            d = agg.aggregate(
                rf_prob=float(rf_p[i]),
                xgb_prob=float(xgb_p[i]),
                if_score=float(if_p[i]),
                ae_error_norm=float(ae_p[i]),
            )
            assert abs(d.combined_probability - round(float(vec_prob[i]), 4)) <= 1e-4
            assert d.is_anomaly == bool(vec_pred[i])
            if policy == AggregationPolicy.WEIGHTED_ENSEMBLE:
                dp_val = int(dports[i]) if not np.isnan(dports[i]) else None
                rs = scorer.compute_risk(
                    ai_probability=float(vec_prob[i]),
                    behavioral_anomaly_score=0.0,
                    dest_port=dp_val,
                )
                c_port = (
                    15.0
                    if dp_val in RiskScorer.SENSITIVE_PORTS
                    else (6.0 if dp_val is not None and dp_val < 1024 else 0.0)
                )
                expected = min(100.0, float(vec_prob[i]) * 50.0 + c_port)
                assert abs(rs.score - expected) <= 1e-6


def _binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray) -> Dict[str, Any]:
    tp = int(np.sum((y_true == 1) & y_pred))
    fp = int(np.sum((y_true == 0) & y_pred))
    fn = int(np.sum((y_true == 1) & (~y_pred)))
    tn = int(np.sum((y_true == 0) & (~y_pred)))
    total = max(1, tp + fp + fn + tn)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    auc = float(roc_auc_score(y_true, scores)) if len(np.unique(y_true)) == 2 else None
    return {
        "accuracy": round((tp + tn) / total, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "roc_auc": round(auc, 4) if auc is not None else None,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def _risk_distribution(
    ai_probs: np.ndarray,
    dports: np.ndarray,
    y_true: np.ndarray,
) -> Dict[str, Any]:
    c_port = np.zeros(len(ai_probs), dtype=np.float64)
    valid_dp = ~np.isnan(dports)
    sens_mask = np.isin(np.where(valid_dp, dports, -1), list(RiskScorer.SENSITIVE_PORTS))
    priv_mask = valid_dp & (dports >= 0) & (dports < 1024) & (~sens_mask)
    c_port[sens_mask] = RiskScorer.W_PORT_PROTOCOL
    c_port[priv_mask] = RiskScorer.W_PORT_PROTOCOL * 0.4

    scores = np.clip(np.clip(ai_probs, 0.0, 1.0) * RiskScorer.W_AI_CONFIDENCE + c_port, 0.0, 100.0)

    def _bucket(mask: np.ndarray) -> Dict[str, Any]:
        sub = scores[mask]
        n = int(sub.size)
        if n == 0:
            return {"count": 0}
        crit = int(np.sum(sub >= RiskScorer.CRITICAL_ROTATION_THRESHOLD))
        high = int(
            np.sum(
                (sub >= RiskScorer.HIGH_SEVERITY_THRESHOLD)
                & (sub < RiskScorer.CRITICAL_ROTATION_THRESHOLD)
            )
        )
        med = int(
            np.sum(
                (sub >= RiskScorer.MEDIUM_SEVERITY_THRESHOLD)
                & (sub < RiskScorer.HIGH_SEVERITY_THRESHOLD)
            )
        )
        low = int(np.sum(sub < RiskScorer.MEDIUM_SEVERITY_THRESHOLD))
        return {
            "count": n,
            "mean_score": round(float(np.mean(sub)), 2),
            "p95_score": round(float(np.percentile(sub, 95)), 2),
            "low_count": low,
            "medium_count": med,
            "high_count": high,
            "critical_count": crit,
            "critical_rotation_trigger_rate": round(crit / n, 6),
        }

    return {
        "overall": _bucket(np.ones(len(scores), dtype=bool)),
        "benign_flows": _bucket(y_true == 0),
        "attack_flows": _bucket(y_true == 1),
    }


def main() -> int:
    t0 = time.perf_counter()
    if not PREPROC_ARTIFACT_PATH.is_file():
        raise FileNotFoundError(f"Missing preprocessor: {PREPROC_ARTIFACT_PATH}")
    preproc = TrainOnlyPreprocessor.load(PREPROC_ARTIFACT_PATH)
    registry = ModelRegistry(
        preprocessor_path=PREPROC_ARTIFACT_PATH,
        preprocessor_manifest_path=PREPROC_MANIFEST_PATH,
        warmup=True,
    )

    profiler = EntityBaselineProfiler(window_size=50)
    behavioral_results: Dict[str, Any] = {}
    policy_results: Dict[str, Any] = {}
    parity_verified = False

    for part_name, csv_path in PARTITIONS:
        if not csv_path.is_file():
            raise FileNotFoundError(f"Missing partition CSV: {csv_path}")
        print(f"[eval] Loading {part_name} ({csv_path.name})...", flush=True)
        df = pd.read_csv(csv_path, low_memory=False)
        X_scaled = preproc.transform(df[list(ML_FEATURE_COLUMNS)].copy(), partition_name=part_name)
        X_np = X_scaled.to_numpy(dtype=np.float64)
        y_true = df["label_binary"].to_numpy(dtype=np.int64)
        dports = (
            pd.to_numeric(df["dest_port"], errors="coerce").to_numpy(dtype=np.float64)
            if "dest_port" in df.columns
            else np.full(len(df), np.nan, dtype=np.float64)
        )

        # Model inference
        rf_p, _ = registry.score_batch("random_forest", X_np)
        xgb_p, _ = registry.score_batch("xgboost", X_np)
        if_raw, _ = registry.score_batch("isolation_forest", X_np)
        ae_raw, _ = registry.score_batch("autoencoder", X_np)
        if_p = _vectorized_normalize_unsupervised(registry, "isolation_forest", if_raw)
        ae_p = _vectorized_normalize_unsupervised(registry, "autoencoder", ae_raw)

        if not parity_verified:
            _verify_parity_with_domain_objects(rf_p, xgb_p, if_p, ae_p, dports)
            parity_verified = True

        # Multi-model aggregation & RiskScorer across all flows
        part_policies: Dict[str, Any] = {"row_count": int(len(df)), "policies": {}}
        for policy in AggregationPolicy:
            comb_prob, pred = _compute_policy_scores(policy, rf_p, xgb_p, if_p, ae_p)
            part_policies["policies"][policy.value] = {
                "classification": _binary_metrics(y_true, pred, comb_prob),
                "risk_flow_only_beh0": _risk_distribution(comb_prob, dports, y_true),
            }
        policy_results[part_name] = part_policies

        # Behavioral Vector Engine evaluation (#103 AC3)
        sub_df = _select_behavioral_subset(df, max_flows=20_000)
        vectors, is_attack = _build_session_vectors(sub_df, part_name)
        sim_stats = _evaluate_similarity(vectors, is_attack, max_per_class=40)

        # Warm EntityBaselineProfiler ONLY from ait_val benign sessions (zero leakage)
        if part_name == "ait_val":
            for vec, atk in zip(vectors, is_attack):
                if not atk:
                    # Group under common reference key or per-entity key
                    profiler.update(vec)

        benign_devs: List[float] = []
        attack_devs: List[float] = []
        has_base_cnt = 0
        for vec, atk in zip(vectors, is_attack):
            res = profiler.score_deviation(vec)
            if res["has_baseline"]:
                has_base_cnt += 1
            if atk:
                attack_devs.append(float(res["deviation_score"]))
            else:
                benign_devs.append(float(res["deviation_score"]))

        sim_stats["baseline_profiler_deviation"] = {
            "baseline_matched_sessions": has_base_cnt,
            "benign_sessions": _dist_summary(benign_devs),
            "attack_sessions": _dist_summary(attack_devs),
        }
        behavioral_results[part_name] = sim_stats

    report = {
        "schema_version": "2.0.0",
        "evaluation_mode": "read_only_frozen_E0_no_retraining",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.perf_counter() - t0, 2),
        "split_manifest": str(SPLIT_MANIFEST_PATH.relative_to(PROJECT_ROOT)).replace("\\", "/"),
        "environment": build_environment_block(),
        "domain_parity_verified": parity_verified,
        "risk_scorer_formula": {
            "weights": {
                "ai_confidence": RiskScorer.W_AI_CONFIDENCE,
                "behavioral_deviation": RiskScorer.W_BEHAVIORAL_DEV,
                "port_protocol": RiskScorer.W_PORT_PROTOCOL,
                "auth_failures": RiskScorer.W_AUTH_FAILURES,
            },
            "thresholds": {
                "medium": RiskScorer.MEDIUM_SEVERITY_THRESHOLD,
                "high": RiskScorer.HIGH_SEVERITY_THRESHOLD,
                "critical_rotation": RiskScorer.CRITICAL_ROTATION_THRESHOLD,
                "ood_cap": 65.0,
            },
            "note": (
                "Full-partition RiskScorer metrics evaluate AI confidence + dest_port sensitivity "
                "(behavioral_deviation=0.0, auth_failures=0 because NetFlow partitions contain flow "
                "telemetry without OS auth logs and baseline profiling varies per host history)."
            ),
        },
        "behavioral_engine_evaluation": behavioral_results,
        "policy_and_risk_evaluation": policy_results,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(
        f"[done] Behavioral & Risk Policy Evaluation written: {OUT_JSON} ({report['elapsed_seconds']}s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
