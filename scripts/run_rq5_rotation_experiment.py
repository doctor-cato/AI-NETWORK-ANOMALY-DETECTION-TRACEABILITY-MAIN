#!/usr/bin/env python3
"""Research Experiment RQ5: Fixed vs Adaptive Key Rotation Simulation (Issue #125).

Labeled explicitly as SIMULATION. Computes all exposure windows, per-key record
counts, detection-to-rotation durations, and blast radius dynamically from the
recorded simulated event timeline and rotation history (never hardcoded).
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPTS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPTS_DIR.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from _rq_common import collect_environment_metadata  # noqa: E402

from network_anomaly.crypto.key_manager import KeyManager  # noqa: E402
from network_anomaly.crypto.rotation import (  # noqa: E402
    KeyRotationPolicy,
    RotationDecision,
    RotationTrigger,
)


def _compute_exposure_metrics(
    timeline: List[Dict[str, Any]],
    rotations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Derive exposure window, per-key counts, blast radius, and detection-to-rotation time."""
    records_per_key: Counter[str] = Counter()
    attack_records_per_key: Counter[str] = Counter()
    key_first_attack_sec: Dict[str, float] = {}
    key_last_attack_or_end_sec: Dict[str, float] = {}

    for rec in timeline:
        kid = rec["key_id"]
        t_sec = float(rec["sim_elapsed_s"])
        records_per_key[kid] += 1
        if rec["is_attack"]:
            attack_records_per_key[kid] += 1
            if kid not in key_first_attack_sec:
                key_first_attack_sec[kid] = t_sec
            key_last_attack_or_end_sec[kid] = t_sec

    # If a key used during an attack rotated later, its exposure lasted until rotation completed;
    # otherwise until the last attack event observed under that key.
    rotation_by_old_key = {
        r["old_key_id"]: float(r["sim_completed_s"])
        for r in rotations
        if r.get("old_key_id") and r.get("decision") == RotationDecision.EXECUTED.value
    }

    exposure_windows_s: List[float] = []
    for kid, first_atk_s in key_first_attack_sec.items():
        end_s = rotation_by_old_key.get(kid, key_last_attack_or_end_sec[kid])
        exposure_windows_s.append(max(0.0, end_s - first_atk_s))

    max_exposure_s = max(exposure_windows_s) if exposure_windows_s else 0.0
    max_blast_radius = max(attack_records_per_key.values(), default=0)

    first_attack_s = min((r["sim_elapsed_s"] for r in timeline if r["is_attack"]), default=None)
    first_attack_rot_s = next(
        (
            r["sim_completed_s"]
            for r in rotations
            if r["decision"] == RotationDecision.EXECUTED.value
            and first_attack_s is not None
            and r["sim_elapsed_s"] >= first_attack_s
        ),
        None,
    )
    detection_to_rotation_s = (
        round(first_attack_rot_s - first_attack_s, 3)
        if (first_attack_s is not None and first_attack_rot_s is not None)
        else None
    )

    return {
        "records_per_key": dict(records_per_key),
        "attack_records_per_key": dict(attack_records_per_key),
        "max_attack_key_exposure_seconds": round(max_exposure_s, 3),
        "max_attack_key_exposure_minutes": round(max_exposure_s / 60.0, 4),
        "blast_radius_max_attack_records_single_key": int(max_blast_radius),
        "detection_to_rotation_seconds": detection_to_rotation_s,
    }


def run_rq5_experiment(output_dir: Optional[Path] = None) -> Dict[str, Any]:
    output_dir = output_dir or Path("reports/experiments/crypto")
    output_dir.mkdir(parents=True, exist_ok=True)
    env = collect_environment_metadata()

    t0 = datetime(2026, 11, 17, 10, 0, 0, tzinfo=timezone.utc)
    step_seconds = 30.0  # 120 events * 30s = 60 simulated minutes
    total_events = 120

    def _event_spec(idx: int) -> tuple[bool, float]:
        # Attack burst occurs during events 20..79 (minutes 10..40, crossing the 30-min boundary)
        if 20 <= idx < 80:
            return True, 88.0 + float(idx % 10)
        return False, 20.0 + float(idx % 10)

    with tempfile.TemporaryDirectory() as tmp:
        keystore_root = Path(tmp) / "keys"

        # 1. FIXED ROTATION BASELINE (30-minute = 1800s fixed schedule)
        km_fixed = KeyManager(keystore_dir=keystore_root / "fixed")
        policy_fixed = KeyRotationPolicy(km_fixed, fixed_interval_seconds=1800, cooldown_seconds=0)
        fixed_timeline: List[Dict[str, Any]] = []
        fixed_rotations: List[Dict[str, Any]] = []
        last_fixed_rot_s = 0.0

        for i in range(total_events):
            sim_s = i * step_seconds
            ts_iso = (t0 + timedelta(seconds=sim_s)).isoformat()
            is_atk, risk = _event_spec(i)

            if sim_s - last_fixed_rot_s >= 1800.0:
                old_id, _ = km_fixed.get_active_key()
                dec, detail = policy_fixed.execute_rotation(
                    trigger=RotationTrigger.FIXED_SCHEDULE,
                    reason=f"Fixed 30m schedule at sim_s={sim_s}",
                )
                last_fixed_rot_s = sim_s
                fixed_rotations.append(
                    {
                        "sim_elapsed_s": sim_s,
                        "sim_completed_s": sim_s,
                        "timestamp_utc": ts_iso,
                        "trigger": RotationTrigger.FIXED_SCHEDULE.value,
                        "decision": dec.value,
                        "old_key_id": old_id,
                        "new_key_id": detail if dec == RotationDecision.EXECUTED else None,
                    }
                )

            active_id, _ = km_fixed.get_active_key()
            fixed_timeline.append(
                {
                    "event_index": i,
                    "sim_elapsed_s": sim_s,
                    "timestamp_utc": ts_iso,
                    "is_attack": is_atk,
                    "risk_score": risk,
                    "key_id": active_id,
                }
            )

        # 2. ADAPTIVE RISK ROTATION (Threshold >= 85.0, 180s sim cooldown)
        km_adapt = KeyManager(keystore_dir=keystore_root / "adaptive")
        policy_adapt = KeyRotationPolicy(km_adapt, cooldown_seconds=0, adaptive_risk_threshold=85.0)
        adapt_timeline: List[Dict[str, Any]] = []
        adapt_rotations: List[Dict[str, Any]] = []
        last_adapt_rot_s = -1e9
        sim_cooldown_s = 180.0

        for i in range(total_events):
            sim_s = i * step_seconds
            ts_iso = (t0 + timedelta(seconds=sim_s)).isoformat()
            is_atk, risk = _event_spec(i)

            active_before, _ = km_adapt.get_active_key()
            # Record event with current key first, then trigger adaptive rotation if risk >= 85
            adapt_timeline.append(
                {
                    "event_index": i,
                    "sim_elapsed_s": sim_s,
                    "timestamp_utc": ts_iso,
                    "is_attack": is_atk,
                    "risk_score": risk,
                    "key_id": active_before,
                }
            )

            if risk >= 85.0 and (sim_s - last_adapt_rot_s) >= sim_cooldown_s:
                dec, detail = policy_adapt.evaluate_adaptive_rotation(
                    risk_score=risk, context={"event_index": i}
                )
                if dec == RotationDecision.EXECUTED:
                    last_adapt_rot_s = sim_s
                    # Key rotation completion occurs within the event processing step
                    adapt_rotations.append(
                        {
                            "sim_elapsed_s": sim_s,
                            "sim_completed_s": sim_s + 0.01,
                            "timestamp_utc": ts_iso,
                            "trigger": RotationTrigger.ADAPTIVE_RISK.value,
                            "decision": dec.value,
                            "old_key_id": active_before,
                            "new_key_id": detail,
                        }
                    )

        fixed_metrics = _compute_exposure_metrics(fixed_timeline, fixed_rotations)
        adapt_metrics = _compute_exposure_metrics(adapt_timeline, adapt_rotations)

    fixed_exp_m = fixed_metrics["max_attack_key_exposure_minutes"]
    adapt_exp_m = adapt_metrics["max_attack_key_exposure_minutes"]
    reduction_pct = ((fixed_exp_m - adapt_exp_m) / fixed_exp_m) * 100.0 if fixed_exp_m > 0 else 0.0

    blast_fixed = fixed_metrics["blast_radius_max_attack_records_single_key"]
    blast_adapt = adapt_metrics["blast_radius_max_attack_records_single_key"]
    blast_reduction_pct = (
        ((blast_fixed - blast_adapt) / blast_fixed) * 100.0 if blast_fixed > 0 else 0.0
    )

    results: Dict[str, Any] = {
        "experiment_id": "EXP-RQ5-ROTATION-01",
        "execution_mode": "SIMULATION",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hypothesis": "H5: Adaptive Key Rotation reduces attack-key exposure window >= 70% vs fixed 30-min schedule",
        "environment": env,
        "simulation_config": {
            "total_events": total_events,
            "step_seconds": step_seconds,
            "simulated_duration_minutes": (total_events * step_seconds) / 60.0,
            "attack_window_events": "20..79",
            "fixed_interval_minutes": 30.0,
            "adaptive_risk_threshold": 85.0,
            "adaptive_cooldown_seconds": sim_cooldown_s,
        },
        "fixed_schedule": {
            "total_rotations": len(fixed_rotations),
            "rotations": fixed_rotations,
            **fixed_metrics,
        },
        "adaptive_rotation": {
            "total_rotations": len(adapt_rotations),
            "rotations": adapt_rotations,
            **adapt_metrics,
            "exposure_reduction_percentage": round(reduction_pct, 2),
            "blast_radius_reduction_percentage": round(blast_reduction_pct, 2),
        },
        "hypothesis_confirmed": reduction_pct >= 70.0,
        "event_timeline_sample": adapt_timeline[18:25],
        "limitations": [
            "Results come from a deterministic 60-minute discrete-time lab simulation using real KeyManager/KeyRotationPolicy objects, not long-duration production traffic.",
        ],
    }

    manifest_path = output_dir / "rq5_rotation_experiment.json"
    manifest_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")

    report_path = output_dir / "rq5_rotation_report.md"
    md_lines = [
        "# Research Experiment RQ5: Fixed vs Adaptive Key Rotation (SIMULATION)",
        "",
        f"- **Execution Mode:** `{results['execution_mode']}`",
        f"- **Timestamp (UTC):** `{results['timestamp']}`",
        f"- **Hypothesis Confirmed (>= 70% exposure reduction):** `{results['hypothesis_confirmed']}`",
        "",
        "## Computed Metrics from Recorded Timeline",
        "",
        "| Metric | Fixed 30m Schedule | Adaptive Risk (>= 85) | Delta / Reduction |",
        "|---|---:|---:|---:|",
        f"| Total Key Rotations | {len(fixed_rotations)} | {len(adapt_rotations)} | - |",
        f"| Max Attack-Key Exposure (min) | {fixed_exp_m:.4f} | {adapt_exp_m:.4f} | {reduction_pct:.2f}% |",
        f"| Blast Radius (max attack records / key) | {blast_fixed} | {blast_adapt} | {blast_reduction_pct:.2f}% |",
        f"| Detection-to-Rotation (s) | {fixed_metrics['detection_to_rotation_seconds']} | {adapt_metrics['detection_to_rotation_seconds']} | - |",
        "",
        "## Limitations",
        *[f"- {lim}" for lim in results["limitations"]],
    ]
    report_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
    print(f"RQ5 simulation report written: {manifest_path} and {report_path}")
    return results


if __name__ == "__main__":
    run_rq5_experiment(Path("reports/experiments/crypto"))
