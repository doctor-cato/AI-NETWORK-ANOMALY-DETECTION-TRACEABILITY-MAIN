"""Deterministic Adaptive Security Response Simulation / Dry-Run Engine (Issue #27 / C8).

IMPORTANT SAFETY BOUNDARIES:
1. DRY-RUN / RECOMMENDED ONLY: Evaluates deterministic policy recommendations
   (`NO_ACTION`, `MONITOR`, `INVESTIGATE`, `ISOLATE_RECOMMENDED`) and simulated
   adaptive key-rotation readiness without touching OS firewalls, PowerShell,
   external subprocesses, or real cryptographic keys.
2. FAIL-CLOSED OOD GUARD: Any flow flagged `ABSTAINED_OOD` (physical invariant
   violation or telemetry drift) is strictly prohibited from receiving containment
   recommendations (`ISOLATE_RECOMMENDED`) or auto-rotation escalation alone.
3. DEFERRED SCOPE DISTINCTION: Production AES-256-GCM keyring encryption, live
   automatic cryptographic key rotation, and OS firewall execution remain DEFERRED.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from network_anomaly.api.desktop_csv import (
    _SECURITY_NOTICE,
    _atomic_write_text,
    _canonical_results_sha256,
    _get_analysis_store,
    _sha256_file,
    _utc_now_iso,
    validate_safe_csv_path,
    validate_safe_export_path,
)
from network_anomaly.api.repositories import (
    KeyMetadataRepository,
    ResponseSimulationRepository,
    RotationAuditRepository,
)
from network_anomaly.api.schemas import (
    AdaptiveKeyRotationSimulation,
    CompatibilityGateSummarySchema,
    CsvFlowPredictionItem,
    PaginatedSecuritySimulationsResponse,
    ResponseFlowRecommendationItem,
    SecurityResponseSimulateRequest,
    SecurityResponseSimulationResponse,
    SecuritySimulationExportRequest,
    SecuritySimulationExportResponse,
    SecuritySimulationHistoryItem,
)
from network_anomaly.api.service import ROTATION_COOLDOWN_SECONDS, ApiService

DEFERRED_CAPABILITIES: Tuple[str, ...] = (
    "production_aes256_gcm_keyring",
    "automatic_real_key_rotation",
    "os_firewall_command_execution",
)

ACTION_PRIORITY: Dict[str, int] = {
    "NO_ACTION": 0,
    "MONITOR": 1,
    "INVESTIGATE": 2,
    "ISOLATE_RECOMMENDED": 3,
}

SEVERITY_BY_ACTION: Dict[str, str] = {
    "NO_ACTION": "INFO",
    "MONITOR": "LOW",
    "INVESTIGATE": "MEDIUM",
    "ISOLATE_RECOMMENDED": "CRITICAL",
}

ADAPTIVE_ROTATION_MIN_ATTACK_RATIO: float = 0.25
ADAPTIVE_ROTATION_MIN_ESCALATED_FLOWS: int = 5

DISALLOWED_ISOLATION_COMPAT_STATUSES: frozenset[str] = frozenset(
    {
        "INCOMPATIBLE",
        "UNVERIFIED_CLIENT_INPUT",
        "BENCHMARK_FAILED",
        "SCHEMA_INVALID",
        "FEATURE_INCOMPATIBLE",
        "VALIDATION_NOT_VERIFIED",
        "UNVALIDATED",
        "PARSEABLE",
    }
)


def _build_flow_provenance(
    *,
    item: CsvFlowPredictionItem,
    analysis_id: Optional[str],
    model_key: str,
    model_type: str,
    run_id: Optional[str],
    model_sha256: Optional[str],
    source_id: str,
    provenance_verified: bool,
    provenance_verification: str,
    compatibility_status: str,
    inference_mode: str,
) -> Dict[str, Any]:
    return {
        "analysis_id": analysis_id,
        "row_id": item.row_id,
        "model_key": model_key,
        "model_type": model_type,
        "run_id": run_id,
        "model_sha256": model_sha256,
        "source_id": source_id,
        "provenance_verified": bool(provenance_verified),
        "provenance_verification": provenance_verification,
        "compatibility_status": compatibility_status,
        "inference_mode": inference_mode,
        "score_type": item.score_type,
        "risk_score": item.risk_score,
        "risk_level": item.risk_level,
        "ood_flagged": bool(item.is_ood_flagged or item.predicted_class == "ABSTAINED_OOD"),
    }


def evaluate_flow_response_policy(
    item: CsvFlowPredictionItem,
    *,
    analysis_id: Optional[str] = None,
    model_key: str = "random_forest",
    model_type: str = "Random Forest",
    run_id: Optional[str] = None,
    model_sha256: Optional[str] = None,
    source_id: str = "source:nf-v3-unverified",
    provenance_verified: bool = False,
    provenance_verification: str = "client_supplied_unverified",
    compatibility_status: str = "VALIDATION_NOT_VERIFIED",
    eligible: bool = True,
    inference_mode: str = "verified_model",
) -> ResponseFlowRecommendationItem:
    """Evaluate deterministic Issue #27 dry-run policy for a single flow prediction.

    Rules (in strict priority order):
    1. OOD Guard (`is_ood_flagged`, `ABSTAINED_OOD`, `predicted_label is None`, or
       `risk_level == "ABSTAINED_OOD"`): NEVER issues `ISOLATE_RECOMMENDED`; issues
       `MONITOR` (zero-TTL drift only) or `INVESTIGATE` (physical invariant violation).
    2. Benign (`predicted_class == "Benign"` or `predicted_label == 0`): issues
       `MONITOR` when borderline risk >= 25.0, else `NO_ACTION`.
    3. Attack (`predicted_class == "Attack"` or `predicted_label == 1`):
       - `CRITICAL` (`risk_score >= 80.0`) with `provenance_verification == "server_verified_analysis"`,
         non-empty `analysis_id`, `inference_mode == "verified_model"`, and compatible & eligible gate
         -> `ISOLATE_RECOMMENDED` (`CRITICAL`, advisory only);
         otherwise downgraded to `INVESTIGATE` (`HIGH`) without containment permission.
       - `HIGH` (`50.0 <= risk_score < 80.0`) or unavailable risk -> `INVESTIGATE` (`HIGH`).
       - `MEDIUM` (`25.0 <= risk_score < 50.0`) -> `MONITOR` (`MEDIUM`).
       - `LOW` (`risk_score < 25.0`) -> `MONITOR` (`LOW`).
    """
    is_ood = (
        bool(item.is_ood_flagged)
        or item.predicted_class == "ABSTAINED_OOD"
        or item.predicted_label is None
        or item.risk_level == "ABSTAINED_OOD"
    )
    provenance = _build_flow_provenance(
        item=item,
        analysis_id=analysis_id,
        model_key=model_key,
        model_type=model_type,
        run_id=run_id,
        model_sha256=model_sha256,
        source_id=source_id,
        provenance_verified=provenance_verified,
        provenance_verification=provenance_verification,
        compatibility_status=compatibility_status,
        inference_mode=inference_mode,
    )

    containment_allowed = False
    if is_ood:
        reason_lower = (item.ood_reason or "").lower()
        zero_ttl_only = (
            ("min_ttl" in reason_lower or "zero_ttl" in reason_lower or "ttl=0" in reason_lower)
            and "physical" not in reason_lower
            and "invariant" not in reason_lower
        )
        if zero_ttl_only:
            action = "MONITOR"
            severity = "LOW"
        else:
            action = "INVESTIGATE"
            severity = "MEDIUM"
        reason = (
            "ABSTAINED_OOD guard enforced: telemetry drifted or violated physical invariants "
            f"({item.ood_reason or 'OOD abstention'}); automatic containment strictly prohibited."
        )
    elif item.predicted_class == "Benign" or item.predicted_label == 0:
        if item.risk_score is not None and item.risk_score >= 25.0:
            action = "MONITOR"
            severity = "LOW"
            reason = (
                f"Predicted Benign with borderline risk priority {item.risk_score:.1f}; "
                "passive monitoring recommended (dry-run only)."
            )
        else:
            action = "NO_ACTION"
            severity = "INFO"
            score_txt = f"{item.risk_score:.1f}" if item.risk_score is not None else "N/A"
            reason = (
                f"Predicted Benign within normal thresholds (risk {score_txt}); "
                "no intervention required."
            )
    else:
        risk_val = item.risk_score
        risk_tier = (item.risk_level or "").upper()
        is_server_verified = provenance_verification == "server_verified_analysis" and bool(
            analysis_id
        )
        evidence_ok = (
            is_server_verified
            and inference_mode == "verified_model"
            and bool(eligible)
            and compatibility_status not in DISALLOWED_ISOLATION_COMPAT_STATUSES
        )
        is_critical = risk_tier == "CRITICAL" or (risk_val is not None and risk_val >= 80.0)
        score_txt = f"{risk_val:.1f}" if risk_val is not None else "N/A"
        if is_critical and risk_val is not None and risk_val >= 80.0 and evidence_ok:
            action = "ISOLATE_RECOMMENDED"
            severity = "CRITICAL"
            containment_allowed = True
            prov_note = (
                "canonical provenance verified"
                if provenance_verified
                else "external unverified CSV source"
            )
            reason = (
                f"Attack predicted with CRITICAL risk {score_txt} by verified {model_type} "
                f"({prov_note}); host/flow isolation RECOMMENDED in dry-run simulation only "
                "(executed=false)."
            )
        elif is_critical or risk_tier == "HIGH" or (risk_val is not None and risk_val >= 50.0):
            action = "INVESTIGATE"
            severity = "HIGH"
            if not is_critical:
                downgrade_note = ""
            elif not is_server_verified:
                downgrade_note = (
                    " [downgraded from isolation: requires server-verified analysis provenance]"
                )
            else:
                downgrade_note = (
                    " [downgraded from isolation because evidence/risk gate is unverified]"
                )
            reason = (
                f"Attack predicted with risk {score_txt} ({risk_tier or 'UNAVAILABLE'}); "
                f"SOC analyst triage recommended{downgrade_note}."
            )
        elif risk_tier == "MEDIUM" or (risk_val is not None and risk_val >= 25.0):
            action = "MONITOR"
            severity = "MEDIUM"
            reason = (
                f"Attack predicted with moderate risk ({score_txt}); "
                "elevated telemetry watch recommended without containment."
            )
        else:
            action = "MONITOR"
            severity = "LOW"
            reason = (
                f"Attack predicted with low/unavailable risk ({score_txt}); "
                "monitor correlation window before escalation."
            )

    return ResponseFlowRecommendationItem(
        row_id=item.row_id,
        row_index=item.row_index,
        predicted_class=item.predicted_class,
        is_ood_flagged=is_ood,
        risk_score=None if is_ood else item.risk_score,
        risk_level="ABSTAINED_OOD" if is_ood else item.risk_level,
        action=action,
        severity=severity,
        action_status="RECOMMENDED",
        simulation_status="SIMULATED",
        executed=False,
        execution_status="NOT_EXECUTED",
        containment_allowed=containment_allowed,
        reason=reason,
        src_ip=item.src_ip,
        dst_ip=item.dst_ip,
        src_port=item.src_port,
        dst_port=item.dst_port,
        flow_start_ms=item.flow_start_ms,
        provenance=provenance,
    )


def evaluate_adaptive_key_rotation(
    service: ApiService,
    *,
    recommendations: Sequence[ResponseFlowRecommendationItem],
    total_flows: int,
    evaluated_flows: int,
    ood_abstained_flows: int,
    provenance_verification: str = "client_supplied_unverified",
    analysis_id: Optional[str] = None,
) -> AdaptiveKeyRotationSimulation:
    """Simulate an adaptive key rotation readiness decision without generating or changing keys."""
    with service.db.transaction() as conn:
        active = KeyMetadataRepository.get_active_key(conn)
        last_rot = RotationAuditRepository.get_last_rotation(conn)

    active_key_id = active.get("key_id") if active else None
    active_version = (
        int(active["version"]) if active and active.get("version") is not None else None
    )
    next_version = (active_version + 1) if active_version is not None else 1

    cooldown_remaining = 0.0
    if last_rot and last_rot.get("status") == "SUCCESS":
        try:
            last_dt = datetime.fromisoformat(str(last_rot["created_at"]))
            elapsed = max(0.0, (datetime.now(timezone.utc) - last_dt).total_seconds())
            if elapsed < ROTATION_COOLDOWN_SECONDS:
                cooldown_remaining = round(ROTATION_COOLDOWN_SECONDS - elapsed, 3)
        except (TypeError, ValueError):
            cooldown_remaining = 0.0

    server_verified = provenance_verification == "server_verified_analysis" and bool(analysis_id)
    isolate_count = sum(1 for r in recommendations if r.action == "ISOLATE_RECOMMENDED")
    investigate_non_ood = sum(
        1 for r in recommendations if r.action == "INVESTIGATE" and not r.is_ood_flagged
    )
    attack_ratio = (
        round(sum(1 for r in recommendations if r.predicted_class == "Attack") / evaluated_flows, 4)
        if evaluated_flows > 0
        else 0.0
    )
    trigger_metrics = {
        "total_flows": total_flows,
        "evaluated_flows": evaluated_flows,
        "ood_abstained_flows": ood_abstained_flows,
        "isolate_recommended_flows": isolate_count,
        "investigate_attack_flows": investigate_non_ood,
        "evaluated_attack_ratio": attack_ratio,
        "provenance_verification": provenance_verification,
        "server_verified_provenance": server_verified,
    }

    pressure_triggered = isolate_count >= 1 or (
        attack_ratio >= ADAPTIVE_ROTATION_MIN_ATTACK_RATIO
        and (isolate_count + investigate_non_ood) >= ADAPTIVE_ROTATION_MIN_ESCALATED_FLOWS
    )

    if evaluated_flows == 0 and ood_abstained_flows > 0:
        decision = "HOLD_OOD_ABSTAINED"
        recommended = False
        would_rotate = False
        reason = (
            "All flows abstained under OOD invariants; adaptive key rotation simulation "
            "suppressed to prevent drift-driven churn."
        )
    elif not server_verified:
        decision = "HOLD_UNVERIFIED_PROVENANCE"
        recommended = False
        would_rotate = False
        reason = (
            "Client-supplied simulation inputs lack server-verified analysis provenance "
            "(analysis_id); adaptive key rotation escalation is suppressed."
        )
    elif pressure_triggered and cooldown_remaining > 0.0:
        decision = "DEFERRED_COOLDOWN"
        recommended = True
        would_rotate = False
        reason = (
            f"Adaptive rotation policy triggered ({isolate_count} ISOLATE_RECOMMENDED, "
            f"attack_ratio={attack_ratio:.2%}), but simulated rotation is rate-limited "
            f"({cooldown_remaining:.2f}s cooldown remaining). Real keyring remains DEFERRED."
        )
    elif pressure_triggered:
        decision = "SIMULATED_ROTATION_RECOMMENDED"
        recommended = True
        would_rotate = True
        reason = (
            f"High-risk attack pressure detected ({isolate_count} ISOLATE_RECOMMENDED flows, "
            f"attack_ratio={attack_ratio:.2%}); simulated metadata transition "
            f"{active_key_id or 'none'} -> proposed v{next_version}. Zero real cryptographic keys generated."
        )
    else:
        decision = "NO_ROTATION_NEEDED"
        recommended = False
        would_rotate = False
        reason = (
            f"Threat pressure below adaptive key-rotation threshold ({isolate_count} "
            f"ISOLATE_RECOMMENDED, attack_ratio={attack_ratio:.2%}); retaining current key policy metadata."
        )

    return AdaptiveKeyRotationSimulation(
        decision=decision,
        recommended=recommended,
        would_rotate=would_rotate,
        simulation_status="SIMULATED",
        executed=False,
        key_material_generated=False,
        real_key_modified=False,
        keyring_status="DEFERRED_PRODUCTION_KEYRING",
        active_key_id=active_key_id,
        active_key_version=active_version,
        simulated_next_version=next_version if would_rotate else None,
        cooldown_seconds=ROTATION_COOLDOWN_SECONDS,
        cooldown_remaining_seconds=cooldown_remaining,
        trigger_metrics=trigger_metrics,
        reason=reason,
    )


def _resolve_simulation_inputs(
    service: ApiService,
    request: SecurityResponseSimulateRequest,
) -> Tuple[
    List[CsvFlowPredictionItem],
    str,
    str,
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
    Optional[str],
    str,
    CompatibilityGateSummarySchema,
    str,
]:
    """Resolve and verify flow predictions and provenance before policy evaluation."""
    if request.analysis_id:
        lock, store = _get_analysis_store(service)
        with lock:
            rec = store.get(request.analysis_id)
        if rec is None:
            raise ValueError(
                f"Unknown or expired analysis_id {request.analysis_id!r}; run CSV analysis first."
            )
        if request.results is not None and (
            _canonical_results_sha256(request.results) != rec["results_sha256"]
        ):
            raise ValueError(
                "Submitted prediction rows do not match server-recorded analysis results."
            )
        if request.source_csv_path is not None:
            req_src = str(validate_safe_csv_path(request.source_csv_path))
            if req_src != rec["source_csv_path"]:
                raise ValueError("source_csv_path does not match server-recorded analysis CSV.")
        if request.model_key is not None and request.model_key != rec["model_key"]:
            raise ValueError("model_key does not match server-recorded analysis model.")
        if request.model_type is not None and request.model_type != rec["model_type"]:
            raise ValueError("model_type does not match server-recorded analysis model.")
        if request.run_id is not None and request.run_id != rec["run_id"]:
            raise ValueError("run_id does not match server-recorded analysis run_id.")
        if request.model_sha256 is not None and request.model_sha256 != rec["model_sha256"]:
            raise ValueError("model_sha256 does not match server-recorded model artifact digest.")
        if (
            request.preprocessor_sha256 is not None
            and request.preprocessor_sha256 != rec["preprocessor_sha256"]
        ):
            raise ValueError(
                "preprocessor_sha256 does not match server-recorded preprocessor digest."
            )
        if request.inference_mode is not None and request.inference_mode != rec["inference_mode"]:
            raise ValueError(
                "inference_mode does not match server-recorded analysis inference_mode."
            )
        if (
            request.compatibility_gate is not None
            and request.compatibility_gate.model_dump() != rec["compatibility_gate"]
        ):
            raise ValueError(
                "compatibility_gate does not match server-recorded analysis compatibility gate."
            )

        items = [CsvFlowPredictionItem.model_validate(r) for r in rec["results"]]
        gate = CompatibilityGateSummarySchema.model_validate(rec["compatibility_gate"])
        return (
            items,
            rec["model_key"],
            rec["model_type"],
            rec["run_id"],
            rec["model_sha256"],
            rec["preprocessor_sha256"],
            rec["source_csv_path"],
            rec["source_csv_sha256"],
            rec["inference_mode"],
            gate,
            "server_verified_analysis",
        )

    items = list(request.results or [])
    model_key = request.model_key or "unknown"
    model_type = request.model_type or model_key
    source_csv_path: Optional[str] = None
    source_csv_sha256: Optional[str] = None
    if request.source_csv_path:
        resolved = validate_safe_csv_path(request.source_csv_path)
        source_csv_path = str(resolved)
        source_csv_sha256 = _sha256_file(resolved)

    # Client-supplied inputs without a server-recorded analysis_id MUST fail closed:
    # ignore client compatibility_gate / inference_mode / digest assertions so unverified
    # payloads can never spoof verified provenance or elevate to containment/rotation.
    gate = CompatibilityGateSummarySchema(
        source_id="source:client-supplied-unverified",
        provenance_verified=False,
        model_key=model_key,
        model_identifier=None,
        eligible=False,
        eligibility_status="VALIDATION_NOT_VERIFIED",
        compatibility_status="UNVERIFIED_CLIENT_INPUT",
        reasons=[
            "Client-supplied predictions lack a server-verified analysis_id; "
            "ISOLATE_RECOMMENDED and adaptive key-rotation escalation are suppressed."
        ],
        warnings=(
            list(request.compatibility_gate.warnings)
            if request.compatibility_gate is not None
            else []
        ),
        missing_features=(
            list(request.compatibility_gate.missing_features)
            if request.compatibility_gate is not None
            else []
        ),
    )
    return (
        items,
        model_key,
        model_type,
        None,
        None,
        None,
        source_csv_path,
        source_csv_sha256,
        "client_supplied_unverified",
        gate,
        "client_supplied_unverified",
    )


def simulate_security_response(
    service: ApiService,
    request: SecurityResponseSimulateRequest,
) -> SecurityResponseSimulationResponse:
    """Run deterministic Issue #27 dry-run policy simulation and persist audit record."""
    if request.dry_run is not True:
        raise ValueError("Live security response execution is disabled; dry_run must be True.")

    (
        items,
        model_key,
        model_type,
        run_id,
        model_sha256,
        preprocessor_sha256,
        source_csv_path,
        source_csv_sha256,
        inference_mode,
        gate,
        provenance_verification,
    ) = _resolve_simulation_inputs(service, request)

    recommendations = [
        evaluate_flow_response_policy(
            item,
            analysis_id=request.analysis_id,
            model_key=model_key,
            model_type=model_type,
            run_id=run_id,
            model_sha256=model_sha256,
            source_id=gate.source_id,
            provenance_verified=gate.provenance_verified,
            provenance_verification=provenance_verification,
            compatibility_status=gate.compatibility_status,
            eligible=gate.eligible,
            inference_mode=inference_mode,
        )
        for item in items
    ]

    action_counts = {
        "NO_ACTION": sum(1 for r in recommendations if r.action == "NO_ACTION"),
        "MONITOR": sum(1 for r in recommendations if r.action == "MONITOR"),
        "INVESTIGATE": sum(1 for r in recommendations if r.action == "INVESTIGATE"),
        "ISOLATE_RECOMMENDED": sum(1 for r in recommendations if r.action == "ISOLATE_RECOMMENDED"),
    }

    overall_recommendation = "NO_ACTION"
    for candidate in ("ISOLATE_RECOMMENDED", "INVESTIGATE", "MONITOR", "NO_ACTION"):
        if action_counts[candidate] > 0:
            overall_recommendation = candidate
            break

    if recommendations:
        overall_rec_items = [r for r in recommendations if r.action == overall_recommendation]
        sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        overall_severity = max(
            (r.severity for r in overall_rec_items),
            key=lambda s: sev_order.get(s, 0),
        )
    else:
        overall_severity = "INFO"

    total_flows = len(recommendations)
    ood_abstained_flows = sum(1 for r in recommendations if r.is_ood_flagged)
    evaluated_flows = total_flows - ood_abstained_flows

    key_rotation_sim = evaluate_adaptive_key_rotation(
        service,
        recommendations=recommendations,
        total_flows=total_flows,
        evaluated_flows=evaluated_flows,
        ood_abstained_flows=ood_abstained_flows,
        provenance_verification=provenance_verification,
        analysis_id=request.analysis_id,
    )

    policy_summary = (
        f"Dry-run simulated {total_flows} flows ({evaluated_flows} evaluated, "
        f"{ood_abstained_flows} ABSTAINED_OOD blocked from containment): "
        f"ISOLATE_RECOMMENDED={action_counts['ISOLATE_RECOMMENDED']}, "
        f"INVESTIGATE={action_counts['INVESTIGATE']}, "
        f"MONITOR={action_counts['MONITOR']}, "
        f"NO_ACTION={action_counts['NO_ACTION']}. "
        f"Adaptive key rotation simulation: {key_rotation_sim.decision} (executed=false)."
    )

    provenance_bundle = {
        "analysis_id": request.analysis_id,
        "source_csv_path": source_csv_path,
        "source_csv_sha256": source_csv_sha256,
        "source_id": gate.source_id,
        "source_provenance_verified": gate.provenance_verified,
        "provenance_verification": provenance_verification,
        "model_key": model_key,
        "model_type": model_type,
        "run_id": run_id,
        "model_sha256": model_sha256,
        "preprocessor_sha256": preprocessor_sha256,
        "inference_mode": inference_mode,
        "compatibility_status": gate.compatibility_status,
        "eligibility_status": gate.eligibility_status,
        "os_firewall_touched": False,
        "real_key_rotated": False,
        "executed": False,
    }

    sim_id = f"sim_{uuid.uuid4().hex[:12]}"
    created_at = _utc_now_iso()
    with service.db.transaction() as conn:
        ResponseSimulationRepository.create_simulation(
            conn,
            {
                "simulation_id": sim_id,
                "analysis_id": request.analysis_id,
                "source_csv_path": source_csv_path,
                "source_csv_sha256": source_csv_sha256,
                "model_key": model_key,
                "model_type": model_type,
                "run_id": run_id,
                "triggered_by": request.triggered_by,
                "execution_mode": "DRY_RUN_SIMULATION",
                "action_status": "SIMULATED",
                "recommendation_status": "RECOMMENDED",
                "overall_recommendation": overall_recommendation,
                "overall_severity": overall_severity,
                "total_flows": total_flows,
                "evaluated_flows": evaluated_flows,
                "ood_abstained_flows": ood_abstained_flows,
                "provenance_verification": provenance_verification,
                "action_counts": action_counts,
                "key_rotation_simulation": key_rotation_sim.model_dump(),
                "provenance": provenance_bundle,
                "recommendations": [r.model_dump() for r in recommendations],
                "policy_summary": policy_summary,
                "created_at": created_at,
            },
        )

    return SecurityResponseSimulationResponse(
        simulation_id=sim_id,
        created_at_utc=created_at,
        analysis_id=request.analysis_id,
        source_csv_path=source_csv_path,
        source_csv_sha256=source_csv_sha256,
        model_key=model_key,
        model_type=model_type,
        run_id=run_id,
        model_sha256=model_sha256,
        preprocessor_sha256=preprocessor_sha256,
        triggered_by=request.triggered_by,
        provenance_verification=provenance_verification,
        execution_mode="DRY_RUN_SIMULATION",
        action_status="SIMULATED",
        recommendation_status="RECOMMENDED",
        execution_status="NOT_EXECUTED",
        executed=False,
        os_firewall_touched=False,
        real_key_rotated=False,
        overall_recommendation=overall_recommendation,
        overall_severity=overall_severity,
        total_flows=total_flows,
        evaluated_flows=evaluated_flows,
        ood_abstained_flows=ood_abstained_flows,
        action_counts=action_counts,
        key_rotation_simulation=key_rotation_sim,
        policy_summary=policy_summary,
        security_notice=_SECURITY_NOTICE,
        deferred_capabilities=list(DEFERRED_CAPABILITIES),
        provenance=provenance_bundle,
        recommendations=recommendations,
    )


def list_security_simulations(
    service: ApiService,
    limit: int = 20,
    offset: int = 0,
) -> PaginatedSecuritySimulationsResponse:
    """List persisted Issue #27 dry-run simulation summaries from SQLite."""
    with service.db.transaction() as conn:
        rows = ResponseSimulationRepository.list_simulations(conn, limit=limit, offset=offset)
        total = ResponseSimulationRepository.count(conn)

    items = [
        SecuritySimulationHistoryItem(
            simulation_id=r["simulation_id"],
            created_at_utc=r["created_at"],
            analysis_id=r.get("analysis_id"),
            source_csv_path=r.get("source_csv_path"),
            source_csv_sha256=r.get("source_csv_sha256"),
            model_key=r["model_key"],
            model_type=r["model_type"],
            run_id=r.get("run_id"),
            triggered_by=r["triggered_by"],
            provenance_verification=r["provenance_verification"],
            execution_mode=r["execution_mode"],
            action_status=r["action_status"],
            recommendation_status=r["recommendation_status"],
            execution_status="NOT_EXECUTED",
            executed=False,
            os_firewall_touched=False,
            real_key_rotated=False,
            overall_recommendation=r["overall_recommendation"],
            overall_severity=r["overall_severity"],
            total_flows=r["total_flows"],
            evaluated_flows=r["evaluated_flows"],
            ood_abstained_flows=r["ood_abstained_flows"],
            action_counts=r["action_counts"],
            key_rotation_simulation=AdaptiveKeyRotationSimulation.model_validate(
                r["key_rotation_simulation"]
            ),
            policy_summary=r["policy_summary"],
        )
        for r in rows
    ]
    return PaginatedSecuritySimulationsResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + len(items)) < total,
    )


def export_security_simulation_evidence(
    service: ApiService,
    request: SecuritySimulationExportRequest,
) -> SecuritySimulationExportResponse:
    """Export an Issue #27 simulation evidence bundle and companion metadata JSON atomically."""
    with service.db.transaction() as conn:
        rec = ResponseSimulationRepository.get_simulation(conn, request.simulation_id)
    if rec is None:
        raise ValueError(f"Simulation record {request.simulation_id!r} was not found.")

    json_out: Path = validate_safe_export_path(
        request.output_path,
        source_csv_path=rec.get("source_csv_path"),
        expected_suffix=".json",
    )
    meta_out = json_out.with_suffix(".metadata.json")
    exported_at = _utc_now_iso()

    evidence_payload = {
        "schema_version": "1.0",
        "issue": "#27 (C8)",
        "simulation_id": rec["simulation_id"],
        "created_at_utc": rec["created_at"],
        "exported_at_utc": exported_at,
        "execution_mode": "DRY_RUN_SIMULATION",
        "action_status": "SIMULATED",
        "recommendation_status": "RECOMMENDED",
        "execution_status": "NOT_EXECUTED",
        "executed": False,
        "os_firewall_touched": False,
        "real_key_rotated": False,
        "deferred_capabilities": list(DEFERRED_CAPABILITIES),
        "overall_recommendation": rec["overall_recommendation"],
        "overall_severity": rec["overall_severity"],
        "total_flows": rec["total_flows"],
        "evaluated_flows": rec["evaluated_flows"],
        "ood_abstained_flows": rec["ood_abstained_flows"],
        "action_counts": rec["action_counts"],
        "key_rotation_simulation": rec["key_rotation_simulation"],
        "policy_summary": rec["policy_summary"],
        "provenance": rec["provenance"],
        "recommendations": rec["recommendations"],
        "security_notice": _SECURITY_NOTICE,
    }
    _atomic_write_text(json_out, json.dumps(evidence_payload, indent=2))
    json_sha256 = _sha256_file(json_out)

    meta_payload = {
        "schema_version": "1.0",
        "artifact_type": "security_response_dry_run_evidence",
        "simulation_id": rec["simulation_id"],
        "exported_at_utc": exported_at,
        "json_path": str(json_out),
        "json_sha256": json_sha256,
        "execution_mode": "DRY_RUN_SIMULATION",
        "executed": False,
        "os_firewall_touched": False,
        "real_key_rotated": False,
        "provenance": rec["provenance"],
        "security_notice": _SECURITY_NOTICE,
    }
    _atomic_write_text(meta_out, json.dumps(meta_payload, indent=2))
    meta_sha256 = _sha256_file(meta_out)

    return SecuritySimulationExportResponse(
        simulation_id=rec["simulation_id"],
        json_path=str(json_out),
        metadata_path=str(meta_out),
        json_sha256=json_sha256,
        metadata_sha256=meta_sha256,
        exported_at_utc=exported_at,
    )
