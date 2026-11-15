"""Unit and API contract tests for Issue #27 / C8 adaptive security response dry-run engine."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from unittest.mock import patch

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.desktop_csv import _canonical_results_sha256, _get_analysis_store
from network_anomaly.api.main import create_app
from network_anomaly.api.repositories import KeyMetadataRepository, RotationAuditRepository
from network_anomaly.api.response_policy import (
    evaluate_flow_response_policy,
    list_security_simulations,
    simulate_security_response,
)
from network_anomaly.api.schemas import (
    CompatibilityGateSummarySchema,
    CsvFlowPredictionItem,
    ResponseFlowRecommendationItem,
    SecurityResponseSimulateRequest,
)
from network_anomaly.api.service import ApiService


def _make_flow(
    *,
    row_id: int = 1,
    row_index: int = 0,
    predicted_label: int | None = 0,
    predicted_class: str = "Benign",
    attack_probability: float | None = 0.05,
    raw_anomaly_score: float | None = 0.05,
    risk_score: float | None = 5.0,
    risk_level: str = "LOW",
    is_ood_flagged: bool = False,
    ood_kind: str | None = None,
    ood_reason: str | None = None,
) -> CsvFlowPredictionItem:
    return CsvFlowPredictionItem(
        row_id=row_id,
        row_index=row_index,
        predicted_label=predicted_label,
        predicted_class=predicted_class,
        attack_probability=attack_probability,
        raw_anomaly_score=raw_anomaly_score,
        decision_threshold=0.5,
        score_type="attack_probability",
        score_direction="higher_is_more_anomalous",
        risk_score=risk_score,
        risk_level=risk_level,
        is_ood_flagged=is_ood_flagged,
        ood_kind=ood_kind,
        ood_reason=ood_reason,
        flow_start_ms=1_700_000_000_000 + row_index,
        flow_end_ms=1_700_000_001_000 + row_index,
        src_ip="10.0.0.10",
        dst_ip="192.168.1.50",
        src_port=51234,
        dst_port=443,
        protocol=6,
        flow_duration_ms=1000,
        min_ttl=62.0,
    )


@pytest.fixture
def client(tmp_path: Path):
    app = create_app(db_path=tmp_path / "issue27_unit.db")
    with TestClient(app, raise_server_exceptions=False) as tc:
        yield tc


def test_deterministic_policy_matrix_covers_all_four_actions():
    """Verify deterministic mapping to NO_ACTION, MONITOR, INVESTIGATE, ISOLATE_RECOMMENDED."""
    benign_low = evaluate_flow_response_policy(
        _make_flow(row_id=1, risk_score=5.0, risk_level="LOW")
    )
    assert benign_low.action == "NO_ACTION"
    assert benign_low.severity == "INFO"
    assert benign_low.containment_allowed is False
    assert benign_low.executed is False
    assert benign_low.action_status == "RECOMMENDED"
    assert benign_low.simulation_status == "SIMULATED"

    benign_borderline = evaluate_flow_response_policy(
        _make_flow(row_id=2, attack_probability=0.35, risk_score=35.0, risk_level="MEDIUM")
    )
    assert benign_borderline.action == "MONITOR"
    assert benign_borderline.severity == "LOW"
    assert benign_borderline.containment_allowed is False

    attack_medium = evaluate_flow_response_policy(
        _make_flow(
            row_id=3,
            predicted_label=1,
            predicted_class="Attack",
            attack_probability=0.45,
            risk_score=45.0,
            risk_level="MEDIUM",
        )
    )
    assert attack_medium.action == "MONITOR"
    assert attack_medium.severity == "MEDIUM"

    attack_high = evaluate_flow_response_policy(
        _make_flow(
            row_id=4,
            predicted_label=1,
            predicted_class="Attack",
            attack_probability=0.68,
            risk_score=68.0,
            risk_level="HIGH",
        )
    )
    assert attack_high.action == "INVESTIGATE"
    assert attack_high.severity == "HIGH"
    assert attack_high.containment_allowed is False

    attack_critical = evaluate_flow_response_policy(
        _make_flow(
            row_id=5,
            predicted_label=1,
            predicted_class="Attack",
            attack_probability=0.96,
            risk_score=96.0,
            risk_level="CRITICAL",
        ),
        analysis_id="csvrun_verified_001",
        provenance_verified=True,
        provenance_verification="server_verified_analysis",
        compatibility_status="MODEL_VALIDATED",
        eligibility_status="PREDICTION_AVAILABLE",
        eligible=True,
        inference_mode="verified_model",
    )
    assert attack_critical.action == "ISOLATE_RECOMMENDED"
    assert attack_critical.severity == "CRITICAL"
    assert attack_critical.containment_allowed is True
    assert attack_critical.executed is False
    assert attack_critical.execution_status == "NOT_EXECUTED"

    # Without server_verified_analysis provenance, CRITICAL attack MUST NOT isolate
    unverified_critical = evaluate_flow_response_policy(
        _make_flow(
            row_id=6,
            predicted_label=1,
            predicted_class="Attack",
            attack_probability=0.96,
            risk_score=96.0,
            risk_level="CRITICAL",
        ),
        provenance_verified=True,
        provenance_verification="client_supplied_unverified",
        compatibility_status="MODEL_VALIDATED",
        eligible=True,
        inference_mode="verified_model",
    )
    assert unverified_critical.action == "INVESTIGATE"
    assert unverified_critical.containment_allowed is False


def _register_server_analysis(
    svc: ApiService,
    *,
    analysis_id: str,
    flows: list[CsvFlowPredictionItem],
    model_key: str = "random_forest",
    model_type: str = "Random Forest",
    inference_mode: str = "verified_model",
    compatibility_status: str = "MODEL_VALIDATED",
    eligibility_status: str | None = None,
    eligible: bool = True,
) -> None:
    resolved_eligibility = (
        eligibility_status
        if eligibility_status is not None
        else ("PREDICTION_AVAILABLE" if eligible else "ABSTAINED")
    )
    gate = CompatibilityGateSummarySchema(
        source_id="source:nf-v3-canonical",
        provenance_verified=True,
        model_key=model_key,
        model_identifier="rf-verified-run",
        eligible=eligible,
        eligibility_status=resolved_eligibility,
        compatibility_status=compatibility_status,
    )
    lock, store = _get_analysis_store(svc)
    with lock:
        store[analysis_id] = {
            "analysis_id": analysis_id,
            "source_csv_path": "data/demo/demo_flows.csv",
            "source_csv_sha256": "c" * 64,
            "model_key": model_key,
            "model_type": model_type,
            "run_id": "rf-verified-run",
            "model_sha256": "d" * 64,
            "preprocessor_sha256": "e" * 64,
            "inference_mode": inference_mode,
            "compatibility_gate": gate.model_dump(),
            "results": [f.model_dump() for f in flows],
            "results_sha256": _canonical_results_sha256(flows),
        }


def test_abstained_ood_never_receives_containment_and_fallback_downgrades():
    """OOD abstained flows must NEVER get ISOLATE_RECOMMENDED; heuristic mode cannot isolate."""
    ood_hard = evaluate_flow_response_policy(
        _make_flow(
            row_id=10,
            predicted_label=None,
            predicted_class="ABSTAINED_OOD",
            attack_probability=None,
            raw_anomaly_score=None,
            risk_score=None,
            risk_level="ABSTAINED_OOD",
            is_ood_flagged=True,
            ood_reason="Physical invariant violated: LONGEST_FLOW_PKT < SHORTEST_FLOW_PKT",
        )
    )
    assert ood_hard.action == "INVESTIGATE"
    assert ood_hard.action != "ISOLATE_RECOMMENDED"
    assert ood_hard.containment_allowed is False
    assert ood_hard.executed is False

    ood_ttl = evaluate_flow_response_policy(
        _make_flow(
            row_id=11,
            predicted_label=None,
            predicted_class="ABSTAINED_OOD",
            attack_probability=None,
            raw_anomaly_score=None,
            risk_score=None,
            risk_level="ABSTAINED_OOD",
            is_ood_flagged=True,
            ood_reason="OOD abstention: MIN_TTL=0 telemetry drift",
        )
    )
    assert ood_ttl.action == "MONITOR"
    assert ood_ttl.containment_allowed is False

    # Schema-level invariant must reject manual creation of ABSTAINED_OOD + ISOLATE_RECOMMENDED
    with pytest.raises(ValueError, match="ABSTAINED_OOD"):
        ResponseFlowRecommendationItem(
            row_id=12,
            row_index=0,
            predicted_class="ABSTAINED_OOD",
            is_ood_flagged=True,
            risk_score=None,
            risk_level="ABSTAINED_OOD",
            action="ISOLATE_RECOMMENDED",
            severity="CRITICAL",
            containment_allowed=True,
            reason="invalid",
        )

    # Degraded/heuristic inference never recommends isolation
    downgraded = evaluate_flow_response_policy(
        _make_flow(
            row_id=13,
            predicted_label=1,
            predicted_class="Attack",
            attack_probability=0.95,
            risk_score=95.0,
            risk_level="CRITICAL",
        ),
        inference_mode="heuristic_fallback",
    )
    assert downgraded.action == "INVESTIGATE"
    assert downgraded.containment_allowed is False


def test_adaptive_key_rotation_simulation_never_creates_or_mutates_real_keys(tmp_path: Path):
    """Server-verified simulation recommends dry-run rotation transition without mutating SQLite keys table."""
    svc = ApiService(DatabaseManager(tmp_path / "key_dry_run.db"))
    with svc.db.transaction() as conn:
        keys_before = KeyMetadataRepository.list_keys(conn)
        rot_count_before = RotationAuditRepository.count(conn)

    flows = [
        _make_flow(
            row_id=101,
            row_index=0,
            predicted_label=1,
            predicted_class="Attack",
            attack_probability=0.99,
            risk_score=99.0,
            risk_level="CRITICAL",
        ),
        _make_flow(
            row_id=102,
            row_index=1,
            predicted_label=None,
            predicted_class="ABSTAINED_OOD",
            attack_probability=None,
            raw_anomaly_score=None,
            risk_score=None,
            risk_level="ABSTAINED_OOD",
            is_ood_flagged=True,
            ood_reason="Physical invariant violation",
        ),
    ]
    _register_server_analysis(svc, analysis_id="csvrun_verified_rot_001", flows=flows)

    req = SecurityResponseSimulateRequest(
        analysis_id="csvrun_verified_rot_001",
        triggered_by="unit_verified_test",
        dry_run=True,
    )
    resp = simulate_security_response(svc, req)
    assert resp.execution_mode == "DRY_RUN_SIMULATION"
    assert resp.action_status == "SIMULATED"
    assert resp.recommendation_status == "RECOMMENDED"
    assert resp.execution_status == "NOT_EXECUTED"
    assert resp.executed is False
    assert resp.os_firewall_touched is False
    assert resp.real_key_rotated is False
    assert resp.provenance_verification == "server_verified_analysis"
    assert resp.key_rotation_simulation.decision == "SIMULATED_ROTATION_RECOMMENDED"
    assert resp.key_rotation_simulation.would_rotate is True
    assert resp.key_rotation_simulation.executed is False
    assert resp.key_rotation_simulation.key_material_generated is False
    assert resp.key_rotation_simulation.real_key_modified is False
    assert resp.key_rotation_simulation.keyring_status == "DEFERRED_PRODUCTION_KEYRING"
    assert resp.action_counts == {
        "NO_ACTION": 0,
        "MONITOR": 0,
        "INVESTIGATE": 1,
        "ISOLATE_RECOMMENDED": 1,
    }
    assert resp.recommendations[1].action != "ISOLATE_RECOMMENDED"
    assert resp.recommendations[1].containment_allowed is False

    # Verify zero mutation in cryptographic key_metadata & rotation_audit tables
    with svc.db.transaction() as conn:
        keys_after = KeyMetadataRepository.list_keys(conn)
        rot_count_after = RotationAuditRepository.count(conn)
    assert keys_after == keys_before
    assert rot_count_after == rot_count_before

    # Verify history persisted across service re-instantiation
    svc_reloaded = ApiService(DatabaseManager(tmp_path / "key_dry_run.db"))
    hist = list_security_simulations(svc_reloaded, limit=10, offset=0)
    assert hist.total == 1
    assert hist.items[0].simulation_id == resp.simulation_id
    assert hist.items[0].executed is False


def test_client_supplied_inputs_cannot_spoof_isolate_or_rotation_escalation(tmp_path: Path):
    """P1 regression: unverified client payloads cannot forge gate/mode to escalate actions."""
    svc = ApiService(DatabaseManager(tmp_path / "p1_spoof_block.db"))

    # Even with 6 CRITICAL flows (ratio=1.0 >= 0.25, count=6 >= 5) AND forged
    # compatibility_gate + inference_mode="verified_model" + fake hashes,
    # missing server analysis_id MUST block ISOLATE_RECOMMENDED and rotation escalation.
    attack_flows = [
        _make_flow(
            row_id=300 + i,
            row_index=i,
            predicted_label=1,
            predicted_class="Attack",
            attack_probability=0.99,
            risk_score=99.0,
            risk_level="CRITICAL",
        )
        for i in range(6)
    ]
    spoof_gate = CompatibilityGateSummarySchema(
        source_id="source:nf-v3-canonical",
        provenance_verified=True,
        model_key="random_forest",
        model_identifier="spoofed-rf-run",
        eligible=True,
        eligibility_status="PREDICTION_AVAILABLE",
        compatibility_status="MODEL_VALIDATED",
    )
    req = SecurityResponseSimulateRequest(
        model_key="random_forest",
        model_type="Random Forest",
        run_id="spoofed-run-id",
        model_sha256="a" * 64,
        preprocessor_sha256="b" * 64,
        inference_mode="verified_model",
        compatibility_gate=spoof_gate,
        results=attack_flows,
    )
    resp = simulate_security_response(svc, req)
    assert resp.provenance_verification == "client_supplied_unverified"
    assert resp.run_id is None
    assert resp.model_sha256 is None
    assert resp.preprocessor_sha256 is None
    assert resp.action_counts["ISOLATE_RECOMMENDED"] == 0
    assert resp.action_counts["INVESTIGATE"] == 6
    assert resp.overall_recommendation == "INVESTIGATE"
    assert all(r.containment_allowed is False for r in resp.recommendations)
    assert all(
        r.provenance["provenance_verification"] == "client_supplied_unverified"
        and r.provenance["inference_mode"] == "client_supplied_unverified"
        and r.provenance["compatibility_status"] == "UNVERIFIED_CLIENT_INPUT"
        for r in resp.recommendations
    )
    assert resp.key_rotation_simulation.decision == "HOLD_UNVERIFIED_PROVENANCE"
    assert resp.key_rotation_simulation.recommended is False
    assert resp.key_rotation_simulation.would_rotate is False
    assert resp.provenance["source_provenance_verified"] is False
    assert resp.provenance["inference_mode"] == "client_supplied_unverified"
    assert resp.provenance["compatibility_status"] == "UNVERIFIED_CLIENT_INPUT"
    assert resp.provenance["eligibility_status"] == "VALIDATION_NOT_VERIFIED"


def test_response_simulation_ood_only_batch_holds_rotation(tmp_path: Path):
    """A 100% OOD batch must suppress adaptive key rotation simulation."""
    svc = ApiService(DatabaseManager(tmp_path / "ood_hold.db"))
    req = SecurityResponseSimulateRequest(
        model_key="isolation_forest",
        model_type="Isolation Forest",
        results=[
            _make_flow(
                row_id=201,
                row_index=0,
                predicted_label=None,
                predicted_class="ABSTAINED_OOD",
                attack_probability=None,
                raw_anomaly_score=None,
                risk_score=None,
                risk_level="ABSTAINED_OOD",
                is_ood_flagged=True,
                ood_reason="MIN_TTL=0 telemetry drift",
            )
        ],
    )
    resp = simulate_security_response(svc, req)
    assert resp.action_counts["ISOLATE_RECOMMENDED"] == 0
    assert resp.key_rotation_simulation.decision == "HOLD_OOD_ABSTAINED"
    assert resp.key_rotation_simulation.would_rotate is False


def test_api_contract_rejects_dry_run_false_and_persists_history_and_export(
    client: TestClient, tmp_path: Path
):
    """API contract tests for #27 endpoints: fail-closed dry_run=false, anti-spoof, history, export."""
    flow = _make_flow(
        row_id=501,
        row_index=0,
        predicted_label=1,
        predicted_class="Attack",
        attack_probability=0.91,
        risk_score=91.0,
        risk_level="CRITICAL",
    ).model_dump()

    bad = client.post(
        "/api/v1/security/simulate-response",
        json={"dry_run": False, "model_key": "random_forest", "results": [flow]},
    )
    assert bad.status_code == 422

    # Unverified analysis_id fails closed (400 BadRequest)
    bad_id = client.post(
        "/api/v1/security/simulate-response",
        json={"analysis_id": "csvrun_does_not_exist"},
    )
    assert bad_id.status_code == 400

    # Client-supplied input without analysis_id downgrades CRITICAL -> INVESTIGATE & holds rotation
    sim_resp = client.post(
        "/api/v1/security/simulate-response",
        json={
            "dry_run": True,
            "triggered_by": "audit_test",
            "model_key": "random_forest",
            "model_type": "Random Forest",
            "inference_mode": "verified_model",
            "compatibility_gate": {
                "source_id": "source:nf-v3-canonical",
                "provenance_verified": True,
                "model_key": "random_forest",
                "eligible": True,
                "eligibility_status": "PREDICTION_AVAILABLE",
                "compatibility_status": "MODEL_VALIDATED",
            },
            "results": [flow],
        },
    )
    assert sim_resp.status_code == 200, sim_resp.text
    sim_data = sim_resp.json()
    assert sim_data["executed"] is False
    assert sim_data["os_firewall_touched"] is False
    assert sim_data["real_key_rotated"] is False
    assert sim_data["execution_mode"] == "DRY_RUN_SIMULATION"
    assert sim_data["provenance_verification"] == "client_supplied_unverified"
    assert sim_data["overall_recommendation"] == "INVESTIGATE"
    assert sim_data["action_counts"]["ISOLATE_RECOMMENDED"] == 0
    assert sim_data["key_rotation_simulation"]["decision"] == "HOLD_UNVERIFIED_PROVENANCE"
    assert sim_data["key_rotation_simulation"]["would_rotate"] is False
    assert sim_data["deferred_capabilities"] == [
        "production_aes256_gcm_keyring",
        "automatic_real_key_rotation",
        "os_firewall_command_execution",
    ]

    # Server-verified analysis_id rejects spoofed gate/mode (400) and grants advisory
    # ISOLATE_RECOMMENDED + SIMULATED_ROTATION_RECOMMENDED only when consistent.
    flow_item = CsvFlowPredictionItem.model_validate(flow)
    _register_server_analysis(
        client.app.state.service,
        analysis_id="csvrun_contract_verified",
        flows=[flow_item],
    )
    tampered_mode = client.post(
        "/api/v1/security/simulate-response",
        json={
            "analysis_id": "csvrun_contract_verified",
            "inference_mode": "heuristic_fallback",
            "dry_run": True,
        },
    )
    assert tampered_mode.status_code == 400

    tampered_gate = client.post(
        "/api/v1/security/simulate-response",
        json={
            "analysis_id": "csvrun_contract_verified",
            "compatibility_gate": {
                "source_id": "source:spoofed",
                "provenance_verified": False,
                "model_key": "random_forest",
                "eligible": False,
                "eligibility_status": "ABSTAINED",
                "compatibility_status": "INCOMPATIBLE",
            },
            "dry_run": True,
        },
    )
    assert tampered_gate.status_code == 400

    verified_resp = client.post(
        "/api/v1/security/simulate-response",
        json={"analysis_id": "csvrun_contract_verified", "dry_run": True},
    )
    assert verified_resp.status_code == 200, verified_resp.text
    verified_data = verified_resp.json()
    assert verified_data["provenance_verification"] == "server_verified_analysis"
    assert verified_data["overall_recommendation"] == "ISOLATE_RECOMMENDED"
    assert verified_data["action_counts"]["ISOLATE_RECOMMENDED"] == 1
    assert verified_data["key_rotation_simulation"]["decision"] == "SIMULATED_ROTATION_RECOMMENDED"
    assert verified_data["key_rotation_simulation"]["would_rotate"] is True
    assert verified_data["executed"] is False

    hist_resp = client.get("/api/v1/security/simulations?limit=10&offset=0")
    assert hist_resp.status_code == 200
    hist = hist_resp.json()
    assert hist["total"] == 2
    assert hist["items"][0]["simulation_id"] == verified_data["simulation_id"]

    export_file = tmp_path / "test_issue27_dry_run_unit.json"
    exp_resp = client.post(
        "/api/v1/security/simulations/export",
        json={
            "output_path": str(export_file),
            "simulation_id": verified_data["simulation_id"],
        },
    )
    assert exp_resp.status_code == 200, exp_resp.text
    exp_json = exp_resp.json()
    exported = json.loads(Path(exp_json["json_path"]).read_text(encoding="utf-8"))
    assert exported["executed"] is False
    assert exported["os_firewall_touched"] is False
    assert exported["real_key_rotated"] is False
    assert exported["simulation_id"] == verified_data["simulation_id"]
    assert Path(exp_json["metadata_path"]).is_file()


def test_research_only_and_unverified_gate_cannot_isolate_or_escalate_rotation(tmp_path: Path):
    """F-01 regression: RESEARCH_ONLY and non-MODEL_VALIDATED/PREDICTION_AVAILABLE gates fail closed."""
    svc = ApiService(DatabaseManager(tmp_path / "f01_research_only.db"))
    critical_attacks = [
        _make_flow(
            row_id=700 + i,
            row_index=i,
            predicted_label=1,
            predicted_class="Attack",
            attack_probability=None,
            raw_anomaly_score=0.2,
            risk_score=95.0,
            risk_level="CRITICAL",
        )
        for i in range(8)
    ]
    _register_server_analysis(
        svc,
        analysis_id="csvrun_research_only_if",
        flows=critical_attacks,
        model_key="isolation_forest",
        model_type="Isolation Forest",
        inference_mode="verified_model",
        compatibility_status="RESEARCH_ONLY",
        eligibility_status="RESEARCH_ONLY",
        eligible=True,
    )
    resp = simulate_security_response(
        svc,
        SecurityResponseSimulateRequest(
            analysis_id="csvrun_research_only_if",
            dry_run=True,
        ),
    )
    assert resp.action_counts["ISOLATE_RECOMMENDED"] == 0
    assert resp.action_counts["INVESTIGATE"] == 8
    assert resp.overall_recommendation == "INVESTIGATE"
    assert all(r.containment_allowed is False for r in resp.recommendations)
    assert resp.key_rotation_simulation.decision == "HOLD_RESEARCH_ONLY_MODEL"
    assert resp.key_rotation_simulation.recommended is False
    assert resp.key_rotation_simulation.would_rotate is False

    # External unverified CSV (SEMANTICALLY_COMPATIBLE / VALIDATION_NOT_VERIFIED) also stays downgraded
    _register_server_analysis(
        svc,
        analysis_id="csvrun_semantic_unverified",
        flows=critical_attacks,
        compatibility_status="SEMANTICALLY_COMPATIBLE",
        eligibility_status="VALIDATION_NOT_VERIFIED",
        eligible=True,
    )
    sem_resp = simulate_security_response(
        svc,
        SecurityResponseSimulateRequest(
            analysis_id="csvrun_semantic_unverified",
            dry_run=True,
        ),
    )
    assert sem_resp.action_counts["ISOLATE_RECOMMENDED"] == 0
    assert sem_resp.key_rotation_simulation.decision == "HOLD_UNVERIFIED_GATE"
    assert sem_resp.key_rotation_simulation.would_rotate is False


def test_ood_structured_kind_precedence_over_reason_text():
    """F-05 regression: structured ood_kind takes precedence over free-text ood_reason."""
    phys_with_ttl_wording = evaluate_flow_response_policy(
        _make_flow(
            row_id=801,
            predicted_label=None,
            predicted_class="ABSTAINED_OOD",
            attack_probability=None,
            raw_anomaly_score=None,
            risk_score=None,
            risk_level="ABSTAINED_OOD",
            is_ood_flagged=True,
            ood_kind="PHYSICAL_INVARIANT",
            ood_reason="Protocol anomaly mentioning min_ttl field",
        )
    )
    assert phys_with_ttl_wording.action == "INVESTIGATE"
    assert phys_with_ttl_wording.severity == "MEDIUM"
    assert phys_with_ttl_wording.containment_allowed is False

    zero_ttl_structured = evaluate_flow_response_policy(
        _make_flow(
            row_id=802,
            predicted_label=None,
            predicted_class="ABSTAINED_OOD",
            attack_probability=None,
            raw_anomaly_score=None,
            risk_score=None,
            risk_level="ABSTAINED_OOD",
            is_ood_flagged=True,
            ood_kind="ZERO_TTL_DRIFT",
            ood_reason="unusual wording without ttl substring",
        )
    )
    assert zero_ttl_structured.action == "MONITOR"
    assert zero_ttl_structured.severity == "LOW"
    assert zero_ttl_structured.containment_allowed is False


def test_simulation_payload_limit_bounded_storage_and_memory_cache(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F-02 & F-03 regressions: max_length on results, bounded recommendations storage, compressed cache eviction."""
    from network_anomaly.api import desktop_csv
    from network_anomaly.api.repositories import ResponseSimulationRepository
    from network_anomaly.api.response_policy import MAX_PERSISTED_RECOMMENDATIONS
    from network_anomaly.api.schemas import (
        MAX_SECURITY_SIMULATE_RESULTS,
        BehavioralSummarySchema,
        CompatibilityGateSummarySchema,
        CsvAnalyzeResponse,
        OodSummarySchema,
    )

    # 1. Client payload exceeding MAX_SECURITY_SIMULATE_RESULTS -> HTTP 422
    one_flow = _make_flow(row_id=1).model_dump()
    oversized = client.post(
        "/api/v1/security/simulate-response",
        json={"dry_run": True, "results": [one_flow] * (MAX_SECURITY_SIMULATE_RESULTS + 1)},
    )
    assert oversized.status_code == 422

    # 2. > MAX_PERSISTED_RECOMMENDATIONS server-verified flows -> full counts, bounded stored sample
    svc = client.app.state.service
    total_batch = MAX_PERSISTED_RECOMMENDATIONS + 250
    flows = [
        _make_flow(
            row_id=1000 + i,
            row_index=i,
            predicted_label=1 if i % 5 == 0 else 0,
            predicted_class="Attack" if i % 5 == 0 else "Benign",
            attack_probability=0.95 if i % 5 == 0 else 0.05,
            risk_score=95.0 if i % 5 == 0 else 5.0,
            risk_level="CRITICAL" if i % 5 == 0 else "LOW",
        )
        for i in range(total_batch)
    ]
    _register_server_analysis(svc, analysis_id="csvrun_bounded_storage", flows=flows)
    sim_resp = client.post(
        "/api/v1/security/simulate-response",
        json={"analysis_id": "csvrun_bounded_storage", "dry_run": True},
    )
    assert sim_resp.status_code == 200, sim_resp.text
    sim_data = sim_resp.json()
    assert sim_data["total_flows"] == total_batch
    assert len(sim_data["recommendations"]) == MAX_PERSISTED_RECOMMENDATIONS
    assert sim_data["provenance"]["recommendations_truncated"] is True
    assert sim_data["provenance"]["recommendations_stored_count"] == MAX_PERSISTED_RECOMMENDATIONS
    assert sim_data["action_counts"]["ISOLATE_RECOMMENDED"] == total_batch // 5

    # Summary listing queries omit heavy recommendations/provenance columns
    with svc.db.transaction() as conn:
        listed = ResponseSimulationRepository.list_simulations(conn, limit=10, offset=0)
    assert len(listed) == 1
    assert "recommendations" not in listed[0]
    assert "provenance" not in listed[0]

    # 3. Compressed analysis cache evicts older results_gz under byte budget while keeping sha256
    monkeypatch.setattr(desktop_csv, "_MAX_CACHED_RESULTS_BYTES", 2_000)
    svc_cache = ApiService(DatabaseManager(tmp_path / "cache_evict.db"))
    gate = CompatibilityGateSummarySchema(
        source_id="source:nf-v3-canonical",
        provenance_verified=True,
        model_key="random_forest",
        eligible=True,
        eligibility_status="PREDICTION_AVAILABLE",
        compatibility_status="MODEL_VALIDATED",
    )
    sample_batch = [_make_flow(row_id=i, row_index=i) for i in range(60)]
    ood_summary = OodSummarySchema(
        total_rows=len(sample_batch),
        has_ood_warning=False,
        hard_violation_count=0,
        shortcut_shift_count=0,
        zero_ttl_count=0,
        affected_rows_count=0,
        shortcut_drift_ratio=0.0,
        zero_ttl_ratio=0.0,
        abstention_rate=0.0,
        prediction_coverage=1.0,
    )
    behavioral_summary = BehavioralSummarySchema(
        total_flows=len(sample_batch),
        unique_src_ips=1,
        unique_dst_ips=1,
        unique_src_ports=1,
        unique_dst_ports=1,
        non_attribution_notice="Metadata summary only.",
    )
    for run_idx in range(3):
        fake_resp = CsvAnalyzeResponse(
            analysis_id=f"csvrun_cache_{run_idx}",
            analyzed_at_utc="2026-11-16T00:00:00Z",
            file_path="data/demo/demo_flows.csv",
            file_sha256="f" * 64,
            model_key="random_forest",
            model_type="Random Forest",
            inference_mode="verified_model",
            total_rows=len(sample_batch),
            benign_count=len(sample_batch),
            attack_count=0,
            ood_flagged_count=0,
            abstained_risk_count=0,
            decision_threshold=0.5,
            score_type="attack_probability",
            score_direction="higher_is_more_anomalous",
            compatibility_gate=gate,
            ood_report=ood_summary,
            behavioral_summary=behavioral_summary,
            security_notice="dry-run",
            results=sample_batch,
            timeline=[],
        )
        desktop_csv._record_csv_analysis(svc_cache, fake_resp)

    _, store = _get_analysis_store(svc_cache)
    assert "results" not in store["csvrun_cache_0"]
    assert store["csvrun_cache_0"]["results_gz"] is None
    assert len(store["csvrun_cache_0"]["results_sha256"]) == 64
    assert store["csvrun_cache_2"]["results_gz"] is not None

    with pytest.raises(ValueError, match="not retained in the in-memory cache"):
        simulate_security_response(
            svc_cache,
            SecurityResponseSimulateRequest(analysis_id="csvrun_cache_0", dry_run=True),
        )
    fallback_sim = simulate_security_response(
        svc_cache,
        SecurityResponseSimulateRequest(
            analysis_id="csvrun_cache_0",
            results=sample_batch,
            dry_run=True,
        ),
    )
    assert fallback_sim.provenance_verification == "server_verified_analysis"
    assert fallback_sim.total_flows == len(sample_batch)


def test_response_policy_module_has_zero_os_command_or_subprocess_calls():
    """Static & runtime check: response_policy.py never imports OS/subprocess shells or invokes them."""
    module_path = Path("src/network_anomaly/api/response_policy.py")
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported = set()
    called_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called_names.add(node.func.attr)

    forbidden_modules = {"os", "subprocess", "pty", "ctypes", "shlex"}
    assert imported.isdisjoint(forbidden_modules), f"Forbidden modules imported: {imported}"
    forbidden_calls = {"system", "popen", "eval", "exec", "spawn"}
    assert called_names.isdisjoint(forbidden_calls), f"Forbidden calls found: {called_names}"

    svc = ApiService(DatabaseManager(":memory:"))
    with (
        patch("subprocess.run", side_effect=AssertionError("subprocess.run called!")) as p_run,
        patch(
            "subprocess.Popen", side_effect=AssertionError("subprocess.Popen called!")
        ) as p_popen,
        patch("os.system", side_effect=AssertionError("os.system called!")) as p_os,
    ):
        simulate_security_response(
            svc,
            SecurityResponseSimulateRequest(
                model_key="random_forest",
                results=[
                    _make_flow(
                        predicted_label=1,
                        predicted_class="Attack",
                        attack_probability=0.95,
                        risk_score=95.0,
                        risk_level="CRITICAL",
                    )
                ],
            ),
        )
    p_run.assert_not_called()
    p_popen.assert_not_called()
    p_os.assert_not_called()
