"""Contract tests for RQ1-RQ6 experiment scripts and dynamic benchmarks."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_script(name: str, rel_path: str):
    path = Path(__file__).resolve().parents[2] / rel_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_rq1_rq2_rq4_fail_closed_to_blocked_when_raw_data_absent(tmp_path, monkeypatch):
    rq_common = _load_script("_rq_common", "scripts/_rq_common.py")
    monkeypatch.setattr(rq_common, "PROCESSED_V2_DIR", tmp_path / "missing_v2")

    rq1 = _load_script(
        "generate_model_comparison_report", "scripts/generate_model_comparison_report.py"
    )
    monkeypatch.setattr(rq1, "check_v2_prerequisites", rq_common.check_v2_prerequisites)
    res1 = rq1.generate_comparison_report(
        output_json=tmp_path / "rq1.json", output_md=tmp_path / "rq1.md"
    )
    assert res1["status"] == "BLOCKED"
    assert res1["models"] == {}

    rq2 = _load_script(
        "run_rq2_rare_attack_experiment", "scripts/run_rq2_rare_attack_experiment.py"
    )
    monkeypatch.setattr(rq2, "check_v2_prerequisites", rq_common.check_v2_prerequisites)
    res2 = rq2.run_rq2_experiment(output_json=tmp_path / "rq2.json", output_md=tmp_path / "rq2.md")
    assert res2["status"] == "BLOCKED"

    rq4 = _load_script(
        "run_rq4_unknown_attack_experiment", "scripts/run_rq4_unknown_attack_experiment.py"
    )
    monkeypatch.setattr(rq4, "check_v2_prerequisites", rq_common.check_v2_prerequisites)
    res4 = rq4.run_rq4_experiment(output_json=tmp_path / "rq4.json", output_md=tmp_path / "rq4.md")
    assert res4["status"] == "BLOCKED"


def test_rq3_reports_simulation_metrics_and_blocked_empirical_ait(tmp_path):
    rq3 = _load_script(
        "run_rq3_session_correlation_experiment",
        "scripts/run_rq3_session_correlation_experiment.py",
    )
    res = rq3.run_rq3_experiment(
        output_dir=tmp_path / "behavioral",
        ait_data_dir=tmp_path / "absent_ait",
        md_output_path=tmp_path / "EXP5.md",
    )
    assert res["execution_mode"] == "SIMULATION"
    assert res["empirical_dataset_status"] == "BLOCKED"
    strat_a = res["ablation"]["strategy_a_ip_exact_matching"]
    strat_b = res["ablation"]["strategy_b_behavioral_vector_cosine"]
    assert strat_a["pairwise_recall"] == 0.0
    assert strat_b["pairwise_f1"] > strat_a["pairwise_f1"]
    assert "false_link_rate" in strat_b
    assert "match_accuracy" in strat_b


def test_rq5_computes_exposure_and_blast_radius_dynamically(tmp_path):
    rq5 = _load_script("run_rq5_rotation_experiment", "scripts/run_rq5_rotation_experiment.py")
    res = rq5.run_rq5_experiment(output_dir=tmp_path / "crypto")
    assert res["execution_mode"] == "SIMULATION"
    fixed = res["fixed_schedule"]
    adapt = res["adaptive_rotation"]
    assert fixed["records_per_key"]
    assert adapt["records_per_key"]
    assert adapt["max_attack_key_exposure_minutes"] < fixed["max_attack_key_exposure_minutes"]
    assert (
        adapt["blast_radius_max_attack_records_single_key"]
        < fixed["blast_radius_max_attack_records_single_key"]
    )
    assert adapt["detection_to_rotation_seconds"] is not None


def test_rq6_crypto_benchmark_multi_size_and_percentiles(tmp_path):
    bm_crypto = _load_script("benchmark_crypto_overhead", "scripts/benchmark_crypto_overhead.py")
    res = bm_crypto.run_benchmark(
        iterations=100, warmup=10, payload_sizes=(256, 1024), output_dir=tmp_path / "bm"
    )
    assert len(res["payload_benchmarks"]) == 2
    for entry in res["payload_benchmarks"].values():
        assert entry["encryption"]["p95_us"] >= entry["encryption"]["median_us"]
        assert entry["encryption"]["p99_us"] >= entry["encryption"]["p95_us"]
        assert entry["plaintext_json_roundtrip"]["throughput_ops_sec"] > 0
    assert res["environment"]["cpu_count"] is not None


def test_wp3_leakage_policy_and_report_schema_consistency():
    import json

    wp3 = _load_script("run_wp3_controlled_ablation", "scripts/run_wp3_controlled_ablation.py")
    root = Path(__file__).resolve().parents[2]
    report_path = root / "reports" / "experiments" / "ml" / "wp3_controlled_ablation_report.json"
    summary_path = root / "reports" / "experiments" / "ml" / "model_improvement_summary.json"

    report = json.loads(report_path.read_text(encoding="utf-8"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))

    policy = report["leakage_policy"]
    assert policy == wp3._build_leakage_policy()
    assert summary["wp3_leakage_policy"] == policy
    for legacy_key in ("ait_test_touched_for_selection", "ctu_touched_for_zero_shot_selection"):
        assert legacy_key not in policy

    assert policy["ait_test_used_for_training"] is False
    assert policy["ait_test_used_for_feature_transform_fitting"] is False
    assert policy["ait_test_used_for_threshold_calibration"] is False
    assert policy["ait_test_used_for_hyperparameter_tuning"] is False
    assert policy["ait_test_used_for_posthoc_evaluation"] is True
    assert policy["ait_test_used_for_posthoc_candidate_selection"] is True
    assert policy["ctu_used_for_training_in_zero_shot_experiments"] is False
    assert policy["ctu_used_for_zero_shot_evaluation"] is True
    assert policy["ctu_used_for_posthoc_candidate_selection"] is True
    assert policy["independent_holdout_selection_claim"] is False

    rec = report["selection_recommendation"]
    assert rec == wp3._build_selection_recommendation()
    assert summary["wp3_selection_recommendation"] == rec
    assert rec["official_registered_artifacts_action"] == "RETAIN_E0_BASELINE_ARTIFACTS"
    assert rec["selection_type"] == "posthoc_holdout_informed_retention_decision"
    assert rec["holdout_independent_selection"] is False

    e0_block = report["experiments"]["E0_baseline"]
    assert e0_block["exp_id"] == "E0_frozen_18f_reference"
    rf_manifest = json.loads(
        (root / "reports" / "models" / "random_forest_manifest.json").read_text(encoding="utf-8")
    )
    assert rf_manifest["is_canonical_baseline"] is False
    assert e0_block["models"]["random_forest"]["is_canonical_baseline"] is False
    assert (
        e0_block["models"]["random_forest"]["protocol_version"] == rf_manifest["protocol_version"]
    )

    for exp_key in (
        "E1_base_6f_ablation",
        "E2_byte_rate_ablation",
        "E2b_pure_non_byte_ablation",
        "E3a_protocol_semantic_onehot",
        "E3b_protocol_semantic_onehot_floor",
    ):
        exp = report["experiments"][exp_key]
        assert "test_touched_for_selection_or_threshold" not in exp
        assert exp["test_used_for_training_or_transform"] is False
        assert exp["test_used_for_threshold_calibration"] is False
        assert exp["test_used_for_hyperparameter_tuning"] is False
        assert exp["test_used_for_posthoc_evaluation"] is True
        assert exp["test_referenced_in_posthoc_selection_rationale"] is True
