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
