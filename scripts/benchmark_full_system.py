#!/usr/bin/env python3
"""Dynamic End-to-End & Subsystem System Benchmark (Issue #147).

Measures real throughput, median/P95/P99 latency, and ring-buffer utilization
with warm-up and multiple iterations on the actual runtime environment.
Contains zero hardcoded capacity targets, OS strings, or line-rate claims.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPTS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPTS_DIR.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from _rq_common import collect_environment_metadata  # noqa: E402

from network_anomaly.behavioral.vector import BehavioralVectorBuilder  # noqa: E402
from network_anomaly.canonical.event import (  # noqa: E402
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.canonical.feature_contract import (  # noqa: E402
    get_flow_feature_contract_v2,
)
from network_anomaly.crypto.aead import AESGCMCipher  # noqa: E402
from network_anomaly.data.v2_schema import (  # noqa: E402
    compute_flow_features_from_base,
)
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator  # noqa: E402
from network_anomaly.streaming.pipeline import StreamingEventPipeline  # noqa: E402
from network_anomaly.telemetry.collector import NetFlowIPFIXDecoder  # noqa: E402
from network_anomaly.telemetry.modes import ModeOrchestrator  # noqa: E402

OUTPUT_JSON = Path("reports/benchmarks/system_performance_benchmark.json")
OUTPUT_MD = Path("docs/benchmarks/SYSTEM_PERFORMANCE.md")


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def _summary_us(samples_us: List[float]) -> Dict[str, float]:
    s = sorted(samples_us)
    return {
        "median_us": round(statistics.median(s), 2),
        "p95_us": round(_percentile(s, 95.0), 2),
        "p99_us": round(_percentile(s, 99.0), 2),
    }


def _variance_stats(samples: List[float]) -> Dict[str, Any]:
    mean_v = statistics.mean(samples)
    std_v = statistics.stdev(samples) if len(samples) > 1 else 0.0
    cv_pct = (std_v / mean_v * 100.0) if mean_v > 0.0 else 0.0
    return {
        "n_runs": len(samples),
        "samples": [round(float(x), 3) for x in samples],
        "mean": round(float(mean_v), 3),
        "std": round(float(std_v), 3),
        "cv_pct": round(float(cv_pct), 2),
    }


def _run_single_benchmark_pass(
    batch_events: int,
    micro_iters: int,
    runtime_mode: Optional[str] = None,
    expected_ood_gate_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    env = collect_environment_metadata()
    contract = get_flow_feature_contract_v2()
    orchestrator = LiveSystemOrchestrator(
        runtime_mode=runtime_mode,
        expected_ood_gate_sha256=expected_ood_gate_sha256,
    )
    mode_mgr = ModeOrchestrator(orchestrator=orchestrator)

    base_feats = compute_flow_features_from_base(
        duration_ms=50.0,
        bytes_in=1000.0,
        bytes_out=2500.0,
        pkts_in=10.0,
        pkts_out=12.0,
        protocol_num=6,
    )
    events = [
        CanonicalSecurityEvent(
            event_timestamp=datetime.now(timezone.utc),
            event_kind=EventKind.FLOW,
            source_id="bench:offline",
            source_ip=f"10.0.{(i // 250) % 256}.{(i % 250) + 1}",
            dest_ip="192.168.1.1",
            source_port=10000 + (i % 50000),
            dest_port=80,
            protocol="TCP",
            flow_metrics=FlowMetrics(
                duration_ms=50.0,
                bytes_in=1000,
                bytes_out=2500,
                pkts_in=10,
                pkts_out=12,
                tcp_flags=24,
            ),
            raw_provenance=RawProvenance(source_file="bench.csv", adapter_name="BenchAdapter"),
            is_ml_complete=True,
            ml_features=dict(base_feats),
        )
        for i in range(batch_events)
    ]

    # Warm-up
    for ev in events[:10]:
        orchestrator.process_event(ev)

    # 1. End-to-End single-event latency distribution (separate from component microbenchmarks)
    e2e_latencies_us: List[float] = []
    t0_batch = time.perf_counter()
    for ev in events:
        t_s = time.perf_counter_ns()
        orchestrator.process_event(ev)
        e2e_latencies_us.append((time.perf_counter_ns() - t_s) / 1000.0)
    e2e_elapsed = max(1e-9, time.perf_counter() - t0_batch)
    e2e_throughput = round(len(events) / e2e_elapsed, 2)

    # 2. Replay mode throughput
    replay_summary = mode_mgr.run_replay_scenario(
        events=events,
        source_name="bench:replay",
        speed_factor=float("inf"),
    )

    # 3. Ring-buffer pipeline metrics measured directly from StreamingEventPipeline
    ring_pipeline = StreamingEventPipeline(capacity=2000, batch_size=32)
    ring_pipeline.enqueue_batch(events)
    peak_util_pct = ring_pipeline.get_metrics().queue_utilization_pct
    drained = ring_pipeline.flush_all()
    ring_metrics = ring_pipeline.get_metrics()

    # 4. Separate component microbenchmarks (with warm-up)
    decoder = NetFlowIPFIXDecoder()
    sample_raw = b"\x00\x09\x00\x01\x00\x00\x03\xe8\x65\x50\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01"
    for _ in range(20):
        decoder.decode_datagram(sample_raw)
    dec_us = []
    for _ in range(micro_iters):
        t_s = time.perf_counter_ns()
        decoder.decode_datagram(sample_raw)
        dec_us.append((time.perf_counter_ns() - t_s) / 1000.0)

    contract_us = []
    for _ in range(micro_iters):
        t_s = time.perf_counter_ns()
        contract.validate_features(base_feats)
        contract_us.append((time.perf_counter_ns() - t_s) / 1000.0)

    inf_us = []
    for _ in range(min(micro_iters, 40)):
        t_s = time.perf_counter_ns()
        orchestrator.inference_engine.infer_event(events[0], base_feats)
        inf_us.append((time.perf_counter_ns() - t_s) / 1000.0)

    sessions = orchestrator.sessionizer.sessionize(events[:5])
    vec_builder = BehavioralVectorBuilder()
    beh_us = []
    for _ in range(micro_iters):
        t_s = time.perf_counter_ns()
        vec_builder.build_vector(sessions[0])
        beh_us.append((time.perf_counter_ns() - t_s) / 1000.0)

    cipher = AESGCMCipher(b"\x01" * 32, key_id="k-bench")
    vec_bytes = b"0.12,0.45,0.88,0.05,0.67,0.92,0.33,0.14,0.77,0.44,0.19,0.81,0.65,0.28,0.39,0.52"
    cry_us = []
    for _ in range(micro_iters):
        t_s = time.perf_counter_ns()
        cipher.encrypt(vec_bytes)
        cry_us.append((time.perf_counter_ns() - t_s) / 1000.0)

    risk_us = []
    for _ in range(micro_iters):
        t_s = time.perf_counter_ns()
        orchestrator.alert_manager.process_event_risk(events[0])
        risk_us.append((time.perf_counter_ns() - t_s) / 1000.0)

    readiness = orchestrator.inference_engine.readiness()

    results: Dict[str, Any] = {
        "benchmark_title": "NetFlow Sentinel v2.0 Dynamic System Performance Benchmark",
        "benchmark_executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "hardware_environment": env,
        "inference_readiness": {
            "inference_mode": readiness["inference_mode"],
            "ready_count": readiness["ready_count"],
            "validated_count": readiness["validated_count"],
            "runtime_mode": readiness["runtime_mode"],
            "ood_gate_status": readiness["ood_gate_status"],
            "ood_gate_trust_anchor": readiness["ood_gate_trust_anchor"],
        },
        "end_to_end_measured": {
            "events_processed": len(events),
            "elapsed_seconds": round(e2e_elapsed, 4),
            "throughput_events_per_sec": e2e_throughput,
            "latency_us": _summary_us(e2e_latencies_us),
        },
        "replay_mode_measured": {
            "events_processed": replay_summary.total_events_processed,
            "elapsed_seconds": replay_summary.elapsed_seconds,
            "throughput_events_per_sec": replay_summary.throughput_events_per_sec,
        },
        "ring_buffer_measured": {
            "capacity": 2000,
            "events_enqueued": len(events),
            "events_drained": len(drained),
            "peak_utilization_pct": peak_util_pct,
            "dropped_events": ring_metrics.total_dropped,
        },
        "component_microbenchmarks_us": {
            "collector_decoding": _summary_us(dec_us),
            "feature_contract_validation": _summary_us(contract_us),
            "multi_model_ai_inference": _summary_us(inf_us),
            "behavioral_vector_build": _summary_us(beh_us),
            "aes_256_gcm_encrypt": _summary_us(cry_us),
            "risk_scoring_dedup": _summary_us(risk_us),
        },
        "limitations": [
            "Measurements reflect in-process synthetic event workloads on this specific host and do not constitute 1-10 Gbps physical NIC line-rate certification.",
            "Component microbenchmarks and full end-to-end event processing latency are reported separately because Python loop/dispatch and SQLite/sessionizer overhead are not additive across isolated microbenchmarks.",
        ],
    }
    return results


def run_benchmark(
    batch_events: int = 200,
    micro_iters: int = 100,
    repeats: int = 3,
    runtime_mode: Optional[str] = None,
    expected_ood_gate_sha256: Optional[str] = None,
    output_json: Optional[Path] = None,
    output_md: Optional[Path] = None,
) -> Dict[str, Any]:
    eff_output_json = Path(output_json) if output_json is not None else OUTPUT_JSON
    eff_output_md = Path(output_md) if output_md is not None else OUTPUT_MD
    repeats = max(1, int(repeats))
    runs = [
        _run_single_benchmark_pass(
            batch_events=batch_events,
            micro_iters=micro_iters,
            runtime_mode=runtime_mode,
            expected_ood_gate_sha256=expected_ood_gate_sha256,
        )
        for _ in range(repeats)
    ]
    results = dict(runs[-1])
    comp_keys = list(results["component_microbenchmarks_us"].keys())
    repeatability = {
        "repeats": repeats,
        "end_to_end_throughput_events_per_sec": _variance_stats(
            [r["end_to_end_measured"]["throughput_events_per_sec"] for r in runs]
        ),
        "end_to_end_median_latency_us": _variance_stats(
            [r["end_to_end_measured"]["latency_us"]["median_us"] for r in runs]
        ),
        "replay_mode_throughput_events_per_sec": _variance_stats(
            [r["replay_mode_measured"]["throughput_events_per_sec"] for r in runs]
        ),
        "component_medians_us": {
            ck: _variance_stats([r["component_microbenchmarks_us"][ck]["median_us"] for r in runs])
            for ck in comp_keys
        },
    }
    results["repeatability_summary"] = repeatability

    eff_output_json.parent.mkdir(parents=True, exist_ok=True)
    eff_output_json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")

    env = results["hardware_environment"]
    readiness = results["inference_readiness"]
    events_n = results["end_to_end_measured"]["events_processed"]
    e2e_throughput = results["end_to_end_measured"]["throughput_events_per_sec"]
    e2e_lat = results["end_to_end_measured"]["latency_us"]
    peak_util_pct = results["ring_buffer_measured"]["peak_utilization_pct"]
    dropped_events = results["ring_buffer_measured"]["dropped_events"]
    md_lines = [
        "# System Performance Benchmark Report (Dynamic Measurement)",
        "",
        f"- **Executed At (UTC):** `{results['benchmark_executed_at_utc']}`",
        f"- **Host OS / CPU / RAM:** `{env['os']}` / `{env['cpu_count']} vCPU` / `{env['total_ram_gb']} GB`",
        (
            f"- **Python:** `{env['python_version']}` | "
            f"**AI Readiness:** `{readiness['ready_count']}/4 ({readiness['inference_mode']})` | "
            f"**Runtime Mode:** `{readiness['runtime_mode']}` | "
            f"**OOD Gate:** `{readiness['ood_gate_status']}` (`{readiness['ood_gate_trust_anchor']}`)"
        ),
        f"- **Repeatability Runs:** `{repeats}`",
        "",
        "## 1. End-to-End Orchestrator Measurement",
        f"- **Events Processed:** `{events_n}` (latest run)",
        f"- **Throughput (Latest / Mean ± Std / CV%):** `{e2e_throughput:,.2f} flow/s` / `{repeatability['end_to_end_throughput_events_per_sec']['mean']:,.2f} ± {repeatability['end_to_end_throughput_events_per_sec']['std']:,.2f}` (`CV={repeatability['end_to_end_throughput_events_per_sec']['cv_pct']}%`)",
        f"- **E2E Latency (Med / P95 / P99):** `{e2e_lat['median_us']} / {e2e_lat['p95_us']} / {e2e_lat['p99_us']} us` (Med CV=`{repeatability['end_to_end_median_latency_us']['cv_pct']}%`)",
        f"- **Replay Throughput (Mean ± Std / CV%):** `{repeatability['replay_mode_throughput_events_per_sec']['mean']:,.2f} ± {repeatability['replay_mode_throughput_events_per_sec']['std']:,.2f} flow/s` (`CV={repeatability['replay_mode_throughput_events_per_sec']['cv_pct']}%`)",
        f"- **Ring Buffer Peak Utilization:** `{peak_util_pct}%` (`dropped={dropped_events}`)",
        "",
        "## 2. Isolated Component Microbenchmarks (Separate from E2E)",
        "",
        "| Component | Median (us) | P95 (us) | P99 (us) | Repeat Mean ± Std (us) | CV (%) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for cname, cstats in results["component_microbenchmarks_us"].items():
        rstats = repeatability["component_medians_us"][cname]
        md_lines.append(
            f"| {cname} | {cstats['median_us']} | {cstats['p95_us']} | {cstats['p99_us']} | "
            f"{rstats['mean']} ± {rstats['std']} | {rstats['cv_pct']}% |"
        )
    md_lines.extend(["", "## 3. Limitations", *[f"- {lim}" for lim in results["limitations"]]])
    eff_output_md.parent.mkdir(parents=True, exist_ok=True)
    eff_output_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Dynamic system benchmark written: {eff_output_json} and {eff_output_md}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Dynamic System Performance Benchmark")
    parser.add_argument("--events", type=int, default=200)
    parser.add_argument("--micro-iters", type=int, default=100)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--runtime-mode",
        choices=["deployment", "research"],
        default=None,
        help="Runtime policy mode (defaults to fail-closed deployment).",
    )
    parser.add_argument(
        "--ood-gate-sha256",
        default=None,
        help="Trusted 64-hex SHA-256 trust anchor for persisted OOD gate verification.",
    )
    args = parser.parse_args()
    run_benchmark(
        batch_events=args.events,
        micro_iters=args.micro_iters,
        repeats=args.repeats,
        runtime_mode=args.runtime_mode,
        expected_ood_gate_sha256=args.ood_gate_sha256,
    )


if __name__ == "__main__":
    main()
