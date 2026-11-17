#!/usr/bin/env python3
"""Benchmark AES-256-GCM Cryptographic Overhead (Issue #126 / RQ6).

Measures encryption, decryption, and plaintext JSON baseline across multiple
payload sizes with warm-up iterations, multiple trials, median/P95/P99 latency,
throughput, peak traced memory, and runtime hardware/software metadata.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import tracemalloc
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

from network_anomaly.crypto.aead import AESGCMCipher  # noqa: E402


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


def _stats_us(latencies_us: List[float]) -> Dict[str, float]:
    s = sorted(latencies_us)
    return {
        "median_us": round(statistics.median(s), 3),
        "mean_us": round(statistics.mean(s), 3),
        "p95_us": round(_percentile(s, 95.0), 3),
        "p99_us": round(_percentile(s, 99.0), 3),
    }


def _build_payload(target_bytes: int) -> Dict[str, Any]:
    base = {
        "entity_id": "host-192.0.2.100",
        "vector_16d": [round(0.05 * (i + 1), 3) for i in range(16)],
        "window_start": "2026-11-17T14:00:00Z",
        "padding": "",
    }
    raw_len = len(json.dumps(base).encode("utf-8"))
    if target_bytes > raw_len:
        base["padding"] = "x" * (target_bytes - raw_len)
    return base


def run_benchmark(
    iterations: int = 2000,
    warmup: int = 200,
    payload_sizes: tuple[int, ...] = (256, 1024, 4096),
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    output_dir = output_dir or Path("reports/benchmarks")
    output_dir.mkdir(parents=True, exist_ok=True)
    env = collect_environment_metadata()

    key = os.urandom(32)
    cipher = AESGCMCipher(key, key_id="k-benchmark")
    aad = b"domain:behavioral|entity:host-192.0.2.100"

    per_size: Dict[str, Any] = {}
    for size in payload_sizes:
        payload_obj = _build_payload(size)
        payload_bytes = json.dumps(payload_obj).encode("utf-8")

        # Warm-up
        for _ in range(warmup):
            env_w = cipher.encrypt(payload_bytes, aad=aad)
            _ = cipher.decrypt(env_w, expected_aad=aad)

        # Plaintext JSON serialization baseline
        plain_latencies_us: List[float] = []
        t0_plain = time.perf_counter()
        for _ in range(iterations):
            t_s = time.perf_counter_ns()
            encoded = json.dumps(payload_obj).encode("utf-8")
            _ = json.loads(encoded.decode("utf-8"))
            plain_latencies_us.append((time.perf_counter_ns() - t_s) / 1000.0)
        plain_total_s = max(1e-9, time.perf_counter() - t0_plain)

        # Encryption benchmark with traced memory
        tracemalloc.start()
        enc_latencies_us: List[float] = []
        envelopes = []
        t0_enc = time.perf_counter()
        for _ in range(iterations):
            t_s = time.perf_counter_ns()
            env_item = cipher.encrypt(payload_bytes, aad=aad)
            enc_latencies_us.append((time.perf_counter_ns() - t_s) / 1000.0)
            envelopes.append(env_item)
        enc_total_s = max(1e-9, time.perf_counter() - t0_enc)
        _, peak_enc_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Decryption benchmark
        dec_latencies_us: List[float] = []
        t0_dec = time.perf_counter()
        for env_item in envelopes:
            t_s = time.perf_counter_ns()
            _ = cipher.decrypt(env_item, expected_aad=aad)
            dec_latencies_us.append((time.perf_counter_ns() - t_s) / 1000.0)
        dec_total_s = max(1e-9, time.perf_counter() - t0_dec)

        enc_stats = _stats_us(enc_latencies_us)
        dec_stats = _stats_us(dec_latencies_us)
        plain_stats = _stats_us(plain_latencies_us)
        per_size[str(len(payload_bytes))] = {
            "actual_payload_bytes": len(payload_bytes),
            "plaintext_json_roundtrip": {
                **plain_stats,
                "throughput_ops_sec": round(iterations / plain_total_s, 1),
            },
            "encryption": {
                **enc_stats,
                "throughput_ops_sec": round(iterations / enc_total_s, 1),
                "peak_traced_memory_mb": round(peak_enc_bytes / (1024 * 1024), 3),
            },
            "decryption": {
                **dec_stats,
                "throughput_ops_sec": round(iterations / dec_total_s, 1),
            },
        }

    # Evaluate H6 on the 256B behavioral-vector payload bucket
    first_key = next(iter(per_size))
    primary = per_size[first_key]
    hypothesis_confirmed = (
        primary["encryption"]["p95_us"] <= 500.0
        and primary["encryption"]["throughput_ops_sec"] >= 5000.0
    )

    results: Dict[str, Any] = {
        "benchmark_id": "BM-CRYPTO-OVERHEAD-RQ6",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "warmup_iterations": warmup,
        "measured_iterations_per_size": iterations,
        "hypothesis": "H6: AES-256-GCM adds <= 500 us P95 latency per vector event and >= 5,000 ops/sec",
        "hypothesis_confirmed": hypothesis_confirmed,
        "environment": env,
        "payload_benchmarks": per_size,
        "limitations": [
            "Microbenchmark runs in-process on the current host CPU and excludes SQLite disk I/O.",
        ],
    }

    json_path = output_dir / "crypto_benchmark_report.json"
    json_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    rows = []
    for sz, entry in per_size.items():
        enc = entry["encryption"]
        dec = entry["decryption"]
        pln = entry["plaintext_json_roundtrip"]
        rows.append(
            f"| {sz} B | {pln['median_us']:.2f} us | {enc['median_us']:.2f} / {enc['p95_us']:.2f} / {enc['p99_us']:.2f} us | "
            f"{dec['median_us']:.2f} / {dec['p95_us']:.2f} / {dec['p99_us']:.2f} us | "
            f"{enc['throughput_ops_sec']:,.1f} ops/s | {enc['peak_traced_memory_mb']} MB |"
        )
    md_lines = [
        "# Cryptographic Performance & Overhead Benchmark (RQ6)",
        "",
        f"- **Timestamp (UTC):** `{results['timestamp']}`",
        f"- **Host OS / CPU / RAM:** `{env['os']}` / `{env['cpu_count']} vCPU` / `{env['total_ram_gb']} GB`",
        f"- **Python / cryptography:** `{env['python_version']}` / `{env['packages']['cryptography']}`",
        f"- **Warm-up:** `{warmup}` | **Iterations/size:** `{iterations}`",
        f"- **Hypothesis Confirmed:** `{hypothesis_confirmed}`",
        "",
        "| Payload | Plaintext Median | Encrypt (Med / P95 / P99) | Decrypt (Med / P95 / P99) | Encrypt Throughput | Peak Traced RAM |",
        "|---:|---:|---:|---:|---:|---:|",
        *rows,
    ]
    md_path = output_dir / "crypto_benchmark_report.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"RQ6 crypto benchmark written: {json_path} and {md_path}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="RQ6 AES-256-GCM Overhead Benchmark")
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=200)
    args = parser.parse_args()
    run_benchmark(iterations=args.iterations, warmup=args.warmup)


if __name__ == "__main__":
    main()
