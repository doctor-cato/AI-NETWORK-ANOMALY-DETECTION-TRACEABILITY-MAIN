#!/usr/bin/env python3
"""Real-Dataset NetFlow v9 / IPFIX UDP Loopback Replay Verification (#137 / #142).

Reads real canonical v2 flow records (from demo_flows.csv + demo_labels.csv, or
processed_v2 partitions such as ait_test.csv.gz), serializes them into real
NetFlow v9 datagrams over the OS UDP loopback stack, and tracks them end-to-end
through:

    Real Flow CSV -> UDP socket -> NetFlowIPFIXDecoder -> StreamingEventPipeline
    -> LiveSystemOrchestrator (deployment or research policy) -> 4-model E0 AI
    -> RiskScorer -> Alerts -> EncryptedStorageVault -> Multi-Stage Attack Timeline

Limitation Notice:
    This is a Real-Dataset UDP Loopback Replay integration check. It uses real
    flow records from published datasets rather than handcrafted flows, while
    still transmitting over localhost UDP (real_hardware_switch = false). It
    does NOT replace physical router/switch lab hardware acceptance for #137.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = PROJECT_ROOT / "src"
_SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(_SRC_DIR), str(_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.ml.ood_gate import DEFAULT_OOD_GATE_PATH  # noqa: E402
from network_anomaly.streaming.live_service import LiveTelemetryService  # noqa: E402
from network_anomaly.telemetry.collector import LAB_ENTERPRISE_FIELD_BASE  # noqa: E402
from network_anomaly.trace.timeline import AttackTimelineReconstructor  # noqa: E402

OUT_JSON = PROJECT_ROOT / "reports" / "acceptance" / "real_dataset_udp_replay_report.json"
OUT_MD = PROJECT_ROOT / "docs" / "telemetry" / "REAL_DATASET_UDP_REPLAY.md"


def _safe_ipv4(ip_val: Any, fallback: str) -> str:
    if ip_val is None or pd.isna(ip_val):
        return fallback
    s = str(ip_val).strip()
    try:
        socket.inet_aton(s)
        return s
    except OSError:
        return fallback


def _safe_uint(val: Any, default: int, upper: int) -> int:
    if val is None or pd.isna(val):
        return default
    try:
        iv = int(float(val))
        return max(0, min(upper, iv))
    except (TypeError, ValueError):
        return default


def _build_v9_template_packet() -> List[Tuple[int, int]]:
    standard = [
        (8, 4),  # IPV4_SRC_ADDR
        (12, 4),  # IPV4_DST_ADDR
        (7, 2),  # L4_SRC_PORT
        (11, 2),  # L4_DST_PORT
        (4, 1),  # PROTOCOL
        (1, 4),  # IN_BYTES
        (23, 4),  # OUT_BYTES
        (2, 4),  # IN_PKTS
        (24, 4),  # OUT_PKTS
        (6, 1),  # TCP_FLAGS
        (22, 4),  # FLOW_START_SYS_UP
        (21, 4),  # FLOW_END_SYS_UP
    ]
    lab = [(LAB_ENTERPRISE_FIELD_BASE + idx, 8) for idx in range(len(ML_FEATURE_COLUMNS))]
    return standard + lab


def _encode_real_flows_v9_packet(
    rows: List[Dict[str, Any]],
    *,
    include_template: bool,
    template_id: int = 260,
    base_sys_uptime_ms: int = 2_000_000,
) -> bytes:
    payload = bytearray()
    if include_template:
        fields = _build_v9_template_packet()
        tmpl_body = struct.pack("!HH", template_id, len(fields))
        for ftype, flen in fields:
            tmpl_body += struct.pack("!HH", ftype, flen)
        payload += struct.pack("!HH", 0, 4 + len(tmpl_body)) + tmpl_body

    rec_bytes = bytearray()
    for idx, row in enumerate(rows):
        src_ip = _safe_ipv4(row.get("source_ip"), f"10.10.{(idx // 200) % 256}.{(idx % 200) + 1}")
        dst_ip = _safe_ipv4(row.get("dest_ip"), "192.168.50.10")
        src_port = _safe_uint(row.get("source_port"), 40000 + (idx % 20000), 65535)
        dst_port = _safe_uint(row.get("dest_port"), 443, 65535)
        proto = _safe_uint(row.get("protocol_num"), 6, 255)
        b_in = _safe_uint(row.get("bytes_in"), 0, 0xFFFFFFFF)
        b_out = _safe_uint(row.get("bytes_out"), 0, 0xFFFFFFFF)
        p_in = _safe_uint(row.get("pkts_in"), 0, 0xFFFFFFFF)
        p_out = _safe_uint(row.get("pkts_out"), 0, 0xFFFFFFFF)
        dur = _safe_uint(row.get("duration_ms"), 1, 0x7FFFFFFF)
        tcp_flags = 24 if proto == 6 else 0
        start_up = base_sys_uptime_ms + idx * 10

        rec = (
            socket.inet_aton(src_ip)
            + socket.inet_aton(dst_ip)
            + struct.pack(
                "!HHBIIIIBII",
                src_port,
                dst_port,
                proto,
                b_in,
                b_out,
                p_in,
                p_out,
                tcp_flags,
                start_up,
                start_up + dur,
            )
        )
        rec += b"".join(struct.pack("!d", float(row[col])) for col in ML_FEATURE_COLUMNS)
        rec_bytes += rec

    payload += struct.pack("!HH", template_id, 4 + len(rec_bytes)) + rec_bytes
    header = struct.pack(
        "!HHIIII",
        9,
        (1 if include_template else 0) + len(rows),
        base_sys_uptime_ms,
        int(time.time()),
        1,
        101,
    )
    return header + bytes(payload)


def _load_real_replay_sample(
    *,
    source_csv: Optional[Path] = None,
    max_per_category: int = 12,
) -> Tuple[pd.DataFrame, str]:
    """Load real dataset rows spanning Benign and multiple attack phases."""
    if source_csv is not None:
        df = pd.read_csv(source_csv, low_memory=False)
        resolved_src = source_csv.resolve()
        src_desc = (
            str(resolved_src.relative_to(PROJECT_ROOT.resolve())).replace("\\", "/")
            if resolved_src.is_relative_to(PROJECT_ROOT.resolve())
            else source_csv.name
        )
    else:
        ait_test = PROJECT_ROOT / "data" / "processed" / "v2" / "ait_test.csv.gz"
        demo_flows = PROJECT_ROOT / "data" / "demo" / "demo_flows.csv"
        demo_labels = PROJECT_ROOT / "data" / "demo" / "demo_labels.csv"
        if ait_test.is_file():
            df = pd.read_csv(ait_test, low_memory=False)
            src_desc = "data/processed/v2/ait_test.csv.gz"
        elif demo_flows.is_file() and demo_labels.is_file():
            f_df = pd.read_csv(demo_flows)
            l_df = pd.read_csv(demo_labels)
            df = f_df.merge(l_df, on="row_id", how="left")
            src_desc = "data/demo/demo_flows.csv + demo_labels.csv"
        else:
            raise FileNotFoundError(
                "No real replay source found (checked ait_test.csv.gz and demo_flows.csv)"
            )

    if "attack_category" in df.columns:
        parts: List[pd.DataFrame] = []
        # Deterministic chronological order across distinct categories/phases
        for cat in sorted(df["attack_category"].dropna().astype(str).unique().tolist()):
            sub = df[df["attack_category"].astype(str) == cat].iloc[:max_per_category]
            parts.append(sub)
        sample = pd.concat(parts, ignore_index=True)
    else:
        sample = df.iloc[: (max_per_category * 4)].copy()

    return sample, src_desc


def run_real_udp_replay(
    *,
    runtime_mode: str = "deployment",
    expected_ood_gate_sha256: Optional[str] = None,
    source_csv: Optional[Path] = None,
    max_per_category: int = 12,
    write_outputs: bool = True,
) -> Dict[str, Any]:
    sample_df, source_desc = _load_real_replay_sample(
        source_csv=source_csv,
        max_per_category=max_per_category,
    )
    rows = sample_df.to_dict(orient="records")
    if not rows:
        raise ValueError("Replay dataset produced 0 rows")

    eff_sha = expected_ood_gate_sha256 or os.environ.get("NETFLOW_OOD_GATE_SHA256")
    if eff_sha is None and runtime_mode == "deployment" and DEFAULT_OOD_GATE_PATH.is_file():
        eff_sha = hashlib.sha256(DEFAULT_OOD_GATE_PATH.read_bytes()).hexdigest().lower()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / "real_replay.db"
        key_dir = tmp_path / "keystore"

        service = LiveTelemetryService(
            host="127.0.0.1",
            port=0,
            db_path=db_path,
            keystore_dir=key_dir,
            demo_heuristics=False,
            runtime_mode=runtime_mode,
            require_ood_gate=(runtime_mode == "deployment"),
            expected_ood_gate_sha256=eff_sha,
            queue_capacity=2048,
            batch_size=16,
            history_capacity=len(rows) + 50,
        )
        start_info = service.start()
        bound_port = int(start_info["bound_port"])
        t0 = time.perf_counter()
        try:
            chunk_size = 10
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for i in range(0, len(rows), chunk_size):
                    chunk = rows[i : i + chunk_size]
                    pkt = _encode_real_flows_v9_packet(
                        chunk,
                        include_template=(i == 0),
                    )
                    sock.sendto(pkt, ("127.0.0.1", bound_port))
                    time.sleep(0.02)

            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                st = service.status()
                if int(st["metrics"]["events_processed"]) >= len(rows):
                    break
                time.sleep(0.05)

            elapsed = max(0.001, time.perf_counter() - t0)
            final_status = service.status()
            alerts = service.recent_alerts(limit=200)
            recent = service.recent_results(limit=len(rows) + 20)

            reconstructor = AttackTimelineReconstructor()
            tl_events: List[Dict[str, Any]] = []
            for idx, item in enumerate(recent):
                risk_sc = float(item.get("risk_score", 0.0) or 0.0)
                if risk_sc >= 30.0 or item.get("alert"):
                    tl_events.append(
                        {
                            "event_id": item.get("event_id", f"ev-{idx}"),
                            "timestamp": item.get("timestamp")
                            or datetime.now(timezone.utc).isoformat(),
                            "source_ip": item.get("source_ip") or "unknown",
                            "dest_ip": item.get("dest_ip") or "unknown",
                            "dest_port": int(item.get("dest_port") or 0),
                            "bytes_out": float(
                                rows[min(idx, len(rows) - 1)].get("bytes_out") or 0.0
                            ),
                            "attack_type": item.get("attack_type") or "",
                            "risk_score": risk_sc,
                            "is_observed": True,
                            "confidence": min(0.99, max(0.5, risk_sc / 100.0)),
                            "description": f"Real-replay flow alert risk={risk_sc:.2f}",
                        }
                    )
            timeline = reconstructor.reconstruct_timeline("real-dataset-udp-replay", tl_events)
            campaigns = [timeline] if timeline.stages else []
            multi_stage_campaigns = (
                [timeline] if len({s.phase.value for s in timeline.stages}) >= 2 else []
            )
        finally:
            service.stop()

    cat_counts = (
        {str(k): int(v) for k, v in sample_df["attack_category"].value_counts().items()}
        if "attack_category" in sample_df.columns
        else {}
    )
    encrypted_count = sum(1 for r in recent if r.get("behavioral_vector_encrypted"))
    report: Dict[str, Any] = {
        "report_title": "Real-Dataset NetFlow v9 UDP Loopback Replay Verification",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "real_hardware_switch": False,
        "synthetic_handcrafted_flows": False,
        "dataset_source": source_desc,
        "category_distribution_replayed": cat_counts,
        "runtime_policy": {
            "runtime_mode": runtime_mode,
            "expected_ood_gate_sha256_supplied": bool(eff_sha),
            "ood_gate_trust_anchor": final_status["inference"].get("ood_gate_trust_anchor"),
            "ood_gate_status": final_status["inference"].get("ood_gate_status"),
            "inference_mode": final_status["inference"].get("inference_mode"),
            "ready_count": final_status["inference"].get("ready_count"),
        },
        "replay_metrics": {
            "flows_sent": len(rows),
            "flows_decoded": int(final_status["collector"].get("flows_decoded", 0)),
            "events_processed": int(final_status["metrics"].get("events_processed", 0)),
            "ml_ready_events": int(final_status["metrics"].get("ml_ready_events", 0)),
            "avg_inference_latency_us": final_status["metrics"].get("avg_inference_latency_us"),
            "elapsed_seconds": round(elapsed, 4),
            "encrypted_behavioral_vectors": encrypted_count,
            "alerts_generated": len(alerts),
            "campaigns_reconstructed": len(campaigns),
            "multi_stage_campaigns": len(multi_stage_campaigns),
        },
        "sample_timelines": [
            {
                "campaign_id": c.timeline_id,
                "stage_count": len(c.stages),
                "phases": sorted({s.phase.value for s in c.stages}),
                "observed_stages": sum(1 for s in c.stages if s.is_observed),
                "inferred_stages": sum(1 for s in c.stages if not s.is_observed),
            }
            for c in campaigns[:5]
        ],
        "limitations": [
            "Real flow features from published datasets were encoded into NetFlow v9 UDP datagrams over localhost (127.0.0.1); real_hardware_switch=false.",
            "Does NOT replace physical Cisco/MikroTik/softflowd router switch telemetry required for full #137 hardware lab signoff.",
        ],
    }

    if write_outputs:
        OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
        OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        rp = report["runtime_policy"]
        rm = report["replay_metrics"]
        md_lines = [
            "# Real-Dataset NetFlow v9 UDP Replay Verification (`#137` / `#142`)",
            "",
            f"- **Executed At (UTC):** `{report['executed_at_utc']}`",
            f"- **Source Dataset:** `{source_desc}` (`real_hardware_switch: false`)",
            f"- **Runtime Policy:** `{rp['runtime_mode']}` | **OOD Trust Anchor:** `{rp['ood_gate_trust_anchor']}` (`{rp['ood_gate_status']}`)",
            f"- **AI Readiness:** `{rp['ready_count']}/4` (`{rp['inference_mode']}`)",
            "",
            "## Replay Pipeline Metrics",
            f"- **Flows Sent / Decoded / Processed:** `{rm['flows_sent']}` / `{rm['flows_decoded']}` / `{rm['events_processed']}`",
            f"- **ML-Ready Events:** `{rm['ml_ready_events']}` | **Encrypted Behavioral Vectors:** `{rm['encrypted_behavioral_vectors']}`",
            f"- **Alerts Generated:** `{rm['alerts_generated']}` | **Reconstructed Campaigns:** `{rm['campaigns_reconstructed']}` (`multi_stage={rm['multi_stage_campaigns']}`)",
            f"- **Avg Inference Latency:** `{rm['avg_inference_latency_us']} us` | **Elapsed:** `{rm['elapsed_seconds']} s`",
            "",
            "## Replayed Categories",
            *[f"- `{k}`: `{v}` flows" for k, v in cat_counts.items()],
            "",
            "## Limitations",
            *[f"- {lim}" for lim in report["limitations"]],
        ]
        OUT_MD.parent.mkdir(parents=True, exist_ok=True)
        OUT_MD.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
        print(f"[done] Real-dataset UDP replay written: {OUT_JSON} and {OUT_MD}")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Real-Dataset NetFlow v9 UDP Replay")
    parser.add_argument("--runtime-mode", choices=("deployment", "research"), default="deployment")
    parser.add_argument("--expected-ood-gate-sha256", default=None)
    parser.add_argument("--source-csv", type=Path, default=None)
    parser.add_argument("--max-per-category", type=int, default=12)
    args = parser.parse_args()
    rep = run_real_udp_replay(
        runtime_mode=args.runtime_mode,
        expected_ood_gate_sha256=args.expected_ood_gate_sha256,
        source_csv=args.source_csv,
        max_per_category=args.max_per_category,
    )
    ok = rep["replay_metrics"]["events_processed"] >= rep["replay_metrics"]["flows_sent"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
