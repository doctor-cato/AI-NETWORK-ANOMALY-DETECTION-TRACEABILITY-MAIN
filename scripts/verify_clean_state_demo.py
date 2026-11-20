#!/usr/bin/env python3
"""Clean-State 2x Repeatability Verification across Offline, Replay, and Live UDP modes.

Implements Issue #150 AC1 for NetFlow Sentinel v2.0.

Executes 2 independent clean-state runs (each inside a fresh TemporaryDirectory
with an empty SQLite DB and empty keystore, runtime_mode="deployment", and the
trusted OOD reference gate SHA-256) across:
  1. Scenario 1 (Offline): 200 flows from data/demo/demo_flows.csv through
     ModelRegistry & LiveSystemOrchestrator.process_batch.
  2. Scenario 2 (Replay): 65 real flows from ait_test (or demo_flows.csv fallback)
     through ModeOrchestrator.run_replay_scenario(batch_size=32).
  3. Scenario 3 (Live UDP Loopback): LiveTelemetryService bound on 127.0.0.1:0
     receiving binary NetFlow v9 UDP datagrams over loopback.

Compares Run 1 vs Run 2 deterministic counts (repeatable_100pct: true) and writes
reports/demo/clean_state_demo_verification.json.
"""

from __future__ import annotations

import json
import socket
import sqlite3
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
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from network_anomaly.canonical.event import (  # noqa: E402
    CanonicalSecurityEvent,
    EventKind,
    FlowMetrics,
    RawProvenance,
)
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.models.registry import ModelRegistry  # noqa: E402
from network_anomaly.streaming.live_orchestrator import LiveSystemOrchestrator  # noqa: E402
from network_anomaly.streaming.live_service import LiveTelemetryService  # noqa: E402
from network_anomaly.telemetry.collector import LAB_ENTERPRISE_FIELD_BASE  # noqa: E402
from network_anomaly.telemetry.modes import ModeOrchestrator  # noqa: E402

TRUSTED_OOD_GATE_SHA256 = "8a52bfe5ad156560a3949afd5d4860c175ce5d158c38eb47aae07342102e9825"
OUT_JSON = PROJECT_ROOT / "reports" / "demo" / "clean_state_demo_verification.json"


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


def _proto_num_to_name(proto_num: int) -> str:
    if proto_num == 6:
        return "TCP"
    if proto_num == 17:
        return "UDP"
    if proto_num == 1:
        return "ICMP"
    return str(proto_num)


def _row_to_canonical_event(
    row: Dict[str, Any],
    idx: int,
    source_id: str,
    source_file: str,
) -> CanonicalSecurityEvent:
    row_id = row.get("row_id", idx)
    ts_raw = row.get("timestamp_ms")
    if ts_raw is not None and not pd.isna(ts_raw):
        val = float(ts_raw)
        ts = datetime.fromtimestamp(val / 1000.0 if val > 1e11 else val, tz=timezone.utc)
    else:
        ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    src_ip = _safe_ipv4(row.get("source_ip"), f"10.10.{(idx // 200) % 256}.{(idx % 200) + 1}")
    dst_ip = _safe_ipv4(row.get("dest_ip"), "192.168.50.10")
    src_port = _safe_uint(row.get("source_port"), 40000 + (idx % 20000), 65535)
    dst_port = _safe_uint(row.get("dest_port"), 443, 65535)
    proto_num = _safe_uint(row.get("protocol_num"), 6, 255)

    ml_features = {col: float(row[col]) for col in ML_FEATURE_COLUMNS}
    attack_cat = row.get("attack_category")
    attack_cat_str = (
        str(attack_cat)
        if attack_cat is not None and not pd.isna(attack_cat) and str(attack_cat).strip()
        else None
    )

    return CanonicalSecurityEvent(
        event_id=f"{source_id}-ev-{idx}-{row_id}",
        event_timestamp=ts,
        event_kind=EventKind.FLOW,
        source_id=source_id,
        entity_id=f"host:{src_ip}",
        source_ip=src_ip,
        dest_ip=dst_ip,
        source_port=src_port,
        dest_port=dst_port,
        protocol=_proto_num_to_name(proto_num),
        flow_metrics=FlowMetrics(
            duration_ms=float(row.get("duration_ms", 0.0)),
            bytes_in=int(float(row.get("bytes_in", 0.0))),
            bytes_out=int(float(row.get("bytes_out", 0.0))),
            pkts_in=int(float(row.get("pkts_in", 0.0))),
            pkts_out=int(float(row.get("pkts_out", 0.0))),
        ),
        ml_features=ml_features,
        attack_category=attack_cat_str,
        raw_provenance=RawProvenance(
            source_file=source_file,
            adapter_name="clean-state-demo-verifier",
        ),
    )


def _load_replay_65_rows() -> Tuple[List[Dict[str, Any]], str]:
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
        src_desc = "data/demo/demo_flows.csv + data/demo/demo_labels.csv"
    elif demo_flows.is_file():
        df = pd.read_csv(demo_flows)
        src_desc = "data/demo/demo_flows.csv"
    else:
        raise FileNotFoundError("Neither ait_test.csv.gz nor demo_flows.csv is available.")

    if "attack_category" in df.columns:
        parts: List[pd.DataFrame] = []
        for cat in sorted(df["attack_category"].dropna().astype(str).unique().tolist()):
            sub = df[df["attack_category"].astype(str) == cat].iloc[:12]
            parts.append(sub)
        sample = pd.concat(parts, ignore_index=True)
        if len(sample) < 65 and len(df) >= 65:
            remaining = df.loc[~df.index.isin(sample.index)].iloc[: (65 - len(sample))]
            sample = pd.concat([sample, remaining], ignore_index=True)
        sample = sample.iloc[:65].copy()
    else:
        sample = df.iloc[:65].copy()

    return sample.to_dict(orient="records"), src_desc


def _build_v9_template_fields() -> List[Tuple[int, int]]:
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


def _encode_v9_datagram(
    rows: List[Dict[str, Any]],
    *,
    include_template: bool,
    template_id: int = 260,
    base_sys_uptime_ms: int = 2_000_000,
    fixed_unix_secs: int = 1_700_000_000,
) -> bytes:
    payload = bytearray()
    if include_template:
        fields = _build_v9_template_fields()
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
        fixed_unix_secs,
        1,
        101,
    )
    return header + bytes(payload)


def _count_sqlite_rows(db_path: Path, table_name: str) -> int:
    if not db_path.is_file():
        return 0
    from contextlib import closing

    with closing(sqlite3.connect(db_path)) as conn:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        if cur.fetchone() is None:
            return 0
        row = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()
        return int(row[0]) if row else 0


def _run_offline_scenario(run_index: int) -> Dict[str, Any]:
    demo_csv = PROJECT_ROOT / "data" / "demo" / "demo_flows.csv"
    df = pd.read_csv(demo_csv)
    rows = df.to_dict(orient="records")
    events = [
        _row_to_canonical_event(row, idx, "offline-demo", "data/demo/demo_flows.csv")
        for idx, row in enumerate(rows)
    ]

    with tempfile.TemporaryDirectory(
        prefix=f"nf-clean-offline-run{run_index}-",
        ignore_cleanup_errors=True,
    ) as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / "offline_clean.db"
        keystore_dir = tmp_path / "keystore"

        registry = ModelRegistry()
        statuses = registry.statuses()
        ready_models = [s.model_key for s in statuses if s.decision_ready]

        orchestrator = LiveSystemOrchestrator(
            db_path=db_path,
            keystore_dir=keystore_dir,
            runtime_mode="deployment",
            require_ood_gate=True,
            expected_ood_gate_sha256=TRUSTED_OOD_GATE_SHA256,
        )
        t0 = time.perf_counter()
        results = orchestrator.process_batch(events)
        elapsed_s = round(time.perf_counter() - t0, 4)

        readiness = orchestrator.inference_engine.readiness()
        anomalies = sum(
            1
            for r in results
            if r.inference_decision is not None and r.inference_decision.ensemble_is_anomaly
        )
        ood_abstained = sum(
            1 for r in results if r.inference_decision is not None and r.inference_decision.is_ood
        )
        ml_ready_count = sum(1 for r in results if r.is_ml_flow)
        encrypted_vectors = sum(1 for r in results if r.behavioral_vector_encrypted)
        alerts_count = sum(1 for r in results if r.alert_generated is not None)
        errors_count = sum(
            1
            for r in results
            if r.inference_decision is None or r.inference_decision.inference_mode != "REAL_MODELS"
        )
        per_model_anomaly_counts: Dict[str, int] = {}
        for r in results:
            if r.inference_decision:
                for m_id, pred in r.inference_decision.model_predictions.items():
                    if pred.get("is_anomaly"):
                        per_model_anomaly_counts[m_id] = per_model_anomaly_counts.get(m_id, 0) + 1
                    else:
                        per_model_anomaly_counts.setdefault(m_id, 0)

        persisted_events = _count_sqlite_rows(db_path, "unified_security_events")
        persisted_vectors = _count_sqlite_rows(db_path, "behavioral_vectors")

        assert len(ready_models) == 4, f"Expected 4 ready models, got {ready_models}"
        assert readiness["inference_mode"] == "REAL_MODELS"
        assert readiness["ready_count"] == 4
        assert readiness["ood_gate_status"] == "FITTED"
        assert len(results) == 200
        assert ml_ready_count == 200
        assert errors_count == 0
        assert persisted_events == 200
        assert persisted_vectors == 200

        return {
            "scenario": "offline_csv_200_flows",
            "source_file": "data/demo/demo_flows.csv",
            "runtime_mode": readiness["runtime_mode"],
            "inference_mode": readiness["inference_mode"],
            "ready_count": readiness["ready_count"],
            "ready_models": sorted(ready_models),
            "ood_gate_status": readiness["ood_gate_status"],
            "flows_loaded": len(events),
            "events_processed": len(results),
            "ml_ready_events": ml_ready_count,
            "anomalies_detected": anomalies,
            "ood_abstained_count": ood_abstained,
            "per_model_anomaly_counts": dict(sorted(per_model_anomaly_counts.items())),
            "alerts_generated": alerts_count,
            "encrypted_behavioral_vectors": encrypted_vectors,
            "persisted_unified_security_events": persisted_events,
            "persisted_behavioral_vectors": persisted_vectors,
            "inference_errors": errors_count,
            "elapsed_seconds": elapsed_s,
        }


def _run_replay_scenario(
    run_index: int,
    replay_rows: List[Dict[str, Any]],
    source_desc: str,
) -> Dict[str, Any]:
    events = [
        _row_to_canonical_event(row, idx, "replay-demo", source_desc)
        for idx, row in enumerate(replay_rows)
    ]

    with tempfile.TemporaryDirectory(
        prefix=f"nf-clean-replay-run{run_index}-",
        ignore_cleanup_errors=True,
    ) as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / "replay_clean.db"
        keystore_dir = tmp_path / "keystore"

        orchestrator = LiveSystemOrchestrator(
            db_path=db_path,
            keystore_dir=keystore_dir,
            runtime_mode="deployment",
            require_ood_gate=True,
            expected_ood_gate_sha256=TRUSTED_OOD_GATE_SHA256,
        )
        mode_orchestrator = ModeOrchestrator(orchestrator=orchestrator)
        collected_results = []
        summary = mode_orchestrator.run_replay_scenario(
            events=events,
            source_name=source_desc,
            speed_factor=float("inf"),
            callback=collected_results.append,
            batch_size=32,
        )

        readiness = orchestrator.inference_engine.readiness()
        encrypted_vectors = sum(1 for r in collected_results if r.behavioral_vector_encrypted)
        errors_count = sum(
            1
            for r in collected_results
            if r.inference_decision is None or r.inference_decision.inference_mode != "REAL_MODELS"
        )
        persisted_events = _count_sqlite_rows(db_path, "unified_security_events")
        persisted_vectors = _count_sqlite_rows(db_path, "behavioral_vectors")
        dropped_events = len(events) - summary.total_events_processed

        assert readiness["inference_mode"] == "REAL_MODELS"
        assert readiness["ready_count"] == 4
        assert readiness["ood_gate_status"] == "FITTED"
        assert summary.total_events_processed == len(events)
        assert dropped_events == 0
        assert errors_count == 0
        assert encrypted_vectors == len(events)
        assert persisted_events == len(events)
        assert persisted_vectors == len(events)

        return {
            "scenario": "replay_mode_batch_32",
            "source_file": source_desc,
            "mode": summary.mode.value,
            "runtime_mode": readiness["runtime_mode"],
            "inference_mode": readiness["inference_mode"],
            "ready_count": readiness["ready_count"],
            "ood_gate_status": readiness["ood_gate_status"],
            "batch_size": 32,
            "total_events_processed": summary.total_events_processed,
            "anomalies_detected": summary.anomalies_detected,
            "alerts_raised": summary.alerts_raised,
            "adaptive_rotations_triggered": summary.adaptive_rotations_triggered,
            "encrypted_behavioral_vectors": encrypted_vectors,
            "persisted_unified_security_events": persisted_events,
            "persisted_behavioral_vectors": persisted_vectors,
            "dropped_events": dropped_events,
            "inference_errors": errors_count,
            "elapsed_seconds": summary.elapsed_seconds,
            "throughput_events_per_sec": summary.throughput_events_per_sec,
        }


def _run_live_udp_scenario(
    run_index: int,
    udp_rows: List[Dict[str, Any]],
    source_desc: str,
) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix=f"nf-clean-liveudp-run{run_index}-",
        ignore_cleanup_errors=True,
    ) as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / "live_udp_clean.db"
        keystore_dir = tmp_path / "keystore"

        service = LiveTelemetryService(
            host="127.0.0.1",
            port=0,
            db_path=db_path,
            keystore_dir=keystore_dir,
            demo_heuristics=False,
            runtime_mode="deployment",
            require_ood_gate=True,
            expected_ood_gate_sha256=TRUSTED_OOD_GATE_SHA256,
            queue_capacity=2048,
            batch_size=16,
            history_capacity=len(udp_rows) + 50,
        )
        start_status = service.start()
        live_mode_while_running = start_status["mode"]
        bound_port = int(start_status["bound_port"])
        t0 = time.perf_counter()

        try:
            chunk_size = 8
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for i in range(0, len(udp_rows), chunk_size):
                    chunk = udp_rows[i : i + chunk_size]
                    pkt = _encode_v9_datagram(
                        chunk,
                        include_template=(i == 0),
                        base_sys_uptime_ms=2_000_000 + i * 100,
                    )
                    sock.sendto(pkt, ("127.0.0.1", bound_port))
                    time.sleep(0.01)

            service.wait_until_processed(len(udp_rows), timeout_s=30.0)
            mid_status = service.status()
        finally:
            final_status = service.stop(flush=True)

        elapsed_s = round(time.perf_counter() - t0, 4)
        results = service.recent_results(limit=len(udp_rows) + 10)
        anomalies = sum(
            1 for r in results if r.get("inference", {}).get("ensemble_is_anomaly") is True
        )
        encrypted_vectors = sum(1 for r in results if r.get("behavioral_vector_encrypted") is True)
        persisted_events = _count_sqlite_rows(db_path, "unified_security_events")
        persisted_vectors = _count_sqlite_rows(db_path, "behavioral_vectors")

        readiness = final_status["inference"]
        metrics = final_status["metrics"]
        pipeline_stats = final_status["pipeline"]
        collector_stats = final_status["collector"]

        assert live_mode_while_running == "LIVE"
        assert mid_status["mode"] == "LIVE"
        assert readiness["inference_mode"] == "REAL_MODELS"
        assert readiness["ready_count"] == 4
        assert readiness["ood_gate_status"] == "FITTED"
        assert metrics["events_processed"] == len(udp_rows)
        assert metrics["ml_ready_events"] == len(udp_rows)
        assert metrics["inference_errors"] == 0
        assert pipeline_stats["total_dropped"] == 0
        assert persisted_events == len(udp_rows)
        assert persisted_vectors == len(udp_rows)

        return {
            "scenario": "live_udp_loopback_netflow_v9",
            "source_file": source_desc,
            "mode_while_running": live_mode_while_running,
            "mode_after_stop": final_status["mode"],
            "runtime_mode": readiness["runtime_mode"],
            "inference_mode": readiness["inference_mode"],
            "ready_count": readiness["ready_count"],
            "ood_gate_status": readiness["ood_gate_status"],
            "flows_sent": len(udp_rows),
            "datagrams_received": collector_stats["datagrams_received"],
            "flows_decoded": collector_stats["decoder"]["total_flows_decoded"],
            "events_processed": metrics["events_processed"],
            "ml_ready_events": metrics["ml_ready_events"],
            "anomalies_detected": anomalies,
            "alerts_raised": metrics["alerts_raised"],
            "encrypted_behavioral_vectors": encrypted_vectors,
            "persisted_unified_security_events": persisted_events,
            "persisted_behavioral_vectors": persisted_vectors,
            "dropped_events": pipeline_stats["total_dropped"],
            "inference_errors": metrics["inference_errors"],
            "elapsed_seconds": elapsed_s,
        }


def _extract_deterministic_signature(run_data: Dict[str, Any]) -> Dict[str, Any]:
    offline = run_data["offline"]
    replay = run_data["replay"]
    live_udp = run_data["live_udp"]
    return {
        "offline": {
            "runtime_mode": offline["runtime_mode"],
            "inference_mode": offline["inference_mode"],
            "ready_count": offline["ready_count"],
            "ood_gate_status": offline["ood_gate_status"],
            "events_processed": offline["events_processed"],
            "ml_ready_events": offline["ml_ready_events"],
            "anomalies_detected": offline["anomalies_detected"],
            "ood_abstained_count": offline["ood_abstained_count"],
            "per_model_anomaly_counts": offline["per_model_anomaly_counts"],
            "alerts_generated": offline["alerts_generated"],
            "encrypted_behavioral_vectors": offline["encrypted_behavioral_vectors"],
            "persisted_unified_security_events": offline["persisted_unified_security_events"],
            "persisted_behavioral_vectors": offline["persisted_behavioral_vectors"],
            "inference_errors": offline["inference_errors"],
        },
        "replay": {
            "mode": replay["mode"],
            "runtime_mode": replay["runtime_mode"],
            "inference_mode": replay["inference_mode"],
            "ready_count": replay["ready_count"],
            "ood_gate_status": replay["ood_gate_status"],
            "total_events_processed": replay["total_events_processed"],
            "anomalies_detected": replay["anomalies_detected"],
            "alerts_raised": replay["alerts_raised"],
            "adaptive_rotations_triggered": replay["adaptive_rotations_triggered"],
            "encrypted_behavioral_vectors": replay["encrypted_behavioral_vectors"],
            "persisted_unified_security_events": replay["persisted_unified_security_events"],
            "persisted_behavioral_vectors": replay["persisted_behavioral_vectors"],
            "dropped_events": replay["dropped_events"],
            "inference_errors": replay["inference_errors"],
        },
        "live_udp": {
            "mode_while_running": live_udp["mode_while_running"],
            "mode_after_stop": live_udp["mode_after_stop"],
            "runtime_mode": live_udp["runtime_mode"],
            "inference_mode": live_udp["inference_mode"],
            "ready_count": live_udp["ready_count"],
            "ood_gate_status": live_udp["ood_gate_status"],
            "flows_sent": live_udp["flows_sent"],
            "flows_decoded": live_udp["flows_decoded"],
            "events_processed": live_udp["events_processed"],
            "ml_ready_events": live_udp["ml_ready_events"],
            "anomalies_detected": live_udp["anomalies_detected"],
            "alerts_raised": live_udp["alerts_raised"],
            "encrypted_behavioral_vectors": live_udp["encrypted_behavioral_vectors"],
            "persisted_unified_security_events": live_udp["persisted_unified_security_events"],
            "persisted_behavioral_vectors": live_udp["persisted_behavioral_vectors"],
            "dropped_events": live_udp["dropped_events"],
            "inference_errors": live_udp["inference_errors"],
        },
    }


def run_clean_state_2x_verification(
    *,
    output_path: Optional[Path] = OUT_JSON,
) -> Dict[str, Any]:
    replay_rows, replay_src = _load_replay_65_rows()
    udp_rows = replay_rows[:24]

    runs: List[Dict[str, Any]] = []
    for run_idx in (1, 2):
        t_run = time.perf_counter()
        offline_res = _run_offline_scenario(run_idx)
        replay_res = _run_replay_scenario(run_idx, replay_rows, replay_src)
        live_udp_res = _run_live_udp_scenario(run_idx, udp_rows, replay_src)
        runs.append(
            {
                "run_index": run_idx,
                "clean_state_isolated_tempdir": True,
                "total_run_elapsed_seconds": round(time.perf_counter() - t_run, 4),
                "offline": offline_res,
                "replay": replay_res,
                "live_udp": live_udp_res,
            }
        )

    sig1 = _extract_deterministic_signature(runs[0])
    sig2 = _extract_deterministic_signature(runs[1])

    offline_match = sig1["offline"] == sig2["offline"]
    replay_match = sig1["replay"] == sig2["replay"]
    live_udp_match = sig1["live_udp"] == sig2["live_udp"]
    repeatable_100pct = bool(offline_match and replay_match and live_udp_match)

    if not repeatable_100pct:
        raise AssertionError(
            f"Clean-state 2x repeatability mismatch: "
            f"offline={offline_match}, replay={replay_match}, live_udp={live_udp_match}"
        )

    report: Dict[str, Any] = {
        "verification_title": (
            "Issue #150 AC1 — Clean-State 2x Repeatability Verification "
            "(Offline, Replay, Live UDP Loopback)"
        ),
        "issue_ref": "#150",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "runtime_policy": {
            "runtime_mode": "deployment",
            "require_ood_gate": True,
            "expected_ood_gate_sha256": TRUSTED_OOD_GATE_SHA256,
            "inference_mode": "REAL_MODELS",
            "ready_count": 4,
            "ood_gate_status": "FITTED",
        },
        "live_udp_scope_note": (
            "Loopback Live UDP verification encodes pre-computed 18 canonical features "
            "using lab-only enterprise Information Elements (PEN 50000..50017) into "
            "Python UDPFlowCollector on localhost (127.0.0.1); it does not represent "
            "a physical router or hardware switch."
        ),
        "repeatability_verdict": {
            "runs_executed": 2,
            "offline_match": offline_match,
            "replay_match": replay_match,
            "live_udp_match": live_udp_match,
            "repeatable_100pct": repeatable_100pct,
            "status": "PASS" if repeatable_100pct else "FAIL",
        },
        "deterministic_signature": sig1,
        "runs": runs,
    }

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    return report


def main() -> int:
    report = run_clean_state_2x_verification(output_path=OUT_JSON)
    verdict = report["repeatability_verdict"]
    print(
        f"[PASS] Clean-State 2x Repeatability Verification: "
        f"repeatable_100pct={verdict['repeatable_100pct']} "
        f"(offline_match={verdict['offline_match']}, "
        f"replay_match={verdict['replay_match']}, "
        f"live_udp_match={verdict['live_udp_match']}) -> {OUT_JSON}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
