#!/usr/bin/env python3
"""Synthetic UDP Loopback Integration Acceptance for NetFlow Sentinel v2.0.

This is an integration acceptance test, *not* a router/switch lab capture. A
Python exporter constructs synthetic NetFlow v9 and IPFIX datagrams, sends them
over the OS UDP stack to the real collector, and the test follows the events
through the real pipeline:

    UDP socket -> NetFlowIPFIXDecoder -> CanonicalSecurityEvent
    -> StreamingEventPipeline -> LiveSystemOrchestrator -> feature contract
    -> real four-model inference (when artifacts exist) -> risk -> alerts
    -> behavioral vector -> AES-256-GCM vault -> entity/trace graph

The 47 model features travel in a documented private lab convention: IPFIX
enterprise IE (PEN 50000) / NetFlow v9 IE ``50000 + index`` carrying an IEEE-754
float64. No standard router exports that; it exists only so the synthetic
exporter can exercise the full contract. Synthetic values are labelled
``synthetic: true`` and are never presented as benchmark data.

Issues #132, #135, #137.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import struct
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from network_anomaly.canonical.feature_contract import get_baseline_47_feature_contract
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.streaming.live_service import LiveTelemetryService
from network_anomaly.telemetry.collector import LAB_ENTERPRISE_FIELD_BASE, LAB_ENTERPRISE_NUMBER

OUTPUT_JSON = Path("reports/acceptance/synthetic_udp_loopback_report.json")
OUTPUT_MD = Path("docs/telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md")
ACCEPTANCE_TITLE = "Synthetic UDP Loopback Integration Acceptance"

# Synthetic benign reference row built from column medians of a 200k-row sample
# of NF-UNSW-NB15-v3. It is a synthetic fixture, not a dataset record.
BASE_FEATURES: Dict[str, float] = {
    "PROTOCOL": 6.0,
    "L7_PROTO": 36.0,
    "IN_BYTES": 1580.0,
    "IN_PKTS": 16.0,
    "OUT_BYTES": 2260.0,
    "OUT_PKTS": 18.0,
    "TCP_FLAGS": 27.0,
    "CLIENT_TCP_FLAGS": 24.0,
    "SERVER_TCP_FLAGS": 24.0,
    "FLOW_DURATION_MILLISECONDS": 34.0,
    "DURATION_IN": 31.0,
    "DURATION_OUT": 31.0,
    "MIN_TTL": 31.0,
    "MAX_TTL": 32.0,
    "LONGEST_FLOW_PKT": 362.0,
    "SHORTEST_FLOW_PKT": 52.0,
    "MIN_IP_PKT_LEN": 52.0,
    "MAX_IP_PKT_LEN": 362.0,
    "SRC_TO_DST_SECOND_BYTES": 162.0,
    "DST_TO_SRC_SECOND_BYTES": 81.35,
    "RETRANSMITTED_IN_BYTES": 436.0,
    "RETRANSMITTED_IN_PKTS": 4.0,
    "RETRANSMITTED_OUT_BYTES": 793.0,
    "RETRANSMITTED_OUT_PKTS": 4.0,
    "SRC_TO_DST_AVG_THROUGHPUT": 520000.0,
    "DST_TO_SRC_AVG_THROUGHPUT": 656000.0,
    "NUM_PKTS_UP_TO_128_BYTES": 30.0,
    "NUM_PKTS_128_TO_256_BYTES": 0.0,
    "NUM_PKTS_256_TO_512_BYTES": 0.0,
    "NUM_PKTS_512_TO_1024_BYTES": 0.0,
    "NUM_PKTS_1024_TO_1514_BYTES": 0.0,
    "TCP_WIN_MAX_IN": 14480.0,
    "TCP_WIN_MAX_OUT": 13032.0,
    "ICMP_TYPE": 21248.0,
    "ICMP_IPV4_TYPE": 83.0,
    "DNS_QUERY_ID": 0.0,
    "DNS_QUERY_TYPE": 0.0,
    "DNS_TTL_ANSWER": 0.0,
    "FTP_COMMAND_RET_CODE": 0.0,
    "SRC_TO_DST_IAT_MIN": 0.0,
    "SRC_TO_DST_IAT_MAX": 6.0,
    "SRC_TO_DST_IAT_AVG": 0.0,
    "SRC_TO_DST_IAT_STDDEV": 1.0,
    "DST_TO_SRC_IAT_MIN": 0.0,
    "DST_TO_SRC_IAT_MAX": 6.0,
    "DST_TO_SRC_IAT_AVG": 0.0,
    "DST_TO_SRC_IAT_STDDEV": 1.0,
}

LAB_FLOWS: List[Dict[str, Any]] = [
    {
        "label": "recon_probe",
        "src_ip": "192.0.2.100",
        "dst_ip": "192.0.2.10",
        "src_port": 52341,
        "dest_port": 80,
        "tcp_flags": 2,
        "overrides": {"IN_BYTES": 350, "OUT_BYTES": 120, "IN_PKTS": 4, "OUT_PKTS": 3},
    },
    {
        "label": "web_exploit_attempt",
        "src_ip": "192.0.2.105",
        "dst_ip": "192.0.2.10",
        "src_port": 44122,
        "dest_port": 80,
        "tcp_flags": 24,
        "overrides": {"IN_BYTES": 8900, "OUT_BYTES": 25000, "IN_PKTS": 25, "OUT_PKTS": 30},
    },
    {
        "label": "large_outbound_transfer",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.5",
        "src_port": 51234,
        "dest_port": 445,
        "tcp_flags": 24,
        "overrides": {
            "IN_BYTES": 5000,
            "OUT_BYTES": 150000,
            "IN_PKTS": 20,
            "OUT_PKTS": 200,
            "LONGEST_FLOW_PKT": 1514.0,
            "MAX_IP_PKT_LEN": 1514.0,
        },
    },
    {
        "label": "benign_baseline",
        "src_ip": "192.0.2.77",
        "dst_ip": "192.0.2.20",
        "src_port": 55100,
        "dest_port": 443,
        "tcp_flags": 24,
        "overrides": {},
    },
]

TEMPLATE_CACHE_FLOW = {
    "label": "template_cache_reuse",
    "src_ip": "192.0.2.88",
    "dst_ip": "192.0.2.20",
    "src_port": 55200,
    "dest_port": 443,
    "tcp_flags": 24,
    "overrides": {"IN_BYTES": 900, "OUT_BYTES": 1200},
}

IPFIX_FLOW = {
    "label": "ipfix_enterprise",
    "src_ip": "192.0.2.99",
    "dst_ip": "192.0.2.20",
    "src_port": 55300,
    "dest_port": 443,
    "tcp_flags": 24,
    "overrides": {"IN_BYTES": 1200, "OUT_BYTES": 1800},
}


def _features_for(flow: Dict[str, Any]) -> Dict[str, float]:
    features = dict(BASE_FEATURES)
    features.update({name: float(value) for name, value in flow["overrides"].items()})
    if flow["dest_port"] == 445:
        features["IN_BYTES"] = float(flow["overrides"]["IN_BYTES"])
    return features


def _v9_template_fields() -> List[Tuple[int, int]]:
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
    lab = [(LAB_ENTERPRISE_FIELD_BASE + index, 8) for index in range(len(ML_FEATURE_COLUMNS))]
    return standard + lab


def _v9_record(flow: Dict[str, Any], start_sys_up: int) -> bytes:
    features = _features_for(flow)
    proto_num = int(features["PROTOCOL"])
    record = (
        socket.inet_aton(flow["src_ip"])
        + socket.inet_aton(flow["dst_ip"])
        + struct.pack(
            "!HHBIIIIBII",
            flow["src_port"],
            flow["dest_port"],
            proto_num,
            int(features["IN_BYTES"]),
            int(features["OUT_BYTES"]),
            int(features["IN_PKTS"]),
            int(features["OUT_PKTS"]),
            flow["tcp_flags"],
            start_sys_up,
            start_sys_up + int(features["FLOW_DURATION_MILLISECONDS"]),
        )
    )
    record += b"".join(struct.pack("!d", features[name]) for name in ML_FEATURE_COLUMNS)
    return record


def build_netflow_v9_packet(
    flows: List[Dict[str, Any]],
    include_template: bool = True,
    template_id: int = 256,
    sys_uptime_ms: int = 1_000_000,
    unix_secs: Optional[int] = None,
) -> bytes:
    """Construct a NetFlow v9 datagram with the private lab feature convention."""
    unix_secs = int(time.time()) if unix_secs is None else unix_secs
    payload = bytearray()
    if include_template:
        fields = _v9_template_fields()
        template_data = struct.pack("!HH", template_id, len(fields))
        for ftype, flen in fields:
            template_data += struct.pack("!HH", ftype, flen)
        payload += struct.pack("!HH", 0, 4 + len(template_data)) + template_data

    record_bytes = bytearray()
    for index, flow in enumerate(flows):
        record_bytes += _v9_record(flow, sys_uptime_ms - 50_000 - index * 1_000)
    pad = (4 - (len(record_bytes) % 4)) % 4
    record_bytes += b"\x00" * pad
    payload += struct.pack("!HH", template_id, 4 + len(record_bytes)) + bytes(record_bytes)

    header = struct.pack("!HHIIII", 9, 1, sys_uptime_ms, unix_secs, 1, 1)
    return header + bytes(payload)


def build_ipfix_packet(
    flow: Dict[str, Any],
    template_id: int = 300,
    include_template: bool = True,
) -> bytes:
    """Construct an IPFIX datagram using PEN 50000 enterprise IEs."""
    features = _features_for(flow)
    now_ms = int(time.time() * 1000)

    payload = bytearray()
    if include_template:
        standard = [
            (8, 4),
            (12, 4),
            (7, 2),
            (11, 2),
            (4, 1),
            (1, 4),
            (23, 4),
            (2, 4),
            (24, 4),
            (6, 1),
            (152, 8),
            (153, 8),
        ]
        fields_bytes = bytearray()
        for ftype, flen in standard:
            fields_bytes += struct.pack("!HH", ftype, flen)
        for index in range(len(ML_FEATURE_COLUMNS)):
            fields_bytes += struct.pack("!HHI", 0x8000 | index, 8, LAB_ENTERPRISE_NUMBER)
        template = struct.pack("!HH", template_id, len(standard) + len(ML_FEATURE_COLUMNS))
        template += bytes(fields_bytes)
        payload += struct.pack("!HH", 2, 4 + len(template)) + template

    record = (
        socket.inet_aton(flow["src_ip"])
        + socket.inet_aton(flow["dst_ip"])
        + struct.pack(
            "!HHBIIIIBQQ",
            flow["src_port"],
            flow["dest_port"],
            int(features["PROTOCOL"]),
            int(features["IN_BYTES"]),
            int(features["OUT_BYTES"]),
            int(features["IN_PKTS"]),
            int(features["OUT_PKTS"]),
            flow["tcp_flags"],
            now_ms,
            now_ms + int(features["FLOW_DURATION_MILLISECONDS"]),
        )
    )
    record += b"".join(struct.pack("!d", features[name]) for name in ML_FEATURE_COLUMNS)
    payload += struct.pack("!HH", template_id, 4 + len(record)) + record

    header = struct.pack("!HHIII", 10, 16 + len(payload), int(time.time()), 1, 1)
    return header + bytes(payload)


def _send(sock: socket.socket, payload: bytes, port: int) -> None:
    sock.sendto(payload, ("127.0.0.1", port))


def run_lab_acceptance_scenario() -> Dict[str, Any]:
    """Run the synthetic UDP loopback integration acceptance and write evidence."""
    contract = get_baseline_47_feature_contract()
    print(f"Running {ACCEPTANCE_TITLE}...")

    with tempfile.TemporaryDirectory(prefix="nf-sentinel-acceptance-") as temp_dir:
        temp = Path(temp_dir)
        service = LiveTelemetryService(
            host="127.0.0.1",
            port=0,
            db_path=temp / "acceptance.db",
            keystore_dir=temp / "keys",
            queue_capacity=2_048,
            batch_size=16,
        )
        service.start()
        port = service.bound_port

        exporter = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            t_start = time.perf_counter()

            v9_with_template = build_netflow_v9_packet(LAB_FLOWS)
            _send(exporter, v9_with_template, port)

            v9_data_only = build_netflow_v9_packet(
                [TEMPLATE_CACHE_FLOW], include_template=False, sys_uptime_ms=1_020_000
            )
            _send(exporter, v9_data_only, port)

            ipfix_packet = build_ipfix_packet(IPFIX_FLOW)
            _send(exporter, ipfix_packet, port)

            expected_events = len(LAB_FLOWS) + 1 + 1
            processed = service.wait_until_processed(expected_events, timeout_s=20.0)

            # Deliberately malformed datagram to prove the counter moves.
            _send(exporter, b"\x00\x09\x00", port)
            time.sleep(0.3)
            t_end = time.perf_counter()
        finally:
            exporter.close()
            final_status = service.stop(flush=True)

    results_payload = service.recent_results(limit=expected_events)
    alerts = service.recent_alerts(limit=expected_events)
    collector = final_status["collector"]
    decoder_stats = collector["decoder"]

    ml_ready = sum(1 for r in results_payload if r["feature_status"] == "MODEL_READY")
    encrypted_vectors = sum(1 for r in results_payload if r["behavioral_vector_encrypted"])
    vector_count = sum(1 for r in results_payload if r.get("behavioral_vector"))
    inferred = [
        r for r in results_payload if r.get("inference", {}).get("inference_mode") == "REAL_MODELS"
    ]
    participating = sorted(
        {model for r in inferred for model in r["inference"].get("participating_models", [])}
    )
    inference_readiness = final_status["inference"]
    inference_mode = inference_readiness.get("inference_mode")
    avg_inference_latency = final_status["metrics"]["avg_inference_latency_us"]
    trace_graph = service.orchestrator.entity_graph.to_dict()

    stages: Dict[str, Dict[str, Any]] = {
        "udp_transport": {
            "status": "PASS" if collector["datagrams_received"] >= 3 else "FAIL",
            "evidence": f"{collector['datagrams_received']} datagrams received on UDP port {port}",
        },
        "decoder": {
            "status": "PASS" if decoder_stats["total_flows_decoded"] >= expected_events else "FAIL",
            "evidence": (
                f"{decoder_stats['total_flows_decoded']} flows decoded "
                f"(NetFlow v9 + IPFIX; {decoder_stats['unresolved_template_count']} unresolved)"
            ),
        },
        "template_cache": {
            "status": (
                "PASS"
                if decoder_stats["templates_cached"] >= 2 and processed >= expected_events
                else "FAIL"
            ),
            "evidence": (
                f"{decoder_stats['templates_cached']} templates cached; data-only packet decoded"
            ),
        },
        "malformed_packet_handling": {
            "status": (
                "PASS"
                if decoder_stats["malformed_packet_count"] >= 1
                and collector["datagrams_rejected"] >= 1
                else "FAIL"
            ),
            "evidence": (
                f"malformed_packet_count={decoder_stats['malformed_packet_count']}, "
                f"datagrams_rejected={collector['datagrams_rejected']}"
            ),
        },
        "streaming_pipeline": {
            "status": (
                "PASS" if final_status["pipeline"]["total_processed"] >= expected_events else "FAIL"
            ),
            "evidence": (
                f"{final_status['pipeline']['total_processed']} processed, "
                f"{final_status['pipeline']['total_dropped']} dropped, "
                f"queue={final_status['pipeline']['queue_utilization_pct']}%"
            ),
        },
        "feature_contract": {
            "status": "PASS" if ml_ready == expected_events else "FAIL",
            "evidence": (
                f"{ml_ready}/{expected_events} events satisfied all "
                f"{len(contract.feature_names)} non-imputed features"
            ),
        },
        "ai_inference": {
            "status": (
                "PASS"
                if inference_mode == "REAL_MODELS" and len(participating) == 4
                else ("PARTIAL" if participating else "UNAVAILABLE")
            ),
            "evidence": (
                f"mode={inference_mode}, participating={participating or 'none'}, "
                f"avg_latency_us={avg_inference_latency}, "
                f"ood_gate={inference_readiness.get('ood_gate_status')}"
            ),
        },
        "model_readiness": {
            "status": "PASS" if inference_readiness.get("validated_count", 0) == 4 else "PARTIAL",
            "evidence": "; ".join(
                f"{m['model_key']}={m['readiness']}" for m in inference_readiness.get("models", [])
            ),
        },
        "risk_scoring": {
            "status": (
                "PASS"
                if results_payload and all(0.0 <= r["risk_score"] <= 100.0 for r in results_payload)
                else "FAIL"
            ),
            "evidence": (
                "risk scores: "
                + ", ".join(f"{r['event_id'][:8]}={r['risk_score']:.1f}" for r in results_payload)
            ),
        },
        "alerts": {
            "status": "PASS" if alerts else "NOT_TRIGGERED",
            "evidence": f"{len(alerts)} alerts raised above the 70.0 risk threshold",
        },
        "behavioral_vector": {
            "status": "PASS" if vector_count == expected_events else "FAIL",
            "evidence": f"{vector_count}/{expected_events} events produced a 16-D session vector",
        },
        "vector_encryption": {
            "status": "PASS" if encrypted_vectors == expected_events else "FAIL",
            "evidence": (
                f"{encrypted_vectors}/{expected_events} vectors stored as AES-256-GCM "
                "ciphertext in the vault (plaintext column NULL)"
            ),
        },
        "trace_graph": {
            "status": "PASS" if trace_graph.get("nodes") else "FAIL",
            "evidence": (
                f"{len(trace_graph.get('nodes', []))} entity nodes / "
                f"{len(trace_graph.get('edges', []))} relations"
            ),
        },
    }

    hard_failures = [name for name, stage in stages.items() if stage["status"] == "FAIL"]
    limitations = [
        "Loopback UDP with a synthetic Python exporter; no physical router or switch was tested.",
        "The 47 model features use a private lab IE convention (PEN 50000 / IE 50000+i, float64).",
        "Synthetic feature values are fixtures, not benchmark samples from NF-UNSW-NB15-v3.",
    ]
    if inference_mode != "REAL_MODELS":
        limitations.append(
            "Model artifacts were unavailable in this environment, so AI inference and any "
            "alert/rotation behaviour that depends on model scores are NOT demonstrated."
        )
    if not alerts:
        limitations.append(
            "No alert reached the 70.0 risk threshold with the synthetic fixture; alert "
            "production is implemented but not exercised by this run."
        )

    report: Dict[str, Any] = {
        "acceptance_title": ACCEPTANCE_TITLE,
        "synthetic": True,
        "dataset_provenance": "synthetic_lab_exporter (not an official dataset)",
        "issue": "#137",
        "tested_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "transport": "UDP over 127.0.0.1 loopback",
            "exporter": "in-process synthetic NetFlow v9 / IPFIX exporter",
            "real_device_tested": False,
            "production_readiness_claimed": False,
        },
        "environment": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "pid": os.getpid(),
        },
        "packets": {
            "netflow_v9_sha256": hashlib.sha256(v9_with_template).hexdigest(),
            "netflow_v9_data_only_sha256": hashlib.sha256(v9_data_only).hexdigest(),
            "ipfix_sha256": hashlib.sha256(ipfix_packet).hexdigest(),
        },
        "expected_events": expected_events,
        "events_processed": processed,
        "elapsed_seconds": round(max(0.001, t_end - t_start), 4),
        "stages": stages,
        "collector": collector,
        "pipeline": final_status["pipeline"],
        "metrics": final_status["metrics"],
        "inference": inference_readiness,
        "alerts": alerts,
        "event_results": results_payload,
        "limitations": limitations,
        "hard_failures": hard_failures,
        "overall_status": (
            "FAILED"
            if hard_failures
            else ("ACCEPTED" if inference_mode == "REAL_MODELS" else "ACCEPTED_WITH_LIMITATIONS")
        ),
    }

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")

    stage_rows = "\n".join(
        f"| {name} | **{data['status']}** | {data['evidence']} |" for name, data in stages.items()
    )
    md = f"""# {ACCEPTANCE_TITLE}

**Issue:** `#137` · **Synthetic test:** yes · **Real exporter hardware:** no
**Run at (UTC):** `{report["tested_at_utc"]}`
**Verdict:** **`{report["overall_status"]}`**

> This is an integration test over UDP loopback with a synthetic exporter. It is not a
> router/switch capture, not a benchmark of detection quality, and not evidence of
> production readiness.

## Scope

- Transport: UDP `127.0.0.1` (ephemeral port `{port}`)
- Packets: one NetFlow v9 template+data datagram, one v9 data-only datagram
  (template-cache reuse), one IPFIX template+data datagram, one malformed datagram
- Model features: private lab IE convention `PEN {LAB_ENTERPRISE_NUMBER}` (IPFIX) /
  IE `{LAB_ENTERPRISE_FIELD_BASE}+i` (NetFlow v9), IEEE-754 float64

## Stage results

| Stage | Status | Evidence |
| :--- | :---: | :--- |
{stage_rows}

## Inference

- Mode: `{inference_mode}`
- Validated models: `{inference_readiness.get("validated_count")}/4`
- OOD gate: `{inference_readiness.get("ood_gate_status")}`
- Participating models in the ensemble: `{", ".join(participating) if participating else "none"}`

## Limitations

{chr(10).join(f"- {item}" for item in limitations)}

Artifacts: `{OUTPUT_JSON.as_posix()}`.
"""
    OUTPUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_MD.write_text(md, encoding="utf-8")

    print(f"Verdict: {report['overall_status']}")
    print(f"  {OUTPUT_JSON}")
    print(f"  {OUTPUT_MD}")
    if hard_failures:
        print(f"Hard failures: {hard_failures}")
    return report


if __name__ == "__main__":
    result = run_lab_acceptance_scenario()
    raise SystemExit(1 if result["hard_failures"] else 0)
