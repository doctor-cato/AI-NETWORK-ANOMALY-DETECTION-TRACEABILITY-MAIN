#!/usr/bin/env python3
"""Research Experiment RQ3: IP-Independent Session Correlation Benchmark (Issue #104).

Separates:
1. Synthetic simulation benchmark (Strategy A IP-tuple matching vs Strategy B
   16-D Behavioral Vector Cosine matching under simulated IP rotation), computing
   pairwise precision, pairwise recall, F1, false link rate, and match accuracy.
2. Empirical dataset evaluation on AIT multi-source ground truth, reporting
   BLOCKED / NOT VERIFIED when official AIT cross-source campaign linkage labels
   are absent or unverified.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

_SCRIPTS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPTS_DIR.parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))
if str(_PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from _rq_common import collect_environment_metadata  # noqa: E402
from fetch_multi_source_dataset import _is_official_data_present  # noqa: E402

from network_anomaly.behavioral.correlation import IPSpoofingSessionCorrelator  # noqa: E402
from network_anomaly.behavioral.sessionizer import EventSessionizer  # noqa: E402
from network_anomaly.behavioral.vector import BehavioralVectorBuilder  # noqa: E402
from network_anomaly.canonical.event import (  # noqa: E402
    AuthData,
    CanonicalSecurityEvent,
    DNSData,
    EventKind,
    FlowMetrics,
    HTTPData,
    RawProvenance,
)


def _pairwise_metrics(
    all_items: List[tuple[str, str, Any]],
    strategy_fn: Any,
) -> Dict[str, Any]:
    """Compute exact pairwise precision, recall, F1, false link rate, match accuracy."""
    tp = fp = fn = tn = 0
    n = len(all_items)
    for i in range(n):
        c1, ip1, v1 = all_items[i]
        for j in range(i + 1, n):
            c2, ip2, v2 = all_items[j]
            same_entity = c1 == c2
            predicted_link = bool(strategy_fn(ip1, v1, ip2, v2))
            if same_entity and predicted_link:
                tp += 1
            elif (not same_entity) and predicted_link:
                fp += 1
            elif same_entity and (not predicted_link):
                fn += 1
            else:
                tn += 1

    total_pairs = tp + fp + fn + tn
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    false_link_rate = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    accuracy = ((tp + tn) / total_pairs) if total_pairs > 0 else 0.0
    return {
        "total_pairs": total_pairs,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "pairwise_precision": round(precision, 6),
        "pairwise_recall": round(recall, 6),
        "pairwise_f1": round(f1, 6),
        "false_link_rate": round(false_link_rate, 6),
        "match_accuracy": round(accuracy, 6),
    }


def run_rq3_experiment(
    output_dir: Optional[Path] = None,
    ait_data_dir: Path = Path("data/raw/ait"),
    md_output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    output_dir = output_dir or Path("reports/experiments/behavioral")
    output_dir.mkdir(parents=True, exist_ok=True)
    env = collect_environment_metadata()

    sessionizer = EventSessionizer()
    builder = BehavioralVectorBuilder()
    now = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)

    # Distinct multi-source behavioral profiles per campaign under rotating source IPs
    campaign_profiles = [
        {
            "kind": EventKind.FLOW,
            "duration_ms": 20.0,
            "bytes_in": 120,
            "bytes_out": 60,
            "pkts_in": 2,
            "pkts_out": 1,
            "flags": 2,
            "ports": [21, 22, 23, 80, 443, 445, 3389, 8080],
        },
        {
            "kind": EventKind.DNS,
            "duration_ms": 500.0,
            "bytes_in": 400,
            "bytes_out": 85000,
            "pkts_in": 10,
            "pkts_out": 80,
            "flags": 0,
            "ports": [53],
        },
        {
            "kind": EventKind.WEB,
            "duration_ms": 150.0,
            "bytes_in": 45000,
            "bytes_out": 900,
            "pkts_in": 40,
            "pkts_out": 8,
            "flags": 24,
            "ports": [80],
        },
        {
            "kind": EventKind.AUTH,
            "duration_ms": 900.0,
            "bytes_in": 600,
            "bytes_out": 600,
            "pkts_in": 8,
            "pkts_out": 8,
            "flags": 24,
            "ports": [22],
        },
        {
            "kind": EventKind.FLOW,
            "duration_ms": 12000.0,
            "bytes_in": 800,
            "bytes_out": 250000,
            "pkts_in": 12,
            "pkts_out": 220,
            "flags": 20,
            "ports": [445],
        },
    ]

    labeled_vectors: List[tuple[str, str, Any]] = []
    for c_idx, prof in enumerate(campaign_profiles):
        campaign_name = f"campaign_{c_idx + 1}"
        for s_idx in range(4):
            ip = f"198.51.{c_idx + 10}.{s_idx + 1}"
            ts = now + timedelta(minutes=(c_idx * 60) + (s_idx * 15))
            evs = []
            for ev_idx in range(8):
                kind = prof["kind"]
                evs.append(
                    CanonicalSecurityEvent(
                        event_timestamp=ts + timedelta(milliseconds=ev_idx * 250),
                        event_kind=kind,
                        source_id="synthetic:rq3-simulation",
                        entity_id=campaign_name,
                        source_ip=ip,
                        dest_ip="10.0.0.100",
                        dest_port=prof["ports"][ev_idx % len(prof["ports"])],
                        protocol="UDP" if kind == EventKind.DNS else "TCP",
                        flow_metrics=FlowMetrics(
                            duration_ms=prof["duration_ms"],
                            bytes_in=prof["bytes_in"] + (ev_idx * 10),
                            bytes_out=prof["bytes_out"] + (ev_idx * 20),
                            pkts_in=prof["pkts_in"],
                            pkts_out=prof["pkts_out"],
                            tcp_flags=prof["flags"],
                        ),
                        dns_data=(
                            DNSData(query_name=f"c{ev_idx}.exfil.example", query_type="TXT")
                            if kind == EventKind.DNS
                            else None
                        ),
                        http_data=(
                            HTTPData(method="POST", url="/api/upload.action", status_code=200)
                            if kind == EventKind.WEB
                            else None
                        ),
                        auth_data=(
                            AuthData(username="admin", auth_result="FAILURE", service="ssh")
                            if kind == EventKind.AUTH
                            else None
                        ),
                        raw_provenance=RawProvenance(
                            source_file="synthetic_simulation", adapter_name="rq3_sim"
                        ),
                    )
                )
            sess = sessionizer.sessionize(evs)[0]
            vec = builder.build_vector(sess)
            labeled_vectors.append((campaign_name, ip, vec))

    threshold = 0.85
    correlator = IPSpoofingSessionCorrelator(match_threshold=threshold)

    strategy_a = _pairwise_metrics(
        labeled_vectors,
        lambda ip1, _v1, ip2, _v2: ip1 == ip2,
    )
    strategy_b = _pairwise_metrics(
        labeled_vectors,
        lambda _ip1, v1, _ip2, v2: correlator.calc.cosine_similarity(v1.to_numpy(), v2.to_numpy())
        >= threshold,
    )
    strategy_b_strict = _pairwise_metrics(
        labeled_vectors,
        lambda _ip1, v1, _ip2, v2: correlator.calc.cosine_similarity(v1.to_numpy(), v2.to_numpy())
        >= 0.95,
    )

    # Strategy C: Z-score feature-standardized cosine similarity across the 16-D vector space
    # Balances low-amplitude protocol/flag/auth ratios against high-magnitude log_bytes dimensions.
    def _standardized_eval(
        items: List[tuple[str, str, Any]], *, cos_threshold: float = 0.60
    ) -> Dict[str, Any]:
        if len(items) < 2:
            return _pairwise_metrics(items, lambda *_args: False)
        mat = np.vstack([it[2].to_numpy() for it in items]).astype(np.float64)
        mu = np.mean(mat, axis=0)
        sigma = np.std(mat, axis=0)
        active = sigma > 1e-6
        z_mat = np.where(active, (mat - mu) / np.where(active, sigma, 1.0), 0.0)
        z_items = [(items[i][0], items[i][1], z_mat[i]) for i in range(len(items))]

        def _cos_z(_ip1: str, z1: np.ndarray, _ip2: str, z2: np.ndarray) -> bool:
            n1 = float(np.linalg.norm(z1))
            n2 = float(np.linalg.norm(z2))
            if n1 < 1e-9 or n2 < 1e-9:
                return False
            return float(np.dot(z1, z2) / (n1 * n2)) >= cos_threshold

        return _pairwise_metrics(z_items, _cos_z)

    strategy_c_std = _standardized_eval(labeled_vectors, cos_threshold=0.60)

    # Real-dataset empirical tactic correlation check on UWF-ZeekData24 (CC BY 4.0) if present locally
    uwf_dir = _PROJECT_ROOT / "data" / "raw" / "uwf_zeekdata24"
    uwf_empirical: Dict[str, Any] = {
        "status": "SKIPPED",
        "reason": "UWF-ZeekData24 raw CSVs absent locally.",
    }
    uwf_tactics = (
        "Benign",
        "Credential_Access",
        "Defense_Evasion",
        "Exfiltration",
        "Initial_Access",
        "Persistence",
        "Privilege_Escalation",
        "Reconnaissance",
    )
    if all((uwf_dir / f"{t}.csv").is_file() for t in uwf_tactics):
        import csv

        from network_anomaly.ingestion.adapters.uwf_zeek import parse_uwf_zeek_row

        uwf_labeled: List[tuple[str, str, Any]] = []
        for tactic in uwf_tactics:
            csv_path = uwf_dir / f"{tactic}.csv"
            evs: List[CanonicalSecurityEvent] = []
            with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
                for idx, raw in enumerate(csv.DictReader(fh)):
                    if idx >= 4000:
                        break
                    try:
                        parsed = parse_uwf_zeek_row(
                            raw, allow_zeek_unset_zero=True, subset_name=tactic
                        )
                    except Exception:
                        continue
                    if parsed["label_binary"] is None:
                        continue
                    ev_ts = datetime.fromtimestamp(
                        float(parsed["timestamp_ms"]) / 1000.0, tz=timezone.utc
                    )
                    src_ip = str(parsed["source_ip"])
                    evs.append(
                        CanonicalSecurityEvent(
                            event_timestamp=ev_ts,
                            event_kind=EventKind.FLOW,
                            source_id=f"uwf:{tactic}",
                            entity_id=f"host:{src_ip}",
                            source_ip=src_ip,
                            dest_ip=str(parsed["dest_ip"]),
                            source_port=int(parsed["source_port"]),
                            dest_port=int(parsed["dest_port"]),
                            protocol=str(parsed["raw_protocol_str"]),
                            flow_metrics=FlowMetrics(
                                duration_ms=float(parsed["duration_ms"]),
                                bytes_in=int(round(float(parsed["bytes_in"]))),
                                bytes_out=int(round(float(parsed["bytes_out"]))),
                                pkts_in=int(round(float(parsed["pkts_in"]))),
                                pkts_out=int(round(float(parsed["pkts_out"]))),
                            ),
                            raw_provenance=RawProvenance(
                                source_file=f"{tactic}.csv", adapter_name="uwf_zeek"
                            ),
                        )
                    )
            sessions = [s for s in sessionizer.sessionize(evs) if s.event_count >= 2]
            for s in sessions[:15]:
                uwf_labeled.append(
                    (
                        tactic,
                        s.entity_key,
                        builder.build_vector(s),
                    )
                )

        if len(uwf_labeled) >= 10:
            uwf_ip = _pairwise_metrics(uwf_labeled, lambda ip1, _v1, ip2, _v2: ip1 == ip2)
            uwf_raw_cos = _pairwise_metrics(
                uwf_labeled,
                lambda _ip1, v1, _ip2, v2: correlator.calc.cosine_similarity(
                    v1.to_numpy(), v2.to_numpy()
                )
                >= threshold,
            )
            uwf_std_cos = _standardized_eval(uwf_labeled, cos_threshold=0.60)
            uwf_empirical = {
                "status": "EVALUATED",
                "dataset": "UWF-ZeekData24 (CC BY 4.0, MITRE ATT&CK Tactics)",
                "sessions_evaluated": len(uwf_labeled),
                "tactics_represented": sorted({c for c, _, _ in uwf_labeled}),
                "strategy_a_ip_exact": uwf_ip,
                "strategy_b_raw_16d_cosine_0_85": uwf_raw_cos,
                "strategy_c_standardized_cosine_0_60": uwf_std_cos,
            }

    official_ait_files = _is_official_data_present(ait_data_dir)
    if official_ait_files:
        empirical_status = {
            "status": "BLOCKED",
            "reason": (
                "Official AIT files found, but cross-session campaign ground truth linkage "
                "labels are not yet mapped for automatic pairwise scoring."
            ),
            "files_detected": len(official_ait_files),
        }
    else:
        empirical_status = {
            "status": "BLOCKED",
            "reason": (
                f"Official AIT campaign-linkage ground truth absent or not verified in {ait_data_dir}; "
                "empirical real-dataset validation cannot be claimed from simulation alone."
            ),
            "files_detected": 0,
        }

    results: Dict[str, Any] = {
        "experiment_id": "EXP-RQ3-CORRELATION-01",
        "execution_mode": "SIMULATION",
        "empirical_dataset_status": empirical_status["status"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hypothesis": "H3: Behavioral Vector achieves >= 85% session correlation F1/recall independent of IP",
        "dataset_provenance": {
            "simulation_source": "synthetic_ip_rotation_benchmark (synthetic: true)",
            "official_ait_source_doi": "10.5281/zenodo.13168643",
            "official_ait_status": empirical_status,
        },
        "configuration": {
            "campaigns": len(campaign_profiles),
            "sessions_per_campaign": 4,
            "total_sessions": len(labeled_vectors),
            "cosine_match_threshold": threshold,
            "vector_dimensions": 16,
        },
        "environment": env,
        "ablation": {
            "strategy_a_ip_exact_matching": strategy_a,
            "strategy_b_behavioral_vector_cosine": strategy_b,
            "strategy_b_strict_cosine_0_95": strategy_b_strict,
            "strategy_c_standardized_behavioral_cosine_0_60": strategy_c_std,
        },
        "simulation_hypothesis_met": (
            strategy_b["pairwise_f1"] >= 0.85
            and strategy_b["pairwise_recall"] > strategy_a["pairwise_recall"]
        ),
        "simulation_standardized_hypothesis_met": (
            strategy_c_std["pairwise_f1"] >= 0.85
            and strategy_c_std["pairwise_recall"] > strategy_a["pairwise_recall"]
        ),
        "empirical_ait_evaluation": empirical_status,
        "empirical_uwf_zeek24_tactic_correlation": uwf_empirical,
        "conclusion": (
            f"SIMULATION ONLY: Strategy B achieved pairwise F1={strategy_b['pairwise_f1']:.4f} "
            f"(precision={strategy_b['pairwise_precision']:.4f}, recall={strategy_b['pairwise_recall']:.4f}, "
            f"false_link_rate={strategy_b['false_link_rate']:.4f}) vs Strategy A IP-matching "
            f"recall={strategy_a['pairwise_recall']:.4f}. Empirical validation on real AIT dataset is "
            f"{empirical_status['status']} ({empirical_status['reason']})."
        ),
        "limitations": [
            "Synthetic IP-rotation simulation tests algorithmic behavior only and MUST NOT be treated as empirical validation on real enterprise datasets.",
            empirical_status["reason"],
        ],
    }

    json_path = output_dir / "rq3_session_correlation_experiment.json"
    json_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")

    md_path = md_output_path or Path("docs/experiments/EXP5_SESSION_CORRELATION.md")
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_lines = [
        "# Experiment 5 (RQ3): IP-Independent Session Correlation Benchmark",
        "",
        f"- **Execution Mode:** `{results['execution_mode']}` (Synthetic IP-rotation simulation)",
        f"- **Empirical AIT Dataset Status:** `{empirical_status['status']}` — {empirical_status['reason']}",
        f"- **Timestamp (UTC):** `{results['timestamp']}`",
        "",
        "## Simulation Ablation: IP Exact Match vs 16-D Behavioral Vector",
        "",
        "| Strategy | Pairwise Precision | Pairwise Recall | Pairwise F1 | False Link Rate | Match Accuracy |",
        "|---|---:|---:|---:|---:|---:|",
        f"| Strategy A: IP Exact Match | {strategy_a['pairwise_precision']:.4f} | {strategy_a['pairwise_recall']:.4f} | {strategy_a['pairwise_f1']:.4f} | {strategy_a['false_link_rate']:.4f} | {strategy_a['match_accuracy']:.4f} |",
        f"| Strategy B: 16-D Behavioral Vector (cos >= {threshold}) | {strategy_b['pairwise_precision']:.4f} | {strategy_b['pairwise_recall']:.4f} | {strategy_b['pairwise_f1']:.4f} | {strategy_b['false_link_rate']:.4f} | {strategy_b['match_accuracy']:.4f} |",
        f"| Strategy B (Strict cos >= 0.95) | {strategy_b_strict['pairwise_precision']:.4f} | {strategy_b_strict['pairwise_recall']:.4f} | {strategy_b_strict['pairwise_f1']:.4f} | {strategy_b_strict['false_link_rate']:.4f} | {strategy_b_strict['match_accuracy']:.4f} |",
        f"| Strategy C: Feature-Standardized 16-D Cosine (>= 0.60) | {strategy_c_std['pairwise_precision']:.4f} | {strategy_c_std['pairwise_recall']:.4f} | {strategy_c_std['pairwise_f1']:.4f} | {strategy_c_std['false_link_rate']:.4f} | {strategy_c_std['match_accuracy']:.4f} |",
        "",
    ]
    if uwf_empirical.get("status") == "EVALUATED":
        ui = uwf_empirical["strategy_a_ip_exact"]
        ur = uwf_empirical["strategy_b_raw_16d_cosine_0_85"]
        us = uwf_empirical["strategy_c_standardized_cosine_0_60"]
        md_lines.extend(
            [
                f"## Real-Dataset Tactic Correlation (`UWF-ZeekData24`, `{uwf_empirical['sessions_evaluated']}` multi-flow sessions across `{len(uwf_empirical['tactics_represented'])}` MITRE ATT&CK Tactics)",
                "",
                "| Strategy | Pairwise Precision | Pairwise Recall | Pairwise F1 | False Link Rate | Match Accuracy |",
                "|---|---:|---:|---:|---:|---:|",
                f"| IP Exact Match | {ui['pairwise_precision']:.4f} | {ui['pairwise_recall']:.4f} | {ui['pairwise_f1']:.4f} | {ui['false_link_rate']:.4f} | {ui['match_accuracy']:.4f} |",
                f"| Raw 16-D Cosine (>= {threshold}) | {ur['pairwise_precision']:.4f} | {ur['pairwise_recall']:.4f} | {ur['pairwise_f1']:.4f} | {ur['false_link_rate']:.4f} | {ur['match_accuracy']:.4f} |",
                f"| Feature-Standardized 16-D Cosine (>= 0.60) | {us['pairwise_precision']:.4f} | {us['pairwise_recall']:.4f} | {us['pairwise_f1']:.4f} | {us['false_link_rate']:.4f} | {us['match_accuracy']:.4f} |",
                "",
            ]
        )
    md_lines.extend(
        [
            "## Limitations",
            *[f"- {lim}" for lim in results["limitations"]],
        ]
    )
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8", newline="\n")
    print(f"RQ3 simulation report written: {json_path} and {md_path}")
    return results


if __name__ == "__main__":
    run_rq3_experiment()
