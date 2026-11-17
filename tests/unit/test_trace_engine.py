"""Unit tests for Trace Engine, Graph, Timeline, and Investigation Report (Issues #110, #111, #112, #113)."""

from network_anomaly.trace.engine import TraceEngine
from network_anomaly.trace.graph import (
    AlertDeduplicator,
    EntityKind,
    EntityRelationshipGraph,
    RelationType,
)
from network_anomaly.trace.investigation import InvestigationReportGenerator
from network_anomaly.trace.timeline import AttackPhase, AttackTimelineReconstructor


def test_entity_graph_and_deduplication():
    graph = EntityRelationshipGraph()
    graph.add_node("198.51.100.10", EntityKind.IP, "Attacker IP")
    graph.add_node("10.0.0.5", EntityKind.IP, "Web Server")
    graph.add_node("port:443", EntityKind.PORT, "HTTPS Port")

    graph.add_edge(
        "198.51.100.10", "10.0.0.5", RelationType.CONNECTS_TO, confidence=1.0, is_observed=True
    )
    graph.add_edge(
        "10.0.0.5", "port:443", RelationType.CONNECTS_TO, confidence=1.0, is_observed=True
    )

    assert len(graph.nodes) == 3
    assert len(graph.edges) == 2

    # Deduplicator
    dedup = AlertDeduplicator(window_seconds=10.0)
    emit1, count1 = dedup.should_emit(
        "198.51.100.10", "10.0.0.5", "Exploit", current_timestamp=100.0
    )
    assert emit1 is True
    assert count1 == 1

    # Immediate second alert within 10s: suppressed
    emit2, count2 = dedup.should_emit(
        "198.51.100.10", "10.0.0.5", "Exploit", current_timestamp=105.0
    )
    assert emit2 is False
    assert count2 == 2

    # Alert after window: emitted
    emit3, count3 = dedup.should_emit(
        "198.51.100.10", "10.0.0.5", "Exploit", current_timestamp=115.0
    )
    assert emit3 is True
    assert count3 == 3


def test_trace_engine_traversal():
    graph = EntityRelationshipGraph()
    # Chain: A -> B -> C -> D
    graph.add_edge("host-A", "host-B", RelationType.CONNECTS_TO, is_observed=True)
    graph.add_edge("host-B", "host-C", RelationType.CONNECTS_TO, is_observed=True)
    graph.add_edge(
        "host-C", "host-D", RelationType.SIMILAR_BEHAVIOR, is_observed=False, confidence=0.88
    )

    engine = TraceEngine(graph, max_depth=3)
    trace_res = engine.trace("host-A")

    assert len(trace_res.nodes_visited) == 4
    assert len(trace_res.edges_traversed) == 3
    assert len(trace_res.observed_edges) == 2
    assert len(trace_res.inferred_edges) == 1
    assert trace_res.inferred_edges[0].relation_type == RelationType.SIMILAR_BEHAVIOR


def test_attack_timeline_reconstruction():
    reconstructor = AttackTimelineReconstructor()
    events = [
        {
            "timestamp": "2026-11-17T10:00:00Z",
            "source_ip": "198.51.100.1",
            "dest_ip": "10.0.0.5",
            "attack_type": "Reconnaissance",
            "dest_port": 80,
            "bytes_out": 200,
        },
        {
            "timestamp": "2026-11-17T10:15:00Z",
            "source_ip": "198.51.100.1",
            "dest_ip": "10.0.0.5",
            "attack_type": "Exploits",
            "dest_port": 80,
            "risk_score": 90.0,
        },
        {
            "timestamp": "2026-11-17T10:30:00Z",
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.8",
            "attack_type": "Lateral Movement",
            "dest_port": 445,
        },
        {
            "timestamp": "2026-11-17T10:45:00Z",
            "source_ip": "10.0.0.8",
            "dest_ip": "203.0.113.5",
            "attack_type": "Exfiltration",
            "dest_port": 8443,
            "bytes_out": 1500000,
        },
    ]

    timeline = reconstructor.reconstruct_timeline("APT-Campaign-Omega", events)
    assert timeline.stage_count == 4
    assert timeline.stages[0].phase == AttackPhase.RECONNAISSANCE
    assert timeline.stages[1].phase == AttackPhase.INITIAL_ACCESS
    assert timeline.stages[2].phase == AttackPhase.LATERAL_MOVEMENT
    assert timeline.stages[3].phase == AttackPhase.EXFILTRATION_IMPACT
    assert "198.51.100.1" in timeline.entities_involved
    assert "10.0.0.8" in timeline.entities_involved


def test_investigation_report_generation():
    reconstructor = AttackTimelineReconstructor()
    timeline = reconstructor.reconstruct_timeline(
        "Demo-Campaign",
        [
            {
                "timestamp": "2026-11-17T10:00:00Z",
                "source_ip": "192.168.1.5",
                "dest_ip": "10.0.0.1",
                "attack_type": "Exploits",
                "dest_port": 80,
            }
        ],
    )

    gen = InvestigationReportGenerator()
    report = gen.generate_report(
        incident_id="INC-2026-001",
        title="Web Server Exploit Incident",
        severity="HIGH",
        root_cause_summary="SQL injection attempt exploited unauthenticated endpoint.",
        timeline=timeline,
        evidence_records=[
            {
                "evidence_id": "ev-01",
                "source_file": "flows.csv",
                "line": 42,
                "sha256": "abcdef123456",
            }
        ],
    )

    assert report.incident_id == "INC-2026-001"
    assert report.artifact_hash != ""
    md = report.to_markdown()
    assert "# Incident Investigation Report" in md
    assert "SQL injection attempt" in md
    assert "ev-01" in md
