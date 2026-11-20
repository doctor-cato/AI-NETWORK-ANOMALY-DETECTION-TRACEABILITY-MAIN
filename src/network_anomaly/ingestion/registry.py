"""Source Registry and versioned schema directory for NetFlow Sentinel v2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

from network_anomaly.data.v2_schema import ALL_CANONICAL_COLUMNS, ML_FEATURE_COLUMNS
from network_anomaly.ingestion.exceptions import SourceUnsupportedError


@dataclass
class SourceDefinition:
    """Registered network data source contract definition."""

    source_id: str
    name: str
    physical_format: str
    schema_version: str
    ml_supported: bool
    trace_supported: bool
    description: str
    expected_columns: Optional[List[str]] = None
    adapter_name: Optional[str] = None
    extra_metadata: Dict[str, Any] = field(default_factory=dict)


class SourceRegistry:
    """Central registry of known network data sources, schema signatures, and capabilities."""

    def __init__(self) -> None:
        self._sources: Dict[str, SourceDefinition] = {}
        self._register_default_sources()

    def _register_default_sources(self) -> None:
        # 1. Canonical v2 Flow Schema
        self.register(
            SourceDefinition(
                source_id="source:canonical-flow-v2",
                name="NetFlow Sentinel Canonical Flow v2",
                physical_format="csv",
                schema_version="2.0.0",
                ml_supported=True,
                trace_supported=True,
                description="Canonical 18-feature v2 flow contract aligned across AIT-NDS-v2, CTU-SME-11, and live telemetry.",
                expected_columns=list(ML_FEATURE_COLUMNS),
                adapter_name="CanonicalFlowV2Adapter",
            )
        )

        # 2. AIT NetFlow Data Set v2 (Tstat)
        self.register(
            SourceDefinition(
                source_id="source:ait-nds-v2",
                name="AIT NetFlow Data Set v2 (10.5281/zenodo.13168643)",
                physical_format="csv",
                schema_version="2.0.0",
                ml_supported=True,
                trace_supported=True,
                description="Primary synthetic NetFlow ML benchmark derived from AIT-LDS-v2.0 PCAPs via Tstat.",
                expected_columns=list(ALL_CANONICAL_COLUMNS),
                adapter_name="CanonicalFlowV2Adapter",
            )
        )

        # 3. CTU-SME-11 (Real Captured SME Network Traffic via Zeek)
        self.register(
            SourceDefinition(
                source_id="source:ctu-sme-11",
                name="CTU-SME-11 Real Captured Network Traffic (10.5281/zenodo.7958258)",
                physical_format="tsv/csv",
                schema_version="2.0.0",
                ml_supported=True,
                trace_supported=True,
                description="Expert-labeled real captured network traffic from 11 devices over 7 days (Zeek conn.log.labeled).",
                expected_columns=list(ML_FEATURE_COLUMNS),
                adapter_name="CanonicalFlowV2Adapter",
            )
        )

        # 3b. UWF-ZeekData24 (Supplemental Cyber Range Zeek L4-Payload Evaluation Only)
        self.register(
            SourceDefinition(
                source_id="source:uwf-zeek24",
                name="UWF-ZeekData24 Supplemental Zeek Flow Benchmark (CC BY 4.0)",
                physical_format="csv/parquet",
                schema_version="2.0.0",
                ml_supported=True,
                trace_supported=True,
                description=(
                    "MITRE ATT&CK labeled Cyber Range Zeek logs (orig_bytes/resp_bytes L4 payload); "
                    "evaluation_only=true, does not replace UGR'16 ISP traffic."
                ),
                expected_columns=[
                    "duration",
                    "orig_bytes",
                    "resp_bytes",
                    "orig_pkts",
                    "resp_pkts",
                    "proto",
                    "src_ip_zeek",
                    "dest_ip_zeek",
                    "src_port_zeek",
                    "dest_port_zeek",
                    "ts",
                ],
                adapter_name="UWFZeekAdapter",
            )
        )

        # 4. Unverified v2 Flow CSV
        self.register(
            SourceDefinition(
                source_id="source:flow-v2-unverified",
                name="Unverified Canonical Flow v2 CSV Input",
                physical_format="csv",
                schema_version="2.0.0",
                ml_supported=True,
                trace_supported=True,
                description="Canonical flow v2 CSV without verified benchmark provenance; requires explicit opt-in.",
                expected_columns=list(ML_FEATURE_COLUMNS),
                adapter_name="CanonicalFlowV2Adapter",
            )
        )

        # 5. Standard Zeek conn.log (trace-only unless adapted with full IP-byte bidirectional contract)
        self.register(
            SourceDefinition(
                source_id="source:zeek-conn",
                name="Zeek Security Connection Log (conn.log)",
                physical_format="tsv/json",
                schema_version="1.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Zeek network monitor connection logs containing 5-tuple, uid, and connection state.",
                expected_columns=[
                    "ts",
                    "uid",
                    "id.orig_h",
                    "id.orig_p",
                    "id.resp_h",
                    "id.resp_p",
                    "proto",
                    "service",
                    "duration",
                    "orig_bytes",
                    "resp_bytes",
                    "conn_state",
                ],
                adapter_name="ZeekConnAdapter",
            )
        )

        # 6. Cisco NetFlow v5
        self.register(
            SourceDefinition(
                source_id="source:netflow-v5",
                name="Cisco NetFlow v5 (Legacy Enterprise)",
                physical_format="csv/tsv",
                schema_version="5.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Traditional Cisco NetFlow v5 format with 5-tuple and single-direction volume counters.",
                expected_columns=[
                    "srcaddr",
                    "dstaddr",
                    "srcport",
                    "dstport",
                    "prot",
                    "dOctets",
                    "dPkts",
                    "tcp_flags",
                ],
                adapter_name="NetFlowV5Adapter",
            )
        )

        # 7. Enterprise NetFlow v9 / IPFIX Standard
        self.register(
            SourceDefinition(
                source_id="source:netflow-v9-ipfix",
                name="Enterprise NetFlow v9 / IPFIX",
                physical_format="csv/json",
                schema_version="9.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Standard enterprise IPFIX flow records routed to Trace/Risk when bidirectional fields are incomplete.",
                expected_columns=[
                    "sourceIPv4Address",
                    "destinationIPv4Address",
                    "sourceTransportPort",
                    "destinationTransportPort",
                    "protocolIdentifier",
                    "octetDeltaCount",
                    "packetDeltaCount",
                ],
                adapter_name="NetFlowV9Adapter",
            )
        )

        # 8. AWS VPC Flow Logs
        self.register(
            SourceDefinition(
                source_id="source:aws-vpc-flow",
                name="AWS VPC Flow Logs (Standard)",
                physical_format="tsv/space",
                schema_version="2.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Aggregated 1-10 min window AWS VPC flow records (version 2 format).",
                expected_columns=[
                    "version",
                    "account-id",
                    "interface-id",
                    "srcaddr",
                    "dstaddr",
                    "srcport",
                    "dstport",
                    "protocol",
                    "packets",
                    "bytes",
                    "start",
                    "end",
                    "action",
                    "log-status",
                ],
                adapter_name="AWSVPCFlowAdapter",
            )
        )

        # 9. Suricata EVE JSON
        self.register(
            SourceDefinition(
                source_id="source:suricata-eve",
                name="Suricata EVE Log (eve.json)",
                physical_format="jsonl",
                schema_version="1.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Suricata EVE JSON event output for flow records and alert events.",
                expected_columns=[
                    "timestamp",
                    "event_type",
                    "src_ip",
                    "src_port",
                    "dest_ip",
                    "dest_port",
                    "proto",
                ],
                adapter_name="SuricataEveAdapter",
            )
        )

        # 10. sFlow (RFC 3176) — Unsupported for ML inference
        self.register(
            SourceDefinition(
                source_id="source:sflow",
                name="sFlow Sampled Packet Stream",
                physical_format="binary",
                schema_version="5.0.0",
                ml_supported=False,
                trace_supported=False,
                description="Statistical 1-in-N sampled packet stream. Semantically incompatible with flow modeling.",
                adapter_name="UnsupportedSourceAdapter",
            )
        )

        # 11-15. Unified v2 Security Event Adapters
        self.register(
            SourceDefinition(
                source_id="v2_netflow",
                name="Unified v2 NetFlow Adapter",
                physical_format="csv/tsv",
                schema_version="2.0.0",
                ml_supported=True,
                trace_supported=True,
                description="Adapts AIT-NDS-v2 Tstat, CTU-SME-11 Zeek, and canonical v2 flow records.",
                expected_columns=list(ML_FEATURE_COLUMNS),
                adapter_name="UnifiedNetFlowAdapter",
            )
        )
        self.register(
            SourceDefinition(
                source_id="v2_dns",
                name="Application DNS Adapter (v2)",
                physical_format="jsonl/tsv",
                schema_version="2.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Adapts DNS query logs to CanonicalSecurityEvent (route-only, no ML imputation).",
                adapter_name="ApplicationDNSAdapter",
            )
        )
        self.register(
            SourceDefinition(
                source_id="v2_web",
                name="Application Web Log Adapter (v2)",
                physical_format="clf/combined",
                schema_version="2.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Adapts HTTP/Nginx access logs to CanonicalSecurityEvent with URL credential stripping.",
                adapter_name="ApplicationWebAdapter",
            )
        )
        self.register(
            SourceDefinition(
                source_id="v2_auth",
                name="Identity & Auth Log Adapter (v2)",
                physical_format="syslog",
                schema_version="2.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Adapts SSH/VPN authentication syslog lines to CanonicalSecurityEvent.",
                adapter_name="IdentityAuthAdapter",
            )
        )
        self.register(
            SourceDefinition(
                source_id="v2_audit",
                name="System Audit Adapter (v2)",
                physical_format="jsonl",
                schema_version="2.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Adapts Sysmon and auditd records to CanonicalSecurityEvent.",
                adapter_name="SystemAuditAdapter",
            )
        )

    def get_adapter_class(self, source_id: str) -> Type[Any]:
        """Resolve a registered v2 source_id or adapter_name to its adapter class."""
        from network_anomaly.ingestion.adapters.uwf_zeek import UWFZeekAdapter
        from network_anomaly.ingestion.adapters.v2_adapter import (
            ApplicationDNSAdapter,
            ApplicationWebAdapter,
            IdentityAuthAdapter,
            SystemAuditAdapter,
            UnifiedNetFlowAdapter,
        )

        adapter_map: Dict[str, Type[Any]] = {
            "v2_netflow": UnifiedNetFlowAdapter,
            "UnifiedNetFlowAdapter": UnifiedNetFlowAdapter,
            "source:ait-nds-v2": UnifiedNetFlowAdapter,
            "source:ctu-sme-11": UnifiedNetFlowAdapter,
            "source:canonical-flow-v2": UnifiedNetFlowAdapter,
            "source:uwf-zeek24": UWFZeekAdapter,
            "UWFZeekAdapter": UWFZeekAdapter,
            "v2_dns": ApplicationDNSAdapter,
            "ApplicationDNSAdapter": ApplicationDNSAdapter,
            "v2_web": ApplicationWebAdapter,
            "ApplicationWebAdapter": ApplicationWebAdapter,
            "v2_auth": IdentityAuthAdapter,
            "IdentityAuthAdapter": IdentityAuthAdapter,
            "v2_audit": SystemAuditAdapter,
            "SystemAuditAdapter": SystemAuditAdapter,
        }
        if source_id in adapter_map:
            return adapter_map[source_id]
        source_def = self.get_source(source_id)
        if source_def.adapter_name and source_def.adapter_name in adapter_map:
            return adapter_map[source_def.adapter_name]
        raise SourceUnsupportedError(f"No runtime adapter class bound for source '{source_id}'.")

    def create_adapter(self, source_id: str, **kwargs: Any) -> Any:
        """Instantiate the registered adapter class for a given source_id."""
        cls = self.get_adapter_class(source_id)
        return cls(source_id=source_id, **kwargs) if "source_id" not in kwargs else cls(**kwargs)

    def register(self, source: SourceDefinition) -> None:
        self._sources[source.source_id] = source

    def get_source(self, source_id: str) -> SourceDefinition:
        if source_id not in self._sources:
            raise SourceUnsupportedError(
                f"Source ID '{source_id}' is not registered. Registered sources: {list(self._sources.keys())}"
            )
        return self._sources[source_id]

    def list_sources(self) -> List[SourceDefinition]:
        return list(self._sources.values())

    def detect_source(self, column_names: List[str]) -> Optional[SourceDefinition]:
        col_set = set(column_names)

        if all(col in col_set for col in ML_FEATURE_COLUMNS):
            return self.get_source("source:canonical-flow-v2")

        if {"#15#c_ip:1", "durat:31"}.issubset(col_set) or {"#c_ip:1", "c_first_abs:3"}.issubset(
            col_set
        ):
            return self.get_source("source:ait-nds-v2")

        if {"src_ip_zeek", "dest_ip_zeek", "orig_bytes", "resp_bytes"}.issubset(col_set):
            return self.get_source("source:uwf-zeek24")

        if {"id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"}.issubset(col_set):
            return self.get_source("source:zeek-conn")

        if {"srcaddr", "dstaddr", "srcport", "dstport", "dOctets"}.issubset(col_set):
            return self.get_source("source:netflow-v5")

        if {"account-id", "interface-id", "action"}.issubset(col_set):
            return self.get_source("source:aws-vpc-flow")

        if {"sourceIPv4Address", "destinationIPv4Address"}.issubset(col_set):
            return self.get_source("source:netflow-v9-ipfix")

        if {"event_type", "src_ip", "dest_ip"}.issubset(col_set):
            return self.get_source("source:suricata-eve")

        return None
