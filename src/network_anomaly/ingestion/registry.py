"""Source Registry and versioned schema directory for network ingestion (Issue #46)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from network_anomaly.data.nf_unsw_nb15_v3 import ALL_COLUMNS, ML_FEATURE_COLUMNS
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
        # 1. NF-UNSW-NB15-v3 (Canonical Lab Baseline)
        self.register(
            SourceDefinition(
                source_id="source:nf-v3-canonical",
                name="NF-UNSW-NB15-v3 Canonical Flow",
                physical_format="csv",
                schema_version="1.0.0",
                ml_supported=True,
                trace_supported=True,
                description="Canonical NetFlow v3 nProbe CSV dataset from UNSW-NB15 lab traffic.",
                expected_columns=list(ALL_COLUMNS),
                adapter_name="NetFlowV3Adapter",
            )
        )

        # 2. NF-CSE-CIC-IDS2018-v3 / NF-ToN-IoT-v3 (External Benchmark)
        self.register(
            SourceDefinition(
                source_id="source:nf-v3-external",
                name="NetFlow v3 External Benchmark (CIC-IDS2018 / ToN-IoT)",
                physical_format="csv",
                schema_version="1.0.0",
                ml_supported=True,
                trace_supported=True,
                description="Standard NetFlow v3 55-column format extracted via nProbe v3 on external networks.",
                expected_columns=list(ALL_COLUMNS),
                adapter_name="NetFlowV3Adapter",
            )
        )

        # 3. Zeek conn.log
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

        # 4. Cisco NetFlow v5
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

        # 5. Enterprise NetFlow v9 / IPFIX Standard
        self.register(
            SourceDefinition(
                source_id="source:netflow-v9-ipfix",
                name="Enterprise NetFlow v9 / IPFIX",
                physical_format="csv/json",
                schema_version="9.0.0",
                ml_supported=False,
                trace_supported=True,
                description="Standard enterprise IPFIX flow records without micro-packet IAT histograms.",
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

        # 6. AWS VPC Flow Logs
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

        # 7. Suricata EVE JSON
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

        # 8. sFlow (RFC 3176) — Declared UNSUPPORTED for ML inference
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

    def register(self, source: SourceDefinition) -> None:
        """Register a new source definition."""
        self._sources[source.source_id] = source

    def get_source(self, source_id: str) -> SourceDefinition:
        """Retrieve registered source by ID or raise SourceUnsupportedError."""
        if source_id not in self._sources:
            raise SourceUnsupportedError(
                f"Source ID '{source_id}' is not registered. Registered sources: {list(self._sources.keys())}"
            )
        return self._sources[source_id]

    def list_sources(self) -> List[SourceDefinition]:
        """Return all registered source definitions."""
        return list(self._sources.values())

    def detect_source(self, column_names: List[str]) -> Optional[SourceDefinition]:
        """Infer source definition based on column name signatures."""
        col_set = set(column_names)

        # Check NetFlow v3 signature (all 47 ML features present)
        if all(col in col_set for col in ML_FEATURE_COLUMNS):
            return self.get_source("source:nf-v3-external")

        # Check Zeek conn.log signature
        zeek_cols = {"id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"}
        if zeek_cols.issubset(col_set):
            return self.get_source("source:zeek-conn")

        # Check NetFlow v5 signature
        v5_cols = {"srcaddr", "dstaddr", "srcport", "dstport", "dOctets"}
        if v5_cols.issubset(col_set):
            return self.get_source("source:netflow-v5")

        # Check AWS VPC Flow signature
        aws_cols = {"account-id", "interface-id", "action"}
        if aws_cols.issubset(col_set):
            return self.get_source("source:aws-vpc-flow")

        # Check IPFIX signature
        ipfix_cols = {"sourceIPv4Address", "destinationIPv4Address"}
        if ipfix_cols.issubset(col_set):
            return self.get_source("source:netflow-v9-ipfix")

        # Check Suricata signature
        suricata_cols = {"event_type", "src_ip", "dest_ip"}
        if suricata_cols.issubset(col_set):
            return self.get_source("source:suricata-eve")

        return None
