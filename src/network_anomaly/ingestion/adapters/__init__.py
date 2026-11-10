"""Adapters for translating heterogeneous network records into CanonicalNetworkEvents."""

from network_anomaly.ingestion.adapters.aws_vpc import AWSVPCFlowAdapter
from network_anomaly.ingestion.adapters.base import BaseSourceAdapter
from network_anomaly.ingestion.adapters.netflow_v3 import NetFlowV3Adapter
from network_anomaly.ingestion.adapters.netflow_v5 import NetFlowV5Adapter
from network_anomaly.ingestion.adapters.suricata import SuricataEveAdapter
from network_anomaly.ingestion.adapters.unsupported import UnsupportedSourceAdapter
from network_anomaly.ingestion.adapters.zeek import ZeekConnAdapter

__all__ = [
    "BaseSourceAdapter",
    "NetFlowV3Adapter",
    "ZeekConnAdapter",
    "NetFlowV5Adapter",
    "AWSVPCFlowAdapter",
    "SuricataEveAdapter",
    "UnsupportedSourceAdapter",
]
