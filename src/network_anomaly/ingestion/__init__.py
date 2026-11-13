"""Multi-source network ingestion, compatibility evaluation, and OOD gate package (Issue #46)."""

from network_anomaly.ingestion.adapters import (
    AWSVPCFlowAdapter,
    BaseSourceAdapter,
    NetFlowV3Adapter,
    NetFlowV5Adapter,
    SuricataEveAdapter,
    UnsupportedSourceAdapter,
    ZeekConnAdapter,
)
from network_anomaly.ingestion.compatibility import (
    CompatibilityEvaluationReport,
    FeatureCompatibilityEvaluator,
)
from network_anomaly.ingestion.contracts import (
    APIIngestResponse,
    DashboardViewModel,
    RiskEngineContract,
    TraceEngineContract,
    create_api_response,
    create_dashboard_view_model,
    route_to_risk_engine,
    route_to_trace_engine,
)
from network_anomaly.ingestion.deployment import (
    DeploymentReadinessReport,
    check_deployment_readiness,
)
from network_anomaly.ingestion.exceptions import (
    AbstentionError,
    FeatureIncompatibleError,
    FormatInvalidError,
    IngestionError,
    OODWarningException,
    SchemaValidationError,
    SemanticMismatchError,
    SourceUnsupportedError,
)
from network_anomaly.ingestion.gate import GateDecision, InferenceEligibilityGate
from network_anomaly.ingestion.ood import OODReport, OODValidator
from network_anomaly.ingestion.parser import FormatSniffer, StreamingChunkParser
from network_anomaly.ingestion.registry import SourceDefinition, SourceRegistry
from network_anomaly.ingestion.schemas import (
    ApplicationContext,
    CanonicalNetworkEvent,
    EventMetadata,
    ExtendedTelemetry,
    FeatureMappingStatus,
    FlowMetrics,
    InferenceEligibility,
    Network5Tuple,
    ValidationStatus,
)

__all__ = [
    # Schemas & Statuses
    "ValidationStatus",
    "InferenceEligibility",
    "FeatureMappingStatus",
    "EventMetadata",
    "Network5Tuple",
    "FlowMetrics",
    "ExtendedTelemetry",
    "ApplicationContext",
    "CanonicalNetworkEvent",
    # Registry
    "SourceDefinition",
    "SourceRegistry",
    # Adapters
    "BaseSourceAdapter",
    "NetFlowV3Adapter",
    "ZeekConnAdapter",
    "NetFlowV5Adapter",
    "AWSVPCFlowAdapter",
    "SuricataEveAdapter",
    "UnsupportedSourceAdapter",
    # Parser & Sniffer
    "FormatSniffer",
    "StreamingChunkParser",
    # Compatibility & OOD
    "FeatureCompatibilityEvaluator",
    "CompatibilityEvaluationReport",
    "InferenceEligibilityGate",
    "GateDecision",
    "OODValidator",
    "OODReport",
    # M6 Contracts
    "APIIngestResponse",
    "DashboardViewModel",
    "TraceEngineContract",
    "RiskEngineContract",
    "create_api_response",
    "create_dashboard_view_model",
    "route_to_trace_engine",
    "route_to_risk_engine",
    # Deployment
    "check_deployment_readiness",
    "DeploymentReadinessReport",
    # Exceptions
    "IngestionError",
    "SourceUnsupportedError",
    "FormatInvalidError",
    "SchemaValidationError",
    "FeatureIncompatibleError",
    "SemanticMismatchError",
    "AbstentionError",
    "OODWarningException",
]
