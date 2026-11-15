#!/usr/bin/env python3
"""Export OpenAPI schema specification and markdown contract evidence.

Generates:
1. reports/api/openapi.json
2. reports/api/API_CONTRACT.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Tuple

_LOCAL_SOURCE = Path(__file__).resolve().parents[1] / "src"
if str(_LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SOURCE))

from network_anomaly.api.main import create_app  # noqa: E402
from network_anomaly.config import PROJECT_ROOT  # noqa: E402


def render_openapi_artifacts() -> Tuple[str, str]:
    """Generate deterministic OpenAPI JSON and Markdown API contract text."""
    app = create_app(":memory:")
    openapi_schema = app.openapi()
    json_text = json.dumps(openapi_schema, indent=2)

    paths = openapi_schema.get("paths", {})
    lines = [
        "# FastAPI Service Integration Contract",
        "",
        f"**API Title**: {openapi_schema.get('info', {}).get('title')}",
        f"**Version**: {openapi_schema.get('info', {}).get('version')}",
        f"**Total Endpoints**: {len(paths)}",
        "",
        "## Endpoints Specification",
        "",
        "| Method | Path | Summary | Tags |",
        "|---|---|---|---|",
    ]

    for path, methods in sorted(paths.items()):
        for method, details in methods.items():
            summary = details.get("summary", "")
            tags = ", ".join(details.get("tags", []))
            lines.append(f"| `{method.upper()}` | `{path}` | {summary} | {tags} |")

    lines.extend(
        [
            "",
            "## Key Deliverables & Design Rules",
            (
                "- **Zero Secret Leaks**: Key metadata endpoints only return non-sensitive "
                "fields (`key_id`, `version`, `algorithm`, `status`). Key secrets are never stored."
            ),
            (
                "- **Fail-Closed Artifact Health**: `/health` verifies preprocessor and model "
                "artifacts independently (`preprocessor_ready` vs `model_ready`) against companion "
                "manifests before declaring readiness; missing or mismatched target model artifacts "
                "report `degraded`."
            ),
            (
                "- **Strict Model Identity**: `/api/v1/analyze` enforces an explicit 4-model "
                "allowlist (`random_forest`, `xgboost`, `isolation_forest`, `autoencoder`), "
                "rejects invalid `model_name` selectors with HTTP `422` without silent fallback, "
                "and binds `model_used` to the canonical verified model family."
            ),
            (
                "- **Anomaly Score Semantics & Verified Decision Policy**: `/api/v1/analyze` "
                "preserves the verified model's binary prediction and frozen `decision_threshold`, "
                "returns unclamped `raw_anomaly_score`/`anomaly_score` (`higher_is_more_anomalous`), "
                "emits `attack_probability` and `probabilities` only for supervised probabilistic models "
                "(`null` for Isolation Forest and Autoencoder), and sets `normalized_anomaly_score` "
                "to `null` unless a valid Train/Validation calibration contract exists. "
                "Request `threshold` applies only to an explicitly enabled heuristic fallback."
            ),
            (
                "- **Key Metadata Scope**: Key and rotation endpoints record metadata and audit "
                "events only. They do not encrypt flow payloads; `algorithm` describes a planned "
                "key policy, not active AES-GCM encryption."
            ),
            (
                "- **Adaptive Response Dry-Run Scope (#27)**: `/api/v1/security/simulate-response` "
                "and `/api/v1/security/simulations/*` generate deterministic policy recommendations "
                "(`NO_ACTION`, `MONITOR`, `INVESTIGATE`, `ISOLATE_RECOMMENDED`) and simulated "
                "adaptive key-rotation readiness with `executed=false`. `ISOLATE_RECOMMENDED` and "
                "adaptive key-rotation escalation are granted ONLY when `analysis_id` is verified "
                "in the bounded in-memory CSV analysis registry (volatile across restarts; old IDs "
                "fail closed with HTTP `400`) AND the gate is `MODEL_VALIDATED` + "
                "`PREDICTION_AVAILABLE` (`client_supplied_unverified` and `RESEARCH_ONLY` inputs "
                "downgrade to `INVESTIGATE` and `HOLD_*`); `ABSTAINED_OOD` flows never receive "
                "containment recommendations; SQLite durably persists simulation history with "
                "bounded recommendations; OS firewall commands and production AES-256-GCM keyring "
                "operations remain disabled/DEFERRED."
            ),
            (
                "- **SQLite Durability**: Ingestion, incidents, timeline, and audit logs "
                "persist durably across restarts."
            ),
            (
                "- **Idempotent Ingestion & Rotation**: Supported via `X-Idempotency-Key` "
                "or `idempotency_key` payload property."
            ),
            (
                "- **Sanitized Errors**: Exception handlers prevent Python tracebacks or "
                "sensitive server details from leaking in 4xx/5xx responses."
            ),
            "",
        ]
    )
    return json_text, "\n".join(lines)


def export_openapi(check: bool = False) -> int:
    """Write or verify reports/api/openapi.json and reports/api/API_CONTRACT.md."""
    output_dir = PROJECT_ROOT / "reports" / "api"
    json_path = output_dir / "openapi.json"
    md_path = output_dir / "API_CONTRACT.md"

    json_text, md_text = render_openapi_artifacts()

    if check:
        mismatches = []
        for target_path, expected in ((json_path, json_text), (md_path, md_text)):
            if not target_path.is_file():
                mismatches.append(f"Missing generated file: {target_path}")
                continue
            actual = target_path.read_text(encoding="utf-8")
            if actual != expected:
                mismatches.append(f"Out-of-date API contract artifact: {target_path}")
        if mismatches:
            for msg in mismatches:
                sys.stderr.write(f"ERROR: {msg}\n")
            sys.stderr.write("Run `python scripts/export_openapi_spec.py` to regenerate.\n")
            return 1
        print(f"OpenAPI spec and contract verified up-to-date: {json_path}, {md_path}")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json_text)
    print(f"Exported OpenAPI JSON to: {json_path}")

    with open(md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(md_text)
    print(f"Exported API Contract Markdown to: {md_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export or verify OpenAPI specification and markdown contract evidence."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed openapi.json and API_CONTRACT.md match app schemas without overwriting.",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()
    sys.exit(export_openapi(check=args.check))
