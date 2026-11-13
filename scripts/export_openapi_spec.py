#!/usr/bin/env python3
"""Export OpenAPI schema specification and markdown contract evidence.

Generates:
1. reports/api/openapi.json
2. reports/api/API_CONTRACT.md
"""

from __future__ import annotations

import json

from network_anomaly.api.main import create_app
from network_anomaly.config import PROJECT_ROOT


def export_openapi() -> None:
    app = create_app(":memory:")
    openapi_schema = app.openapi()

    output_dir = PROJECT_ROOT / "reports" / "api"
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "openapi.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(openapi_schema, f, indent=2)
    print(f"Exported OpenAPI JSON to: {json_path}")

    # Generate Markdown contract summary
    md_path = output_dir / "API_CONTRACT.md"
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
                "- **Fail-Closed Artifact Health**: `/health` verifies model and preprocessor "
                "artifacts against companion manifests before declaring `model_ready: true`; "
                "missing or mismatched artifacts report `degraded`."
            ),
            (
                "- **Key Metadata Scope**: Key and rotation endpoints record metadata and audit "
                "events only. They do not encrypt flow payloads; `algorithm` describes a planned "
                "key policy, not active AES-GCM encryption."
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

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Exported API Contract Markdown to: {md_path}")


if __name__ == "__main__":
    export_openapi()
