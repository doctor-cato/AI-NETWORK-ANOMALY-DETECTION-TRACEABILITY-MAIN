#!/usr/bin/env python3
"""Run FastAPI application server for local testing and reproduction."""

from __future__ import annotations

import argparse
import multiprocessing
import os
import sys
from pathlib import Path

import uvicorn

_FROZEN = bool(getattr(sys, "frozen", False))
if _FROZEN:
    _REPO_ROOT = Path(sys.executable).resolve().parent
    _SRC_DIR = _REPO_ROOT / "src"
else:
    _REPO_ROOT = Path(__file__).resolve().parent.parent
    _SRC_DIR = _REPO_ROOT / "src"
    if str(_SRC_DIR) not in sys.path:
        sys.path.insert(0, str(_SRC_DIR))


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    return normalized in {"127.0.0.1", "localhost", "::1"}


def main() -> None:
    multiprocessing.freeze_support()
    parser = argparse.ArgumentParser(description="Run Network Anomaly Detection FastAPI Service")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)"
    )
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable live code reload")
    parser.add_argument(
        "--db-path", default=None, help="Custom SQLite DB path (default: data/network_anomaly.db)"
    )
    parser.add_argument(
        "--allow-non-local",
        action="store_true",
        help="Explicitly allow binding a non-loopback host (disabled by default for #26)",
    )
    parser.add_argument(
        "--runtime-mode",
        choices=("deployment", "research"),
        default=None,
        help=(
            "Explicit OOD runtime policy ('deployment' or 'research'). "
            "Defaults fail-closed to NETFLOW_RUNTIME_MODE or 'deployment'."
        ),
    )
    parser.add_argument(
        "--require-ood-gate",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Explicitly require a verified persisted OOD gate (cannot be disabled in deployment).",
    )
    parser.add_argument(
        "--ood-gate-sha256",
        default=None,
        help="Trusted expected 64-hex SHA-256 digest for persisted artifacts/ml/ood_reference_gate.json.",
    )
    args = parser.parse_args()

    if not args.allow_non_local and not _is_loopback_host(args.host):
        parser.error(
            f"Refusing non-loopback host {args.host!r} without --allow-non-local (#26 local-only security)"
        )
    if args.allow_non_local and not _is_loopback_host(args.host):
        print(
            "[SECURITY WARNING] --allow-non-local enabled: binding FastAPI on non-loopback "
            f"host {args.host!r} WITHOUT built-in authentication or TLS. Exposed CSV endpoints "
            "can read/write permitted local .csv paths; restrict network access with a firewall "
            "or authenticated reverse proxy, and consider NETWORK_ANOMALY_ALLOWED_CSV_ROOTS.",
            file=sys.stderr,
        )

    if not _FROZEN:
        existing_pypath = os.environ.get("PYTHONPATH", "")
        if str(_SRC_DIR) not in existing_pypath.split(os.pathsep):
            os.environ["PYTHONPATH"] = (
                f"{_SRC_DIR}{os.pathsep}{existing_pypath}" if existing_pypath else str(_SRC_DIR)
            )

    if args.db_path is not None:
        os.environ["NETWORK_ANOMALY_DB_PATH"] = args.db_path

    from network_anomaly.ml.ood_gate import resolve_expected_ood_gate_sha256
    from network_anomaly.streaming.realtime_inference import resolve_runtime_policy

    try:
        effective_mode, effective_require_ood, policy_source = resolve_runtime_policy(
            args.runtime_mode, args.require_ood_gate
        )
    except ValueError as exc:
        parser.error(str(exc))

    explicit_sha: str | None = args.ood_gate_sha256

    try:
        resolved_sha, sha_source = resolve_expected_ood_gate_sha256(explicit_sha)
        trust_summary = sha_source or (
            "missing_trusted_expected_sha256" if effective_require_ood else "none"
        )
    except ValueError as exc:
        resolved_sha = None
        trust_summary = f"invalid_expected_sha256 ({exc})"

    print(f"Starting Network Anomaly FastAPI Service on http://{args.host}:{args.port}")
    print(f"OpenAPI documentation available at http://{args.host}:{args.port}/docs")
    print(
        f"Runtime policy: mode={effective_mode} ({policy_source}), "
        f"require_ood_gate={effective_require_ood}, "
        f"ood_trust_anchor={trust_summary}, sha_configured={bool(resolved_sha)}"
    )
    if not os.environ.get("NETWORK_ANOMALY_API_TOKEN", "").strip():
        print(
            "[SECURITY WARNING] NETWORK_ANOMALY_API_TOKEN is unset; "
            "API endpoints are unauthenticated (loopback dev mode only)."
        )

    if args.reload:
        if _FROZEN:
            parser.error("--reload is not supported in frozen standalone backend mode.")
        os.environ["NETFLOW_RUNTIME_MODE"] = effective_mode
        os.environ["NETFLOW_REQUIRE_OOD_GATE"] = "1" if effective_require_ood else "0"
        if explicit_sha is not None:
            os.environ["NETFLOW_OOD_GATE_SHA256"] = explicit_sha.strip().lower()
        uvicorn.run(
            "network_anomaly.api.main:app",
            host=args.host,
            port=args.port,
            reload=True,
        )
        return

    from network_anomaly.api.main import create_app

    uvicorn.run(
        create_app(
            runtime_mode=effective_mode,
            require_ood_gate=effective_require_ood,
            expected_ood_gate_sha256=explicit_sha,
        ),
        host=args.host,
        port=args.port,
        reload=False,
    )


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
