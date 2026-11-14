#!/usr/bin/env python3
"""Run FastAPI application server for local testing and reproduction."""

from __future__ import annotations

import argparse

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Network Anomaly Detection FastAPI Service")
    parser.add_argument(
        "--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)"
    )
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable live code reload")
    parser.add_argument(
        "--db-path", default=None, help="Custom SQLite DB path (default: data/network_anomaly.db)"
    )
    args = parser.parse_args()

    print(f"Starting Network Anomaly FastAPI Service on http://{args.host}:{args.port}")
    print(f"OpenAPI documentation available at http://{args.host}:{args.port}/docs")

    uvicorn.run(
        "network_anomaly.api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
