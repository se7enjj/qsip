#!/usr/bin/env python3
"""
QSIP Live Demo Server — launch script.

Usage:
    python serve.py [--host HOST] [--port PORT] [--reload]

Defaults:
    host:  0.0.0.0
    port:  8000
    reload: False

Then open http://localhost:8000 in your browser.
"""
from __future__ import annotations

import argparse
import sys

try:
    import uvicorn
except ImportError:
    print("uvicorn not installed.  Run:  pip install 'uvicorn[standard]>=0.27.0'")
    sys.exit(1)

try:
    import fastapi  # noqa: F401
except ImportError:
    print("fastapi not installed.  Run:  pip install 'fastapi>=0.110.0'")
    sys.exit(1)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Start the QSIP live demo server")
    p.add_argument("--host",   default="0.0.0.0",   help="Bind host  (default: 0.0.0.0)")
    p.add_argument("--port",   default=8000, type=int, help="Port  (default: 8000)")
    p.add_argument("--reload", action="store_true",  help="Enable uvicorn auto-reload (dev only)")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    print(f"\n  QSIP Live Demo Server")
    print(f"  ─────────────────────────────────────────────")
    print(f"  URL  :  http://localhost:{args.port}")
    print(f"  Host :  {args.host}:{args.port}")
    print(f"  PID  :  {__import__('os').getpid()}")
    print(f"\n  Open your browser → http://localhost:{args.port}\n")

    uvicorn.run(
        "src.web.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
