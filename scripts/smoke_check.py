"""Dev smoke check: verifies backend liveness + readiness over HTTP.

Usage:
    python scripts/smoke_check.py [--base-url http://localhost:8000]

Read-only: performs GETs only, never touches security tooling.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request


def get(base_url: str, path: str, timeout: int = 10) -> tuple[int, dict]:
    url = base_url.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode())
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL {url}: {exc}")
        return -1, {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://localhost:8000")
    args = parser.parse_args()

    ok = True
    status, health = get(args.base_url, "/api/v1/health")
    print(f"GET /api/v1/health -> {status} {health}")
    ok &= status == 200 and health.get("status") == "ok"

    status, ready = get(args.base_url, "/api/v1/ready")
    print(f"GET /api/v1/ready -> {status} {ready}")
    ok &= status in (200, 503) and "checks" in ready

    status, version = get(args.base_url, "/api/v1/version")
    print(f"GET /api/v1/version -> {status} {version}")
    ok &= status == 200 and "version" in version

    print("SMOKE OK" if ok else "SMOKE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
