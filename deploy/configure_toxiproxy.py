"""Create the directed fault-injection links used by the acceptance suite."""

from __future__ import annotations

import argparse
import time

import httpx

PROXIES = (
    {"name": "a_to_b", "listen": "0.0.0.0:8666", "upstream": "warden-b:8080"},
    {"name": "b_to_a", "listen": "0.0.0.0:8667", "upstream": "warden-a:8080"},
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", required=True)
    arguments = parser.parse_args()
    base_url = arguments.api.rstrip("/")
    deadline = time.monotonic() + 60
    with httpx.Client(timeout=3) as client:
        while True:
            try:
                response = client.get(f"{base_url}/proxies")
                response.raise_for_status()
                break
            except httpx.HTTPError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.25)
        existing = response.json()
        for proxy in PROXIES:
            payload = {**proxy, "enabled": True}
            if proxy["name"] in existing:
                configured = client.patch(
                    f"{base_url}/proxies/{proxy['name']}",
                    json=payload,
                )
            else:
                configured = client.post(f"{base_url}/proxies", json=payload)
            configured.raise_for_status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
