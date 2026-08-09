from __future__ import annotations

import time
from collections.abc import Iterator

import httpx
import pytest

from lets.client import LETSClient, RemoteValidationError, RetryPolicy


class _SlowBytes(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        for _ in range(100):
            time.sleep(0.02)
            yield b" "


def test_client_rejects_oversize_response_without_buffering_it_all() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=b"x" * 65, request=request)
    )
    client = LETSClient(
        "https://warden.test",
        transport=transport,
        max_response_bytes=64,
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(RemoteValidationError) as raised:
            client.liveness()
        assert raised.value.problem.code == "response_too_large"
    finally:
        client.close()


def test_client_total_deadline_interrupts_a_slow_drip_response() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=_SlowBytes(), request=request)
    )
    client = LETSClient(
        "https://warden.test",
        transport=transport,
        timeout=1.0,
        total_timeout_s=0.05,
        retry=RetryPolicy(max_attempts=1),
    )
    started = time.perf_counter()
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            client.liveness()
        assert time.perf_counter() - started < 0.5
    finally:
        client.close()


@pytest.mark.parametrize("failure", ["response", "transport"])
def test_client_total_deadline_interrupts_retry_backoff(failure: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if failure == "transport":
            raise httpx.ConnectError("injected outage", request=request)
        return httpx.Response(503, request=request)

    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(handler),
        total_timeout_s=0.05,
        retry=RetryPolicy(
            max_attempts=2,
            initial_backoff_s=0.5,
            maximum_backoff_s=0.5,
        ),
    )
    started = time.perf_counter()
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            client.liveness()
        assert calls == 1
        assert time.perf_counter() - started < 0.4
    finally:
        client.close()


@pytest.mark.parametrize(
    "options",
    [
        {"total_timeout_s": 0},
        {"max_response_bytes": 0},
        {"max_response_bytes": 16_777_217},
    ],
)
def test_client_rejects_unbounded_response_configuration(options: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        LETSClient("https://warden.test", **options)
