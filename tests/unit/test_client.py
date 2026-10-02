"""Tests for client.py's response handling: oversize responses are rejected without full
buffering, and a total deadline interrupts a slow drip response or retry backoff.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

from typing import Any

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
        {"total_timeout_s": float("nan")},
        {"total_timeout_s": float("inf")},
        {"total_timeout_s": -1.0},
        {"max_response_bytes": 0},
        {"max_response_bytes": 16_777_217},
    ],
)
def test_client_rejects_unbounded_response_configuration(options: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        LETSClient("https://warden.test", **options)


@pytest.mark.parametrize(
    "options,exc_type",
    [
        ({"total_timeout_s": True}, TypeError),
        ({"total_timeout_s": "10"}, TypeError),
        ({"max_response_bytes": 1.5}, TypeError),
        ({"max_response_bytes": True}, TypeError),
    ],
)
def test_client_rejects_invalid_types(options: dict[str, Any], exc_type: type[Exception]) -> None:
    with pytest.raises(exc_type):
        LETSClient("https://warden.test", **options)


def test_retry_policy_validation() -> None:
    with pytest.raises(TypeError):
        RetryPolicy(max_attempts=True)
    with pytest.raises(TypeError):
        RetryPolicy(max_attempts=1.5)  # type: ignore
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(initial_backoff_s=float("nan"))
    with pytest.raises(ValueError):
        RetryPolicy(initial_backoff_s=float("inf"))
    with pytest.raises(TypeError):
        RetryPolicy(initial_backoff_s=True)  # type: ignore
    with pytest.raises(ValueError):
        RetryPolicy(initial_backoff_s=-0.1)
    with pytest.raises(ValueError):
        RetryPolicy(maximum_backoff_s=float("nan"))
    with pytest.raises(ValueError):
        RetryPolicy(maximum_backoff_s=float("inf"))


def test_retry_delay_handles_non_finite_headers() -> None:
    resp_nan = httpx.Response(429, headers={"retry-after": "NaN"})
    assert LETSClient._retry_delay(resp_nan, 0.5, 1.0) == 0.5

    resp_inf = httpx.Response(429, headers={"retry-after": "Infinity"})
    assert LETSClient._retry_delay(resp_inf, 0.5, 1.0) == 0.5

    resp_invalid = httpx.Response(429, headers={"retry-after": "invalid-date"})
    assert LETSClient._retry_delay(resp_invalid, 0.5, 1.0) == 0.5

    resp_valid = httpx.Response(429, headers={"retry-after": "2"})
    assert LETSClient._retry_delay(resp_valid, 0.5, 1.0) == 1.0


def test_client_preserves_injected_client_on_timeout() -> None:
    def slow_handler(request: httpx.Request) -> httpx.Response:
        time.sleep(0.2)
        return httpx.Response(200, json={"status": "ok"}, request=request)

    external_client = httpx.Client(
        base_url="https://warden.test/",
        transport=httpx.MockTransport(slow_handler),
    )
    client = LETSClient(
        "https://warden.test",
        client=external_client,
        total_timeout_s=0.05,
        retry=RetryPolicy(max_attempts=1),
    )

    try:
        with pytest.raises(httpx.TimeoutException):
            client.liveness()
        # Injected client must NOT be closed by deadline watchdog
        assert not external_client.is_closed
    finally:
        client.close()
        # Explicit client close should also not close external client
        assert not external_client.is_closed
        external_client.close()


def test_client_admission_wait_included_in_total_deadline() -> None:
    import threading

    def slow_handler(request: httpx.Request) -> httpx.Response:
        time.sleep(0.3)
        return httpx.Response(200, json={"status": "ok"}, request=request)

    transport = httpx.MockTransport(slow_handler)
    client = LETSClient(
        "https://warden.test",
        transport=transport,
        total_timeout_s=0.1,
        retry=RetryPolicy(max_attempts=1),
    )

    t1_started = threading.Event()

    def run_first_call() -> None:
        t1_started.set()
        try:
            client.liveness()
        except Exception:
            pass

    t1 = threading.Thread(target=run_first_call)
    t1.start()
    t1_started.wait()
    time.sleep(0.02)  # Ensure t1 has acquired lock

    started = time.perf_counter()
    with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
        client.liveness()
    elapsed = time.perf_counter() - started

    # Admission wait should time out around total_timeout_s (0.1s), well before 0.3s
    assert elapsed < 0.25
    t1.join()
    client.close()

