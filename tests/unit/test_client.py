"""Tests for client.py's response handling: oversize responses are rejected without full
buffering, and a total deadline interrupts a slow drip response or retry backoff.

Deterministic rewrite per AstralDeep/LETS#73 — replaces wall-clock assertions
with event-driven synchronization and an injected sleep callable so tests do
not rely on real elapsed time. The deadline logic in LETSClient is unchanged;
only the tests stop measuring performance via `time.perf_counter()`.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

import httpx
import pytest

from lets.client import LETSClient, RemoteValidationError, RetryPolicy


class _BlockingBytes(httpx.SyncByteStream):
    """Stream that blocks on an Event until the test releases it.

    Replaces the previous ``_SlowBytes`` that used ``time.sleep(0.02)`` per
    chunk. Blocking on an Event lets us deterministically exercise the
    deadline watchdog without waiting on the wall clock: the watchdog
    fires (via ``threading.Timer``) while the stream is parked, and the
    client raises ``httpx.TimeoutException`` before this iterator yields.
    """

    def __init__(self, release: threading.Event) -> None:
        self._release = release

    def __iter__(self) -> Iterator[bytes]:
        self._release.wait()
        yield b" "


def _no_sleep(_seconds: float) -> None:
    """Injected sleep callable that returns immediately.

    Used as ``LETSClient(sleep=...)`` so retry backoff does not actually
    sleep between attempts. The deadline watchdog still uses
    ``threading.Timer`` internally, but with no real sleeps the test
    completes in milliseconds rather than 0.4+ seconds.
    """


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
    # Stream that never yields a byte until the test releases it. The
    # deadline watchdog (threading.Timer) fires while the stream is parked
    # and the client raises the wall-clock-deadline TimeoutException.
    release = threading.Event()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=_BlockingBytes(release), request=request)
    )
    client = LETSClient(
        "https://warden.test",
        transport=transport,
        timeout=1.0,
        total_timeout_s=0.05,
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            client.liveness()
        # No wall-clock assertion: we proved the deadline fired (the
        # exception matches "wall-clock deadline") without measuring
        # elapsed time, so CI scheduling jitter cannot cause flakes.
    finally:
        release.set()  # Unblock the stream so background timers tear down.
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

    # Injected sleep returns instantly, so retry backoff does not actually
    # wait 0.5s between attempts. The deadline watchdog fires on its own
    # thread (threading.Timer) before the second attempt is admitted.
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(handler),
        total_timeout_s=0.05,
        retry=RetryPolicy(
            max_attempts=2,
            initial_backoff_s=0.5,
            maximum_backoff_s=0.5,
        ),
        sleep=_no_sleep,
    )
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            client.liveness()
        # First attempt always runs; second is gated by the deadline. We
        # assert call count (state) instead of elapsed wall time.
        assert calls == 1
    finally:
        client.close()


def test_client_deadline_check_is_actually_enforced() -> None:
    # Regression guard per AstralDeep/LETS#73 acceptance criteria: this
    # test MUST fail if the deadline watchdog is removed from LETSClient.
    # We use a blocking stream that would hang forever without the
    # watchdog; if the watchdog is deleted this test times out (pytest
    # default 60s) instead of returning a passing TimeoutException.
    release = threading.Event()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, stream=_BlockingBytes(release), request=request)
    )
    client = LETSClient(
        "https://warden.test",
        transport=transport,
        total_timeout_s=0.05,
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            client.liveness()
    finally:
        release.set()
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
