"""Tests for LETSClient client ownership across total-deadline aborts: the deadline
watchdog preserves injected clients while owned clients are closed and replaced, explicit
and concurrent shutdowns never destroy a borrowed client, and every wrapper request stays
bounded by the remaining deadline. Fake timers and mock transports keep every outcome
deterministic without wall-clock sleeps or real requests.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from lets.client import LETSClient, RetryPolicy

_GUARD_TIMEOUT_S = 30.0

_BASE_URL = "https://warden.test"


class _FakeWatchdog:
    def __init__(self) -> None:
        self.function: Callable[[], None] | None = None
        self.started = False
        self.cancelled = False
        self.fire_count = 0
        self.daemon = False

    def arm(self, interval: float, function: Callable[[], None]) -> _FakeWatchdog:
        self.function = function
        return self

    def start(self) -> None:
        self.started = True

    def cancel(self) -> None:
        self.cancelled = True

    def join(self, timeout: float | None = None) -> None:
        return None

    def fire(self) -> None:
        self.fire_count += 1
        assert self.function is not None
        self.function()


class _TimerOnlyThreading:
    def __init__(self, watchdog: _FakeWatchdog) -> None:
        self.Timer = watchdog.arm

    def __getattr__(self, name: str) -> Any:
        return getattr(threading, name)


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class _ClockTime:
    def __init__(self, clock: _FakeClock) -> None:
        self._clock = clock

    def monotonic(self) -> float:
        return self._clock.monotonic()

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


class _RecordingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self.timeouts: list[dict[str, float | None]] = []
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.timeouts.append(dict(request.extensions["timeout"]))
        if self.calls == 1:
            return httpx.Response(503, request=request)
        return httpx.Response(200, json={"status": "ok"}, request=request)


def _patch_fake_watchdog(monkeypatch: pytest.MonkeyPatch) -> _FakeWatchdog:
    watchdog = _FakeWatchdog()
    monkeypatch.setattr("lets.client.threading", _TimerOnlyThreading(watchdog))
    return watchdog


def _counting_handler(calls: list[str]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if len(calls) == 1:
            return httpx.Response(503, request=request)
        return httpx.Response(200, json={"status": "ok"}, request=request)

    return handler


def _ok_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"status": "ok"}, request=request)


def _borrowed_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    timeout: httpx.Timeout | None = None,
) -> httpx.Client:
    if timeout is None:
        return httpx.Client(base_url=f"{_BASE_URL}/", transport=httpx.MockTransport(handler))
    return httpx.Client(
        base_url=f"{_BASE_URL}/",
        transport=httpx.MockTransport(handler),
        timeout=timeout,
    )


def _fired_on_sleep(watchdog: _FakeWatchdog) -> Callable[[float], None]:
    def sleep(_delay: float) -> None:
        watchdog.fire()

    return sleep


def test_deadline_expired_during_backoff_is_enforced_at_the_attempt_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watchdog = _patch_fake_watchdog(monkeypatch)
    clock = _FakeClock()
    monkeypatch.setattr("lets.client.time", _ClockTime(clock))
    calls: list[str] = []
    external = _borrowed_client(_counting_handler(calls))

    def advance_past_deadline(_delay: float) -> None:
        clock.now += 10.0

    wrapper = LETSClient(
        _BASE_URL,
        client=external,
        total_timeout_s=5.0,
        retry=RetryPolicy(max_attempts=2, initial_backoff_s=1.0),
        sleep=advance_past_deadline,
    )
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            wrapper.liveness()
        assert watchdog.fire_count == 0
        assert watchdog.cancelled
        assert calls == ["/health/live"]
        assert not external.is_closed
        assert wrapper.liveness() == {"status": "ok"}
        assert calls == ["/health/live", "/health/live"]
    finally:
        wrapper.close()
        external.close()


def test_deadline_expired_during_a_response_read_raises_at_the_retry_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watchdog = _patch_fake_watchdog(monkeypatch)
    clock = _FakeClock()
    monkeypatch.setattr("lets.client.time", _ClockTime(clock))
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        clock.now += 10.0
        return httpx.Response(503, request=request)

    external = _borrowed_client(handler)
    wrapper = LETSClient(
        _BASE_URL,
        client=external,
        total_timeout_s=5.0,
        retry=RetryPolicy(max_attempts=2, initial_backoff_s=1.0),
        sleep=lambda _delay: None,
    )
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            wrapper.liveness()
        assert watchdog.fire_count == 0
        assert calls == ["/health/live"]
        assert not external.is_closed
    finally:
        wrapper.close()
        external.close()


def test_deadline_abort_leaves_a_borrowed_clients_unrelated_requests_usable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watchdog = _patch_fake_watchdog(monkeypatch)
    calls: list[str] = []
    external = _borrowed_client(_counting_handler(calls))
    wrapper = LETSClient(
        _BASE_URL,
        client=external,
        total_timeout_s=5.0,
        retry=RetryPolicy(max_attempts=2, initial_backoff_s=1.0),
        sleep=_fired_on_sleep(watchdog),
    )
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            wrapper.liveness()
        assert watchdog.started
        assert watchdog.cancelled
        assert watchdog.fire_count == 1
        assert calls == ["/health/live"]
        assert not external.is_closed
        assert wrapper._client is external
        unrelated = external.request("GET", f"{_BASE_URL}/v1/unrelated")
        assert unrelated.status_code == 200
        assert calls == ["/health/live", "/v1/unrelated"]
        assert wrapper.liveness() == {"status": "ok"}
        assert calls == ["/health/live", "/v1/unrelated", "/health/live"]
    finally:
        wrapper.close()
        external.close()


def test_explicit_wrapper_close_preserves_a_borrowed_client() -> None:
    external = _borrowed_client(_ok_handler)
    wrapper = LETSClient(_BASE_URL, client=external)
    wrapper.close()
    assert wrapper._client is external
    assert not external.is_closed
    with pytest.raises(RuntimeError, match="LETS client is closed"):
        wrapper.liveness()
    unrelated = external.request("GET", f"{_BASE_URL}/v1/unrelated")
    assert unrelated.status_code == 200
    external.close()
    assert external.is_closed


def test_deadline_abort_replaces_an_owned_client_and_keeps_the_wrapper_usable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watchdog = _patch_fake_watchdog(monkeypatch)
    calls: list[str] = []
    wrapper = LETSClient(
        _BASE_URL,
        transport=httpx.MockTransport(_counting_handler(calls)),
        total_timeout_s=5.0,
        retry=RetryPolicy(max_attempts=2, initial_backoff_s=1.0),
        sleep=_fired_on_sleep(watchdog),
    )
    original = wrapper._client
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            wrapper.liveness()
        assert original.is_closed
        assert wrapper._client is not original
        assert not wrapper._client.is_closed
        assert calls == ["/health/live"]
        assert wrapper.liveness() == {"status": "ok"}
        assert calls == ["/health/live", "/health/live"]
    finally:
        wrapper.close()
    assert wrapper._client.is_closed


def test_deadline_during_transport_failure_preserves_a_borrowed_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watchdog = _patch_fake_watchdog(monkeypatch)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if len(calls) == 1:
            raise httpx.ConnectError("injected outage", request=request)
        return httpx.Response(200, json={"status": "ok"}, request=request)

    external = _borrowed_client(handler)
    wrapper = LETSClient(
        _BASE_URL,
        client=external,
        total_timeout_s=5.0,
        retry=RetryPolicy(max_attempts=2, initial_backoff_s=1.0),
        sleep=_fired_on_sleep(watchdog),
    )
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            wrapper.liveness()
        assert calls == ["/health/live"]
        assert not external.is_closed
        assert wrapper.liveness() == {"status": "ok"}
        assert calls == ["/health/live", "/health/live"]
    finally:
        wrapper.close()
        external.close()


def test_concurrent_close_during_a_deadline_abort_preserves_a_borrowed_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watchdog = _patch_fake_watchdog(monkeypatch)
    calls: list[str] = []
    external = _borrowed_client(_counting_handler(calls))
    close_started = threading.Event()
    close_finished = threading.Event()
    failures: list[Exception] = []

    def racing_sleep(_delay: float) -> None:
        close_started.set()
        if not close_finished.wait(_GUARD_TIMEOUT_S):
            failures.append(AssertionError("concurrent close handshake timed out"))
            return
        watchdog.fire()

    wrapper = LETSClient(
        _BASE_URL,
        client=external,
        total_timeout_s=5.0,
        retry=RetryPolicy(max_attempts=2, initial_backoff_s=1.0),
        sleep=racing_sleep,
    )

    def closer() -> None:
        try:
            if not close_started.wait(_GUARD_TIMEOUT_S):
                failures.append(AssertionError("deadline handshake timed out"))
                return
            wrapper.close()
            close_finished.set()
        except Exception as error:
            failures.append(error)

    closer_thread = threading.Thread(target=closer)
    closer_thread.start()
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            wrapper.liveness()
    finally:
        closer_thread.join(_GUARD_TIMEOUT_S)
    assert not closer_thread.is_alive()
    assert failures == []
    assert not external.is_closed
    assert wrapper._client is external
    with pytest.raises(RuntimeError, match="LETS client is closed"):
        wrapper.liveness()
    unrelated = external.request("GET", f"{_BASE_URL}/v1/unrelated")
    assert unrelated.status_code == 200
    external.close()


def test_concurrent_close_during_a_deadline_abort_keeps_an_owned_client_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    watchdog = _patch_fake_watchdog(monkeypatch)
    calls: list[str] = []
    close_started = threading.Event()
    close_finished = threading.Event()
    failures: list[Exception] = []

    def racing_sleep(_delay: float) -> None:
        close_started.set()
        if not close_finished.wait(_GUARD_TIMEOUT_S):
            failures.append(AssertionError("concurrent close handshake timed out"))
            return
        watchdog.fire()

    wrapper = LETSClient(
        _BASE_URL,
        transport=httpx.MockTransport(_counting_handler(calls)),
        total_timeout_s=5.0,
        retry=RetryPolicy(max_attempts=2, initial_backoff_s=1.0),
        sleep=racing_sleep,
    )
    original = wrapper._client

    def closer() -> None:
        try:
            if not close_started.wait(_GUARD_TIMEOUT_S):
                failures.append(AssertionError("deadline handshake timed out"))
                return
            wrapper.close()
            close_finished.set()
        except Exception as error:
            failures.append(error)

    closer_thread = threading.Thread(target=closer)
    closer_thread.start()
    try:
        with pytest.raises(httpx.TimeoutException, match="wall-clock deadline"):
            wrapper.liveness()
    finally:
        closer_thread.join(_GUARD_TIMEOUT_S)
    assert not closer_thread.is_alive()
    assert failures == []
    assert wrapper._client is original
    assert original.is_closed
    with pytest.raises(RuntimeError, match="LETS client is closed"):
        wrapper.liveness()


def test_wrapper_requests_cap_client_timeouts_at_the_remaining_deadline() -> None:
    transport = _RecordingTransport()
    external = _borrowed_client(
        transport.handle_request,
        timeout=httpx.Timeout(connect=1.0, read=None, write=8.0, pool=0.5),
    )
    wrapper = LETSClient(
        _BASE_URL,
        client=external,
        total_timeout_s=5.0,
        retry=RetryPolicy(max_attempts=3, initial_backoff_s=0.001),
        sleep=lambda _delay: None,
    )
    try:
        assert wrapper.liveness() == {"status": "ok"}
        assert transport.calls == 2
        first = transport.timeouts[0]
        second = transport.timeouts[1]
        assert first["connect"] == 1.0
        assert first["pool"] == 0.5
        assert first["read"] is not None and 0.0 < first["read"] <= 5.0
        assert first["write"] is not None and 0.0 < first["write"] <= 5.0
        assert second["read"] is not None and 0.0 < second["read"] <= first["read"]
        assert second["write"] is not None and 0.0 < second["write"] <= first["write"]
        assert second["connect"] == 1.0
        assert wrapper.liveness() == {"status": "ok"}
        assert transport.calls == 3
    finally:
        wrapper.close()
        external.close()
