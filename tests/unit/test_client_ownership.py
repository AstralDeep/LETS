"""Verifies that LETS rejects unsupported shared HTTP clients without taking ownership.
Owned clients still recover after deadlines and respect concurrent shutdown.
"""

from __future__ import annotations

import threading
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


def _fired_on_sleep(watchdog: _FakeWatchdog) -> Callable[[float], None]:
    def sleep(_delay: float) -> None:
        watchdog.fire()

    return sleep


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


@pytest.mark.parametrize("mock_transport", [False, True])
def test_shared_clients_are_rejected_without_closing_or_using_them(mock_transport):
    calls = []

    def respond(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"status": "ok"}, request=request)

    external = httpx.Client(
        base_url=_BASE_URL,
        transport=httpx.MockTransport(respond) if mock_transport else None,
    )
    try:
        with pytest.raises(ValueError, match="borrowed HTTP clients"):
            LETSClient(_BASE_URL, client=external)
        assert not external.is_closed
        assert calls == []
        if mock_transport:
            assert external.get("/unrelated").json() == {"status": "ok"}
            assert calls == ["/unrelated"]
    finally:
        external.close()
