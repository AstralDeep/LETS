"""Tests for LETSClient's serialized admission: the total deadline is created before the
request lock is acquired, so concurrent callers consume their own budget while waiting and
fail with an explicit ClientCapacityError before any transport use. Deterministic event
barriers and a fake monotonic clock replace elapsed-time assertions.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from lets.client import ClientCapacityError, LETSClient, RetryPolicy

_GATE_TIMEOUT_S = 30.0


class _GatedHandler:
    def __init__(self, gated_calls: tuple[int, ...]) -> None:
        self._lock = threading.Lock()
        self._gated = frozenset(gated_calls)
        self.calls = 0
        self.order: list[str] = []
        self.entered = {index: threading.Event() for index in self._gated}
        self.releases = {index: threading.Event() for index in self._gated}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        with self._lock:
            index = self.calls
            self.calls += 1
            self.order.append(f"enter:{index}")
        if index in self._gated:
            self.entered[index].set()
            self.releases[index].wait(_GATE_TIMEOUT_S)
        with self._lock:
            self.order.append(f"exit:{index}")
        return httpx.Response(200, json={"status": "ok"}, request=request)

    def release(self, index: int) -> None:
        self.releases[index].set()

    def release_all(self) -> None:
        for event in self.releases.values():
            event.set()


def _start_call(
    client: LETSClient,
    outcome: list[object],
) -> threading.Thread:
    def call() -> None:
        try:
            outcome.append(client.liveness())
        except Exception as error:
            outcome.append(error)

    thread = threading.Thread(target=call, daemon=True)
    thread.start()
    return thread


def _finish(thread: threading.Thread) -> None:
    thread.join(_GATE_TIMEOUT_S)
    assert not thread.is_alive()


def test_admission_timeout_raises_capacity_error_before_transport_use() -> None:
    handler = _GatedHandler(())
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(handler),
        total_timeout_s=0.2,
        retry=RetryPolicy(max_attempts=1),
    )
    waiter_outcome: list[object] = []
    try:
        assert client._request_lock.acquire(timeout=_GATE_TIMEOUT_S)
        try:
            waiter = _start_call(client, waiter_outcome)
            _finish(waiter)
            assert isinstance(waiter_outcome[0], ClientCapacityError)
            assert isinstance(waiter_outcome[0], httpx.TimeoutException)
            assert "admission wait" in str(waiter_outcome[0])
            assert handler.calls == 0
        finally:
            client._request_lock.release()
        assert client.liveness() == {"status": "ok"}
        assert handler.calls == 1
    finally:
        handler.release_all()
        client.close()


def test_multiple_waiters_fail_without_transport_use_while_client_is_occupied() -> None:
    handler = _GatedHandler(())
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(handler),
        total_timeout_s=0.2,
        retry=RetryPolicy(max_attempts=1),
    )
    waiter_outcomes: list[list[object]] = [[], [], []]
    try:
        assert client._request_lock.acquire(timeout=_GATE_TIMEOUT_S)
        try:
            waiters = [_start_call(client, outcome) for outcome in waiter_outcomes]
            for waiter in waiters:
                _finish(waiter)
            for outcome in waiter_outcomes:
                assert isinstance(outcome[0], ClientCapacityError)
            assert handler.calls == 0
        finally:
            client._request_lock.release()
        assert client.liveness() == {"status": "ok"}
        assert handler.calls == 1
    finally:
        handler.release_all()
        client.close()


def test_waiting_callers_are_admitted_serially_after_the_occupier_finishes() -> None:
    handler = _GatedHandler((0,))
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(handler),
        total_timeout_s=30.0,
        retry=RetryPolicy(max_attempts=1),
    )
    occupier_outcome: list[object] = []
    waiter_outcomes: list[list[object]] = [[], []]
    try:
        occupier = _start_call(client, occupier_outcome)
        assert handler.entered[0].wait(_GATE_TIMEOUT_S)
        waiters = [_start_call(client, outcome) for outcome in waiter_outcomes]
        handler.release(0)
        _finish(occupier)
        for waiter in waiters:
            _finish(waiter)
        for outcome in waiter_outcomes:
            assert outcome[0] == {"status": "ok"}
        assert handler.order[:2] == ["enter:0", "exit:0"]
        tail = handler.order[2:]
        assert [entry.split(":")[0] for entry in tail] == [
            "enter",
            "exit",
            "enter",
            "exit",
        ]
        assert {tail[0].split(":")[1], tail[2].split(":")[1]} == {"1", "2"}
    finally:
        handler.release_all()
        for thread in [occupier, *waiters]:
            _finish(thread)
        client.close()


def test_close_while_waiting_for_admission_fails_the_waiter_with_closed_error() -> None:
    handler = _GatedHandler(())
    borrowed = httpx.Client(base_url="https://warden.test/", transport=httpx.MockTransport(handler))
    client = LETSClient("https://warden.test", client=borrowed, total_timeout_s=30.0)
    waiter_outcome: list[object] = []
    try:
        assert client._request_lock.acquire(timeout=_GATE_TIMEOUT_S)
        try:
            waiter = _start_call(client, waiter_outcome)
            client.close()
            client._request_lock.release()
            _finish(waiter)
            assert isinstance(waiter_outcome[0], RuntimeError)
            assert "LETS client is closed" in str(waiter_outcome[0])
            with pytest.raises(RuntimeError, match="LETS client is closed"):
                client.liveness()
            assert handler.calls == 0
        finally:
            if client._request_lock.locked():
                client._request_lock.release()
    finally:
        handler.release_all()
        client.close()
        borrowed.close()


def test_admission_deadline_bounds_a_waiter_even_after_close() -> None:
    handler = _GatedHandler(())
    borrowed = httpx.Client(base_url="https://warden.test/", transport=httpx.MockTransport(handler))
    client = LETSClient("https://warden.test", client=borrowed, total_timeout_s=0.2)
    waiter_outcome: list[object] = []
    try:
        assert client._request_lock.acquire(timeout=_GATE_TIMEOUT_S)
        try:
            waiter = _start_call(client, waiter_outcome)
            client.close()
            _finish(waiter)
            assert isinstance(waiter_outcome[0], ClientCapacityError)
            assert handler.calls == 0
        finally:
            client._request_lock.release()
        with pytest.raises(RuntimeError, match="LETS client is closed"):
            client.liveness()
    finally:
        handler.release_all()
        client.close()
        borrowed.close()


def test_admission_wait_consumes_the_total_deadline_before_transport_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = _GatedHandler((0, 1))
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(handler),
        total_timeout_s=10.0,
        retry=RetryPolicy(max_attempts=1),
    )
    occupier_outcome: list[object] = []
    victim_outcome: list[object] = []
    try:
        occupier = _start_call(client, occupier_outcome)
        assert handler.entered[0].wait(_GATE_TIMEOUT_S)

        base = time.monotonic()
        now = [base]
        deadline_computed = threading.Event()

        def fake_monotonic() -> float:
            deadline_computed.set()
            return now[0]

        monkeypatch.setattr(time, "monotonic", fake_monotonic)

        victim = _start_call(client, victim_outcome)
        assert deadline_computed.wait(_GATE_TIMEOUT_S), (
            "the victim never computed its admission deadline before the lock was released"
        )

        now[0] = base + 5.0
        intervals: list[float] = []
        real_timer = threading.Timer

        def recording_timer(
            interval: float,
            function: Callable[..., Any],
            args: tuple[Any, ...] | None = None,
            kwargs: dict[str, Any] | None = None,
        ) -> threading.Timer:
            intervals.append(interval)
            return real_timer(interval, function, args, kwargs)

        monkeypatch.setattr(threading, "Timer", recording_timer)

        handler.release(0)
        _finish(occupier)
        assert occupier_outcome[0] == {"status": "ok"}
        assert handler.entered[1].wait(_GATE_TIMEOUT_S), (
            "the victim was never admitted to the transport"
        )

        now[0] = base + 11.0
        handler.release(1)
        _finish(victim)

        assert intervals == [pytest.approx(5.0, abs=1e-6)]
        assert isinstance(victim_outcome[0], httpx.TimeoutException)
        assert not isinstance(victim_outcome[0], ClientCapacityError)
        assert "wall-clock deadline" in str(victim_outcome[0])
        assert handler.calls == 2
    finally:
        handler.release_all()
        client.close()
