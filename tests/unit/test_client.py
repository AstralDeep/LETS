"""Tests for client.py's response handling: oversize responses are rejected without full
buffering, and a total deadline interrupts a slow drip response or retry backoff. Response
envelopes, discriminators, and redirects are validated against OpenAPI contracts.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from lets.client import LETSClient, RemoteUnavailableError, RemoteValidationError, RetryPolicy


class _SlowBytes(httpx.SyncByteStream):
    def __iter__(self) -> Iterator[bytes]:
        for _ in range(100):
            time.sleep(0.02)
            yield b" "


def _retry_response(value: str) -> httpx.Response:
    return httpx.Response(
        429,
        headers={"retry-after": value},
        request=httpx.Request("GET", "https://warden.test/v1/info"),
    )


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
    ("options", "exception"),
    [
        ({"total_timeout_s": 0}, ValueError),
        ({"total_timeout_s": -1}, ValueError),
        ({"total_timeout_s": float("nan")}, ValueError),
        ({"total_timeout_s": float("inf")}, ValueError),
        ({"total_timeout_s": float("-inf")}, ValueError),
        ({"total_timeout_s": 10**309}, ValueError),
        ({"total_timeout_s": threading.TIMEOUT_MAX * 2}, ValueError),
        ({"total_timeout_s": threading.TIMEOUT_MAX + 1.0}, ValueError),
        ({"total_timeout_s": True}, TypeError),
        ({"total_timeout_s": False}, TypeError),
        ({"total_timeout_s": "10"}, TypeError),
        ({"max_response_bytes": 0}, ValueError),
        ({"max_response_bytes": -1}, ValueError),
        ({"max_response_bytes": 16_777_217}, ValueError),
        ({"max_response_bytes": 10**309}, ValueError),
        ({"max_response_bytes": 1.5}, TypeError),
        ({"max_response_bytes": float("nan")}, TypeError),
        ({"max_response_bytes": True}, TypeError),
        ({"max_response_bytes": False}, TypeError),
        ({"max_response_bytes": "1000"}, TypeError),
    ],
)
def test_client_rejects_invalid_numeric_configuration(
    options: dict[str, Any], exception: type[Exception]
) -> None:
    with pytest.raises(exception):
        LETSClient("https://warden.test", **options)


@pytest.mark.parametrize(
    ("options", "exception"),
    [
        ({"total_timeout_s": 0}, ValueError),
        ({"total_timeout_s": float("nan")}, ValueError),
        ({"total_timeout_s": 10**309}, ValueError),
        ({"total_timeout_s": True}, TypeError),
        ({"total_timeout_s": "10"}, TypeError),
        ({"max_response_bytes": 0}, ValueError),
        ({"max_response_bytes": 1.5}, TypeError),
        ({"max_response_bytes": True}, TypeError),
    ],
)
def test_client_configuration_error_before_transport_creation(
    monkeypatch: pytest.MonkeyPatch, options: dict[str, Any], exception: type[Exception]
) -> None:
    calls = 0

    def fail_client_init(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        raise AssertionError("httpx.Client must not be allocated for invalid configuration")

    monkeypatch.setattr(httpx, "Client", fail_client_init)
    with pytest.raises(exception):
        LETSClient("https://warden.test", **options)
    assert calls == 0


@pytest.mark.parametrize(
    ("policy_kwargs", "exception"),
    [
        ({"max_attempts": 0}, ValueError),
        ({"max_attempts": -1}, ValueError),
        ({"max_attempts": 1.5}, TypeError),
        ({"max_attempts": True}, TypeError),
        ({"max_attempts": False}, TypeError),
        ({"max_attempts": "3"}, TypeError),
        ({"initial_backoff_s": -0.01}, ValueError),
        ({"initial_backoff_s": float("nan")}, ValueError),
        ({"initial_backoff_s": float("inf")}, ValueError),
        ({"initial_backoff_s": float("-inf")}, ValueError),
        ({"initial_backoff_s": 10**309}, ValueError),
        ({"initial_backoff_s": True}, TypeError),
        ({"initial_backoff_s": "0.1"}, TypeError),
        ({"maximum_backoff_s": -0.01}, ValueError),
        ({"maximum_backoff_s": float("nan")}, ValueError),
        ({"maximum_backoff_s": float("inf")}, ValueError),
        ({"maximum_backoff_s": float("-inf")}, ValueError),
        ({"maximum_backoff_s": 10**309}, ValueError),
        ({"maximum_backoff_s": True}, TypeError),
        ({"maximum_backoff_s": "1.0"}, TypeError),
    ],
)
def test_retry_policy_rejects_invalid_parameters(
    policy_kwargs: dict[str, Any], exception: type[Exception]
) -> None:
    with pytest.raises(exception):
        RetryPolicy(**policy_kwargs)


@pytest.mark.parametrize(
    "policy_kwargs",
    [
        {"max_attempts": 1, "initial_backoff_s": 0.0, "maximum_backoff_s": 0.0},
        {"max_attempts": 1, "initial_backoff_s": 0, "maximum_backoff_s": 0},
        {"max_attempts": 10, "initial_backoff_s": 0.1, "maximum_backoff_s": 2.5},
        {"max_attempts": 3, "initial_backoff_s": 1, "maximum_backoff_s": 1},
        {"max_attempts": 3, "initial_backoff_s": 2.0, "maximum_backoff_s": 1.0},
    ],
)
def test_retry_policy_accepts_valid_parameters(policy_kwargs: dict[str, Any]) -> None:
    policy = RetryPolicy(**policy_kwargs)
    assert policy.max_attempts >= 1
    assert policy.initial_backoff_s >= 0
    assert policy.maximum_backoff_s >= 0


@pytest.mark.parametrize(
    "value",
    [
        "NaN",
        "nan",
        "NAN",
        "inf",
        "-inf",
        "Infinity",
        "-Infinity",
        "1.5",
        "0.0",
        "1e2",
        "-5",
        "invalid-header",
        "١٢",
    ],
)
def test_parse_retry_after_rejects_invalid_numeric_values(value: str) -> None:
    assert LETSClient._parse_retry_after(value, datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)) is None


@pytest.mark.parametrize(
    "value",
    [
        "Sun, 06 Nov 1994 08:49:37 PST",
        "Sun, 06 Nov 1994 08:49:37 +0000",
        "Sun, 06 Nov 1994 08:49:37 UTC",
        "sun, 06 nov 1994 08:49:37 gmt",
        "Sun, 06 Nov 1994 08:49:37",
        "Sun, 6 Nov 1994 08:49:37 GMT",
        "Sun,  06 Nov 1994 08:49:37 GMT",
        "Sun, 07 Nov 1994 08:49:37 GMT",
        "Monday, 06-Nov-94 08:49:37 GMT",
        "Mon Nov  6 08:49:37 1994",
        "Sun, 31 Feb 2017 00:00:00 GMT",
        "Sun, 31 Dec 1899 23:59:59 GMT",
        "Mon, 01 Jan 0001 00:00:00 GMT",
        "Sun Dec 31 23:59:59 1899",
    ],
)
def test_parse_retry_after_rejects_non_rfc_values(value: str) -> None:
    assert LETSClient._parse_retry_after(value, datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)) is None


@pytest.mark.parametrize(("value", "expected"), [("0", 0.0), ("1", 1.0), ("120", 120.0)])
def test_parse_retry_after_reads_delay_seconds(value: str, expected: float) -> None:
    assert (
        LETSClient._parse_retry_after(value, datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC))
        == expected
    )


@pytest.mark.parametrize("value", ["9" * 400, "9" * 5000])
def test_parse_retry_after_treats_oversized_delay_seconds_as_unbounded(value: str) -> None:
    result = LETSClient._parse_retry_after(value, datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC))
    assert result == math.inf


def test_parse_retry_after_leap_second_adds_one_second() -> None:
    now = datetime(2016, 12, 31, 23, 59, 0, tzinfo=UTC)
    second_59 = LETSClient._parse_retry_after("Sat, 31 Dec 2016 23:59:59 GMT", now)
    second_60 = LETSClient._parse_retry_after("Sat, 31 Dec 2016 23:59:60 GMT", now)
    assert second_59 == 59.0
    assert second_60 == 60.0
    assert second_60 - second_59 == 1.0


def test_parse_retry_after_rfc850_leap_second_and_past_century() -> None:
    leap_now = datetime(2016, 12, 31, 23, 59, 0, tzinfo=UTC)
    assert LETSClient._parse_retry_after("Saturday, 31-Dec-16 23:59:60 GMT", leap_now) == 60.0
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    assert (
        LETSClient._parse_retry_after("Sunday, 06-Nov-94 08:49:37 GMT", now)
        == (datetime(1994, 11, 6, 8, 49, 37, tzinfo=UTC) - now).total_seconds()
    )


def test_parse_retry_after_rfc850_century_window() -> None:
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    future = LETSClient._parse_retry_after("Thursday, 01-Oct-76 12:00:00 GMT", now)
    rolled = LETSClient._parse_retry_after("Sunday, 03-Oct-76 12:00:00 GMT", now)
    assert future == (datetime(2076, 10, 1, 12, 0, 0, tzinfo=UTC) - now).total_seconds()
    assert rolled == (datetime(1976, 10, 3, 12, 0, 0, tzinfo=UTC) - now).total_seconds()


def test_parse_retry_after_rfc850_50_year_boundary_is_exclusive() -> None:
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    threshold = now.replace(year=now.year + 50)
    at_threshold = LETSClient._parse_retry_after("Friday, 02-Oct-76 12:00:00 GMT", now)
    beyond_threshold = LETSClient._parse_retry_after("Saturday, 02-Oct-76 12:00:01 GMT", now)
    assert at_threshold == (threshold - now).total_seconds()
    assert beyond_threshold == (datetime(1976, 10, 2, 12, 0, 1, tzinfo=UTC) - now).total_seconds()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Sat, 31 Dec 2016 23:59:60 GMT", 60.0),
        ("Saturday, 31-Dec-16 23:59:60 GMT", 60.0),
        ("Sat Dec 31 23:59:60 2016", 60.0),
    ],
)
def test_parse_retry_after_weekday_check_is_locale_independent(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: float
) -> None:
    real_datetime = datetime

    class _LocalizedStrftime(datetime):
        def strftime(self, fmt: str) -> str:
            if "%a" in fmt:
                return "周六"
            if "%A" in fmt:
                return "星期六"
            return super().strftime(fmt)

    class _MockDatetime:
        def __new__(cls, *args: Any, **kwargs: Any) -> Any:
            return _LocalizedStrftime(*args, **kwargs)

    monkeypatch.setattr("lets.client.datetime", _MockDatetime)
    now = real_datetime(2016, 12, 31, 23, 59, 0, tzinfo=UTC)
    assert LETSClient._parse_retry_after(value, now) == expected


@pytest.mark.parametrize(
    ("header_val", "fallback", "maximum", "expected"),
    [
        ("NaN", 0.25, 2.0, 0.25),
        ("1.5", 0.1, 2.0, 0.1),
        ("invalid", 5.0, 2.0, 2.0),
        ("0", 0.5, 2.0, 0.0),
        ("1", 0.1, 2.0, 1.0),
        ("5", 0.1, 2.0, 2.0),
        ("9" * 400, 0.25, 2.0, 2.0),
        ("Sun, 06 Nov 1994 08:49:37 GMT", 0.5, 2.0, 0.0),
        ("Sun Nov  6 08:49:37 1994", 0.5, 2.0, 0.0),
        ("Sat, 31 Dec 2016 23:59:60 GMT", 0.5, 2.0, 0.0),
        ("Sun, 31 Dec 1899 23:59:59 GMT", 0.5, 2.0, 0.5),
        ("Fri, 31 Dec 9999 23:59:60 GMT", 0.5, 2.0, 0.5),
    ],
)
def test_retry_delay_applies_bounded_fallback_and_clamp(
    header_val: str, fallback: float, maximum: float, expected: float
) -> None:
    assert LETSClient._retry_delay(
        _retry_response(header_val), fallback=fallback, maximum=maximum
    ) == pytest.approx(expected)


def test_retry_delay_without_header_or_response_uses_bounded_fallback() -> None:
    resp = httpx.Response(429, request=httpx.Request("GET", "https://warden.test/v1/info"))
    assert LETSClient._retry_delay(resp, fallback=5.0, maximum=2.0) == 2.0
    assert LETSClient._retry_delay(None, fallback=0.5, maximum=2.0) == 0.5


@pytest.mark.parametrize("valid_timeout", [1, 0.25, 10.0, 100, threading.TIMEOUT_MAX])
def test_client_accepts_valid_numeric_timeouts(valid_timeout: int | float) -> None:
    transport = httpx.MockTransport(
        lambda req: httpx.Response(200, json={"status": "ok"}, request=req)
    )
    client = LETSClient("https://warden.test", transport=transport, total_timeout_s=valid_timeout)
    try:
        assert client._total_timeout_s == valid_timeout
    finally:
        client.close()


def test_client_idempotent_retry_exhaustion() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, request=request)

    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(handler),
        retry=RetryPolicy(max_attempts=3, initial_backoff_s=0.001, maximum_backoff_s=0.002),
        total_timeout_s=5.0,
    )
    try:
        with pytest.raises(RemoteUnavailableError):
            client.liveness()
        assert calls == 3
    finally:
        client.close()


@pytest.mark.parametrize("failure_mode", ["status_503", "connect_error"])
def test_client_preserves_idempotent_only_retries(failure_mode: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if failure_mode == "connect_error":
            raise httpx.ConnectError("injected transport failure", request=request)
        return httpx.Response(503, request=request)

    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(handler),
        retry=RetryPolicy(max_attempts=3, initial_backoff_s=0.001, maximum_backoff_s=0.002),
        total_timeout_s=5.0,
    )
    try:
        with pytest.raises((RemoteUnavailableError, httpx.ConnectError)):
            client._request("POST", "/v1/transition", payload={"test": True}, idempotent=False)
        assert calls == 1
    finally:
        client.close()


def test_client_info_accepts_valid_document_and_rejects_missing_or_invalid_fields() -> None:
    valid_doc = {"api_version": "v1", "protocol": "lets/1", "warden_id": "warden-a"}
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=valid_doc, request=req)),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        assert client.info() == valid_doc
    finally:
        client.close()

    for invalid in [
        {"api_version": "v1", "protocol": "lets/1"},
        {"protocol": "lets/1", "warden_id": "warden-a"},
        {"api_version": "v1", "warden_id": "warden-a"},
        {"api_version": "v2", "protocol": "lets/1", "warden_id": "warden-a"},
        {"api_version": "v1", "protocol": "lets/2", "warden_id": "warden-a"},
    ]:
        client = LETSClient(
            "https://warden.test",
            transport=httpx.MockTransport(
                lambda req, d=invalid: httpx.Response(200, json=d, request=req)
            ),
            retry=RetryPolicy(max_attempts=1),
        )
        try:
            with pytest.raises(RemoteValidationError):
                client.info()
        finally:
            client.close()


def test_client_keys_accepts_valid_and_rejects_missing_fields() -> None:
    valid_keys = {"warden_id": "warden-a", "keys": [{"key_id": "k1", "algorithm": "Ed25519"}]}
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=valid_keys, request=req)
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        assert client.keys() == valid_keys
    finally:
        client.close()

    for invalid in [{"warden_id": "warden-a"}, {"keys": []}]:
        client = LETSClient(
            "https://warden.test",
            transport=httpx.MockTransport(
                lambda req, d=invalid: httpx.Response(200, json=d, request=req)
            ),
            retry=RetryPolicy(max_attempts=1),
        )
        try:
            with pytest.raises(RemoteValidationError):
                client.keys()
        finally:
            client.close()


def test_client_authorize_accepts_valid_and_rejects_malformed_receipt() -> None:
    valid_receipt = {"type": "lets.receipt/v1", "receipt_id": "r-1", "signature": "sig-1"}
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=valid_receipt, request=req)
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    payload = {"request_id": "req-1", "executor_audience": "aud-1", "nonce": "n-1"}
    try:
        assert client.authorize("lease-1", payload) == valid_receipt
    finally:
        client.close()

    for invalid in [
        {"type": "lets.receipt/v1", "receipt_id": "r-1"},
        {"type": "lets.receipt/v1", "signature": "sig-1"},
        {"type": "lets.receipt/v2", "receipt_id": "r-1", "signature": "sig-1"},
        {"receipt_id": "r-1", "signature": "sig-1"},
    ]:
        client = LETSClient(
            "https://warden.test",
            transport=httpx.MockTransport(
                lambda req, d=invalid: httpx.Response(200, json=d, request=req)
            ),
            retry=RetryPolicy(max_attempts=1),
        )
        try:
            with pytest.raises(RemoteValidationError):
                client.authorize("lease-1", payload)
        finally:
            client.close()


def test_client_audit_and_verify_accept_valid_and_reject_malformed() -> None:
    valid_audit = {"records": [{"seq": 1}]}
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=valid_audit, request=req)
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        assert client.audit() == valid_audit
    finally:
        client.close()

    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={"audit": []}, request=req)
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(RemoteValidationError):
            client.audit()
    finally:
        client.close()

    valid_verify = {"valid": True}
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=valid_verify, request=req)
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        assert client.verify_audit() == valid_verify
    finally:
        client.close()

    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={"verified": True}, request=req)
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(RemoteValidationError):
            client.verify_audit()
    finally:
        client.close()


@pytest.mark.parametrize("status_code", [301, 302, 307, 308])
def test_client_rejects_redirect_responses(status_code: int) -> None:
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                status_code,
                headers={"Location": "https://other.test/v1/info"},
                request=req,
            )
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(RemoteValidationError) as raised:
            client.info()
        assert raised.value.problem.status == 502
    finally:
        client.close()


@pytest.mark.parametrize("response_args", [(204, b""), (200, b""), (200, b"   ")])
def test_client_rejects_empty_responses(response_args: tuple[int, bytes]) -> None:
    status_code, content = response_args
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(status_code, content=content, request=req)
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(RemoteValidationError):
            client.info()
    finally:
        client.close()


@pytest.mark.parametrize(
    "wrong_content",
    [b"[]", b"[1, 2, 3]", b"42", b'"success"', b"null", b"true"],
)
def test_client_rejects_wrong_root_type(wrong_content: bytes) -> None:
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                content=wrong_content,
                headers={"content-type": "application/json"},
                request=req,
            )
        ),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(RemoteValidationError):
            client.info()
    finally:
        client.close()


def test_client_rejects_unexpected_status_codes() -> None:
    valid_doc = {"api_version": "v1", "protocol": "lets/1", "warden_id": "warden-a"}
    client = LETSClient(
        "https://warden.test",
        transport=httpx.MockTransport(lambda req: httpx.Response(201, json=valid_doc, request=req)),
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        with pytest.raises(RemoteValidationError):
            client.info()
    finally:
        client.close()
