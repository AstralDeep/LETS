"""Blocking HTTP client library for calling a LETS warden: LETSClient for application
operations and PeerClient for signed inter-warden messages, both retrying only
idempotent calls. Used by peer.py's dispatcher and by AstralDeep's orchestrator.
"""

from __future__ import annotations

import functools
import json
import math
import re
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple, Self, cast
from urllib.parse import quote

import httpx

from lets.auth import PeerSigner, sign_peer_headers
from lets.canonical import canonical_json, strict_json_loads

TLSVerify = bool | str | ssl.SSLContext
TLSCertificate = str | tuple[str, str] | tuple[str, str, str]


def _httpx_tls_configuration(
    verify: TLSVerify,
    cert: TLSCertificate | None,
) -> tuple[TLSVerify, TLSCertificate | None]:
    context: ssl.SSLContext
    if isinstance(verify, str):
        trust = Path(verify)
        context = (
            ssl.create_default_context(capath=verify)
            if trust.is_dir()
            else ssl.create_default_context(cafile=verify)
        )
    elif cert is None:
        return verify, None
    elif isinstance(verify, ssl.SSLContext):
        context = verify
    elif verify:
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if cert is not None:
        if isinstance(cert, str):
            context.load_cert_chain(cert)
        else:
            context.load_cert_chain(*cert)
    return context, None


def _response_json(response: httpx.Response, content: bytes | None = None) -> Any:
    return strict_json_loads(response.content if content is None else content)


@dataclass(frozen=True, slots=True)
class ProblemDetails:
    type: str
    title: str
    status: int
    detail: str
    instance: str | None
    code: str
    request_id: str | None

    @classmethod
    def from_response(cls, response: httpx.Response, content: bytes | None = None) -> Self:
        try:
            raw = _response_json(response, content)
        except (ValueError, UnicodeDecodeError):
            raw = {}
        body = raw if isinstance(raw, Mapping) else {}
        status = body.get("status", response.status_code)
        if (
            isinstance(status, bool)
            or not isinstance(status, int)
            or status != response.status_code
        ):
            status = response.status_code
        code = body.get("code", f"http_{response.status_code}")
        if not isinstance(code, str):
            code = f"http_{response.status_code}"
        detail = body.get("detail", response.reason_phrase or "remote LETS request failed")
        if not isinstance(detail, str):
            detail = "remote LETS request failed"
        title = body.get("title", "LETS request failed")
        if not isinstance(title, str):
            title = "LETS request failed"
        problem_type = body.get("type", f"urn:lets:problem:{code}")
        if not isinstance(problem_type, str):
            problem_type = f"urn:lets:problem:{code}"
        instance = body.get("instance")
        if not isinstance(instance, str):
            instance = None
        request_id = body.get("request_id", response.headers.get("x-request-id"))
        if not isinstance(request_id, str):
            request_id = None
        return cls(
            type=problem_type,
            title=title,
            status=status,
            detail=detail,
            instance=instance,
            code=code,
            request_id=request_id,
        )


class LETSClientError(Exception):
    def __init__(self, problem: ProblemDetails) -> None:
        self.problem = problem
        super().__init__(f"{problem.code}: {problem.detail}")

    @property
    def status_code(self) -> int:
        return self.problem.status


class AuthenticationFailedError(LETSClientError):
    pass


class PermissionDeniedError(LETSClientError):
    pass


class ResourceNotFoundError(LETSClientError):
    pass


class RequestConflictError(LETSClientError):
    pass


class RemoteValidationError(LETSClientError):
    pass


class RemoteUnavailableError(LETSClientError):
    pass


def _problem_error(response: httpx.Response, content: bytes | None = None) -> LETSClientError:
    problem = ProblemDetails.from_response(response, content)
    exception_type: type[LETSClientError]
    if response.status_code == 401:
        exception_type = AuthenticationFailedError
    elif response.status_code == 403:
        exception_type = PermissionDeniedError
    elif response.status_code == 404:
        exception_type = ResourceNotFoundError
    elif response.status_code in {409, 410}:
        exception_type = RequestConflictError
    elif response.status_code in {400, 413, 415, 422}:
        exception_type = RemoteValidationError
    elif response.status_code >= 500:
        exception_type = RemoteUnavailableError
    else:
        exception_type = LETSClientError
    return exception_type(problem)


def _require_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer, not boolean or float")


def _require_finite_real(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a real number, not boolean or other type")
    try:
        converted = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be finite") from exc
    if not math.isfinite(converted):
        raise ValueError(f"{name} must be finite")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_backoff_s: float = 0.05
    maximum_backoff_s: float = 1.0

    def __post_init__(self) -> None:
        _require_int("max_attempts", self.max_attempts)
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
        _require_finite_real("initial_backoff_s", self.initial_backoff_s)
        _require_finite_real("maximum_backoff_s", self.maximum_backoff_s)
        if self.initial_backoff_s < 0 or self.maximum_backoff_s < 0:
            raise ValueError("retry backoff values must be non-negative")


_IMF_FIXDATE_RE = re.compile(
    r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), ([0-3][0-9]) "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) "
    r"([0-2][0-9]):([0-5][0-9]):([0-5][0-9]|60) GMT$"
)
_RFC850_DATE_RE = re.compile(
    r"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), ([0-3][0-9])-"
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-([0-9]{2}) "
    r"([0-2][0-9]):([0-5][0-9]):([0-5][0-9]|60) GMT$"
)
_ASCTIME_DATE_RE = re.compile(
    r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?: ([1-9])|([0-3][0-9])) "
    r"([0-2][0-9]):([0-5][0-9]):([0-5][0-9]|60) ([0-9]{4})$"
)

_MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_WEEKDAY_INDEX = {
    "Mon": 0,
    "Tue": 1,
    "Wed": 2,
    "Thu": 3,
    "Fri": 4,
    "Sat": 5,
    "Sun": 6,
}


class LETSClient:
    _RETRYABLE_STATUS = frozenset({429, 502, 503, 504})

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        verify: TLSVerify = True,
        cert: TLSCertificate | None = None,
        timeout: float | httpx.Timeout = 10.0,
        total_timeout_s: float = 10.0,
        max_response_bytes: int = 1_048_576,
        retry: RetryPolicy | None = None,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if client is not None and transport is not None:
            raise ValueError("pass either client or transport, not both")
        _require_finite_real("total_timeout_s", total_timeout_s)
        if total_timeout_s <= 0:
            raise ValueError("total_timeout_s must be positive")
        if total_timeout_s > threading.TIMEOUT_MAX:
            raise ValueError("total_timeout_s must not exceed the platform timeout limit")
        _require_int("max_response_bytes", max_response_bytes)
        if max_response_bytes < 1 or max_response_bytes > 16_777_216:
            raise ValueError("max_response_bytes must be between 1 and 16777216")
        headers = {"accept": JSON_MEDIA_TYPE}
        if token is not None:
            if not token:
                raise ValueError("token cannot be empty")
            headers["authorization"] = f"Bearer {token}"
        self._owns_client = client is None
        self._client_factory: Callable[[], httpx.Client] | None = None
        if client is None:
            tls_verify, tls_cert = _httpx_tls_configuration(verify, cert)

            def create_client() -> httpx.Client:
                return httpx.Client(
                    base_url=base_url.rstrip("/") + "/",
                    headers=headers,
                    verify=tls_verify,
                    cert=tls_cert,
                    timeout=timeout,
                    transport=transport,
                    follow_redirects=False,
                )

            self._client_factory = create_client
            self._client = create_client()
        else:
            self._client = client
        self._retry = retry or RetryPolicy()
        self._sleep = sleep
        self._total_timeout_s = total_timeout_s
        self._max_response_bytes = max_response_bytes
        self._request_lock = threading.Lock()
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        if self._owns_client:
            self._client.close()

    def _read_bounded(self, response: httpx.Response, deadline_fired: threading.Event) -> bytes:
        content = bytearray()
        for chunk in response.iter_bytes():
            if deadline_fired.is_set():
                raise httpx.TimeoutException("LETS request exceeded its total wall-clock deadline")
            if len(content) > self._max_response_bytes - len(chunk):
                raise RemoteValidationError(
                    ProblemDetails(
                        type="urn:lets:problem:response_too_large",
                        title="LETS response exceeds the configured limit",
                        status=502,
                        detail=f"remote response exceeds {self._max_response_bytes} bytes",
                        instance=str(response.request.url),
                        code="response_too_large",
                        request_id=response.headers.get("x-request-id"),
                    )
                )
            content.extend(chunk)
        return bytes(content)

    @staticmethod
    def _parse_retry_after(value: str, now: datetime) -> float | None:
        if value.isdigit() and value.isascii():
            try:
                return float(int(value))
            except (ValueError, OverflowError):
                return math.inf

        m_imf = _IMF_FIXDATE_RE.match(value)
        if m_imf:
            wk_s, day_s, mon_s, yr_s, hr_s, min_s, sec_s = m_imf.groups()
            year = int(yr_s)
            if year < 1900:
                return None
            sec = int(sec_s)
            try:
                dt = datetime(
                    year,
                    _MONTH_MAP[mon_s],
                    int(day_s),
                    int(hr_s),
                    int(min_s),
                    min(sec, 59),
                    tzinfo=UTC,
                )
                if _WEEKDAY_INDEX[wk_s] != dt.weekday():
                    return None
                if sec == 60:
                    dt += timedelta(seconds=1)
                return (dt - now).total_seconds()
            except (TypeError, ValueError, OverflowError):
                return None

        m_rfc850 = _RFC850_DATE_RE.match(value)
        if m_rfc850:
            wk_s, day_s, mon_s, yr2_s, hr_s, min_s, sec_s = m_rfc850.groups()
            sec = int(sec_s)
            try:
                calendar_dt = datetime(
                    (now.year // 100) * 100 + int(yr2_s),
                    _MONTH_MAP[mon_s],
                    int(day_s),
                    int(hr_s),
                    int(min_s),
                    min(sec, 59),
                    tzinfo=UTC,
                )
                effective_dt = calendar_dt + timedelta(seconds=1 if sec == 60 else 0)
                # RFC 9110 §5.6.7: values more than 50 years ahead mean the past century.
                try:
                    future_threshold = now.replace(year=now.year + 50)
                except ValueError:
                    future_threshold = now.replace(year=now.year + 50, day=28)
                if effective_dt > future_threshold:
                    calendar_dt = calendar_dt.replace(year=calendar_dt.year - 100)
                    effective_dt = effective_dt.replace(year=effective_dt.year - 100)
                if _WEEKDAY_INDEX[wk_s[:3]] != calendar_dt.weekday():
                    return None
                return (effective_dt - now).total_seconds()
            except (TypeError, ValueError, OverflowError):
                return None

        m_asc = _ASCTIME_DATE_RE.match(value)
        if m_asc:
            wk_s, mon_s, day_sp, day_2d, hr_s, min_s, sec_s, yr_s = m_asc.groups()
            year = int(yr_s)
            if year < 1900:
                return None
            sec = int(sec_s)
            try:
                dt = datetime(
                    year,
                    _MONTH_MAP[mon_s],
                    int(day_sp if day_sp is not None else day_2d),
                    int(hr_s),
                    int(min_s),
                    min(sec, 59),
                    tzinfo=UTC,
                )
                if _WEEKDAY_INDEX[wk_s] != dt.weekday():
                    return None
                if sec == 60:
                    dt += timedelta(seconds=1)
                return (dt - now).total_seconds()
            except (TypeError, ValueError, OverflowError):
                return None

        return None

    @staticmethod
    def _retry_delay(response: httpx.Response | None, fallback: float, maximum: float) -> float:
        safe_fallback = min(fallback, maximum)
        if response is None:
            return safe_fallback
        header = response.headers.get("retry-after")
        if header is None:
            return safe_fallback
        delay = LETSClient._parse_retry_after(header.strip(), datetime.now(UTC))
        if delay is None:
            return safe_fallback
        return min(max(delay, 0.0), maximum)

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        idempotent: bool,
        peer_signer: PeerSigner | None = None,
        endpoint_template: str | None = None,
    ) -> Any:
        with self._request_lock:
            if self._closed:
                raise RuntimeError("LETS client is closed")
            body = b"" if payload is None else canonical_json(payload)
            base_headers = {"content-type": JSON_MEDIA_TYPE} if payload is not None else {}
            backoff = self._retry.initial_backoff_s
            response: httpx.Response | None = None
            response_content = b""
            active_client = self._client
            deadline_fired = threading.Event()
            deadline = time.monotonic() + self._total_timeout_s

            def deadline_error() -> httpx.TimeoutException:
                return httpx.TimeoutException("LETS request exceeded its total wall-clock deadline")

            def wait_for_retry(delay: float) -> None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    deadline_fired.set()
                    raise deadline_error()
                bounded_delay = min(delay, remaining)
                if self._sleep is time.sleep:
                    interrupted = deadline_fired.wait(bounded_delay)
                else:
                    self._sleep(bounded_delay)
                    interrupted = deadline_fired.is_set()
                if interrupted or delay >= remaining or time.monotonic() >= deadline:
                    deadline_fired.set()
                    raise deadline_error()

            def abort_at_deadline() -> None:
                deadline_fired.set()
                active_client.close()

            watchdog = threading.Timer(self._total_timeout_s, abort_at_deadline)
            watchdog.daemon = True
            watchdog.start()
            try:
                for attempt in range(1, self._retry.max_attempts + 1):
                    if deadline_fired.is_set():
                        raise deadline_error()
                    headers = dict(base_headers)
                    if peer_signer is not None:
                        headers.update(
                            sign_peer_headers(
                                peer_signer,
                                method=method,
                                path=path,
                                body=body,
                            )
                        )
                    try:
                        with active_client.stream(
                            method, path, content=body, headers=headers
                        ) as response:
                            if (
                                idempotent
                                and response.status_code in self._RETRYABLE_STATUS
                                and attempt < self._retry.max_attempts
                            ):
                                delay = self._retry_delay(
                                    response,
                                    backoff,
                                    self._retry.maximum_backoff_s,
                                )
                            else:
                                response_content = self._read_bounded(response, deadline_fired)
                                break
                    except httpx.TransportError as error:
                        if deadline_fired.is_set():
                            raise deadline_error() from error
                        if not idempotent or attempt == self._retry.max_attempts:
                            raise
                        wait_for_retry(min(backoff, self._retry.maximum_backoff_s))
                        backoff = min(backoff * 2, self._retry.maximum_backoff_s)
                        continue
                    wait_for_retry(delay)
                    backoff = min(backoff * 2, self._retry.maximum_backoff_s)
                if deadline_fired.is_set() or time.monotonic() >= deadline:
                    raise deadline_error()
                if response is None:
                    raise RuntimeError(
                        "HTTP request produced neither a response nor a transport error"
                    )
                if response.is_error:
                    raise _problem_error(response, response_content)
                if response.is_redirect or 300 <= response.status_code < 400:
                    raise RemoteValidationError(
                        ProblemDetails(
                            type="urn:lets:problem:invalid_response",
                            title="Invalid LETS Response",
                            status=502,
                            detail=(
                                "the remote node returned an unexpected redirect status "
                                f"{response.status_code}"
                            ),
                            instance=path,
                            code="invalid_response",
                            request_id=response.headers.get("x-request-id"),
                        )
                    )
                if response.status_code == 204 or not response_content:
                    raise RemoteValidationError(
                        ProblemDetails(
                            type="urn:lets:problem:invalid_response",
                            title="Invalid LETS Response",
                            status=502,
                            detail="the remote node returned an empty response",
                            instance=path,
                            code="invalid_response",
                            request_id=response.headers.get("x-request-id"),
                        )
                    )
                try:
                    data = _response_json(response, response_content)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise RemoteValidationError(
                        ProblemDetails(
                            type="urn:lets:problem:invalid_response",
                            title="Invalid LETS Response",
                            status=502,
                            detail="the remote node returned a non-JSON success response",
                            instance=path,
                            code="invalid_response",
                            request_id=response.headers.get("x-request-id"),
                        )
                    ) from exc
                template = endpoint_template or path.split("?")[0]
                contract = _contract_map().get((method.upper(), template))
                if contract is not None and response.status_code not in contract.allowed_statuses:
                    raise RemoteValidationError(
                        ProblemDetails(
                            type="urn:lets:problem:invalid_response",
                            title="Invalid LETS Response",
                            status=502,
                            detail=(
                                "the remote node returned unexpected status "
                                f"{response.status_code} for {path}"
                            ),
                            instance=path,
                            code="invalid_response",
                            request_id=response.headers.get("x-request-id"),
                        )
                    )
                return self._validate_contract(
                    data,
                    method=method,
                    template=template,
                    instance=path,
                    request_id=response.headers.get("x-request-id"),
                )
            finally:
                watchdog.cancel()
                watchdog.join()
                if (
                    deadline_fired.is_set()
                    and self._client_factory is not None
                    and not self._closed
                ):
                    self._client = self._client_factory()

    @staticmethod
    def _id(value: object) -> str:
        return quote(str(value), safe="")

    @staticmethod
    def _idempotent_payload(payload: Mapping[str, Any]) -> None:
        request_id = payload.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("an idempotent mutation requires a non-empty request_id")

    def _validate_contract(
        self,
        result: Any,
        *,
        method: str,
        template: str,
        instance: str,
        request_id: str | None = None,
    ) -> Mapping[str, Any]:
        if not isinstance(result, Mapping):
            raise RemoteValidationError(
                ProblemDetails(
                    type="urn:lets:problem:invalid_response",
                    title="Invalid LETS Response",
                    status=502,
                    detail=f"the remote node returned a non-object response for {instance}",
                    instance=instance,
                    code="invalid_response",
                    request_id=request_id,
                )
            )
        contract = _contract_map().get((method.upper(), template))
        if contract is not None:
            for field in contract.required_fields:
                if field not in result or result[field] is None:
                    raise RemoteValidationError(
                        ProblemDetails(
                            type="urn:lets:problem:invalid_response",
                            title="Invalid LETS Response",
                            status=502,
                            detail=(
                                f"the remote response for {instance} is missing required field "
                                f"'{field}'"
                            ),
                            instance=instance,
                            code="invalid_response",
                            request_id=request_id,
                        )
                    )
            for field, expected in contract.const_fields:
                if (field in contract.required_fields or field in result) and result.get(
                    field
                ) != expected:
                    raise RemoteValidationError(
                        ProblemDetails(
                            type="urn:lets:problem:invalid_response",
                            title="Invalid LETS Response",
                            status=502,
                            detail=(
                                f"the remote response for {instance} has invalid {field}: "
                                f"expected '{expected}'"
                            ),
                            instance=instance,
                            code="invalid_response",
                            request_id=request_id,
                        )
                    )
        return result

    def _validate_mapping(
        self, result: Any, path: str, required_fields: tuple[str, ...] = ()
    ) -> Mapping[str, Any]:
        if not isinstance(result, Mapping):
            raise RemoteValidationError(
                ProblemDetails(
                    type="urn:lets:problem:invalid_response",
                    title="Invalid LETS Response",
                    status=502,
                    detail=f"the remote node returned a non-object response for {path}",
                    instance=path,
                    code="invalid_response",
                    request_id=None,
                )
            )
        for field in required_fields:
            if field not in result or result[field] is None:
                raise RemoteValidationError(
                    ProblemDetails(
                        type="urn:lets:problem:invalid_response",
                        title="Invalid LETS Response",
                        status=502,
                        detail=(
                            f"the remote response for {path} is missing required field '{field}'"
                        ),
                        instance=path,
                        code="invalid_response",
                        request_id=None,
                    )
                )
        return result

    def liveness(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request("GET", "/health/live", idempotent=True, endpoint_template="/health/live"),
        )

    def readiness(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "GET", "/health/ready", idempotent=True, endpoint_template="/health/ready"
            ),
        )

    def info(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request("GET", "/v1/info", idempotent=True, endpoint_template="/v1/info"),
        )

    def keys(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request("GET", "/v1/keys", idempotent=True, endpoint_template="/v1/keys"),
        )

    def create_envelope(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                "/v1/envelopes",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/envelopes",
            ),
        )

    def register_policy(self, policy: Mapping[str, Any]) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                "/v1/policies",
                payload=policy,
                idempotent=True,
                endpoint_template="/v1/policies",
            ),
        )

    def issue_root(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                "/v1/roots",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/roots",
            ),
        )

    def spawn(self, parent_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                f"/v1/leases/{self._id(parent_id)}/children",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/leases/{parent_id}/children",
            ),
        )

    def authorize(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        if "executor_audience" not in payload or "audience" in payload:
            raise ValueError("transition requests require canonical executor_audience")
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                f"/v1/leases/{self._id(lease_id)}/transitions",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/leases/{lease_id}/transitions",
            ),
        )

    def renew(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                f"/v1/leases/{self._id(lease_id)}/renew",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/leases/{lease_id}/renew",
            ),
        )

    def _lifecycle(
        self, operation: str, lease_id: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                f"/v1/leases/{self._id(lease_id)}/{operation}",
                payload=payload,
                idempotent=True,
                endpoint_template=f"/v1/leases/{{lease_id}}/{operation}",
            ),
        )

    def quiesce(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._lifecycle("quiesce", lease_id, payload)

    def resume(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._lifecycle("resume", lease_id, payload)

    def close_lease(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._lifecycle("close", lease_id, payload)

    def lease(self, lease_id: str) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "GET",
                f"/v1/leases/{self._id(lease_id)}",
                idempotent=True,
                endpoint_template="/v1/leases/{lease_id}",
            ),
        )

    def revoke_branch(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                f"/v1/branches/{self._id(lease_id)}/revoke",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/branches/{lease_id}/revoke",
            ),
        )

    def reclaim(self, payload: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                "/v1/maintenance/reclaim",
                payload=payload or {},
                idempotent=True,
                endpoint_template="/v1/maintenance/reclaim",
            ),
        )

    def runtime_status(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "GET",
                "/v1/maintenance/runtime",
                idempotent=True,
                endpoint_template="/v1/maintenance/runtime",
            ),
        )

    def set_runtime_mode(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                "/v1/maintenance/runtime",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/maintenance/runtime",
            ),
        )

    def invariants(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "GET",
                "/v1/invariants",
                idempotent=True,
                endpoint_template="/v1/invariants",
            ),
        )

    def metrics(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "GET",
                "/v1/metrics",
                idempotent=True,
                endpoint_template="/v1/metrics",
            ),
        )

    def audit(self, *, after_sequence: int = -1, limit: int = 100) -> Mapping[str, Any]:
        path = f"/v1/audit?after_sequence={after_sequence}&limit={limit}"
        return cast(
            Mapping[str, Any],
            self._request(
                "GET",
                path,
                idempotent=True,
                endpoint_template="/v1/audit",
            ),
        )

    def verify_audit(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "GET",
                "/v1/audit/verify",
                idempotent=True,
                endpoint_template="/v1/audit/verify",
            ),
        )

    def prepare_transfer(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                "/v1/transfers/prepare",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/transfers/prepare",
            ),
        )

    def create_transfer_checkpoint(
        self,
        target_warden: str,
        *,
        through_sequence: int | None = None,
    ) -> Mapping[str, Any]:
        payload = {} if through_sequence is None else {"through_sequence": through_sequence}
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                f"/v1/transfers/{self._id(target_warden)}/checkpoints",
                payload=payload,
                idempotent=True,
                endpoint_template="/v1/transfers/{target_warden}/checkpoints",
            ),
        )


class _EndpointContract(NamedTuple):
    allowed_statuses: frozenset[int]
    required_fields: tuple[str, ...]
    const_fields: tuple[tuple[str, str], ...]


@functools.cache
def _contract_map() -> dict[tuple[str, str], _EndpointContract]:
    contract_file = Path(__file__).resolve().parents[2] / "protocol" / "openapi.yaml"
    contracts: dict[tuple[str, str], _EndpointContract] = {
        ("GET", "/health/live"): _EndpointContract(frozenset({200}), (), ()),
        ("GET", "/health/ready"): _EndpointContract(frozenset({200}), (), ()),
    }
    if not contract_file.is_file():
        return contracts
    try:
        spec = json.loads(contract_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return contracts
    schemas = spec.get("components", {}).get("schemas", {})
    for path, methods in spec.get("paths", {}).items():
        if not isinstance(methods, Mapping):
            continue
        for method, op in methods.items():
            if not isinstance(op, Mapping):
                continue
            resps = op.get("responses", {})
            if not isinstance(resps, Mapping):
                continue
            allowed = frozenset(int(c) for c in resps if c.isdigit() and c.startswith("2"))
            if not allowed:
                continue
            success_code = next((str(c) for c in (200, 201) if str(c) in resps), None)
            req_fields: tuple[str, ...] = ()
            const_fields: list[tuple[str, str]] = []
            if success_code is not None:
                content = resps[success_code].get("content", {}).get("application/json", {})
                schema_ref = content.get("schema", {}).get("$ref")
                if schema_ref and isinstance(schema_ref, str):
                    sname = schema_ref.rsplit("/", 1)[-1]
                    s = schemas.get(sname, {})
                    if isinstance(s, Mapping):
                        if sname == "LeaseGrant":
                            req_fields = ("lease_id",)
                        elif sname == "LeaseSnapshot":
                            req_fields = ("type", "grant")
                        elif sname == "Receipt":
                            req_fields = ("type", "receipt_id", "signature")
                        else:
                            req_fields = tuple(s.get("required", ()))
                        props = s.get("properties", {})
                        if isinstance(props, Mapping):
                            for pname, pval in props.items():
                                if isinstance(pval, Mapping) and "const" in pval:
                                    const_fields.append((pname, str(pval["const"])))
            contracts[(method.upper(), path)] = _EndpointContract(
                allowed, req_fields, tuple(const_fields)
            )
    return contracts


JSON_MEDIA_TYPE = "application/json"


class PeerClient(LETSClient):
    def __init__(self, base_url: str, *, signer: PeerSigner, **options: Any) -> None:
        super().__init__(base_url, **options)
        self._signer = signer

    def _signed_post(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        endpoint_template: str | None = None,
    ) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                path,
                payload=payload,
                idempotent=True,
                peer_signer=self._signer,
                endpoint_template=endpoint_template,
            ),
        )

    def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._signed_post(
            "/v1/transfers/"
            f"{self._id(voucher['source_warden'])}/{self._id(voucher['sequence'])}/accept",
            voucher,
            endpoint_template="/v1/transfers/{source_warden}/{sequence}/accept",
        )

    def finalize_transfer(self, acknowledgement: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._signed_post(
            "/v1/transfers/"
            f"{self._id(acknowledgement['target_warden'])}/"
            f"{self._id(acknowledgement['sequence'])}/finalize",
            acknowledgement,
            endpoint_template="/v1/transfers/{target_warden}/{sequence}/finalize",
        )

    def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._signed_post(
            "/v1/peer/revocations",
            revocation,
            endpoint_template="/v1/peer/revocations",
        )

    def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._signed_post(
            "/v1/peer/transfer-checkpoints",
            checkpoint,
            endpoint_template="/v1/peer/transfer-checkpoints",
        )
