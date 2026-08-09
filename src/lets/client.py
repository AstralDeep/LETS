"""Synchronous, retry-disciplined HTTP clients for LETS nodes."""

from __future__ import annotations

import email.utils
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Self, cast
from urllib.parse import quote

import httpx

from lets.auth import PeerSigner, sign_peer_headers
from lets.canonical import canonical_json, strict_json_loads


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
    """Base exception for a typed remote RFC 9457 problem."""

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


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_backoff_s: float = 0.05
    maximum_backoff_s: float = 1.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least one")
        if self.initial_backoff_s < 0 or self.maximum_backoff_s < 0:
            raise ValueError("retry backoff values must be non-negative")


class LETSClient:
    """Blocking client with bounded retries only for idempotent operations."""

    _RETRYABLE_STATUS = frozenset({429, 502, 503, 504})

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        verify: bool | str = True,
        cert: str | tuple[str, str] | None = None,
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
        if total_timeout_s <= 0:
            raise ValueError("total_timeout_s must be positive")
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

            def create_client() -> httpx.Client:
                return httpx.Client(
                    base_url=base_url.rstrip("/") + "/",
                    headers=headers,
                    verify=verify,
                    cert=cert,
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
    def _retry_delay(response: httpx.Response | None, fallback: float, maximum: float) -> float:
        if response is None:
            return min(fallback, maximum)
        retry_after = response.headers.get("retry-after")
        if retry_after is None:
            return min(fallback, maximum)
        try:
            return min(max(float(retry_after), 0.0), maximum)
        except ValueError:
            try:
                retry_time = email.utils.parsedate_to_datetime(retry_after).timestamp()
            except (TypeError, ValueError, OverflowError):
                return min(fallback, maximum)
            return min(max(retry_time - time.time(), 0.0), maximum)

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        idempotent: bool,
        peer_signer: PeerSigner | None = None,
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
                if response.status_code == 204 or not response_content:
                    return None
                try:
                    return _response_json(response, response_content)
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

    def liveness(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._request("GET", "/health/live", idempotent=True))

    def readiness(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._request("GET", "/health/ready", idempotent=True))

    def info(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._request("GET", "/v1/info", idempotent=True))

    def keys(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._request("GET", "/v1/keys", idempotent=True))

    def create_envelope(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request("POST", "/v1/envelopes", payload=payload, idempotent=True),
        )

    def register_policy(self, policy: Mapping[str, Any]) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request("POST", "/v1/policies", payload=policy, idempotent=True),
        )

    def issue_root(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request("POST", "/v1/roots", payload=payload, idempotent=True),
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
            self._request("GET", f"/v1/leases/{self._id(lease_id)}", idempotent=True),
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
            ),
        )

    def reclaim(self, payload: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "POST", "/v1/maintenance/reclaim", payload=payload or {}, idempotent=True
            ),
        )

    def runtime_status(self) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request("GET", "/v1/maintenance/runtime", idempotent=True),
        )

    def set_runtime_mode(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request("POST", "/v1/maintenance/runtime", payload=payload, idempotent=True),
        )

    def invariants(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._request("GET", "/v1/invariants", idempotent=True))

    def metrics(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._request("GET", "/v1/metrics", idempotent=True))

    def audit(self, *, after_sequence: int = -1, limit: int = 100) -> Mapping[str, Any]:
        path = f"/v1/audit?after_sequence={after_sequence}&limit={limit}"
        return cast(Mapping[str, Any], self._request("GET", path, idempotent=True))

    def verify_audit(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._request("GET", "/v1/audit/verify", idempotent=True))

    def prepare_transfer(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self._idempotent_payload(payload)
        return cast(
            Mapping[str, Any],
            self._request("POST", "/v1/transfers/prepare", payload=payload, idempotent=True),
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
            ),
        )


JSON_MEDIA_TYPE = "application/json"


class PeerClient(LETSClient):
    """Message-signing warden client; all exposed operations are idempotent."""

    def __init__(self, base_url: str, *, signer: PeerSigner, **options: Any) -> None:
        super().__init__(base_url, **options)
        self._signer = signer

    def _signed_post(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return cast(
            Mapping[str, Any],
            self._request(
                "POST",
                path,
                payload=payload,
                idempotent=True,
                peer_signer=self._signer,
            ),
        )

    def accept_transfer(self, voucher: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._signed_post(
            "/v1/transfers/"
            f"{self._id(voucher['source_warden'])}/{self._id(voucher['sequence'])}/accept",
            voucher,
        )

    def finalize_transfer(self, acknowledgement: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._signed_post(
            "/v1/transfers/"
            f"{self._id(acknowledgement['target_warden'])}/"
            f"{self._id(acknowledgement['sequence'])}/finalize",
            acknowledgement,
        )

    def ingest_revocation(self, revocation: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._signed_post("/v1/peer/revocations", revocation)

    def ingest_transfer_checkpoint(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._signed_post("/v1/peer/transfer-checkpoints", checkpoint)
