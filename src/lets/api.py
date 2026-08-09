"""FastAPI transport for a standalone LETS warden node."""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, is_dataclass
from functools import partial
from typing import Annotated, Any, cast

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from lets.auth import (
    AuthenticationError,
    IdentityAuthenticator,
    PeerIdentity,
    PeerMessageAuthenticator,
)
from lets.canonical import b64url_encode, strict_json_loads
from lets.errors import (
    ClockUncertainError,
    ConflictError,
    ExpiredError,
    InvariantError,
    LETSError,
    NotFoundError,
    PolicyError,
    ReplayError,
    SignatureError,
    StorageError,
    ValidationError,
)
from lets.ids import new_id
from lets.models import IdentityContext
from lets.policy import MAX_TRANSFER_GAP_WINDOW

API_VERSION = "v1"
REQUEST_ID_HEADER = "x-request-id"
PROBLEM_MEDIA_TYPE = "application/problem+json"
JSON_MEDIA_TYPE = "application/json"
LOGGER = logging.getLogger("lets.api")
WARDEN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"
KEY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._~:/+-]{0,511}$"

WardenPath = Annotated[str, Path(pattern=WARDEN_ID_PATTERN)]
PositiveTransferSequence = Annotated[int, Path(ge=1)]


class ServiceMethodUnavailableError(StorageError):
    """The configured core does not implement a required node-plane method."""

    code = "service_method_unavailable"


def _status_for(error: Exception) -> int:
    if isinstance(error, AuthenticationError):
        return 401
    if isinstance(error, SignatureError):
        return 401
    if isinstance(error, NotFoundError):
        return 404
    if isinstance(error, ExpiredError):
        return 410
    if isinstance(error, (ConflictError, ReplayError)):
        return 409
    if isinstance(error, ValidationError):
        return 422
    if isinstance(error, ClockUncertainError):
        return 503
    if isinstance(error, PolicyError):
        return 403
    if isinstance(error, ServiceMethodUnavailableError):
        return 501
    if isinstance(error, StorageError):
        return 503
    if isinstance(error, InvariantError):
        return 500
    return 500


def _title_for(status_code: int) -> str:
    return {
        400: "Bad Request",
        401: "Authentication Required",
        403: "Request Denied",
        404: "Not Found",
        409: "Conflict",
        410: "Gone",
        413: "Content Too Large",
        422: "Validation Failed",
        500: "Internal Server Error",
        501: "Not Implemented",
        503: "Service Unavailable",
    }.get(status_code, "Request Failed")


def _problem_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    detail: str,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", new_id("request"))
    body = {
        "type": f"urn:lets:problem:{code}",
        "title": _title_for(status_code),
        "status": status_code,
        "detail": detail,
        "instance": request.url.path,
        "code": code,
        "request_id": request_id,
    }
    response_headers = {"cache-control": "no-store"}
    if headers is not None:
        response_headers.update(headers)
    return JSONResponse(
        body,
        status_code=status_code,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=response_headers,
    )


def _wire(value: object) -> object:
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _wire(to_dict())
    if is_dataclass(value) and not isinstance(value, type):
        return _wire(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _wire(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_wire(item) for item in value]
    return value


def _json_response(value: object, *, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        _wire(value),
        status_code=status_code,
        media_type=JSON_MEDIA_TYPE,
        headers={"cache-control": "no-store"},
    )


async def _invoke(method: Callable[..., object], /, **arguments: object) -> object:
    result = await run_in_threadpool(partial(method, **arguments))
    if inspect.isawaitable(result):
        return await cast(Awaitable[object], result)
    return result


async def _authenticate(
    authenticator: IdentityAuthenticator,
    request: Request,
) -> IdentityContext:
    result = authenticator.authenticate(request)
    if inspect.isawaitable(result):
        result = await result
    if not isinstance(result, IdentityContext):
        raise AuthenticationError("the client authenticator returned no valid identity")
    return result


async def _json_object(request: Request, *, maximum_bytes: int) -> dict[str, Any]:
    body = await request.body()
    if len(body) > maximum_bytes:
        raise HTTPException(status_code=413, detail="request body exceeds the configured limit")
    if not body:
        return {}
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if content_type != JSON_MEDIA_TYPE:
        raise HTTPException(status_code=415, detail="application/json is required")
    try:
        decoded = strict_json_loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="request body is not valid JSON") from exc
    except ValueError as exc:
        raise ValidationError(f"request JSON is outside LETS-CJ/1: {exc}") from exc
    if not isinstance(decoded, dict):
        raise ValidationError("request body must be a JSON object")
    return cast(dict[str, Any], decoded)


async def _buffer_bounded_body(request: Request, *, maximum_bytes: int) -> bool:
    """Buffer at most the configured request bytes before any authenticator runs."""

    if request.method not in {"POST", "PUT", "PATCH"}:
        return True
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > maximum_bytes:
                return False
        except ValueError:
            # The HTTP server normally rejects this first; fail closed if it reaches us.
            return False
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > maximum_bytes:
            return False
        chunks.append(chunk)
    request._body = b"".join(chunks)
    return True


def _fields(
    body: Mapping[str, Any],
    *,
    required: frozenset[str] = frozenset(),
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    missing = required - body.keys()
    if missing:
        raise ValidationError(f"missing request fields: {sorted(missing)}")
    unknown = body.keys() - required - optional
    if unknown:
        raise ValidationError(f"unknown request fields: {sorted(unknown)}")
    return dict(body)


def _require_admin(identity: IdentityContext) -> None:
    if not identity.scopes.intersection({"lets.admin", "lets.warden.admin"}):
        raise PolicyError("warden administration scope is required")


def _method(service: object, name: str) -> Callable[..., object]:
    candidate = getattr(service, name, None)
    if not callable(candidate):
        raise ServiceMethodUnavailableError(f"the warden core does not implement {name}()")
    return cast(Callable[..., object], candidate)


def create_app(
    service: object,
    *,
    authenticator: IdentityAuthenticator,
    signer: object | None = None,
    peer_authenticator: PeerMessageAuthenticator | None = None,
    peer_tenant_id: str | None = None,
    readiness_check: Callable[[], bool | Awaitable[bool]] | None = None,
    metrics_provider: Callable[[], Mapping[str, object] | Awaitable[Mapping[str, object]]]
    | None = None,
    node_metadata: Mapping[str, object] | None = None,
    maximum_body_bytes: int = 2 * 1024 * 1024,
) -> FastAPI:
    """Build an authenticated LETS API without coupling the core to FastAPI.

    ``peer_tenant_id`` is trusted node configuration, not a value read from a
    voucher.  It is required whenever peer routes are enabled so the service's
    tenant-bound ``IdentityContext`` remains transport-derived.
    """

    if maximum_body_bytes <= 0:
        raise ValueError("maximum_body_bytes must be positive")
    if peer_authenticator is not None and not peer_tenant_id:
        raise ValueError("peer_tenant_id is required when peer authentication is enabled")

    app = FastAPI(
        title="LETS Warden API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/v1/openapi.json",
    )
    app.state.service = service

    @app.middleware("http")
    async def request_ids(request: Request, call_next: Callable[[Request], Awaitable[Any]]) -> Any:
        supplied = request.headers.get(REQUEST_ID_HEADER)
        if supplied is not None and (
            not supplied.isascii()
            or not 1 <= len(supplied) <= 128
            or any(character.isspace() for character in supplied)
        ):
            request.state.request_id = new_id("request")
            response = _problem_response(
                request,
                status_code=400,
                code="invalid_request_id",
                detail="X-Request-ID must contain 1..128 non-whitespace ASCII characters",
            )
        else:
            request.state.request_id = supplied or new_id("request")
            if not await _buffer_bounded_body(request, maximum_bytes=maximum_body_bytes):
                response = _problem_response(
                    request,
                    status_code=413,
                    code="http_413",
                    detail="request body exceeds the configured limit",
                )
            else:
                response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(LETSError)
    async def lets_error(request: Request, error: LETSError) -> JSONResponse:
        status_code = _status_for(error)
        headers = {"WWW-Authenticate": "Bearer"} if status_code == 401 else None
        return _problem_response(
            request,
            status_code=status_code,
            code=error.code,
            detail=str(error),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation(request: Request, error: RequestValidationError) -> JSONResponse:
        return _problem_response(
            request,
            status_code=422,
            code="validation_error",
            detail=str(error),
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException) -> JSONResponse:
        detail = error.detail if isinstance(error.detail, str) else "the HTTP request was rejected"
        return _problem_response(
            request,
            status_code=error.status_code,
            code=f"http_{error.status_code}",
            detail=detail,
            headers=error.headers,
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, error: Exception) -> JSONResponse:
        LOGGER.error(
            "unhandled LETS API error request_id=%s path=%s",
            getattr(request.state, "request_id", "unassigned"),
            request.url.path,
            exc_info=(type(error), error, error.__traceback__),
        )
        return _problem_response(
            request,
            status_code=500,
            code="internal_error",
            detail="the warden could not complete the request",
        )

    async def client_identity(request: Request) -> IdentityContext:
        return await _authenticate(authenticator, request)

    async def peer_identity(request: Request) -> tuple[PeerIdentity, IdentityContext]:
        if peer_authenticator is None or peer_tenant_id is None:
            raise ServiceMethodUnavailableError("peer authentication is not configured")
        peer = await peer_authenticator.authenticate(request)
        identity = IdentityContext(
            subject_id=peer.warden_id,
            tenant_id=peer_tenant_id,
            scopes=frozenset(
                {
                    "lets.transfer",
                    "lets.peer",
                    "lets.revocation.propagate",
                }
            ),
            authentication_method="peer-ed25519",
        )
        return peer, identity

    @app.get("/health/live", include_in_schema=False)
    async def liveness() -> JSONResponse:
        return _json_response({"status": "live"})

    @app.get("/health/ready", include_in_schema=False)
    async def readiness(request: Request) -> JSONResponse:
        ready = True
        if readiness_check is not None:
            result = await run_in_threadpool(readiness_check)
            ready = bool(await result) if inspect.isawaitable(result) else bool(result)
        if not ready:
            return _problem_response(
                request,
                status_code=503,
                code="not_ready",
                detail="the warden has not completed its readiness checks",
            )
        return _json_response({"status": "ready"})

    @app.get("/v1/info")
    async def info() -> JSONResponse:
        document: dict[str, object] = {
            "api_version": API_VERSION,
            "protocol": "lets/1",
            "warden_id": getattr(service, "warden_id", None),
        }
        if node_metadata is not None:
            document["metadata"] = dict(node_metadata)
        return _json_response(document)

    async def key_document() -> JSONResponse:
        if signer is None:
            raise ServiceMethodUnavailableError("public key discovery is not configured")
        public_key = getattr(signer, "public_key_bytes", None)
        if not isinstance(public_key, bytes):
            raise ServiceMethodUnavailableError(
                "the configured signer cannot export its public key"
            )
        return _json_response(
            {
                "warden_id": getattr(signer, "warden_id", None),
                "keys": [
                    {
                        "key_id": getattr(signer, "key_id", None),
                        "algorithm": "Ed25519",
                        "public_key": b64url_encode(public_key),
                    }
                ],
            }
        )

    app.add_api_route("/v1/keys", key_document, methods=["GET"])
    app.add_api_route(
        "/.well-known/lets-keys.json",
        key_document,
        methods=["GET"],
        include_in_schema=False,
    )

    @app.post("/v1/envelopes", status_code=201)
    async def create_envelope(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        _require_admin(identity)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset(
                {"tenant_id", "envelope_id", "config_epoch", "budget", "local_share"}
            ),
            optional=frozenset(
                {
                    "receipt_ttl_ns",
                    "max_clock_uncertainty_ns",
                    "transfer_gap_window",
                    "dimension_metadata",
                    "config",
                }
            ),
        )
        value = await _invoke(_method(service, "create_envelope"), identity=identity, **body)
        return _json_response(value, status_code=201)

    @app.post("/v1/policies", status_code=201)
    async def register_policy(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        _require_admin(identity)
        policy = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset(
                {
                    "policy_id",
                    "policy_version",
                    "resources",
                    "machine",
                    "max_lease_ttl_ns",
                    "receipt_ttl_ns",
                    "max_clock_uncertainty_ns",
                    "transfer_gap_window",
                }
            ),
            optional=frozenset({"machine_digest", "policy_digest"}),
        )
        digest = await _invoke(
            _method(service, "register_policy"),
            policy=policy,
            identity=identity,
        )
        return _json_response({"policy_digest": digest}, status_code=201)

    async def issue_root(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset(
                {
                    "request_id",
                    "tenant_id",
                    "envelope_id",
                    "subject_id",
                    "allocation",
                    "capabilities",
                    "policy_digest",
                    "ttl_ns",
                }
            ),
            optional=frozenset({"lineage_id"}),
        )
        value = await _invoke(_method(service, "issue_root"), identity=identity, **body)
        return _json_response(value, status_code=201)

    app.add_api_route("/v1/roots", issue_root, methods=["POST"], status_code=201)
    app.add_api_route(
        "/v1/leases/issue",
        issue_root,
        methods=["POST"],
        status_code=201,
        include_in_schema=False,
    )

    async def spawn_child(parent_id: str, request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset(
                {"request_id", "subject_id", "allocation", "capabilities", "ttl_ns"}
            ),
            optional=frozenset({"policy_digest", "expected_sequence"}),
        )
        value = await _invoke(
            _method(service, "spawn"), identity=identity, parent_id=parent_id, **body
        )
        return _json_response(value, status_code=201)

    app.add_api_route(
        "/v1/leases/{parent_id}/children",
        spawn_child,
        methods=["POST"],
        status_code=201,
    )
    app.add_api_route(
        "/v1/leases/{parent_id}/spawn",
        spawn_child,
        methods=["POST"],
        status_code=201,
        include_in_schema=False,
    )

    async def authorize_transition(lease_id: str, request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = await _json_object(request, maximum_bytes=maximum_body_bytes)
        if "executor_audience" in body:
            if "audience" in body:
                raise ValidationError("use only one executor audience field")
            body["audience"] = body.pop("executor_audience")
        arguments = _fields(
            body,
            required=frozenset({"request_id", "transition", "audience", "nonce"}),
            optional=frozenset({"evidence", "expected_state", "expected_sequence"}),
        )
        value = await _invoke(
            _method(service, "authorize"), identity=identity, lease_id=lease_id, **arguments
        )
        return _json_response(value)

    app.add_api_route("/v1/leases/{lease_id}/transitions", authorize_transition, methods=["POST"])
    app.add_api_route(
        "/v1/leases/{lease_id}/authorize",
        authorize_transition,
        methods=["POST"],
        include_in_schema=False,
    )

    @app.post("/v1/leases/{lease_id}/renew")
    async def renew(lease_id: str, request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset({"request_id", "ttl_ns"}),
            optional=frozenset({"expected_sequence", "cascade"}),
        )
        value = await _invoke(
            _method(service, "renew"), identity=identity, lease_id=lease_id, **body
        )
        return _json_response(value)

    async def lifecycle(operation: str, lease_id: str, request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset({"request_id"}),
            optional=frozenset({"expected_sequence"}),
        )
        value = await _invoke(
            _method(service, operation), identity=identity, lease_id=lease_id, **body
        )
        return _json_response(value)

    @app.post("/v1/leases/{lease_id}/quiesce")
    async def quiesce(lease_id: str, request: Request) -> JSONResponse:
        return await lifecycle("quiesce", lease_id, request)

    @app.post("/v1/leases/{lease_id}/resume")
    async def resume(lease_id: str, request: Request) -> JSONResponse:
        return await lifecycle("resume", lease_id, request)

    @app.post("/v1/leases/{lease_id}/close")
    async def close(lease_id: str, request: Request) -> JSONResponse:
        return await lifecycle("close", lease_id, request)

    @app.get("/v1/leases/{lease_id}")
    async def lease_snapshot(lease_id: str, request: Request) -> JSONResponse:
        identity = await client_identity(request)
        value = await _invoke(_method(service, "snapshot"), identity=identity, lease_id=lease_id)
        return _json_response(value)

    @app.post("/v1/branches/{lease_id}/revoke")
    async def revoke(lease_id: str, request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset({"request_id", "reason"}),
            optional=frozenset({"expected_epoch"}),
        )
        value = await _invoke(
            _method(service, "revoke_branch"), identity=identity, lease_id=lease_id, **body
        )
        return _json_response(value)

    @app.post("/v1/maintenance/reclaim")
    async def reclaim(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        _require_admin(identity)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            optional=frozenset({"tenant_id", "envelope_id"}),
        )
        value = await _invoke(_method(service, "reclaim_expired"), identity=identity, **body)
        return _json_response({"reclaimed": value})

    @app.get("/v1/maintenance/runtime")
    async def runtime_status(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        value = await _invoke(_method(service, "runtime_status"), identity=identity)
        return _json_response(value)

    @app.post("/v1/maintenance/runtime")
    async def set_runtime_mode(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset({"request_id", "mode", "reason"}),
        )
        value = await _invoke(_method(service, "set_runtime_mode"), identity=identity, **body)
        return _json_response(value)

    @app.get("/v1/invariants")
    async def invariants(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        value = await _invoke(_method(service, "invariant_snapshot"), identity=identity)
        return _json_response(value)

    @app.get("/v1/metrics")
    async def metrics(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        if not identity.scopes.intersection(
            {"lets.admin", "lets.warden.admin", "lets.metrics.read"}
        ):
            raise PolicyError("metrics read scope is required")
        if metrics_provider is None:
            raise ServiceMethodUnavailableError("node metrics are not configured")
        value = await run_in_threadpool(metrics_provider)
        if inspect.isawaitable(value):
            value = await value
        if not isinstance(value, Mapping):
            raise StorageError("metrics provider returned a malformed snapshot")
        return _json_response(value)

    @app.get("/v1/audit")
    async def audit(
        request: Request,
        after_sequence: int = Query(default=-1, ge=-1),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> JSONResponse:
        identity = await client_identity(request)
        records = await _invoke(
            _method(service, "list_audit"),
            identity=identity,
            after_sequence=after_sequence,
            limit=limit,
        )
        return _json_response({"records": records})

    @app.get("/v1/audit/verify")
    async def verify_audit(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        valid = await _invoke(_method(service, "verify_audit"), identity=identity)
        return _json_response({"valid": valid})

    @app.post("/v1/transfers/prepare", status_code=201)
    async def prepare_transfer(request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            required=frozenset(
                {"request_id", "tenant_id", "envelope_id", "target_warden", "amount"}
            ),
            optional=frozenset({"policy_digest"}),
        )
        value = await _invoke(_method(service, "prepare_transfer"), identity=identity, **body)
        return _json_response(value, status_code=201)

    @app.post("/v1/transfers/{source_warden}/{sequence}/accept")
    async def accept_transfer(
        source_warden: WardenPath,
        sequence: PositiveTransferSequence,
        request: Request,
    ) -> JSONResponse:
        peer, identity = await peer_identity(request)
        body = await _json_object(request, maximum_bytes=maximum_body_bytes)
        if peer.warden_id != source_warden or body.get("source_warden") != source_warden:
            raise PolicyError("authenticated peer does not match the voucher source")
        if body.get("sequence") != sequence:
            raise ConflictError("voucher sequence does not match the request target")
        value = await _invoke(_method(service, "accept_transfer"), identity=identity, voucher=body)
        return _json_response(value)

    @app.post("/v1/transfers/{target_warden}/{sequence}/finalize")
    async def finalize_transfer(
        target_warden: WardenPath,
        sequence: PositiveTransferSequence,
        request: Request,
    ) -> JSONResponse:
        peer, identity = await peer_identity(request)
        body = await _json_object(request, maximum_bytes=maximum_body_bytes)
        if peer.warden_id != target_warden or body.get("target_warden") != target_warden:
            raise PolicyError("authenticated peer does not match the acknowledgement target")
        if body.get("sequence") != sequence:
            raise ConflictError("acknowledgement sequence does not match the request target")
        value = await _invoke(
            _method(service, "finalize_transfer"), identity=identity, acknowledgement=body
        )
        return _json_response(value)

    @app.post("/v1/peer/revocations")
    async def ingest_revocation(request: Request) -> JSONResponse:
        _, identity = await peer_identity(request)
        body = await _json_object(request, maximum_bytes=maximum_body_bytes)
        value = await _invoke(
            _method(service, "ingest_revocation"), identity=identity, revocation=body
        )
        return _json_response(value)

    @app.post("/v1/transfers/{target_warden}/checkpoints")
    async def create_checkpoint(target_warden: WardenPath, request: Request) -> JSONResponse:
        identity = await client_identity(request)
        body = _fields(
            await _json_object(request, maximum_bytes=maximum_body_bytes),
            optional=frozenset({"through_sequence"}),
        )
        value = await _invoke(
            _method(service, "create_transfer_checkpoint"),
            identity=identity,
            target_warden=target_warden,
            **body,
        )
        return _json_response(value)

    @app.post("/v1/peer/transfer-checkpoints")
    async def ingest_checkpoint(request: Request) -> JSONResponse:
        peer, identity = await peer_identity(request)
        body = await _json_object(request, maximum_bytes=maximum_body_bytes)
        source = body.get("source_warden", body.get("issuer_warden"))
        if source != peer.warden_id:
            raise PolicyError("authenticated peer does not match the checkpoint issuer")
        value = await _invoke(
            _method(service, "ingest_transfer_checkpoint"),
            identity=identity,
            checkpoint=body,
        )
        return _json_response(value)

    # Request bytes are parsed manually so peer signatures cover the exact
    # representation.  Add the corresponding strict contracts to OpenAPI
    # explicitly; otherwise FastAPI cannot infer request bodies from Request.
    schemas: dict[str, dict[str, Any]] = {
        "WardenId": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": WARDEN_ID_PATTERN,
            "description": "ASCII URI-segment and HTTP-header-safe stable warden identifier.",
        },
        "KeyId": {
            "type": "string",
            "minLength": 1,
            "maxLength": 512,
            "pattern": KEY_ID_PATTERN,
            "description": "ASCII HTTP-header-safe cryptographic key identifier.",
        },
        "Problem": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "type",
                "title",
                "status",
                "detail",
                "instance",
                "code",
                "request_id",
            ],
            "properties": {
                "type": {"type": "string"},
                "title": {"type": "string"},
                "status": {"type": "integer", "minimum": 400, "maximum": 599},
                "detail": {"type": "string"},
                "instance": {"type": "string"},
                "code": {"type": "string"},
                "request_id": {"type": "string"},
            },
        },
        "InfoDocument": {
            "type": "object",
            "additionalProperties": False,
            "required": ["api_version", "protocol", "warden_id"],
            "properties": {
                "api_version": {"const": API_VERSION},
                "protocol": {"const": "lets/1"},
                "warden_id": {"$ref": "#/components/schemas/WardenId"},
                "metadata": {"type": "object"},
            },
        },
        "PublicKey": {
            "type": "object",
            "additionalProperties": False,
            "required": ["key_id", "algorithm", "public_key"],
            "properties": {
                "key_id": {"$ref": "#/components/schemas/KeyId"},
                "algorithm": {"const": "Ed25519"},
                "public_key": {
                    "type": "string",
                    "minLength": 43,
                    "maxLength": 43,
                    "pattern": "^[A-Za-z0-9_-]{43}$",
                },
            },
        },
        "KeyDocument": {
            "type": "object",
            "additionalProperties": False,
            "required": ["warden_id", "keys"],
            "properties": {
                "warden_id": {"$ref": "#/components/schemas/WardenId"},
                "keys": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"$ref": "#/components/schemas/PublicKey"},
                },
            },
        },
        "ResourceVector": {
            "type": "array",
            "minItems": 1,
            "maxItems": 256,
            "items": {"type": "integer", "minimum": 0},
        },
        "EnvelopeRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": ["tenant_id", "envelope_id", "config_epoch", "budget", "local_share"],
            "properties": {
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "config_epoch": {"type": "integer", "minimum": 1},
                "budget": {"$ref": "#/components/schemas/ResourceVector"},
                "local_share": {"$ref": "#/components/schemas/ResourceVector"},
                "receipt_ttl_ns": {"type": "integer", "minimum": 1},
                "max_clock_uncertainty_ns": {"type": "integer", "minimum": 0},
                "transfer_gap_window": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TRANSFER_GAP_WINDOW,
                },
                "dimension_metadata": {"type": "array", "items": {"type": "object"}},
                "config": {"type": "object"},
            },
        },
        "ResourceDimension": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id", "unit"],
            "properties": {
                "id": {"type": "string"},
                "unit": {"type": "string", "minLength": 1, "maxLength": 80},
                "description": {"type": "string", "maxLength": 500},
            },
        },
        "EvidenceRule": {
            "type": "object",
            "additionalProperties": False,
            "required": ["op"],
            "properties": {
                "op": {
                    "type": "string",
                    "enum": [
                        "all",
                        "any",
                        "not",
                        "exists",
                        "eq",
                        "ne",
                        "lt",
                        "lte",
                        "gt",
                        "gte",
                        "in",
                        "fresh",
                    ],
                },
                "path": {"type": "string"},
                "value": {},
                "values": {"type": "array", "items": {}},
                "rules": {
                    "type": "array",
                    "items": {"$ref": "#/components/schemas/EvidenceRule"},
                },
                "rule": {"$ref": "#/components/schemas/EvidenceRule"},
                "observed_at_path": {"type": "string"},
                "max_age_ns": {"type": "integer", "minimum": 0},
            },
        },
        "TransitionSpec": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "source", "target", "cost", "capability"],
            "properties": {
                "name": {"type": "string"},
                "source": {"type": "string"},
                "target": {"type": "string"},
                "cost": {"$ref": "#/components/schemas/ResourceVector"},
                "capability": {"type": "string"},
                "evidence": {"$ref": "#/components/schemas/EvidenceRule"},
            },
        },
        "MachineSpec": {
            "type": "object",
            "additionalProperties": False,
            "required": ["machine_id", "initial_state", "transitions"],
            "properties": {
                "machine_id": {"type": "string"},
                "initial_state": {"type": "string"},
                "transitions": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"$ref": "#/components/schemas/TransitionSpec"},
                },
                "machine_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            },
        },
        "Policy": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "policy_id",
                "policy_version",
                "resources",
                "machine",
                "max_lease_ttl_ns",
                "receipt_ttl_ns",
                "max_clock_uncertainty_ns",
                "transfer_gap_window",
            ],
            "properties": {
                "policy_id": {"type": "string"},
                "policy_version": {"type": "string"},
                "resources": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 256,
                    "items": {"$ref": "#/components/schemas/ResourceDimension"},
                },
                "machine": {"$ref": "#/components/schemas/MachineSpec"},
                "machine_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "policy_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "max_lease_ttl_ns": {"type": "integer", "minimum": 1},
                "receipt_ttl_ns": {"type": "integer", "minimum": 1},
                "max_clock_uncertainty_ns": {"type": "integer", "minimum": 0},
                "transfer_gap_window": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_TRANSFER_GAP_WINDOW,
                },
            },
        },
        "IssueRootRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "request_id",
                "tenant_id",
                "envelope_id",
                "subject_id",
                "allocation",
                "capabilities",
                "policy_digest",
                "ttl_ns",
            ],
            "properties": {
                "request_id": {"type": "string"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "subject_id": {"type": "string"},
                "allocation": {"$ref": "#/components/schemas/ResourceVector"},
                "capabilities": {
                    "type": "array",
                    "uniqueItems": True,
                    "items": {"type": "string"},
                },
                "policy_digest": {"type": "string"},
                "ttl_ns": {"type": "integer", "minimum": 1},
                "lineage_id": {"type": "string"},
            },
        },
        "SpawnRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id", "subject_id", "allocation", "capabilities", "ttl_ns"],
            "properties": {
                "request_id": {"type": "string"},
                "subject_id": {"type": "string"},
                "allocation": {"$ref": "#/components/schemas/ResourceVector"},
                "capabilities": {"type": "array", "items": {"type": "string"}},
                "ttl_ns": {"type": "integer", "minimum": 1},
                "policy_digest": {"type": "string"},
                "expected_sequence": {"type": "integer", "minimum": 0},
            },
        },
        "TransitionRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id", "transition", "executor_audience", "nonce"],
            "properties": {
                "request_id": {"type": "string"},
                "transition": {"type": "string"},
                "executor_audience": {"type": "string"},
                "nonce": {"type": "string", "minLength": 16},
                "evidence": {"type": "object"},
                "expected_state": {"type": "string"},
                "expected_sequence": {"type": "integer", "minimum": 0},
            },
        },
        "IdempotentRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id"],
            "properties": {
                "request_id": {"type": "string"},
                "expected_sequence": {"type": "integer", "minimum": 0},
            },
        },
        "RenewRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id", "ttl_ns"],
            "properties": {
                "request_id": {"type": "string"},
                "ttl_ns": {"type": "integer", "minimum": 1},
                "expected_sequence": {"type": "integer", "minimum": 0},
                "cascade": {"type": "boolean"},
            },
        },
        "RevocationRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id", "reason"],
            "properties": {
                "request_id": {"type": "string"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
                "expected_epoch": {"type": "integer", "minimum": 0},
            },
        },
        "PrepareTransferRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "request_id",
                "tenant_id",
                "envelope_id",
                "target_warden",
                "amount",
            ],
            "properties": {
                "request_id": {"type": "string"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "target_warden": {"$ref": "#/components/schemas/WardenId"},
                "amount": {"$ref": "#/components/schemas/ResourceVector"},
                "policy_digest": {"type": "string"},
            },
        },
        "TransferVoucher": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "type",
                "tenant_id",
                "envelope_id",
                "config_epoch",
                "transfer_id",
                "source_warden",
                "target_warden",
                "policy_id",
                "policy_version",
                "policy_digest",
                "sequence",
                "amount",
                "issued_at_ns",
                "key_id",
                "signature",
            ],
            "properties": {
                "type": {"const": "lets.transfer-voucher/v1"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "config_epoch": {"type": "integer", "minimum": 1},
                "transfer_id": {"type": "string"},
                "source_warden": {"$ref": "#/components/schemas/WardenId"},
                "target_warden": {"$ref": "#/components/schemas/WardenId"},
                "policy_id": {"type": "string"},
                "policy_version": {"type": "string"},
                "policy_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "sequence": {"type": "integer", "minimum": 1},
                "amount": {"$ref": "#/components/schemas/ResourceVector"},
                "issued_at_ns": {"type": "integer", "minimum": 0},
                "key_id": {"$ref": "#/components/schemas/KeyId"},
                "signature": {"type": "string"},
            },
        },
        "TransferAck": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "type",
                "tenant_id",
                "envelope_id",
                "config_epoch",
                "transfer_id",
                "source_warden",
                "target_warden",
                "sequence",
                "voucher_digest",
                "accepted_at_ns",
                "contiguous_watermark",
                "key_id",
                "signature",
            ],
            "properties": {
                "type": {"const": "lets.transfer-ack/v1"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "config_epoch": {"type": "integer", "minimum": 1},
                "transfer_id": {"type": "string"},
                "source_warden": {"$ref": "#/components/schemas/WardenId"},
                "target_warden": {"$ref": "#/components/schemas/WardenId"},
                "sequence": {"type": "integer", "minimum": 1},
                "voucher_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "accepted_at_ns": {"type": "integer", "minimum": 0},
                "contiguous_watermark": {"type": "integer", "minimum": 0},
                "key_id": {"$ref": "#/components/schemas/KeyId"},
                "signature": {"type": "string"},
            },
        },
        "BranchRevocation": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "type",
                "tenant_id",
                "envelope_id",
                "config_epoch",
                "branch_lease_id",
                "lineage_id",
                "epoch",
                "issuer_warden",
                "issued_at_ns",
                "reason",
                "key_id",
                "signature",
            ],
            "properties": {
                "type": {"const": "lets.branch-revocation/v1"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "config_epoch": {"type": "integer", "minimum": 1},
                "branch_lease_id": {"type": "string"},
                "lineage_id": {"type": "string"},
                "epoch": {"type": "integer", "minimum": 1},
                "issuer_warden": {"$ref": "#/components/schemas/WardenId"},
                "issued_at_ns": {"type": "integer", "minimum": 0},
                "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
                "key_id": {"$ref": "#/components/schemas/KeyId"},
                "signature": {"type": "string"},
            },
        },
        "TransferCheckpoint": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "type",
                "tenant_id",
                "envelope_id",
                "config_epoch",
                "source_warden",
                "target_warden",
                "through_sequence",
                "issued_at_ns",
                "key_id",
                "signature",
            ],
            "properties": {
                "type": {"const": "lets.transfer-checkpoint/v1"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "config_epoch": {"type": "integer", "minimum": 1},
                "source_warden": {"$ref": "#/components/schemas/WardenId"},
                "target_warden": {"$ref": "#/components/schemas/WardenId"},
                "through_sequence": {"type": "integer", "minimum": 1},
                "issued_at_ns": {"type": "integer", "minimum": 0},
                "key_id": {"$ref": "#/components/schemas/KeyId"},
                "signature": {"type": "string"},
            },
        },
        "CheckpointRequest": {
            "type": "object",
            "additionalProperties": False,
            "properties": {"through_sequence": {"type": "integer", "minimum": 1}},
        },
        "LeaseGrant": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "type",
                "tenant_id",
                "envelope_id",
                "config_epoch",
                "lease_id",
                "lineage_id",
                "parent_id",
                "subject_id",
                "warden_id",
                "allocation",
                "capabilities",
                "policy_id",
                "policy_version",
                "policy_digest",
                "machine_digest",
                "ancestor_path",
                "branch_epoch",
                "issued_at_ns",
                "expires_at_ns",
                "key_id",
                "signature",
            ],
            "properties": {
                "type": {"const": "lets.lease-grant/v1"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "config_epoch": {"type": "integer", "minimum": 1},
                "lease_id": {"type": "string"},
                "lineage_id": {"type": "string"},
                "parent_id": {"type": ["string", "null"]},
                "subject_id": {"type": "string"},
                "warden_id": {"$ref": "#/components/schemas/WardenId"},
                "allocation": {"$ref": "#/components/schemas/ResourceVector"},
                "capabilities": {
                    "type": "array",
                    "uniqueItems": True,
                    "items": {"type": "string"},
                },
                "policy_id": {"type": "string"},
                "policy_version": {"type": "string"},
                "policy_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "machine_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "ancestor_path": {
                    "type": "array",
                    "maxItems": 64,
                    "uniqueItems": True,
                    "items": {"type": "string"},
                },
                "branch_epoch": {"type": "integer", "minimum": 0},
                "issued_at_ns": {"type": "integer", "minimum": 0},
                "expires_at_ns": {"type": "integer", "minimum": 1},
                "key_id": {"$ref": "#/components/schemas/KeyId"},
                "signature": {"type": "string"},
            },
        },
        "LeaseSnapshot": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "type",
                "grant",
                "residual",
                "current_state",
                "status",
                "sequence",
                "updated_at_ns",
            ],
            "properties": {
                "type": {"const": "lets.lease-snapshot/v1"},
                "grant": {"$ref": "#/components/schemas/LeaseGrant"},
                "residual": {"$ref": "#/components/schemas/ResourceVector"},
                "current_state": {"type": "string"},
                "status": {
                    "type": "string",
                    "enum": [
                        "PROVISIONED",
                        "ACTIVE",
                        "QUIESCENT",
                        "REVOKED",
                        "EXPIRED",
                        "CLOSED",
                    ],
                },
                "sequence": {"type": "integer", "minimum": 0},
                "updated_at_ns": {"type": "integer", "minimum": 0},
            },
        },
        "Receipt": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "type",
                "tenant_id",
                "envelope_id",
                "config_epoch",
                "receipt_id",
                "request_id",
                "warden_id",
                "key_id",
                "policy_id",
                "policy_version",
                "policy_digest",
                "machine_digest",
                "lease_id",
                "lineage_id",
                "subject_id",
                "executor_audience",
                "transition",
                "source_state",
                "target_state",
                "cost",
                "resulting_sequence",
                "evidence_digest",
                "nonce",
                "issued_at_ns",
                "expires_at_ns",
                "signature",
            ],
            "properties": {
                "type": {"const": "lets.receipt/v1"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "config_epoch": {"type": "integer", "minimum": 1},
                "receipt_id": {"type": "string"},
                "request_id": {"type": "string"},
                "warden_id": {"$ref": "#/components/schemas/WardenId"},
                "key_id": {"$ref": "#/components/schemas/KeyId"},
                "policy_id": {"type": "string"},
                "policy_version": {"type": "string"},
                "policy_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "machine_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "lease_id": {"type": "string"},
                "lineage_id": {"type": "string"},
                "subject_id": {"type": "string"},
                "executor_audience": {"type": "string"},
                "transition": {"type": "string"},
                "source_state": {"type": "string"},
                "target_state": {"type": "string"},
                "cost": {"$ref": "#/components/schemas/ResourceVector"},
                "resulting_sequence": {"type": "integer", "minimum": 1},
                "evidence_digest": {
                    "type": ["string", "null"],
                    "pattern": "^sha256:[0-9a-f]{64}$",
                },
                "nonce": {"type": "string"},
                "issued_at_ns": {"type": "integer", "minimum": 0},
                "expires_at_ns": {"type": "integer", "minimum": 1},
                "signature": {"type": "string"},
            },
        },
        "InvariantSnapshot": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "tenant_id",
                "envelope_id",
                "config_epoch",
                "initial_share",
                "transferred_in",
                "transferred_out",
                "free_pool",
                "lease_residual",
                "consumed",
                "checked_at_ns",
                "healthy",
            ],
            "properties": {
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "config_epoch": {"type": "integer", "minimum": 1},
                "initial_share": {"$ref": "#/components/schemas/ResourceVector"},
                "transferred_in": {"$ref": "#/components/schemas/ResourceVector"},
                "transferred_out": {"$ref": "#/components/schemas/ResourceVector"},
                "free_pool": {"$ref": "#/components/schemas/ResourceVector"},
                "lease_residual": {"$ref": "#/components/schemas/ResourceVector"},
                "consumed": {"$ref": "#/components/schemas/ResourceVector"},
                "checked_at_ns": {"type": "integer", "minimum": 0},
                "healthy": {"type": "boolean"},
            },
        },
        "PolicyRegistration": {
            "type": "object",
            "additionalProperties": False,
            "required": ["policy_digest"],
            "properties": {"policy_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}},
        },
        "ReclaimResult": {
            "type": "object",
            "additionalProperties": False,
            "required": ["reclaimed"],
            "properties": {"reclaimed": {"$ref": "#/components/schemas/ResourceVector"}},
        },
        "AuditVerification": {
            "type": "object",
            "additionalProperties": False,
            "required": ["valid"],
            "properties": {"valid": {"type": "boolean"}},
        },
        "AuditRecord": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "sequence",
                "event_type",
                "tenant_id",
                "envelope_id",
                "entity_id",
                "actor_id",
                "occurred_at_ns",
                "details",
                "previous_hash",
                "event_hash",
                "key_id",
                "signature",
            ],
            "properties": {
                "sequence": {"type": "integer", "minimum": 0},
                "event_type": {"type": "string"},
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
                "entity_id": {"type": ["string", "null"]},
                "actor_id": {"type": "string"},
                "occurred_at_ns": {"type": "integer", "minimum": 0},
                "details": {"type": "object"},
                "previous_hash": {
                    "type": ["string", "null"],
                    "pattern": "^sha256:[0-9a-f]{64}$",
                },
                "event_hash": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                "key_id": {"$ref": "#/components/schemas/KeyId"},
                "signature": {"type": "string"},
            },
        },
        "AuditPage": {
            "type": "object",
            "additionalProperties": False,
            "required": ["records"],
            "properties": {
                "records": {
                    "type": "array",
                    "items": {"$ref": "#/components/schemas/AuditRecord"},
                }
            },
        },
        "MetricsSnapshot": {
            "type": "object",
            "description": "Implementation-defined node metrics snapshot.",
            "additionalProperties": True,
        },
        "ReclaimRequest": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "tenant_id": {"type": "string"},
                "envelope_id": {"type": "string"},
            },
        },
        "RuntimeModeRequest": {
            "type": "object",
            "additionalProperties": False,
            "required": ["request_id", "mode", "reason"],
            "properties": {
                "request_id": {"type": "string"},
                "mode": {"type": "string", "enum": ["ACTIVE", "DRAINING"]},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2000},
            },
        },
        "RuntimeStatus": {
            "type": "object",
            "additionalProperties": False,
            "required": ["mode", "generation", "reason", "changed_at_ns", "changed_by"],
            "properties": {
                "mode": {"type": "string", "enum": ["ACTIVE", "DRAINING"]},
                "generation": {"type": "integer", "minimum": 0},
                "reason": {"type": "string", "minLength": 1, "maxLength": 2000},
                "changed_at_ns": {"type": "integer", "minimum": 0},
                "changed_by": {"type": "string"},
            },
        },
    }
    body_contracts = {
        "/v1/envelopes": "EnvelopeRequest",
        "/v1/policies": "Policy",
        "/v1/roots": "IssueRootRequest",
        "/v1/leases/{parent_id}/children": "SpawnRequest",
        "/v1/leases/{lease_id}/transitions": "TransitionRequest",
        "/v1/leases/{lease_id}/renew": "RenewRequest",
        "/v1/leases/{lease_id}/quiesce": "IdempotentRequest",
        "/v1/leases/{lease_id}/resume": "IdempotentRequest",
        "/v1/leases/{lease_id}/close": "IdempotentRequest",
        "/v1/branches/{lease_id}/revoke": "RevocationRequest",
        "/v1/maintenance/reclaim": "ReclaimRequest",
        "/v1/maintenance/runtime": "RuntimeModeRequest",
        "/v1/transfers/prepare": "PrepareTransferRequest",
        "/v1/transfers/{source_warden}/{sequence}/accept": "TransferVoucher",
        "/v1/transfers/{target_warden}/{sequence}/finalize": "TransferAck",
        "/v1/peer/revocations": "BranchRevocation",
        "/v1/transfers/{target_warden}/checkpoints": "CheckpointRequest",
        "/v1/peer/transfer-checkpoints": "TransferCheckpoint",
    }
    peer_paths = {
        "/v1/transfers/{source_warden}/{sequence}/accept",
        "/v1/transfers/{target_warden}/{sequence}/finalize",
        "/v1/peer/revocations",
        "/v1/peer/transfer-checkpoints",
    }
    success_contracts = {
        "/v1/info": "InfoDocument",
        "/v1/keys": "KeyDocument",
        "/v1/envelopes": "InvariantSnapshot",
        "/v1/policies": "PolicyRegistration",
        "/v1/roots": "LeaseGrant",
        "/v1/leases/{parent_id}/children": "LeaseGrant",
        "/v1/leases/{lease_id}/transitions": "Receipt",
        "/v1/leases/{lease_id}/renew": "LeaseSnapshot",
        "/v1/leases/{lease_id}/quiesce": "LeaseSnapshot",
        "/v1/leases/{lease_id}/resume": "LeaseSnapshot",
        "/v1/leases/{lease_id}/close": "LeaseSnapshot",
        "/v1/leases/{lease_id}": "LeaseSnapshot",
        "/v1/branches/{lease_id}/revoke": "BranchRevocation",
        "/v1/maintenance/reclaim": "ReclaimResult",
        "/v1/maintenance/runtime": "RuntimeStatus",
        "/v1/invariants": "InvariantSnapshot",
        "/v1/metrics": "MetricsSnapshot",
        "/v1/audit": "AuditPage",
        "/v1/audit/verify": "AuditVerification",
        "/v1/transfers/prepare": "TransferVoucher",
        "/v1/transfers/{source_warden}/{sequence}/accept": "TransferAck",
        "/v1/transfers/{target_warden}/{sequence}/finalize": "TransferAck",
        "/v1/peer/revocations": "BranchRevocation",
        "/v1/transfers/{target_warden}/checkpoints": "TransferCheckpoint",
        "/v1/peer/transfer-checkpoints": "TransferCheckpoint",
    }
    peer_security_schemes = {
        "peerWardenId": {
            "type": "apiKey",
            "in": "header",
            "name": "X-LETS-Warden-ID",
            "description": "Signer warden ID matching the WardenId schema.",
        },
        "peerKeyId": {
            "type": "apiKey",
            "in": "header",
            "name": "X-LETS-Key-ID",
            "description": "Signer key ID matching the KeyId schema.",
        },
        "peerTimestamp": {
            "type": "apiKey",
            "in": "header",
            "name": "X-LETS-Timestamp",
            "description": "Unsigned decimal Unix timestamp in seconds.",
        },
        "peerNonce": {
            "type": "apiKey",
            "in": "header",
            "name": "X-LETS-Nonce",
            "description": "Unique 16..256 character replay nonce.",
        },
        "peerContentSha256": {
            "type": "apiKey",
            "in": "header",
            "name": "X-LETS-Content-SHA256",
            "description": "Canonical sha256:<64 lowercase hex> digest of the exact request body.",
        },
        "peerSignature": {
            "type": "apiKey",
            "in": "header",
            "name": "X-LETS-Signature",
            "description": "Unpadded base64url Ed25519 signature over the peer request envelope.",
        },
    }
    peer_security_requirement: dict[str, list[str]] = {name: [] for name in peer_security_schemes}
    original_openapi = app.openapi

    def strict_openapi() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema
        document = original_openapi()
        components = document.setdefault("components", {})
        component_schemas = components.setdefault("schemas", {})
        component_schemas.update(schemas)
        # FastAPI's generated validation models describe its default response,
        # but this application serializes every validation error as Problem.
        component_schemas.pop("HTTPValidationError", None)
        component_schemas.pop("ValidationError", None)
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes.update(
            {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
                **peer_security_schemes,
            }
        )
        paths = document.get("paths", {})
        for path, name in body_contracts.items():
            operation = paths[path]["post"]
            operation["requestBody"] = {
                "required": path != "/v1/maintenance/reclaim",
                "content": {JSON_MEDIA_TYPE: {"schema": {"$ref": f"#/components/schemas/{name}"}}},
            }
        public_paths = {"/health/live", "/health/ready", "/v1/info", "/v1/keys"}
        for path, path_item in paths.items():
            for operation in path_item.values():
                if not isinstance(operation, dict) or "responses" not in operation:
                    continue
                for parameter in operation.get("parameters", []):
                    if parameter.get("in") != "path":
                        continue
                    if parameter.get("name") in {"source_warden", "target_warden"}:
                        parameter["schema"] = {"$ref": "#/components/schemas/WardenId"}
                    elif parameter.get("name") == "sequence":
                        parameter["schema"] = {"type": "integer", "minimum": 1}
                if path in public_paths:
                    operation["security"] = []
                elif path in peer_paths:
                    operation["security"] = [dict(peer_security_requirement)]
                else:
                    operation["security"] = [{"bearerAuth": []}]
                responses = operation["responses"]
                if "422" in responses:
                    responses["422"] = {
                        "description": "RFC 9457 LETS validation problem",
                        "content": {
                            PROBLEM_MEDIA_TYPE: {"schema": {"$ref": "#/components/schemas/Problem"}}
                        },
                    }
                success_schema = success_contracts.get(path)
                if success_schema is not None:
                    for status_code, response in responses.items():
                        if not status_code.startswith("2"):
                            continue
                        response["content"] = {
                            JSON_MEDIA_TYPE: {
                                "schema": {"$ref": f"#/components/schemas/{success_schema}"}
                            }
                        }
                operation["responses"].setdefault(
                    "default",
                    {
                        "description": "RFC 9457 LETS problem",
                        "content": {
                            PROBLEM_MEDIA_TYPE: {"schema": {"$ref": "#/components/schemas/Problem"}}
                        },
                    },
                )
        app.openapi_schema = document
        return document

    app.openapi = strict_openapi  # type: ignore[method-assign]

    return app
