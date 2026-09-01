"""Home-scoped development agent for the three-host Linux experiment.

This module is uploaded separately from the tracked LETS source archive.  It
uses the real LETS service, SQLite storage, and executor receipt-claim paths,
but its small authenticated HTTP transport is only an experiment harness.  In
particular, the link gate below injects an *application-path* partition; it is
not a kernel firewall or a physical network partition.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from lets.clock import SystemClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import LETSError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

SCHEMA = "lets.three-host-linux-agent/v1"
ALIASES = ("s1", "s2", "s3")
TENANT = "three-host-study"
ENVELOPE = "three-host-envelope"
CAPABILITY = "three-host.act"
MAX_BODY_BYTES = 1_000_000
PEER_CLOCK_SKEW_SECONDS = 30
PEER_NONCE_CACHE_LIMIT = 4096


def experiment_policy() -> PolicySpec:
    return PolicySpec(
        policy_id="three-host-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("actions", "count"),),
        machine=MachineSpec(
            machine_id="three-host-worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (1,), CAPABILITY),),
        ),
        max_lease_ttl_ns=3_600_000_000_000,
        receipt_ttl_ns=300_000_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=64,
    )


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return dict(value)


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _peer_mac(
    token: str,
    path: str,
    timestamp: str,
    nonce: str,
    body_sha256: str,
    source_alias: str,
) -> str:
    canonical = "\n".join(("POST", path, timestamp, nonce, body_sha256, source_alias)).encode(
        "utf-8"
    )
    return hmac.new(token.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def re_fullmatch_hex(value: str, length: int) -> bool:
    return len(value) == length and all(character in "0123456789abcdef" for character in value)


def _safe_endpoint(value: object) -> str:
    endpoint = _string(value, "target_endpoint")
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "target_endpoint must be an origin-only 127.0.0.1 http URL with an explicit port"
        )
    return endpoint.rstrip("/")


@dataclass(frozen=True, slots=True)
class AgentConfig:
    alias: str
    warden_id: str
    port: int
    token: str
    run_root: Path
    budget: int
    initial_share: int
    initial_lease: int
    seed: bytes
    public_keys: dict[str, tuple[str, bytes]]

    @classmethod
    def load(cls, path: Path) -> AgentConfig:
        payload = _mapping(json.loads(path.read_text(encoding="utf-8")), "configuration")
        keys = _mapping(payload.get("public_keys"), "public_keys")
        public_keys: dict[str, tuple[str, bytes]] = {}
        for warden_id, raw in keys.items():
            item = _mapping(raw, f"public_keys[{warden_id!r}]")
            public_keys[_string(warden_id, "warden_id")] = (
                _string(item.get("key_id"), "key_id"),
                base64.b64decode(_string(item.get("public_key"), "public_key"), validate=True),
            )
        run_root = Path(_string(payload.get("run_root"), "run_root")).resolve()
        config = cls(
            alias=_string(payload.get("alias"), "alias"),
            warden_id=_string(payload.get("warden_id"), "warden_id"),
            port=_integer(payload.get("port"), "port", minimum=1024),
            token=_string(payload.get("token"), "token"),
            run_root=run_root,
            budget=_integer(payload.get("budget"), "budget", minimum=1),
            initial_share=_integer(payload.get("initial_share"), "initial_share", minimum=1),
            initial_lease=_integer(payload.get("initial_lease"), "initial_lease", minimum=1),
            seed=base64.b64decode(_string(payload.get("seed"), "seed"), validate=True),
            public_keys=public_keys,
        )
        if config.initial_lease > config.initial_share:
            raise ValueError("initial_lease exceeds initial_share")
        if config.alias not in ALIASES or config.alias != config.warden_id:
            raise ValueError("alias and warden_id must be the same known host alias")
        if set(config.public_keys) != set(ALIASES):
            raise ValueError("public_keys must contain exactly s1, s2, and s3")
        if config.warden_id not in config.public_keys:
            raise ValueError("local public key is missing")
        if len(config.seed) != 32 or any(len(item[1]) != 32 for item in public_keys.values()):
            raise ValueError("Ed25519 material must contain exactly 32 bytes")
        if not path.resolve().is_relative_to(run_root):
            raise ValueError("configuration is outside run_root")
        return config


class NodeState:
    """One real local warden and one real local executor claim database."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.clock = SystemClock()
        self.registry = PublicKeyRegistry(clock=self.clock)
        for warden_id, (key_id, public_key) in sorted(config.public_keys.items()):
            self.registry.register(warden_id, key_id, public_key)
        self.signer = Ed25519Signer.from_seed(config.warden_id, config.seed)
        expected_key_id, expected_public = config.public_keys[config.warden_id]
        if self.signer.key_id != expected_key_id or self.signer.public_key_bytes != expected_public:
            raise ValueError("local private seed does not match declared public key")

        state_dir = config.run_root / "state"
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        policy = experiment_policy()
        self.store = SQLiteStorage.initialize(
            state_dir / "warden.sqlite3",
            config.warden_id,
            (config.budget,),
            signing_key_id=self.signer.key_id,
            signing_public_key=self.signer.public_key_bytes,
            tenant_id=TENANT,
            envelope_id=ENVELOPE,
            initial_local_share=(config.initial_share,),
            receipt_ttl_ns=policy.receipt_ttl_ns,
            max_clock_uncertainty_ns=0,
            transfer_gap_window=policy.transfer_gap_window,
        )
        peers = set(config.public_keys) - {config.warden_id}
        self.service = WardenService(
            self.store,
            signer=self.signer,
            clock=self.clock,
            trust_registry=self.registry,
            allowed_peer_wardens=peers,
        )
        self.service.register_policy(policy)
        self.replay = SQLiteReceiptReplayStore.initialize(
            state_dir / "executor.sqlite3", allow_unanchored=True
        )
        self.verifier = ReceiptVerifier(
            self.registry,
            self.replay,
            ExecutorPolicy(
                audience=self.audience,
                tenant_id=TENANT,
                envelope_id=ENVELOPE,
                config_epoch=1,
                allowed_policy_digests=frozenset({policy.digest}),
                allowed_machine_digests=frozenset({policy.machine.digest}),
                trusted_wardens=frozenset({config.warden_id}),
            ),
            clock=self.clock,
        )
        self.identity = IdentityContext(
            config.warden_id,
            TENANT,
            frozenset({"lets.admin", "lets.transfer", "lets.peer"}),
            "experiment-bearer",
        )
        self.lease_id: str | None = None
        self.sequence = 0
        self.operation_index = 0
        self.link_enabled = {peer: True for peer in peers}
        self.peer_nonces: dict[tuple[str, str], int] = {}
        self.lock = threading.RLock()
        self.central: sqlite3.Connection | None = None
        if config.alias == "s2":
            self.central = sqlite3.connect(
                state_dir / "central.sqlite3", isolation_level=None, check_same_thread=False
            )
            self.central.execute("PRAGMA journal_mode=WAL")
            self.central.execute("PRAGMA synchronous=FULL")
            self.central.execute(
                "CREATE TABLE counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                "remaining INTEGER NOT NULL, consumed INTEGER NOT NULL) STRICT"
            )
            self.central.execute(
                "INSERT INTO counter(singleton, remaining, consumed) VALUES(1, ?, 0)",
                (config.budget,),
            )
            self.central.execute(
                "CREATE TABLE requests(request_id TEXT PRIMARY KEY, site TEXT NOT NULL, "
                "outcome TEXT NOT NULL) STRICT"
            )
        self.issue(config.initial_lease, "initial")

    @property
    def audience(self) -> str:
        return f"three-host-executor-{self.config.warden_id}"

    def issue(self, amount: int, suffix: str) -> dict[str, object]:
        with self.lock:
            if self.lease_id is not None:
                raise ValueError("a local lease is already active")
            grant = self.service.issue_root(
                request_id=f"issue-{self.config.warden_id}-{suffix}",
                identity=self.identity,
                tenant_id=TENANT,
                envelope_id=ENVELOPE,
                subject_id=self.config.warden_id,
                allocation=(amount,),
                capabilities={CAPABILITY},
                policy_digest=experiment_policy().digest,
                ttl_ns=3_000_000_000_000,
            )
            self.lease_id = grant.lease_id
            self.sequence = 0
            return {"issued": amount, "sequence": self.sequence}

    def close_lease(self, suffix: str) -> dict[str, object]:
        with self.lock:
            if self.lease_id is None:
                return {"closed": False, "reason": "no_active_lease"}
            self.service.close(
                request_id=f"close-{self.config.warden_id}-{suffix}",
                identity=self.identity,
                lease_id=self.lease_id,
                expected_sequence=self.sequence,
            )
            self.lease_id = None
            self.sequence = 0
            return {"closed": True}

    def authorize(self, request_id: str) -> dict[str, object]:
        started = time.perf_counter_ns()
        with self.lock:
            if self.lease_id is None:
                return {"authorized": False, "reason": "no_active_lease", "latency_ns": 0}
            try:
                self.operation_index += 1
                receipt = self.service.authorize(
                    request_id=request_id,
                    identity=self.identity,
                    lease_id=self.lease_id,
                    transition="act",
                    audience=self.audience,
                    nonce=f"three-host-{self.config.warden_id}-{self.operation_index:016d}",
                    expected_state="ready",
                    expected_sequence=self.sequence,
                )
                self.verifier.verify_and_claim(receipt)
                self.sequence = receipt.resulting_sequence
            except LETSError as exc:
                return {
                    "authorized": False,
                    "executor_claimed": False,
                    "reason": exc.code,
                    "latency_ns": time.perf_counter_ns() - started,
                }
        return {
            "authorized": True,
            "executor_claimed": True,
            "resulting_sequence": self.sequence,
            "latency_ns": time.perf_counter_ns() - started,
        }

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            value = self.service.invariant_snapshot(identity=self.identity)
            replay = self.replay.status()
            return {
                "alias": self.config.alias,
                "warden_id": self.config.warden_id,
                "initial_share": value.initial_share[0],
                "transferred_in": value.transferred_in[0],
                "transferred_out": value.transferred_out[0],
                "free_pool": value.free_pool[0],
                "lease_residual": value.lease_residual[0],
                "consumed": value.consumed[0],
                "healthy": value.healthy,
                "active_lease": self.lease_id is not None,
                "local_executor_claim_sequence": replay.claim_sequence,
                "executor_development_unanchored": not replay.rollback_protected,
            }

    def set_link(self, peer: str, enabled: bool) -> dict[str, object]:
        with self.lock:
            if peer not in self.link_enabled:
                raise ValueError("unknown peer alias")
            self.link_enabled[peer] = enabled
            return {
                "peer": peer,
                "enabled": enabled,
                "fault_model": "application_path_gate",
            }

    def require_link(self, peer: str) -> None:
        if peer not in self.link_enabled:
            raise ValueError("unknown peer alias")
        if not self.link_enabled[peer]:
            raise LinkPartitionedError(peer)

    def verify_peer_auth(
        self,
        *,
        path: str,
        source_alias: str,
        timestamp: str,
        nonce: str,
        body_sha256: str,
        authorization: str,
        body: bytes,
    ) -> bool:
        if source_alias not in self.link_enabled:
            return False
        if re_fullmatch_hex(body_sha256, 64) is False or re_fullmatch_hex(nonce, 64) is False:
            return False
        try:
            timestamp_value = int(timestamp)
        except ValueError:
            return False
        now = int(time.time())
        if abs(now - timestamp_value) > PEER_CLOCK_SKEW_SECONDS:
            return False
        if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), body_sha256):
            return False
        prefix = "LETS-HMAC "
        if not authorization.startswith(prefix):
            return False
        supplied = authorization[len(prefix) :]
        expected = _peer_mac(
            self.config.token,
            path,
            timestamp,
            nonce,
            body_sha256,
            source_alias,
        )
        if not hmac.compare_digest(supplied, expected):
            return False
        with self.lock:
            expired = [key for key, expires in self.peer_nonces.items() if expires < now]
            for key in expired:
                self.peer_nonces.pop(key, None)
            key = (source_alias, nonce)
            if key in self.peer_nonces:
                return False
            if len(self.peer_nonces) >= PEER_NONCE_CACHE_LIMIT:
                return False
            self.peer_nonces[key] = max(now, timestamp_value) + PEER_CLOCK_SKEW_SECONDS
        return True

    def central_authorize(self, source_alias: str, request_id: str) -> dict[str, object]:
        if self.central is None:
            raise ValueError("central counter is hosted only by s2")
        started = time.perf_counter_ns()
        with self.lock:
            self.central.execute("BEGIN IMMEDIATE")
            try:
                prior = self.central.execute(
                    "SELECT outcome FROM requests WHERE request_id=?", (request_id,)
                ).fetchone()
                if prior is not None:
                    self.central.rollback()
                    outcome = str(prior[0])
                else:
                    remaining = int(
                        self.central.execute(
                            "SELECT remaining FROM counter WHERE singleton=1"
                        ).fetchone()[0]
                    )
                    outcome = "authorized" if remaining > 0 else "budget_exhausted"
                    if remaining > 0:
                        self.central.execute(
                            "UPDATE counter SET remaining=remaining-1, "
                            "consumed=consumed+1 WHERE singleton=1"
                        )
                    self.central.execute(
                        "INSERT INTO requests(request_id, site, outcome) VALUES(?, ?, ?)",
                        (request_id, source_alias, outcome),
                    )
                    self.central.commit()
                remaining, consumed = self.central.execute(
                    "SELECT remaining, consumed FROM counter WHERE singleton=1"
                ).fetchone()
            except BaseException:
                if self.central.in_transaction:
                    self.central.rollback()
                raise
        return {
            "authorized": outcome == "authorized",
            "reason": outcome,
            "remaining": int(remaining),
            "consumed": int(consumed),
            "latency_ns": time.perf_counter_ns() - started,
        }

    def central_proxy(self, target_alias: str, endpoint: str, request_id: str) -> dict[str, object]:
        with self.lock:
            self.require_link(target_alias)
        response = _post_peer(
            f"{_safe_endpoint(endpoint)}/peer/central-authorize",
            self.config.token,
            self.config.alias,
            {"request_id": request_id},
        )
        return {
            **response,
            "source": self.config.alias,
            "target": target_alias,
            "transport": "peer_tcp_http_hmac",
        }

    def peer_ping(self, target_alias: str, endpoint: str) -> dict[str, object]:
        with self.lock:
            self.require_link(target_alias)
        response = _post_peer(
            f"{_safe_endpoint(endpoint)}/peer/ping",
            self.config.token,
            self.config.alias,
            {"source_alias": self.config.alias},
        )
        if response.get("target") != target_alias:
            raise RuntimeError("peer_target_mismatch")
        return {
            "delivered": response.get("accepted") is True,
            "source": self.config.alias,
            "target": target_alias,
            "target_observed_source_sha256": response.get("transport_peer_sha256"),
            "transport": "peer_tcp_http_hmac",
        }

    def transfer(
        self, target_alias: str, endpoint: str, amount: int, request_id: str
    ) -> dict[str, object]:
        with self.lock:
            self.require_link(target_alias)
            voucher = self.service.prepare_transfer(
                request_id=request_id,
                identity=self.identity,
                tenant_id=TENANT,
                envelope_id=ENVELOPE,
                target_warden=target_alias,
                amount=(amount,),
                policy_digest=experiment_policy().digest,
            )
        response = _post_peer(
            f"{_safe_endpoint(endpoint)}/peer/transfer",
            self.config.token,
            self.config.alias,
            {"voucher": voucher.to_dict()},
        )
        acknowledgement = _mapping(response.get("acknowledgement"), "acknowledgement")
        with self.lock:
            self.service.finalize_transfer(identity=self.identity, acknowledgement=acknowledgement)
        return {
            "delivered": True,
            "finalized": True,
            "source": self.config.alias,
            "target": target_alias,
            "amount": amount,
            "sequence": voucher.sequence,
            "target_observed_source_sha256": response.get("transport_peer_sha256"),
            "transport": "peer_tcp_http_hmac",
        }

    def accept_transfer(self, source_alias: str, voucher: object) -> dict[str, object]:
        with self.lock:
            self.require_link(source_alias)
            acknowledgement = self.service.accept_transfer(
                identity=self.identity, voucher=_mapping(voucher, "voucher")
            )
        return {"acknowledgement": acknowledgement.to_dict()}

    def close(self) -> None:
        if self.central is not None:
            self.central.close()
        self.store.close()


class LinkPartitionedError(RuntimeError):
    def __init__(self, peer: str) -> None:
        super().__init__("application-path peer link is disabled")
        self.peer = peer


def _post_peer(url: str, token: str, alias: str, payload: Mapping[str, object]) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    path = urllib.parse.urlsplit(url).path
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(32)
    body_sha256 = hashlib.sha256(body).hexdigest()
    signature = _peer_mac(token, path, timestamp, nonce, body_sha256, alias)
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"LETS-HMAC {signature}",
            "Content-Type": "application/json",
            "X-LETS-Peer-Alias": alias,
            "X-LETS-Timestamp": timestamp,
            "X-LETS-Nonce": nonce,
            "X-LETS-Body-SHA256": body_sha256,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return _mapping(json.loads(response.read()), "peer response")
    except urllib.error.HTTPError as exc:
        try:
            payload = _mapping(json.loads(exc.read()), "peer error")
            reason = str(payload.get("error", "peer_request_failed"))
        except Exception:
            reason = "peer_request_failed"
        raise RuntimeError(reason) from None
    except (OSError, urllib.error.URLError):
        raise RuntimeError("peer_transport_unreachable") from None


class AgentServer(HTTPServer):
    allow_reuse_address = True
    state: NodeState


class Handler(BaseHTTPRequestHandler):
    server: AgentServer

    def log_message(self, _format: str, *_args: object) -> None:
        # The default includes client IPs.  Never put addresses into the agent log.
        return

    def _authorized(self) -> bool:
        expected = f"Bearer {self.server.state.config.token}"
        return self.client_address[0] == "127.0.0.1" and hmac.compare_digest(
            self.headers.get("Authorization", ""), expected
        )

    def _raw_body(self) -> bytes:
        length = _integer(int(self.headers.get("Content-Length", "0")), "content length")
        if length > MAX_BODY_BYTES:
            raise ValueError("request body is too large")
        return self.rfile.read(length)

    @staticmethod
    def _body(raw: bytes) -> dict[str, Any]:
        return _mapping(json.loads(raw or b"{}"), "request")

    def _send(self, status: HTTPStatus, payload: Mapping[str, object]) -> None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        if self.path == "/health":
            self._send(
                HTTPStatus.OK,
                {
                    "schema": SCHEMA,
                    "ready": True,
                    "alias": self.server.state.config.alias,
                    "fault_model": "application_path_gate_not_firewall",
                },
            )
        elif self.path == "/snapshot":
            self._send(HTTPStatus.OK, self.server.state.snapshot())
        else:
            self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        try:
            raw_body = self._raw_body()
            peer_alias = self.headers.get("X-LETS-Peer-Alias", "")
            if self.path.startswith("/peer/"):
                if not self.server.state.verify_peer_auth(
                    path=self.path,
                    source_alias=peer_alias,
                    timestamp=self.headers.get("X-LETS-Timestamp", ""),
                    nonce=self.headers.get("X-LETS-Nonce", ""),
                    body_sha256=self.headers.get("X-LETS-Body-SHA256", ""),
                    authorization=self.headers.get("Authorization", ""),
                    body=raw_body,
                ):
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized_peer_mac"})
                    return
            elif not self._authorized():
                self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            body = self._body(raw_body)
            if self.path == "/local/authorize":
                result = self.server.state.authorize(_string(body.get("request_id"), "request_id"))
            elif self.path == "/local/central-authorize":
                result = self.server.state.central_authorize(
                    self.server.state.config.alias,
                    _string(body.get("request_id"), "request_id"),
                )
            elif self.path == "/local/close":
                result = self.server.state.close_lease(_string(body.get("suffix"), "suffix"))
            elif self.path == "/local/issue":
                result = self.server.state.issue(
                    _integer(body.get("amount"), "amount", minimum=1),
                    _string(body.get("suffix"), "suffix"),
                )
            elif self.path == "/control/link":
                enabled = body.get("enabled")
                if not isinstance(enabled, bool):
                    raise ValueError("enabled must be a boolean")
                result = self.server.state.set_link(_string(body.get("peer"), "peer"), enabled)
            elif self.path == "/proxy/ping":
                result = self.server.state.peer_ping(
                    _string(body.get("target_alias"), "target_alias"),
                    _safe_endpoint(body.get("target_endpoint")),
                )
            elif self.path == "/proxy/transfer":
                result = self.server.state.transfer(
                    _string(body.get("target_alias"), "target_alias"),
                    _safe_endpoint(body.get("target_endpoint")),
                    _integer(body.get("amount"), "amount", minimum=1),
                    _string(body.get("request_id"), "request_id"),
                )
            elif self.path == "/proxy/central-authorize":
                result = self.server.state.central_proxy(
                    _string(body.get("target_alias"), "target_alias"),
                    _safe_endpoint(body.get("target_endpoint")),
                    _string(body.get("request_id"), "request_id"),
                )
            elif self.path == "/peer/ping":
                source = _string(peer_alias, "peer alias")
                self.server.state.require_link(source)
                result = {
                    "accepted": True,
                    "target": self.server.state.config.alias,
                    "transport_peer_sha256": _digest(str(self.client_address[0])),
                }
            elif self.path == "/peer/transfer":
                source = _string(peer_alias, "peer alias")
                result = self.server.state.accept_transfer(source, body.get("voucher"))
                result["transport_peer_sha256"] = _digest(str(self.client_address[0]))
            elif self.path == "/peer/central-authorize":
                source = _string(peer_alias, "peer alias")
                self.server.state.require_link(source)
                result = self.server.state.central_authorize(
                    source, _string(body.get("request_id"), "request_id")
                )
                result["transport_peer_sha256"] = _digest(str(self.client_address[0]))
            elif self.path == "/control/shutdown":
                result = {"shutting_down": True}
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            self._send(HTTPStatus.OK, result)
        except LinkPartitionedError as exc:
            self._send(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "error": "application_path_partition",
                    "peer": exc.peer,
                    "fault_model": "application_path_gate_not_firewall",
                },
            )
        except LETSError as exc:
            self._send(
                HTTPStatus.CONFLICT,
                {"error": exc.code, "error_class": type(exc).__name__},
            )
        except (RuntimeError, ValueError, KeyError) as exc:
            self._send(
                HTTPStatus.BAD_REQUEST,
                {"error": str(exc)[:160], "error_class": type(exc).__name__},
            )


def serve(config_path: Path) -> None:
    config = AgentConfig.load(config_path)
    state = NodeState(config)
    # Only SSH-local loopback is exposed. Cross-host experiment traffic reaches
    # this listener through the controller's two-session SSH byte relay.
    server = AgentServer(("127.0.0.1", config.port), Handler)
    server.state = state
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        state.close()


def request_local(config_path: Path, request_path: Path) -> int:
    config = AgentConfig.load(config_path)
    if not request_path.resolve().is_relative_to(config.run_root):
        raise ValueError("request file is outside run_root")
    payload = _mapping(json.loads(request_path.read_text(encoding="utf-8")), "request file")
    method = _string(payload.get("method"), "method")
    path = _string(payload.get("path"), "path")
    if method not in {"GET", "POST"} or not path.startswith("/") or "//" in path:
        raise ValueError("invalid local request target")
    data = None
    if method == "POST":
        data = json.dumps(_mapping(payload.get("body", {}), "body")).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{config.port}{path}",
        data=data,
        headers={"Authorization": f"Bearer {config.token}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = _mapping(json.loads(response.read()), "response")
            status = response.status
    except urllib.error.HTTPError as exc:
        result = _mapping(json.loads(exc.read()), "error response")
        status = exc.code
    print(json.dumps({"http_status": status, "response": result}, sort_keys=True))
    return 0 if status < 400 else 2


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--config", type=Path, required=True)
    request_parser = subparsers.add_parser("request")
    request_parser.add_argument("--config", type=Path, required=True)
    request_parser.add_argument("--request", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    if arguments.command == "serve":
        serve(arguments.config)
        return 0
    return request_local(arguments.config, arguments.request)


if __name__ == "__main__":
    raise SystemExit(main())
