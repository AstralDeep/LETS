"""Authoritative LETS warden application service.

This module is the local serialization point for a warden.  All safety
decisions and their durable consequences happen in one SQLite
``BEGIN IMMEDIATE`` transaction supplied by :mod:`lets.storage`.  Network
adapters are deliberately kept outside this module.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import asdict, is_dataclass, replace
from hashlib import sha256
from typing import Any, Protocol, TypeAlias, cast

from lets.canonical import (
    b64url_decode,
    b64url_encode,
    canonical_digest,
    canonical_json,
    strict_json_loads,
)
from lets.clock import Clock, SystemClock
from lets.errors import (
    ClockUncertainError,
    ConflictError,
    DrainingError,
    ExpiredError,
    InvariantError,
    NotFoundError,
    PolicyError,
    ReplayError,
    SignatureError,
    StorageError,
    ValidationError,
)
from lets.ids import new_id, require_digest, require_identifier, require_warden_id
from lets.invariants import ConservationSnapshot
from lets.models import (
    MAX_LINEAGE_DEPTH,
    AuditRecord,
    BranchRevocation,
    IdentityContext,
    InvariantSnapshot,
    LeaseGrant,
    LeaseSnapshot,
    LeaseStatus,
    Receipt,
    RuntimeMode,
    RuntimeStatus,
    TransferAck,
    TransferVoucher,
)
from lets.policy import (
    MAX_MACHINE_TRANSITIONS,
    MAX_TRANSFER_GAP_WINDOW,
    EvidenceRule,
    evaluate_evidence,
)
from lets.vector import (
    MAX_RESOURCE,
    ResourceVector,
    add,
    less_than_or_equal,
    pack,
    subtract,
    vector,
    zero,
)

WireObject: TypeAlias = dict[str, Any]
EvidenceEvaluator: TypeAlias = Callable[..., bool]

_ACTIONABLE = frozenset({"ACTIVE"})
_LIVE = frozenset({"PROVISIONED", "ACTIVE", "QUIESCENT", "MIGRATING", "REVOKED"})
_SUBJECT_LIFECYCLE_SCOPES = frozenset({"lets.admin", "lets.lease.manage"})
_ADMIN_SCOPES = frozenset({"lets.admin", "lets.warden.admin"})
_ROOT_ISSUER_SCOPES = _ADMIN_SCOPES | frozenset({"lets.lease.issue"})


class _Transaction(Protocol):
    connection: sqlite3.Connection


class Storage(Protocol):
    @property
    def metadata(self) -> Any: ...

    def write(self) -> AbstractContextManager[Any]: ...

    def read(self) -> AbstractContextManager[Any]: ...


class Signer(Protocol):
    warden_id: str
    key_id: str

    @property
    def public_key_bytes(self) -> bytes: ...

    def sign(self, payload: bytes) -> bytes: ...


class TrustRegistry(Protocol):
    def verify(
        self,
        warden_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
    ) -> bool: ...

    def require_current_warden(self, warden_id: str) -> None: ...


def _object_mapping(value: object) -> WireObject:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        if isinstance(result, Mapping):
            return {str(key): item for key, item in result.items()}
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise ValidationError(f"{type(value).__name__} is not a protocol object")


def _json_object(payload: bytes | str | memoryview) -> WireObject:
    if isinstance(payload, memoryview):
        payload = payload.tobytes()
    decoded = strict_json_loads(payload)
    if not isinstance(decoded, dict):
        raise StorageError("stored protocol payload is not a JSON object")
    return decoded


def _json_array(payload: bytes | str | memoryview) -> list[Any]:
    if isinstance(payload, memoryview):
        payload = payload.tobytes()
    decoded = strict_json_loads(payload)
    if not isinstance(decoded, list):
        raise StorageError("stored protocol payload is not a JSON array")
    return decoded


def _row_value(row: sqlite3.Row | Mapping[str, Any], key: str) -> Any:
    return row[key]


class WardenService:
    """Durable, fail-closed application service for one stable warden."""

    def __init__(
        self,
        store: Storage,
        *,
        signer: Signer,
        clock: Clock | None = None,
        trust_registry: TrustRegistry | None = None,
        evidence_evaluator: EvidenceEvaluator = evaluate_evidence,
        signing_key_validity: tuple[int | None, int | None] | None = None,
        allowed_peer_wardens: Iterable[str] | None = None,
    ) -> None:
        self._store = store
        self._signer = signer
        self._clock = SystemClock() if clock is None else clock
        self._trust_registry = trust_registry
        self._evidence_evaluator = evidence_evaluator
        self._signing_key_validity = signing_key_validity
        require_warden_id(signer.warden_id, field="signer warden id")
        require_identifier(signer.key_id, field="signer key_id")
        self._allowed_peer_wardens = (
            None
            if allowed_peer_wardens is None
            else frozenset(
                require_warden_id(warden_id, field="allowed peer warden_id")
                for warden_id in allowed_peer_wardens
            )
        )
        if (
            self._allowed_peer_wardens is not None
            and signer.warden_id in self._allowed_peer_wardens
        ):
            raise ValidationError("the local warden cannot be configured as its own peer")
        if not isinstance(signer.public_key_bytes, bytes) or len(signer.public_key_bytes) != 32:
            raise SignatureError("signer public key must contain exactly 32 bytes")
        if signing_key_validity is not None:
            if not isinstance(signing_key_validity, tuple) or len(signing_key_validity) != 2:
                raise ValidationError("signing_key_validity must be a (not_before, not_after) pair")
            start, end = signing_key_validity
            for field, value in (("not_before", start), ("not_after", end)):
                if value is not None and (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                    or value > MAX_RESOURCE
                ):
                    raise ValidationError(f"signing key {field} must be a signed 64-bit timestamp")
            if start is not None and end is not None and end <= start:
                raise ValidationError("signing key validity interval is empty")
        self._require_signing_key_current()
        with self._store.read() as transaction:
            self._verify_database_identity(self._connection(transaction))

    @property
    def warden_id(self) -> str:
        return self._signer.warden_id

    def _connection(self, transaction: _Transaction) -> sqlite3.Connection:
        return transaction.connection

    @staticmethod
    def _enqueue_peer_delivery(
        connection: sqlite3.Connection,
        *,
        record_kind: str,
        record_id: str,
        target_warden: str,
        ordering_key: str,
        stream_position: int,
        payload: bytes,
        now_ns: int,
        supersede_older: bool = False,
    ) -> None:
        if supersede_older:
            cursor = connection.execute(
                """
                UPDATE peer_delivery_state
                SET superseded_at_ns = ?, last_error = 'superseded by newer signed state'
                WHERE record_kind = ? AND target_warden = ? AND ordering_key = ?
                  AND delivered_at_ns IS NULL AND superseded_at_ns IS NULL
                """,
                (now_ns, record_kind, target_warden, ordering_key),
            )
            if cursor.rowcount:
                connection.execute(
                    """
                    INSERT INTO peer_delivery_counters(
                        record_kind, target_warden, delivered_count,
                        superseded_count, last_terminal_ns
                    ) VALUES (?, ?, 0, ?, ?)
                    ON CONFLICT(record_kind, target_warden) DO UPDATE SET
                        superseded_count = superseded_count + excluded.superseded_count,
                        last_terminal_ns = excluded.last_terminal_ns
                    """,
                    (record_kind, target_warden, cursor.rowcount, now_ns),
                )
        connection.execute(
            """
            INSERT INTO peer_delivery_state(
                record_kind, record_id, target_warden, ordering_key, stream_position,
                payload, created_at_ns, attempts, next_attempt_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
            """,
            (
                record_kind,
                record_id,
                target_warden,
                ordering_key,
                stream_position,
                payload,
                now_ns,
            ),
        )

    def _identity_fields(self, identity: IdentityContext) -> tuple[str, str, frozenset[str]]:
        if not isinstance(identity, IdentityContext):
            raise PolicyError("an authenticated identity context is required")
        tenant_id = getattr(identity, "tenant_id", None)
        subject_id = getattr(identity, "subject_id", None)
        if subject_id is None:
            subject_id = getattr(identity, "subject", None)
        scopes_value: object = getattr(identity, "scopes", frozenset())
        if not isinstance(scopes_value, (set, frozenset, tuple, list)):
            raise PolicyError("identity scopes are malformed")
        if not isinstance(tenant_id, str) or not isinstance(subject_id, str):
            raise PolicyError("authenticated identity fields are malformed")
        tenant = require_identifier(tenant_id, field="identity tenant_id")
        subject = require_identifier(subject_id, field="identity subject_id")
        scopes = frozenset(
            require_identifier(item, field="identity scope") for item in scopes_value
        )
        return tenant, subject, scopes

    def _bind_tenant(self, identity: IdentityContext, tenant_id: str) -> tuple[str, frozenset[str]]:
        identity_tenant, subject, scopes = self._identity_fields(identity)
        require_identifier(tenant_id, field="tenant_id")
        if identity_tenant != tenant_id:
            raise PolicyError("identity tenant does not match request tenant")
        return subject, scopes

    @staticmethod
    def _has_scope(scopes: frozenset[str], accepted: frozenset[str]) -> bool:
        return bool(scopes & accepted)

    def _bind_subject(
        self,
        identity: IdentityContext,
        *,
        tenant_id: str,
        subject_id: str,
        administrative_scopes: frozenset[str] = _ADMIN_SCOPES,
    ) -> str:
        actor, scopes = self._bind_tenant(identity, tenant_id)
        require_identifier(subject_id, field="subject_id")
        if actor != subject_id and not self._has_scope(scopes, administrative_scopes):
            raise PolicyError("authenticated subject does not match requested subject")
        return actor

    def _require_admin(self, identity: IdentityContext, tenant_id: str) -> str:
        actor, scopes = self._bind_tenant(identity, tenant_id)
        if not self._has_scope(scopes, _ADMIN_SCOPES):
            raise PolicyError("warden administration scope is required")
        return actor

    @staticmethod
    def _runtime_status(connection: sqlite3.Connection) -> RuntimeStatus:
        row = connection.execute(
            """
            SELECT mode, generation, reason, changed_at_ns, changed_by
            FROM runtime_control WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise StorageError("runtime control state is missing")
        try:
            return RuntimeStatus(
                mode=RuntimeMode(str(_row_value(row, "mode"))),
                generation=int(_row_value(row, "generation")),
                reason=str(_row_value(row, "reason")),
                changed_at_ns=int(_row_value(row, "changed_at_ns")),
                changed_by=str(_row_value(row, "changed_by")),
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise StorageError("runtime control state is malformed") from exc

    @classmethod
    def _require_runtime_active(cls, connection: sqlite3.Connection) -> None:
        status = cls._runtime_status(connection)
        if status.mode is not RuntimeMode.ACTIVE:
            raise DrainingError(
                f"warden is draining at generation {status.generation}: {status.reason}"
            )

    def _envelope(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        envelope_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM envelopes WHERE tenant_id = ? AND envelope_id = ?",
            (tenant_id, envelope_id),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"envelope {tenant_id}/{envelope_id} is not configured")
        return cast(sqlite3.Row, row)

    def _singleton_envelope(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM envelopes WHERE singleton = 1").fetchone()
        if row is None:
            raise NotFoundError("this warden has no configured envelope")
        return cast(sqlite3.Row, row)

    def _verify_database_identity(self, connection: sqlite3.Connection) -> None:
        row = connection.execute(
            """
            SELECT warden_id, signing_key_id, signing_public_key_sha256
            FROM database_metadata WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise StorageError("database metadata is missing")
        if _row_value(row, "warden_id") != self.warden_id:
            raise ConflictError("signer warden_id does not match the durable database identity")
        if _row_value(row, "signing_key_id") != self._signer.key_id:
            raise ConflictError("signer key_id does not match the durable database identity")
        fingerprint = _row_value(row, "signing_public_key_sha256")
        if (
            not isinstance(fingerprint, bytes)
            or fingerprint != sha256(self._signer.public_key_bytes).digest()
        ):
            raise ConflictError("signer public key does not match the durable database identity")

    def _require_signing_key_current(self) -> None:
        """Require the full declared clock interval to fit the manifest key interval."""

        if self._signing_key_validity is None:
            # Direct in-process/non-manifest embeddings explicitly have no manifest interval.
            return
        now_ns = self._clock.now_ns()
        uncertainty_ns = self._clock.uncertainty_ns()
        if (
            isinstance(now_ns, bool)
            or not isinstance(now_ns, int)
            or now_ns < 0
            or now_ns > MAX_RESOURCE
            or isinstance(uncertainty_ns, bool)
            or not isinstance(uncertainty_ns, int)
            or uncertainty_ns < 0
            or uncertainty_ns > MAX_RESOURCE
            or now_ns > MAX_RESOURCE - uncertainty_ns
        ):
            raise ClockUncertainError("clock cannot establish local signing-key validity")
        not_before_ns, not_after_ns = self._signing_key_validity
        if not_before_ns is not None and now_ns - uncertainty_ns < not_before_ns:
            raise SignatureError("local signing key is not yet valid for the full clock interval")
        if not_after_ns is not None and now_ns + uncertainty_ns >= not_after_ns:
            raise SignatureError("local signing key is expired for the full clock interval")

    def _clock_is_safe(
        self,
        connection: sqlite3.Connection,
        envelope: sqlite3.Row,
        *,
        now_ns: int,
        advance_floor: bool = True,
    ) -> int:
        if (
            isinstance(now_ns, bool)
            or not isinstance(now_ns, int)
            or now_ns < 0
            or now_ns > MAX_RESOURCE
        ):
            raise ClockUncertainError("clock time is outside signed 64-bit Unix nanoseconds")
        uncertainty = self._clock.uncertainty_ns()
        if (
            isinstance(uncertainty, bool)
            or not isinstance(uncertainty, int)
            or uncertainty < 0
            or uncertainty > MAX_RESOURCE
        ):
            raise ClockUncertainError("clock reported invalid uncertainty")
        maximum = int(_row_value(envelope, "max_clock_uncertainty_ns"))
        if uncertainty > maximum:
            raise ClockUncertainError(
                f"clock uncertainty {uncertainty}ns exceeds configured maximum {maximum}ns"
            )
        if now_ns > MAX_RESOURCE - uncertainty:
            raise ClockUncertainError("clock uncertainty interval exceeds signed 64-bit time")
        floor_row = connection.execute(
            """
            SELECT clock_floor_ns FROM warden_state
            WHERE tenant_id = ? AND envelope_id = ?
            """,
            (_row_value(envelope, "tenant_id"), _row_value(envelope, "envelope_id")),
        ).fetchone()
        if floor_row is None:
            raise StorageError("warden state is missing")
        floor_value = _row_value(floor_row, "clock_floor_ns")
        if floor_value is not None and now_ns + uncertainty < int(floor_value):
            raise ClockUncertainError(
                "clock moved behind the durable warden clock floor beyond its declared uncertainty"
            )
        if advance_floor and (floor_value is None or now_ns > int(floor_value)):
            connection.execute(
                """
                UPDATE warden_state SET clock_floor_ns = ?
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (
                    now_ns,
                    _row_value(envelope, "tenant_id"),
                    _row_value(envelope, "envelope_id"),
                ),
            )
        return uncertainty

    def ready(self) -> bool:
        """Return whether the durable database and declared clock are safe for authority."""

        try:
            capacity_provider = getattr(self._store, "capacity_snapshot", None)
            if callable(capacity_provider):
                capacity = capacity_provider()
                if not bool(getattr(capacity, "healthy", False)):
                    return False
            self._require_signing_key_current()
            now_ns = self._clock.now_ns()
            with self._store.read() as transaction:
                connection = self._connection(transaction)
                self._verify_database_identity(connection)
                envelope = self._singleton_envelope(connection)
                self._clock_is_safe(
                    connection,
                    envelope,
                    now_ns=now_ns,
                    advance_floor=False,
                )
                if self._runtime_status(connection).mode is not RuntimeMode.ACTIVE:
                    return False
                if not self._invariant_snapshot(connection, envelope, now_ns).healthy:
                    return False
        except (
            ClockUncertainError,
            ConflictError,
            InvariantError,
            NotFoundError,
            SignatureError,
            StorageError,
            ValidationError,
            sqlite3.Error,
        ):
            return False
        return True

    def _sign(self, kind: str, payload: Mapping[str, Any]) -> tuple[bytes, WireObject]:
        self._require_signing_key_current()
        signing_object = {"kind": kind, "payload": payload}
        signature = self._signer.sign(canonical_json(signing_object))
        if not isinstance(signature, bytes) or not signature:
            raise SignatureError("signer returned an invalid signature")
        wire = dict(payload)
        wire["key_id"] = self._signer.key_id
        wire["signature"] = b64url_encode(signature)
        return signature, wire

    def _sign_record(
        self,
        record: LeaseGrant | Receipt | TransferVoucher | TransferAck | BranchRevocation,
    ) -> LeaseGrant | Receipt | TransferVoucher | TransferAck | BranchRevocation:
        self._require_signing_key_current()
        signature = self._signer.sign(canonical_json(record.unsigned_payload()))
        if not isinstance(signature, bytes) or not signature:
            raise SignatureError("signer returned an invalid signature")
        return replace(record, signature=b64url_encode(signature))

    def _verify_record(
        self,
        record: TransferVoucher | TransferAck | BranchRevocation | LeaseGrant | Receipt,
        *,
        warden_id: str,
    ) -> None:
        try:
            signature = b64url_decode(record.signature)
        except Exception as error:
            raise SignatureError("signed record contains malformed base64url") from error
        message = canonical_json(record.unsigned_payload())
        if warden_id == self.warden_id and record.key_id == self._signer.key_id:
            verifier = getattr(self._signer, "verify", None)
            if callable(verifier):
                try:
                    result = verifier(message, signature)
                except Exception as error:
                    raise SignatureError("invalid local record signature") from error
                if result is False:
                    raise SignatureError("invalid local record signature")
                return
        if self._trust_registry is None:
            raise SignatureError(f"no trusted key is configured for warden {warden_id!r}")
        try:
            valid = self._trust_registry.verify(
                warden_id,
                record.key_id,
                message,
                signature,
            )
        except Exception as error:
            raise SignatureError(f"could not verify record from {warden_id!r}") from error
        if not valid:
            raise SignatureError(f"invalid record signature from {warden_id!r}")

    def _verify_signed(
        self,
        kind: str,
        wire: Mapping[str, Any],
        *,
        warden_id: str,
    ) -> None:
        key_id = wire.get("key_id")
        signature_text = wire.get("signature")
        if not isinstance(key_id, str) or not isinstance(signature_text, str):
            raise SignatureError(f"signed {kind} is missing key_id or signature")
        try:
            signature = b64url_decode(signature_text)
        except Exception as error:
            raise SignatureError(f"signed {kind} contains malformed base64url") from error
        unsigned = {
            str(key): value for key, value in wire.items() if key not in {"signature", "key_id"}
        }
        message = canonical_json({"kind": kind, "payload": unsigned})

        if warden_id == self.warden_id and key_id == self._signer.key_id:
            verifier = getattr(self._signer, "verify", None)
            if callable(verifier):
                try:
                    result = verifier(message, signature)
                except Exception as error:
                    raise SignatureError(f"invalid local {kind} signature") from error
                if result is False:
                    raise SignatureError(f"invalid local {kind} signature")
                return

        if self._trust_registry is None:
            raise SignatureError(f"no trusted key is configured for warden {warden_id!r}")
        try:
            valid = self._trust_registry.verify(warden_id, key_id, message, signature)
        except Exception as error:
            raise SignatureError(f"could not verify {kind} from {warden_id!r}") from error
        if not valid:
            raise SignatureError(f"invalid {kind} signature from {warden_id!r}")

    @staticmethod
    def _policy_payload(policy: object) -> WireObject:
        payload = _object_mapping(policy)
        nested = payload.get("payload")
        if isinstance(nested, Mapping):
            merged = {str(key): value for key, value in nested.items()}
            for name in (
                "tenant_id",
                "envelope_id",
                "policy_version",
                "policy_digest",
                "machine_digest",
            ):
                if name in payload:
                    merged[name] = payload[name]
            payload = merged
        return payload

    @staticmethod
    def _machine(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        machine = payload.get("machine", payload)
        if not isinstance(machine, Mapping):
            raise ValidationError("policy machine must be an object")
        return machine

    @classmethod
    def _initial_state(cls, payload: Mapping[str, Any]) -> str:
        machine = cls._machine(payload)
        initial = machine.get("initial_state")
        if not isinstance(initial, str):
            raise ValidationError("policy initial_state must be a string")
        return require_identifier(initial, field="policy initial_state")

    @classmethod
    def _transition(
        cls,
        payload: Mapping[str, Any],
        *,
        state: str,
        name: str,
        dimensions: int,
    ) -> tuple[Mapping[str, Any], ResourceVector]:
        machine = cls._machine(payload)
        transitions = machine.get("transitions")
        if isinstance(transitions, Mapping):
            candidates: Iterable[Any] = transitions.values()
        elif isinstance(transitions, Sequence) and not isinstance(transitions, (str, bytes)):
            candidates = transitions
        else:
            raise PolicyError("registered machine has no valid transition table")
        matches: list[Mapping[str, Any]] = []
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            candidate_name = candidate.get("name", candidate.get("transition"))
            source = candidate.get("source", candidate.get("source_state"))
            if candidate_name == name and source == state:
                matches.append(candidate)
        if len(matches) != 1:
            raise PolicyError(f"transition {name!r} is not uniquely enabled from state {state!r}")
        rule = matches[0]
        target = rule.get("target", rule.get("target_state"))
        require_identifier(target, field="transition target_state")
        cost_raw = rule.get("cost")
        if not isinstance(cost_raw, Sequence) or isinstance(cost_raw, (str, bytes, bytearray)):
            raise PolicyError("transition cost is malformed")
        cost = vector(cast(Sequence[int], cost_raw), dimensions=dimensions)
        return rule, cost

    def _policy(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        envelope_id: str,
        policy_digest: str,
    ) -> tuple[sqlite3.Row, WireObject]:
        row = connection.execute(
            """
            SELECT * FROM policies
            WHERE tenant_id = ? AND envelope_id = ? AND policy_digest = ?
            """,
            (tenant_id, envelope_id, policy_digest),
        ).fetchone()
        if row is None:
            raise PolicyError(f"policy {policy_digest!r} is not registered for this envelope")
        return cast(sqlite3.Row, row), _json_object(_row_value(row, "payload"))

    @staticmethod
    def _fingerprint(operation: str, arguments: Mapping[str, Any]) -> bytes:
        return canonical_digest({"operation": operation, "arguments": arguments}).encode("ascii")

    def _idempotent_response(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        envelope_id: str,
        scope: str,
        request_id: str,
        fingerprint: bytes,
    ) -> WireObject | None:
        row = connection.execute(
            """
            SELECT scope, fingerprint, response FROM idempotency
            WHERE tenant_id = ? AND envelope_id = ? AND request_id = ?
            """,
            (tenant_id, envelope_id, request_id),
        ).fetchone()
        if row is None:
            return None
        if (
            _row_value(row, "scope") != scope
            or bytes(_row_value(row, "fingerprint")) != fingerprint
        ):
            raise ConflictError(
                f"request_id {request_id!r} was already used with incompatible arguments"
            )
        return _json_object(_row_value(row, "response"))

    @staticmethod
    def _remember_response(
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        envelope_id: str,
        scope: str,
        request_id: str,
        fingerprint: bytes,
        response: Mapping[str, Any],
        now_ns: int,
        status_code: int = 200,
    ) -> None:
        connection.execute(
            """
            INSERT INTO idempotency(
                tenant_id, envelope_id, scope, request_id, fingerprint, response,
                status_code, created_at_ns, expires_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                tenant_id,
                envelope_id,
                scope,
                request_id,
                fingerprint,
                canonical_json(response),
                status_code,
                now_ns,
            ),
        )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        envelope_id: str,
        event_type: str,
        entity_type: str | None,
        entity_id: str | None,
        actor_id: str,
        details: Mapping[str, Any],
        now_ns: int,
    ) -> None:
        row = connection.execute(
            """
            SELECT sequence, event_hash FROM audit_log
            WHERE tenant_id = ? AND envelope_id = ?
            ORDER BY sequence DESC LIMIT 1
            """,
            (tenant_id, envelope_id),
        ).fetchone()
        if row is None:
            sequence = 0
            previous_hash = bytes(32)
        else:
            sequence = int(_row_value(row, "sequence")) + 1
            previous_hash = bytes(_row_value(row, "event_hash"))
        body = {
            "sequence": sequence,
            "event_type": event_type,
            "tenant_id": tenant_id,
            "envelope_id": envelope_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "actor_id": actor_id,
            "occurred_at_ns": now_ns,
            "details": details,
        }
        _, signed = self._sign("audit-event/v1", body)
        payload = canonical_json(signed)
        hash_row = connection.execute(
            "SELECT lets_audit_hash(?, ?, ?, ?, ?, ?, ?)",
            (
                previous_hash,
                sequence,
                event_type,
                entity_type,
                entity_id,
                payload,
                now_ns,
            ),
        ).fetchone()
        if hash_row is None:
            raise StorageError("audit hash function returned no result")
        event_hash = bytes(hash_row[0])
        connection.execute(
            """
            INSERT INTO audit_log(
                tenant_id, envelope_id, sequence, event_type, entity_type,
                entity_id, payload, previous_hash, event_hash, created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                envelope_id,
                sequence,
                event_type,
                entity_type,
                entity_id,
                payload,
                previous_hash,
                event_hash,
                now_ns,
            ),
        )
        connection.execute(
            """
            INSERT INTO audit_outbox(
                tenant_id, envelope_id, sequence, event_hash, payload, created_at_ns
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (tenant_id, envelope_id, sequence, event_hash, payload, now_ns),
        )

    def _grant_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row | Mapping[str, Any],
    ) -> LeaseGrant:
        policy_row = connection.execute(
            """
            SELECT payload FROM policies
            WHERE tenant_id = ? AND envelope_id = ? AND policy_digest = ?
            """,
            (
                _row_value(row, "tenant_id"),
                _row_value(row, "envelope_id"),
                _row_value(row, "policy_digest"),
            ),
        ).fetchone()
        if policy_row is None:
            raise StorageError("lease references a missing policy")
        policy = _json_object(_row_value(policy_row, "payload"))
        policy_id = policy.get("policy_id", policy.get("policy_version"))
        if not isinstance(policy_id, str):
            raise StorageError("stored policy has no policy_id")
        return LeaseGrant(
            tenant_id=_row_value(row, "tenant_id"),
            envelope_id=_row_value(row, "envelope_id"),
            config_epoch=int(_row_value(row, "config_epoch")),
            lease_id=_row_value(row, "lease_id"),
            lineage_id=_row_value(row, "lineage_id"),
            parent_id=_row_value(row, "parent_id"),
            subject_id=_row_value(row, "subject_id"),
            warden_id=_row_value(row, "warden_id"),
            allocation=vector(_unpack_blob(_row_value(row, "allocation"))),
            capabilities=frozenset(_json_array(_row_value(row, "capabilities_json"))),
            policy_id=policy_id,
            policy_version=_row_value(row, "policy_version"),
            policy_digest=_row_value(row, "policy_digest"),
            machine_digest=_row_value(row, "machine_digest"),
            ancestor_path=tuple(_json_array(_row_value(row, "ancestor_path_json"))),
            branch_epoch=int(_row_value(row, "branch_epoch")),
            issued_at_ns=int(_row_value(row, "issued_at_ns")),
            expires_at_ns=int(_row_value(row, "expires_at_ns")),
            key_id=_row_value(row, "key_id"),
            signature=b64url_encode(bytes(_row_value(row, "signature"))),
        )

    def _snapshot_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row | Mapping[str, Any],
    ) -> LeaseSnapshot:
        return LeaseSnapshot(
            grant=self._grant_from_row(connection, row),
            residual=vector(_unpack_blob(_row_value(row, "residual"))),
            current_state=_row_value(row, "state"),
            status=LeaseStatus(_row_value(row, "status")),
            sequence=int(_row_value(row, "sequence")),
            updated_at_ns=int(_row_value(row, "updated_at_ns")),
        )

    @staticmethod
    def _load_lease(
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        envelope_id: str,
        lease_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM leases
            WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
            """,
            (tenant_id, envelope_id, lease_id),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"lease {lease_id!r} does not exist")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _lease_revoked(connection: sqlite3.Connection, lease: sqlite3.Row) -> bool:
        path = (
            *tuple(_json_array(_row_value(lease, "ancestor_path_json"))),
            _row_value(lease, "lease_id"),
        )
        placeholders = ",".join("?" for _ in path)
        # Only the number of bound placeholders is interpolated; every value remains bound.
        query = (
            "SELECT 1 FROM revocations "
            "WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ? "
            f"AND branch_lease_id IN ({placeholders}) "  # nosec B608
            "LIMIT 1"
        )
        row = connection.execute(
            query,
            (
                _row_value(lease, "tenant_id"),
                _row_value(lease, "envelope_id"),
                _row_value(lease, "lineage_id"),
                *path,
            ),
        ).fetchone()
        return row is not None

    def _require_actionable(
        self,
        connection: sqlite3.Connection,
        lease: sqlite3.Row,
        envelope: sqlite3.Row,
        *,
        now_ns: int,
    ) -> None:
        status = str(_row_value(lease, "status"))
        if status not in _ACTIONABLE:
            raise PolicyError(f"lease status {status!r} is not actionable")
        uncertainty = self._clock_is_safe(connection, envelope, now_ns=now_ns)
        if now_ns + uncertainty >= int(_row_value(lease, "expires_at_ns")):
            raise ExpiredError("lease is expired or cannot be proven fresh")
        if self._lease_revoked(connection, lease):
            raise PolicyError("lease is beneath a revoked branch")

    def runtime_status(self, *, identity: IdentityContext) -> RuntimeStatus:
        """Return the durable maintenance mode to an authorized operator."""

        with self._store.read() as transaction:
            connection = self._connection(transaction)
            self._verify_database_identity(connection)
            envelope = self._singleton_envelope(connection)
            self._require_admin(identity, cast(str, _row_value(envelope, "tenant_id")))
            return self._runtime_status(connection)

    def set_runtime_mode(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        mode: RuntimeMode | str,
        reason: str,
    ) -> RuntimeStatus:
        """Idempotently activate or drain this warden under admin authority."""

        require_identifier(request_id, field="request_id")
        try:
            requested_mode = mode if isinstance(mode, RuntimeMode) else RuntimeMode(mode)
        except ValueError as exc:
            raise ValidationError("runtime mode must be ACTIVE or DRAINING") from exc
        if not isinstance(reason, str) or not 1 <= len(reason) <= 2000:
            raise ValidationError("runtime mode reason must contain 1..2000 characters")
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            self._verify_database_identity(connection)
            envelope = self._singleton_envelope(connection)
            tenant_id = cast(str, _row_value(envelope, "tenant_id"))
            envelope_id = cast(str, _row_value(envelope, "envelope_id"))
            actor = self._require_admin(identity, tenant_id)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            fingerprint = self._fingerprint(
                "set_runtime_mode",
                {"actor": actor, "mode": requested_mode.value, "reason": reason},
            )
            prior = self._idempotent_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope="set_runtime_mode",
                request_id=request_id,
                fingerprint=fingerprint,
            )
            if prior is not None:
                return RuntimeStatus.from_dict(prior)
            current = self._runtime_status(connection)
            if current.mode is requested_mode and current.reason == reason:
                updated = current
            else:
                updated = RuntimeStatus(
                    mode=requested_mode,
                    generation=current.generation + 1,
                    reason=reason,
                    changed_at_ns=now_ns,
                    changed_by=actor,
                )
                cursor = connection.execute(
                    """
                    UPDATE runtime_control
                    SET mode = ?, generation = ?, reason = ?, changed_at_ns = ?, changed_by = ?
                    WHERE singleton = 1 AND generation = ?
                    """,
                    (
                        updated.mode.value,
                        updated.generation,
                        updated.reason,
                        updated.changed_at_ns,
                        updated.changed_by,
                        current.generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ConflictError("runtime control changed concurrently")
                self._append_audit(
                    connection,
                    tenant_id=tenant_id,
                    envelope_id=envelope_id,
                    event_type="warden.runtime-mode-changed",
                    entity_type="warden",
                    entity_id=self.warden_id,
                    actor_id=actor,
                    details={
                        "previous_mode": current.mode.value,
                        "mode": updated.mode.value,
                        "generation": updated.generation,
                        "reason": updated.reason,
                    },
                    now_ns=now_ns,
                )
            self._remember_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope="set_runtime_mode",
                request_id=request_id,
                fingerprint=fingerprint,
                response=updated.to_dict(),
                now_ns=now_ns,
            )
            return updated

    def create_envelope(
        self,
        *,
        identity: IdentityContext,
        tenant_id: str,
        envelope_id: str,
        config_epoch: int,
        budget: Sequence[int],
        local_share: Sequence[int],
        receipt_ttl_ns: int = 1_000_000_000,
        max_clock_uncertainty_ns: int = 0,
        transfer_gap_window: int = 64,
        dimension_metadata: Sequence[Mapping[str, Any]] = (),
        config: Mapping[str, Any] | None = None,
    ) -> InvariantSnapshot:
        """Create the immutable local projection of a signed genesis envelope."""

        actor = self._require_admin(identity, tenant_id)
        require_identifier(envelope_id, field="envelope_id")
        if (
            isinstance(config_epoch, bool)
            or not isinstance(config_epoch, int)
            or config_epoch <= 0
            or config_epoch > MAX_RESOURCE
        ):
            raise ValidationError("config_epoch must be a positive integer")
        configured_budget = vector(budget)
        if len(configured_budget) > 256:
            raise ValidationError("LETS v1 envelopes support at most 256 resource dimensions")
        share = vector(local_share, dimensions=len(configured_budget))
        if not less_than_or_equal(share, configured_budget):
            raise ValidationError("local genesis share exceeds the configured envelope budget")
        for name, value, allow_zero in (
            ("receipt_ttl_ns", receipt_ttl_ns, False),
            ("max_clock_uncertainty_ns", max_clock_uncertainty_ns, True),
            ("transfer_gap_window", transfer_gap_window, False),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or (not allow_zero and value == 0)
                or value > MAX_RESOURCE
            ):
                qualifier = (
                    "a non-negative signed 64-bit integer"
                    if allow_zero
                    else "a positive signed 64-bit integer"
                )
                raise ValidationError(f"{name} must be {qualifier}")
        if transfer_gap_window > MAX_TRANSFER_GAP_WINDOW:
            raise ValidationError(
                f"transfer_gap_window exceeds the v1 limit of {MAX_TRANSFER_GAP_WINDOW}"
            )
        metadata = [dict(item) for item in dimension_metadata]
        if metadata and len(metadata) != len(configured_budget):
            raise ValidationError("dimension metadata must match the resource-vector dimensions")
        now_ns = self._clock.now_ns()
        configuration = {
            "tenant_id": tenant_id,
            "envelope_id": envelope_id,
            "config_epoch": config_epoch,
            "budget": list(configured_budget),
            "local_share": list(share),
            "receipt_ttl_ns": receipt_ttl_ns,
            "max_clock_uncertainty_ns": max_clock_uncertainty_ns,
            "transfer_gap_window": transfer_gap_window,
            "dimension_metadata": metadata,
            "extensions": {} if config is None else dict(config),
        }
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            self._verify_database_identity(connection)
            existing = connection.execute("SELECT * FROM envelopes WHERE singleton = 1").fetchone()
            if existing is not None:
                self._clock_is_safe(
                    connection,
                    cast(sqlite3.Row, existing),
                    now_ns=now_ns,
                )
                existing_config = _json_object(_row_value(existing, "config_json"))
                if existing_config != configuration:
                    raise ConflictError("this database already contains a different envelope")
                return self._invariant_snapshot(connection, cast(sqlite3.Row, existing), now_ns)
            self._require_runtime_active(connection)
            connection.execute(
                """
                INSERT INTO envelopes(
                    tenant_id, envelope_id, singleton, config_epoch, dimension_count,
                    dimension_metadata_json, budget, initial_local_share, receipt_ttl_ns,
                    max_clock_uncertainty_ns, transfer_gap_window, config_json, created_at_ns
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    envelope_id,
                    config_epoch,
                    len(configured_budget),
                    canonical_json(metadata),
                    pack(configured_budget),
                    pack(share),
                    receipt_ttl_ns,
                    max_clock_uncertainty_ns,
                    transfer_gap_window,
                    canonical_json(configuration),
                    now_ns,
                ),
            )
            empty = zero(len(configured_budget))
            connection.execute(
                """
                INSERT INTO warden_state(
                    tenant_id, envelope_id, free_pool, lease_residual, consumed,
                    transferred_in, transferred_out, clock_floor_ns, revision, updated_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    tenant_id,
                    envelope_id,
                    pack(share),
                    pack(empty),
                    pack(empty),
                    pack(empty),
                    pack(empty),
                    now_ns,
                    now_ns,
                ),
            )
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="envelope.created",
                entity_type="envelope",
                entity_id=envelope_id,
                actor_id=actor,
                details={"config_digest": canonical_digest(configuration)},
                now_ns=now_ns,
            )
            envelope = self._envelope(connection, tenant_id, envelope_id)
            return self._invariant_snapshot(connection, envelope, now_ns)

    def register_policy(self, policy: object) -> str:
        """Register one immutable, content-addressed policy and machine."""

        payload = self._policy_payload(policy)
        allowed_policy_fields = {
            "tenant_id",
            "envelope_id",
            "policy_id",
            "policy_version",
            "resources",
            "machine",
            "machine_digest",
            "max_lease_ttl_ns",
            "receipt_ttl_ns",
            "max_clock_uncertainty_ns",
            "transfer_gap_window",
            "policy_digest",
        }
        unknown_policy_fields = set(payload) - allowed_policy_fields
        if unknown_policy_fields:
            raise ValidationError(f"unknown policy fields: {sorted(unknown_policy_fields)}")
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            self._verify_database_identity(connection)
            envelope = self._singleton_envelope(connection)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            tenant_id = payload.get("tenant_id", _row_value(envelope, "tenant_id"))
            envelope_id = payload.get("envelope_id", _row_value(envelope, "envelope_id"))
            if tenant_id != _row_value(envelope, "tenant_id") or envelope_id != _row_value(
                envelope, "envelope_id"
            ):
                raise PolicyError("policy tenant/envelope binding does not match this warden")
            machine = self._machine(payload)
            machine_digest = payload.get("machine_digest", machine.get("machine_digest"))
            computed_machine_digest = canonical_digest(
                {str(key): value for key, value in machine.items() if key != "machine_digest"}
            )
            if machine_digest is None:
                machine_digest = computed_machine_digest
                payload["machine_digest"] = machine_digest
            require_digest(machine_digest, field="machine_digest")
            if machine_digest != computed_machine_digest:
                raise ValidationError("machine_digest does not match the canonical machine")
            semantic = {str(key): value for key, value in payload.items() if key != "policy_digest"}
            computed_policy_digest = canonical_digest(semantic)
            policy_digest = payload.get("policy_digest", computed_policy_digest)
            require_digest(policy_digest, field="policy_digest")
            if policy_digest != computed_policy_digest:
                raise ValidationError("policy_digest does not match the canonical policy")
            payload["policy_digest"] = policy_digest
            policy_version = payload.get("policy_version")
            policy_id = payload.get("policy_id", policy_version)
            if not isinstance(policy_version, str) or not isinstance(policy_id, str):
                raise ValidationError("policy_id and policy_version are required")
            require_identifier(policy_version, field="policy_version")
            require_identifier(policy_id, field="policy_id")
            dimensions = int(_row_value(envelope, "dimension_count"))
            resources = payload.get("resources")
            if not isinstance(resources, Sequence) or isinstance(resources, (str, bytes)):
                raise ValidationError("policy resources must be an array")
            if len(resources) != dimensions:
                raise ValidationError("policy resource dimensions do not match the envelope")
            for policy_field, envelope_field in (
                ("receipt_ttl_ns", "receipt_ttl_ns"),
                ("max_clock_uncertainty_ns", "max_clock_uncertainty_ns"),
                ("transfer_gap_window", "transfer_gap_window"),
            ):
                if payload.get(policy_field) != _row_value(envelope, envelope_field):
                    raise ValidationError(
                        f"policy {policy_field} does not match immutable envelope configuration"
                    )
            self._initial_state(payload)
            machine_transitions = machine.get("transitions")
            if not isinstance(machine_transitions, (Mapping, Sequence)) or isinstance(
                machine_transitions, (str, bytes)
            ):
                raise ValidationError("policy transitions must be an object or array")
            transition_values = (
                tuple(machine_transitions.values())
                if isinstance(machine_transitions, Mapping)
                else tuple(machine_transitions)
            )
            if not transition_values or len(transition_values) > MAX_MACHINE_TRANSITIONS:
                raise ValidationError(
                    "policy machine must define between 1 and "
                    f"{MAX_MACHINE_TRANSITIONS} transitions"
                )
            names: set[tuple[str, str]] = set()
            for item in transition_values:
                if not isinstance(item, Mapping):
                    raise ValidationError("each transition must be an object")
                name = item.get("name", item.get("transition"))
                source = item.get("source", item.get("source_state"))
                target = item.get("target", item.get("target_state"))
                capability = item.get("capability")
                for field_name, value in (
                    ("transition name", name),
                    ("transition source", source),
                    ("transition target", target),
                    ("transition capability", capability),
                ):
                    if not isinstance(value, str):
                        raise ValidationError(f"{field_name} must be a string")
                    require_identifier(value, field=field_name)
                transition_key = (cast(str, source), cast(str, name))
                if transition_key in names:
                    raise ValidationError(f"duplicate transition {transition_key!r}")
                names.add(transition_key)
                cost_raw = item.get("cost")
                if not isinstance(cost_raw, Sequence) or isinstance(cost_raw, (str, bytes)):
                    raise ValidationError("transition cost must be an integer array")
                checked_cost = vector(cast(Sequence[int], cost_raw), dimensions=dimensions)
                if not any(checked_cost):
                    raise ValidationError("transition cost must contain a non-zero dimension")
                raw_evidence = item.get("evidence")
                if raw_evidence is not None:
                    if not isinstance(raw_evidence, dict):
                        raise ValidationError("transition evidence must be an object")
                    EvidenceRule.from_dict(raw_evidence)

            stored_payload = canonical_json(payload)
            existing = connection.execute(
                """
                SELECT policy_digest, payload FROM policies
                WHERE tenant_id = ? AND envelope_id = ? AND policy_version = ?
                """,
                (tenant_id, envelope_id, policy_version),
            ).fetchone()
            if existing is not None:
                if (
                    _row_value(existing, "policy_digest") != policy_digest
                    or bytes(_row_value(existing, "payload")) != stored_payload
                ):
                    raise ConflictError("policy_version is already bound to different content")
                return cast(str, policy_digest)
            self._require_runtime_active(connection)
            active = (
                1
                if connection.execute(
                    """
                SELECT 1 FROM policies
                WHERE tenant_id = ? AND envelope_id = ? AND active = 1
                """,
                    (tenant_id, envelope_id),
                ).fetchone()
                is None
                else 0
            )
            connection.execute(
                """
                INSERT INTO policies(
                    tenant_id, envelope_id, policy_version, policy_digest,
                    machine_digest, payload, active, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    envelope_id,
                    policy_version,
                    policy_digest,
                    machine_digest,
                    stored_payload,
                    active,
                    now_ns,
                ),
            )
            self._append_audit(
                connection,
                tenant_id=cast(str, tenant_id),
                envelope_id=cast(str, envelope_id),
                event_type="policy.registered",
                entity_type="policy",
                entity_id=policy_digest,
                actor_id=self.warden_id,
                details={
                    "policy_id": policy_id,
                    "policy_version": policy_version,
                    "machine_digest": machine_digest,
                    "active": bool(active),
                },
                now_ns=now_ns,
            )
            return cast(str, policy_digest)

    @staticmethod
    def _positive_ttl(ttl_ns: int) -> int:
        if (
            isinstance(ttl_ns, bool)
            or not isinstance(ttl_ns, int)
            or ttl_ns <= 0
            or ttl_ns > MAX_RESOURCE
        ):
            raise ValidationError("ttl_ns must be a positive signed 64-bit integer")
        return ttl_ns

    def _new_grant(
        self,
        *,
        tenant_id: str,
        envelope_id: str,
        config_epoch: int,
        lease_id: str,
        lineage_id: str,
        parent_id: str | None,
        subject_id: str,
        allocation: ResourceVector,
        capabilities: frozenset[str],
        policy_row: sqlite3.Row,
        policy_payload: Mapping[str, Any],
        ancestor_path: tuple[str, ...],
        branch_epoch: int,
        issued_at_ns: int,
        expires_at_ns: int,
    ) -> LeaseGrant:
        policy_id = policy_payload.get("policy_id", policy_payload.get("policy_version"))
        if not isinstance(policy_id, str):
            raise StorageError("stored policy has no policy_id")
        unsigned = LeaseGrant(
            tenant_id=tenant_id,
            envelope_id=envelope_id,
            config_epoch=config_epoch,
            lease_id=lease_id,
            lineage_id=lineage_id,
            parent_id=parent_id,
            subject_id=subject_id,
            warden_id=self.warden_id,
            allocation=allocation,
            capabilities=capabilities,
            policy_id=policy_id,
            policy_version=_row_value(policy_row, "policy_version"),
            policy_digest=_row_value(policy_row, "policy_digest"),
            machine_digest=_row_value(policy_row, "machine_digest"),
            ancestor_path=ancestor_path,
            branch_epoch=branch_epoch,
            issued_at_ns=issued_at_ns,
            expires_at_ns=expires_at_ns,
            key_id=self._signer.key_id,
        )
        return cast(LeaseGrant, self._sign_record(unsigned))

    @staticmethod
    def _insert_lease(
        connection: sqlite3.Connection,
        *,
        grant: LeaseGrant,
        residual: ResourceVector,
        state: str,
        status: LeaseStatus,
        sequence: int,
        now_ns: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO leases(
                tenant_id, envelope_id, lease_id, lineage_id, parent_id, subject_id,
                warden_id, allocation, residual, capabilities_json, machine_digest,
                ancestor_path_json, branch_epoch, config_epoch, issued_at_ns,
                expires_at_ns, key_id, signature, state, status, sequence,
                policy_version, policy_digest, created_at_ns, updated_at_ns
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                grant.tenant_id,
                grant.envelope_id,
                grant.lease_id,
                grant.lineage_id,
                grant.parent_id,
                grant.subject_id,
                grant.warden_id,
                pack(grant.allocation),
                pack(residual),
                canonical_json(sorted(grant.capabilities)),
                grant.machine_digest,
                canonical_json(grant.ancestor_path),
                grant.branch_epoch,
                grant.config_epoch,
                grant.issued_at_ns,
                grant.expires_at_ns,
                grant.key_id,
                b64url_decode(grant.signature),
                state,
                status.value,
                sequence,
                grant.policy_version,
                grant.policy_digest,
                now_ns,
                now_ns,
            ),
        )

    def issue_root(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        tenant_id: str,
        envelope_id: str,
        subject_id: str,
        allocation: Sequence[int],
        capabilities: Iterable[str],
        policy_digest: str,
        ttl_ns: int,
        lineage_id: str | None = None,
    ) -> LeaseGrant:
        """Idempotently debit the local free pool and issue a signed root grant."""

        require_identifier(request_id, field="request_id")
        require_identifier(envelope_id, field="envelope_id")
        require_digest(policy_digest, field="policy_digest")
        actor, scopes = self._bind_tenant(identity, tenant_id)
        require_identifier(subject_id, field="subject_id")
        if not self._has_scope(scopes, _ROOT_ISSUER_SCOPES):
            raise PolicyError("root lease issuance scope is required")
        ttl = self._positive_ttl(ttl_ns)
        requested_lineage = None
        if lineage_id is not None:
            requested_lineage = require_identifier(lineage_id, field="lineage_id")
        requested_capabilities = frozenset(
            require_identifier(item, field="capability") for item in capabilities
        )
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            self._verify_database_identity(connection)
            envelope = self._envelope(connection, tenant_id, envelope_id)
            uncertainty = self._clock_is_safe(connection, envelope, now_ns=now_ns)
            checked_allocation = vector(
                allocation,
                dimensions=int(_row_value(envelope, "dimension_count")),
            )
            if not any(checked_allocation):
                raise ValidationError("root allocation must contain a non-zero dimension")
            fingerprint = self._fingerprint(
                "issue_root",
                {
                    "actor": actor,
                    "subject_id": subject_id,
                    "allocation": list(checked_allocation),
                    "capabilities": sorted(requested_capabilities),
                    "policy_digest": policy_digest,
                    "ttl_ns": ttl,
                    "lineage_id": requested_lineage,
                    "config_epoch": int(_row_value(envelope, "config_epoch")),
                },
            )
            prior = self._idempotent_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope="issue_root",
                request_id=request_id,
                fingerprint=fingerprint,
            )
            if prior is not None:
                return LeaseGrant.from_dict(prior)
            self._require_runtime_active(connection)
            policy_row, policy = self._policy(
                connection,
                tenant_id,
                envelope_id,
                policy_digest,
            )
            machine = self._machine(policy)
            transitions = machine.get("transitions")
            transition_values: Iterable[Any]
            if isinstance(transitions, Mapping):
                transition_values = transitions.values()
            elif isinstance(transitions, Sequence) and not isinstance(transitions, (str, bytes)):
                transition_values = transitions
            else:
                raise StorageError("registered policy transition table is malformed")
            declared_capabilities = {
                candidate.get("capability")
                for candidate in transition_values
                if isinstance(candidate, Mapping) and isinstance(candidate.get("capability"), str)
            }
            if not requested_capabilities.issubset(declared_capabilities):
                raise PolicyError("root grant requests capabilities undeclared by its policy")
            maximum_ttl = policy.get("max_lease_ttl_ns")
            if not isinstance(maximum_ttl, int) or ttl > maximum_ttl:
                raise PolicyError("requested root TTL exceeds the registered policy maximum")
            state_row = connection.execute(
                """
                SELECT free_pool FROM warden_state
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (tenant_id, envelope_id),
            ).fetchone()
            if state_row is None:
                raise StorageError("warden state is missing")
            free_pool = _unpack_blob(_row_value(state_row, "free_pool"))
            if not less_than_or_equal(checked_allocation, free_pool):
                raise PolicyError("local warden free pool lacks the requested root allocation")
            expires_at_ns = now_ns + ttl
            if expires_at_ns <= now_ns + uncertainty:
                raise ExpiredError("requested root lease is not fresh under clock uncertainty")
            lease_id = new_id("lease")
            actual_lineage = requested_lineage or new_id("lineage")
            grant = self._new_grant(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                config_epoch=int(_row_value(envelope, "config_epoch")),
                lease_id=lease_id,
                lineage_id=actual_lineage,
                parent_id=None,
                subject_id=subject_id,
                allocation=checked_allocation,
                capabilities=requested_capabilities,
                policy_row=policy_row,
                policy_payload=policy,
                ancestor_path=(),
                branch_epoch=0,
                issued_at_ns=now_ns,
                expires_at_ns=expires_at_ns,
            )
            self._insert_lease(
                connection,
                grant=grant,
                residual=checked_allocation,
                state=self._initial_state(policy),
                status=LeaseStatus.ACTIVE,
                sequence=0,
                now_ns=now_ns,
            )
            connection.execute(
                """
                UPDATE warden_state
                SET free_pool = ?, revision = revision + 1, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (
                    pack(subtract(free_pool, checked_allocation)),
                    now_ns,
                    tenant_id,
                    envelope_id,
                ),
            )
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="lease.root-issued",
                entity_type="lease",
                entity_id=lease_id,
                actor_id=actor,
                details={
                    "lineage_id": actual_lineage,
                    "allocation": list(checked_allocation),
                    "policy_digest": policy_digest,
                },
                now_ns=now_ns,
            )
            self._remember_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope="issue_root",
                request_id=request_id,
                fingerprint=fingerprint,
                response=grant.to_dict(),
                now_ns=now_ns,
                status_code=201,
            )
            return grant

    def spawn(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        parent_id: str,
        subject_id: str,
        allocation: Sequence[int],
        capabilities: Iterable[str],
        ttl_ns: int,
        policy_digest: str | None = None,
        expected_sequence: int | None = None,
    ) -> LeaseGrant:
        """Atomically partition a parent's residual rights into a child grant."""

        require_identifier(request_id, field="request_id")
        require_identifier(parent_id, field="parent_id")
        require_identifier(subject_id, field="subject_id")
        ttl = self._positive_ttl(ttl_ns)
        child_capabilities = frozenset(
            require_identifier(item, field="capability") for item in capabilities
        )
        if policy_digest is not None:
            require_digest(policy_digest, field="policy_digest")
        if expected_sequence is not None and (
            isinstance(expected_sequence, bool)
            or not isinstance(expected_sequence, int)
            or expected_sequence < 0
            or expected_sequence > MAX_RESOURCE
        ):
            raise ValidationError("expected_sequence must be a non-negative integer")
        identity_tenant, actor, scopes = self._identity_fields(identity)
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match parent tenant")
            parent = self._load_lease(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                lease_id=parent_id,
            )
            if actor != _row_value(parent, "subject_id") and not self._has_scope(
                scopes, _SUBJECT_LIFECYCLE_SCOPES
            ):
                raise PolicyError("only the parent subject may spawn a child")
            selected_policy_digest = policy_digest or str(_row_value(parent, "policy_digest"))
            checked_allocation = vector(
                allocation,
                dimensions=int(_row_value(envelope, "dimension_count")),
            )
            if not any(checked_allocation):
                raise ValidationError("child allocation must contain a non-zero dimension")
            fingerprint = self._fingerprint(
                "spawn",
                {
                    "actor": actor,
                    "parent_id": parent_id,
                    "subject_id": subject_id,
                    "allocation": list(checked_allocation),
                    "capabilities": sorted(child_capabilities),
                    "ttl_ns": ttl,
                    "policy_digest": selected_policy_digest,
                    "expected_sequence": expected_sequence,
                    "config_epoch": int(_row_value(envelope, "config_epoch")),
                },
            )
            prior = self._idempotent_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"spawn:{parent_id}",
                request_id=request_id,
                fingerprint=fingerprint,
            )
            if prior is not None:
                return LeaseGrant.from_dict(prior)
            self._require_runtime_active(connection)
            self._require_actionable(connection, parent, envelope, now_ns=now_ns)
            parent_sequence = int(_row_value(parent, "sequence"))
            if expected_sequence is not None and parent_sequence != expected_sequence:
                raise ConflictError(
                    f"parent sequence is {parent_sequence}, expected {expected_sequence}"
                )
            parent_capabilities = frozenset(_json_array(_row_value(parent, "capabilities_json")))
            if not child_capabilities.issubset(parent_capabilities):
                raise PolicyError("child capability set is not attenuated from its parent")
            parent_residual = _unpack_blob(_row_value(parent, "residual"))
            if not less_than_or_equal(checked_allocation, parent_residual):
                raise PolicyError("parent residual does not cover the child allocation")
            policy_row, policy = self._policy(
                connection,
                tenant_id,
                envelope_id,
                selected_policy_digest,
            )
            if selected_policy_digest != _row_value(parent, "policy_digest"):
                raise PolicyError("child policy is not inherited exactly from its parent")
            maximum_ttl = policy.get("max_lease_ttl_ns")
            if not isinstance(maximum_ttl, int) or ttl > maximum_ttl:
                raise PolicyError("requested child TTL exceeds the registered policy maximum")
            expires_at_ns = min(now_ns + ttl, int(_row_value(parent, "expires_at_ns")))
            uncertainty = self._clock_is_safe(connection, envelope, now_ns=now_ns)
            if expires_at_ns <= now_ns + uncertainty:
                raise ExpiredError("child expiry is not fresh under clock uncertainty")
            lease_id = new_id("lease")
            parent_path = tuple(_json_array(_row_value(parent, "ancestor_path_json")))
            if len(parent_path) >= MAX_LINEAGE_DEPTH:
                raise PolicyError(
                    f"child would exceed the v1 lineage depth limit of {MAX_LINEAGE_DEPTH}"
                )
            grant = self._new_grant(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                config_epoch=int(_row_value(envelope, "config_epoch")),
                lease_id=lease_id,
                lineage_id=str(_row_value(parent, "lineage_id")),
                parent_id=parent_id,
                subject_id=subject_id,
                allocation=checked_allocation,
                capabilities=child_capabilities,
                policy_row=policy_row,
                policy_payload=policy,
                ancestor_path=(*parent_path, parent_id),
                branch_epoch=int(_row_value(parent, "branch_epoch")),
                issued_at_ns=now_ns,
                expires_at_ns=expires_at_ns,
            )
            connection.execute(
                """
                UPDATE leases
                SET residual = ?, sequence = sequence + 1, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                """,
                (
                    pack(subtract(parent_residual, checked_allocation)),
                    now_ns,
                    tenant_id,
                    envelope_id,
                    parent_id,
                ),
            )
            self._insert_lease(
                connection,
                grant=grant,
                residual=checked_allocation,
                state=self._initial_state(policy),
                status=LeaseStatus.ACTIVE,
                sequence=0,
                now_ns=now_ns,
            )
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="lease.spawned",
                entity_type="lease",
                entity_id=lease_id,
                actor_id=actor,
                details={
                    "parent_id": parent_id,
                    "lineage_id": _row_value(parent, "lineage_id"),
                    "allocation": list(checked_allocation),
                    "policy_digest": selected_policy_digest,
                },
                now_ns=now_ns,
            )
            self._remember_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"spawn:{parent_id}",
                request_id=request_id,
                fingerprint=fingerprint,
                response=grant.to_dict(),
                now_ns=now_ns,
                status_code=201,
            )
            return grant

    def authorize(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        lease_id: str,
        transition: str,
        audience: str,
        nonce: str,
        evidence: Mapping[str, Any] | None = None,
        expected_state: str | None = None,
        expected_sequence: int | None = None,
    ) -> Receipt:
        """Authorize, debit, advance state/sequence, and persist one signed receipt."""

        require_identifier(request_id, field="request_id")
        require_identifier(lease_id, field="lease_id")
        require_identifier(transition, field="transition")
        require_identifier(audience, field="executor audience")
        require_identifier(nonce, field="nonce")
        if len(nonce) < 16:
            raise ValidationError("nonce must contain at least 16 characters")
        if expected_state is not None:
            require_identifier(expected_state, field="expected_state")
        if expected_sequence is not None and (
            isinstance(expected_sequence, bool)
            or not isinstance(expected_sequence, int)
            or expected_sequence < 0
            or expected_sequence > MAX_RESOURCE
        ):
            raise ValidationError("expected_sequence must be a non-negative integer")
        if evidence is not None and not isinstance(evidence, Mapping):
            raise ValidationError("evidence must be an object")
        evidence_object = None if evidence is None else dict(evidence)
        evidence_digest = canonical_digest(evidence_object) if evidence_object is not None else None
        identity_tenant, actor, scopes = self._identity_fields(identity)
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match lease tenant")
            lease = self._load_lease(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                lease_id=lease_id,
            )
            if actor != _row_value(lease, "subject_id") and not self._has_scope(
                scopes, _SUBJECT_LIFECYCLE_SCOPES
            ):
                raise PolicyError("authenticated subject does not own this lease")
            fingerprint = self._fingerprint(
                "authorize",
                {
                    "actor": actor,
                    "lease_id": lease_id,
                    "transition": transition,
                    "audience": audience,
                    "nonce": nonce,
                    "evidence_digest": evidence_digest,
                    "expected_state": expected_state,
                    "expected_sequence": expected_sequence,
                    "policy_digest": _row_value(lease, "policy_digest"),
                    "machine_digest": _row_value(lease, "machine_digest"),
                    "config_epoch": int(_row_value(envelope, "config_epoch")),
                },
            )
            prior = self._idempotent_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"authorize:{lease_id}",
                request_id=request_id,
                fingerprint=fingerprint,
            )
            if prior is not None:
                return Receipt.from_dict(prior)
            self._require_runtime_active(connection)
            self._require_actionable(connection, lease, envelope, now_ns=now_ns)
            current_state = str(_row_value(lease, "state"))
            current_sequence = int(_row_value(lease, "sequence"))
            if expected_state is not None and current_state != expected_state:
                raise ConflictError(
                    f"lease state is {current_state!r}, expected {expected_state!r}"
                )
            if expected_sequence is not None and current_sequence != expected_sequence:
                raise ConflictError(
                    f"lease sequence is {current_sequence}, expected {expected_sequence}"
                )
            duplicate_nonce = connection.execute(
                """
                SELECT request_id FROM receipts
                WHERE tenant_id = ? AND envelope_id = ?
                  AND executor_audience = ? AND nonce = ?
                LIMIT 1
                """,
                (tenant_id, envelope_id, audience, nonce),
            ).fetchone()
            if duplicate_nonce is not None:
                raise ReplayError("executor nonce was already authorized")
            policy_row, policy = self._policy(
                connection,
                tenant_id,
                envelope_id,
                str(_row_value(lease, "policy_digest")),
            )
            if _row_value(policy_row, "machine_digest") != _row_value(lease, "machine_digest"):
                raise PolicyError("lease machine digest is not bound to its registered policy")
            rule, cost = self._transition(
                policy,
                state=current_state,
                name=transition,
                dimensions=int(_row_value(envelope, "dimension_count")),
            )
            capability = rule.get("capability")
            if not isinstance(capability, str):
                raise PolicyError("transition has no valid capability binding")
            lease_capabilities = frozenset(_json_array(_row_value(lease, "capabilities_json")))
            if capability not in lease_capabilities:
                raise PolicyError(f"lease lacks transition capability {capability!r}")
            allowed_audiences = rule.get("audiences")
            if allowed_audiences is None and "audience" in rule:
                allowed_audiences = [rule["audience"]]
            if allowed_audiences is not None:
                if isinstance(allowed_audiences, str):
                    allowed = frozenset({allowed_audiences})
                elif isinstance(allowed_audiences, Sequence):
                    allowed = frozenset(allowed_audiences)
                else:
                    raise PolicyError("transition audience policy is malformed")
                if audience not in allowed:
                    raise PolicyError("executor audience is not allowed for this transition")
            try:
                evidence_allowed = self._evidence_evaluator(
                    rule.get("evidence"),
                    evidence_object,
                    now_ns=now_ns,
                    subject_id=str(_row_value(lease, "subject_id")),
                    audience=audience,
                )
            except (PolicyError, ValidationError):
                raise
            except Exception as error:
                raise PolicyError("evidence evaluator failed closed") from error
            if evidence_allowed is not True:
                raise PolicyError("transition evidence predicate was not satisfied")
            residual = _unpack_blob(_row_value(lease, "residual"))
            if not less_than_or_equal(cost, residual):
                raise PolicyError("lease residual does not cover transition cost")
            state_row = connection.execute(
                """
                SELECT consumed FROM warden_state
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (tenant_id, envelope_id),
            ).fetchone()
            if state_row is None:
                raise StorageError("warden state is missing")
            consumed = _unpack_blob(_row_value(state_row, "consumed"))
            target_state = rule.get("target", rule.get("target_state"))
            if not isinstance(target_state, str):
                raise PolicyError("transition target state is malformed")
            resulting_sequence = current_sequence + 1
            receipt_expires_at = min(
                now_ns + int(_row_value(envelope, "receipt_ttl_ns")),
                int(_row_value(lease, "expires_at_ns")),
            )
            prior_receipt = connection.execute(
                """
                SELECT expires_at_ns FROM receipts
                WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                  AND executor_audience = ?
                ORDER BY resulting_sequence DESC
                LIMIT 1
                """,
                (tenant_id, envelope_id, lease_id, audience),
            ).fetchone()
            if prior_receipt is not None and receipt_expires_at < int(
                _row_value(prior_receipt, "expires_at_ns")
            ):
                raise ConflictError(
                    "receipt expiry would regress below an outstanding authorization horizon"
                )
            uncertainty = self._clock_is_safe(connection, envelope, now_ns=now_ns)
            if receipt_expires_at <= now_ns + uncertainty:
                raise ExpiredError("receipt cannot be fresh under clock uncertainty")
            policy_id = policy.get("policy_id", policy.get("policy_version"))
            if not isinstance(policy_id, str):
                raise StorageError("stored policy has no policy_id")
            unsigned_receipt = Receipt(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                config_epoch=int(_row_value(envelope, "config_epoch")),
                receipt_id=new_id("receipt"),
                request_id=request_id,
                warden_id=self.warden_id,
                key_id=self._signer.key_id,
                policy_id=policy_id,
                policy_version=str(_row_value(policy_row, "policy_version")),
                policy_digest=str(_row_value(policy_row, "policy_digest")),
                machine_digest=str(_row_value(policy_row, "machine_digest")),
                lease_id=lease_id,
                lineage_id=str(_row_value(lease, "lineage_id")),
                subject_id=str(_row_value(lease, "subject_id")),
                executor_audience=audience,
                transition=transition,
                source_state=current_state,
                target_state=target_state,
                cost=cost,
                resulting_sequence=resulting_sequence,
                evidence_digest=evidence_digest,
                nonce=nonce,
                issued_at_ns=now_ns,
                expires_at_ns=receipt_expires_at,
            )
            receipt = cast(Receipt, self._sign_record(unsigned_receipt))
            receipt_payload = canonical_json(receipt.to_dict())
            connection.execute(
                """
                UPDATE leases
                SET residual = ?, state = ?, sequence = ?, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                """,
                (
                    pack(subtract(residual, cost)),
                    target_state,
                    resulting_sequence,
                    now_ns,
                    tenant_id,
                    envelope_id,
                    lease_id,
                ),
            )
            connection.execute(
                """
                UPDATE warden_state
                SET consumed = ?, revision = revision + 1, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (pack(add(consumed, cost)), now_ns, tenant_id, envelope_id),
            )
            connection.execute(
                """
                INSERT INTO receipts(
                    tenant_id, envelope_id, receipt_id, request_id, warden_id,
                    key_id, config_epoch, policy_version, policy_digest,
                    machine_digest, lease_id, lineage_id, subject_id,
                    executor_audience, transition_name, source_state, target_state,
                    cost, resulting_sequence, evidence_digest, nonce, issued_at_ns,
                    expires_at_ns, signature, payload
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    tenant_id,
                    envelope_id,
                    receipt.receipt_id,
                    request_id,
                    self.warden_id,
                    receipt.key_id,
                    receipt.config_epoch,
                    receipt.policy_version,
                    receipt.policy_digest,
                    receipt.machine_digest,
                    lease_id,
                    receipt.lineage_id,
                    receipt.subject_id,
                    audience,
                    transition,
                    current_state,
                    target_state,
                    pack(cost),
                    resulting_sequence,
                    evidence_digest,
                    nonce,
                    now_ns,
                    receipt_expires_at,
                    b64url_decode(receipt.signature),
                    receipt_payload,
                ),
            )
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="transition.authorized",
                entity_type="receipt",
                entity_id=receipt.receipt_id,
                actor_id=actor,
                details={
                    "lease_id": lease_id,
                    "transition": transition,
                    "source_state": current_state,
                    "target_state": target_state,
                    "cost": list(cost),
                    "resulting_sequence": resulting_sequence,
                    "executor_audience": audience,
                    "evidence_digest": evidence_digest,
                },
                now_ns=now_ns,
            )
            self._remember_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"authorize:{lease_id}",
                request_id=request_id,
                fingerprint=fingerprint,
                response=receipt.to_dict(),
                now_ns=now_ns,
            )
            return receipt

    def renew(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        lease_id: str,
        ttl_ns: int,
        expected_sequence: int | None = None,
        cascade: bool = False,
    ) -> LeaseSnapshot:
        """Renew a lease while preserving every ancestor/descendant expiry bound."""

        require_identifier(request_id, field="request_id")
        require_identifier(lease_id, field="lease_id")
        ttl = self._positive_ttl(ttl_ns)
        if expected_sequence is not None and (
            isinstance(expected_sequence, bool)
            or not isinstance(expected_sequence, int)
            or expected_sequence < 0
            or expected_sequence > MAX_RESOURCE
        ):
            raise ValidationError("expected_sequence must be a non-negative integer")
        identity_tenant, actor, scopes = self._identity_fields(identity)
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match lease tenant")
            lease = self._load_lease(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                lease_id=lease_id,
            )
            if actor != _row_value(lease, "subject_id") and not self._has_scope(
                scopes, _SUBJECT_LIFECYCLE_SCOPES
            ):
                raise PolicyError("authenticated subject may not renew this lease")
            if _row_value(lease, "parent_id") is None and not self._has_scope(
                scopes, _SUBJECT_LIFECYCLE_SCOPES
            ):
                raise PolicyError("root lease renewal requires lease-management scope")
            fingerprint = self._fingerprint(
                "renew",
                {
                    "actor": actor,
                    "lease_id": lease_id,
                    "ttl_ns": ttl,
                    "expected_sequence": expected_sequence,
                    "cascade": cascade,
                    "policy_digest": _row_value(lease, "policy_digest"),
                    "machine_digest": _row_value(lease, "machine_digest"),
                    "config_epoch": int(_row_value(envelope, "config_epoch")),
                },
            )
            prior = self._idempotent_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"renew:{lease_id}",
                request_id=request_id,
                fingerprint=fingerprint,
            )
            if prior is not None:
                return LeaseSnapshot.from_dict(prior)
            self._require_runtime_active(connection)
            status = str(_row_value(lease, "status"))
            if status not in {LeaseStatus.ACTIVE.value, LeaseStatus.QUIESCENT.value}:
                raise PolicyError(f"lease status {status!r} cannot be renewed")
            uncertainty = self._clock_is_safe(connection, envelope, now_ns=now_ns)
            if now_ns + uncertainty >= int(_row_value(lease, "expires_at_ns")):
                raise ExpiredError("expired lease cannot be renewed")
            if self._lease_revoked(connection, lease):
                raise PolicyError("revoked branch cannot be renewed")
            _, policy = self._policy(
                connection,
                tenant_id,
                envelope_id,
                str(_row_value(lease, "policy_digest")),
            )
            maximum_ttl = policy.get("max_lease_ttl_ns")
            if not isinstance(maximum_ttl, int) or ttl > maximum_ttl:
                raise PolicyError("requested renewal TTL exceeds the registered policy maximum")
            sequence = int(_row_value(lease, "sequence"))
            if expected_sequence is not None and sequence != expected_sequence:
                raise ConflictError(f"lease sequence is {sequence}, expected {expected_sequence}")
            requested_expires_at = now_ns + ttl
            parent_id = _row_value(lease, "parent_id")
            if parent_id is not None:
                parent = self._load_lease(
                    connection,
                    tenant_id=tenant_id,
                    envelope_id=envelope_id,
                    lease_id=str(parent_id),
                )
                parent_status = str(_row_value(parent, "status"))
                if parent_status not in {
                    LeaseStatus.ACTIVE.value,
                    LeaseStatus.QUIESCENT.value,
                }:
                    raise PolicyError("lease parent is not renewable")
                if self._lease_revoked(connection, parent):
                    raise PolicyError("lease parent is revoked")
                if requested_expires_at > int(_row_value(parent, "expires_at_ns")):
                    raise PolicyError("renewal would outlive the parent lease")
            if requested_expires_at <= now_ns + uncertainty:
                raise ExpiredError("renewal is not fresh under clock uncertainty")
            descendants = connection.execute(
                """
                WITH RECURSIVE subtree(lease_id) AS (
                    SELECT lease_id FROM leases
                    WHERE tenant_id = ? AND envelope_id = ? AND parent_id = ?
                    UNION ALL
                    SELECT child.lease_id FROM leases AS child
                    JOIN subtree ON child.parent_id = subtree.lease_id
                    WHERE child.tenant_id = ? AND child.envelope_id = ?
                )
                SELECT leases.* FROM leases JOIN subtree USING (lease_id)
                WHERE leases.tenant_id = ? AND leases.envelope_id = ?
                  AND leases.status IN ('PROVISIONED', 'ACTIVE', 'QUIESCENT',
                                        'MIGRATING', 'REVOKED')
                  AND leases.expires_at_ns > ?
                ORDER BY leases.lease_id
                """,
                (
                    tenant_id,
                    envelope_id,
                    lease_id,
                    tenant_id,
                    envelope_id,
                    tenant_id,
                    envelope_id,
                    requested_expires_at,
                ),
            ).fetchall()
            if descendants and not cascade:
                raise ConflictError(
                    "renewal shortens the parent beneath a live child; use cascade=True"
                )
            changed_ids: list[str] = []
            for descendant in descendants:
                descendant_grant = self._grant_from_row(connection, descendant)
                renewed_descendant = replace(
                    descendant_grant,
                    issued_at_ns=now_ns,
                    expires_at_ns=requested_expires_at,
                    key_id=self._signer.key_id,
                    signature="",
                )
                renewed_descendant = cast(
                    LeaseGrant,
                    self._sign_record(renewed_descendant),
                )
                connection.execute(
                    """
                    UPDATE leases
                    SET issued_at_ns = ?, expires_at_ns = ?, key_id = ?, signature = ?,
                        sequence = sequence + 1, updated_at_ns = ?
                    WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                    """,
                    (
                        now_ns,
                        requested_expires_at,
                        renewed_descendant.key_id,
                        b64url_decode(renewed_descendant.signature),
                        now_ns,
                        tenant_id,
                        envelope_id,
                        renewed_descendant.lease_id,
                    ),
                )
                changed_ids.append(renewed_descendant.lease_id)
            grant = self._grant_from_row(connection, lease)
            renewed = replace(
                grant,
                issued_at_ns=now_ns,
                expires_at_ns=requested_expires_at,
                key_id=self._signer.key_id,
                signature="",
            )
            renewed = cast(LeaseGrant, self._sign_record(renewed))
            connection.execute(
                """
                UPDATE leases
                SET issued_at_ns = ?, expires_at_ns = ?, key_id = ?, signature = ?,
                    sequence = sequence + 1, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                """,
                (
                    now_ns,
                    requested_expires_at,
                    renewed.key_id,
                    b64url_decode(renewed.signature),
                    now_ns,
                    tenant_id,
                    envelope_id,
                    lease_id,
                ),
            )
            updated = self._load_lease(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                lease_id=lease_id,
            )
            snapshot = self._snapshot_from_row(connection, updated)
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="lease.renewed",
                entity_type="lease",
                entity_id=lease_id,
                actor_id=actor,
                details={
                    "expires_at_ns": requested_expires_at,
                    "cascaded_descendants": changed_ids,
                    "sequence": snapshot.sequence,
                },
                now_ns=now_ns,
            )
            self._remember_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"renew:{lease_id}",
                request_id=request_id,
                fingerprint=fingerprint,
                response=snapshot.to_dict(),
                now_ns=now_ns,
            )
            return snapshot

    def _lifecycle(
        self,
        operation: str,
        *,
        request_id: str,
        identity: IdentityContext,
        lease_id: str,
        expected_sequence: int | None,
    ) -> LeaseSnapshot:
        require_identifier(request_id, field="request_id")
        require_identifier(lease_id, field="lease_id")
        if expected_sequence is not None and (
            isinstance(expected_sequence, bool)
            or not isinstance(expected_sequence, int)
            or expected_sequence < 0
            or expected_sequence > MAX_RESOURCE
        ):
            raise ValidationError("expected_sequence must be a non-negative integer")
        identity_tenant, actor, scopes = self._identity_fields(identity)
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match lease tenant")
            lease = self._load_lease(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                lease_id=lease_id,
            )
            if actor != _row_value(lease, "subject_id") and not self._has_scope(
                scopes, _SUBJECT_LIFECYCLE_SCOPES
            ):
                raise PolicyError("authenticated subject may not manage this lease")
            fingerprint = self._fingerprint(
                operation,
                {
                    "actor": actor,
                    "lease_id": lease_id,
                    "expected_sequence": expected_sequence,
                    "policy_digest": _row_value(lease, "policy_digest"),
                    "machine_digest": _row_value(lease, "machine_digest"),
                    "config_epoch": int(_row_value(envelope, "config_epoch")),
                },
            )
            scope = f"{operation}:{lease_id}"
            prior = self._idempotent_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=scope,
                request_id=request_id,
                fingerprint=fingerprint,
            )
            if prior is not None:
                return LeaseSnapshot.from_dict(prior)
            if operation == "resume":
                self._require_runtime_active(connection)
            sequence = int(_row_value(lease, "sequence"))
            if expected_sequence is not None and sequence != expected_sequence:
                raise ConflictError(f"lease sequence is {sequence}, expected {expected_sequence}")
            status = str(_row_value(lease, "status"))
            residual = _unpack_blob(_row_value(lease, "residual"))
            resulting_status: str
            returned = zero(len(residual))
            mutate = True
            if operation == "quiesce":
                if status == LeaseStatus.QUIESCENT.value:
                    mutate = False
                    resulting_status = status
                else:
                    self._require_actionable(connection, lease, envelope, now_ns=now_ns)
                    resulting_status = LeaseStatus.QUIESCENT.value
            elif operation == "resume":
                if status == LeaseStatus.ACTIVE.value:
                    mutate = False
                    resulting_status = status
                elif status == LeaseStatus.QUIESCENT.value:
                    self._clock_is_safe(connection, envelope, now_ns=now_ns)
                    if now_ns + self._clock.uncertainty_ns() >= int(
                        _row_value(lease, "expires_at_ns")
                    ):
                        raise ExpiredError("lease cannot be safely resumed")
                    if self._lease_revoked(connection, lease):
                        raise PolicyError("revoked branch cannot be resumed")
                    resulting_status = LeaseStatus.ACTIVE.value
                else:
                    raise PolicyError(f"lease status {status!r} cannot be resumed")
            elif operation == "close":
                if status in {LeaseStatus.CLOSED.value, LeaseStatus.EXPIRED.value}:
                    mutate = False
                    resulting_status = status
                else:
                    resulting_status = LeaseStatus.CLOSED.value
                    returned = residual
            else:
                raise AssertionError(f"unknown lifecycle operation {operation!r}")
            if mutate:
                new_residual = zero(len(residual)) if operation == "close" else residual
                connection.execute(
                    """
                    UPDATE leases
                    SET residual = ?, status = ?, sequence = sequence + 1, updated_at_ns = ?
                    WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                    """,
                    (
                        pack(new_residual),
                        resulting_status,
                        now_ns,
                        tenant_id,
                        envelope_id,
                        lease_id,
                    ),
                )
                if operation == "close" and any(returned):
                    state_row = connection.execute(
                        """
                        SELECT free_pool FROM warden_state
                        WHERE tenant_id = ? AND envelope_id = ?
                        """,
                        (tenant_id, envelope_id),
                    ).fetchone()
                    if state_row is None:
                        raise StorageError("warden state is missing")
                    free_pool = _unpack_blob(_row_value(state_row, "free_pool"))
                    connection.execute(
                        """
                        UPDATE warden_state
                        SET free_pool = ?, revision = revision + 1, updated_at_ns = ?
                        WHERE tenant_id = ? AND envelope_id = ?
                        """,
                        (pack(add(free_pool, returned)), now_ns, tenant_id, envelope_id),
                    )
                self._append_audit(
                    connection,
                    tenant_id=tenant_id,
                    envelope_id=envelope_id,
                    event_type=f"lease.{operation}d" if operation != "close" else "lease.closed",
                    entity_type="lease",
                    entity_id=lease_id,
                    actor_id=actor,
                    details={"returned": list(returned)},
                    now_ns=now_ns,
                )
            updated = self._load_lease(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                lease_id=lease_id,
            )
            snapshot = self._snapshot_from_row(connection, updated)
            self._remember_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=scope,
                request_id=request_id,
                fingerprint=fingerprint,
                response=snapshot.to_dict(),
                now_ns=now_ns,
            )
            return snapshot

    def quiesce(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        lease_id: str,
        expected_sequence: int | None = None,
    ) -> LeaseSnapshot:
        return self._lifecycle(
            "quiesce",
            request_id=request_id,
            identity=identity,
            lease_id=lease_id,
            expected_sequence=expected_sequence,
        )

    def resume(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        lease_id: str,
        expected_sequence: int | None = None,
    ) -> LeaseSnapshot:
        return self._lifecycle(
            "resume",
            request_id=request_id,
            identity=identity,
            lease_id=lease_id,
            expected_sequence=expected_sequence,
        )

    def close(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        lease_id: str,
        expected_sequence: int | None = None,
    ) -> LeaseSnapshot:
        return self._lifecycle(
            "close",
            request_id=request_id,
            identity=identity,
            lease_id=lease_id,
            expected_sequence=expected_sequence,
        )

    def revoke_branch(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        lease_id: str,
        reason: str,
        expected_epoch: int | None = None,
    ) -> BranchRevocation:
        """Increment and sign a branch-scoped revocation epoch."""

        require_identifier(request_id, field="request_id")
        require_identifier(lease_id, field="lease_id")
        if not isinstance(reason, str) or not reason or len(reason) > 1000:
            raise ValidationError("revocation reason must contain 1..1000 characters")
        if expected_epoch is not None and (
            isinstance(expected_epoch, bool)
            or not isinstance(expected_epoch, int)
            or expected_epoch < 0
            or expected_epoch > MAX_RESOURCE
        ):
            raise ValidationError("expected_epoch must be a non-negative integer")
        identity_tenant, actor, scopes = self._identity_fields(identity)
        if not self._has_scope(scopes, _ADMIN_SCOPES | frozenset({"lets.branch.revoke"})):
            raise PolicyError("branch revocation scope is required")
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match branch tenant")
            branch = self._load_lease(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                lease_id=lease_id,
            )
            lineage_id = str(_row_value(branch, "lineage_id"))
            current = connection.execute(
                """
                SELECT epoch FROM revocations
                WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ?
                  AND branch_lease_id = ?
                """,
                (tenant_id, envelope_id, lineage_id, lease_id),
            ).fetchone()
            current_epoch = 0 if current is None else int(_row_value(current, "epoch"))
            if expected_epoch is not None and expected_epoch != current_epoch:
                raise ConflictError(
                    f"branch revocation epoch is {current_epoch}, expected {expected_epoch}"
                )
            fingerprint = self._fingerprint(
                "revoke_branch",
                {
                    "actor": actor,
                    "lease_id": lease_id,
                    "lineage_id": lineage_id,
                    "reason": reason,
                    "expected_epoch": expected_epoch,
                    "config_epoch": int(_row_value(envelope, "config_epoch")),
                },
            )
            prior = self._idempotent_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"revoke:{lease_id}",
                request_id=request_id,
                fingerprint=fingerprint,
            )
            if prior is not None:
                return BranchRevocation.from_dict(prior)
            unsigned = BranchRevocation(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                config_epoch=int(_row_value(envelope, "config_epoch")),
                branch_lease_id=lease_id,
                lineage_id=lineage_id,
                epoch=current_epoch + 1,
                issuer_warden=self.warden_id,
                issued_at_ns=now_ns,
                reason=reason,
                key_id=self._signer.key_id,
            )
            revocation = cast(BranchRevocation, self._sign_record(unsigned))
            payload = canonical_json(revocation.to_dict())
            delivery_id = canonical_digest(revocation.to_dict())
            if current is None:
                connection.execute(
                    """
                    INSERT INTO revocations(
                        tenant_id, envelope_id, lineage_id, branch_lease_id, epoch,
                        config_epoch, observed_at_ns, source_warden, reason, key_id,
                        issued_at_ns, signature, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant_id,
                        envelope_id,
                        lineage_id,
                        lease_id,
                        revocation.epoch,
                        revocation.config_epoch,
                        now_ns,
                        self.warden_id,
                        reason,
                        revocation.key_id,
                        revocation.issued_at_ns,
                        b64url_decode(revocation.signature),
                        payload,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE revocations
                    SET epoch = ?, observed_at_ns = ?, source_warden = ?, reason = ?,
                        key_id = ?, issued_at_ns = ?, signature = ?, payload = ?
                    WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ?
                      AND branch_lease_id = ?
                    """,
                    (
                        revocation.epoch,
                        now_ns,
                        self.warden_id,
                        reason,
                        revocation.key_id,
                        revocation.issued_at_ns,
                        b64url_decode(revocation.signature),
                        payload,
                        tenant_id,
                        envelope_id,
                        lineage_id,
                        lease_id,
                    ),
                )
            if self._allowed_peer_wardens is not None:
                for target_warden in sorted(self._allowed_peer_wardens):
                    self._enqueue_peer_delivery(
                        connection,
                        record_kind="revocation",
                        record_id=delivery_id,
                        target_warden=target_warden,
                        ordering_key=canonical_digest(
                            {"lineage_id": lineage_id, "branch_lease_id": lease_id}
                        ),
                        stream_position=revocation.epoch,
                        payload=payload,
                        now_ns=now_ns,
                        supersede_older=True,
                    )
            connection.execute(
                """
                WITH RECURSIVE subtree(lease_id) AS (
                    SELECT ?
                    UNION ALL
                    SELECT child.lease_id FROM leases AS child
                    JOIN subtree ON child.parent_id = subtree.lease_id
                    WHERE child.tenant_id = ? AND child.envelope_id = ?
                )
                UPDATE leases
                SET status = 'REVOKED', sequence = sequence + 1, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ?
                  AND lease_id IN (SELECT lease_id FROM subtree)
                  AND status IN ('PROVISIONED', 'ACTIVE', 'QUIESCENT', 'MIGRATING')
                """,
                (
                    lease_id,
                    tenant_id,
                    envelope_id,
                    now_ns,
                    tenant_id,
                    envelope_id,
                ),
            )
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="branch.revoked",
                entity_type="lease",
                entity_id=lease_id,
                actor_id=actor,
                details={
                    "lineage_id": lineage_id,
                    "epoch": revocation.epoch,
                    "reason": reason,
                },
                now_ns=now_ns,
            )
            self._remember_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"revoke:{lease_id}",
                request_id=request_id,
                fingerprint=fingerprint,
                response=revocation.to_dict(),
                now_ns=now_ns,
            )
            return revocation

    def ingest_revocation(
        self,
        *,
        identity: IdentityContext,
        revocation: BranchRevocation | Mapping[str, Any],
    ) -> BranchRevocation:
        """Verify and monotonically apply a peer-issued branch revocation."""

        parsed = (
            revocation
            if isinstance(revocation, BranchRevocation)
            else BranchRevocation.from_dict(dict(revocation))
        )
        identity_tenant, actor, scopes = self._identity_fields(identity)
        if actor != parsed.issuer_warden and not self._has_scope(
            scopes,
            _ADMIN_SCOPES
            | frozenset({"lets.branch.revoke.ingest", "lets.revocation.propagate", "lets.peer"}),
        ):
            raise PolicyError("peer identity does not match revocation issuer")
        self._verify_record(parsed, warden_id=parsed.issuer_warden)
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._envelope(connection, parsed.tenant_id, parsed.envelope_id)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            if identity_tenant != parsed.tenant_id:
                raise PolicyError("identity tenant does not match revocation tenant")
            if parsed.config_epoch != int(_row_value(envelope, "config_epoch")):
                raise ConflictError("revocation configuration epoch does not match target")
            branch = connection.execute(
                """
                SELECT lineage_id, warden_id FROM leases
                WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                """,
                (parsed.tenant_id, parsed.envelope_id, parsed.branch_lease_id),
            ).fetchone()
            if branch is not None and _row_value(branch, "lineage_id") != parsed.lineage_id:
                raise ConflictError("revocation lineage does not match local branch")
            if branch is not None and _row_value(branch, "warden_id") != parsed.issuer_warden:
                raise PolicyError("revocation issuer does not own the addressed local branch")
            existing = connection.execute(
                """
                SELECT epoch, payload FROM revocations
                WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ?
                  AND branch_lease_id = ?
                """,
                (
                    parsed.tenant_id,
                    parsed.envelope_id,
                    parsed.lineage_id,
                    parsed.branch_lease_id,
                ),
            ).fetchone()
            payload = canonical_json(parsed.to_dict())
            if existing is not None:
                existing_epoch = int(_row_value(existing, "epoch"))
                if parsed.epoch < existing_epoch:
                    raise ReplayError("revocation epoch is older than the durable branch epoch")
                if parsed.epoch == existing_epoch:
                    if bytes(_row_value(existing, "payload")) != payload:
                        raise ConflictError("revocation epoch is bound to different signed content")
                    return parsed
                connection.execute(
                    """
                    UPDATE revocations
                    SET epoch = ?, config_epoch = ?, observed_at_ns = ?, source_warden = ?,
                        reason = ?, key_id = ?, issued_at_ns = ?, signature = ?, payload = ?
                    WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ?
                      AND branch_lease_id = ?
                    """,
                    (
                        parsed.epoch,
                        parsed.config_epoch,
                        now_ns,
                        parsed.issuer_warden,
                        parsed.reason,
                        parsed.key_id,
                        parsed.issued_at_ns,
                        b64url_decode(parsed.signature),
                        payload,
                        parsed.tenant_id,
                        parsed.envelope_id,
                        parsed.lineage_id,
                        parsed.branch_lease_id,
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO revocations(
                        tenant_id, envelope_id, lineage_id, branch_lease_id, epoch,
                        config_epoch, observed_at_ns, source_warden, reason, key_id,
                        issued_at_ns, signature, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        parsed.tenant_id,
                        parsed.envelope_id,
                        parsed.lineage_id,
                        parsed.branch_lease_id,
                        parsed.epoch,
                        parsed.config_epoch,
                        now_ns,
                        parsed.issuer_warden,
                        parsed.reason,
                        parsed.key_id,
                        parsed.issued_at_ns,
                        b64url_decode(parsed.signature),
                        payload,
                    ),
                )
            leases = connection.execute(
                """
                SELECT lease_id, ancestor_path_json FROM leases
                WHERE tenant_id = ? AND envelope_id = ? AND lineage_id = ?
                  AND status IN ('PROVISIONED', 'ACTIVE', 'QUIESCENT', 'MIGRATING')
                """,
                (parsed.tenant_id, parsed.envelope_id, parsed.lineage_id),
            ).fetchall()
            affected: list[str] = []
            for lease in leases:
                lease_id = str(_row_value(lease, "lease_id"))
                ancestors = _json_array(_row_value(lease, "ancestor_path_json"))
                if lease_id != parsed.branch_lease_id and parsed.branch_lease_id not in ancestors:
                    continue
                connection.execute(
                    """
                    UPDATE leases
                    SET status = 'REVOKED', sequence = sequence + 1, updated_at_ns = ?
                    WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                    """,
                    (now_ns, parsed.tenant_id, parsed.envelope_id, lease_id),
                )
                affected.append(lease_id)
            self._append_audit(
                connection,
                tenant_id=parsed.tenant_id,
                envelope_id=parsed.envelope_id,
                event_type="branch.revocation-ingested",
                entity_type="lease",
                entity_id=parsed.branch_lease_id,
                actor_id=actor,
                details={
                    "lineage_id": parsed.lineage_id,
                    "epoch": parsed.epoch,
                    "issuer_warden": parsed.issuer_warden,
                    "affected": affected,
                },
                now_ns=now_ns,
            )
            return parsed

    def reclaim_expired(
        self,
        *,
        identity: IdentityContext,
        tenant_id: str | None = None,
        envelope_id: str | None = None,
    ) -> ResourceVector:
        """Reclaim residual only beyond the uncertainty and receipt-freshness barrier."""

        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            actual_tenant = str(_row_value(envelope, "tenant_id"))
            actual_envelope = str(_row_value(envelope, "envelope_id"))
            if tenant_id is not None and tenant_id != actual_tenant:
                raise NotFoundError("requested tenant is not configured by this warden")
            if envelope_id is not None and envelope_id != actual_envelope:
                raise NotFoundError("requested envelope is not configured by this warden")
            actor = self._require_admin(identity, actual_tenant)
            uncertainty = self._clock_is_safe(connection, envelope, now_ns=now_ns)
            receipt_ttl = int(_row_value(envelope, "receipt_ttl_ns"))
            candidates = connection.execute(
                """
                SELECT leases.*,
                       COALESCE(MAX(receipts.expires_at_ns), leases.expires_at_ns)
                           AS last_receipt_expiry_ns
                FROM leases
                LEFT JOIN receipts
                  ON receipts.tenant_id = leases.tenant_id
                 AND receipts.envelope_id = leases.envelope_id
                 AND receipts.lease_id = leases.lease_id
                WHERE leases.tenant_id = ? AND leases.envelope_id = ?
                  AND leases.status IN ('PROVISIONED', 'ACTIVE', 'QUIESCENT',
                                        'MIGRATING', 'REVOKED')
                GROUP BY leases.tenant_id, leases.envelope_id, leases.lease_id
                ORDER BY leases.lease_id
                """,
                (actual_tenant, actual_envelope),
            ).fetchall()
            dimensions = int(_row_value(envelope, "dimension_count"))
            reclaimed = zero(dimensions)
            reclaimed_ids: list[str] = []
            lower_bound_now = now_ns - uncertainty
            for lease in candidates:
                lease_expiry = int(_row_value(lease, "expires_at_ns"))
                last_receipt_expiry = int(_row_value(lease, "last_receipt_expiry_ns"))
                barrier = max(lease_expiry + receipt_ttl, last_receipt_expiry)
                if lower_bound_now < barrier:
                    continue
                residual = _unpack_blob(_row_value(lease, "residual"))
                reclaimed = add(reclaimed, residual)
                lease_identifier = str(_row_value(lease, "lease_id"))
                connection.execute(
                    """
                    UPDATE leases
                    SET residual = ?, status = 'EXPIRED', sequence = sequence + 1,
                        updated_at_ns = ?
                    WHERE tenant_id = ? AND envelope_id = ? AND lease_id = ?
                    """,
                    (
                        pack(zero(dimensions)),
                        now_ns,
                        actual_tenant,
                        actual_envelope,
                        lease_identifier,
                    ),
                )
                reclaimed_ids.append(lease_identifier)
            if reclaimed_ids:
                state_row = connection.execute(
                    """
                    SELECT free_pool FROM warden_state
                    WHERE tenant_id = ? AND envelope_id = ?
                    """,
                    (actual_tenant, actual_envelope),
                ).fetchone()
                if state_row is None:
                    raise StorageError("warden state is missing")
                free_pool = _unpack_blob(_row_value(state_row, "free_pool"))
                connection.execute(
                    """
                    UPDATE warden_state
                    SET free_pool = ?, revision = revision + 1, updated_at_ns = ?
                    WHERE tenant_id = ? AND envelope_id = ?
                    """,
                    (
                        pack(add(free_pool, reclaimed)),
                        now_ns,
                        actual_tenant,
                        actual_envelope,
                    ),
                )
                self._append_audit(
                    connection,
                    tenant_id=actual_tenant,
                    envelope_id=actual_envelope,
                    event_type="leases.reclaimed",
                    entity_type="envelope",
                    entity_id=actual_envelope,
                    actor_id=actor,
                    details={
                        "lease_ids": reclaimed_ids,
                        "reclaimed": list(reclaimed),
                        "lower_bound_now_ns": lower_bound_now,
                    },
                    now_ns=now_ns,
                )
            return reclaimed

    def snapshot(
        self,
        *,
        identity: IdentityContext,
        lease_id: str,
    ) -> LeaseSnapshot:
        """Return a non-authoritative client snapshot after tenant/subject binding."""

        require_identifier(lease_id, field="lease_id")
        identity_tenant, actor, scopes = self._identity_fields(identity)
        with self._store.read() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match lease tenant")
            lease = self._load_lease(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                lease_id=lease_id,
            )
            if actor != _row_value(lease, "subject_id") and not self._has_scope(
                scopes, _SUBJECT_LIFECYCLE_SCOPES
            ):
                raise PolicyError("authenticated subject may not inspect this lease")
            return self._snapshot_from_row(connection, lease)

    def _invariant_snapshot(
        self,
        connection: sqlite3.Connection,
        envelope: sqlite3.Row,
        now_ns: int,
    ) -> InvariantSnapshot:
        tenant_id = str(_row_value(envelope, "tenant_id"))
        envelope_id = str(_row_value(envelope, "envelope_id"))
        state = connection.execute(
            """
            SELECT * FROM warden_state
            WHERE tenant_id = ? AND envelope_id = ?
            """,
            (tenant_id, envelope_id),
        ).fetchone()
        if state is None:
            raise StorageError("warden state is missing")
        # Lease triggers maintain this aggregate in the same transaction as every
        # residual mutation. Startup and explicit diagnostics reconcile it against
        # lease rows; frequent snapshots can therefore remain O(dimensions).
        residual = _unpack_blob(_row_value(state, "lease_residual"))
        conservation = ConservationSnapshot(
            initial_share=_unpack_blob(_row_value(envelope, "initial_local_share")),
            transferred_in=_unpack_blob(_row_value(state, "transferred_in")),
            transferred_out=_unpack_blob(_row_value(state, "transferred_out")),
            free_pool=_unpack_blob(_row_value(state, "free_pool")),
            residual=residual,
            consumed=_unpack_blob(_row_value(state, "consumed")),
        )
        return InvariantSnapshot(
            tenant_id=tenant_id,
            envelope_id=envelope_id,
            config_epoch=int(_row_value(envelope, "config_epoch")),
            initial_share=conservation.initial_share,
            transferred_in=conservation.transferred_in,
            transferred_out=conservation.transferred_out,
            free_pool=conservation.free_pool,
            lease_residual=conservation.residual,
            consumed=conservation.consumed,
            checked_at_ns=now_ns,
            healthy=conservation.healthy,
        )

    def invariant_snapshot(
        self,
        *,
        identity: IdentityContext,
    ) -> InvariantSnapshot:
        identity_tenant, _, _ = self._identity_fields(identity)
        now_ns = self._clock.now_ns()
        with self._store.read() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            if identity_tenant != _row_value(envelope, "tenant_id"):
                raise PolicyError("identity tenant does not match envelope tenant")
            return self._invariant_snapshot(connection, envelope, now_ns)

    def prepare_transfer(
        self,
        *,
        request_id: str,
        identity: IdentityContext,
        tenant_id: str,
        envelope_id: str,
        target_warden: str,
        amount: Sequence[int],
        policy_digest: str | None = None,
    ) -> TransferVoucher:
        """Move free rights into a signed, per-peer sequenced transfer voucher."""

        require_identifier(request_id, field="request_id")
        require_identifier(envelope_id, field="envelope_id")
        require_warden_id(target_warden, field="target_warden")
        if target_warden == self.warden_id:
            raise ValidationError("transfer target must differ from the source warden")
        if (
            self._allowed_peer_wardens is not None
            and target_warden not in self._allowed_peer_wardens
        ):
            raise PolicyError("transfer target is not authorized by this warden configuration")
        actor, scopes = self._bind_tenant(identity, tenant_id)
        if actor != self.warden_id and not self._has_scope(
            scopes, _ADMIN_SCOPES | frozenset({"lets.transfer"})
        ):
            raise PolicyError("transfer preparation scope is required")
        if policy_digest is not None:
            require_digest(policy_digest, field="policy_digest")
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            self._verify_database_identity(connection)
            envelope = self._envelope(connection, tenant_id, envelope_id)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            checked_amount = vector(
                amount,
                dimensions=int(_row_value(envelope, "dimension_count")),
            )
            if not any(checked_amount):
                raise ValidationError("transfer amount must contain a non-zero dimension")
            if policy_digest is None:
                policy_row = connection.execute(
                    """
                    SELECT * FROM policies
                    WHERE tenant_id = ? AND envelope_id = ? AND active = 1
                    """,
                    (tenant_id, envelope_id),
                ).fetchone()
                if policy_row is None:
                    raise PolicyError("no active policy is registered")
                selected_policy_digest = str(_row_value(policy_row, "policy_digest"))
                policy = _json_object(_row_value(policy_row, "payload"))
            else:
                policy_row, policy = self._policy(
                    connection,
                    tenant_id,
                    envelope_id,
                    policy_digest,
                )
                selected_policy_digest = policy_digest
            fingerprint = self._fingerprint(
                "prepare_transfer",
                {
                    "actor": actor,
                    "target_warden": target_warden,
                    "amount": list(checked_amount),
                    "policy_digest": selected_policy_digest,
                    "config_epoch": int(_row_value(envelope, "config_epoch")),
                },
            )
            prior = self._idempotent_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"prepare_transfer:{target_warden}",
                request_id=request_id,
                fingerprint=fingerprint,
            )
            if prior is not None:
                return TransferVoucher.from_dict(prior)
            self._require_runtime_active(connection)
            if self._trust_registry is None:
                raise SignatureError(
                    "transfer preparation requires current target verification material"
                )
            self._trust_registry.require_current_warden(target_warden)
            state = connection.execute(
                """
                SELECT free_pool, transferred_out FROM warden_state
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (tenant_id, envelope_id),
            ).fetchone()
            if state is None:
                raise StorageError("warden state is missing")
            free_pool = _unpack_blob(_row_value(state, "free_pool"))
            transferred_out = _unpack_blob(_row_value(state, "transferred_out"))
            if not less_than_or_equal(checked_amount, free_pool):
                raise PolicyError("local free pool does not cover transfer amount")
            connection.execute(
                """
                INSERT INTO outgoing_transfer_streams(
                    tenant_id, envelope_id, target_warden, config_epoch,
                    next_sequence, acked_through, updated_at_ns
                ) VALUES (?, ?, ?, ?, 1, 0, ?)
                ON CONFLICT(tenant_id, envelope_id, target_warden) DO NOTHING
                """,
                (
                    tenant_id,
                    envelope_id,
                    target_warden,
                    int(_row_value(envelope, "config_epoch")),
                    now_ns,
                ),
            )
            stream = connection.execute(
                """
                SELECT * FROM outgoing_transfer_streams
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                """,
                (tenant_id, envelope_id, target_warden),
            ).fetchone()
            if stream is None:
                raise StorageError("outgoing transfer stream is missing")
            if int(_row_value(stream, "config_epoch")) != int(_row_value(envelope, "config_epoch")):
                raise ConflictError("outgoing stream belongs to another configuration epoch")
            sequence = int(_row_value(stream, "next_sequence"))
            policy_id = policy.get("policy_id", policy.get("policy_version"))
            if not isinstance(policy_id, str):
                raise StorageError("stored policy has no policy_id")
            unsigned = TransferVoucher(
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                config_epoch=int(_row_value(envelope, "config_epoch")),
                transfer_id=new_id("transfer"),
                source_warden=self.warden_id,
                target_warden=target_warden,
                policy_id=policy_id,
                policy_version=str(_row_value(policy_row, "policy_version")),
                policy_digest=selected_policy_digest,
                sequence=sequence,
                amount=checked_amount,
                issued_at_ns=now_ns,
                key_id=self._signer.key_id,
            )
            voucher = cast(TransferVoucher, self._sign_record(unsigned))
            voucher_payload = canonical_json(voucher.to_dict())
            voucher_digest = canonical_digest(voucher.to_dict())
            connection.execute(
                """
                INSERT INTO outgoing_transfers(
                    tenant_id, envelope_id, transfer_id, source_warden, target_warden,
                    sequence, config_epoch, amount, policy_version, policy_digest,
                    digest, key_id, signature, voucher_payload, status, prepared_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?)
                """,
                (
                    tenant_id,
                    envelope_id,
                    voucher.transfer_id,
                    self.warden_id,
                    target_warden,
                    sequence,
                    voucher.config_epoch,
                    pack(checked_amount),
                    voucher.policy_version,
                    voucher.policy_digest,
                    voucher_digest,
                    voucher.key_id,
                    b64url_decode(voucher.signature),
                    voucher_payload,
                    now_ns,
                ),
            )
            if self._allowed_peer_wardens is not None:
                self._enqueue_peer_delivery(
                    connection,
                    record_kind="transfer",
                    record_id=voucher.transfer_id,
                    target_warden=target_warden,
                    ordering_key=target_warden,
                    stream_position=sequence,
                    payload=voucher_payload,
                    now_ns=now_ns,
                )
            connection.execute(
                """
                UPDATE outgoing_transfer_streams
                SET next_sequence = next_sequence + 1, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                """,
                (now_ns, tenant_id, envelope_id, target_warden),
            )
            connection.execute(
                """
                UPDATE warden_state
                SET free_pool = ?, transferred_out = ?, revision = revision + 1,
                    updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (
                    pack(subtract(free_pool, checked_amount)),
                    pack(add(transferred_out, checked_amount)),
                    now_ns,
                    tenant_id,
                    envelope_id,
                ),
            )
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="transfer.prepared",
                entity_type="transfer",
                entity_id=voucher.transfer_id,
                actor_id=actor,
                details={
                    "target_warden": target_warden,
                    "sequence": sequence,
                    "amount": list(checked_amount),
                    "voucher_digest": voucher_digest,
                },
                now_ns=now_ns,
            )
            self._remember_response(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                scope=f"prepare_transfer:{target_warden}",
                request_id=request_id,
                fingerprint=fingerprint,
                response=voucher.to_dict(),
                now_ns=now_ns,
                status_code=201,
            )
            return voucher

    def accept_transfer(
        self,
        *,
        identity: IdentityContext,
        voucher: TransferVoucher | Mapping[str, Any],
    ) -> TransferAck:
        """Verify and exactly-once credit a peer voucher within a bounded gap window."""

        parsed = (
            voucher
            if isinstance(voucher, TransferVoucher)
            else TransferVoucher.from_dict(dict(voucher))
        )
        identity_tenant, actor, scopes = self._identity_fields(identity)
        if actor != self.warden_id and not self._has_scope(
            scopes, _ADMIN_SCOPES | frozenset({"lets.peer", "lets.transfer"})
        ):
            raise PolicyError("transfer acceptance scope is required")
        self._verify_record(parsed, warden_id=parsed.source_warden)
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._envelope(connection, parsed.tenant_id, parsed.envelope_id)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            if identity_tenant != parsed.tenant_id:
                raise PolicyError("identity tenant does not match transfer tenant")
            if parsed.target_warden != self.warden_id:
                raise PolicyError("voucher target does not match this warden")
            if parsed.config_epoch != int(_row_value(envelope, "config_epoch")):
                raise ConflictError("voucher configuration epoch does not match target")
            policy_row, policy = self._policy(
                connection,
                parsed.tenant_id,
                parsed.envelope_id,
                parsed.policy_digest,
            )
            policy_id = policy.get("policy_id", policy.get("policy_version"))
            if (
                parsed.policy_version != _row_value(policy_row, "policy_version")
                or parsed.policy_id != policy_id
            ):
                raise PolicyError("voucher policy identity does not match registered policy")
            amount = vector(
                parsed.amount,
                dimensions=int(_row_value(envelope, "dimension_count")),
            )
            digest = canonical_digest(parsed.to_dict())
            existing = connection.execute(
                """
                SELECT transfer_digest, ack_payload FROM inbound_transfer_acks
                WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                  AND sequence = ?
                """,
                (
                    parsed.tenant_id,
                    parsed.envelope_id,
                    parsed.source_warden,
                    parsed.sequence,
                ),
            ).fetchone()
            if existing is not None:
                if _row_value(existing, "transfer_digest") != digest:
                    raise ConflictError("transfer sequence is bound to another voucher digest")
                return TransferAck.from_dict(_json_object(_row_value(existing, "ack_payload")))
            self._require_runtime_active(connection)
            duplicate_id = connection.execute(
                """
                SELECT sequence, transfer_digest FROM inbound_transfer_acks
                WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                  AND transfer_id = ?
                """,
                (
                    parsed.tenant_id,
                    parsed.envelope_id,
                    parsed.source_warden,
                    parsed.transfer_id,
                ),
            ).fetchone()
            if duplicate_id is not None:
                raise ConflictError(
                    "transfer_id is already bound to sequence "
                    f"{int(_row_value(duplicate_id, 'sequence'))}"
                )
            connection.execute(
                """
                INSERT INTO inbound_transfer_streams(
                    tenant_id, envelope_id, source_warden, config_epoch,
                    contiguous_through, highest_seen, updated_at_ns
                ) VALUES (?, ?, ?, ?, 0, 0, ?)
                ON CONFLICT(tenant_id, envelope_id, source_warden) DO NOTHING
                """,
                (
                    parsed.tenant_id,
                    parsed.envelope_id,
                    parsed.source_warden,
                    parsed.config_epoch,
                    now_ns,
                ),
            )
            stream = connection.execute(
                """
                SELECT * FROM inbound_transfer_streams
                WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                """,
                (parsed.tenant_id, parsed.envelope_id, parsed.source_warden),
            ).fetchone()
            if stream is None:
                raise StorageError("inbound transfer stream is missing")
            if int(_row_value(stream, "config_epoch")) != parsed.config_epoch:
                raise ConflictError("inbound stream belongs to another configuration epoch")
            contiguous = int(_row_value(stream, "contiguous_through"))
            if parsed.sequence <= contiguous:
                raise ReplayError("compacted transfer prefix has no matching acknowledgement")
            window = int(_row_value(envelope, "transfer_gap_window"))
            if parsed.sequence > contiguous + window:
                raise ReplayError(
                    f"transfer sequence {parsed.sequence} exceeds admission window ending "
                    f"at {contiguous + window}"
                )
            if parsed.sequence > contiguous + 1:
                connection.execute(
                    """
                    INSERT INTO inbound_transfer_gaps(
                        tenant_id, envelope_id, source_warden, sequence, observed_at_ns
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        parsed.tenant_id,
                        parsed.envelope_id,
                        parsed.source_warden,
                        parsed.sequence,
                        now_ns,
                    ),
                )
                new_contiguous = contiguous
            else:
                new_contiguous = parsed.sequence
                while True:
                    next_gap = connection.execute(
                        """
                        SELECT 1 FROM inbound_transfer_gaps
                        WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                          AND sequence = ?
                        """,
                        (
                            parsed.tenant_id,
                            parsed.envelope_id,
                            parsed.source_warden,
                            new_contiguous + 1,
                        ),
                    ).fetchone()
                    if next_gap is None:
                        break
                    new_contiguous += 1
                    connection.execute(
                        """
                        DELETE FROM inbound_transfer_gaps
                        WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                          AND sequence = ?
                        """,
                        (
                            parsed.tenant_id,
                            parsed.envelope_id,
                            parsed.source_warden,
                            new_contiguous,
                        ),
                    )
            highest_seen = max(int(_row_value(stream, "highest_seen")), parsed.sequence)
            unsigned_ack = TransferAck(
                tenant_id=parsed.tenant_id,
                envelope_id=parsed.envelope_id,
                config_epoch=parsed.config_epoch,
                transfer_id=parsed.transfer_id,
                source_warden=parsed.source_warden,
                target_warden=self.warden_id,
                sequence=parsed.sequence,
                voucher_digest=digest,
                accepted_at_ns=now_ns,
                contiguous_watermark=new_contiguous,
                key_id=self._signer.key_id,
            )
            ack = cast(TransferAck, self._sign_record(unsigned_ack))
            ack_payload = canonical_json(ack.to_dict())
            state = connection.execute(
                """
                SELECT free_pool, transferred_in FROM warden_state
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (parsed.tenant_id, parsed.envelope_id),
            ).fetchone()
            if state is None:
                raise StorageError("warden state is missing")
            free_pool = _unpack_blob(_row_value(state, "free_pool"))
            transferred_in = _unpack_blob(_row_value(state, "transferred_in"))
            connection.execute(
                """
                UPDATE warden_state
                SET free_pool = ?, transferred_in = ?, revision = revision + 1,
                    updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ?
                """,
                (
                    pack(add(free_pool, amount)),
                    pack(add(transferred_in, amount)),
                    now_ns,
                    parsed.tenant_id,
                    parsed.envelope_id,
                ),
            )
            connection.execute(
                """
                UPDATE inbound_transfer_streams
                SET contiguous_through = ?, highest_seen = ?, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                """,
                (
                    new_contiguous,
                    highest_seen,
                    now_ns,
                    parsed.tenant_id,
                    parsed.envelope_id,
                    parsed.source_warden,
                ),
            )
            connection.execute(
                """
                INSERT INTO inbound_transfer_acks(
                    tenant_id, envelope_id, transfer_id, source_warden, target_warden,
                    sequence, config_epoch, transfer_digest, contiguous_watermark,
                    key_id, ack_payload, signature, accepted_at_ns, expires_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    parsed.tenant_id,
                    parsed.envelope_id,
                    parsed.transfer_id,
                    parsed.source_warden,
                    self.warden_id,
                    parsed.sequence,
                    parsed.config_epoch,
                    digest,
                    new_contiguous,
                    ack.key_id,
                    ack_payload,
                    b64url_decode(ack.signature),
                    now_ns,
                ),
            )
            self._append_audit(
                connection,
                tenant_id=parsed.tenant_id,
                envelope_id=parsed.envelope_id,
                event_type="transfer.accepted",
                entity_type="transfer",
                entity_id=parsed.transfer_id,
                actor_id=actor,
                details={
                    "source_warden": parsed.source_warden,
                    "sequence": parsed.sequence,
                    "amount": list(amount),
                    "voucher_digest": digest,
                    "contiguous_watermark": new_contiguous,
                },
                now_ns=now_ns,
            )
            return ack

    def finalize_transfer(
        self,
        *,
        identity: IdentityContext,
        acknowledgement: TransferAck | Mapping[str, Any],
    ) -> TransferAck:
        """Durably record the target's signed acceptance and advance source watermark."""

        ack = (
            acknowledgement
            if isinstance(acknowledgement, TransferAck)
            else TransferAck.from_dict(dict(acknowledgement))
        )
        identity_tenant, actor, scopes = self._identity_fields(identity)
        if actor != self.warden_id and not self._has_scope(
            scopes, _ADMIN_SCOPES | frozenset({"lets.peer", "lets.transfer"})
        ):
            raise PolicyError("transfer finalization scope is required")
        self._verify_record(ack, warden_id=ack.target_warden)
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._envelope(connection, ack.tenant_id, ack.envelope_id)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            if identity_tenant != ack.tenant_id:
                raise PolicyError("identity tenant does not match transfer tenant")
            if ack.source_warden != self.warden_id:
                raise PolicyError("acknowledgement source does not match this warden")
            if ack.config_epoch != int(_row_value(envelope, "config_epoch")):
                raise ConflictError("acknowledgement configuration epoch does not match source")
            outgoing = connection.execute(
                """
                SELECT * FROM outgoing_transfers
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                  AND sequence = ?
                """,
                (ack.tenant_id, ack.envelope_id, ack.target_warden, ack.sequence),
            ).fetchone()
            if outgoing is None:
                raise NotFoundError("outgoing transfer does not exist")
            if _row_value(outgoing, "transfer_id") != ack.transfer_id:
                raise ConflictError("acknowledgement transfer_id does not match voucher")
            if _row_value(outgoing, "digest") != ack.voucher_digest:
                raise ConflictError("acknowledgement voucher digest does not match transfer")
            status = str(_row_value(outgoing, "status"))
            ack_payload = canonical_json(ack.to_dict())
            if status in {"FINALIZED", "ACKNOWLEDGED"}:
                stored_ack = _row_value(outgoing, "ack_payload")
                if stored_ack is None or bytes(stored_ack) != ack_payload:
                    raise ConflictError("transfer was finalized with another acknowledgement")
                return ack
            if status != "PREPARED":
                raise ConflictError(f"transfer status {status!r} cannot be finalized")
            connection.execute(
                """
                UPDATE outgoing_transfers
                SET status = 'FINALIZED', acknowledged_at_ns = ?, ack_payload = ?
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                  AND sequence = ?
                """,
                (
                    now_ns,
                    ack_payload,
                    ack.tenant_id,
                    ack.envelope_id,
                    ack.target_warden,
                    ack.sequence,
                ),
            )
            stream = connection.execute(
                """
                SELECT acked_through FROM outgoing_transfer_streams
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                """,
                (ack.tenant_id, ack.envelope_id, ack.target_warden),
            ).fetchone()
            if stream is None:
                raise StorageError("outgoing transfer stream is missing")
            watermark = int(_row_value(stream, "acked_through"))
            while True:
                next_row = connection.execute(
                    """
                    SELECT status FROM outgoing_transfers
                    WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                      AND sequence = ?
                    """,
                    (
                        ack.tenant_id,
                        ack.envelope_id,
                        ack.target_warden,
                        watermark + 1,
                    ),
                ).fetchone()
                if next_row is None or _row_value(next_row, "status") not in {
                    "FINALIZED",
                    "ACKNOWLEDGED",
                }:
                    break
                watermark += 1
            connection.execute(
                """
                UPDATE outgoing_transfer_streams
                SET acked_through = ?, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                """,
                (
                    watermark,
                    now_ns,
                    ack.tenant_id,
                    ack.envelope_id,
                    ack.target_warden,
                ),
            )
            self._append_audit(
                connection,
                tenant_id=ack.tenant_id,
                envelope_id=ack.envelope_id,
                event_type="transfer.finalized",
                entity_type="transfer",
                entity_id=ack.transfer_id,
                actor_id=actor,
                details={
                    "target_warden": ack.target_warden,
                    "sequence": ack.sequence,
                    "acked_through": watermark,
                    "voucher_digest": ack.voucher_digest,
                },
                now_ns=now_ns,
            )
            return ack

    def create_transfer_checkpoint(
        self,
        *,
        identity: IdentityContext,
        target_warden: str,
        through_sequence: int | None = None,
    ) -> WireObject:
        """Sign a finalized prefix proof and compact its source-side voucher rows."""

        require_warden_id(target_warden, field="target_warden")
        identity_tenant, actor, scopes = self._identity_fields(identity)
        if actor != self.warden_id and not self._has_scope(
            scopes,
            _ADMIN_SCOPES | frozenset({"lets.transfer", "lets.peer"}),
        ):
            raise PolicyError("transfer checkpoint scope is required")
        if through_sequence is not None and (
            isinstance(through_sequence, bool)
            or not isinstance(through_sequence, int)
            or through_sequence <= 0
            or through_sequence > MAX_RESOURCE
        ):
            raise ValidationError("through_sequence must be a positive integer")
        now_ns = self._clock.now_ns()
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match transfer tenant")
            stream = connection.execute(
                """
                SELECT * FROM outgoing_transfer_streams
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                """,
                (tenant_id, envelope_id, target_warden),
            ).fetchone()
            if stream is None:
                raise NotFoundError("outgoing transfer stream does not exist")
            acked = int(_row_value(stream, "acked_through"))
            compacted = int(_row_value(stream, "compacted_through"))
            through = acked if through_sequence is None else through_sequence
            if through <= 0:
                raise ConflictError("outgoing transfer stream has no finalized prefix")
            if through > acked:
                raise ConflictError("checkpoint exceeds the finalized acknowledgement watermark")
            existing_payload = _row_value(stream, "checkpoint_payload")
            if through == compacted:
                if existing_payload is None:
                    raise StorageError("compacted stream is missing its checkpoint proof")
                return _json_object(existing_payload)
            if through < compacted:
                raise ConflictError("transfer checkpoint would move backward")
            unfinalized = connection.execute(
                """
                SELECT 1 FROM outgoing_transfers
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                  AND sequence <= ? AND status NOT IN ('FINALIZED', 'ACKNOWLEDGED')
                LIMIT 1
                """,
                (tenant_id, envelope_id, target_warden, through),
            ).fetchone()
            if unfinalized is not None:
                raise ConflictError("checkpoint prefix contains an unfinalized transfer")
            if self._allowed_peer_wardens is not None:
                undelivered = connection.execute(
                    """
                    SELECT 1
                    FROM outgoing_transfers AS transfer
                    LEFT JOIN peer_delivery_state AS delivery
                      ON delivery.record_kind = 'transfer'
                     AND delivery.record_id = transfer.transfer_id
                     AND delivery.target_warden = transfer.target_warden
                    WHERE transfer.tenant_id = ? AND transfer.envelope_id = ?
                      AND transfer.target_warden = ? AND transfer.sequence <= ?
                      AND (delivery.record_id IS NULL OR delivery.delivered_at_ns IS NULL)
                    LIMIT 1
                    """,
                    (tenant_id, envelope_id, target_warden, through),
                ).fetchone()
                if undelivered is not None:
                    raise ConflictError(
                        "checkpoint prefix still contains an unconfirmed peer delivery"
                    )
            body = {
                "type": "lets.transfer-checkpoint/v1",
                "tenant_id": tenant_id,
                "envelope_id": envelope_id,
                "config_epoch": int(_row_value(envelope, "config_epoch")),
                "source_warden": self.warden_id,
                "target_warden": target_warden,
                "through_sequence": through,
                "issued_at_ns": now_ns,
            }
            _, checkpoint = self._sign("transfer-checkpoint/v1", body)
            checkpoint_payload = canonical_json(checkpoint)
            connection.execute(
                """
                UPDATE outgoing_transfer_streams
                SET compacted_through = ?, checkpoint_payload = ?, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                """,
                (through, checkpoint_payload, now_ns, tenant_id, envelope_id, target_warden),
            )
            if self._allowed_peer_wardens is not None:
                self._enqueue_peer_delivery(
                    connection,
                    record_kind="checkpoint",
                    record_id=canonical_digest(checkpoint),
                    target_warden=target_warden,
                    ordering_key=target_warden,
                    stream_position=through,
                    payload=checkpoint_payload,
                    now_ns=now_ns,
                    supersede_older=True,
                )
            connection.execute(
                """
                DELETE FROM outgoing_transfers
                WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
                  AND sequence <= ?
                """,
                (tenant_id, envelope_id, target_warden, through),
            )
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="transfer.checkpoint-created",
                entity_type="warden",
                entity_id=target_warden,
                actor_id=actor,
                details={"through_sequence": through},
                now_ns=now_ns,
            )
            return checkpoint

    def ingest_transfer_checkpoint(
        self,
        *,
        identity: IdentityContext,
        checkpoint: Mapping[str, Any],
    ) -> WireObject:
        """Verify a source prefix proof before compacting target acknowledgements."""

        wire = dict(checkpoint)
        required = {
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
        }
        if set(wire) != required or wire.get("type") != "lets.transfer-checkpoint/v1":
            raise ValidationError("transfer checkpoint fields are malformed")
        for field in (
            "tenant_id",
            "envelope_id",
            "source_warden",
            "target_warden",
            "key_id",
        ):
            value = wire.get(field)
            if not isinstance(value, str):
                raise ValidationError(f"checkpoint {field} must be a string")
            require_identifier(value, field=f"checkpoint {field}")
        for field in ("config_epoch", "through_sequence", "issued_at_ns"):
            value = wire.get(field)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or (field != "issued_at_ns" and value == 0)
                or value > MAX_RESOURCE
            ):
                raise ValidationError(f"checkpoint {field} is invalid")
        source_warden = cast(str, wire["source_warden"])
        identity_tenant, actor, scopes = self._identity_fields(identity)
        if actor != source_warden and not self._has_scope(
            scopes,
            _ADMIN_SCOPES | frozenset({"lets.transfer", "lets.peer"}),
        ):
            raise PolicyError("peer identity does not match checkpoint source")
        self._verify_signed("transfer-checkpoint/v1", wire, warden_id=source_warden)
        now_ns = self._clock.now_ns()
        tenant_id = cast(str, wire["tenant_id"])
        envelope_id = cast(str, wire["envelope_id"])
        through = cast(int, wire["through_sequence"])
        with self._store.write() as transaction:
            connection = self._connection(transaction)
            envelope = self._envelope(connection, tenant_id, envelope_id)
            self._clock_is_safe(connection, envelope, now_ns=now_ns)
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match checkpoint tenant")
            if wire["target_warden"] != self.warden_id:
                raise PolicyError("checkpoint target does not match this warden")
            if wire["config_epoch"] != int(_row_value(envelope, "config_epoch")):
                raise ConflictError("checkpoint configuration epoch does not match target")
            stream = connection.execute(
                """
                SELECT * FROM inbound_transfer_streams
                WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                """,
                (tenant_id, envelope_id, source_warden),
            ).fetchone()
            if stream is None:
                raise NotFoundError("inbound transfer stream does not exist")
            contiguous = int(_row_value(stream, "contiguous_through"))
            compacted = int(_row_value(stream, "compacted_through"))
            payload = canonical_json(wire)
            if through > contiguous:
                raise ConflictError("checkpoint exceeds the target contiguous watermark")
            if through < compacted:
                raise ReplayError("checkpoint is older than the durable compacted watermark")
            if through == compacted:
                existing = _row_value(stream, "checkpoint_payload")
                if existing is None or bytes(existing) != payload:
                    raise ConflictError("checkpoint watermark is bound to different signed content")
                return wire
            connection.execute(
                """
                UPDATE inbound_transfer_streams
                SET compacted_through = ?, checkpoint_payload = ?, updated_at_ns = ?
                WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                """,
                (through, payload, now_ns, tenant_id, envelope_id, source_warden),
            )
            connection.execute(
                """
                DELETE FROM inbound_transfer_acks
                WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
                  AND sequence <= ?
                """,
                (tenant_id, envelope_id, source_warden, through),
            )
            self._append_audit(
                connection,
                tenant_id=tenant_id,
                envelope_id=envelope_id,
                event_type="transfer.checkpoint-ingested",
                entity_type="warden",
                entity_id=source_warden,
                actor_id=actor,
                details={"through_sequence": through},
                now_ns=now_ns,
            )
            return wire

    def verify_audit(
        self,
        *,
        identity: IdentityContext,
    ) -> bool:
        """Verify the complete durable audit hash chain and every event signature."""

        identity_tenant, _, scopes = self._identity_fields(identity)
        if not self._has_scope(
            scopes,
            _ADMIN_SCOPES | frozenset({"lets.audit.read", "lets.audit.verify"}),
        ):
            raise PolicyError("audit verification scope is required")
        with self._store.read() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match audit tenant")
            rows = connection.execute(
                """
                SELECT * FROM audit_log
                WHERE tenant_id = ? AND envelope_id = ?
                ORDER BY sequence
                """,
                (tenant_id, envelope_id),
            ).fetchall()
            expected_previous = bytes(32)
            for expected_sequence, row in enumerate(rows):
                sequence = int(_row_value(row, "sequence"))
                if sequence != expected_sequence:
                    raise InvariantError(
                        f"audit sequence gap: got {sequence}, expected {expected_sequence}"
                    )
                previous = bytes(_row_value(row, "previous_hash"))
                if previous != expected_previous:
                    raise InvariantError(f"audit previous hash mismatch at sequence {sequence}")
                payload_bytes = bytes(_row_value(row, "payload"))
                computed_row = connection.execute(
                    "SELECT lets_audit_hash(?, ?, ?, ?, ?, ?, ?)",
                    (
                        previous,
                        sequence,
                        _row_value(row, "event_type"),
                        _row_value(row, "entity_type"),
                        _row_value(row, "entity_id"),
                        payload_bytes,
                        int(_row_value(row, "created_at_ns")),
                    ),
                ).fetchone()
                if computed_row is None:
                    raise StorageError("audit hash function returned no result")
                event_hash = bytes(_row_value(row, "event_hash"))
                if bytes(computed_row[0]) != event_hash:
                    raise InvariantError(f"audit event hash mismatch at sequence {sequence}")
                signed = _json_object(payload_bytes)
                self._verify_signed("audit-event/v1", signed, warden_id=self.warden_id)
                if (
                    signed.get("sequence") != sequence
                    or signed.get("event_type") != _row_value(row, "event_type")
                    or signed.get("tenant_id") != tenant_id
                    or signed.get("envelope_id") != envelope_id
                    or signed.get("entity_type") != _row_value(row, "entity_type")
                    or signed.get("entity_id") != _row_value(row, "entity_id")
                    or signed.get("occurred_at_ns") != int(_row_value(row, "created_at_ns"))
                ):
                    raise InvariantError(f"audit payload/row mismatch at sequence {sequence}")
                expected_previous = event_hash
            return True

    def list_audit(
        self,
        *,
        identity: IdentityContext,
        after_sequence: int = -1,
        limit: int = 100,
    ) -> tuple[AuditRecord, ...]:
        """Return one bounded, ordered page of independently verifiable audit records."""

        if (
            isinstance(after_sequence, bool)
            or not isinstance(after_sequence, int)
            or after_sequence < -1
            or after_sequence > MAX_RESOURCE
        ):
            raise ValidationError("after_sequence must be an integer greater than or equal to -1")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValidationError("audit limit must be between 1 and 1000")
        identity_tenant, _, scopes = self._identity_fields(identity)
        if not self._has_scope(
            scopes,
            _ADMIN_SCOPES | frozenset({"lets.audit.read", "lets.audit.verify"}),
        ):
            raise PolicyError("audit read scope is required")
        with self._store.read() as transaction:
            connection = self._connection(transaction)
            envelope = self._singleton_envelope(connection)
            tenant_id = str(_row_value(envelope, "tenant_id"))
            envelope_id = str(_row_value(envelope, "envelope_id"))
            if identity_tenant != tenant_id:
                raise PolicyError("identity tenant does not match audit tenant")
            rows = connection.execute(
                """
                SELECT * FROM audit_log
                WHERE tenant_id = ? AND envelope_id = ? AND sequence > ?
                ORDER BY sequence LIMIT ?
                """,
                (tenant_id, envelope_id, after_sequence, limit),
            ).fetchall()
            output: list[AuditRecord] = []
            for row in rows:
                signed = _json_object(_row_value(row, "payload"))
                details = signed.get("details")
                if not isinstance(details, dict):
                    raise StorageError("audit details are malformed")
                previous = bytes(_row_value(row, "previous_hash"))
                signature = signed.get("signature")
                key_id = signed.get("key_id")
                actor_id = signed.get("actor_id")
                if not all(isinstance(value, str) for value in (signature, key_id, actor_id)):
                    raise StorageError("audit signature identity is malformed")
                output.append(
                    AuditRecord(
                        sequence=int(_row_value(row, "sequence")),
                        event_type=str(_row_value(row, "event_type")),
                        tenant_id=tenant_id,
                        envelope_id=envelope_id,
                        entity_id=_row_value(row, "entity_id"),
                        actor_id=cast(str, actor_id),
                        occurred_at_ns=int(_row_value(row, "created_at_ns")),
                        details=details,
                        previous_hash=(
                            None
                            if int(_row_value(row, "sequence")) == 0
                            else f"sha256:{previous.hex()}"
                        ),
                        event_hash=f"sha256:{bytes(_row_value(row, 'event_hash')).hex()}",
                        key_id=cast(str, key_id),
                        signature=cast(str, signature),
                    )
                )
            return tuple(output)

    def authorize_transition(self, **arguments: Any) -> Receipt:
        """Compatibility name matching the protocol operation."""

        return self.authorize(**arguments)

    def get_lease(self, **arguments: Any) -> LeaseSnapshot:
        """Compatibility name matching storage/RPC adapters."""

        return self.snapshot(**arguments)


def _unpack_blob(value: object) -> ResourceVector:
    from lets.vector import unpack

    if isinstance(value, memoryview):
        value = value.tobytes()
    if not isinstance(value, bytes):
        raise StorageError("stored resource vector is not a BLOB")
    return unpack(value)
