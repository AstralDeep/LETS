"""A LETS holder that lives on one device: it spends its period share by issuing receipts through
a WardenService, stops at the share's edge, and restores headroom through prepare, accept and
finalize transfers. It adds a clock floor, a freshness rule that falls back to the solo cap, and
the restored-device-is-a-new-holder rule on top of the shares derived in period.py.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Any

from lets.canonical import canonical_json
from lets.clock import Clock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ConflictError, PolicyError, ValidationError
from lets.ids import require_identifier
from lets.models import IdentityContext, Receipt, TransferAck, TransferVoucher
from lets.period import (
    BudgetPolicy,
    Member,
    MemberShare,
    PolicyChange,
    PolicyVerifier,
    WideningConsent,
    adopt_policy,
    classify_change,
    derive_budget,
    period_index,
)
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage
from lets.vector import MAX_RESOURCE, ResourceVector

DAY_NS = 86_400 * 1_000_000_000
MAX_UNITS_PER_SPEND = 1_024
MembershipSource = Callable[[int], Sequence[Member]]

_STATE_FILE = "device.json"
_READY = "ready"
_ADMIN = frozenset({"lets.admin"})


class Mode(StrEnum):
    FRESH = "fresh"
    SOLO = "solo"


class Refusal(StrEnum):
    NOT_A_MEMBER = "not_a_member"
    SHARE_SPENT = "share_spent"
    SOLO_CAP_REACHED = "solo_cap_reached"
    LAPSED = "lapsed"
    UNKNOWN_DIMENSION = "unknown_dimension"
    INVALID_AMOUNT = "invalid_amount"


class AllowanceRefusedError(PolicyError):
    def __init__(
        self,
        reason: Refusal,
        message: str,
        *,
        dimension: str | None = None,
        requested: int = 0,
        remaining: int = 0,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.dimension = dimension
        self.requested = requested
        self.remaining = remaining


@dataclass(frozen=True, slots=True)
class DeviceConfig:
    mesh_id: str
    freshness_window_ns: int = DAY_NS
    receipt_ttl_ns: int = 300 * 1_000_000_000
    max_clock_uncertainty_ns: int = 0
    transfer_gap_window: int = 64

    def __post_init__(self) -> None:
        require_identifier(self.mesh_id, field="mesh_id")
        for name in ("freshness_window_ns", "receipt_ttl_ns", "transfer_gap_window"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= MAX_RESOURCE
            ):
                raise ValidationError(f"{name} must be a positive signed 64-bit integer")
        value = self.max_clock_uncertainty_ns
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_RESOURCE:
            raise ValidationError("max_clock_uncertainty_ns must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class Allowance:
    period_index: int
    mode: Mode
    dimensions: tuple[str, ...]
    cap: ResourceVector
    consumed: ResourceVector
    remaining: ResourceVector
    clock_regressed: bool
    retired: bool

    def remaining_for(self, dimension: str) -> int:
        return self.remaining[self.dimensions.index(dimension)]


@dataclass(slots=True)
class _Period:
    index: int
    policy: BudgetPolicy
    members: tuple[Member, ...]
    total: ResourceVector
    initial_share: ResourceVector
    store: SQLiteStorage | None = None
    service: WardenService | None = None
    leases: list[str] | None = None
    pending: dict[str, Any] | None = None

    def share(self, member_id: str) -> MemberShare | None:
        return derive_budget(self.policy, self.members, self.index).share_of(member_id)


class _FlooredClock:
    def __init__(self, holder: DeviceHolder) -> None:
        self._holder = holder

    def now_ns(self) -> int:
        return self._holder.effective_now_ns()

    def uncertainty_ns(self) -> int:
        return self._holder.clock_uncertainty_ns()


def lets_policy(policy: BudgetPolicy, config: DeviceConfig) -> PolicySpec:
    return PolicySpec(
        policy_id=policy.policy_id,
        policy_version="period-v1",
        dimensions=tuple(ResourceDimension(name, "unit") for name in policy.dimensions),
        machine=MachineSpec(
            machine_id="device-period",
            initial_state=_READY,
            transitions=tuple(
                TransitionSpec(
                    f"spend.{name}",
                    _READY,
                    _READY,
                    tuple(1 if other == name else 0 for other in policy.dimensions),
                    f"spend.{name}",
                )
                for name in policy.dimensions
            ),
        ),
        max_lease_ttl_ns=policy.period_ns,
        receipt_ttl_ns=config.receipt_ttl_ns,
        max_clock_uncertainty_ns=config.max_clock_uncertainty_ns,
        transfer_gap_window=config.transfer_gap_window,
    )


class DeviceHolder:
    def __init__(
        self,
        *,
        directory: Path | str,
        signer: Ed25519Signer,
        registry: PublicKeyRegistry,
        clock: Clock,
        policy: BudgetPolicy,
        policy_verifier: PolicyVerifier,
        membership_source: MembershipSource,
        config: DeviceConfig,
        seed_clock_floor_ns: int = 0,
    ) -> None:
        policy.verify(policy_verifier)
        registry.register_signer(signer)
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._signer = signer
        self._registry = registry
        self._clock = clock
        self._policy = policy
        self._verifier = policy_verifier
        self._members = membership_source
        self._config = config
        self._lock = threading.RLock()
        self._identity = IdentityContext(signer.warden_id, config.mesh_id, _ADMIN)
        self._period: _Period | None = None
        self._regressed = False
        state = self._load_state()
        self._floor = max(int(state.get("clock_floor_ns", 0)), seed_clock_floor_ns)
        self._last_contact: int | None = state.get("last_contact_ns")
        self._retired_period: int | None = state.get("retired_period")
        self._saved_period = state.get("period")

    @property
    def member_id(self) -> str:
        return self._signer.warden_id

    def effective_now_ns(self) -> int:
        raw = self._clock.now_ns()
        if raw < self._floor:
            self._regressed = True
            return self._floor
        self._floor = raw
        return raw

    def clock_uncertainty_ns(self) -> int:
        return self._clock.uncertainty_ns()

    def record_contact(self) -> None:
        with self._lock:
            self._last_contact = self.effective_now_ns()
            self._save()

    def set_policy(
        self,
        candidate: BudgetPolicy,
        *,
        consent: WideningConsent | None = None,
    ) -> BudgetPolicy:
        with self._lock:
            adopted = adopt_policy(
                self._policy, candidate, verifier=self._verifier, consent=consent
            )
            if adopted is not self._policy:
                change = classify_change(self._policy, adopted)
                self._policy = adopted
                if self._period is not None and change is not PolicyChange.WIDENED:
                    self._period.policy = adopted
                self._save()
            return self._policy

    def retire(self) -> None:
        with self._lock:
            index = self._current_index()
            self._retired_period = index
            self._save()

    def export_backup(self) -> dict[str, Any]:
        with self._lock:
            self.effective_now_ns()
            return {
                "member_id": self.member_id,
                "clock_floor_ns": self._floor,
                "policy_digest": self._policy.digest,
            }

    @staticmethod
    def seed_from_backup(backup: Mapping[str, Any], *, new_signer: Ed25519Signer) -> int:
        if backup.get("member_id") == new_signer.warden_id:
            raise ValidationError("a restored device must enroll under a new member id")
        floor = backup.get("clock_floor_ns")
        if isinstance(floor, bool) or not isinstance(floor, int) or floor < 0:
            raise ValidationError("backup clock floor is invalid")
        return floor

    def close(self) -> None:
        with self._lock:
            if self._period is not None and self._period.store is not None:
                self._period.store.close()
            self._period = None

    def allowance(self) -> Allowance:
        with self._lock:
            period = self._period_now()
            return self._allowance(period)

    def spend(
        self,
        dimension: str,
        units: int = 1,
        *,
        audience: str,
        request_id: str,
    ) -> tuple[Receipt, ...]:
        require_identifier(audience, field="audience")
        require_identifier(request_id, field="request_id")
        if (
            isinstance(units, bool)
            or not isinstance(units, int)
            or not 0 < units <= MAX_UNITS_PER_SPEND
        ):
            raise AllowanceRefusedError(
                Refusal.INVALID_AMOUNT,
                f"units must be between 1 and {MAX_UNITS_PER_SPEND}",
                dimension=dimension,
                requested=units if isinstance(units, int) else 0,
            )
        with self._lock:
            period = self._period_now()
            if dimension not in period.policy.dimensions:
                raise AllowanceRefusedError(
                    Refusal.UNKNOWN_DIMENSION,
                    f"{dimension!r} is not a budgeted dimension",
                    dimension=dimension,
                    requested=units,
                )
            self._require_member(period)
            allowance = self._allowance(period)
            remaining = allowance.remaining_for(dimension)
            if units > remaining:
                solo = allowance.mode is Mode.SOLO
                raise AllowanceRefusedError(
                    Refusal.SOLO_CAP_REACHED if solo else Refusal.SHARE_SPENT,
                    f"{dimension} allowance for this period has {remaining} left in "
                    f"{allowance.mode.value} mode and {units} were requested",
                    dimension=dimension,
                    requested=units,
                    remaining=remaining,
                )
            service = self._service(period)
            receipts: list[Receipt] = []
            for position in range(units):
                lease_id = self._lease_with_room(period, service, dimension)
                nonce = sha256(f"{self.member_id}/{request_id}/{position}".encode()).hexdigest()[
                    :32
                ]
                receipts.append(
                    service.authorize(
                        request_id=f"{request_id}.{position}",
                        identity=self._identity,
                        lease_id=lease_id,
                        transition=f"spend.{dimension}",
                        audience=audience,
                        nonce=nonce,
                        expected_state=_READY,
                    )
                )
            self._save()
            return tuple(receipts)

    def offer_headroom(
        self,
        target_member: str,
        amounts: Mapping[str, int],
        *,
        request_id: str,
    ) -> TransferVoucher:
        with self._lock:
            period = self._period_now()
            self._require_member(period)
            service = self._service(period)
            vector = self._vector(period, amounts)
            allowance = self._allowance(period)
            for name, wanted, left in zip(
                period.policy.dimensions, vector, allowance.remaining, strict=True
            ):
                if wanted > left:
                    raise AllowanceRefusedError(
                        Refusal.SHARE_SPENT,
                        f"only {left} of {name} is left to give",
                        dimension=name,
                        requested=wanted,
                        remaining=left,
                    )
            try:
                for lease_id in list(period.leases or []):
                    service.close(
                        request_id=f"close.{lease_id}", identity=self._identity, lease_id=lease_id
                    )
                voucher = service.prepare_transfer(
                    request_id=request_id,
                    identity=self._identity,
                    tenant_id=self._config.mesh_id,
                    envelope_id=f"period-{period.index}",
                    target_warden=target_member,
                    amount=vector,
                    policy_digest=self._lets_digest(period),
                )
            finally:
                self._lease_free_pool(period, service)
            self._save()
            return voucher

    def accept_headroom(self, voucher: TransferVoucher | Mapping[str, Any]) -> TransferAck:
        with self._lock:
            period = self._period_now()
            self._require_member(period)
            service = self._service(period)
            ack = service.accept_transfer(identity=self._identity, voucher=voucher)
            self._last_contact = self.effective_now_ns()
            self._lease_free_pool(period, service)
            self._save()
            return ack

    def settle_headroom(self, ack: TransferAck | Mapping[str, Any]) -> TransferAck:
        with self._lock:
            period = self._period_now()
            self._require_member(period)
            service = self._service(period)
            settled = service.finalize_transfer(identity=self._identity, acknowledgement=ack)
            self._last_contact = self.effective_now_ns()
            self._save()
            return settled

    @staticmethod
    def _require_member(period: _Period) -> None:
        if period.leases is None:
            raise AllowanceRefusedError(
                Refusal.NOT_A_MEMBER, "this device holds no share in the current period"
            )

    def _vector(self, period: _Period, amounts: Mapping[str, int]) -> ResourceVector:
        unknown = set(amounts) - set(period.policy.dimensions)
        if unknown:
            raise AllowanceRefusedError(
                Refusal.UNKNOWN_DIMENSION, f"unknown dimensions {sorted(unknown)}"
            )
        values = tuple(amounts.get(name, 0) for name in period.policy.dimensions)
        if not any(values) or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in values
        ):
            raise AllowanceRefusedError(Refusal.INVALID_AMOUNT, "amounts must be positive integers")
        return values

    def _current_index(self) -> int:
        return period_index(self._policy, self.effective_now_ns())

    def _period_now(self) -> _Period:
        index = self._current_index()
        if self._retired_period is not None and index > self._retired_period:
            raise AllowanceRefusedError(
                Refusal.LAPSED, "this holder was retired and its period share has lapsed"
            )
        current = self._period
        if current is not None and current.index == index:
            return current
        if current is not None and current.store is not None:
            current.store.close()
        self._period = self._open_period(index)
        self._save()
        return self._period

    def _open_period(self, index: int) -> _Period:
        saved = self._saved_period
        if isinstance(saved, dict) and saved.get("index") == index:
            period = _Period(
                index=index,
                policy=BudgetPolicy.from_dict(saved["policy"]),
                members=tuple(
                    Member(item["member_id"], item["kind"], item["attested"])
                    for item in saved["members"]
                ),
                total=tuple(saved["total"]),
                initial_share=tuple(saved["initial_share"]),
                leases=(
                    list(saved["leases"])
                    if any(item["member_id"] == self.member_id for item in saved["members"])
                    else None
                ),
                pending=saved.get("pending"),
            )
            if self._policy.digest != period.policy.digest and (
                classify_change(period.policy, self._policy) is not PolicyChange.WIDENED
            ):
                period.policy = self._policy
            return period
        members = tuple(self._members(index))
        budget = derive_budget(self._policy, members, index)
        share = budget.share_of(self.member_id)
        return _Period(
            index=index,
            policy=self._policy,
            members=members,
            total=budget.total,
            initial_share=share.fresh if share is not None else tuple(0 for _ in budget.total),
            leases=[] if share is not None else None,
        )

    def _service(self, period: _Period) -> WardenService:
        if period.service is not None:
            return period.service
        self._require_member(period)
        path = self._dir / f"period-{period.index}.sqlite3"
        options: dict[str, Any] = {
            "signing_key_id": self._signer.key_id,
            "signing_public_key": self._signer.public_key_bytes,
            "tenant_id": self._config.mesh_id,
            "envelope_id": f"period-{period.index}",
            "config_epoch": period.index + 1,
            "initial_local_share": period.initial_share,
            "receipt_ttl_ns": self._config.receipt_ttl_ns,
            "max_clock_uncertainty_ns": self._config.max_clock_uncertainty_ns,
            "transfer_gap_window": self._config.transfer_gap_window,
        }
        if path.exists():
            store = SQLiteStorage(path, self.member_id, period.total, **options)
        else:
            store = SQLiteStorage.initialize(path, self.member_id, period.total, **options)
        service = WardenService(
            store,
            signer=self._signer,
            clock=_FlooredClock(self),
            trust_registry=self._registry,
        )
        service.register_policy(lets_policy(period.policy, self._config))
        period.store = store
        period.service = service
        self._lease_free_pool(period, service)
        return service

    def _lets_digest(self, period: _Period) -> str:
        return lets_policy(period.policy, self._config).digest

    def _lease_free_pool(self, period: _Period, service: WardenService) -> None:
        if period.pending is not None:
            self._issue(period, service, period.pending)
        snapshot = service.invariant_snapshot(identity=self._identity)
        if any(snapshot.free_pool):
            now = self.effective_now_ns()
            ends = period.policy.epoch_ns + (period.index + 1) * period.policy.period_ns
            period.pending = {
                "n": len(period.leases or []),
                "allocation": list(snapshot.free_pool),
                "ttl_ns": max(1, ends - now),
            }
            self._save()
            self._issue(period, service, period.pending)

    def _issue(self, period: _Period, service: WardenService, intent: Mapping[str, Any]) -> None:
        grant = service.issue_root(
            request_id=f"lease.{period.index}.{intent['n']}",
            identity=self._identity,
            tenant_id=self._config.mesh_id,
            envelope_id=f"period-{period.index}",
            subject_id=self.member_id,
            allocation=tuple(intent["allocation"]),
            capabilities={f"spend.{name}" for name in period.policy.dimensions},
            policy_digest=self._lets_digest(period),
            ttl_ns=intent["ttl_ns"],
        )
        leases = period.leases if period.leases is not None else []
        if grant.lease_id not in leases:
            leases.append(grant.lease_id)
        period.leases = leases
        period.pending = None
        self._save()

    def _lease_with_room(self, period: _Period, service: WardenService, dimension: str) -> str:
        position = period.policy.dimensions.index(dimension)
        for lease_id in period.leases or []:
            snapshot = service.snapshot(identity=self._identity, lease_id=lease_id)
            if snapshot.status.value == "ACTIVE" and snapshot.residual[position] > 0:
                return lease_id
        raise ConflictError("no live lease holds rights for this dimension")

    def _allowance(self, period: _Period) -> Allowance:
        dimensions = period.policy.dimensions
        zero = tuple(0 for _ in dimensions)
        share = period.share(self.member_id)
        now = self.effective_now_ns()
        others = any(item.member_id != self.member_id for item in period.members)
        fresh = (
            others
            and self._last_contact is not None
            and 0 <= now - self._last_contact <= self._config.freshness_window_ns
        )
        mode = Mode.FRESH if fresh else Mode.SOLO
        if share is None or period.leases is None:
            return Allowance(
                period.index, mode, dimensions, zero, zero, zero, self._regressed, False
            )
        service = self._service(period)
        snapshot = service.invariant_snapshot(identity=self._identity)
        entitlement = tuple(
            max(0, base + received - given)
            for base, received, given in zip(
                share.fresh, snapshot.transferred_in, snapshot.transferred_out, strict=True
            )
        )
        stored = tuple(
            initial + received - given
            for initial, received, given in zip(
                snapshot.initial_share,
                snapshot.transferred_in,
                snapshot.transferred_out,
                strict=True,
            )
        )
        fresh_cap = tuple(min(left, right) for left, right in zip(entitlement, stored, strict=True))
        cap = (
            fresh_cap
            if mode is Mode.FRESH
            else tuple(min(item, limit) for item, limit in zip(share.solo, fresh_cap, strict=True))
        )
        remaining = tuple(
            max(0, limit - used) for limit, used in zip(cap, snapshot.consumed, strict=True)
        )
        retired = self._retired_period is not None and period.index == self._retired_period
        return Allowance(
            period.index,
            mode,
            dimensions,
            cap,
            snapshot.consumed,
            remaining,
            self._regressed,
            retired,
        )

    def _load_state(self) -> dict[str, Any]:
        path = self._dir / _STATE_FILE
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ValidationError("device state file is unreadable") from error
        if not isinstance(data, dict) or data.get("member_id") != self.member_id:
            raise ValidationError("device state belongs to another member")
        return data

    def _save(self) -> None:
        period = self._period
        record: dict[str, Any] = {
            "member_id": self.member_id,
            "clock_floor_ns": self._floor,
            "last_contact_ns": self._last_contact,
            "retired_period": self._retired_period,
            "period": self._saved_period,
        }
        if period is not None:
            record["period"] = {
                "index": period.index,
                "policy": period.policy.to_dict(),
                "members": [item.to_dict() for item in period.members],
                "total": list(period.total),
                "initial_share": list(period.initial_share),
                "leases": period.leases or [],
                "pending": period.pending,
            }
            self._saved_period = record["period"]
        payload = canonical_json(record)
        descriptor, temporary = tempfile.mkstemp(prefix=".device.", suffix=".tmp", dir=self._dir)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._dir / _STATE_FILE)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
            raise
