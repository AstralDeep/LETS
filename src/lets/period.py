"""Period budgets derived from a signed budget policy and a membership list, so two holders that
derive apart get byte-identical, disjoint shares. Signature checking is a caller-supplied
verifier and member ids are opaque, which keeps LETS protocol-neutral. device.py builds the
per-device holder on top of these shares.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from typing import Any, ClassVar, Self

from lets.canonical import canonical_digest, canonical_json
from lets.errors import ConflictError, PolicyError, SignatureError, ValidationError
from lets.ids import require_identifier
from lets.vector import MAX_RESOURCE, ResourceVector

PERMILLE = 1000
MAX_MEMBERS = 1024
MAX_DIMENSIONS = 64
ATTESTED = "attested"
UNATTESTED = "unattested"
_REDUCTION_KEYS = frozenset({ATTESTED, UNATTESTED})

PolicyVerifier = Callable[[str, bytes, str], bool]


def _integer(value: object, field: str, *, minimum: int = 0, maximum: int = MAX_RESOURCE) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < minimum or value > maximum:
        raise ValidationError(f"{field} must be between {minimum} and {maximum}")
    return value


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValidationError(f"{field} must be an object")
    return value


def _vector_map(value: object, dimensions: tuple[str, ...], field: str) -> ResourceVector:
    mapping = _mapping(value, field)
    if set(mapping) != set(dimensions):
        raise ValidationError(f"{field} must name exactly the policy dimensions")
    return tuple(_integer(mapping[name], f"{field}.{name}") for name in dimensions)


@dataclass(frozen=True, slots=True)
class Member:
    member_id: str
    kind: str
    attested: bool

    def __post_init__(self) -> None:
        require_identifier(self.member_id, field="member_id")
        require_identifier(self.kind, field="member kind")
        if not isinstance(self.attested, bool):
            raise ValidationError("member attested flag must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {"member_id": self.member_id, "kind": self.kind, "attested": self.attested}


@dataclass(frozen=True, slots=True)
class BudgetPolicy:
    WIRE_TYPE: ClassVar[str] = "lets.period-policy/v1"

    policy_id: str
    version: int
    issuer: str
    epoch_ns: int
    period_ns: int
    dimensions: tuple[str, ...]
    totals: ResourceVector
    shares: Mapping[str, ResourceVector]
    solo: Mapping[str, ResourceVector]
    attested_reduction_permille: int
    unattested_reduction_permille: int
    sig: str = ""

    def __post_init__(self) -> None:
        require_identifier(self.policy_id, field="policy_id")
        require_identifier(self.issuer, field="issuer")
        _integer(self.version, "version", minimum=1)
        _integer(self.epoch_ns, "epoch_ns")
        _integer(self.period_ns, "period_ns", minimum=1)
        if not self.dimensions or len(self.dimensions) > MAX_DIMENSIONS:
            raise ValidationError(f"policy needs 1 to {MAX_DIMENSIONS} dimensions")
        if list(self.dimensions) != sorted(set(self.dimensions)):
            raise ValidationError("policy dimensions must be unique and sorted")
        for name in self.dimensions:
            require_identifier(name, field="dimension")
        if len(self.totals) != len(self.dimensions):
            raise ValidationError("policy totals must cover every dimension")
        for item in self.totals:
            _integer(item, "total")
        if not self.shares or set(self.shares) != set(self.solo):
            raise ValidationError("policy must give every member kind a share and a solo cap")
        for kind, values in self.shares.items():
            require_identifier(kind, field="member kind")
            solo = self.solo[kind]
            if len(values) != len(self.dimensions) or len(solo) != len(self.dimensions):
                raise ValidationError("member kind vectors must cover every dimension")
            for share, cap in zip(values, solo, strict=True):
                _integer(share, "share")
                _integer(cap, "solo cap")
                if cap > share:
                    raise ValidationError("a solo cap must not exceed the fresh share")
        for field, value in (
            ("attested_reduction_permille", self.attested_reduction_permille),
            ("unattested_reduction_permille", self.unattested_reduction_permille),
        ):
            _integer(value, field, maximum=PERMILLE)
        if not isinstance(self.sig, str):
            raise ValidationError("sig must be a string")
        object.__setattr__(self, "shares", {k: tuple(v) for k, v in self.shares.items()})
        object.__setattr__(self, "solo", {k: tuple(v) for k, v in self.solo.items()})

    def unsigned_payload(self) -> dict[str, Any]:
        def named(values: ResourceVector) -> dict[str, int]:
            return dict(zip(self.dimensions, values, strict=True))

        return {
            "type": self.WIRE_TYPE,
            "policy_id": self.policy_id,
            "version": self.version,
            "issuer": self.issuer,
            "epoch_ns": self.epoch_ns,
            "period_ns": self.period_ns,
            "totals": named(self.totals),
            "shares": {kind: named(values) for kind, values in sorted(self.shares.items())},
            "solo": {kind: named(values) for kind, values in sorted(self.solo.items())},
            "reduction_permille": {
                ATTESTED: self.attested_reduction_permille,
                UNATTESTED: self.unattested_reduction_permille,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "sig": self.sig}

    def message(self) -> bytes:
        return canonical_json(self.unsigned_payload())

    @property
    def digest(self) -> str:
        return canonical_digest(self.unsigned_payload())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        allowed = {
            "type",
            "policy_id",
            "version",
            "issuer",
            "epoch_ns",
            "period_ns",
            "totals",
            "shares",
            "solo",
            "reduction_permille",
            "sig",
        }
        if set(data) != allowed:
            raise ValidationError("period policy has missing or unknown fields")
        if data["type"] != cls.WIRE_TYPE:
            raise ValidationError("unsupported period policy type")
        totals = _mapping(data["totals"], "totals")
        dimensions = tuple(sorted(totals))
        shares = _mapping(data["shares"], "shares")
        solo = _mapping(data["solo"], "solo")
        reduction = _mapping(data["reduction_permille"], "reduction_permille")
        if set(reduction) != _REDUCTION_KEYS:
            raise ValidationError("reduction_permille must name attested and unattested")
        return cls(
            policy_id=data["policy_id"],
            version=data["version"],
            issuer=data["issuer"],
            epoch_ns=data["epoch_ns"],
            period_ns=data["period_ns"],
            dimensions=dimensions,
            totals=_vector_map(totals, dimensions, "totals"),
            shares={k: _vector_map(v, dimensions, f"shares.{k}") for k, v in shares.items()},
            solo={k: _vector_map(v, dimensions, f"solo.{k}") for k, v in solo.items()},
            attested_reduction_permille=reduction[ATTESTED],
            unattested_reduction_permille=reduction[UNATTESTED],
            sig=data["sig"],
        )

    def verify(self, verifier: PolicyVerifier) -> None:
        try:
            valid = verifier(self.issuer, self.message(), self.sig)
        except Exception as error:
            raise SignatureError("budget policy signature could not be verified") from error
        if valid is not True:
            raise SignatureError("budget policy signature is invalid")


def period_index(policy: BudgetPolicy, now_ns: int) -> int:
    _integer(now_ns, "now_ns")
    if now_ns < policy.epoch_ns:
        raise PolicyError("time is before the policy epoch")
    return (now_ns - policy.epoch_ns) // policy.period_ns


def period_bounds(policy: BudgetPolicy, index: int) -> tuple[int, int]:
    _integer(index, "period index")
    start = policy.epoch_ns + index * policy.period_ns
    end = start + policy.period_ns
    if end > MAX_RESOURCE:
        raise ValidationError("period bounds exceed signed 64-bit time")
    return start, end


@dataclass(frozen=True, slots=True)
class MemberShare:
    member_id: str
    fresh: ResourceVector
    solo: ResourceVector

    def to_dict(self, dimensions: tuple[str, ...]) -> dict[str, Any]:
        return {
            "member_id": self.member_id,
            "fresh": dict(zip(dimensions, self.fresh, strict=True)),
            "solo": dict(zip(dimensions, self.solo, strict=True)),
        }


@dataclass(frozen=True, slots=True)
class PeriodBudget:
    WIRE_TYPE: ClassVar[str] = "lets.period-budget/v1"

    period_index: int
    starts_at_ns: int
    ends_at_ns: int
    policy_digest: str
    membership_digest: str
    dimensions: tuple[str, ...]
    total: ResourceVector
    reserve: ResourceVector
    shares: tuple[MemberShare, ...]

    def share_of(self, member_id: str) -> MemberShare | None:
        return next((item for item in self.shares if item.member_id == member_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.WIRE_TYPE,
            "period_index": self.period_index,
            "starts_at_ns": self.starts_at_ns,
            "ends_at_ns": self.ends_at_ns,
            "policy_digest": self.policy_digest,
            "membership_digest": self.membership_digest,
            "total": dict(zip(self.dimensions, self.total, strict=True)),
            "reserve": dict(zip(self.dimensions, self.reserve, strict=True)),
            "shares": [item.to_dict(self.dimensions) for item in self.shares],
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


def membership_digest(members: Iterable[Member]) -> str:
    ordered = _ordered_members(members)
    return canonical_digest(
        {"type": "lets.period-membership/v1", "members": [item.to_dict() for item in ordered]}
    )


def _ordered_members(members: Iterable[Member]) -> list[Member]:
    ordered = sorted(members, key=lambda item: item.member_id)
    if not ordered:
        raise ValidationError("a period needs at least one member")
    if len(ordered) > MAX_MEMBERS:
        raise ValidationError(f"a period supports at most {MAX_MEMBERS} members")
    for left, right in pairwise(ordered):
        if left.member_id == right.member_id:
            raise ValidationError(f"member {left.member_id!r} is listed twice")
    return ordered


def _scale(values: ResourceVector, reduction_permille: int) -> ResourceVector:
    return tuple(value * (PERMILLE - reduction_permille) // PERMILLE for value in values)


def derive_budget(policy: BudgetPolicy, members: Iterable[Member], index: int) -> PeriodBudget:
    ordered = _ordered_members(members)
    starts, ends = period_bounds(policy, index)
    entries: list[tuple[str, ResourceVector, ResourceVector]] = []
    for member in ordered:
        if member.kind not in policy.shares:
            raise PolicyError(f"policy has no share for member kind {member.kind!r}")
        reduction = (
            policy.attested_reduction_permille
            if member.attested
            else policy.unattested_reduction_permille
        )
        entries.append(
            (
                member.member_id,
                _scale(policy.shares[member.kind], reduction),
                _scale(policy.solo[member.kind], reduction),
            )
        )
    demand = tuple(sum(entry[1][i] for entry in entries) for i in range(len(policy.dimensions)))
    shares: list[MemberShare] = []
    for member_id, wanted, solo_wanted in entries:
        fresh = tuple(
            amount if demand[i] <= policy.totals[i] else amount * policy.totals[i] // demand[i]
            for i, amount in enumerate(wanted)
        )
        solo = tuple(min(cap, fresh[i]) for i, cap in enumerate(solo_wanted))
        shares.append(MemberShare(member_id, fresh, solo))
    reserve = tuple(
        policy.totals[i] - sum(item.fresh[i] for item in shares)
        for i in range(len(policy.dimensions))
    )
    return PeriodBudget(
        period_index=index,
        starts_at_ns=starts,
        ends_at_ns=ends,
        policy_digest=policy.digest,
        membership_digest=membership_digest(ordered),
        dimensions=policy.dimensions,
        total=policy.totals,
        reserve=reserve,
        shares=tuple(shares),
    )


class PolicyChange(StrEnum):
    UNCHANGED = "unchanged"
    NARROWED = "narrowed"
    WIDENED = "widened"


def classify_change(current: BudgetPolicy, candidate: BudgetPolicy) -> PolicyChange:
    if (
        candidate.epoch_ns != current.epoch_ns
        or candidate.period_ns != current.period_ns
        or candidate.dimensions != current.dimensions
        or set(candidate.shares) != set(current.shares)
    ):
        return PolicyChange.WIDENED
    pairs: list[tuple[ResourceVector, ResourceVector]] = [(current.totals, candidate.totals)]
    for kind in current.shares:
        pairs.append((current.shares[kind], candidate.shares[kind]))
        pairs.append((current.solo[kind], candidate.solo[kind]))
    reductions_hold = (
        candidate.attested_reduction_permille >= current.attested_reduction_permille
        and candidate.unattested_reduction_permille >= current.unattested_reduction_permille
    )
    never_larger = all(
        new <= old
        for old_vector, new_vector in pairs
        for old, new in zip(old_vector, new_vector, strict=True)
    )
    if not (reductions_hold and never_larger):
        return PolicyChange.WIDENED
    same_terms = (
        all(old_vector == new_vector for old_vector, new_vector in pairs)
        and candidate.attested_reduction_permille == current.attested_reduction_permille
        and candidate.unattested_reduction_permille == current.unattested_reduction_permille
    )
    return PolicyChange.UNCHANGED if same_terms else PolicyChange.NARROWED


@dataclass(frozen=True, slots=True)
class WideningConsent:
    policy_digest: str
    given_by: str
    evidence: str

    def __post_init__(self) -> None:
        require_identifier(self.policy_digest, field="consent policy_digest")
        require_identifier(self.given_by, field="consent given_by")
        require_identifier(self.evidence, field="consent evidence")


def adopt_policy(
    current: BudgetPolicy | None,
    candidate: BudgetPolicy,
    *,
    verifier: PolicyVerifier,
    consent: WideningConsent | None = None,
) -> BudgetPolicy:
    candidate.verify(verifier)
    if current is None:
        return candidate
    if candidate.policy_id != current.policy_id:
        raise ConflictError("candidate belongs to another budget policy")
    if candidate.version == current.version and candidate.digest == current.digest:
        return current
    if candidate.version <= current.version:
        raise PolicyError("policy version is not newer than the adopted one")
    if classify_change(current, candidate) is PolicyChange.WIDENED and (
        consent is None or consent.policy_digest != candidate.digest
    ):
        raise PolicyError("widening a budget policy needs consent bound to the new digest")
    return candidate
