"""Immutable, content-addressed LETS policy and state-machine definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Self

from lets.canonical import canonical_digest, canonical_json
from lets.errors import PolicyError, ValidationError
from lets.ids import require_identifier
from lets.vector import MAX_RESOURCE, ResourceVector, vector

_MISSING = object()
_BOOLEAN_OPS = frozenset({"all", "any"})
_COMPARISON_OPS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte"})
_PATH_OPS = frozenset({"exists", *_COMPARISON_OPS})
_RESERVED_ROOTS = frozenset({"evidence", "now_ns", "subject", "audience"})
MAX_EVIDENCE_DEPTH = 32
MAX_EVIDENCE_NODES = 256
MAX_EVIDENCE_VALUES = 256
MAX_MACHINE_TRANSITIONS = 1024
MAX_POLICY_DIMENSIONS = 256
MAX_TRANSFER_GAP_WINDOW = 1_048_576


@dataclass(frozen=True, slots=True)
class ResourceDimension:
    id: str
    unit: str
    description: str = ""

    def __post_init__(self) -> None:
        require_identifier(self.id, field="resource dimension id")
        if not self.unit or len(self.unit) > 80:
            raise ValidationError("resource dimension unit must contain 1..80 characters")
        if len(self.description) > 500:
            raise ValidationError("resource dimension description exceeds 500 characters")

    def to_dict(self) -> dict[str, str]:
        result = {"id": self.id, "unit": self.unit}
        if self.description:
            result["description"] = self.description
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        unknown = set(data) - {"id", "unit", "description"}
        if unknown:
            raise ValidationError(f"unknown resource dimension fields: {sorted(unknown)}")
        return cls(id=data["id"], unit=data["unit"], description=data.get("description", ""))


@dataclass(frozen=True, slots=True)
class EvidenceRule:
    """Closed, non-executable evidence expression tree."""

    op: str
    path: str | None = None
    value: Any = field(default=_MISSING, repr=False)
    values: tuple[Any, ...] = ()
    rules: tuple[EvidenceRule, ...] = ()
    rule: EvidenceRule | None = None
    observed_at_path: str | None = None
    max_age_ns: int | None = None

    def __post_init__(self) -> None:
        if any(not isinstance(item, EvidenceRule) for item in self.rules):
            raise ValidationError("evidence rules must contain evidence rule objects")
        if self.rule is not None and not isinstance(self.rule, EvidenceRule):
            raise ValidationError("evidence rule must contain an evidence rule object")
        if self.op in _BOOLEAN_OPS:
            if not self.rules:
                raise ValidationError(f"evidence {self.op} requires at least one rule")
            self._reject_extras("rules")
        elif self.op == "not":
            if self.rule is None:
                raise ValidationError("evidence not requires one rule")
            self._reject_extras("rule")
        elif self.op in _PATH_OPS:
            _validate_path(self.path, "evidence path")
            if self.op in _COMPARISON_OPS and self.value is _MISSING:
                raise ValidationError(f"evidence {self.op} requires value")
            if self.op == "exists" and self.value is not _MISSING:
                raise ValidationError("evidence exists does not accept value")
            self._reject_extras("path_value" if self.op in _COMPARISON_OPS else "path")
        elif self.op == "in":
            _validate_path(self.path, "evidence path")
            if not self.values:
                raise ValidationError("evidence in requires a non-empty values array")
            self._reject_extras("path_values")
        elif self.op == "fresh":
            _validate_path(self.observed_at_path, "observed_at_path")
            if (
                isinstance(self.max_age_ns, bool)
                or not isinstance(self.max_age_ns, int)
                or self.max_age_ns < 0
                or self.max_age_ns > MAX_RESOURCE
            ):
                raise ValidationError(
                    "evidence fresh requires signed-int64 non-negative max_age_ns"
                )
            self._reject_extras("fresh")
        else:
            raise ValidationError(f"unknown evidence operation {self.op!r}")
        if self.value is not _MISSING:
            self._validate_literal(self.value)
        if len(self.values) > MAX_EVIDENCE_VALUES:
            raise ValidationError(f"evidence values exceeds the v1 limit of {MAX_EVIDENCE_VALUES}")
        for item in self.values:
            self._validate_literal(item)
        self._validate_shape()

    @staticmethod
    def _validate_literal(value: Any) -> None:
        try:
            canonical_json(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("evidence literal is outside the LETS-CJ/1 subset") from exc

    def _validate_shape(self) -> None:
        nodes = 0
        stack: list[tuple[EvidenceRule, int]] = [(self, 1)]
        while stack:
            current, depth = stack.pop()
            nodes += 1
            if depth > MAX_EVIDENCE_DEPTH:
                raise ValidationError(
                    f"evidence depth exceeds the v1 limit of {MAX_EVIDENCE_DEPTH}"
                )
            if nodes > MAX_EVIDENCE_NODES:
                raise ValidationError(
                    f"evidence node count exceeds the v1 limit of {MAX_EVIDENCE_NODES}"
                )
            stack.extend((item, depth + 1) for item in current.rules)
            if current.rule is not None:
                stack.append((current.rule, depth + 1))

    def _reject_extras(self, shape: str) -> None:
        present = {
            "path": self.path is not None,
            "value": self.value is not _MISSING,
            "values": bool(self.values),
            "rules": bool(self.rules),
            "rule": self.rule is not None,
            "observed_at_path": self.observed_at_path is not None,
            "max_age_ns": self.max_age_ns is not None,
        }
        allowed = {
            "rules": {"rules"},
            "rule": {"rule"},
            "path": {"path"},
            "path_value": {"path", "value"},
            "path_values": {"path", "values"},
            "fresh": {"observed_at_path", "max_age_ns"},
        }[shape]
        extras = {name for name, exists in present.items() if exists and name not in allowed}
        if extras:
            raise ValidationError(f"evidence {self.op} has incompatible fields: {sorted(extras)}")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"op": self.op}
        if self.op in _BOOLEAN_OPS:
            result["rules"] = [item.to_dict() for item in self.rules]
        elif self.op == "not":
            if self.rule is None:
                raise ValidationError("evidence not requires one nested rule")
            result["rule"] = self.rule.to_dict()
        elif self.op == "in":
            result.update(path=self.path, values=list(self.values))
        elif self.op == "fresh":
            result.update(observed_at_path=self.observed_at_path, max_age_ns=self.max_age_ns)
        else:
            result["path"] = self.path
            if self.value is not _MISSING:
                result["value"] = self.value
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        counter = [0]
        return cls._from_dict(data, depth=1, counter=counter)

    @classmethod
    def _from_dict(
        cls,
        data: dict[str, Any],
        *,
        depth: int,
        counter: list[int],
    ) -> Self:
        if depth > MAX_EVIDENCE_DEPTH:
            raise ValidationError(f"evidence depth exceeds the v1 limit of {MAX_EVIDENCE_DEPTH}")
        counter[0] += 1
        if counter[0] > MAX_EVIDENCE_NODES:
            raise ValidationError(
                f"evidence node count exceeds the v1 limit of {MAX_EVIDENCE_NODES}"
            )
        if not isinstance(data, dict):
            raise ValidationError("evidence rule must be an object")
        allowed = {
            "op",
            "path",
            "value",
            "values",
            "rules",
            "rule",
            "observed_at_path",
            "max_age_ns",
        }
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"unknown evidence fields: {sorted(unknown)}")
        op = data.get("op")
        if not isinstance(op, str):
            raise ValidationError("evidence op must be a string")
        raw_rules = data.get("rules", ())
        if not isinstance(raw_rules, (list, tuple)):
            raise ValidationError("evidence rules must be an array")
        rules = tuple(cls._from_dict(item, depth=depth + 1, counter=counter) for item in raw_rules)
        raw_rule = data.get("rule")
        nested = (
            cls._from_dict(raw_rule, depth=depth + 1, counter=counter)
            if raw_rule is not None
            else None
        )
        raw_values = data.get("values", ())
        if not isinstance(raw_values, (list, tuple)):
            raise ValidationError("evidence values must be an array")
        return cls(
            op=op,
            path=data.get("path"),
            value=data.get("value", _MISSING),
            values=tuple(raw_values),
            rules=rules,
            rule=nested,
            observed_at_path=data.get("observed_at_path"),
            max_age_ns=data.get("max_age_ns"),
        )


def _validate_path(value: str | None, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field_name} must be a non-empty dotted path")
    for part in value.split("."):
        require_identifier(part, field=field_name, maximum=128)
    return value


def _resolve_path(
    path: str,
    evidence: dict[str, Any],
    *,
    now_ns: int,
    subject_id: str,
    audience: str,
) -> tuple[bool, Any]:
    parts = path.split(".")
    context: dict[str, Any] = {
        "evidence": evidence,
        "now_ns": now_ns,
        "subject": subject_id,
        "audience": audience,
    }
    if parts[0] in _RESERVED_ROOTS:
        current: Any = context
    else:
        current = evidence
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def evaluate_evidence(
    rule: EvidenceRule | dict[str, Any] | None,
    evidence: dict[str, Any] | None,
    *,
    now_ns: int,
    subject_id: str,
    audience: str,
) -> bool:
    """Evaluate the closed expression language; malformed input fails closed."""

    if rule is None:
        return True
    try:
        expression = EvidenceRule.from_dict(rule) if isinstance(rule, dict) else rule
        facts = {} if evidence is None else evidence
        if not isinstance(facts, dict):
            return False
        if expression.op == "all":
            return all(
                evaluate_evidence(
                    item,
                    facts,
                    now_ns=now_ns,
                    subject_id=subject_id,
                    audience=audience,
                )
                for item in expression.rules
            )
        if expression.op == "any":
            return any(
                evaluate_evidence(
                    item,
                    facts,
                    now_ns=now_ns,
                    subject_id=subject_id,
                    audience=audience,
                )
                for item in expression.rules
            )
        if expression.op == "not":
            if expression.rule is None:
                return False
            return not evaluate_evidence(
                expression.rule,
                facts,
                now_ns=now_ns,
                subject_id=subject_id,
                audience=audience,
            )
        path = expression.observed_at_path if expression.op == "fresh" else expression.path
        if path is None:
            return False
        exists, actual = _resolve_path(
            path,
            facts,
            now_ns=now_ns,
            subject_id=subject_id,
            audience=audience,
        )
        if expression.op == "exists":
            return exists
        if not exists:
            return False
        if expression.op == "eq":
            return canonical_json(actual) == canonical_json(expression.value)
        if expression.op == "ne":
            return canonical_json(actual) != canonical_json(expression.value)
        if expression.op == "in":
            encoded = canonical_json(actual)
            return any(encoded == canonical_json(candidate) for candidate in expression.values)
        if expression.op == "fresh":
            return (
                isinstance(actual, int)
                and not isinstance(actual, bool)
                and expression.max_age_ns is not None
                and 0 <= now_ns - actual <= expression.max_age_ns
            )
        expected = expression.value
        same_supported_type = (type(actual) is int and type(expected) is int) or (
            type(actual) is str and type(expected) is str
        )
        if not same_supported_type:
            return False
        comparisons = {
            "lt": lambda: actual < expression.value,
            "lte": lambda: actual <= expression.value,
            "gt": lambda: actual > expression.value,
            "gte": lambda: actual >= expression.value,
        }
        callback = comparisons.get(expression.op)
        if callback is None:
            return False
        try:
            return bool(callback())
        except (TypeError, ValueError):
            return False
    except (KeyError, TypeError, ValueError, ValidationError):
        return False


@dataclass(frozen=True, slots=True)
class TransitionSpec:
    name: str
    source: str
    target: str
    cost: ResourceVector
    capability: str
    evidence: EvidenceRule | None = None

    def __post_init__(self) -> None:
        for field_name in ("name", "source", "target", "capability"):
            require_identifier(getattr(self, field_name), field=f"transition {field_name}")
        object.__setattr__(self, "cost", vector(self.cost))
        if not any(self.cost):
            raise ValidationError("transition cost must contain a non-zero dimension")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "source": self.source,
            "target": self.target,
            "cost": list(self.cost),
            "capability": self.capability,
        }
        if self.evidence is not None:
            result["evidence"] = self.evidence.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        unknown = set(data) - {"name", "source", "target", "cost", "capability", "evidence"}
        if unknown:
            raise ValidationError(f"unknown transition fields: {sorted(unknown)}")
        raw_evidence = data.get("evidence")
        return cls(
            name=data["name"],
            source=data["source"],
            target=data["target"],
            cost=vector(data["cost"]),
            capability=data["capability"],
            evidence=(EvidenceRule.from_dict(raw_evidence) if raw_evidence is not None else None),
        )


@dataclass(frozen=True, slots=True)
class MachineSpec:
    machine_id: str
    initial_state: str
    transitions: tuple[TransitionSpec, ...]

    def __post_init__(self) -> None:
        require_identifier(self.machine_id, field="machine_id")
        require_identifier(self.initial_state, field="initial_state")
        if not self.transitions:
            raise ValidationError("machine must define at least one transition")
        if len(self.transitions) > MAX_MACHINE_TRANSITIONS:
            raise ValidationError(
                f"machine transition count exceeds the v1 limit of {MAX_MACHINE_TRANSITIONS}"
            )
        keys: set[tuple[str, str]] = set()
        for item in self.transitions:
            if not isinstance(item, TransitionSpec):
                raise ValidationError("machine transitions must contain transition objects")
            key = (item.source, item.name)
            if key in keys:
                raise ValidationError(f"duplicate machine transition {key!r}")
            keys.add(key)
        if not any(item.source == self.initial_state for item in self.transitions):
            raise ValidationError("machine initial state has no outgoing transition")

    @property
    def digest(self) -> str:
        return canonical_digest(self._semantic_dict())

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "machine_id": self.machine_id,
            "initial_state": self.initial_state,
            "transitions": [item.to_dict() for item in self.transitions],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._semantic_dict(), "machine_digest": self.digest}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        unknown = set(data) - {"machine_id", "initial_state", "transitions", "machine_digest"}
        if unknown:
            raise ValidationError(f"unknown machine fields: {sorted(unknown)}")
        machine = cls(
            machine_id=data["machine_id"],
            initial_state=data["initial_state"],
            transitions=tuple(TransitionSpec.from_dict(item) for item in data["transitions"]),
        )
        supplied = data.get("machine_digest")
        if supplied is not None and supplied != machine.digest:
            raise ValidationError("machine_digest does not match machine content")
        return machine

    def transition(self, state: str, name: str) -> TransitionSpec:
        matches = [item for item in self.transitions if item.source == state and item.name == name]
        if len(matches) != 1:
            raise PolicyError(f"transition {name!r} is not enabled from state {state!r}")
        return matches[0]


@dataclass(frozen=True, slots=True)
class PolicySpec:
    policy_id: str
    policy_version: str
    dimensions: tuple[ResourceDimension, ...]
    machine: MachineSpec
    max_lease_ttl_ns: int
    receipt_ttl_ns: int
    max_clock_uncertainty_ns: int
    transfer_gap_window: int

    def __post_init__(self) -> None:
        require_identifier(self.policy_id, field="policy_id")
        require_identifier(self.policy_version, field="policy_version")
        if not isinstance(self.machine, MachineSpec):
            raise ValidationError("policy machine must be a machine object")
        if not self.dimensions:
            raise ValidationError("policy must define at least one resource dimension")
        if len(self.dimensions) > MAX_POLICY_DIMENSIONS:
            raise ValidationError(
                f"policy resource dimensions exceed the v1 limit of {MAX_POLICY_DIMENSIONS}"
            )
        if any(not isinstance(item, ResourceDimension) for item in self.dimensions):
            raise ValidationError("policy resources must contain resource-dimension objects")
        dimension_ids = [item.id for item in self.dimensions]
        if len(set(dimension_ids)) != len(dimension_ids):
            raise ValidationError("policy resource dimension ids must be unique")
        for transition in self.machine.transitions:
            vector(transition.cost, dimensions=len(self.dimensions))
        for field_name in ("max_lease_ttl_ns", "receipt_ttl_ns", "transfer_gap_window"):
            value = getattr(self, field_name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > MAX_RESOURCE
            ):
                raise ValidationError(f"{field_name} must be a positive integer")
        if self.transfer_gap_window > MAX_TRANSFER_GAP_WINDOW:
            raise ValidationError(
                f"transfer_gap_window exceeds the v1 limit of {MAX_TRANSFER_GAP_WINDOW}"
            )
        value = self.max_clock_uncertainty_ns
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > MAX_RESOURCE
        ):
            raise ValidationError("max_clock_uncertainty_ns must be a non-negative integer")

    @property
    def digest(self) -> str:
        return canonical_digest(self._semantic_dict())

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "resources": [item.to_dict() for item in self.dimensions],
            "machine": self.machine.to_dict(),
            "machine_digest": self.machine.digest,
            "max_lease_ttl_ns": self.max_lease_ttl_ns,
            "receipt_ttl_ns": self.receipt_ttl_ns,
            "max_clock_uncertainty_ns": self.max_clock_uncertainty_ns,
            "transfer_gap_window": self.transfer_gap_window,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._semantic_dict(), "policy_digest": self.digest}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        allowed = {
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
        unknown = set(data) - allowed
        if unknown:
            raise ValidationError(f"unknown policy fields: {sorted(unknown)}")
        policy = cls(
            policy_id=data["policy_id"],
            policy_version=data["policy_version"],
            dimensions=tuple(ResourceDimension.from_dict(item) for item in data["resources"]),
            machine=MachineSpec.from_dict(data["machine"]),
            max_lease_ttl_ns=data["max_lease_ttl_ns"],
            receipt_ttl_ns=data["receipt_ttl_ns"],
            max_clock_uncertainty_ns=data["max_clock_uncertainty_ns"],
            transfer_gap_window=data["transfer_gap_window"],
        )
        supplied_machine = data.get("machine_digest")
        if supplied_machine is not None and supplied_machine != policy.machine.digest:
            raise ValidationError("top-level machine_digest does not match policy machine")
        supplied = data.get("policy_digest")
        if supplied is not None and supplied != policy.digest:
            raise ValidationError("policy_digest does not match policy content")
        return policy
