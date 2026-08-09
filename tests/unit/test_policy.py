from __future__ import annotations

from dataclasses import replace

import pytest

from lets.errors import PolicyError, ValidationError
from lets.policy import (
    MAX_TRANSFER_GAP_WINDOW,
    EvidenceRule,
    MachineSpec,
    PolicySpec,
    ResourceDimension,
    TransitionSpec,
    evaluate_evidence,
)


def policy(rule: EvidenceRule | None = None) -> PolicySpec:
    machine = MachineSpec(
        machine_id="generic-worker",
        initial_state="READY",
        transitions=(
            TransitionSpec(
                name="execute",
                source="READY",
                target="DONE",
                cost=(1, 2),
                capability="work.execute",
                evidence=rule,
            ),
        ),
    )
    return PolicySpec(
        policy_id="generic",
        policy_version="v1",
        dimensions=(
            ResourceDimension("actions", "action"),
            ResourceDimension("egress", "byte"),
        ),
        machine=machine,
        max_lease_ttl_ns=60_000_000_000,
        receipt_ttl_ns=1_000_000_000,
        max_clock_uncertainty_ns=10_000_000,
        transfer_gap_window=64,
    )


def test_policy_round_trip_and_content_digests() -> None:
    original = policy(EvidenceRule(op="eq", path="verified", value=True))

    assert PolicySpec.from_dict(original.to_dict()) == original
    assert original.to_dict()["policy_digest"] == original.digest
    assert original.machine.to_dict()["machine_digest"] == original.machine.digest
    assert original.machine.transition("READY", "execute").target == "DONE"
    with pytest.raises(PolicyError):
        original.machine.transition("DONE", "execute")


def test_evidence_semantics_are_part_of_machine_and_policy_digest() -> None:
    allows = policy(EvidenceRule(op="eq", path="verified", value=True))
    denies = policy(EvidenceRule(op="eq", path="verified", value=False))

    assert allows.machine.digest != denies.machine.digest
    assert allows.digest != denies.digest


def test_policy_rejects_dimension_and_transition_ambiguity() -> None:
    original = policy()
    with pytest.raises(ValidationError, match="dimension"):
        replace(original, dimensions=(ResourceDimension("actions", "action"),))

    duplicate = original.machine.transitions[0]
    with pytest.raises(ValidationError, match="duplicate"):
        replace(original.machine, transitions=(duplicate, duplicate))


def test_policy_enforces_the_published_transfer_gap_window_bound() -> None:
    assert replace(policy(), transfer_gap_window=MAX_TRANSFER_GAP_WINDOW).transfer_gap_window == (
        MAX_TRANSFER_GAP_WINDOW
    )
    with pytest.raises(ValidationError, match="transfer_gap_window exceeds"):
        replace(policy(), transfer_gap_window=MAX_TRANSFER_GAP_WINDOW + 1)


def test_declarative_evidence_evaluation_is_fail_closed() -> None:
    rule = EvidenceRule.from_dict(
        {
            "op": "all",
            "rules": [
                {"op": "eq", "path": "verified", "value": True},
                {"op": "eq", "path": "subject", "value": "agent-a"},
                {"op": "eq", "path": "audience", "value": "executor-a"},
                {"op": "in", "path": "classification", "values": ["safe", "reviewed"]},
                {"op": "fresh", "observed_at_path": "observed_at_ns", "max_age_ns": 10},
            ],
        }
    )
    evidence = {"verified": True, "classification": "safe", "observed_at_ns": 95}

    assert evaluate_evidence(
        rule,
        evidence,
        now_ns=100,
        subject_id="agent-a",
        audience="executor-a",
    )
    assert not evaluate_evidence(
        rule,
        evidence,
        now_ns=200,
        subject_id="agent-a",
        audience="executor-a",
    )
    assert not evaluate_evidence(
        {"op": "unknown"},
        evidence,
        now_ns=100,
        subject_id="agent-a",
        audience="executor-a",
    )


def test_boolean_and_comparison_evidence_rules() -> None:
    rule = EvidenceRule.from_dict(
        {
            "op": "any",
            "rules": [
                {"op": "gt", "path": "score", "value": 9},
                {"op": "not", "rule": {"op": "exists", "path": "blocked"}},
            ],
        }
    )
    assert evaluate_evidence(
        rule,
        {"score": 1},
        now_ns=1,
        subject_id="agent-a",
        audience="executor-a",
    )
