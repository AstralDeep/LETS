"""Runs period derivation, policy adoption and the device holder against the period and device
vectors, with an independent re-statement of the share arithmetic.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from lets.canonical import b64url_decode
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.device import AllowanceRefusedError, DeviceConfig, DeviceHolder
from lets.errors import ConflictError, PolicyError, SignatureError, ValidationError
from lets.period import (
    BudgetPolicy,
    Member,
    WideningConsent,
    adopt_policy,
    classify_change,
    derive_budget,
    period_index,
)

VECTORS = Path(__file__).resolve().parents[2] / "protocol" / "vectors"


def _load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


PERIOD = _load("period.json")
DEVICE = _load("device.json")


def _verifier(document: dict[str, Any]) -> Any:
    key = document["verifier"]["key"]
    signer_key = b64url_decode(key["public_key"])
    registry = PublicKeyRegistry()
    registry.register(key["warden_id"], key["key_id"], signer_key)

    def verify(issuer: str, message: bytes, signature: str) -> bool:
        if issuer != key["warden_id"]:
            return False
        return registry.verify(key["warden_id"], key["key_id"], message, b64url_decode(signature))

    return verify


VERIFY = _verifier(PERIOD)


def _reason(error: Exception) -> str:
    text = str(error)
    if isinstance(error, SignatureError):
        return "signature"
    if isinstance(error, ConflictError):
        return "policy_id"
    if isinstance(error, AllowanceRefusedError):
        return error.reason.value
    if isinstance(error, ValidationError):
        for marker, reason in (
            ("new member id", "new_member_id_required"),
            ("64-bit", "bounds"),
            ("member", "membership"),
        ):
            if marker in text:
                return reason
    if isinstance(error, PolicyError):
        for marker, reason in (
            ("before the policy epoch", "before_epoch"),
            ("no share", "no_share"),
            ("not newer", "stale_version"),
            ("needs consent", "consent_required"),
        ):
            if marker in text:
                return reason
    raise error


def _members(items: list[dict[str, Any]]) -> list[Member]:
    return [Member(**item) for item in items]


def _independent_budget(
    policy: dict[str, Any], members: list[dict[str, Any]], index: int
) -> dict[str, dict[str, list[int]]]:
    dimensions = sorted(policy["totals"])
    reductions = policy["reduction_permille"]
    scaled: dict[str, tuple[list[int], list[int]]] = {}
    for item in members:
        cut = reductions["attested" if item["attested"] else "unattested"]
        shares = [policy["shares"][item["kind"]][d] * (1000 - cut) // 1000 for d in dimensions]
        solos = [policy["solo"][item["kind"]][d] * (1000 - cut) // 1000 for d in dimensions]
        scaled[item["member_id"]] = (shares, solos)
    demand = [sum(entry[0][i] for entry in scaled.values()) for i in range(len(dimensions))]
    result: dict[str, dict[str, list[int]]] = {}
    for member_id, (shares, solos) in scaled.items():
        fresh = [
            share
            if demand[i] <= policy["totals"][dimensions[i]]
            else share * policy["totals"][dimensions[i]] // demand[i]
            for i, share in enumerate(shares)
        ]
        result[member_id] = {
            "fresh": fresh,
            "solo": [min(s, f) for s, f in zip(solos, fresh, strict=True)],
        }
    return result


@pytest.mark.parametrize("case", PERIOD["derive"], ids=lambda case: case["name"])
def test_derivation_vectors(case: dict[str, Any]) -> None:
    policy = BudgetPolicy.from_dict(case["policy"])
    policy.verify(VERIFY)
    expect = case["expect"]
    if "refuse" in expect:
        with pytest.raises((ValidationError, PolicyError)) as caught:
            derive_budget(policy, _members(case["members"]), case["period_index"])
        assert _reason(caught.value) == expect["refuse"]
        return
    budget = derive_budget(policy, _members(case["members"]), case["period_index"])
    assert budget.to_dict() == expect["budget"]
    assert budget.digest == expect["digest"]
    independent = _independent_budget(case["policy"], case["members"], case["period_index"])
    dimensions = list(budget.dimensions)
    for share in budget.shares:
        assert list(share.fresh) == independent[share.member_id]["fresh"]
        assert list(share.solo) == independent[share.member_id]["solo"]
    for i, dimension in enumerate(dimensions):
        assert sum(item.fresh[i] for item in budget.shares) <= case["policy"]["totals"][dimension]


@pytest.mark.parametrize("case", PERIOD["period_index"], ids=lambda case: case["name"])
def test_period_index_vectors(case: dict[str, Any]) -> None:
    policy = BudgetPolicy.from_dict(case["policy"])
    if "refuse" in case["expect"]:
        with pytest.raises(PolicyError) as caught:
            period_index(policy, case["now_ns"])
        assert _reason(caught.value) == case["expect"]["refuse"]
    else:
        assert period_index(policy, case["now_ns"]) == case["expect"]["index"]


@pytest.mark.parametrize("case", PERIOD["classify"], ids=lambda case: case["name"])
def test_classification_vectors(case: dict[str, Any]) -> None:
    current = BudgetPolicy.from_dict(case["current"])
    candidate = BudgetPolicy.from_dict(case["candidate"])
    assert classify_change(current, candidate).value == case["expect"]


@pytest.mark.parametrize("case", PERIOD["adopt"], ids=lambda case: case["name"])
def test_adoption_vectors(case: dict[str, Any]) -> None:
    current = None if case["current"] is None else BudgetPolicy.from_dict(case["current"])
    candidate = BudgetPolicy.from_dict(case["candidate"])
    consent = None if case["consent"] is None else WideningConsent(**case["consent"])
    expect = case["expect"]
    if expect in {"adopted", "unchanged"}:
        result = adopt_policy(current, candidate, verifier=VERIFY, consent=consent)
        assert result is (candidate if expect == "adopted" else current)
        return
    with pytest.raises((SignatureError, PolicyError, ConflictError)) as caught:
        adopt_policy(current, candidate, verifier=VERIFY, consent=consent)
    assert _reason(caught.value) == expect


class _Scenario:
    def __init__(self, scenario: dict[str, Any], directory: Path) -> None:
        self.data = scenario
        self.directory = directory
        self.registry = PublicKeyRegistry()
        self.holders: dict[str, DeviceHolder] = {}
        self.clocks: dict[str, ManualClock] = {}
        self.counter = 0
        defaults = DEVICE["config_defaults"]
        self.config = DeviceConfig(mesh_id="mesh-vectors", **{**defaults, **scenario["config"]})
        self.members = _members(scenario["members"])
        self.policy = BudgetPolicy.from_dict(scenario["policy"])

    @staticmethod
    def signer(name: str) -> Ed25519Signer:
        seed = sha256(f"lets-vectors/device/{name}".encode()).digest()
        return Ed25519Signer.from_seed(name, seed)

    def request_id(self) -> str:
        self.counter += 1
        return f"request-{self.counter}"

    def run(self) -> None:
        try:
            for step in self.data["steps"]:
                self.step(step)
        finally:
            for holder in self.holders.values():
                holder.close()

    def outcome(self, step: dict[str, Any], action: Any) -> None:
        expect = step.get("expect", "ok")
        if expect == "ok":
            action()
            return
        with pytest.raises((PolicyError, ValidationError)) as caught:
            action()
        assert _reason(caught.value) == expect

    def step(self, step: dict[str, Any]) -> None:
        op = step["op"]
        if op == "start":
            self.outcome(step, lambda: self.start(step))
        elif op == "contact":
            self.holders[step["device"]].record_contact()
        elif op == "clock":
            clock = self.clocks[step["device"]]
            if "set_ns" in step:
                clock.current_ns = step["set_ns"]
            else:
                clock.advance(step["advance_ns"])
        elif op == "spend":
            self.outcome(
                step,
                lambda: self.holders[step["device"]].spend(
                    step["dimension"],
                    step["units"],
                    audience="executor-vectors",
                    request_id=self.request_id(),
                ),
            )
        elif op == "transfer":
            self.outcome(step, lambda: self.transfer(step))
        elif op == "set_policy":
            candidate = BudgetPolicy.from_dict(step["policy"])
            consent = None if step["consent"] is None else WideningConsent(**step["consent"])
            self.outcome(
                step, lambda: self.holders[step["device"]].set_policy(candidate, consent=consent)
            )
        elif op == "retire":
            self.holders[step["device"]].retire()
        elif op == "allowance":
            self.check_allowance(step)
        else:
            raise AssertionError(f"unknown op {op}")

    def start(self, step: dict[str, Any]) -> None:
        name = step["device"]
        signer = self.signer(name)
        floor = 0
        if "seed_floor_from" in step:
            backup = self.holders[step["seed_floor_from"]].export_backup()
            floor = DeviceHolder.seed_from_backup(backup, new_signer=signer)
        clock = ManualClock(self.data["clock_start_ns"])
        self.clocks[name] = clock
        self.holders[name] = DeviceHolder(
            directory=self.directory / name,
            signer=signer,
            registry=self.registry,
            clock=clock,
            policy=self.policy,
            policy_verifier=VERIFY,
            membership_source=lambda _index: self.members,
            config=self.config,
            seed_clock_floor_ns=floor,
        )

    def transfer(self, step: dict[str, Any]) -> None:
        source = self.holders[step["from"]]
        target = self.holders[step["to"]]
        voucher = source.offer_headroom(step["to"], step["amounts"], request_id=self.request_id())
        ack = target.accept_headroom(voucher)
        source.settle_headroom(ack)

    def check_allowance(self, step: dict[str, Any]) -> None:
        allowance = self.holders[step["device"]].allowance()
        named = {
            "cap": allowance.cap,
            "consumed": allowance.consumed,
            "remaining": allowance.remaining,
        }
        for key, value in step["expect"].items():
            if key == "period_index":
                assert allowance.period_index == value
            elif key == "mode":
                assert allowance.mode.value == value
            elif key == "clock_regressed":
                assert allowance.clock_regressed is value
            elif key == "retired":
                assert allowance.retired is value
            else:
                assert dict(zip(allowance.dimensions, named[key], strict=True)) == value, key


@pytest.mark.parametrize("scenario", DEVICE["scenarios"], ids=lambda item: item["name"])
def test_device_scenarios(scenario: dict[str, Any], tmp_path: Path) -> None:
    _Scenario(scenario, tmp_path).run()
