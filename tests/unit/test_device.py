"""Tests for device.py: spending within a derived share, the edge refusal, freshness and the solo
cap, the clock floor, transfers between two devices, and restore as a new holder.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from lets.canonical import b64url_decode, b64url_encode
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.device import (
    DAY_NS,
    AllowanceRefusedError,
    DeviceConfig,
    DeviceHolder,
    Mode,
    Refusal,
)
from lets.errors import ConflictError, PolicyError, ValidationError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.period import BudgetPolicy, Member, WideningConsent

OWNER = Ed25519Signer.from_seed("owner", bytes(range(32)))
EPOCH = 10 * DAY_NS
PHONE = Ed25519Signer.from_seed("phone", bytes([1] * 32))
LAPTOP = Ed25519Signer.from_seed("laptop", bytes([2] * 32))
NEW_PHONE = Ed25519Signer.from_seed("phone-2", bytes([3] * 32))


def verifier(issuer: str, message: bytes, signature: str) -> bool:
    return issuer == "owner" and OWNER.verify(message, b64url_decode(signature))


def make_policy(**overrides: Any) -> BudgetPolicy:
    base: dict[str, Any] = {
        "policy_id": "mesh-budget",
        "version": 1,
        "issuer": "owner",
        "epoch_ns": EPOCH,
        "period_ns": DAY_NS,
        "dimensions": ("model_tokens", "notes_write", "outside_effect"),
        "totals": (1_000, 100, 10),
        "shares": {"pocket": (400, 20, 4), "desktop": (600, 80, 6)},
        "solo": {"pocket": (100, 5, 0), "desktop": (200, 10, 0)},
        "attested_reduction_permille": 0,
        "unattested_reduction_permille": 500,
    }
    base.update(overrides)
    unsigned = BudgetPolicy(**base)
    return replace(unsigned, sig=b64url_encode(OWNER.sign(unsigned.message())))


MEMBERS = (Member("phone", "pocket", True), Member("laptop", "desktop", True))


def holder(
    tmp_path: Path,
    signer: Ed25519Signer,
    clock: ManualClock,
    registry: PublicKeyRegistry,
    *,
    members: tuple[Member, ...] = MEMBERS,
    policy: BudgetPolicy | None = None,
    name: str | None = None,
    **extra: Any,
) -> DeviceHolder:
    return DeviceHolder(
        directory=tmp_path / (name or signer.warden_id),
        signer=signer,
        registry=registry,
        clock=clock,
        policy=policy or make_policy(),
        policy_verifier=verifier,
        membership_source=lambda _index: members,
        config=DeviceConfig(mesh_id="mesh-1"),
        **extra,
    )


@pytest.fixture
def world(tmp_path: Path) -> tuple[Path, ManualClock, PublicKeyRegistry]:
    return tmp_path, ManualClock(EPOCH + 1_000), PublicKeyRegistry()


def test_a_member_spends_within_its_share_and_receipts_verify(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    laptop = holder(tmp_path, LAPTOP, clock, registry)
    try:
        before = phone.allowance()
        assert before.mode is Mode.SOLO
        assert before.cap == (100, 5, 0)
        receipts = phone.spend("notes_write", 3, audience="executor-a", request_id="req-1")
        assert [item.cost for item in receipts] == [(0, 1, 0)] * 3
        assert [item.resulting_sequence for item in receipts] == [1, 2, 3]
        assert phone.allowance().remaining == (100, 2, 0)
        policy = ExecutorPolicy(audience="executor-a")
        store = SQLiteReceiptReplayStore.initialize(tmp_path / "replay.db", allow_unanchored=True)
        checker = ReceiptVerifier(registry, store, policy, clock=clock)
        for receipt in receipts:
            checker.verify_and_claim(receipt)
        assert laptop.allowance().cap == (200, 10, 0)
    finally:
        phone.close()
        laptop.close()


def test_spending_stops_at_the_edge_with_a_clear_reason(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        phone.spend("notes_write", 5, audience="executor-a", request_id="req-1")
        with pytest.raises(AllowanceRefusedError) as solo:
            phone.spend("notes_write", 1, audience="executor-a", request_id="req-2")
        assert solo.value.reason is Refusal.SOLO_CAP_REACHED
        assert solo.value.remaining == 0
        assert "solo" in str(solo.value)
        with pytest.raises(AllowanceRefusedError) as outside:
            phone.spend("outside_effect", 1, audience="executor-a", request_id="req-3")
        assert outside.value.reason is Refusal.SOLO_CAP_REACHED
        with pytest.raises(AllowanceRefusedError) as unknown:
            phone.spend("teleport", 1, audience="executor-a", request_id="req-4")
        assert unknown.value.reason is Refusal.UNKNOWN_DIMENSION
        for bad in (0, -1, 2_000, True):
            with pytest.raises(AllowanceRefusedError) as invalid:
                phone.spend("notes_write", bad, audience="executor-a", request_id="req-5")
            assert invalid.value.reason is Refusal.INVALID_AMOUNT
    finally:
        phone.close()


def test_freshness_unlocks_the_full_share_and_expires_after_the_window(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        phone.spend("notes_write", 5, audience="executor-a", request_id="req-1")
        phone.record_contact()
        fresh = phone.allowance()
        assert fresh.mode is Mode.FRESH
        assert fresh.remaining == (400, 15, 4)
        phone.spend("notes_write", 15, audience="executor-a", request_id="req-2")
        with pytest.raises(AllowanceRefusedError) as spent:
            phone.spend("notes_write", 1, audience="executor-a", request_id="req-3")
        assert spent.value.reason is Refusal.SHARE_SPENT
        clock.advance(DAY_NS // 2)
        assert phone.allowance().mode is Mode.FRESH
        clock.advance(DAY_NS // 2 - 1_001)
        assert phone.allowance().mode is Mode.FRESH
        clock.advance(2_000)
        assert phone.allowance().mode is Mode.SOLO
    finally:
        phone.close()


def test_a_lone_device_is_always_solo(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    alone = holder(tmp_path, PHONE, clock, registry, members=(MEMBERS[0],))
    try:
        alone.record_contact()
        assert alone.allowance().mode is Mode.SOLO
    finally:
        alone.close()


def test_a_new_period_gives_a_new_share_and_a_forward_clock_only_ends_freshness(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        phone.record_contact()
        phone.spend("notes_write", 20, audience="executor-a", request_id="req-1")
        assert phone.allowance().remaining_for("notes_write") == 0
        clock.advance(2 * DAY_NS)
        later = phone.allowance()
        assert later.period_index == 2
        assert later.mode is Mode.SOLO
        assert later.remaining_for("notes_write") == 5
    finally:
        phone.close()


def test_the_clock_floor_stops_a_set_back_clock_from_earning_a_period(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        clock.advance(DAY_NS)
        phone.record_contact()
        phone.spend("notes_write", 5, audience="executor-a", request_id="req-1")
        assert phone.allowance().period_index == 1
        clock.current_ns = EPOCH + 1_000
        held = phone.allowance()
        assert held.period_index == 1
        assert held.clock_regressed
        assert held.remaining_for("notes_write") == 15
        with pytest.raises(AllowanceRefusedError):
            phone.spend("notes_write", 16, audience="executor-a", request_id="req-2")
    finally:
        phone.close()
    reopened = holder(tmp_path, PHONE, clock, registry)
    try:
        assert reopened.allowance().period_index == 1
    finally:
        reopened.close()


def test_state_survives_a_restart_with_the_same_spent_total(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    phone.record_contact()
    phone.spend("notes_write", 7, audience="executor-a", request_id="req-1")
    phone.close()
    again = holder(tmp_path, PHONE, clock, registry)
    try:
        allowance = again.allowance()
        assert allowance.mode is Mode.FRESH
        assert allowance.consumed == (0, 7, 0)
        again.spend("notes_write", 1, audience="executor-a", request_id="req-2")
        assert again.allowance().consumed == (0, 8, 0)
    finally:
        again.close()


def test_a_device_outside_the_period_membership_gets_no_share(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    stranger = holder(tmp_path, NEW_PHONE, clock, registry)
    try:
        assert stranger.allowance().remaining == (0, 0, 0)
        with pytest.raises(AllowanceRefusedError) as refused:
            stranger.spend("notes_write", 1, audience="executor-a", request_id="req-1")
        assert refused.value.reason is Refusal.NOT_A_MEMBER
        with pytest.raises(AllowanceRefusedError):
            stranger.offer_headroom("phone", {"notes_write": 1}, request_id="t-1")
    finally:
        stranger.close()
    reopened = holder(tmp_path, NEW_PHONE, clock, registry)
    try:
        assert reopened.allowance().remaining == (0, 0, 0)
    finally:
        reopened.close()


def test_a_transfer_between_two_devices_restores_headroom(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    laptop = holder(tmp_path, LAPTOP, clock, registry)
    try:
        phone.record_contact()
        phone.spend("notes_write", 20, audience="executor-a", request_id="req-1")
        with pytest.raises(AllowanceRefusedError):
            phone.spend("notes_write", 1, audience="executor-a", request_id="req-2")
        laptop.record_contact()
        voucher = laptop.offer_headroom("phone", {"notes_write": 30}, request_id="give-1")
        assert laptop.allowance().remaining_for("notes_write") == 50
        ack = phone.accept_headroom(voucher)
        laptop.settle_headroom(ack)
        assert phone.allowance().remaining_for("notes_write") == 30
        receipts = phone.spend("notes_write", 30, audience="executor-a", request_id="req-3")
        assert len(receipts) == 30
        with pytest.raises(AllowanceRefusedError):
            phone.spend("notes_write", 1, audience="executor-a", request_id="req-4")
        laptop.spend("notes_write", 50, audience="executor-a", request_id="req-5")
        with pytest.raises(AllowanceRefusedError):
            laptop.spend("notes_write", 1, audience="executor-a", request_id="req-6")
        total = phone.allowance().cap[1] + laptop.allowance().cap[1]
        assert total == 100
    finally:
        phone.close()
        laptop.close()


def test_a_transfer_can_not_give_away_more_than_is_left(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    laptop = holder(tmp_path, LAPTOP, clock, registry)
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        laptop.record_contact()
        with pytest.raises(AllowanceRefusedError) as too_much:
            laptop.offer_headroom("phone", {"notes_write": 81}, request_id="give-1")
        assert too_much.value.reason is Refusal.SHARE_SPENT
        with pytest.raises(AllowanceRefusedError) as unknown:
            laptop.offer_headroom("phone", {"nope": 1}, request_id="give-2")
        assert unknown.value.reason is Refusal.UNKNOWN_DIMENSION
        with pytest.raises(AllowanceRefusedError) as empty:
            laptop.offer_headroom("phone", {"notes_write": 0}, request_id="give-3")
        assert empty.value.reason is Refusal.INVALID_AMOUNT
        with pytest.raises(ValidationError, match="must differ"):
            laptop.offer_headroom("laptop", {"notes_write": 1}, request_id="give-4")
        assert laptop.allowance().remaining_for("notes_write") == 80
        laptop.spend("notes_write", 80, audience="executor-a", request_id="req-1")
    finally:
        laptop.close()
        phone.close()


def test_a_restored_device_is_a_new_holder_and_the_old_share_lapses(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    both = (*MEMBERS, Member("phone-2", "pocket", True))
    old = holder(tmp_path, PHONE, clock, registry, members=both)
    old.record_contact()
    old.spend("notes_write", 5, audience="executor-a", request_id="req-1")
    backup = old.export_backup()
    assert "consumed" not in backup
    floor = DeviceHolder.seed_from_backup(backup, new_signer=NEW_PHONE)
    with pytest.raises(ValidationError, match="new member id"):
        DeviceHolder.seed_from_backup(backup, new_signer=PHONE)
    with pytest.raises(ValidationError, match="floor"):
        DeviceHolder.seed_from_backup({"member_id": "x", "clock_floor_ns": -1}, new_signer=PHONE)
    restored = holder(tmp_path, NEW_PHONE, clock, registry, members=both, seed_clock_floor_ns=floor)
    try:
        fresh_start = restored.allowance()
        assert fresh_start.mode is Mode.SOLO
        assert fresh_start.consumed == (0, 0, 0)
        restored.spend("notes_write", 1, audience="executor-a", request_id="req-1")
        old.retire()
        old.spend("notes_write", 1, audience="executor-a", request_id="req-2")
        assert old.allowance().retired
        clock.advance(DAY_NS)
        with pytest.raises(AllowanceRefusedError) as lapsed:
            old.spend("notes_write", 1, audience="executor-a", request_id="req-3")
        assert lapsed.value.reason is Refusal.LAPSED
        assert restored.allowance().period_index == 1
    finally:
        old.close()
        restored.close()


def test_narrowing_applies_at_once_and_widening_waits_for_consent_and_the_next_period(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        phone.record_contact()
        phone.spend("notes_write", 4, audience="executor-a", request_id="req-1")
        narrower = make_policy(
            version=2,
            totals=(1_000, 100, 10),
            shares={"pocket": (400, 10, 4), "desktop": (600, 80, 6)},
        )
        phone.set_policy(narrower)
        assert phone.allowance().remaining_for("notes_write") == 6
        wider = make_policy(version=3, shares={"pocket": (400, 40, 4), "desktop": (600, 60, 6)})
        with pytest.raises(PolicyError):
            phone.set_policy(wider)
        phone.set_policy(wider, consent=WideningConsent(wider.digest, "owner", "bio-1"))
        assert phone.allowance().remaining_for("notes_write") == 6
        clock.advance(DAY_NS)
        assert phone.allowance().cap[1] == 40
        assert phone.set_policy(wider) is not None
    finally:
        phone.close()


def test_a_restart_keeps_the_narrowed_policy_for_the_period(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    phone.record_contact()
    phone.spend("notes_write", 2, audience="executor-a", request_id="req-1")
    phone.set_policy(
        make_policy(version=2, shares={"pocket": (400, 10, 4), "desktop": (600, 80, 6)})
    )
    phone.close()
    again = holder(
        tmp_path,
        PHONE,
        clock,
        registry,
        policy=make_policy(version=2, shares={"pocket": (400, 10, 4), "desktop": (600, 80, 6)}),
    )
    try:
        assert again.allowance().remaining_for("notes_write") == 8
    finally:
        again.close()


def test_construction_rejects_bad_inputs(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    forged = replace(make_policy(), sig=b64url_encode(bytes(64)))
    with pytest.raises(PolicyError):
        holder(tmp_path, PHONE, clock, registry, policy=forged)
    for field in ("freshness_window_ns", "receipt_ttl_ns", "transfer_gap_window"):
        with pytest.raises(ValidationError):
            DeviceConfig(mesh_id="mesh-1", **{field: 0})
    with pytest.raises(ValidationError):
        DeviceConfig(mesh_id="mesh-1", max_clock_uncertainty_ns=-1)
    (tmp_path / "phone").mkdir()
    (tmp_path / "phone" / "device.json").write_text("{", encoding="utf-8")
    with pytest.raises(ValidationError, match="unreadable"):
        holder(tmp_path, PHONE, clock, registry)
    (tmp_path / "phone" / "device.json").write_text('{"member_id": "other"}', encoding="utf-8")
    with pytest.raises(ValidationError, match="another member"):
        holder(tmp_path, PHONE, clock, registry)


def test_before_the_policy_epoch_nothing_is_spendable(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    clock.current_ns = 5
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        with pytest.raises(PolicyError, match="before the policy epoch"):
            phone.spend("notes_write", 1, audience="executor-a", request_id="req-1")
    finally:
        phone.close()


def test_a_restart_adopts_a_narrower_policy_for_the_saved_period(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    phone.record_contact()
    phone.spend("notes_write", 2, audience="executor-a", request_id="req-1")
    phone.close()
    narrower = make_policy(version=2, shares={"pocket": (400, 10, 4), "desktop": (600, 80, 6)})
    again = holder(tmp_path, PHONE, clock, registry, policy=narrower)
    try:
        assert again.allowance().remaining_for("notes_write") == 8
    finally:
        again.close()


def test_an_interrupted_lease_issue_is_finished_on_the_next_open(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path, clock, registry = world
    crashed = holder(tmp_path, PHONE, clock, registry)

    def crash(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("power lost")

    with monkeypatch.context() as patch:
        patch.setattr(DeviceHolder, "_issue", crash)
        with pytest.raises(RuntimeError):
            crashed.allowance()
    crashed.close()
    recovered = holder(tmp_path, PHONE, clock, registry)
    try:
        assert recovered.allowance().remaining_for("notes_write") == 5
        recovered.spend("notes_write", 5, audience="executor-a", request_id="req-1")
    finally:
        recovered.close()


def test_a_failed_state_write_leaves_no_temporary_file(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        with monkeypatch.context() as patch:
            patch.setattr("lets.device.os.replace", _raise_os_error)
            with pytest.raises(OSError):
                phone.record_contact()
        assert not list((tmp_path / "phone").glob(".device.*"))
    finally:
        phone.close()


def _raise_os_error(*_args: Any) -> None:
    raise OSError("disk full")


def test_a_closed_lease_cannot_be_spent_from(
    world: tuple[Path, ManualClock, PublicKeyRegistry],
) -> None:
    tmp_path, clock, registry = world
    phone = holder(tmp_path, PHONE, clock, registry)
    try:
        phone.allowance()
        period = phone._period
        assert period is not None and period.service is not None and period.leases
        period.service.close(
            request_id="close-1", identity=phone._identity, lease_id=period.leases[0]
        )
        with pytest.raises(ConflictError, match="no live lease"):
            phone.spend("notes_write", 1, audience="executor-a", request_id="req-1")
    finally:
        phone.close()
