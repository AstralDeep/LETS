from __future__ import annotations

from pathlib import Path

import pytest

import lets.crypto as crypto_module
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ConflictError, SignatureError, ValidationError


def test_signer_round_trip_and_mapping_verification() -> None:
    signer = Ed25519Signer.generate("warden-a")
    payload = b"authoritative bytes"
    signature = signer.sign(payload)

    assert signer.verify(payload, signature)
    assert not signer.verify(payload + b"!", signature)
    mapping_signature = signer.sign_mapping({"b": 2, "a": 1})
    signer.verify_mapping({"a": 1, "b": 2}, mapping_signature)
    with pytest.raises(SignatureError):
        signer.verify_mapping({"a": 2}, mapping_signature)


@pytest.mark.parametrize("warden_id", ["site/a", "site%2Fa", "wårdën", "-warden"])
def test_warden_identifiers_are_safe_in_paths_and_http_headers(warden_id: str) -> None:
    with pytest.raises(ValidationError, match="ASCII URI-unreserved"):
        Ed25519Signer.generate(warden_id)


def test_seed_recreates_stable_identity() -> None:
    signer = Ed25519Signer.generate("warden-a")
    restored = Ed25519Signer.from_seed("warden-a", signer.seed_bytes)

    assert restored.key_id == signer.key_id
    assert restored.public_key_bytes == signer.public_key_bytes
    with pytest.raises(ValidationError):
        Ed25519Signer.from_seed("warden-a", b"short")


def test_seed_file_is_atomic_and_refuses_unplanned_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "warden.seed"
    signer = Ed25519Signer.generate("warden-a")
    signer.save_seed_file(path)

    assert Ed25519Signer.load_seed_file("warden-a", path).key_id == signer.key_id
    with pytest.raises(ConflictError):
        signer.save_seed_file(path)


def test_seed_file_no_clobber_is_race_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "raced.seed"
    signer = Ed25519Signer.generate("warden-a")
    original_link = crypto_module.os.link

    def racer(source: str, destination: Path) -> None:
        Path(destination).write_bytes(b"competitor")
        original_link(source, destination)

    monkeypatch.setattr(crypto_module.os, "link", racer)
    with pytest.raises(ConflictError):
        signer.save_seed_file(path)
    assert path.read_bytes() == b"competitor"
    assert list(tmp_path.glob(".raced.seed.*.tmp")) == []


def test_public_key_registry_detects_conflict_and_verifies_peer() -> None:
    first = Ed25519Signer.generate("warden-a")
    second = Ed25519Signer.generate("warden-a")
    registry = PublicKeyRegistry()
    registry.register_signer(first)
    payload = b"voucher"

    assert registry.verify(first.warden_id, first.key_id, payload, first.sign(payload))
    assert not registry.verify("unknown", first.key_id, payload, first.sign(payload))
    with pytest.raises(ConflictError):
        registry.register(first.warden_id, first.key_id, second.public_key_bytes)
    with pytest.raises(SignatureError):
        registry.public_key("unknown", "key")
    with pytest.raises(SignatureError, match="no currently valid trusted key"):
        registry.require_current_warden("unknown")
    registry.require_current_warden(first.warden_id)


def test_public_key_registry_rejects_material_reuse_across_identities() -> None:
    seed = Ed25519Signer.generate("seed-owner").seed_bytes
    first = Ed25519Signer.from_seed("warden-a", seed)
    alias = Ed25519Signer.from_seed("warden-b", seed)
    registry = PublicKeyRegistry()
    registry.register_signer(first)

    with pytest.raises(ConflictError, match="already bound to trusted identity"):
        registry.register_signer(alias)


def test_public_key_registry_requires_full_clock_interval_inside_key_validity() -> None:
    signer = Ed25519Signer.generate("warden-a")
    clock = ManualClock(100, 5)
    registry = PublicKeyRegistry(clock=clock)
    registry.register(
        signer.warden_id,
        signer.key_id,
        signer.public_key_bytes,
        not_before_ns=95,
        not_after_ns=106,
    )

    assert registry.key_validity(signer.warden_id, signer.key_id) == (95, 106)
    registry.require_current(signer.warden_id, signer.key_id)
    payload = b"bounded-key"
    assert registry.verify(signer.warden_id, signer.key_id, payload, signer.sign(payload))

    clock.current_ns = 101
    with pytest.raises(SignatureError, match="outside its validity interval"):
        registry.require_current(signer.warden_id, signer.key_id)
    assert not registry.verify(signer.warden_id, signer.key_id, payload, signer.sign(payload))

    clock.current_ns = 99
    clock.declared_uncertainty_ns = 5
    registry_with_later_start = PublicKeyRegistry(clock=clock)
    registry_with_later_start.register(
        signer.warden_id,
        signer.key_id,
        signer.public_key_bytes,
        not_before_ns=95,
    )
    with pytest.raises(SignatureError, match="outside its validity interval"):
        registry_with_later_start.require_current(signer.warden_id, signer.key_id)
