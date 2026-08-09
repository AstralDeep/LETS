from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

import lets.runtime as runtime_module
from lets.audit import AuditExportRecord
from lets.auth import AuthenticationError
from lets.authority import AuthorityCheckpoint
from lets.cli import _backup, _info, _key, _metrics_provider
from lets.crypto import Ed25519Signer
from lets.errors import SignatureError, ValidationError
from lets.models import IdentityContext
from lets.runtime import (
    RUNTIME_PROVIDER_GROUP,
    RuntimeBindings,
    RuntimeProviderContext,
    open_runtime_provider,
    validate_runtime_options,
)
from lets.service import WardenService
from lets.storage import SQLiteStorage


class Authenticator:
    def __init__(self, identity: object) -> None:
        self.identity = identity

    def authenticate(self, _request: object) -> object:
        return self.identity


class AuthorityAnchor:
    def reconcile(
        self,
        _checkpoint: AuthorityCheckpoint,
        *,
        audit_hash_at: Callable[[int], bytes | None],
        initialize: bool = False,
        allow_schema_upgrade: bool = False,
    ) -> None:
        del audit_hash_at, initialize, allow_schema_upgrade


class AuditSink:
    def publish(self, _record: AuditExportRecord) -> None:
        return None


@dataclass
class FakeEntryPoint:
    name: str
    factory: object
    group: str = RUNTIME_PROVIDER_GROUP
    loads: int = 0

    def load(self) -> object:
        self.loads += 1
        return self.factory


def _context(*, production: bool = False) -> RuntimeProviderContext:
    return RuntimeProviderContext(
        config_path=Path("config.json"),
        warden_id="warden-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        manifest_digest="sha256:" + "1" * 64,
        options={"issuer": "https://issuer.example"},
        production=production,
    )


def _identity(*, tenant_id: str = "tenant-a") -> IdentityContext:
    return IdentityContext(
        subject_id="operator",
        tenant_id=tenant_id,
        scopes=frozenset({"lets.admin"}),
        authentication_method="test-provider",
    )


def _bindings(
    *,
    signer: object | None = None,
    authenticator: object | None = None,
    production_capable: bool = True,
    authority_anchor: object | None = None,
    audit_sink: object | None = None,
    cleanup: Callable[[], object] | None = None,
    warden_id: str = "warden-a",
    tenant_id: str = "tenant-a",
) -> RuntimeBindings:
    return RuntimeBindings(
        warden_id=warden_id,
        tenant_id=tenant_id,
        signer=Ed25519Signer.generate("warden-a") if signer is None else signer,
        authenticator=Authenticator(_identity()) if authenticator is None else authenticator,
        production_capable=production_capable,
        authority_anchor=authority_anchor,  # type: ignore[arg-type]
        audit_sink=audit_sink,  # type: ignore[arg-type]
        cleanup=cleanup,
    )


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *entry_points: FakeEntryPoint,
) -> None:
    monkeypatch.setattr(
        runtime_module.metadata,
        "entry_points",
        lambda **_kwargs: entry_points,
    )


def test_loader_imports_only_selected_entry_point_and_cleans_up_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanups: list[str] = []
    selected = FakeEntryPoint(
        "managed",
        lambda _context: _bindings(cleanup=lambda: cleanups.append("closed")),
    )
    unselected = FakeEntryPoint(
        "unselected",
        lambda _context: pytest.fail("unselected provider was initialized"),
    )
    _install(monkeypatch, unselected, selected)

    session = open_runtime_provider("managed", _context())
    assert selected.loads == 1
    assert unselected.loads == 0
    assert session.provider_name == "managed"
    session.close()
    session.close()
    assert cleanups == ["closed"]


def test_duplicate_selected_entry_points_fail_before_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = FakeEntryPoint("managed", lambda _context: _bindings())
    second = FakeEntryPoint("managed", lambda _context: _bindings())
    _install(monkeypatch, first, second)

    with pytest.raises(ValidationError, match="duplicate installed entry points"):
        open_runtime_provider("managed", _context())
    assert first.loads == second.loads == 0


def test_provider_must_return_the_exact_supported_bindings_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, FakeEntryPoint("managed", lambda _context: object()))

    with pytest.raises(ValidationError, match="must return RuntimeBindings"):
        open_runtime_provider("managed", _context())


def test_production_rejects_builtin_before_it_can_open_seed_material() -> None:
    calls: list[str] = []

    def builtin(_context: RuntimeProviderContext) -> RuntimeBindings:
        calls.append("opened")
        return _bindings()

    with pytest.raises(ValidationError, match="forbidden in production"):
        open_runtime_provider(
            "builtin",
            _context(production=True),
            builtin_factory=builtin,
        )
    assert calls == []


@pytest.mark.parametrize(
    "bindings_factory",
    [
        lambda cleanup: _bindings(warden_id="warden-b", cleanup=cleanup),
        lambda cleanup: _bindings(tenant_id="tenant-b", cleanup=cleanup),
        lambda cleanup: _bindings(signer=Ed25519Signer.generate("warden-b"), cleanup=cleanup),
        lambda cleanup: _bindings(authenticator=object(), cleanup=cleanup),
        lambda cleanup: _bindings(authority_anchor=object(), cleanup=cleanup),
        lambda cleanup: _bindings(audit_sink=object(), cleanup=cleanup),
    ],
)
def test_invalid_provider_types_and_identities_fail_closed_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    bindings_factory: Callable[[Callable[[], object]], RuntimeBindings],
) -> None:
    cleanups: list[str] = []

    def cleanup() -> None:
        cleanups.append("closed")

    _install(
        monkeypatch,
        FakeEntryPoint("managed", lambda _context: bindings_factory(cleanup)),
    )

    with pytest.raises(ValidationError):
        open_runtime_provider("managed", _context())
    assert cleanups == ["closed"]


def test_signer_must_prove_possession_of_advertised_ed25519_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual = Ed25519Signer.generate("warden-a")

    class InvalidSigner:
        warden_id = actual.warden_id
        key_id = actual.key_id
        public_key_bytes = actual.public_key_bytes

        def sign(self, _payload: bytes) -> bytes:
            return bytes(64)

    cleanups: list[str] = []
    _install(
        monkeypatch,
        FakeEntryPoint(
            "managed",
            lambda _context: _bindings(
                signer=InvalidSigner(), cleanup=lambda: cleanups.append("closed")
            ),
        ),
    )

    with pytest.raises(SignatureError, match="proof does not match"):
        open_runtime_provider("managed", _context())
    assert cleanups == ["closed"]


def test_production_requires_explicit_provider_capability_and_bounds_identity_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanups: list[str] = []
    _install(
        monkeypatch,
        FakeEntryPoint(
            "managed",
            lambda _context: _bindings(
                production_capable=False,
                cleanup=lambda: cleanups.append("closed"),
            ),
        ),
    )
    with pytest.raises(ValidationError, match="did not declare production capability"):
        open_runtime_provider("managed", _context(production=True))
    assert cleanups == ["closed"]

    _install(
        monkeypatch,
        FakeEntryPoint(
            "managed",
            lambda _context: _bindings(
                production_capable=True,
                cleanup=lambda: cleanups.append("missing-anchor-closed"),
            ),
        ),
    )
    with pytest.raises(ValidationError, match="independent authority anchor"):
        open_runtime_provider("managed", _context(production=True))
    assert cleanups[-1] == "missing-anchor-closed"

    _install(
        monkeypatch,
        FakeEntryPoint(
            "managed",
            lambda _context: _bindings(
                production_capable=True,
                authority_anchor=AuthorityAnchor(),
                cleanup=lambda: cleanups.append("missing-audit-closed"),
            ),
        ),
    )
    with pytest.raises(ValidationError, match="independent audit sink"):
        open_runtime_provider("managed", _context(production=True))
    assert cleanups[-1] == "missing-audit-closed"

    cross_tenant = Authenticator(_identity(tenant_id="tenant-b"))
    _install(
        monkeypatch,
        FakeEntryPoint(
            "managed",
            lambda _context: _bindings(
                authenticator=cross_tenant,
                authority_anchor=AuthorityAnchor(),
                audit_sink=AuditSink(),
            ),
        ),
    )
    session = open_runtime_provider("managed", _context(production=True))
    try:
        with pytest.raises(AuthenticationError, match="cross-tenant"):
            asyncio.run(session.authenticator.authenticate(object()))
    finally:
        session.close()


def test_provider_options_are_bounded_immutable_and_duplicate_safe() -> None:
    checked = validate_runtime_options((("issuer", "https://issuer.example"),))
    with pytest.raises(TypeError):
        checked["issuer"] = "changed"  # type: ignore[index]
    with pytest.raises(ValidationError, match="duplicate"):
        validate_runtime_options((("issuer", "one"), ("issuer", "two")))
    with pytest.raises(ValidationError, match="control characters"):
        validate_runtime_options((("issuer", "bad\nvalue"),))
    with pytest.raises(ValidationError, match="LETS-CJ/1"):
        validate_runtime_options((("issuer", "\ud800"),))
    with pytest.raises(ValidationError, match="aggregate size"):
        validate_runtime_options((f"option{index}", "x" * 600) for index in range(28))


def test_key_info_and_backup_use_external_provider_without_a_seed_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = Ed25519Signer.generate("warden-a")
    database = tmp_path / "warden.sqlite3"
    store = SQLiteStorage.initialize(
        database,
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        initial_local_share=(10,),
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=8,
    )
    store.close()
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "version": 1,
                "warden_id": "warden-a",
                "tenant_id": "tenant-a",
                "envelope_id": "envelope-a",
                "config_epoch": 1,
                "budget": [10],
                "local_share": [10],
                "database": database.name,
                "receipt_ttl_ns": 100,
                "max_clock_uncertainty_ns": 0,
                "transfer_gap_window": 8,
                "runtime": {"provider": "managed", "options": {}},
            }
        ),
        encoding="utf-8",
    )
    events: list[str] = []
    original_close = SQLiteStorage.close

    def recorded_close(storage: SQLiteStorage) -> None:
        events.append("storage-closed")
        original_close(storage)

    monkeypatch.setattr(SQLiteStorage, "close", recorded_close)
    _install(
        monkeypatch,
        FakeEntryPoint(
            "managed",
            lambda _context: _bindings(
                signer=signer,
                cleanup=lambda: events.append("provider-closed"),
            ),
        ),
    )

    assert _key(config_path) == 0
    assert events == ["provider-closed"]
    events.clear()
    assert _info(config_path) == 0
    assert events == ["storage-closed", "provider-closed"]
    events.clear()
    backup = tmp_path / "backup.sqlite3"
    assert _backup(config_path, backup) == 0
    assert backup.is_file()
    assert events[-1] == "provider-closed"
    assert events.count("storage-closed") == 2


def test_metrics_include_capacity_and_fail_readiness_on_audit_export_error(
    tmp_path: Path,
) -> None:
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteStorage.initialize(
        tmp_path / "metrics.sqlite3",
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
    )
    try:
        service = WardenService(store, signer=signer)
        healthy = _metrics_provider(
            service,
            store,
            _identity(),
            audit_status=lambda: {
                "running": True,
                "last_success_ns": None,
                "last_error": None,
            },
        )
        assert healthy["ready"] is True
        assert healthy["storage_capacity"]["healthy"] is True
        assert healthy["audit_exporter"]["running"] is True

        failed = _metrics_provider(
            service,
            store,
            _identity(),
            audit_status=lambda: {
                "running": True,
                "last_success_ns": None,
                "last_error": "sink unavailable",
            },
        )
        assert failed["ready"] is False
    finally:
        store.close()
