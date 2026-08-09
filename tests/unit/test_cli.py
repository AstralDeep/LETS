from pathlib import Path

import pytest

from lets.canonical import b64url_encode
from lets.cli import (
    _configured_peer_endpoints,
    _database_path,
    _operator_keys,
    _parser,
    _runtime_configuration,
    _serve,
    _sqlite_wal_reset_safe,
    _validate_peer_trust,
    _validate_production_admission,
)
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ValidationError


@pytest.mark.parametrize(
    ("version", "safe"),
    [
        ((3, 44, 5), False),
        ((3, 44, 6), True),
        ((3, 49, 1), False),
        ((3, 50, 6), False),
        ((3, 50, 7), True),
        ((3, 51, 0), False),
        ((3, 51, 2), False),
        ((3, 51, 3), True),
        ((3, 52, 0), False),
        ((3, 52, 9), False),
        ((3, 53, 2), True),
    ],
)
def test_production_sqlite_requires_an_upstream_wal_reset_fix(
    version: tuple[int, int, int], safe: bool
) -> None:
    assert _sqlite_wal_reset_safe(version) is safe


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["serve", "--tls-cert", "server.pem"], "--tls-cert and --tls-key"),
        (["serve", "--client-ca", "clients.pem"], "--client-ca requires"),
        (["serve", "--peer-cert", "peer.pem"], "--peer-cert and --peer-key"),
        (["serve", "--host", "0.0.0.0"], "non-loopback serving requires TLS"),
    ],
)
def test_serve_rejects_incomplete_transport_security_configuration(
    arguments: list[str], message: str
) -> None:
    parsed = _parser().parse_args(arguments)
    with pytest.raises(ValidationError, match=message):
        _serve(Path("configuration-is-not-read.json"), parsed)


def test_serve_parser_accepts_complete_outbound_mtls_configuration() -> None:
    parsed = _parser().parse_args(
        [
            "serve",
            "--peer-ca",
            "peers-ca.pem",
            "--peer-cert",
            "peer-client.pem",
            "--peer-key",
            "peer-client.key",
        ]
    )
    assert parsed.peer_ca == Path("peers-ca.pem")
    assert parsed.peer_cert == Path("peer-client.pem")
    assert parsed.peer_key == Path("peer-client.key")


def test_non_manifest_peer_http_requires_explicit_development_opt_in() -> None:
    config = {"peer_endpoints": {"warden-b": "http://warden-b:8080"}}
    with pytest.raises(ValidationError, match="HTTPS"):
        _configured_peer_endpoints(config, allow_insecure_http=False)
    assert _configured_peer_endpoints(config, allow_insecure_http=True) == {
        "warden-b": "http://warden-b:8080"
    }


def test_peer_endpoints_require_current_trusted_keys_before_serve() -> None:
    local = Ed25519Signer.generate("warden-a")
    peer = Ed25519Signer.generate("warden-b")
    registry = PublicKeyRegistry()
    registry.register_signer(local)
    endpoints = {"warden-b": "https://warden-b.example"}

    with pytest.raises(ValidationError, match="no currently valid trusted verification key"):
        _validate_peer_trust(endpoints, registry, local_warden_id=local.warden_id)

    registry.register_signer(peer)
    _validate_peer_trust(endpoints, registry, local_warden_id=local.warden_id)
    with pytest.raises(ValidationError, match="must not contain the local warden"):
        _validate_peer_trust(
            {local.warden_id: "https://warden-a.example"},
            registry,
            local_warden_id=local.warden_id,
        )


def test_operator_key_parser_rejects_aliases_for_one_public_key() -> None:
    operator = Ed25519Signer.generate("operator-a")
    encoded = b64url_encode(operator.public_key_bytes)

    with pytest.raises(ValidationError, match="aliases must not reuse"):
        _operator_keys([f"operator-a={encoded}", f"operator-b={encoded}"])


def test_runtime_configuration_rejects_duplicate_options_and_scopes_overrides() -> None:
    config = {
        "runtime": {
            "provider": "managed",
            "options": {"issuer": "https://issuer.example"},
        }
    }
    parsed = _parser().parse_args(["key", "--runtime-option", "audience=lets"])
    provider, options = _runtime_configuration(config, parsed)
    assert provider == "managed"
    assert dict(options) == {
        "issuer": "https://issuer.example",
        "audience": "lets",
    }

    duplicate = _parser().parse_args(["key", "--runtime-option", "issuer=changed"])
    with pytest.raises(ValidationError, match="duplicate"):
        _runtime_configuration(config, duplicate)

    override = _parser().parse_args(
        [
            "key",
            "--runtime-provider",
            "replacement",
            "--runtime-option",
            "endpoint=https://kms.example",
        ]
    )
    provider, options = _runtime_configuration(config, override)
    assert provider == "replacement"
    assert dict(options) == {"endpoint": "https://kms.example"}


def test_absolute_database_path_requires_an_external_runtime_provider(tmp_path: Path) -> None:
    database = (tmp_path / "state" / "warden.sqlite3").resolve()
    config_path = (tmp_path / "immutable-config" / "config.json").resolve()

    with pytest.raises(ValidationError, match="external runtime provider"):
        _database_path(config_path, {"database": str(database)})
    with pytest.raises(ValidationError, match="external runtime provider"):
        _database_path(
            config_path,
            {"database": str(database), "runtime": {"provider": "builtin"}},
        )

    assert (
        _database_path(
            config_path,
            {"database": str(database), "runtime": {"provider": "generic-production"}},
        )
        == database
    )


def test_builtin_database_path_remains_project_local(tmp_path: Path) -> None:
    config_path = (tmp_path / "project" / "config.json").resolve()
    assert (
        _database_path(config_path, {"database": "state/warden.sqlite3"})
        == (config_path.parent / "state" / "warden.sqlite3").resolve()
    )
    with pytest.raises(ValidationError, match="escapes its project directory"):
        _database_path(config_path, {"database": "../warden.sqlite3"})


def test_production_admission_rejects_every_development_trust_path() -> None:
    config: dict[str, object] = {
        "manifest": "cluster.json",
        "manifest_digest": "sha256:" + "1" * 64,
        "operator_trust": {"threshold": 1},
        "allow_insecure_manifest": False,
        "bootstrap_identities": [],
        "min_free_disk_bytes": 1_000_000,
        "max_database_bytes": 100_000_000,
        "reserve_pages": 128,
    }
    parsed = _parser().parse_args(
        [
            "serve",
            "--production",
            "--tls-cert",
            "server.pem",
            "--tls-key",
            "server.key",
            "--client-ca",
            "clients-ca.pem",
            "--runtime-provider",
            "managed",
        ]
    )
    _validate_production_admission(config, parsed, provider_name="managed")

    with pytest.raises(ValidationError, match="built-in file signer"):
        _validate_production_admission(config, parsed, provider_name="builtin")

    parsed.tls_cert = None
    with pytest.raises(ValidationError, match="requires --tls-cert"):
        _validate_production_admission(config, parsed, provider_name="managed")
    parsed.tls_cert = Path("server.pem")

    parsed.allow_insecure_peer_http = True
    with pytest.raises(ValidationError, match="insecure client or peer HTTP"):
        _validate_production_admission(config, parsed, provider_name="managed")
    parsed.allow_insecure_peer_http = False

    without_manifest = dict(config)
    without_manifest.pop("manifest_digest")
    with pytest.raises(ValidationError, match="operator-signed cluster manifest"):
        _validate_production_admission(without_manifest, parsed, provider_name="managed")

    insecure_manifest = dict(config)
    insecure_manifest["allow_insecure_manifest"] = True
    with pytest.raises(ValidationError, match="without insecure HTTP"):
        _validate_production_admission(insecure_manifest, parsed, provider_name="managed")

    with_bootstrap = dict(config)
    with_bootstrap["bootstrap_identities"] = [{"token_sha256": "unsafe"}]
    with pytest.raises(ValidationError, match="static bootstrap credentials"):
        _validate_production_admission(with_bootstrap, parsed, provider_name="managed")

    unsafe_capacity = dict(config)
    unsafe_capacity["min_free_disk_bytes"] = 0
    with pytest.raises(ValidationError, match="positive min_free_disk_bytes"):
        _validate_production_admission(unsafe_capacity, parsed, provider_name="managed")
