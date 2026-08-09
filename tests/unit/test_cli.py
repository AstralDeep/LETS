from pathlib import Path

import pytest

from lets.canonical import b64url_encode
from lets.cli import (
    _configured_peer_endpoints,
    _operator_keys,
    _parser,
    _serve,
    _validate_peer_trust,
)
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ValidationError


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
