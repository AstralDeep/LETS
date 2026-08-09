from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from lets.audit import SQLiteAuditSink
from lets.auth import AuthenticationError
from lets.canonical import b64url_encode, canonical_json
from lets.errors import SignatureError, ValidationError
from lets.providers.generic import Ed25519JWTAuthenticator, open_runtime
from lets.runtime import RuntimeProviderContext, open_runtime_provider


@dataclass(frozen=True)
class _Request:
    headers: dict[str, str]


def _jwt(
    key: SigningKey,
    *,
    kid: str,
    now: int,
    tenant_id: str = "tenant",
    lifetime: int = 60,
    algorithm: str = "EdDSA",
) -> str:
    header = b64url_encode(canonical_json({"alg": algorithm, "kid": kid, "typ": "at+jwt"}))
    payload = b64url_encode(
        canonical_json(
            {
                "aud": "lets-api",
                "exp": now + lifetime,
                "iat": now,
                "iss": "issuer-a",
                "jti": "token-0001",
                "nbf": now,
                "scope": "lets.admin lets.audit.read",
                "sub": "operator-a",
                "tenant_id": tenant_id,
            }
        )
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = b64url_encode(key.sign(signing_input).signature)
    return f"{header}.{payload}.{signature}"


def _key_file(path: Path, key: SigningKey) -> Path:
    path.write_bytes(
        canonical_json(
            {
                "keys": [
                    {
                        "kid": "identity-key",
                        "public_key": b64url_encode(key.verify_key.encode()),
                    }
                ]
            }
        )
    )
    return path


def _signer_helper(path: Path) -> Path:
    path.write_text(
        "\n".join(
            (
                "import sys",
                "from nacl.signing import SigningKey",
                "from lets.canonical import b64url_encode",
                "seed = open(sys.argv[1], 'rb').read()",
                "sys.stdout.write(b64url_encode(SigningKey(seed).sign(sys.stdin.buffer.read()).signature))",
            )
        ),
        encoding="utf-8",
    )
    return path


def test_generic_production_provider_uses_external_signer_jwt_anchor_and_sink(
    tmp_path: Path,
) -> None:
    signer_key = SigningKey.generate()
    identity_key = SigningKey.generate()
    helper = _signer_helper(tmp_path / "signer.py")
    identity_keys = _key_file(tmp_path / "identity-keys.json", identity_key)
    anchor_path = tmp_path / "independent" / "anchor.json"
    anchor_path.parent.mkdir()
    audit_root = tmp_path / "audit"
    audit_root.mkdir()
    audit_path = audit_root / "audit.db"
    SQLiteAuditSink.initialize(audit_path)
    seed_file = tmp_path / "signer.seed"
    seed_file.write_bytes(signer_key.encode())
    options = {
        "audit_archive_path": str(audit_path.resolve()),
        "authority_anchor_path": str(anchor_path.resolve()),
        "identity_audience": "lets-api",
        "identity_issuer": "issuer-a",
        "identity_keys_file": str(identity_keys.resolve()),
        "signer_command_json": json.dumps(
            [sys.executable, str(helper.resolve()), str(seed_file.resolve())]
        ),
        "signer_key_id": "warden-key",
        "signer_public_key": b64url_encode(signer_key.verify_key.encode()),
    }
    context = RuntimeProviderContext(
        config_path=tmp_path / "state" / "config.json",
        database_path=tmp_path / "state" / "warden.sqlite3",
        warden_id="warden-a",
        tenant_id="tenant",
        envelope_id="envelope",
        config_epoch=1,
        manifest_digest=None,
        options=options,
        production=True,
    )

    bindings = open_runtime(context)
    assert bindings.production_capable
    assert bindings.authority_anchor is not None
    assert bindings.audit_sink is not None
    payload = b"external-signing-proof"
    signature = bindings.signer.sign(payload)
    signer_key.verify_key.verify(payload, signature)

    token = _jwt(identity_key, kid="identity-key", now=int(time.time()))
    identity = bindings.authenticator.authenticate(_Request({"authorization": f"Bearer {token}"}))
    assert identity.subject_id == "operator-a"
    assert identity.tenant_id == "tenant"
    assert identity.authentication_method == "jwt-eddsa"
    assert identity.scopes == frozenset({"lets.admin", "lets.audit.read"})

    with open_runtime_provider("generic-production", context) as session:
        assert session.production_capable
        assert session.provider_name == "generic-production"
        assert session.authority_anchor is not None
        assert session.audit_sink is not None

    state_root = tmp_path / "state"
    state_root.mkdir()
    colocated = RuntimeProviderContext(
        config_path=tmp_path / "immutable-config" / "config.json",
        database_path=state_root / "warden.sqlite3",
        warden_id=context.warden_id,
        tenant_id=context.tenant_id,
        envelope_id=context.envelope_id,
        config_epoch=context.config_epoch,
        manifest_digest=context.manifest_digest,
        options={
            **dict(context.options),
            "authority_anchor_path": str((state_root / "anchor.json").resolve()),
        },
        production=True,
    )
    with pytest.raises(ValidationError, match="outside node state"):
        open_runtime(colocated)


def test_generic_jwt_fails_closed_on_expiry_wrong_tenant_and_algorithm(tmp_path: Path) -> None:
    key = SigningKey.generate()
    authenticator = Ed25519JWTAuthenticator(
        key_file=_key_file(tmp_path / "keys.json", key),
        issuer="issuer-a",
        audience="lets-api",
        tenant_id="tenant",
        clock_skew_s=0,
        max_lifetime_s=300,
    )
    now = int(time.time())
    cases = (
        _jwt(key, kid="identity-key", now=now - 120, lifetime=30),
        _jwt(key, kid="identity-key", now=now, tenant_id="other"),
        _jwt(key, kid="identity-key", now=now, algorithm="none"),
    )
    for token in cases:
        with pytest.raises(AuthenticationError):
            authenticator.authenticate(_Request({"authorization": f"Bearer {token}"}))


def test_generic_provider_rejects_missing_resources_and_bad_signatures(tmp_path: Path) -> None:
    key = SigningKey.generate()
    helper = tmp_path / "bad-signer.py"
    helper.write_text(
        "from lets.canonical import b64url_encode\nprint(b64url_encode(bytes(64)))\n",
        encoding="utf-8",
    )
    audit_root = tmp_path / "audit"
    audit_root.mkdir()
    audit_path = audit_root / "audit.db"
    SQLiteAuditSink.initialize(audit_path)
    context = RuntimeProviderContext(
        config_path=tmp_path / "state" / "config.json",
        database_path=tmp_path / "state" / "warden.sqlite3",
        warden_id="warden-a",
        tenant_id="tenant",
        envelope_id="envelope",
        config_epoch=1,
        manifest_digest=None,
        options={
            "audit_archive_path": str(audit_path.resolve()),
            "authority_anchor_path": str((tmp_path / "missing-parent" / "anchor").resolve()),
            "identity_audience": "lets-api",
            "identity_issuer": "issuer-a",
            "identity_keys_file": str(_key_file(tmp_path / "keys.json", key).resolve()),
            "signer_command_json": json.dumps([sys.executable, str(helper.resolve())]),
            "signer_key_id": "warden-key",
            "signer_public_key": b64url_encode(key.verify_key.encode()),
        },
        production=True,
    )
    with pytest.raises(ValidationError, match="parent directory"):
        open_runtime(context)

    context = RuntimeProviderContext(
        config_path=context.config_path,
        database_path=context.database_path,
        warden_id=context.warden_id,
        tenant_id=context.tenant_id,
        envelope_id=context.envelope_id,
        config_epoch=context.config_epoch,
        manifest_digest=None,
        options={
            **dict(context.options),
            "authority_anchor_path": str((tmp_path / "anchor" / "warden.json").resolve()),
        },
        production=True,
    )
    (tmp_path / "anchor").mkdir()
    bindings = open_runtime(context)
    with pytest.raises(SignatureError, match="does not match"):
        bindings.signer.sign(b"payload")
