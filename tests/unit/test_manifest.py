from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from jsonschema import Draft202012Validator, FormatChecker

from deploy.bootstrap_cluster import _signed_manifest
from lets.canonical import canonical_json
from lets.crypto import Ed25519Signer
from lets.errors import SignatureError, ValidationError
from lets.manifest import (
    ClusterManifest,
    ManifestPublicKey,
    ManifestSignature,
    WardenManifest,
    validate_endpoint_origin,
)
from lets.policy import (
    MAX_TRANSFER_GAP_WINDOW,
    MachineSpec,
    PolicySpec,
    ResourceDimension,
    TransitionSpec,
)


def _manifest() -> ClusterManifest:
    resources = (
        ResourceDimension("actions", "count"),
        ResourceDimension("tokens", "token"),
    )
    policy = PolicySpec(
        policy_id="agent-runtime",
        policy_version="v1",
        dimensions=resources,
        machine=MachineSpec(
            machine_id="replica",
            initial_state="ready",
            transitions=(
                TransitionSpec(
                    name="run",
                    source="ready",
                    target="ready",
                    cost=(1, 2),
                    capability="agent.run",
                ),
            ),
        ),
        max_lease_ttl_ns=1_000_000,
        receipt_ttl_ns=10_000,
        max_clock_uncertainty_ns=100,
        transfer_gap_window=64,
    )
    signer_a = Ed25519Signer.generate("warden-a")
    signer_b = Ed25519Signer.generate("warden-b")
    return ClusterManifest(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        created_at="2026-08-09T05:00:00Z",
        resources=resources,
        initial_budget=(100, 100),
        wardens=(
            WardenManifest(
                warden_id="warden-a",
                peer_endpoint="https://warden-a:8443",
                client_endpoint="https://warden-a:8443",
                initial_share=(60, 40),
                keys=(ManifestPublicKey(signer_a.key_id, signer_a.public_key_bytes),),
                extensions={},
            ),
            WardenManifest(
                warden_id="warden-b",
                peer_endpoint="https://warden-b:8443",
                client_endpoint="https://warden-b:8443",
                initial_share=(40, 60),
                keys=(ManifestPublicKey(signer_b.key_id, signer_b.public_key_bytes),),
                extensions={},
            ),
        ),
        policies=(policy,),
        extensions={"example.net/placement": {"region": "test"}},
    )


def test_manifest_round_trip_preserves_content_digest() -> None:
    manifest = _manifest()

    parsed = ClusterManifest.from_dict(manifest.to_dict())

    assert parsed == manifest
    assert parsed.digest == manifest.digest
    assert parsed.warden("warden-b").initial_share == (40, 60)


def test_manifest_wire_document_conforms_to_published_schema() -> None:
    schema_path = Path(__file__).parents[2] / "protocol" / "manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(_manifest().to_dict())


def test_acceptance_manifest_conforms_to_published_development_profile_schema() -> None:
    schema_path = Path(__file__).parents[2] / "protocol" / "manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    operator = Ed25519Signer.generate("cluster-operator")
    signers = {
        warden_id: (Path(f"{warden_id}.seed"), Ed25519Signer.generate(warden_id))
        for warden_id in ("warden-a", "warden-b", "warden-c")
    }
    document = _signed_manifest(operator, signers).to_dict()

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    parsed = ClusterManifest.from_dict(document, allow_insecure_http=True)
    assert parsed.verify_signatures(
        {operator.key_id: operator.public_key_bytes}, threshold=1
    ) == frozenset({operator.key_id})


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("warden_id", "site/a"),
        ("warden_id", "w%C3%A4rden"),
        ("warden_id", "wärden"),
        ("key_id", "key percent%"),
        ("key_id", "κλειδί"),
    ],
)
def test_manifest_schema_and_runtime_share_transport_identifier_grammar(
    field: str, invalid: str
) -> None:
    schema_path = Path(__file__).parents[2] / "protocol" / "manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    document = _manifest().to_dict()
    if field == "warden_id":
        document["wardens"][0][field] = invalid
    else:
        document["wardens"][0]["keys"][0][field] = invalid

    assert not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(document)
    with pytest.raises(ValidationError, match=r"transport-safe|URI-unreserved"):
        ClusterManifest.from_dict(document)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("created_at", "2026-08-09t12:00:00z"),
        ("created_at", "2026-08-09T12:00:00.1234567890Z"),
        ("not_before", "2026-08-09t12:00:00z"),
        ("not_after", "2026-08-09T12:00:00.1234567890Z"),
    ],
)
def test_manifest_schema_and_runtime_share_timestamp_grammar(field: str, invalid: str) -> None:
    schema_path = Path(__file__).parents[2] / "protocol" / "manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    document = _manifest().to_dict()
    if field == "created_at":
        document[field] = invalid
    else:
        document["wardens"][0]["keys"][0][field] = invalid

    assert not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(document)
    with pytest.raises(ValidationError, match="RFC 3339"):
        ClusterManifest.from_dict(document)


def test_manifest_signature_threshold_uses_external_operator_trust() -> None:
    manifest = _manifest()
    operator_a = Ed25519Signer.generate("operator-a")
    operator_b = Ed25519Signer.generate("operator-b")
    payload = canonical_json(manifest.unsigned_dict())
    signed = replace(
        manifest,
        signatures=(
            ManifestSignature(operator_a.key_id, operator_a.sign(payload)),
            ManifestSignature(operator_b.key_id, operator_b.sign(payload)),
        ),
    )

    accepted = signed.verify_signatures(
        {
            operator_a.key_id: operator_a.public_key_bytes,
            operator_b.key_id: operator_b.public_key_bytes,
        },
        threshold=2,
    )

    assert accepted == frozenset({operator_a.key_id, operator_b.key_id})


def test_manifest_signature_threshold_rejects_aliases_for_one_operator_key() -> None:
    manifest = _manifest()
    operator = Ed25519Signer.generate("operator-a")
    payload = canonical_json(manifest.unsigned_dict())
    signature = operator.sign(payload)
    signed = replace(
        manifest,
        signatures=(
            ManifestSignature("operator-alias-a", signature),
            ManifestSignature("operator-alias-b", signature),
        ),
    )

    with pytest.raises(ValidationError, match="aliases must not reuse"):
        signed.verify_signatures(
            {
                "operator-alias-a": operator.public_key_bytes,
                "operator-alias-b": operator.public_key_bytes,
            },
            threshold=2,
        )


def test_manifest_operator_and_warden_keys_must_be_role_separated() -> None:
    manifest = _manifest()
    signer = Ed25519Signer.from_seed("warden-a", b"\x01" * 32)
    manifest = replace(
        manifest,
        wardens=(
            replace(
                manifest.wardens[0],
                keys=(ManifestPublicKey(signer.key_id, signer.public_key_bytes),),
            ),
            manifest.wardens[1],
        ),
    )
    payload = canonical_json(manifest.unsigned_dict())
    signed = replace(
        manifest,
        signatures=(ManifestSignature(signer.key_id, signer.sign(payload)),),
    )

    with pytest.raises(ValidationError, match="roles must use disjoint"):
        signed.verify_signatures({signer.key_id: signer.public_key_bytes})


def test_manifest_rejects_public_key_reuse_across_warden_identities() -> None:
    manifest = _manifest()
    shared_seed = Ed25519Signer.generate("seed-owner").seed_bytes
    signer_a = Ed25519Signer.from_seed("warden-a", shared_seed)
    signer_b = Ed25519Signer.from_seed("warden-b", shared_seed)

    with pytest.raises(ValidationError, match="public-key material must be globally unique"):
        replace(
            manifest,
            wardens=(
                replace(
                    manifest.wardens[0],
                    keys=(ManifestPublicKey(signer_a.key_id, signer_a.public_key_bytes),),
                ),
                replace(
                    manifest.wardens[1],
                    keys=(ManifestPublicKey(signer_b.key_id, signer_b.public_key_bytes),),
                ),
            ),
        )


def test_manifest_signature_fails_closed_after_semantic_tampering() -> None:
    manifest = _manifest()
    operator = Ed25519Signer.generate("operator-a")
    signed = replace(
        manifest,
        signatures=(
            ManifestSignature(
                operator.key_id,
                operator.sign(canonical_json(manifest.unsigned_dict())),
            ),
        ),
    )
    changed = replace(signed, envelope_id="other-envelope")

    with pytest.raises(SignatureError):
        changed.verify_signatures({operator.key_id: operator.public_key_bytes})


def test_manifest_rejects_incomplete_genesis_allocation() -> None:
    incomplete = _manifest().to_dict()
    incomplete["wardens"][0]["initial_share"] = [59, 40]

    with pytest.raises(ValidationError, match="sum of warden shares"):
        ClusterManifest.from_dict(incomplete)


def test_manifest_rejects_plain_http_unless_explicitly_enabled() -> None:
    document = _manifest().to_dict()
    document["wardens"][0]["peer_endpoint"] = "http://warden-a:8080"

    with pytest.raises(ValidationError, match="HTTPS"):
        ClusterManifest.from_dict(document)

    parsed = ClusterManifest.from_dict(document, allow_insecure_http=True)
    assert parsed.wardens[0].peer_endpoint == "http://warden-a:8080"


def test_manifest_runtime_rejects_unnamespaced_extensions() -> None:
    with pytest.raises(ValidationError, match="reverse-DNS/name"):
        replace(_manifest(), extensions={"purpose": "ambiguous"})
    with pytest.raises(ValidationError, match="reverse-DNS/name"):
        replace(_manifest().wardens[0], extensions={"purpose": "ambiguous"})


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://warden-a:8443/prefix",
        "https://warden-a:8443?token=secret",
        "https://warden-a:",
        "https://warden-a:0",
        "https://warden-a:08080",
        "https://warden-a:99999",
        "https://operator:secret@warden-a:8443",
        "https://warden-a:8443/#fragment",
    ],
)
def test_manifest_rejects_peer_endpoints_that_cannot_be_safe_client_bases(
    endpoint: str,
) -> None:
    document = _manifest().to_dict()
    document["wardens"][0]["peer_endpoint"] = endpoint

    with pytest.raises(ValidationError, match=r"origin|TCP port"):
        ClusterManifest.from_dict(document)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://evil\n.com",
        "https://\uff10.example.com",
        "https://exa mple.com",
        "https://a..example.com",
        f"https://{'a' * 64}.example.com",
        "https://01.02.03.04",
        "https://999.999.999.999",
        "https://[::ffff:192.0.2.1]",
        "https://[fe80::1%25eth0]",
        "https://[:::]",
    ],
)
def test_manifest_schema_and_runtime_reject_transport_invalid_hosts(endpoint: str) -> None:
    schema_path = Path(__file__).parents[2] / "protocol" / "manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    document = _manifest().to_dict()
    document["wardens"][0]["peer_endpoint"] = endpoint

    assert not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(document)
    with pytest.raises(ValidationError, match=r"valid URI|whitespace|ASCII|DNS|IPv6"):
        ClusterManifest.from_dict(document)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://warden-a:",
        "https://warden-a:0",
        "https://warden-a:08080",
        "https://warden-a:65536",
    ],
)
def test_manifest_schema_and_runtime_reject_invalid_endpoint_ports(endpoint: str) -> None:
    schema_path = Path(__file__).parents[2] / "protocol" / "manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    document = _manifest().to_dict()
    document["wardens"][0]["peer_endpoint"] = endpoint

    assert not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(document)
    with pytest.raises(ValidationError, match="TCP port"):
        ClusterManifest.from_dict(document)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://warden-a:8443",
        "https://xn--bcher-kva.example",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
    ],
)
def test_validated_endpoint_origins_are_constructible_by_httpx(endpoint: str) -> None:
    checked = validate_endpoint_origin(endpoint, "peer_endpoint", allow_insecure_http=True)
    parsed = httpx.URL(checked)
    assert parsed.host


@pytest.mark.parametrize(
    ("endpoint", "canonical"),
    [
        ("https://WARDEN-A:443/", "https://warden-a"),
        ("http://WARDEN-A:80", "http://warden-a"),
        ("https://[0:0:0:0:0:0:0:1]:443", "https://[::1]"),
    ],
)
def test_endpoint_origins_use_one_canonical_identity(endpoint: str, canonical: str) -> None:
    assert (
        validate_endpoint_origin(endpoint, "peer_endpoint", allow_insecure_http=True) == canonical
    )


def test_manifest_rejects_duplicate_warden_and_key_identities() -> None:
    duplicate_warden = _manifest().to_dict()
    duplicate_warden["wardens"][1]["warden_id"] = "warden-a"
    with pytest.raises(ValidationError, match="warden ids"):
        ClusterManifest.from_dict(duplicate_warden)

    duplicate_key = _manifest().to_dict()
    duplicate_key["wardens"][1]["keys"] = duplicate_key["wardens"][0]["keys"]
    with pytest.raises(ValidationError, match="key ids"):
        ClusterManifest.from_dict(duplicate_key)

    duplicate_endpoint = _manifest().to_dict()
    duplicate_endpoint["wardens"][1]["peer_endpoint"] = duplicate_endpoint["wardens"][0][
        "peer_endpoint"
    ]
    with pytest.raises(ValidationError, match="peer endpoint origins"):
        ClusterManifest.from_dict(duplicate_endpoint)


@pytest.mark.parametrize(
    "alias",
    [
        "https://WARDEN-A:8443",
        "https://warden-a:8443/",
    ],
)
def test_manifest_rejects_equivalent_peer_endpoint_aliases(alias: str) -> None:
    document = _manifest().to_dict()
    document["wardens"][1]["peer_endpoint"] = alias
    with pytest.raises(ValidationError, match="peer endpoint origins"):
        ClusterManifest.from_dict(document)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("https://same.example", "https://same.example:443"),
        ("https://[0:0:0:0:0:0:0:1]", "https://[::1]"),
    ],
)
def test_manifest_rejects_default_port_and_ip_spelling_origin_aliases(
    first: str, second: str
) -> None:
    document = _manifest().to_dict()
    document["wardens"][0]["peer_endpoint"] = first
    document["wardens"][1]["peer_endpoint"] = second

    with pytest.raises(ValidationError, match="peer endpoint origins"):
        ClusterManifest.from_dict(document)


def test_manifest_rejects_policy_with_different_immutable_transport_window() -> None:
    manifest = _manifest()
    second = replace(
        manifest.policies[0],
        policy_version="v2",
        transfer_gap_window=128,
    )

    with pytest.raises(ValidationError, match="transfer_gap_window"):
        replace(manifest, policies=(manifest.policies[0], second))


def test_manifest_schema_and_runtime_share_transfer_gap_window_limit() -> None:
    schema_path = Path(__file__).parents[2] / "protocol" / "manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    manifest = _manifest()
    bounded_policy = replace(
        manifest.policies[0],
        transfer_gap_window=MAX_TRANSFER_GAP_WINDOW,
    )
    bounded = replace(manifest, policies=(bounded_policy,)).to_dict()
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(bounded)
    assert ClusterManifest.from_dict(bounded).policies[0].transfer_gap_window == (
        MAX_TRANSFER_GAP_WINDOW
    )

    over_limit = json.loads(json.dumps(bounded))
    over_limit["policies"][0]["transfer_gap_window"] = MAX_TRANSFER_GAP_WINDOW + 1
    assert not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(over_limit)
    with pytest.raises(ValidationError, match="transfer_gap_window exceeds"):
        ClusterManifest.from_dict(over_limit)


@pytest.mark.parametrize(
    "document",
    [
        b'{"api_version":"lets.manifest/v1","api_version":"other"}',
        b'{"outer":{"signed":1,"signed":2}}',
        b'{"config_epoch":NaN}',
        b'{"tenant_id":"\\ud800"}',
    ],
)
def test_manifest_load_rejects_duplicate_and_non_lets_cj_json(
    tmp_path: Path,
    document: bytes,
) -> None:
    path = tmp_path / "malformed-manifest.json"
    path.write_bytes(document)
    with pytest.raises(ValidationError, match="could not load"):
        ClusterManifest.load(path)
