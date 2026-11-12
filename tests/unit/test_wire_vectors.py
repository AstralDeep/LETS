"""Runs the reference verifier against every committed wire vector and proves the vector files still match what scripts/generate_vectors.py emits.
"""

from __future__ import annotations

import importlib.util
import json
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from lets.canonical import b64url_decode, canonical_json
from lets.crypto import Ed25519Signer
from lets.models import LeaseGrant, Receipt, TransferAck, TransferVoucher
from lets.wire_verify import REASONS, VALID, VectorRunner, WireRejection

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "protocol" / "vectors"
FILES = {
    "receipt.json": Receipt,
    "lease-grant.json": LeaseGrant,
    "transfer-voucher.json": TransferVoucher,
    "transfer-ack.json": TransferAck,
}


def _generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "generate_vectors", ROOT / "scripts" / "generate_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _cases() -> list[tuple[str, str]]:
    return [(file, case["name"]) for file in FILES for case in _load(file)["cases"]]


@pytest.mark.parametrize(("file", "name"), _cases())
def test_reference_verifier_matches_every_vector(file: str, name: str, tmp_path: Path) -> None:
    document = _load(file)
    case = next(item for item in document["cases"] if item["name"] == name)
    outcomes = VectorRunner(tmp_path).run(document["wire_type"], case, document["trusted_keys"])
    assert outcomes == [item["expect"] for item in case["steps"]]


@pytest.mark.parametrize("file", sorted(FILES))
def test_vector_documents_declare_their_wire_type(file: str) -> None:
    document = _load(file)
    assert document["format"] == "lets.vectors/v1"
    assert document["wire_type"] == FILES[file].WIRE_TYPE
    for case in document["cases"]:
        for item in case["steps"]:
            assert item["expect"] == VALID or item["expect"] in REASONS


@pytest.mark.parametrize("file", sorted(FILES))
def test_every_required_invalid_class_is_published(file: str) -> None:
    expected = {
        "receipt.json": {"signature", "audience", "expired", "policy_digest", "replay"},
        "lease-grant.json": {"signature", "audience", "expired", "policy_digest"},
        "transfer-voucher.json": {"signature", "audience", "policy_digest", "sequence_conflict"},
        "transfer-ack.json": {"signature", "audience", "voucher_digest"},
    }[file]
    seen = {item["expect"] for case in _load(file)["cases"] for item in case["steps"]}
    assert expected <= seen
    assert VALID in seen
    assert "malformed" in seen


@pytest.mark.parametrize("file", sorted(FILES))
def test_signing_inputs_match_the_published_wire(file: str) -> None:
    model = FILES[file]
    for case in _load(file)["cases"]:
        for item in case["steps"]:
            if "signing_input" not in item:
                continue
            record = model.from_dict(dict(item["wire"]))
            unsigned = canonical_json(record.unsigned_payload())
            assert unsigned.decode("utf-8") == item["signing_input"]
            assert sha256(unsigned).hexdigest() == item["signing_input_sha256"]
            assert record.to_dict() == item["wire"]


def test_committed_vectors_match_the_generator() -> None:
    generator = _generator()
    for name, build in generator.builders().items():
        assert (VECTORS / name).read_text(encoding="utf-8") == generator.render(build()), name


def test_generator_check_flags_a_stale_file(tmp_path: Path) -> None:
    generator = _generator()
    for name, build in generator.builders().items():
        (tmp_path / name).write_text(generator.render(build()), encoding="utf-8")
    assert _run_generator(generator, tmp_path) == 0
    (tmp_path / "receipt.json").write_text("{}\n", encoding="utf-8")
    assert _run_generator(generator, tmp_path) == 1
    (tmp_path / "receipt.json").unlink()
    assert _run_generator(generator, tmp_path) == 1


def _run_generator(generator: Any, directory: Path) -> int:
    import sys

    argv = sys.argv
    sys.argv = ["generate_vectors", "--check", "--output", str(directory)]
    try:
        return int(generator.main())
    finally:
        sys.argv = argv


def test_published_keys_reproduce_from_their_seeds() -> None:
    document = _load("keys.json")
    for entry in document["keys"]:
        signer = Ed25519Signer.from_seed(entry["warden_id"], b64url_decode(entry["seed"]))
        assert signer.key_id == entry["key_id"]
        assert signer.public_key_bytes == b64url_decode(entry["public_key"])


def test_wire_rejection_refuses_an_unknown_reason() -> None:
    with pytest.raises(ValueError, match="unknown rejection reason"):
        WireRejection("nonsense", "x")
