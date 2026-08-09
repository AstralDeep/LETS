from __future__ import annotations

from dataclasses import replace

import pytest

from lets.errors import ValidationError
from lets.models import (
    BranchRevocation,
    IdentityContext,
    LeaseGrant,
    LeaseSnapshot,
    LeaseStatus,
    Receipt,
    TransferAck,
    TransferVoucher,
)

DIGEST = "sha256:" + "1" * 64


def grant() -> LeaseGrant:
    return LeaseGrant(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        lease_id="lease-a",
        lineage_id="lineage-a",
        parent_id=None,
        subject_id="spiffe://example/agent/a",
        warden_id="warden-a",
        allocation=(10, 20),
        capabilities=frozenset({"agent.spawn", "work.execute"}),
        policy_id="generic",
        policy_version="v1",
        policy_digest=DIGEST,
        machine_digest=DIGEST,
        ancestor_path=(),
        branch_epoch=0,
        issued_at_ns=1,
        expires_at_ns=10,
        key_id="warden-a/key-1",
        signature="signed",
    )


def test_identity_context_validates_scopes_and_subject() -> None:
    identity = IdentityContext(
        subject_id="spiffe://example/operator/a",
        tenant_id="tenant-a",
        scopes=frozenset({"lease:issue"}),
        authentication_method="mTLS",
    )
    identity.require_scope("lease:issue")
    with pytest.raises(PermissionError):
        identity.require_scope("admin")


def test_lease_grant_round_trip_and_signature_payload() -> None:
    original = grant()

    assert LeaseGrant.from_dict(original.to_dict()) == original
    assert "signature" not in original.unsigned_payload()
    assert original.unsigned_payload()["capabilities"] == ["agent.spawn", "work.execute"]


def test_lease_grant_rejects_expired_and_unknown_wire_data() -> None:
    with pytest.raises(ValidationError, match="expiry"):
        replace(grant(), expires_at_ns=1)
    wire = grant().to_dict()
    wire["unexpected"] = True
    with pytest.raises(ValidationError, match="unknown"):
        LeaseGrant.from_dict(wire)


def test_snapshot_rejects_residual_above_signed_allocation() -> None:
    snapshot = LeaseSnapshot(
        grant=grant(),
        residual=(4, 5),
        current_state="ACTIVE",
        status=LeaseStatus.ACTIVE,
        sequence=2,
        updated_at_ns=3,
    )
    assert LeaseSnapshot.from_dict(snapshot.to_dict()) == snapshot
    with pytest.raises(ValidationError, match="exceeds"):
        replace(snapshot, residual=(11, 5))


def test_receipt_round_trip_binds_authority_and_effect() -> None:
    receipt = Receipt(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        receipt_id="receipt-a",
        request_id="request-a",
        warden_id="warden-a",
        key_id="warden-a/key-1",
        policy_id="generic",
        policy_version="v1",
        policy_digest=DIGEST,
        machine_digest=DIGEST,
        lease_id="lease-a",
        lineage_id="lineage-a",
        subject_id="spiffe://example/agent/a",
        executor_audience="spiffe://example/executor/a",
        transition="execute",
        source_state="READY",
        target_state="DONE",
        cost=(1, 2),
        resulting_sequence=4,
        evidence_digest=None,
        nonce="nonce-a",
        issued_at_ns=5,
        expires_at_ns=8,
        signature="signed",
    )

    assert Receipt.from_dict(receipt.to_dict()) == receipt
    assert "signature" not in receipt.unsigned_payload()


def test_transfer_records_round_trip_and_reject_zero_or_self_transfer() -> None:
    voucher = TransferVoucher(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        transfer_id="transfer-a",
        source_warden="warden-a",
        target_warden="warden-b",
        policy_id="generic",
        policy_version="v1",
        policy_digest=DIGEST,
        sequence=1,
        amount=(2, 0),
        issued_at_ns=1,
        key_id="warden-a/key-1",
        signature="signed",
    )
    assert TransferVoucher.from_dict(voucher.to_dict()) == voucher

    ack = TransferAck(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        transfer_id="transfer-a",
        source_warden="warden-a",
        target_warden="warden-b",
        sequence=1,
        voucher_digest=DIGEST,
        accepted_at_ns=2,
        contiguous_watermark=1,
        key_id="warden-b/key-1",
        signature="signed",
    )
    assert TransferAck.from_dict(ack.to_dict()) == ack

    with pytest.raises(ValidationError, match="non-zero"):
        replace(voucher, amount=(0, 0))
    with pytest.raises(ValidationError, match="must differ"):
        replace(voucher, target_warden="warden-a")


def test_branch_revocation_round_trip() -> None:
    revocation = BranchRevocation(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        branch_lease_id="lease-a",
        lineage_id="lineage-a",
        epoch=2,
        issuer_warden="warden-a",
        issued_at_ns=5,
        reason="operator request",
        key_id="warden-a/key-1",
        signature="signed",
    )
    assert BranchRevocation.from_dict(revocation.to_dict()) == revocation
