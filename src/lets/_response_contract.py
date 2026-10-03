"""Generated client-side response-envelope rules. DO NOT EDIT BY HAND.

Regenerate with ``uv run python scripts/generate_response_contract.py`` after changing the
committed API contract in ``protocol/openapi.yaml``. The rules are embedded as JSON so the
module text is stable under formatting tools and the client can import it without the
server extras.
"""

from __future__ import annotations

import json
from typing import Any, Final

_CONTRACT_JSON: Final[str] = """\
{
  "GET /v1/audit": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "records"
        ],
        "required_non_null": [
          "records"
        ]
      }
    ]
  },
  "GET /v1/audit/verify": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "valid"
        ],
        "required_non_null": [
          "valid"
        ]
      }
    ]
  },
  "GET /v1/info": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "api_version": "v1",
          "protocol": "lets/1"
        },
        "required": [
          "api_version",
          "protocol",
          "warden_id"
        ],
        "required_non_null": [
          "api_version",
          "protocol",
          "warden_id"
        ]
      }
    ]
  },
  "GET /v1/invariants": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "initial_share",
          "transferred_in",
          "transferred_out",
          "free_pool",
          "lease_residual",
          "consumed",
          "checked_at_ns",
          "healthy"
        ],
        "required_non_null": [
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "initial_share",
          "transferred_in",
          "transferred_out",
          "free_pool",
          "lease_residual",
          "consumed",
          "checked_at_ns",
          "healthy"
        ]
      }
    ]
  },
  "GET /v1/keys": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "warden_id",
          "keys"
        ],
        "required_non_null": [
          "warden_id",
          "keys"
        ]
      }
    ]
  },
  "GET /v1/leases/{lease_id}": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.lease-snapshot/v1"
        },
        "required": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ],
        "required_non_null": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ]
      }
    ]
  },
  "GET /v1/maintenance/authority-status": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "enabled",
          "state",
          "healthy",
          "lifetime_id",
          "namespace_process_id",
          "admission_fenced",
          "fence_id",
          "fenced_at_monotonic_ns",
          "transport_faults",
          "transport_fault_episodes",
          "transport_recovery_attempts",
          "transport_recoveries",
          "unresolved_transport_faults",
          "permanent_faults",
          "fault_stage",
          "fault_reason",
          "retry_not_before_monotonic_ns",
          "first_fault"
        ],
        "required_non_null": [
          "enabled",
          "state",
          "healthy",
          "lifetime_id",
          "namespace_process_id",
          "admission_fenced",
          "transport_faults",
          "transport_fault_episodes",
          "transport_recovery_attempts",
          "transport_recoveries",
          "unresolved_transport_faults",
          "permanent_faults",
          "first_fault"
        ]
      }
    ]
  },
  "GET /v1/maintenance/runtime": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "mode",
          "generation",
          "reason",
          "changed_at_ns",
          "changed_by"
        ],
        "required_non_null": [
          "mode",
          "generation",
          "reason",
          "changed_at_ns",
          "changed_by"
        ]
      }
    ]
  },
  "GET /v1/metrics": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "max_age_ns": 15000000000,
          "schema": "lets.observation-snapshot/v1"
        },
        "required": [
          "audit_exporter",
          "audit_outbox",
          "audit_verification",
          "authority_anchor",
          "authority_checkpoint",
          "capture_duration_ns",
          "schema",
          "generation",
          "snapshot_id",
          "lifetime_id",
          "revision",
          "capture_started_monotonic_ns",
          "captured_at_ns",
          "captured_at_monotonic_ns",
          "captured_authority_anchor",
          "checked_at_ns",
          "clock_healthy",
          "core_state_revision",
          "database_instance_id",
          "invariant",
          "invariant_healthy",
          "leases",
          "max_age_ns",
          "observation_eligible",
          "peer_dispatcher",
          "published_at_ns",
          "published_at_monotonic_ns",
          "receipts",
          "resources",
          "runtime",
          "signing_key_healthy",
          "sqlite_schema_sha256",
          "storage_capacity",
          "transfers",
          "age_ns",
          "capture_status",
          "fresh",
          "ready",
          "served_at_monotonic_ns",
          "service_ready"
        ],
        "required_non_null": [
          "audit_exporter",
          "audit_outbox",
          "audit_verification",
          "authority_anchor",
          "authority_checkpoint",
          "capture_duration_ns",
          "schema",
          "generation",
          "snapshot_id",
          "lifetime_id",
          "revision",
          "capture_started_monotonic_ns",
          "captured_at_ns",
          "captured_at_monotonic_ns",
          "captured_authority_anchor",
          "checked_at_ns",
          "clock_healthy",
          "core_state_revision",
          "database_instance_id",
          "invariant",
          "invariant_healthy",
          "leases",
          "max_age_ns",
          "observation_eligible",
          "peer_dispatcher",
          "published_at_ns",
          "published_at_monotonic_ns",
          "receipts",
          "resources",
          "runtime",
          "signing_key_healthy",
          "sqlite_schema_sha256",
          "storage_capacity",
          "transfers",
          "age_ns",
          "capture_status",
          "fresh",
          "ready",
          "served_at_monotonic_ns",
          "service_ready"
        ]
      },
      {
        "consts": {},
        "required": [],
        "required_non_null": []
      }
    ]
  },
  "POST /v1/branches/{lease_id}/revoke": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.branch-revocation/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "branch_lease_id",
          "lineage_id",
          "epoch",
          "issuer_warden",
          "issued_at_ns",
          "reason",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "branch_lease_id",
          "lineage_id",
          "epoch",
          "issuer_warden",
          "issued_at_ns",
          "reason",
          "key_id",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/envelopes": {
    "root": "object",
    "statuses": [
      201
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "initial_share",
          "transferred_in",
          "transferred_out",
          "free_pool",
          "lease_residual",
          "consumed",
          "checked_at_ns",
          "healthy"
        ],
        "required_non_null": [
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "initial_share",
          "transferred_in",
          "transferred_out",
          "free_pool",
          "lease_residual",
          "consumed",
          "checked_at_ns",
          "healthy"
        ]
      }
    ]
  },
  "POST /v1/leases/{lease_id}/close": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.lease-snapshot/v1"
        },
        "required": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ],
        "required_non_null": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ]
      }
    ]
  },
  "POST /v1/leases/{lease_id}/quiesce": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.lease-snapshot/v1"
        },
        "required": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ],
        "required_non_null": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ]
      }
    ]
  },
  "POST /v1/leases/{lease_id}/renew": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.lease-snapshot/v1"
        },
        "required": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ],
        "required_non_null": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ]
      }
    ]
  },
  "POST /v1/leases/{lease_id}/resume": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.lease-snapshot/v1"
        },
        "required": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ],
        "required_non_null": [
          "type",
          "grant",
          "residual",
          "current_state",
          "status",
          "sequence",
          "updated_at_ns"
        ]
      }
    ]
  },
  "POST /v1/leases/{lease_id}/transitions": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.receipt/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "receipt_id",
          "request_id",
          "warden_id",
          "key_id",
          "policy_id",
          "policy_version",
          "policy_digest",
          "machine_digest",
          "lease_id",
          "lineage_id",
          "subject_id",
          "executor_audience",
          "transition",
          "source_state",
          "target_state",
          "cost",
          "resulting_sequence",
          "evidence_digest",
          "nonce",
          "issued_at_ns",
          "expires_at_ns",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "receipt_id",
          "request_id",
          "warden_id",
          "key_id",
          "policy_id",
          "policy_version",
          "policy_digest",
          "machine_digest",
          "lease_id",
          "lineage_id",
          "subject_id",
          "executor_audience",
          "transition",
          "source_state",
          "target_state",
          "cost",
          "resulting_sequence",
          "nonce",
          "issued_at_ns",
          "expires_at_ns",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/leases/{parent_id}/children": {
    "root": "object",
    "statuses": [
      201
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.lease-grant/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "lease_id",
          "lineage_id",
          "parent_id",
          "subject_id",
          "warden_id",
          "allocation",
          "capabilities",
          "policy_id",
          "policy_version",
          "policy_digest",
          "machine_digest",
          "ancestor_path",
          "branch_epoch",
          "issued_at_ns",
          "expires_at_ns",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "lease_id",
          "lineage_id",
          "subject_id",
          "warden_id",
          "allocation",
          "capabilities",
          "policy_id",
          "policy_version",
          "policy_digest",
          "machine_digest",
          "ancestor_path",
          "branch_epoch",
          "issued_at_ns",
          "expires_at_ns",
          "key_id",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/maintenance/authority-fence": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "schema": "lets.authority-admission-fence/v1"
        },
        "required": [
          "schema",
          "restart_id",
          "warden_id",
          "namespace_process_id",
          "lifetime_id",
          "fenced_at_monotonic_ns",
          "authority_anchor",
          "authority_checkpoint",
          "terminal_audit_proof"
        ],
        "required_non_null": [
          "schema",
          "restart_id",
          "warden_id",
          "namespace_process_id",
          "lifetime_id",
          "fenced_at_monotonic_ns",
          "authority_anchor",
          "authority_checkpoint",
          "terminal_audit_proof"
        ]
      }
    ]
  },
  "POST /v1/maintenance/reclaim": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "reclaimed"
        ],
        "required_non_null": [
          "reclaimed"
        ]
      }
    ]
  },
  "POST /v1/maintenance/runtime": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "mode",
          "generation",
          "reason",
          "changed_at_ns",
          "changed_by"
        ],
        "required_non_null": [
          "mode",
          "generation",
          "reason",
          "changed_at_ns",
          "changed_by"
        ]
      }
    ]
  },
  "POST /v1/peer/revocations": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.branch-revocation/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "branch_lease_id",
          "lineage_id",
          "epoch",
          "issuer_warden",
          "issued_at_ns",
          "reason",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "branch_lease_id",
          "lineage_id",
          "epoch",
          "issuer_warden",
          "issued_at_ns",
          "reason",
          "key_id",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/peer/transfer-checkpoints": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.transfer-checkpoint/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "source_warden",
          "target_warden",
          "through_sequence",
          "issued_at_ns",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "source_warden",
          "target_warden",
          "through_sequence",
          "issued_at_ns",
          "key_id",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/policies": {
    "root": "object",
    "statuses": [
      201
    ],
    "variants": [
      {
        "consts": {},
        "required": [
          "policy_digest"
        ],
        "required_non_null": [
          "policy_digest"
        ]
      }
    ]
  },
  "POST /v1/roots": {
    "root": "object",
    "statuses": [
      201
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.lease-grant/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "lease_id",
          "lineage_id",
          "parent_id",
          "subject_id",
          "warden_id",
          "allocation",
          "capabilities",
          "policy_id",
          "policy_version",
          "policy_digest",
          "machine_digest",
          "ancestor_path",
          "branch_epoch",
          "issued_at_ns",
          "expires_at_ns",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "lease_id",
          "lineage_id",
          "subject_id",
          "warden_id",
          "allocation",
          "capabilities",
          "policy_id",
          "policy_version",
          "policy_digest",
          "machine_digest",
          "ancestor_path",
          "branch_epoch",
          "issued_at_ns",
          "expires_at_ns",
          "key_id",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/transfers/prepare": {
    "root": "object",
    "statuses": [
      201
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.transfer-voucher/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "transfer_id",
          "source_warden",
          "target_warden",
          "policy_id",
          "policy_version",
          "policy_digest",
          "sequence",
          "amount",
          "issued_at_ns",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "transfer_id",
          "source_warden",
          "target_warden",
          "policy_id",
          "policy_version",
          "policy_digest",
          "sequence",
          "amount",
          "issued_at_ns",
          "key_id",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/transfers/{source_warden}/{sequence}/accept": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.transfer-ack/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "transfer_id",
          "source_warden",
          "target_warden",
          "sequence",
          "voucher_digest",
          "accepted_at_ns",
          "contiguous_watermark",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "transfer_id",
          "source_warden",
          "target_warden",
          "sequence",
          "voucher_digest",
          "accepted_at_ns",
          "contiguous_watermark",
          "key_id",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/transfers/{target_warden}/checkpoints": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.transfer-checkpoint/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "source_warden",
          "target_warden",
          "through_sequence",
          "issued_at_ns",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "source_warden",
          "target_warden",
          "through_sequence",
          "issued_at_ns",
          "key_id",
          "signature"
        ]
      }
    ]
  },
  "POST /v1/transfers/{target_warden}/{sequence}/finalize": {
    "root": "object",
    "statuses": [
      200
    ],
    "variants": [
      {
        "consts": {
          "type": "lets.transfer-ack/v1"
        },
        "required": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "transfer_id",
          "source_warden",
          "target_warden",
          "sequence",
          "voucher_digest",
          "accepted_at_ns",
          "contiguous_watermark",
          "key_id",
          "signature"
        ],
        "required_non_null": [
          "type",
          "tenant_id",
          "envelope_id",
          "config_epoch",
          "transfer_id",
          "source_warden",
          "target_warden",
          "sequence",
          "voucher_digest",
          "accepted_at_ns",
          "contiguous_watermark",
          "key_id",
          "signature"
        ]
      }
    ]
  }
}"""

RESPONSE_CONTRACT: Final[dict[str, dict[str, Any]]] = json.loads(_CONTRACT_JSON)
