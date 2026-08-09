"""SQLite schema for the durable LETS warden state.

The first schema intentionally stores one envelope in each database.  Tenant and
envelope identifiers are nevertheless present on every safety-relevant row so a
future multi-envelope backend can retain the same transaction/repository API.
"""

from __future__ import annotations

APPLICATION_ID = 0x4C455453  # ASCII "LETS"
SCHEMA_VERSION = 2

REQUIRED_TABLES = frozenset(
    {
        "database_metadata",
        "database_instance",
        "runtime_control",
        "envelopes",
        "warden_state",
        "policies",
        "leases",
        "idempotency",
        "receipts",
        "revocations",
        "outgoing_transfer_streams",
        "outgoing_transfers",
        "inbound_transfer_streams",
        "inbound_transfer_gaps",
        "inbound_transfer_acks",
        "audit_log",
        "audit_outbox",
        "peer_delivery_state",
        "peer_delivery_heads",
        "peer_delivery_counters",
        "peer_http_authority",
        "peer_http_replay",
        "executor_replay",
    }
)

REQUIRED_INDEXES = frozenset(
    {
        "ux_policies_digest",
        "ux_policies_active",
        "ix_leases_parent",
        "ix_leases_lineage_status",
        "ix_leases_subject_status",
        "ix_leases_expiry",
        "ix_idempotency_expiry",
        "ux_receipts_lease_sequence",
        "ix_receipts_lease_audience_sequence",
        "ix_receipts_executor_expiry",
        "ix_receipts_request",
        "ix_revocations_branch",
        "ix_outgoing_transfers_status",
        "ux_outgoing_transfer_id",
        "ix_inbound_gaps_sequence",
        "ix_inbound_acks_expiry",
        "ux_inbound_ack_transfer_id",
        "ux_audit_event_hash",
        "ix_audit_entity",
        "ix_audit_outbox_pending",
        "ix_peer_delivery_due",
        "ix_peer_delivery_pending_stream",
        "ix_peer_http_replay_expiry",
        "ix_executor_replay_expiry",
        "ux_executor_replay_nonce",
    }
)

REQUIRED_TRIGGERS = frozenset(
    {
        "audit_log_immutable_delete",
        "audit_log_immutable_update",
        "audit_log_monotonic",
        "database_metadata_immutable",
        "database_metadata_no_delete",
        "database_instance_immutable",
        "database_instance_no_delete",
        "runtime_control_generation_monotonic",
        "runtime_control_no_delete",
        "peer_http_authority_monotonic",
        "peer_http_authority_no_delete",
        "peer_http_replay_immutable_update",
        "peer_delivery_head_delete",
        "peer_delivery_head_insert",
        "peer_delivery_head_terminal_update",
        "peer_delivery_stream_identity_immutable",
        "envelopes_immutable",
        "envelopes_no_delete",
        "inbound_acks_binding_insert",
        "inbound_acks_immutable_update",
        "inbound_stream_epoch_insert",
        "inbound_stream_identity_immutable",
        "leases_signed_identity_immutable",
        "leases_residual_total_delete",
        "leases_residual_total_insert",
        "leases_residual_total_update",
        "leases_vectors_insert",
        "leases_vectors_update",
        "outgoing_stream_epoch_insert",
        "outgoing_stream_identity_immutable",
        "outgoing_transfers_signed_immutable",
        "outgoing_transfers_vector_insert",
        "policies_content_immutable",
        "receipts_immutable_update",
        "receipts_expiry_monotonic",
        "receipts_vector_insert",
        "revocations_epoch_insert",
        "revocations_epoch_update",
        "warden_state_vectors_insert",
        "warden_state_vectors_update",
        "warden_state_clock_floor_monotonic",
    }
)


SCHEMA_STATEMENTS = (
    """
    CREATE TABLE database_metadata (
        singleton                 INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
        schema_version            INTEGER NOT NULL CHECK (schema_version >= 1),
        warden_id                 TEXT NOT NULL CHECK (length(warden_id) BETWEEN 1 AND 512),
        signing_key_id            TEXT NOT NULL CHECK (length(signing_key_id) BETWEEN 1 AND 512),
        signing_public_key_sha256 BLOB NOT NULL CHECK (
            typeof(signing_public_key_sha256) = 'blob'
            AND length(signing_public_key_sha256) = 32
        ),
        created_at_ns             INTEGER NOT NULL CHECK (created_at_ns >= 0)
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE envelopes (
        tenant_id                    TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 512),
        envelope_id                  TEXT NOT NULL CHECK (length(envelope_id) BETWEEN 1 AND 512),
        singleton                    INTEGER NOT NULL UNIQUE CHECK (singleton = 1),
        config_epoch                 INTEGER NOT NULL CHECK (config_epoch >= 1),
        dimension_count              INTEGER NOT NULL CHECK (dimension_count BETWEEN 1 AND 256),
        dimension_metadata_json      BLOB NOT NULL CHECK (typeof(dimension_metadata_json) = 'blob'),
        budget                       BLOB NOT NULL
            CHECK (lets_vector_valid(budget, dimension_count) = 1),
        initial_local_share          BLOB NOT NULL
            CHECK (lets_vector_valid(initial_local_share, dimension_count) = 1),
        receipt_ttl_ns               INTEGER NOT NULL CHECK (receipt_ttl_ns > 0),
        max_clock_uncertainty_ns     INTEGER NOT NULL CHECK (max_clock_uncertainty_ns >= 0),
        transfer_gap_window          INTEGER NOT NULL
                                     CHECK (transfer_gap_window > 0
                                            AND transfer_gap_window <= 1048576),
        config_json                  BLOB NOT NULL CHECK (typeof(config_json) = 'blob'),
        created_at_ns                INTEGER NOT NULL CHECK (created_at_ns >= 0),
        PRIMARY KEY (tenant_id, envelope_id)
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE warden_state (
        tenant_id        TEXT NOT NULL,
        envelope_id      TEXT NOT NULL,
        free_pool        BLOB NOT NULL CHECK (lets_vector_valid(free_pool, NULL) = 1),
        lease_residual   BLOB NOT NULL CHECK (lets_vector_valid(lease_residual, NULL) = 1),
        consumed         BLOB NOT NULL CHECK (lets_vector_valid(consumed, NULL) = 1),
        transferred_in   BLOB NOT NULL CHECK (lets_vector_valid(transferred_in, NULL) = 1),
        transferred_out  BLOB NOT NULL CHECK (lets_vector_valid(transferred_out, NULL) = 1),
        clock_floor_ns    INTEGER CHECK (clock_floor_ns IS NULL OR clock_floor_ns >= 0),
        revision          INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
        updated_at_ns     INTEGER NOT NULL CHECK (updated_at_ns >= 0),
        PRIMARY KEY (tenant_id, envelope_id),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE policies (
        tenant_id       TEXT NOT NULL,
        envelope_id     TEXT NOT NULL,
        policy_version  TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 512),
        policy_digest   TEXT NOT NULL CHECK (length(policy_digest) BETWEEN 1 AND 512),
        machine_digest  TEXT NOT NULL CHECK (length(machine_digest) BETWEEN 1 AND 512),
        payload         BLOB NOT NULL CHECK (typeof(payload) = 'blob'),
        active          INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
        created_at_ns   INTEGER NOT NULL CHECK (created_at_ns >= 0),
        retired_at_ns   INTEGER CHECK (retired_at_ns IS NULL OR retired_at_ns >= created_at_ns),
        PRIMARY KEY (tenant_id, envelope_id, policy_version),
        UNIQUE (tenant_id, envelope_id, policy_version, policy_digest),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE UNIQUE INDEX ux_policies_digest
    ON policies(tenant_id, envelope_id, policy_digest)
    """,
    """
    CREATE UNIQUE INDEX ux_policies_active
    ON policies(tenant_id, envelope_id) WHERE active = 1
    """,
    """
    CREATE TABLE leases (
        tenant_id          TEXT NOT NULL,
        envelope_id        TEXT NOT NULL,
        lease_id           TEXT NOT NULL CHECK (length(lease_id) BETWEEN 1 AND 512),
        lineage_id         TEXT NOT NULL CHECK (length(lineage_id) BETWEEN 1 AND 512),
        parent_id          TEXT CHECK (parent_id IS NULL OR length(parent_id) BETWEEN 1 AND 512),
        subject_id         TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 512),
        warden_id          TEXT NOT NULL CHECK (length(warden_id) BETWEEN 1 AND 512),
        allocation         BLOB NOT NULL CHECK (lets_vector_valid(allocation, NULL) = 1),
        residual           BLOB NOT NULL CHECK (lets_vector_valid(residual, NULL) = 1),
        capabilities_json  BLOB NOT NULL CHECK (typeof(capabilities_json) = 'blob'),
        machine_digest     TEXT NOT NULL CHECK (length(machine_digest) BETWEEN 1 AND 512),
        ancestor_path_json BLOB NOT NULL CHECK (typeof(ancestor_path_json) = 'blob'),
        branch_epoch       INTEGER NOT NULL CHECK (branch_epoch >= 0),
        config_epoch       INTEGER NOT NULL CHECK (config_epoch >= 1),
        issued_at_ns       INTEGER NOT NULL CHECK (issued_at_ns >= 0),
        expires_at_ns      INTEGER NOT NULL CHECK (expires_at_ns >= issued_at_ns),
        key_id             TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 512),
        signature          BLOB NOT NULL CHECK (
            typeof(signature) = 'blob' AND length(signature) > 0
        ),
        state              TEXT NOT NULL CHECK (length(state) BETWEEN 1 AND 512),
        status             TEXT NOT NULL CHECK (
            status IN ('PROVISIONED', 'ACTIVE', 'QUIESCENT', 'MIGRATING',
                       'REVOKED', 'EXPIRED', 'TERMINATED', 'CLOSED')
        ),
        sequence           INTEGER NOT NULL DEFAULT 0 CHECK (sequence >= 0),
        policy_version     TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 512),
        policy_digest      TEXT NOT NULL CHECK (length(policy_digest) BETWEEN 1 AND 512),
        created_at_ns      INTEGER NOT NULL CHECK (created_at_ns >= 0),
        updated_at_ns      INTEGER NOT NULL CHECK (updated_at_ns >= created_at_ns),
        PRIMARY KEY (tenant_id, envelope_id, lease_id),
        FOREIGN KEY (tenant_id, envelope_id, parent_id)
            REFERENCES leases(tenant_id, envelope_id, lease_id)
            DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (tenant_id, envelope_id, policy_version, policy_digest)
            REFERENCES policies(tenant_id, envelope_id, policy_version, policy_digest)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_leases_parent
    ON leases(tenant_id, envelope_id, parent_id)
    """,
    """
    CREATE INDEX ix_leases_lineage_status
    ON leases(tenant_id, envelope_id, lineage_id, status)
    """,
    """
    CREATE INDEX ix_leases_subject_status
    ON leases(tenant_id, envelope_id, subject_id, status)
    """,
    """
    CREATE INDEX ix_leases_expiry
    ON leases(tenant_id, envelope_id, expires_at_ns)
    WHERE status IN ('PROVISIONED', 'ACTIVE', 'QUIESCENT', 'MIGRATING', 'REVOKED')
    """,
    """
    CREATE TABLE idempotency (
        tenant_id     TEXT NOT NULL,
        envelope_id   TEXT NOT NULL,
        scope         TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 512),
        request_id    TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
        fingerprint   BLOB NOT NULL CHECK (
            typeof(fingerprint) = 'blob' AND length(fingerprint) > 0
        ),
        response      BLOB NOT NULL CHECK (typeof(response) = 'blob'),
        status_code   INTEGER NOT NULL CHECK (status_code BETWEEN 100 AND 599),
        created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
        expires_at_ns INTEGER CHECK (expires_at_ns IS NULL OR expires_at_ns >= created_at_ns),
        PRIMARY KEY (tenant_id, envelope_id, request_id),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE CASCADE
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_idempotency_expiry
    ON idempotency(tenant_id, envelope_id, expires_at_ns)
    WHERE expires_at_ns IS NOT NULL
    """,
    """
    CREATE TABLE receipts (
        tenant_id           TEXT NOT NULL,
        envelope_id         TEXT NOT NULL,
        receipt_id          TEXT NOT NULL CHECK (length(receipt_id) BETWEEN 1 AND 512),
        request_id          TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 512),
        warden_id           TEXT NOT NULL CHECK (length(warden_id) BETWEEN 1 AND 512),
        key_id              TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 512),
        config_epoch        INTEGER NOT NULL CHECK (config_epoch >= 1),
        policy_version      TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 512),
        policy_digest       TEXT NOT NULL CHECK (length(policy_digest) BETWEEN 1 AND 512),
        machine_digest      TEXT NOT NULL CHECK (length(machine_digest) BETWEEN 1 AND 512),
        lease_id            TEXT NOT NULL CHECK (length(lease_id) BETWEEN 1 AND 512),
        lineage_id          TEXT NOT NULL CHECK (length(lineage_id) BETWEEN 1 AND 512),
        subject_id          TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 512),
        executor_audience   TEXT NOT NULL CHECK (length(executor_audience) BETWEEN 1 AND 512),
        transition_name     TEXT NOT NULL CHECK (length(transition_name) BETWEEN 1 AND 512),
        source_state        TEXT NOT NULL CHECK (length(source_state) BETWEEN 1 AND 512),
        target_state        TEXT NOT NULL CHECK (length(target_state) BETWEEN 1 AND 512),
        cost                BLOB NOT NULL CHECK (lets_vector_valid(cost, NULL) = 1),
        resulting_sequence  INTEGER NOT NULL CHECK (resulting_sequence > 0),
        evidence_digest     TEXT CHECK (
            evidence_digest IS NULL OR length(evidence_digest) BETWEEN 1 AND 512
        ),
        nonce               TEXT NOT NULL CHECK (length(nonce) BETWEEN 1 AND 512),
        issued_at_ns        INTEGER NOT NULL CHECK (issued_at_ns >= 0),
        expires_at_ns       INTEGER NOT NULL CHECK (expires_at_ns >= issued_at_ns),
        signature           BLOB NOT NULL CHECK (
            typeof(signature) = 'blob' AND length(signature) > 0
        ),
        payload             BLOB NOT NULL CHECK (typeof(payload) = 'blob'),
        PRIMARY KEY (tenant_id, envelope_id, receipt_id),
        FOREIGN KEY (tenant_id, envelope_id, lease_id)
            REFERENCES leases(tenant_id, envelope_id, lease_id) ON DELETE RESTRICT,
        FOREIGN KEY (tenant_id, envelope_id, policy_version, policy_digest)
            REFERENCES policies(tenant_id, envelope_id, policy_version, policy_digest)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE UNIQUE INDEX ux_receipts_lease_sequence
    ON receipts(tenant_id, envelope_id, lease_id, resulting_sequence)
    """,
    """
    CREATE INDEX ix_receipts_lease_audience_sequence
    ON receipts(
        tenant_id, envelope_id, lease_id, executor_audience, resulting_sequence DESC
    )
    """,
    """
    CREATE INDEX ix_receipts_executor_expiry
    ON receipts(tenant_id, envelope_id, executor_audience, expires_at_ns)
    """,
    """
    CREATE INDEX ix_receipts_request
    ON receipts(tenant_id, envelope_id, request_id)
    """,
    """
    CREATE TABLE revocations (
        tenant_id       TEXT NOT NULL,
        envelope_id     TEXT NOT NULL,
        lineage_id      TEXT NOT NULL CHECK (length(lineage_id) BETWEEN 1 AND 512),
        branch_lease_id TEXT NOT NULL CHECK (length(branch_lease_id) BETWEEN 1 AND 512),
        epoch           INTEGER NOT NULL CHECK (epoch > 0),
        config_epoch    INTEGER NOT NULL CHECK (config_epoch >= 1),
        observed_at_ns  INTEGER NOT NULL CHECK (observed_at_ns >= 0),
        source_warden   TEXT NOT NULL CHECK (length(source_warden) BETWEEN 1 AND 512),
        reason           TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
        key_id           TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 512),
        issued_at_ns     INTEGER NOT NULL CHECK (
            issued_at_ns >= 0 AND observed_at_ns >= issued_at_ns
        ),
        signature        BLOB NOT NULL CHECK (
            typeof(signature) = 'blob' AND length(signature) > 0
        ),
        payload           BLOB NOT NULL CHECK (typeof(payload) = 'blob'),
        PRIMARY KEY (tenant_id, envelope_id, lineage_id, branch_lease_id),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_revocations_branch
    ON revocations(tenant_id, envelope_id, branch_lease_id, epoch)
    """,
    """
    CREATE TABLE outgoing_transfer_streams (
        tenant_id      TEXT NOT NULL,
        envelope_id    TEXT NOT NULL,
        target_warden  TEXT NOT NULL CHECK (length(target_warden) BETWEEN 1 AND 512),
        config_epoch   INTEGER NOT NULL CHECK (config_epoch >= 1),
        next_sequence  INTEGER NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
        acked_through  INTEGER NOT NULL DEFAULT 0 CHECK (acked_through >= 0),
        compacted_through INTEGER NOT NULL DEFAULT 0 CHECK (compacted_through >= 0),
        checkpoint_payload BLOB CHECK (
            checkpoint_payload IS NULL OR typeof(checkpoint_payload) = 'blob'
        ),
        updated_at_ns  INTEGER NOT NULL CHECK (updated_at_ns >= 0),
        CHECK (acked_through < next_sequence),
        CHECK (compacted_through <= acked_through),
        CHECK (compacted_through = 0 OR checkpoint_payload IS NOT NULL),
        PRIMARY KEY (tenant_id, envelope_id, target_warden),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE outgoing_transfers (
        tenant_id          TEXT NOT NULL,
        envelope_id        TEXT NOT NULL,
        transfer_id        TEXT NOT NULL CHECK (length(transfer_id) BETWEEN 1 AND 512),
        source_warden      TEXT NOT NULL CHECK (length(source_warden) BETWEEN 1 AND 512),
        target_warden      TEXT NOT NULL CHECK (length(target_warden) BETWEEN 1 AND 512),
        sequence           INTEGER NOT NULL CHECK (sequence > 0),
        config_epoch       INTEGER NOT NULL CHECK (config_epoch >= 1),
        amount             BLOB NOT NULL CHECK (
            lets_vector_valid(amount, NULL) = 1 AND lets_vector_nonzero(amount) = 1
        ),
        policy_version     TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 512),
        policy_digest      TEXT NOT NULL CHECK (length(policy_digest) BETWEEN 1 AND 512),
        digest             TEXT NOT NULL CHECK (length(digest) BETWEEN 1 AND 512),
        key_id             TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 512),
        signature          BLOB NOT NULL CHECK (
            typeof(signature) = 'blob' AND length(signature) > 0
        ),
        voucher_payload    BLOB NOT NULL CHECK (typeof(voucher_payload) = 'blob'),
        status             TEXT NOT NULL DEFAULT 'PREPARED'
            CHECK (
                status IN ('PREPARED', 'ACCEPTED', 'FINALIZED', 'ACKNOWLEDGED', 'CANCELLED')
            ),
        prepared_at_ns     INTEGER NOT NULL CHECK (prepared_at_ns >= 0),
        acknowledged_at_ns INTEGER CHECK (
            acknowledged_at_ns IS NULL OR acknowledged_at_ns >= prepared_at_ns
        ),
        ack_payload        BLOB CHECK (ack_payload IS NULL OR typeof(ack_payload) = 'blob'),
        PRIMARY KEY (tenant_id, envelope_id, target_warden, sequence),
        UNIQUE (tenant_id, envelope_id, digest),
        FOREIGN KEY (tenant_id, envelope_id, target_warden)
            REFERENCES outgoing_transfer_streams(tenant_id, envelope_id, target_warden)
            ON DELETE RESTRICT,
        FOREIGN KEY (tenant_id, envelope_id, policy_version, policy_digest)
            REFERENCES policies(tenant_id, envelope_id, policy_version, policy_digest)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_outgoing_transfers_status
    ON outgoing_transfers(tenant_id, envelope_id, status, target_warden, sequence)
    """,
    """
    CREATE UNIQUE INDEX ux_outgoing_transfer_id
    ON outgoing_transfers(tenant_id, envelope_id, transfer_id)
    """,
    """
    CREATE TABLE inbound_transfer_streams (
        tenant_id          TEXT NOT NULL,
        envelope_id        TEXT NOT NULL,
        source_warden      TEXT NOT NULL CHECK (length(source_warden) BETWEEN 1 AND 512),
        config_epoch       INTEGER NOT NULL CHECK (config_epoch >= 1),
        contiguous_through INTEGER NOT NULL DEFAULT 0 CHECK (contiguous_through >= 0),
        highest_seen       INTEGER NOT NULL DEFAULT 0 CHECK (highest_seen >= contiguous_through),
        compacted_through  INTEGER NOT NULL DEFAULT 0 CHECK (compacted_through >= 0),
        checkpoint_payload BLOB CHECK (
            checkpoint_payload IS NULL OR typeof(checkpoint_payload) = 'blob'
        ),
        updated_at_ns      INTEGER NOT NULL CHECK (updated_at_ns >= 0),
        CHECK (compacted_through <= contiguous_through),
        CHECK (compacted_through = 0 OR checkpoint_payload IS NOT NULL),
        PRIMARY KEY (tenant_id, envelope_id, source_warden),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE inbound_transfer_gaps (
        tenant_id      TEXT NOT NULL,
        envelope_id    TEXT NOT NULL,
        source_warden  TEXT NOT NULL CHECK (length(source_warden) BETWEEN 1 AND 512),
        sequence       INTEGER NOT NULL CHECK (sequence > 0),
        observed_at_ns INTEGER NOT NULL CHECK (observed_at_ns >= 0),
        PRIMARY KEY (tenant_id, envelope_id, source_warden, sequence),
        FOREIGN KEY (tenant_id, envelope_id, source_warden)
            REFERENCES inbound_transfer_streams(tenant_id, envelope_id, source_warden)
            ON DELETE CASCADE
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_inbound_gaps_sequence
    ON inbound_transfer_gaps(tenant_id, envelope_id, source_warden, sequence)
    """,
    """
    CREATE TABLE inbound_transfer_acks (
        tenant_id       TEXT NOT NULL,
        envelope_id     TEXT NOT NULL,
        transfer_id     TEXT NOT NULL CHECK (length(transfer_id) BETWEEN 1 AND 512),
        source_warden   TEXT NOT NULL CHECK (length(source_warden) BETWEEN 1 AND 512),
        target_warden   TEXT NOT NULL CHECK (length(target_warden) BETWEEN 1 AND 512),
        sequence        INTEGER NOT NULL CHECK (sequence > 0),
        config_epoch    INTEGER NOT NULL CHECK (config_epoch >= 1),
        transfer_digest TEXT NOT NULL CHECK (length(transfer_digest) BETWEEN 1 AND 512),
        contiguous_watermark INTEGER NOT NULL CHECK (contiguous_watermark >= 0),
        key_id           TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 512),
        ack_payload     BLOB NOT NULL CHECK (typeof(ack_payload) = 'blob'),
        signature       BLOB NOT NULL CHECK (typeof(signature) = 'blob' AND length(signature) > 0),
        accepted_at_ns  INTEGER NOT NULL CHECK (accepted_at_ns >= 0),
        expires_at_ns   INTEGER CHECK (expires_at_ns IS NULL OR expires_at_ns >= accepted_at_ns),
        PRIMARY KEY (tenant_id, envelope_id, source_warden, sequence),
        FOREIGN KEY (tenant_id, envelope_id, source_warden)
            REFERENCES inbound_transfer_streams(tenant_id, envelope_id, source_warden)
            ON DELETE CASCADE
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_inbound_acks_expiry
    ON inbound_transfer_acks(tenant_id, envelope_id, expires_at_ns)
    WHERE expires_at_ns IS NOT NULL
    """,
    """
    CREATE UNIQUE INDEX ux_inbound_ack_transfer_id
    ON inbound_transfer_acks(tenant_id, envelope_id, source_warden, transfer_id)
    """,
    """
    CREATE TABLE audit_log (
        tenant_id      TEXT NOT NULL,
        envelope_id    TEXT NOT NULL,
        sequence       INTEGER NOT NULL CHECK (sequence >= 0),
        event_type     TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 512),
        entity_type    TEXT CHECK (entity_type IS NULL OR length(entity_type) BETWEEN 1 AND 512),
        entity_id      TEXT CHECK (entity_id IS NULL OR length(entity_id) BETWEEN 1 AND 512),
        payload        BLOB NOT NULL CHECK (typeof(payload) = 'blob'),
        previous_hash  BLOB NOT NULL CHECK (
            typeof(previous_hash) = 'blob' AND length(previous_hash) = 32
        ),
        event_hash     BLOB NOT NULL CHECK (
            typeof(event_hash) = 'blob'
            AND length(event_hash) = 32
            AND event_hash = lets_audit_hash(
                previous_hash, sequence, event_type, entity_type, entity_id, payload, created_at_ns
            )
        ),
        created_at_ns  INTEGER NOT NULL CHECK (created_at_ns >= 0),
        PRIMARY KEY (tenant_id, envelope_id, sequence),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE UNIQUE INDEX ux_audit_event_hash
    ON audit_log(tenant_id, envelope_id, event_hash)
    """,
    """
    CREATE INDEX ix_audit_entity
    ON audit_log(tenant_id, envelope_id, entity_type, entity_id, sequence)
    """,
    """
    CREATE TABLE audit_outbox (
        tenant_id       TEXT NOT NULL,
        envelope_id     TEXT NOT NULL,
        sequence        INTEGER NOT NULL CHECK (sequence >= 0),
        event_hash      BLOB NOT NULL CHECK (
            typeof(event_hash) = 'blob' AND length(event_hash) = 32
        ),
        payload         BLOB NOT NULL CHECK (typeof(payload) = 'blob'),
        created_at_ns   INTEGER NOT NULL CHECK (created_at_ns >= 0),
        published_at_ns INTEGER CHECK (published_at_ns IS NULL OR published_at_ns >= created_at_ns),
        attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        last_error      TEXT,
        PRIMARY KEY (tenant_id, envelope_id, sequence),
        FOREIGN KEY (tenant_id, envelope_id, sequence)
            REFERENCES audit_log(tenant_id, envelope_id, sequence) ON DELETE CASCADE
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_audit_outbox_pending
    ON audit_outbox(tenant_id, envelope_id, sequence)
    WHERE published_at_ns IS NULL
    """,
    """
    CREATE TABLE peer_delivery_state (
        record_kind       TEXT NOT NULL CHECK (
            record_kind IN ('transfer', 'revocation', 'checkpoint')
        ),
        record_id         TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 512),
        target_warden     TEXT NOT NULL CHECK (length(target_warden) BETWEEN 1 AND 128),
        ordering_key      TEXT NOT NULL CHECK (length(ordering_key) BETWEEN 1 AND 512),
        stream_position   INTEGER NOT NULL CHECK (stream_position > 0),
        payload           BLOB NOT NULL CHECK (typeof(payload) = 'blob'),
        created_at_ns     INTEGER NOT NULL CHECK (created_at_ns >= 0),
        attempts          INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        next_attempt_ns   INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_ns >= 0),
        last_attempt_ns   INTEGER CHECK (last_attempt_ns IS NULL OR last_attempt_ns >= 0),
        delivered_at_ns  INTEGER CHECK (delivered_at_ns IS NULL OR delivered_at_ns >= 0),
        superseded_at_ns INTEGER CHECK (superseded_at_ns IS NULL OR superseded_at_ns >= 0),
        last_error        TEXT CHECK (last_error IS NULL OR length(last_error) <= 500),
        CHECK (delivered_at_ns IS NULL OR superseded_at_ns IS NULL),
        PRIMARY KEY (record_kind, record_id, target_warden)
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_peer_delivery_due
    ON peer_delivery_state(delivered_at_ns, superseded_at_ns, next_attempt_ns, target_warden)
    """,
    """
    CREATE INDEX ix_peer_delivery_pending_stream
    ON peer_delivery_state(
        target_warden, record_kind, ordering_key,
        stream_position, created_at_ns, record_id
    )
    WHERE delivered_at_ns IS NULL AND superseded_at_ns IS NULL
    """,
    """
    CREATE TABLE peer_delivery_heads (
        target_warden   TEXT NOT NULL CHECK (length(target_warden) BETWEEN 1 AND 128),
        record_kind     TEXT NOT NULL CHECK (
            record_kind IN ('transfer', 'revocation', 'checkpoint')
        ),
        ordering_key    TEXT NOT NULL CHECK (length(ordering_key) BETWEEN 1 AND 512),
        record_id       TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 512),
        stream_position INTEGER NOT NULL CHECK (stream_position > 0),
        created_at_ns   INTEGER NOT NULL CHECK (created_at_ns >= 0),
        PRIMARY KEY (target_warden, record_kind, ordering_key),
        FOREIGN KEY (record_kind, record_id, target_warden)
            REFERENCES peer_delivery_state(record_kind, record_id, target_warden)
            ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TRIGGER peer_delivery_head_insert
    AFTER INSERT ON peer_delivery_state
    WHEN NEW.delivered_at_ns IS NULL AND NEW.superseded_at_ns IS NULL
    BEGIN
        INSERT INTO peer_delivery_heads(
            target_warden, record_kind, ordering_key,
            record_id, stream_position, created_at_ns
        ) VALUES (
            NEW.target_warden, NEW.record_kind, NEW.ordering_key,
            NEW.record_id, NEW.stream_position, NEW.created_at_ns
        )
        ON CONFLICT(target_warden, record_kind, ordering_key) DO UPDATE SET
            record_id = excluded.record_id,
            stream_position = excluded.stream_position,
            created_at_ns = excluded.created_at_ns
        WHERE (
            excluded.stream_position,
            excluded.created_at_ns,
            excluded.record_id
        ) < (
            peer_delivery_heads.stream_position,
            peer_delivery_heads.created_at_ns,
            peer_delivery_heads.record_id
        );
    END
    """,
    """
    CREATE TRIGGER peer_delivery_head_terminal_update
    AFTER UPDATE OF delivered_at_ns, superseded_at_ns ON peer_delivery_state
    WHEN NEW.delivered_at_ns IS NOT OLD.delivered_at_ns
      OR NEW.superseded_at_ns IS NOT OLD.superseded_at_ns
    BEGIN
        DELETE FROM peer_delivery_heads
        WHERE target_warden = OLD.target_warden
          AND record_kind = OLD.record_kind
          AND ordering_key = OLD.ordering_key
          AND record_id = OLD.record_id;

        INSERT INTO peer_delivery_heads(
            target_warden, record_kind, ordering_key,
            record_id, stream_position, created_at_ns
        )
        SELECT target_warden, record_kind, ordering_key,
               record_id, stream_position, created_at_ns
        FROM peer_delivery_state
        WHERE target_warden = OLD.target_warden
          AND record_kind = OLD.record_kind
          AND ordering_key = OLD.ordering_key
          AND delivered_at_ns IS NULL
          AND superseded_at_ns IS NULL
        ORDER BY stream_position, created_at_ns, record_id
        LIMIT 1
        ON CONFLICT(target_warden, record_kind, ordering_key) DO UPDATE SET
            record_id = excluded.record_id,
            stream_position = excluded.stream_position,
            created_at_ns = excluded.created_at_ns;
    END
    """,
    """
    CREATE TRIGGER peer_delivery_head_delete
    AFTER DELETE ON peer_delivery_state
    BEGIN
        DELETE FROM peer_delivery_heads
        WHERE target_warden = OLD.target_warden
          AND record_kind = OLD.record_kind
          AND ordering_key = OLD.ordering_key
          AND record_id = OLD.record_id;

        INSERT INTO peer_delivery_heads(
            target_warden, record_kind, ordering_key,
            record_id, stream_position, created_at_ns
        )
        SELECT target_warden, record_kind, ordering_key,
               record_id, stream_position, created_at_ns
        FROM peer_delivery_state
        WHERE target_warden = OLD.target_warden
          AND record_kind = OLD.record_kind
          AND ordering_key = OLD.ordering_key
          AND delivered_at_ns IS NULL
          AND superseded_at_ns IS NULL
        ORDER BY stream_position, created_at_ns, record_id
        LIMIT 1
        ON CONFLICT(target_warden, record_kind, ordering_key) DO UPDATE SET
            record_id = excluded.record_id,
            stream_position = excluded.stream_position,
            created_at_ns = excluded.created_at_ns;
    END
    """,
    """
    CREATE TRIGGER peer_delivery_stream_identity_immutable
    BEFORE UPDATE OF record_kind, record_id, target_warden, ordering_key,
                     stream_position, payload, created_at_ns
    ON peer_delivery_state
    BEGIN
        SELECT RAISE(ABORT, 'peer delivery stream identity is immutable');
    END
    """,
    """
    INSERT INTO peer_delivery_heads(
        target_warden, record_kind, ordering_key,
        record_id, stream_position, created_at_ns
    )
    SELECT candidate.target_warden, candidate.record_kind, candidate.ordering_key,
           candidate.record_id, candidate.stream_position, candidate.created_at_ns
    FROM peer_delivery_state AS candidate
    WHERE candidate.delivered_at_ns IS NULL
      AND candidate.superseded_at_ns IS NULL
      AND NOT EXISTS (
          SELECT 1
          FROM peer_delivery_state AS earlier
          WHERE earlier.target_warden = candidate.target_warden
            AND earlier.record_kind = candidate.record_kind
            AND earlier.ordering_key = candidate.ordering_key
            AND earlier.delivered_at_ns IS NULL
            AND earlier.superseded_at_ns IS NULL
            AND (
                earlier.stream_position,
                earlier.created_at_ns,
                earlier.record_id
            ) < (
                candidate.stream_position,
                candidate.created_at_ns,
                candidate.record_id
            )
      )
    """,
    """
    CREATE TABLE peer_delivery_counters (
        record_kind       TEXT NOT NULL CHECK (
            record_kind IN ('transfer', 'revocation', 'checkpoint')
        ),
        target_warden     TEXT NOT NULL CHECK (length(target_warden) BETWEEN 1 AND 128),
        delivered_count  INTEGER NOT NULL DEFAULT 0 CHECK (delivered_count >= 0),
        superseded_count INTEGER NOT NULL DEFAULT 0 CHECK (superseded_count >= 0),
        last_terminal_ns INTEGER NOT NULL CHECK (last_terminal_ns >= 0),
        PRIMARY KEY (record_kind, target_warden)
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE executor_replay (
        tenant_id         TEXT NOT NULL,
        envelope_id       TEXT NOT NULL,
        executor_audience TEXT NOT NULL CHECK (length(executor_audience) BETWEEN 1 AND 512),
        receipt_id        TEXT NOT NULL CHECK (length(receipt_id) BETWEEN 1 AND 512),
        receipt_digest    TEXT NOT NULL CHECK (length(receipt_digest) BETWEEN 1 AND 512),
        nonce             TEXT CHECK (nonce IS NULL OR length(nonce) BETWEEN 1 AND 512),
        consumed_at_ns    INTEGER NOT NULL CHECK (consumed_at_ns >= 0),
        expires_at_ns     INTEGER NOT NULL CHECK (expires_at_ns >= consumed_at_ns),
        PRIMARY KEY (tenant_id, envelope_id, executor_audience, receipt_id),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE CASCADE
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_executor_replay_expiry
    ON executor_replay(tenant_id, envelope_id, expires_at_ns)
    """,
    """
    CREATE UNIQUE INDEX ux_executor_replay_nonce
    ON executor_replay(tenant_id, envelope_id, executor_audience, nonce)
    WHERE nonce IS NOT NULL
    """,
    """
    CREATE TRIGGER database_metadata_immutable
    BEFORE UPDATE OF warden_id, signing_key_id, signing_public_key_sha256, created_at_ns
    ON database_metadata
    BEGIN
        SELECT RAISE(ABORT, 'database identity metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER database_metadata_no_delete
    BEFORE DELETE ON database_metadata
    BEGIN
        SELECT RAISE(ABORT, 'database metadata cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER warden_state_clock_floor_monotonic
    BEFORE UPDATE OF clock_floor_ns ON warden_state
    WHEN OLD.clock_floor_ns IS NOT NULL AND (
        NEW.clock_floor_ns IS NULL OR NEW.clock_floor_ns < OLD.clock_floor_ns
    )
    BEGIN
        SELECT RAISE(ABORT, 'warden clock floor cannot move backward');
    END
    """,
    """
    CREATE TRIGGER envelopes_immutable
    BEFORE UPDATE ON envelopes
    BEGIN
        SELECT RAISE(ABORT, 'envelope metadata is immutable');
    END
    """,
    """
    CREATE TRIGGER envelopes_no_delete
    BEFORE DELETE ON envelopes
    BEGIN
        SELECT RAISE(ABORT, 'envelope metadata cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER warden_state_vectors_insert
    BEFORE INSERT ON warden_state
    BEGIN
        SELECT CASE WHEN
            lets_vector_dimensions(NEW.free_pool) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.lease_residual) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.consumed) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.transferred_in) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.transferred_out) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) THEN RAISE(ABORT, 'resource-vector dimension mismatch') END;
    END
    """,
    """
    CREATE TRIGGER warden_state_vectors_update
    BEFORE UPDATE OF free_pool, lease_residual, consumed, transferred_in, transferred_out
    ON warden_state
    BEGIN
        SELECT CASE WHEN
            lets_vector_dimensions(NEW.free_pool) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.lease_residual) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.consumed) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.transferred_in) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.transferred_out) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) THEN RAISE(ABORT, 'resource-vector dimension mismatch') END;
    END
    """,
    """
    CREATE TRIGGER leases_vectors_insert
    BEFORE INSERT ON leases
    BEGIN
        SELECT CASE WHEN
            lets_vector_dimensions(NEW.allocation) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.residual) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) THEN RAISE(ABORT, 'resource-vector dimension mismatch') END;
        SELECT CASE WHEN NEW.warden_id != (
            SELECT warden_id FROM database_metadata WHERE singleton = 1
        ) THEN RAISE(ABORT, 'lease warden mismatch') END;
        SELECT CASE WHEN NEW.config_epoch != (
            SELECT config_epoch FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'lease config epoch mismatch') END;
    END
    """,
    """
    CREATE TRIGGER leases_vectors_update
    BEFORE UPDATE OF allocation, residual, warden_id, config_epoch ON leases
    BEGIN
        SELECT CASE WHEN
            lets_vector_dimensions(NEW.allocation) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) OR lets_vector_dimensions(NEW.residual) != (
                SELECT dimension_count FROM envelopes
                WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ) THEN RAISE(ABORT, 'resource-vector dimension mismatch') END;
        SELECT CASE WHEN NEW.warden_id != (
            SELECT warden_id FROM database_metadata WHERE singleton = 1
        ) THEN RAISE(ABORT, 'lease warden mismatch') END;
    END
    """,
    """
    CREATE TRIGGER leases_signed_identity_immutable
    BEFORE UPDATE OF
        tenant_id, envelope_id, lease_id, lineage_id, parent_id, subject_id,
        warden_id, allocation, capabilities_json, machine_digest,
        ancestor_path_json, config_epoch, policy_version, policy_digest, created_at_ns
    ON leases
    BEGIN
        SELECT RAISE(ABORT, 'signed lease identity is immutable');
    END
    """,
    """
    CREATE TRIGGER leases_residual_total_insert
    AFTER INSERT ON leases
    BEGIN
        UPDATE warden_state
        SET lease_residual = lets_vector_add(lease_residual, NEW.residual)
        WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id;
    END
    """,
    """
    CREATE TRIGGER leases_residual_total_update
    AFTER UPDATE OF residual ON leases
    BEGIN
        UPDATE warden_state
        SET lease_residual = lets_vector_add(
            lets_vector_subtract(lease_residual, OLD.residual),
            NEW.residual
        )
        WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id;
    END
    """,
    """
    CREATE TRIGGER leases_residual_total_delete
    AFTER DELETE ON leases
    BEGIN
        UPDATE warden_state
        SET lease_residual = lets_vector_subtract(lease_residual, OLD.residual)
        WHERE tenant_id = OLD.tenant_id AND envelope_id = OLD.envelope_id;
    END
    """,
    """
    CREATE TRIGGER receipts_vector_insert
    BEFORE INSERT ON receipts
    BEGIN
        SELECT CASE WHEN lets_vector_dimensions(NEW.cost) != (
            SELECT dimension_count FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'resource-vector dimension mismatch') END;
        SELECT CASE WHEN NEW.warden_id != (
            SELECT warden_id FROM database_metadata WHERE singleton = 1
        ) THEN RAISE(ABORT, 'receipt warden mismatch') END;
        SELECT CASE WHEN NEW.config_epoch != (
            SELECT config_epoch FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'receipt config epoch mismatch') END;
    END
    """,
    """
    CREATE TRIGGER receipts_immutable_update
    BEFORE UPDATE ON receipts
    BEGIN
        SELECT RAISE(ABORT, 'receipts are immutable');
    END
    """,
    """
    CREATE TRIGGER receipts_expiry_monotonic
    BEFORE INSERT ON receipts
    BEGIN
        SELECT CASE WHEN EXISTS (
            SELECT 1 FROM receipts
            WHERE tenant_id = NEW.tenant_id
              AND envelope_id = NEW.envelope_id
              AND lease_id = NEW.lease_id
              AND executor_audience = NEW.executor_audience
              AND resulting_sequence < NEW.resulting_sequence
              AND expires_at_ns > NEW.expires_at_ns
        ) THEN RAISE(ABORT, 'receipt expiry regresses below an earlier sequence') END;
        SELECT CASE WHEN EXISTS (
            SELECT 1 FROM receipts
            WHERE tenant_id = NEW.tenant_id
              AND envelope_id = NEW.envelope_id
              AND lease_id = NEW.lease_id
              AND executor_audience = NEW.executor_audience
              AND resulting_sequence > NEW.resulting_sequence
              AND expires_at_ns < NEW.expires_at_ns
        ) THEN RAISE(ABORT, 'receipt expiry exceeds a later sequence') END;
    END
    """,
    """
    CREATE TRIGGER policies_content_immutable
    BEFORE UPDATE OF
        tenant_id, envelope_id, policy_version, policy_digest, machine_digest,
        payload, created_at_ns
    ON policies
    BEGIN
        SELECT RAISE(ABORT, 'policy content is immutable');
    END
    """,
    """
    CREATE TRIGGER outgoing_stream_epoch_insert
    BEFORE INSERT ON outgoing_transfer_streams
    BEGIN
        SELECT CASE WHEN NEW.config_epoch != (
            SELECT config_epoch FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'outgoing stream config epoch mismatch') END;
        SELECT CASE WHEN NEW.target_warden = (
            SELECT warden_id FROM database_metadata WHERE singleton = 1
        ) THEN RAISE(ABORT, 'outgoing transfer target must be remote') END;
    END
    """,
    """
    CREATE TRIGGER outgoing_stream_identity_immutable
    BEFORE UPDATE OF tenant_id, envelope_id, target_warden, config_epoch
    ON outgoing_transfer_streams
    BEGIN
        SELECT RAISE(ABORT, 'outgoing stream identity is immutable');
    END
    """,
    """
    CREATE TRIGGER outgoing_transfers_vector_insert
    BEFORE INSERT ON outgoing_transfers
    BEGIN
        SELECT CASE WHEN lets_vector_dimensions(NEW.amount) != (
            SELECT dimension_count FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'resource-vector dimension mismatch') END;
        SELECT CASE WHEN NEW.config_epoch != (
            SELECT config_epoch FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'transfer config epoch mismatch') END;
        SELECT CASE WHEN NEW.source_warden != (
            SELECT warden_id FROM database_metadata WHERE singleton = 1
        ) THEN RAISE(ABORT, 'outgoing transfer source mismatch') END;
        SELECT CASE WHEN NEW.source_warden = NEW.target_warden
            THEN RAISE(ABORT, 'transfer source and target must differ') END;
    END
    """,
    """
    CREATE TRIGGER outgoing_transfers_signed_immutable
    BEFORE UPDATE OF
        tenant_id, envelope_id, transfer_id, source_warden, target_warden,
        sequence, config_epoch, amount, policy_version, policy_digest, digest,
        key_id, signature, voucher_payload, prepared_at_ns
    ON outgoing_transfers
    BEGIN
        SELECT RAISE(ABORT, 'signed outgoing transfer is immutable');
    END
    """,
    """
    CREATE TRIGGER inbound_stream_epoch_insert
    BEFORE INSERT ON inbound_transfer_streams
    BEGIN
        SELECT CASE WHEN NEW.config_epoch != (
            SELECT config_epoch FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'inbound stream config epoch mismatch') END;
        SELECT CASE WHEN NEW.source_warden = (
            SELECT warden_id FROM database_metadata WHERE singleton = 1
        ) THEN RAISE(ABORT, 'inbound transfer source must be remote') END;
    END
    """,
    """
    CREATE TRIGGER inbound_stream_identity_immutable
    BEFORE UPDATE OF tenant_id, envelope_id, source_warden, config_epoch
    ON inbound_transfer_streams
    BEGIN
        SELECT RAISE(ABORT, 'inbound stream identity is immutable');
    END
    """,
    """
    CREATE TRIGGER inbound_acks_binding_insert
    BEFORE INSERT ON inbound_transfer_acks
    BEGIN
        SELECT CASE WHEN NEW.config_epoch != (
            SELECT config_epoch FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'inbound acknowledgement config epoch mismatch') END;
        SELECT CASE WHEN NEW.target_warden != (
            SELECT warden_id FROM database_metadata WHERE singleton = 1
        ) THEN RAISE(ABORT, 'inbound acknowledgement target mismatch') END;
        SELECT CASE WHEN NEW.source_warden = NEW.target_warden
            THEN RAISE(ABORT, 'transfer source and target must differ') END;
    END
    """,
    """
    CREATE TRIGGER inbound_acks_immutable_update
    BEFORE UPDATE ON inbound_transfer_acks
    BEGIN
        SELECT RAISE(ABORT, 'inbound acknowledgements are immutable');
    END
    """,
    """
    CREATE TRIGGER revocations_epoch_insert
    BEFORE INSERT ON revocations
    BEGIN
        SELECT CASE WHEN NEW.config_epoch != (
            SELECT config_epoch FROM envelopes
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ) THEN RAISE(ABORT, 'revocation config epoch mismatch') END;
    END
    """,
    """
    CREATE TRIGGER revocations_epoch_update
    BEFORE UPDATE ON revocations
    BEGIN
        SELECT CASE WHEN
            NEW.tenant_id != OLD.tenant_id OR NEW.envelope_id != OLD.envelope_id
            OR NEW.lineage_id != OLD.lineage_id
            OR NEW.branch_lease_id != OLD.branch_lease_id
            THEN RAISE(ABORT, 'revocation identity is immutable') END;
        SELECT CASE WHEN NEW.epoch <= OLD.epoch
            THEN RAISE(ABORT, 'revocation epoch must increase') END;
        SELECT CASE WHEN NEW.config_epoch != OLD.config_epoch
            THEN RAISE(ABORT, 'revocation config epoch is immutable') END;
    END
    """,
    """
    CREATE TRIGGER audit_log_monotonic
    BEFORE INSERT ON audit_log
    BEGIN
        SELECT CASE WHEN NEW.sequence != COALESCE((
            SELECT MAX(sequence) + 1 FROM audit_log
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
        ), 0) THEN RAISE(ABORT, 'audit sequence is not contiguous') END;
        SELECT CASE WHEN NEW.previous_hash != COALESCE((
            SELECT event_hash FROM audit_log
            WHERE tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id
            ORDER BY sequence DESC LIMIT 1
        ), zeroblob(32)) THEN RAISE(ABORT, 'audit previous hash mismatch') END;
    END
    """,
    """
    CREATE TRIGGER audit_log_immutable_update
    BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit log is append-only');
    END
    """,
    """
    CREATE TRIGGER audit_log_immutable_delete
    BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit log is append-only');
    END
    """,
)


MIGRATION_2 = (
    """
    CREATE TABLE database_instance (
        singleton   INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
        instance_id BLOB NOT NULL CHECK (
            typeof(instance_id) = 'blob' AND length(instance_id) = 32
        )
    ) STRICT
    """,
    """
    INSERT INTO database_instance(singleton, instance_id) VALUES (1, randomblob(32))
    """,
    """
    CREATE TRIGGER database_instance_immutable
    BEFORE UPDATE ON database_instance
    BEGIN
        SELECT RAISE(ABORT, 'database instance identity is immutable');
    END
    """,
    """
    CREATE TRIGGER database_instance_no_delete
    BEFORE DELETE ON database_instance
    BEGIN
        SELECT RAISE(ABORT, 'database instance identity cannot be deleted');
    END
    """,
    """
    CREATE TABLE runtime_control (
        singleton       INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
        mode            TEXT NOT NULL CHECK (mode IN ('ACTIVE', 'DRAINING')),
        generation      INTEGER NOT NULL CHECK (generation >= 0),
        reason          TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
        changed_at_ns   INTEGER NOT NULL CHECK (changed_at_ns >= 0),
        changed_by      TEXT NOT NULL CHECK (length(changed_by) BETWEEN 1 AND 512)
    ) STRICT
    """,
    """
    INSERT INTO runtime_control(
        singleton, mode, generation, reason, changed_at_ns, changed_by
    ) VALUES (1, 'ACTIVE', 0, 'schema initialization', 0, 'lets-migration')
    """,
    """
    CREATE TRIGGER runtime_control_generation_monotonic
    BEFORE UPDATE ON runtime_control
    BEGIN
        SELECT CASE WHEN NEW.generation != OLD.generation + 1
            THEN RAISE(ABORT, 'runtime control generation must increase by one') END;
        SELECT CASE WHEN NEW.changed_at_ns < OLD.changed_at_ns
            THEN RAISE(ABORT, 'runtime control timestamp cannot move backward') END;
    END
    """,
    """
    CREATE TRIGGER runtime_control_no_delete
    BEFORE DELETE ON runtime_control
    BEGIN
        SELECT RAISE(ABORT, 'runtime control cannot be deleted');
    END
    """,
    """
    CREATE TABLE peer_http_authority (
        singleton               INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
        tenant_id               TEXT NOT NULL,
        envelope_id             TEXT NOT NULL,
        clock_floor_s           INTEGER CHECK (clock_floor_s IS NULL OR clock_floor_s >= 0),
        revision                INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
        history_digest          BLOB NOT NULL CHECK (
            typeof(history_digest) = 'blob' AND length(history_digest) = 32
        ),
        legacy_snapshot_digest  BLOB CHECK (
            legacy_snapshot_digest IS NULL OR (
                typeof(legacy_snapshot_digest) = 'blob'
                AND length(legacy_snapshot_digest) = 32
            )
        ),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE RESTRICT
    ) STRICT
    """,
    """
    INSERT INTO peer_http_authority(
        singleton, tenant_id, envelope_id, clock_floor_s, revision,
        history_digest, legacy_snapshot_digest
    )
    SELECT 1, tenant_id, envelope_id, NULL, 0, zeroblob(32), NULL
    FROM envelopes WHERE singleton = 1
    """,
    """
    CREATE TABLE peer_http_replay (
        tenant_id      TEXT NOT NULL,
        envelope_id    TEXT NOT NULL,
        warden_id      TEXT NOT NULL CHECK (length(warden_id) BETWEEN 1 AND 512),
        key_id         TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 512),
        nonce          TEXT NOT NULL CHECK (length(nonce) BETWEEN 1 AND 512),
        timestamp_s    INTEGER NOT NULL CHECK (timestamp_s >= 0),
        expires_at_s   INTEGER NOT NULL CHECK (expires_at_s >= timestamp_s),
        accepted_at_ns INTEGER NOT NULL CHECK (accepted_at_ns >= 0),
        PRIMARY KEY (tenant_id, envelope_id, warden_id, key_id, nonce),
        FOREIGN KEY (tenant_id, envelope_id)
            REFERENCES envelopes(tenant_id, envelope_id) ON DELETE CASCADE
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE INDEX ix_peer_http_replay_expiry
    ON peer_http_replay(tenant_id, envelope_id, expires_at_s)
    """,
    """
    CREATE TRIGGER peer_http_authority_monotonic
    BEFORE UPDATE ON peer_http_authority
    BEGIN
        SELECT CASE WHEN NEW.revision != OLD.revision + 1
            THEN RAISE(ABORT, 'peer replay revision must increase by one') END;
        SELECT CASE WHEN OLD.clock_floor_s IS NOT NULL AND (
            NEW.clock_floor_s IS NULL OR NEW.clock_floor_s < OLD.clock_floor_s
        ) THEN RAISE(ABORT, 'peer replay clock floor cannot move backward') END;
        SELECT CASE WHEN OLD.legacy_snapshot_digest IS NOT NULL
            AND NEW.legacy_snapshot_digest IS NOT OLD.legacy_snapshot_digest
            THEN RAISE(ABORT, 'legacy replay snapshot binding is immutable') END;
    END
    """,
    """
    CREATE TRIGGER peer_http_authority_no_delete
    BEFORE DELETE ON peer_http_authority
    BEGIN
        SELECT RAISE(ABORT, 'peer replay authority metadata cannot be deleted');
    END
    """,
    """
    CREATE TRIGGER peer_http_replay_immutable_update
    BEFORE UPDATE ON peer_http_replay
    BEGIN
        SELECT RAISE(ABORT, 'peer replay claims are immutable');
    END
    """,
)


MIGRATIONS = {1: SCHEMA_STATEMENTS, 2: MIGRATION_2}

__all__ = [
    "APPLICATION_ID",
    "MIGRATIONS",
    "MIGRATION_2",
    "REQUIRED_INDEXES",
    "REQUIRED_TABLES",
    "REQUIRED_TRIGGERS",
    "SCHEMA_STATEMENTS",
    "SCHEMA_VERSION",
]
