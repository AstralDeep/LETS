# Wire formats, frozen at v1

Four signed records cross a trust boundary: the receipt, the lease grant, the transfer voucher and the transfer acknowledgement. Their v1 formats are frozen. A change to any field, to its meaning, to the signing rule or to the canonical form needs a new wire type such as `lets.receipt/v2`. A v1 verifier must refuse the new type. Adding a field to a v1 type is also a change, because verifiers reject unknown fields.

The vectors in `protocol/vectors/` are the executable form of this page. `scripts/generate_vectors.py --check` fails when the reference implementation stops emitting them. `tests/unit/test_wire_vectors.py` runs the reference verifier over every case. A second implementation proves conformance by reaching the same verdict on every case.

## Rules shared by all four records

- **Canonical form** is LETS-CJ/1, defined in [canonicalization.md](canonicalization.md). Keys are sorted by Unicode scalar value. There is no whitespace. Integers are signed 64-bit. There are no floats. Duplicate keys are refused.
- **Signature.** The signer takes the record without its `signature` field, writes it in canonical form, signs those bytes with Ed25519, and writes the 64-byte signature as unpadded base64url in `signature`. There is no domain prefix. The `type` field already separates the four records.
- **Trust.** A verifier maps `(warden_id, key_id)` to a 32-byte Ed25519 public key. A key that is unknown, outside its validity interval, or bound to another warden is untrusted.
- **Strictness.** A parser refuses a missing required field, an unknown field, a wrong `type`, a wrong JSON type and any value outside the limits below. Refusal comes before any signature check.
- **Identifier** means a non-empty string of at most 512 characters with no surrounding whitespace and no control characters.
- **Warden id** matches `^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`.
- **Key id** matches `^[A-Za-z0-9][A-Za-z0-9._~:/+-]{0,511}$`. The reference signer writes `<warden_id>/ed25519-<first 32 hex characters of SHA-256 of the public key>`.
- **Digest** matches `^sha256:[0-9a-f]{64}$`.
- **Resource vector** is a non-empty array of integers from 0 to 2^63 - 1.
- **Time** is integer nanoseconds since the Unix epoch, from 0 to 2^63 - 1.
- **Record digest.** Where a record is bound by digest, the digest is `sha256:` plus the SHA-256 of the canonical form of the full record including `signature`.

## `lets.receipt/v1`

A warden's proof that one transition was charged to one lease. An executor verifies it offline and claims it once.

| Field | Type | Rule |
|---|---|---|
| `type` | string | Exactly `lets.receipt/v1`. |
| `tenant_id` | identifier | |
| `envelope_id` | identifier | |
| `config_epoch` | integer | At least 1. |
| `receipt_id` | identifier | Unique per warden. |
| `request_id` | identifier | The caller's idempotency key. |
| `warden_id` | warden id | The signer. |
| `key_id` | key id | The signing key. |
| `policy_id` | identifier | |
| `policy_version` | identifier | |
| `policy_digest` | digest | |
| `machine_digest` | digest | |
| `lease_id` | identifier | |
| `lineage_id` | identifier | |
| `subject_id` | identifier | |
| `executor_audience` | identifier | The only executor that may accept it. |
| `transition` | identifier | |
| `source_state` | identifier | |
| `target_state` | identifier | |
| `cost` | resource vector | |
| `resulting_sequence` | integer | At least 1. Per lease. |
| `evidence_digest` | digest or null | Required key, null when there is no evidence. |
| `nonce` | identifier | Unique per receipt. |
| `issued_at_ns` | time | |
| `expires_at_ns` | time | Greater than `issued_at_ns`. |
| `signature` | base64url | |

Executor checks, in order: audience equals the executor's own. Tenant, envelope and epoch match when the executor fixes them. Policy digest is on the allow list when there is one. Machine digest likewise. Warden is trusted when the trusted set is not empty. `issued_at_ns` is not after now plus clock uncertainty. Now plus uncertainty is before `expires_at_ns`. The signature verifies. The durable claim succeeds exactly once.

## `lets.lease-grant/v1`

A warden's grant of a bounded allocation to a subject. A child grant names its parent and the whole path above it.

| Field | Type | Rule |
|---|---|---|
| `type` | string | Exactly `lets.lease-grant/v1`. |
| `tenant_id` | identifier | |
| `envelope_id` | identifier | |
| `config_epoch` | integer | At least 1. |
| `lease_id` | identifier | |
| `lineage_id` | identifier | |
| `parent_id` | identifier or null | Required key. Null for a root. |
| `subject_id` | identifier | |
| `warden_id` | warden id | The signer and the holder. |
| `allocation` | resource vector | At least one non-zero value. |
| `capabilities` | array of identifiers | Sorted by Unicode scalar value. A set in meaning. |
| `policy_id` | identifier | |
| `policy_version` | identifier | |
| `policy_digest` | digest | |
| `machine_digest` | digest | |
| `ancestor_path` | array of identifiers | Empty for a root. For a child it ends with `parent_id`, has no repeats, does not contain `lease_id` and has at most 64 entries. |
| `branch_epoch` | integer | At least 0. |
| `issued_at_ns` | time | |
| `expires_at_ns` | time | At least 1 and greater than `issued_at_ns`. |
| `key_id` | key id | |
| `signature` | base64url | |

The reference check in `lets.wire_verify.verify_lease_grant` tests, in order: the holder is the warden the grant names, the policy digest is the one expected, the window holds under clock uncertainty, and the signature verifies.

## `lets.transfer-voucher/v1`

A source warden's signed debit of part of its free pool in favor of a target warden.

| Field | Type | Rule |
|---|---|---|
| `type` | string | Exactly `lets.transfer-voucher/v1`. |
| `tenant_id` | identifier | |
| `envelope_id` | identifier | |
| `config_epoch` | integer | At least 1. |
| `transfer_id` | identifier | |
| `source_warden` | warden id | The signer. |
| `target_warden` | warden id | Differs from `source_warden`. |
| `policy_id` | identifier | |
| `policy_version` | identifier | |
| `policy_digest` | digest | |
| `sequence` | integer | At least 1. Per source and target pair. |
| `amount` | resource vector | At least one non-zero value. |
| `issued_at_ns` | time | |
| `key_id` | key id | |
| `kind` | string | Optional. Absent means `pool`. `pool` or `lease` when present. |
| `lease_request` | object | Present exactly when `kind` is `lease`. Fields below. |
| `signature` | base64url | |

A pool voucher omits `kind` and `lease_request` from the signed form. A parser accepts an explicit `pool` and signs as if the field were absent, so writers must omit it. A lease voucher includes both. `lease_request` has exactly these fields: `child_lease_id`, `lineage_id`, `parent_id`, `subject_id` (identifiers), `capabilities` (array of identifiers, sorted), `ancestor_path` (non-empty array ending with `parent_id`, no repeats, not containing `child_lease_id`, at most 64 entries), `branch_epoch` (integer from 0) and `expires_at_ns` (time from 1).

Receiver checks in `lets.wire_verify.verify_transfer_voucher`: the receiver is the target, the policy digest is the one expected, the signature verifies under the source, and a sequence already accepted is bound to the record digest of the first voucher. The identical voucher delivered again is accepted again. A different voucher on the same sequence is refused.

## `lets.transfer-ack/v1`

The target warden's signed acceptance of a voucher.

| Field | Type | Rule |
|---|---|---|
| `type` | string | Exactly `lets.transfer-ack/v1`. |
| `tenant_id` | identifier | |
| `envelope_id` | identifier | |
| `config_epoch` | integer | At least 1. |
| `transfer_id` | identifier | |
| `source_warden` | warden id | |
| `target_warden` | warden id | The signer. |
| `sequence` | integer | At least 1. |
| `voucher_digest` | digest | The record digest of the accepted voucher. |
| `accepted_at_ns` | time | |
| `contiguous_watermark` | integer | At least 0. |
| `key_id` | key id | |
| `child_lease_id` | identifier | Optional. Present exactly when `child_outcome` is present. |
| `child_outcome` | string | Optional. `ISSUED` or `FENCED`. |
| `signature` | base64url | |

An ack without a child omits `child_lease_id` and `child_outcome` from the signed form. Source checks in `lets.wire_verify.verify_transfer_ack`: the source is the verifying warden, `voucher_digest` equals the record digest of the voucher it answers, and the signature verifies under the target.

## `lets.period-policy/v1` and `lets.period-budget/v1`

These two types are newer than the four above and follow the same freeze from their first release. The policy is signed. The budget is derived and never signed. The design is in [ADR 0004](adr/0004-period-budgets-and-device-holder.md).

The policy signature covers the canonical form of the policy without `sig`. The signature scheme belongs to the caller. LETS hands the issuer, the canonical bytes and `sig` to a verifier the caller supplies. The vectors use Ed25519 with the key in `period.json`. A mesh uses its own key type and adds its own domain prefix inside its verifier.

| Policy field | Type | Rule |
|---|---|---|
| `type` | string | Exactly `lets.period-policy/v1`. |
| `policy_id` | identifier | |
| `version` | integer | At least 1. A newer version replaces an older one. |
| `issuer` | identifier | |
| `epoch_ns` | time | Periods count from here. |
| `period_ns` | integer | At least 1. |
| `totals` | object | Dimension name to integer. The keys are the dimensions. |
| `shares` | object | Member kind to an object from dimension name to integer. Same keys as `totals`. |
| `solo` | object | Same shape as `shares`. Each value at most the matching share. |
| `reduction_permille` | object | Exactly `attested` and `unattested`, each from 0 to 1000. |
| `sig` | string | Opaque to LETS. |

The budget is `type` (`lets.period-budget/v1`), `period_index`, `starts_at_ns`, `ends_at_ns`, `policy_digest`, `membership_digest`, `total`, `reserve` and `shares`, a list sorted by member id of `member_id`, `fresh` and `solo`. The membership digest is the digest of `{"type":"lets.period-membership/v1","members":[...]}` with members sorted by id, each as `member_id`, `kind` and `attested`. A policy digest is the digest of the canonical form without `sig`.

## Rejection reasons

The vectors name each refusal with a stable reason so implementations in other languages can compare verdicts.

| Reason | Meaning |
|---|---|
| `malformed` | Unknown or missing field, wrong type, wrong value. |
| `signature` | Bad, malformed or untrusted signature. |
| `audience` | Named audience, target, holder or source is not the verifier. |
| `expired` | Now plus uncertainty is at or past expiry. |
| `not_yet_valid` | Issuance is after now plus uncertainty. |
| `policy_digest` | The policy digest is not accepted. |
| `voucher_digest` | An acknowledgement does not match its voucher. |
| `sequence_conflict` | A transfer sequence is bound to a different voucher. |
| `replay` | The receipt was already claimed. |
| `issuer` | The issuing warden is not in the executor's trusted set. |
| `clock` | The executor clock is invalid or too uncertain. |
| `denied` | Any other policy refusal. |

## Vector files

| File | Holds |
|---|---|
| `protocol/vectors/keys.json` | The fixed test keys. Seeds are derived from public labels and are for tests only. |
| `protocol/vectors/receipt.json` | Receipt cases, including a replayed claim. |
| `protocol/vectors/lease-grant.json` | Lease grant cases. |
| `protocol/vectors/transfer-voucher.json` | Voucher cases, including a conflicting sequence. |
| `protocol/vectors/transfer-ack.json` | Acknowledgement cases. |
| `protocol/vectors/period.json` | Period derivation with the expected budgets and digests, period arithmetic, policy classification and adoption. |
| `protocol/vectors/device.json` | Device holder scenarios with expected allowances and refusals. |

The four record files each have `wire_type`, `trusted_keys` and `cases`. `period.json` and `device.json` have their own sections, described by the `arithmetic` and `ops` fields inside them. A case has a `verifier` context and ordered `steps`. A step has the `wire` record, the clock `now_ns` where one applies, and the `expect` verdict, either `valid` or a reason. Steps run in order against one verifier state, so a replay case shows `valid` then `replay`. `signing_input` is the exact canonical text that was signed.
