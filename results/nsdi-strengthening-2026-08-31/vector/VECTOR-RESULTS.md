# Resource-vector and debit/claim results

The runtime used two dimensions (`read`, `system`) and three heterogeneous costs: inspect `(1,0)`, restart `(0,3)`, and credential rotation `(1,5)`.

| Operation | Outcome | Δ free | Δ lease residual | Δ consumed | Δ in-flight | Claim |
|---|---|---:|---:|---:|---:|---|
| root_issue_source | succeeded | (-30,-40) | (30,40) | (0,0) | (0,0) | — |
| spawn_reader | succeeded | (0,0) | (0,0) | (0,0) | (0,0) | — |
| spawn_operator | succeeded | (0,0) | (0,0) | (0,0) | (0,0) | — |
| spawn_recovery | succeeded | (0,0) | (0,0) | (0,0) | (0,0) | — |
| reader_inspect_1 | succeeded | (0,0) | (-1,0) | (1,0) | (0,0) | yes |
| reader_inspect_2 | succeeded | (0,0) | (-1,0) | (1,0) | (0,0) | yes |
| reader_inspect_3 | succeeded | (0,0) | (-1,0) | (1,0) | (0,0) | yes |
| operator_restart_1 | succeeded | (0,0) | (0,-3) | (0,3) | (0,0) | yes |
| operator_restart_2 | succeeded | (0,0) | (0,-3) | (0,3) | (0,0) | yes |
| operator_rotate_denied_zero_read | denied | (0,0) | (0,0) | (0,0) | (0,0) | — |
| recovery_rotate_1 | succeeded | (0,0) | (-1,-5) | (1,5) | (0,0) | yes |
| recovery_rotate_2 | succeeded | (0,0) | (-1,-5) | (1,5) | (0,0) | yes |
| recovery_inspect | succeeded | (0,0) | (-1,0) | (1,0) | (0,0) | yes |
| recovery_restart | succeeded | (0,0) | (0,-3) | (0,3) | (0,0) | yes |
| transfer_prepare | succeeded | (-4,-10) | (0,0) | (0,0) | (4,10) | — |
| transfer_accept | succeeded | (4,10) | (0,0) | (0,0) | (-4,-10) | — |
| transfer_duplicate_accept | succeeded | (0,0) | (0,0) | (0,0) | (0,0) | — |
| transfer_finalize | succeeded | (0,0) | (0,0) | (0,0) | (0,0) | — |
| target_root_from_transferred_units | succeeded | (-4,-10) | (4,10) | (0,0) | (0,0) | — |
| target_rotate_transfer_backed | succeeded | (0,0) | (-1,-5) | (1,5) | (0,0) | yes |
| target_inspect_transfer_backed | succeeded | (0,0) | (-1,0) | (1,0) | (0,0) | yes |
| duplicate_executor_claim_rejected | denied | (0,0) | (0,0) | (0,0) | (0,0) | — |
| target_restart_debited_but_unclaimed | succeeded | (0,0) | (0,-3) | (0,3) | (0,0) | no |
| expired_unclaimed_receipt_cannot_settle | denied | (0,0) | (0,0) | (0,0) | (0,0) | — |

## Direct observations

- Final conserved vector: `(40, 60)` from genesis `(40, 60)`; identity held: `True`.
- Final spendable vector: `(32, 33)`; componentwise spendable bound held: `True`.
- The target began with `(0,0)`, accepted `(4,10)`, issued its root only from that inbound authority, and then authorized and claimed target-side actions.
- An operator child allocated `(0,15)` had the rotate capability but its `(1,5)` action was denied because it had zero read units.
- The warden issued 12 receipts and executors claimed 11. The deliberately unclaimed receipt cost `(0, 3)` and remained debited after expiry; no refund occurred.

Every row in the raw JSON retains the complete before/after local snapshots, aggregate vectors, and category deltas.
