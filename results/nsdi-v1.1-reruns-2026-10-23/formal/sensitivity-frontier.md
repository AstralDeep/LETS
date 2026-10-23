# LETS formal sensitivity and frontier analysis

- Generated: `2026-10-23T05:24:43.322056+00:00`
- Mode: `all`
- Model digest: `sha256:5954e62b7396f61a54c4ae65731148a94fe664b32b55eb4440d7f385d0b7f3d2`
- Analyzer digest: `sha256:4351328db81410edef6184869ed3924a524d71e8a1b430d4e190654ecc91054e`
- Configuration digest: `sha256:f2a62c262e5789546fca41d6fd9ca3cdf2b4d26526f98ee35bb31405fc2ecfa5`
- Success: `true`

## Frontier

- Termination: `depth_limit`.
- Frontier exhausted: `false`.
- States checked: `147673`.
- Expanded transitions checked: `481728`.
- Cutoff states: `68802`.
- Cutoff transitions probed: `430140`.
- Unseen successors beyond the cutoff: `93066`.

| Shortest depth | States | Checked outgoing transitions |
|---:|---:|---:|
| 0 | 1 | 9 |
| 1 | 9 | 75 |
| 2 | 63 | 432 |
| 3 | 294 | 1878 |
| 4 | 1104 | 6783 |
| 5 | 3519 | 21150 |
| 6 | 9438 | 57333 |
| 7 | 21843 | 133344 |
| 8 | 42600 | 260724 |
| 9 | 68802 | 430140 |

## Mutation sensitivity

- Baseline passed: `true`.
- All mutants killed: `true`.

### Baseline

States: `6967`; transitions: `13832`; termination: `depth_limit`.

| Mutant | Killed | Violated property | Depth | States | Transitions | Trace |
|---|:---:|---|---:|---:|---:|---|
| `spawn_without_parent_debit` | true | `global_conservation` | 2 | 15 | 15 | issue_root(w=0,amount=1) → faulty_spawn_without_debit(parent=1,amount=1) |
| `timeout_source_restore_after_accept` | true | `global_conservation` | 3 | 179 | 233 | prepare(source=0,target=1,amount=1) → accept(transfer=1) → faulty_timeout_restore(transfer=1) |
| `duplicate_claim_accepted` | true | `claim_at_most_once` | 4 | 329 | 463 | issue_root(w=0,amount=1) → authorize(lease=1,cost=1) → claim(receipt=1) → faulty_duplicate_claim(receipt=1) |
| `close_parent_with_live_descendant` | true | `active_descendant_has_active_ancestors` | 3 | 67 | 73 | issue_root(w=0,amount=1) → spawn(parent=1,amount=1) → faulty_close_live_parent(lease=1) |
| `stale_sequence_authorization` | true | `authorization_sequence_freshness` | 3 | 103 | 124 | issue_root(w=0,amount=2) → spawn(parent=1,amount=1) → faulty_stale_authorize(lease=1,expected=0,cost=1) |
| `ghost_inbound_without_voucher` | true | `transfer_origin` | 1 | 7 | 7 | faulty_ghost_inbound(source=0,target=1,sequence=1,amount=1) |
| `noncontiguous_checkpoint` | true | `checkpoint_contiguity` | 5 | 2251 | 3827 | prepare(source=0,target=1,amount=1) → prepare(source=0,target=1,amount=1) → accept(transfer=2) → finalize(transfer=2) → faulty_noncontiguous_checkpoint(source=0,target=1,through=2) |
| `remote_spawn_refund_in_flight` | true | `global_conservation` | 3 | 70 | 78 | issue_root(w=0,amount=1) → spawn_remote(parent=1,target=1,amount=1) → faulty_remote_spawn_refund(transfer=1) |
| `remote_child_also_credited_to_pool` | true | `global_conservation` | 3 | 70 | 78 | issue_root(w=0,amount=1) → spawn_remote(parent=1,target=1,amount=1) → faulty_remote_child_pool_credit(transfer=1) |
| `remote_child_without_voucher` | true | `remote_child_origin` | 2 | 15 | 15 | issue_root(w=0,amount=1) → faulty_ghost_remote_child(parent=1,target=1) |
| `close_parent_with_pending_remote_child` | true | `active_descendant_has_active_ancestors` | 4 | 330 | 457 | issue_root(w=0,amount=1) → spawn_remote(parent=1,target=1,amount=1) → faulty_close_pending_remote_parent(lease=1) → accept(transfer=1) |
