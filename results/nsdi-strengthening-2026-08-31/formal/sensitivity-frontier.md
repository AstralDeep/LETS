# LETS formal sensitivity and frontier analysis

- Generated: `2026-09-01T00:16:16.607883+00:00`
- Mode: `all`
- Model digest: `sha256:77d48812fa293cf5934496c90a435f8f7792a6f88aef6e4f460bcf0e7ee3b5b8`
- Analyzer digest: `sha256:c6db9dfd332c2895562fa8cfb3f9729637c6c033823dde6cfd131f685d403f68`
- Configuration digest: `sha256:f2a62c262e5789546fca41d6fd9ca3cdf2b4d26526f98ee35bb31405fc2ecfa5`
- Success: `true`

## Frontier

- Termination: `depth_limit`.
- Frontier exhausted: `false`.
- States checked: `101245`.
- Expanded transitions checked: `318558`.
- Cutoff states: `48720`.
- Cutoff transitions probed: `302688`.
- Unseen successors beyond the cutoff: `69492`.

| Shortest depth | States | Checked outgoing transitions |
|---:|---:|---:|
| 0 | 1 | 9 |
| 1 | 9 | 69 |
| 2 | 57 | 336 |
| 3 | 210 | 1356 |
| 4 | 732 | 4533 |
| 5 | 2199 | 13692 |
| 6 | 6030 | 36693 |
| 7 | 14307 | 86754 |
| 8 | 28980 | 175116 |
| 9 | 48720 | 302688 |

## Mutation sensitivity

- Baseline passed: `true`.
- All mutants killed: `true`.

### Baseline

States: `4569`; transitions: `9341`; termination: `depth_limit`.

| Mutant | Killed | Violated property | Depth | States | Transitions | Trace |
|---|:---:|---|---:|---:|---:|---|
| `spawn_without_parent_debit` | true | `global_conservation` | 2 | 14 | 14 | issue_root(w=0,amount=1) → faulty_spawn_without_debit(parent=1,amount=1) |
| `timeout_source_restore_after_accept` | true | `global_conservation` | 3 | 138 | 185 | prepare(source=0,target=1,amount=1) → accept(transfer=1) → faulty_timeout_restore(transfer=1) |
| `duplicate_claim_accepted` | true | `claim_at_most_once` | 4 | 252 | 366 | issue_root(w=0,amount=1) → authorize(lease=1,cost=1) → claim(receipt=1) → faulty_duplicate_claim(receipt=1) |
| `close_parent_with_live_descendant` | true | `active_descendant_has_active_ancestors` | 3 | 58 | 64 | issue_root(w=0,amount=1) → spawn(parent=1,amount=1) → faulty_close_live_parent(lease=1) |
| `stale_sequence_authorization` | true | `authorization_sequence_freshness` | 3 | 84 | 103 | issue_root(w=0,amount=2) → spawn(parent=1,amount=1) → faulty_stale_authorize(lease=1,expected=0,cost=1) |
| `ghost_inbound_without_voucher` | true | `transfer_origin` | 1 | 7 | 7 | faulty_ghost_inbound(source=0,target=1,sequence=1,amount=1) |
| `noncontiguous_checkpoint` | true | `checkpoint_contiguity` | 5 | 1538 | 2716 | prepare(source=0,target=1,amount=1) → prepare(source=0,target=1,amount=1) → accept(transfer=2) → finalize(transfer=2) → faulty_noncontiguous_checkpoint(source=0,target=1,through=2) |
