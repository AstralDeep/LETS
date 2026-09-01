# Current Docker acceptance result

The exact repository acceptance runner completed successfully on
2026-09-01 UTC from `main` commit
`a9f4ba810e1741f93ba204eb782b6c4e3d409a03` with a stable, dirty source
snapshot. Total evidence-bound duration was 41.759 seconds and the pytest
scenario took 11.261 seconds.

## Test outcome

```text
tests/e2e/test_compose_cluster.py::test_real_three_node_fault_recovery_and_conservation PASSED
tests/e2e/test_production_profile.py::test_production_profile_acceptance SKIPPED
```

The production profile was skipped because `LETS_RUN_PRODUCTION_ACCEPTANCE=1`
was not set. The standard three-node compose scenario was explicitly enabled
by `deploy/run_acceptance.py` and passed.

## Scenario facts

- Three distinct warden process IDs and three distinct Ed25519 key IDs were
  observed in one Docker VM.
- During a bidirectional A↔B link fault, local receipts were issued while peer
  delivery retained a durable retry with two pending transfer records.
- Recovery automatically accepted, finalized, and checkpointed the transfers;
  both source and target compacted through sequence 2 and the source dispatcher
  ended healthy with no pending or prepared records.
- Sending sequence 2 before sequence 1 retained the gap; exact HTTP replay was
  rejected with status 409 and code `replay_detected`.
- After SIGKILL/restart of warden B, the process ID changed, its signing key
  remained stable, and exact replay was still rejected with 409.
- An independent executor verified and claimed a signed receipt, reopened its
  SQLite replay store with integrity `ok`, and rejected the receipt as replay.
- Aggregate accounting was `(300)`: `free + residual + consumed = 300`, transfer
  totals were 20 out and 20 in, every local invariant was healthy, and every
  signed audit chain verified.

This is a fault-path and protocol result for three containers/processes on one
physical host. It is not independent-host or WAN evidence.

## Raw artifact bindings

These files live in the repository's mixed historical `results/generated/`
tree, so use the exact paths and hashes below rather than selecting files by
recency.

| File | Bytes | SHA-256 |
|---|---:|---|
| `results/generated/docker-acceptance.json` | 18,754 | `d787d020b5b0212be284b5b60fce9674a5f55fd4236e66bef44bdc5cd6162f04` |
| `results/generated/scenario-evidence.json` | 2,998 | `adc701f3ff4edd72aadf67c8477f14a4a4159bcdbfcba810e5219529a5a5c934` |
| `results/generated/docker-compose.log` | 1,861 | `144bb1a550fe2bf0b0adbae858d529e0a1492453a657946913f986e46be4570f` |

Reproduce with:

```powershell
.\.venv\Scripts\python.exe deploy\run_acceptance.py
```
