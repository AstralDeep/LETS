# Two-dimensional bounded model-checking results

Generated: `2026-09-01T00:28:55.317879+00:00`

This is standalone evidence; it does not alter the retained scalar checker.

## Configuration

- Bounds: `{"initial_free": [[2, 5], [1, 3]], "max_depth": 10, "max_leases": 2, "max_transfers": 1, "total_budget": [3, 8]}`
- Heterogeneous costs: `{"inspect_configuration": [1, 0], "restart_service": [0, 3], "rotate_credential": [1, 5]}`
- Model SHA-256: `178bb82e630fe432cef215fbe82dc4878be580acea8539a330ca7a7e676cae5b`
- Configuration SHA-256: `3d8369603603566c9f8eaeb4c1d75841501159e9d9ebd856ba74f24fdb1cb428`

## Baseline

- Passed all checked invariants: **true**
- Termination: `frontier_exhausted`
- Frontier exhausted: **true**
- States checked: **8348**
- Transitions checked: **18468**
- Maximum shortest depth: **10**
- Cutoff states: **26**
- Cutoff transitions probed: **0**
- Unseen successors at cutoff: **0**

Action coverage:

| Action kind | Explored transitions |
|---|---:|
| `accept_transfer` | 2891 |
| `authorize:inspect_configuration` | 2464 |
| `authorize:restart_service` | 1801 |
| `authorize:rotate_credential` | 537 |
| `close` | 6546 |
| `issue_root` | 1197 |
| `prepare_transfer` | 2891 |
| `spawn` | 141 |

## Vector-accounting mutant

- Mutant: `cross_dimension_debit`
- Killed: **true**
- Violated property: `per_dimension_conservation`
- Shortest counterexample depth: **2**
- States checked before detection: **47**
- Transitions checked before detection: **47**

Shortest trace:

1. `issue_root(w=0,allocation=(1, 5))`
2. `MUTANT_cross_dimension_debit(lease=0,cost=(1, 5),debited=(1, 0))`

## Interpretation boundary

A passing baseline establishes only the listed invariants over this finite configuration. If `frontier_exhausted` is false, unseen successors remain beyond the recorded depth. The mutant result shows sensitivity to one deliberately injected vector-accounting fault; it is not a proof about all possible implementation defects.
