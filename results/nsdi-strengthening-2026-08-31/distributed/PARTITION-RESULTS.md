# Partition, skew, and centralized-counter results

> Scope: three logical sites with separate durable warden and executor stores in one Python process on one physical host. This is not independent-host evidence.

| Scenario | Scheme | Authorized | Denied | Partition A authorized | Partition A denied | Remote authority at first LETS exhaustion | Normal p50 (ms) | Normal p95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| balanced_equal_shares | lets | 300 | 0 | 50 | 0 | — | 10.530 | 11.889 |
| balanced_equal_shares | centralized_counter | 250 | 50 | 0 | 50 | — | 0.560 | 0.855 |
| skew_equal_shares | lets | 253 | 47 | 58 | 47 | 157 | 10.706 | 12.442 |
| skew_equal_shares | centralized_counter | 195 | 105 | 0 | 105 | — | 0.560 | 0.864 |
| skew_demand_placed_shares | lets | 300 | 0 | 105 | 0 | — | 10.861 | 12.876 |
| skew_demand_placed_shares | centralized_counter | 195 | 105 | 0 | 105 | — | 0.562 | 0.862 |

LETS authorizations include a durable warden debit, receipt verification, and a durable executor claim. The centralized baseline is one durable serialized SQLite counter transaction. Both exclude real network transport and application work.

The raw JSON and CSV preserve every request, phase, decision, latency, per-site snapshot, transfer, and aggregate accounting value.
