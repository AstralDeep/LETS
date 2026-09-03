# Partition, skew, and centralized-counter results

> Scope: three logical sites with separate durable warden and executor stores in one Python process on one physical host. This is not independent-host evidence.

| Scenario | Scheme | Authorized | Denied | Partition A authorized | Partition A denied | Remote authority at first LETS exhaustion | Normal p50 (ms) | Normal p95 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| balanced_equal_shares | lets | 300 | 0 | 50 | 0 | — | 11.390 | 12.267 |
| balanced_equal_shares | centralized_counter | 250 | 50 | 0 | 50 | — | 0.298 | 0.356 |
| skew_equal_shares | lets | 253 | 47 | 58 | 47 | 157 | 11.525 | 12.735 |
| skew_equal_shares | centralized_counter | 195 | 105 | 0 | 105 | — | 0.290 | 0.365 |
| skew_demand_placed_shares | lets | 300 | 0 | 105 | 0 | — | 11.738 | 13.199 |
| skew_demand_placed_shares | centralized_counter | 195 | 105 | 0 | 105 | — | 0.298 | 0.399 |

LETS authorizations include a durable warden debit, receipt verification, and a durable executor claim. The centralized baseline is one durable serialized SQLite counter transaction. Both exclude real network transport and application work.

The raw JSON and CSV preserve every request, phase, decision, latency, per-site snapshot, transfer, and aggregate accounting value.
