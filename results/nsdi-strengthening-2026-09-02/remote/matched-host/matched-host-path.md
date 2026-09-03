# Replacement matched final-dispatch benchmark

> This is a current-composition replacement experiment. It is not an exact
> reproduction of the missing `20260826T231656Z` artifact or its 74.778 ms result.

Trials: 10; warmups/mode: 100; measured operations/mode: 1000.

| Trial | Order | Mode | End-to-end p50 (ms) | p95 (ms) | p99 (ms) |
|---:|---:|:---|---:|---:|---:|
| 0 | 0 | off | 0.009467 | 0.011668 | 0.024956 |
| 0 | 1 | enforce | 33.408049 | 39.301160 | 42.534779 |
| 1 | 0 | enforce | 35.821976 | 43.886686 | 47.850262 |
| 1 | 1 | off | 0.008725 | 0.014722 | 0.021574 |
| 2 | 0 | off | 0.008796 | 0.014627 | 0.021898 |
| 2 | 1 | enforce | 33.989186 | 38.825554 | 44.283835 |
| 3 | 0 | enforce | 33.431710 | 37.936331 | 42.960361 |
| 3 | 1 | off | 0.008822 | 0.014536 | 0.018750 |
| 4 | 0 | off | 0.008944 | 0.014986 | 0.018543 |
| 4 | 1 | enforce | 33.859177 | 39.910379 | 46.159788 |
| 5 | 0 | enforce | 33.998841 | 40.183179 | 45.150121 |
| 5 | 1 | off | 0.008731 | 0.014547 | 0.020778 |
| 6 | 0 | off | 0.019231 | 0.028508 | 0.035490 |
| 6 | 1 | enforce | 33.765244 | 37.120775 | 41.877661 |
| 7 | 0 | enforce | 33.884717 | 37.278207 | 44.105313 |
| 7 | 1 | off | 0.008692 | 0.014272 | 0.017499 |
| 8 | 0 | off | 0.008789 | 0.014532 | 0.020246 |
| 8 | 1 | enforce | 33.824286 | 39.165957 | 44.953909 |
| 9 | 0 | enforce | 33.491305 | 37.638645 | 43.285245 |
| 9 | 1 | off | 0.009420 | 0.015388 | 0.021888 |

The JSON retains every inclusive span, derived exclusive span, span call count,
environment identity, Git/component identity, and storage posture. The CSV retains
one row per measured operation. Fixture construction and root issuance are excluded.

The Warden is unanchored. The executor uses a process-file anchor, but its anchor
and replay database are intentionally within the same temporary storage root, so this
does not establish independent rollback domains. AstralPlane is pinned by the
composition, but the timed host binding/effect-coordinator adapters are deterministic
and in-memory; no PostgreSQL transaction is included.
