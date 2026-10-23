# Replacement matched final-dispatch benchmark

> This is a current-composition replacement experiment. It is not an exact
> reproduction of the missing `20260826T231656Z` artifact or its 74.778 ms result.

Trials: 10; warmups/mode: 100; measured operations/mode: 1000.

| Trial | Order | Mode | End-to-end p50 (ms) | p95 (ms) | p99 (ms) |
|---:|---:|:---|---:|---:|---:|
| 0 | 0 | off | 0.008962 | 0.010419 | 0.018364 |
| 0 | 1 | enforce | 34.106804 | 36.888241 | 41.533911 |
| 1 | 0 | enforce | 34.087224 | 36.792138 | 41.307452 |
| 1 | 1 | off | 0.008408 | 0.014557 | 0.019518 |
| 2 | 0 | off | 0.008543 | 0.014882 | 0.024173 |
| 2 | 1 | enforce | 34.005320 | 36.455840 | 43.425312 |
| 3 | 0 | enforce | 33.681850 | 36.529332 | 37.060647 |
| 3 | 1 | off | 0.008477 | 0.014694 | 0.019186 |
| 4 | 0 | off | 0.008445 | 0.014656 | 0.020065 |
| 4 | 1 | enforce | 34.336932 | 38.615416 | 42.086852 |
| 5 | 0 | enforce | 33.854730 | 37.198013 | 42.789220 |
| 5 | 1 | off | 0.008300 | 0.014268 | 0.019584 |
| 6 | 0 | off | 0.008281 | 0.014460 | 0.018990 |
| 6 | 1 | enforce | 33.839893 | 36.512149 | 37.531622 |
| 7 | 0 | enforce | 34.542531 | 40.408497 | 44.158508 |
| 7 | 1 | off | 0.008566 | 0.013781 | 0.018957 |
| 8 | 0 | off | 0.008801 | 0.013847 | 0.017851 |
| 8 | 1 | enforce | 33.731340 | 36.264563 | 37.154885 |
| 9 | 0 | enforce | 34.424117 | 36.956966 | 39.338131 |
| 9 | 1 | off | 0.008228 | 0.014263 | 0.019807 |

The JSON retains every inclusive span, derived exclusive span, span call count,
environment identity, Git/component identity, and storage posture. The CSV retains
one row per measured operation. Fixture construction and root issuance are excluded.

The Warden is unanchored. The executor uses a process-file anchor, but its anchor
and replay database are intentionally within the same temporary storage root, so this
does not establish independent rollback domains. AstralPlane is pinned by the
composition, but the timed host binding/effect-coordinator adapters are deterministic
and in-memory; no PostgreSQL transaction is included.
