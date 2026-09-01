# Replacement matched final-dispatch benchmark

> This is a current-composition replacement experiment. It is not an exact
> reproduction of the missing `20260826T231656Z` artifact or its 74.778 ms result.

Trials: 10; warmups/mode: 100; measured operations/mode: 1000.

| Trial | Order | Mode | End-to-end p50 (ms) | p95 (ms) | p99 (ms) |
|---:|---:|:---|---:|---:|---:|
| 0 | 0 | off | 0.009037 | 0.022509 | 0.039036 |
| 0 | 1 | enforce | 34.347254 | 40.445481 | 47.264725 |
| 1 | 0 | enforce | 33.613199 | 39.858616 | 46.115735 |
| 1 | 1 | off | 0.008585 | 0.018617 | 0.028508 |
| 2 | 0 | off | 0.008627 | 0.017211 | 0.022042 |
| 2 | 1 | enforce | 33.672212 | 37.968554 | 42.126876 |
| 3 | 0 | enforce | 34.177516 | 39.392831 | 43.985262 |
| 3 | 1 | off | 0.008424 | 0.014325 | 0.018544 |
| 4 | 0 | off | 0.008432 | 0.014226 | 0.018604 |
| 4 | 1 | enforce | 33.788787 | 39.744592 | 48.083018 |
| 5 | 0 | enforce | 33.835454 | 41.171686 | 45.789705 |
| 5 | 1 | off | 0.008545 | 0.014749 | 0.019550 |
| 6 | 0 | off | 0.008555 | 0.015179 | 0.022454 |
| 6 | 1 | enforce | 34.835577 | 41.556992 | 46.636191 |
| 7 | 0 | enforce | 34.446088 | 40.620821 | 46.695350 |
| 7 | 1 | off | 0.008446 | 0.014284 | 0.018563 |
| 8 | 0 | off | 0.008500 | 0.014324 | 0.019588 |
| 8 | 1 | enforce | 33.834039 | 38.605832 | 43.159212 |
| 9 | 0 | enforce | 34.581551 | 41.085574 | 45.891250 |
| 9 | 1 | off | 0.008561 | 0.014350 | 0.019099 |

The JSON retains every inclusive span, derived exclusive span, span call count,
environment identity, Git/component identity, and storage posture. The CSV retains
one row per measured operation. Fixture construction and root issuance are excluded.

The Warden is unanchored. The executor uses a process-file anchor, but its anchor
and replay database are intentionally within the same temporary storage root, so this
does not establish independent rollback domains. AstralPlane is pinned by the
composition, but the timed host binding/effect-coordinator adapters are deterministic
and in-memory; no PostgreSQL transaction is included.
