# AstralDeep host-mediation case study, 2026-10-23

A fresh run of the fixed 19-scenario AstralDeep host-mediation suite
(`benchmarks/astraldeep/`) in each of the three host modes, with every raw
artifact retained:

- `off`: the LETS feature flag is off; the host never contacts LETS.
- `shadow`: the host asks LETS for every governed call and records the answer,
  but never claims a receipt or blocks a call.
- `enforce`: every governed tool call needs a warden-signed receipt that the
  protected executor claims, exactly once, before the tool runs.

All 57 driver invocations (19 per mode) exited 0 and passed the runner's
per-scenario checks. The counts match the 2026-08-22 qualification summarized in
`results/nsdi-evidence-scope-2026-09-03.json`, whose raw bundle was not kept.

## Exact revisions

| Input | Revision |
| --- | --- |
| AstralDeep (host adapter and driver) | `3627625edb6ca461c0a847dc160b978496c39f72` |
| LETS runtime imported by the driver (composition pin, ref `v1.1.0`) | `ed5c1e4bd61a6b11625d265aeb77229b7c2c017b` |
| LETS harness that ran the suite | `a70f07388c0bb843623e09a2aaab8d97a6769538` |
| AstralPlane / AstralProjection / AstralPrimitives | `5ecce4cc` / `5ac37abe` / `d7b45410` |
| Interpreter | CPython 3.11.15, Windows 10, x86-64, 32 logical CPUs |
| Run window (UTC) | 2026-10-23 01:24:59 to 01:26:31 |

The LETS `src/` tree is identical at the runtime pin and the harness commit.
Every repository was clean during the run and capture.

## Counts per mode

| Mode | Scenarios passed | LETS requests | Receipts issued | Receipts claimed | Tool calls that ran | Calls refused | Governed calls without a claimed receipt |
| --- | --- | --- | --- | --- | --- | --- | --- |
| off | 19/19 | 0 | 0 | 0 | 18 | 0 | 0 |
| shadow | 19/19 | 33 | 15 | 0 | 18 | 0 | 0 |
| enforce | 19/19 | 33 | 15 | 15 | 14 | 4 | 0 |

In `off` and `shadow` the four fault scenarios run their tool call, which is why
those modes show 18 calls. Budgets were conserved, receipt sequences were
monotonic, and all seven lifecycle events converged in every mode.

## Enforce mode, scenario by scenario

| Scenario | Host decision | LETS requests | Issued | Claimed | Tool calls | Refusal code |
| --- | --- | --- | --- | --- | --- | --- |
| six tool scopes (read, write, search, system, files, execute) | allowed | 1 each | 1 each | 1 each | 1 each | |
| seven lifecycle events | not applicable | 14 total | 0 | 0 | 0 | |
| parallel dispatch, four branches | allowed | 4 | 4 | 4 | 4 | |
| recursive dispatch, depth 3 | allowed | 4 | 4 | 4 | 4 | |
| warden outage | denied | 1 | 0 | 0 | 0 | `warden_unavailable` |
| receipt replay | denied | 1 | 1 | 1 | 0 | `receipt_replayed` |
| budget exhaustion (all-zero allocation) | denied | 1 | 0 | 0 | 0 | `budget_exhausted` |
| call after the binding was revoked | denied | 2 | 0 | 0 | 0 | `binding_unavailable` |

The 15 claims are the 14 claims that preceded the 14 tool calls plus the
receipt-replay scenario's receipt: the executor claims that receipt once
without running the tool, then the same receipt is presented again to
`claim_and_invoke`, which rejects it as a replay before the tool runs. The
post-revocation scenario's two LETS requests are the lifecycle provision and
revoke; the host refuses the tool call itself before contacting the warden.

## What this suite does and does not exercise

- Real code: AstralDeep's governed dispatch, authorization gateway, lifecycle
  service, and scope profile; the LETS executor with its SQLite claim store;
  Ed25519 receipt signing and verification.
- Stand-in: the warden is the driver's in-process measuring double, which signs
  real receipts but keeps the budget in memory. The warden outage is that
  double raising `warden_unavailable`, not a network failure.
- Measurements are descriptive single samples (147 of 151 measurements have one
  sample, at most 4), so they support no tail-latency or statistical claim.
- Policy and machine digests are placeholder patterns from the driver's test
  rig; they bind this run consistently but are not deployment identities.

## Release gate and how the bundle was captured

The tracked capture and aggregate tooling is bound to signed `v1.0.11`. The
composition now pins LETS ref `v1.1.0`, whose runtime differs from `v1.0.11` and
which has no signed tag yet, so:

- `check_version_disposition compare` produced `successor-required`
  (`bundle/version-disposition.json`), and `gate` refused finalization and wrote
  `bundle/successor-release-handoff.json`. Both are kept as produced.
- The tracked `capture_environment` refused each mode because its evidence
  schema requires `lets_release` = `v1.0.11`. The mode manifests were captured
  with `tools/release_schema.py`, which runs the tracked capture with a schema
  copy whose two `v1.0.11` release constants are `v1.1.0`
  (`tools/case-study-evidence.v1.1.0.schema.json`; nothing else differs).
- The tracked aggregate requires the `v1.0.11` readiness marker, so it cannot
  run. `summary.json` comes from `tools/ungated_summary.py`, which calls the
  tracked aggregate's own validation and summary functions and skips only the
  release-gate binding; its `release_gate` section records this.

## Reproduce

From a LETS checkout at the harness commit with `uv sync --locked --all-extras`,
and an AstralDeep worktree at the commit above with its components initialized
at their pins and a Python 3.11 `.venv` at its root (`uv venv`, then
`uv pip install -r backend/requirements.txt`). Exclude
`results/astraldeep-case-study/` from Git (for example through
`core.excludesFile`), because every tracked command refuses non-ignored output.

```text
uv run --locked --no-sync python -m benchmarks.astraldeep.run_case_study --mode off --evidence-class release-baseline --astraldeep-root <deep> --output results/astraldeep-case-study/baseline/off
uv run --locked --no-sync python -m benchmarks.astraldeep.run_case_study --mode shadow --evidence-class astral-integration --astraldeep-root <deep> --output results/astraldeep-case-study/integration/shadow
uv run --locked --no-sync python -m benchmarks.astraldeep.run_case_study --mode enforce --evidence-class astral-integration --astraldeep-root <deep> --output results/astraldeep-case-study/integration/enforce
```

Write `results/astraldeep-case-study/runtime-identities.json` with the same
bytes as `bundle/runtime-identities.json`, then capture each mode (`PYTHONPATH=.`):

```text
uv run --locked --no-sync python results/astraldeep-case-study-2026-10-23/tools/release_schema.py v1.1.0 tmp/schema.json capture --run-manifest <mode-dir>/run.json --composition <deep>/config/astral-composition.json --runtime-identities results/astraldeep-case-study/runtime-identities.json --repository astraldeep=<deep> --repository astral-projection=<deep>/components/AstralProjection --repository astral-plane=<deep>/components/AstralPlane --repository astral-primitives=<deep>/components/AstralPrimitives --repository lets=. --output <mode-dir>/manifest.json
uv run --locked --no-sync python -m benchmarks.astraldeep.check_version_disposition compare --release-anchor <deep>/specs/074-multirepo-lets-integration/execution/lets-v1.0.11-release-anchor.json --output results/astraldeep-case-study/version-disposition.json
uv run --locked --no-sync python results/astraldeep-case-study-2026-10-23/tools/release_schema.py v1.1.0 tmp/schema.json summary --evidence-root results/astraldeep-case-study --output tmp/summary.json
```

Re-running the last command against `bundle/` revalidates every retained
artifact digest and reproduces `summary.json` except its `generated_at` field.

## Files

- `bundle/baseline/off/`, `bundle/integration/shadow/`,
  `bundle/integration/enforce/`: per mode, `run.json` (runner record),
  `manifest.json` (captured evidence), `raw/scenarios/*.request.json` (the 19
  scenario inputs), `raw/commands/*.stdout.json` (the driver's full result for
  each scenario), `raw/commands/*.stderr.txt` (all empty), and `anchors/`
  (composition bytes, runtime identities, repository revisions).
- `bundle/runtime-identities.json`, `bundle/version-disposition.json`,
  `bundle/successor-release-handoff.json`: the runtime-identity input and the
  release-gate outputs.
- `summary.json`: cross-mode summary with every per-scenario outcome and
  measurement.
- `tools/`: the capture wrapper, the summary builder, and the schema copy they
  use.
