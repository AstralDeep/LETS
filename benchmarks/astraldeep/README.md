# AstralDeep case-study harness

This directory is tracked tooling. Measured output and manuscript state are not.
Before running an experiment, the operator must explicitly ignore
`results/astraldeep-case-study/`; every CLI here refuses any other output root
and never overwrites retained evidence.

## Driver protocol

`run_case_study.py` invokes an exact-composition AstralDeep driver once for each
of 19 scenarios in a single mode:

- all six `astral.tools/v1` scopes;
- provision, spawn, renew, quiesce, resume, close, and revoke lifecycle events;
- parallel and recursive dispatch; and
- warden outage, receipt replay, budget exhaustion, and a post-revocation effect.

Run `off`, `shadow`, and `enforce` into separate directories. The driver reads
one `lets.astraldeep-case-study-scenario/v1` object from stdin and writes one
`lets.astraldeep-case-study-result/v1` object to stdout. A result contains the
matching scenario identity, bounded counters, the converged lifecycle state,
budget-conservation and monotonic-sequence attestations, and raw numeric
measurement samples. The runner independently enforces
flag-off/no-call, shadow/no-claim, enforce/one-claim-per-effect, denial, and zero
unreceipted-governed-effect invariants.

```powershell
uv run --locked --extra dev python -m benchmarks.astraldeep.run_case_study `
  --mode enforce `
  --evidence-class astral-integration `
  --astraldeep-root ../AstralDeep `
  --output results/astraldeep-case-study/integration/enforce
```

The runner accepts no caller-selected executable, working directory, or driver
arguments. It invokes only `backend/tests/lets_case_study_driver.py` from the
exact clean AstralDeep worktree through that worktree's canonical `.venv`
interpreter, passes a minimal allowlisted environment, and rejects a changed
driver, interpreter, AstralPlane import tree, LETS import tree, or component
pin. Caller-provided `PYTHONPATH` is discarded; the driver derives only the
pinned component source roots for its LETS helper subprocesses. The retained
identity contains only revisions, counts, versions, and digests. Do not
substitute expected values for driver measurements.

## Evidence capture

Create a public runtime-identity input with only these required fields:

```json
{
  "config_epoch": 1,
  "format": "lets.astraldeep-runtime-identities/v1",
  "lets_release": "v1.0.10",
  "machine_digest": "sha256:<64 lowercase hex characters>",
  "policy_digest": "sha256:<64 lowercase hex characters>",
  "scope_profile": "astral.tools/v1"
}
```

Optional public fields are `api_version`, `receipt_wire_type`, and
`warden_topology`. Never provide a trust private key, bearer token, credential,
user/host path, or patient identifier. Capture requires all five worktrees to
be clean and verifies the Projection, Plane, and Primitives commits against the
retained composition. The LETS repository commit identifies this tracked
harness; the composition separately identifies the exact released LETS runtime
pin.

```powershell
uv run --locked --extra dev python -m benchmarks.astraldeep.capture_environment `
  --run-manifest results/astraldeep-case-study/integration/enforce/run.json `
  --composition ../AstralDeep/config/astral-composition.json `
  --runtime-identities results/astraldeep-case-study/runtime-identities.json `
  --repository astraldeep=../AstralDeep `
  --repository astral-projection=../AstralProjection `
  --repository astral-plane=../AstralPlane `
  --repository astral-primitives=../AstralPrimitives `
  --repository lets=. `
  --output results/astraldeep-case-study/integration/enforce/manifest.json
```

Validation checks the standalone tracked LETS evidence schema, exact revisions,
raw composition digest, canonical and unique artifact paths, exact run-to-bundle artifact
records, successful command exits, the complete run/command/reproduction time
envelope, measurement derivation from retained samples, and every original
effect/receipt/lifecycle scenario invariant replayed from retained results. It
also recomputes the content-free execution identity from the clean Deep
worktree, requires its supplied composition bytes to match Deep's canonical
composition, requires byte-canonical driver JSON, and applies the tracked
secret/credential and PHI scanner. A
`release-baseline` bundle is valid only in `off` mode and must remain distinct
from `astral-integration` evidence.

## Runtime disposition and paper gate

After committing the tracked harness, compare its clean tree with the trusted
signed-release anchor recorded by AstralDeep:

```powershell
uv run --locked --extra dev python -m benchmarks.astraldeep.check_version_disposition `
  compare `
  --release-anchor ../AstralDeep/specs/074-multirepo-lets-integration/execution/baseline.json `
  --output results/astraldeep-case-study/version-disposition.json
```

The comparison uses the immutable v1.0.10 tag object, peeled commit, tree, and
verified SSH-signature anchor. Changes to LETS runtime, wire, packaging, or
executable deployment inputs produce `successor-required`; benchmark, test,
documentation, and case-study-only changes produce `unchanged-runtime`.

The `gate` subcommand creates a readiness marker only when an unchanged-runtime
disposition matches both the current clean Git tree and a validated integration
bundle whose composition still pins the exact signed v1.0.10 commit. The gate
recomputes the path partition and runtime/protocol tree identities rather than
trusting stale disposition fields. Otherwise it exits non-zero and, for
runtime/wire changes, creates a separate successor-release handoff. Gate
outputs are forbidden under `paper/`, and no command in this directory changes
tag `v1.0.10`, publishes a release, or finalizes a manuscript.
