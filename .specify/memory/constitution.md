# LETS Constitution

## Core Principles

### I. Authority Conservation and Attenuation

LETS (Lineage Escrow Transition Systems) governs recursively created agents, replicas, and
delegates by escrowing a finite, multi-dimensional resource envelope across stable wardens.

- Every warden projection MUST conserve its envelope: initial local share plus accepted
  transfers equals free pool plus live lease residuals plus consumed rights plus sent
  transfers. The signed cluster manifest MUST make the initial warden shares sum exactly to
  the global initial budget.
- Delegation MUST only narrow: a child receives at most its parent's remaining allocation, a
  subset of its capabilities, and an expiry no later than any ancestor's. Lineage depth is
  capped at 64, and every allocation and cost is nonzero in at least one dimension.
- Two wardens MUST NOT be initialized independently with the full budget; genesis shares are
  split exactly.
- Discovery MUST NOT grant authority. An operation is enabled only when the host's policy
  gates, the lease's capabilities, residuals, and state, the evidence rules, and the
  executor's receipt policy all agree.

**Rationale**: Conservation and monotonic attenuation are the safety properties LETS exists to
provide; everything else in the system is built to preserve them.

### II. Fail-Closed Trust Boundaries and Complete Mediation

- Every protected transition produces an audience-bound receipt. An executor MUST NOT perform
  an effect unless `verify_and_claim` succeeds; an exception or a lost reply never
  authorizes.
- `verify_and_claim` provides at-most-once authorization. LETS MUST NOT claim that a generic
  receipt makes an arbitrary external side effect exactly once; exactly-once effects require
  the host to bind the claim and the effect in one transaction or make the effect idempotent.
- Identity MUST be derived from a verified token or a mutually authenticated connection,
  never trusted from JSON fields.
- Peer messages MUST be Ed25519-signed with durably claimed nonces; clock floors persist
  across restarts; production stores bind external compare-and-swap anchors so that a stale
  restore or a losing clone fails admission. A reused `request_id` with changed content
  fails.
- TLS is required off loopback. Insecure modes are explicit developer overrides (for example
  `--allow-insecure-http`), and production guards (the mTLS profile, WAL-safe patched SQLite,
  a bootstrap token shown once and stored only as a digest, and no private seed in the
  database) MUST NOT be weakened.
- `docs/threat-model.md` defines the trusted base, untrusted inputs, and non-goals; a change
  that alters any of them MUST update it in the same change.

### III. Canonical, Versioned Wire Contracts

- Every signature and digest MUST use LETS-CJ/1 canonical JSON (lossless int64, no floats, no
  duplicate keys) and unpadded base64url. `protocol/canonicalization-vectors.json` is
  normative.
- The committed `protocol/openapi.yaml` MUST equal the generated OpenAPI document, and its
  `info.version` MUST equal `lets.__version__` and the `pyproject.toml` version; tests enforce
  both.
- Wire types (`lets.receipt/v1`, `lets.lease-grant/v1`, `lets.manifest/v1`), `API_VERSION`, the
  warden storage schema, and the executor replay schema are versioned. Changing one requires a
  release with compatibility notes; silent padding is forbidden, a new resource dimension
  requires a new policy version, and mixed-version clusters are unsupported.
- The consumer compatibility surface (the public client, executor, authorizer, and receipt
  exports, `API_VERSION`, the OpenAPI digest, the receipt wire type, and the tool scope
  profile) MUST change only in a release.

### IV. Standalone, Protocol-Neutral Core

- LETS MUST NOT import host code (including AstralDeep) or read or write host tables. It is not
  an agent framework, scheduler, model host, or transport.
- Adapters in `src/lets/integrations/` MUST stay thin and are never authority roots: they
  accept only lifecycle IDs, rights vectors, capabilities, TTLs, evidence, and policy
  references, never credentials, process memory, owner identity, open sockets, or opaque
  agent state. An adapter failure MUST NOT turn a denial into an allow.
- Cross-node placement MUST use free-right transfer followed by issuance at the target.
  Copy-and-delete migration is forbidden because it can duplicate authority.

### V. Evidence-Bound Formal Verification

- The TLA+ specification (`formal/LETS.tla`, `formal/LETS.cfg`), the bounded checker
  (`formal/model_checker.py`), and the pinned TLC tool (`formal/tlc-tool.json`) are
  digest-bound to their recorded results; changing any of them MUST regenerate that evidence
  in the same change.
- The duplicate-credit mutant MUST produce a counterexample.
- Formal results MUST be described as bounded exhaustive checking, not proof.

### VI. Durable State and Explicit Migration

- Warden storage uses SQLite in WAL mode with `synchronous=FULL` and one durable transaction per
  command (`BEGIN IMMEDIATE`).
- Schema changes MUST go through the explicit, journaled, stop-the-world `lets migrate`
  operation, run as a dry run first. Automatic or rolling migration is prohibited, and no
  rollback crosses an irreversible migration; `docs/upgrade-recovery.md` documents each step.

### VII. Test and Coverage Discipline

- Tests MUST cover golden, denial, adversarial, property-based, and fault paths; real Docker
  multi-node and injected-fault acceptance tests carry the `e2e` marker.
- CI MUST keep at least 90% coverage of changed lines in the measured packages (`lets` and
  `benchmarks.astraldeep`) and the total coverage floor in `pyproject.toml` (currently 74%). A
  change with no measurable executable lines makes changed-line coverage not applicable, and
  that outcome MUST be recorded explicitly.
- Supported Python is 3.11 through 3.14; CI MUST test that range on Linux and at least its
  ends on Windows.
- Shipped code MUST NOT contain work-in-progress, stubbed, mocked, hard-coded, or debug-only
  paths.

### VIII. Enforced, Bounded, Tamper-Resistant CI

- `.github/workflows/ci.yml` (quality, test matrix, distributed acceptance, and the `required`
  aggregate) and `.github/workflows/security.yml` (Bandit, strict pip-audit, distribution and
  wheel checks, SBOMs, the container build-context policy, actionlint, the hardened container
  run, the patched-SQLite check, and Trivy) MUST run on every pull request and every push to
  `main`.
- The workflow-contract tests (`tests/test_ci_workflow.py` and
  `tests/unit/test_production_deployment.py`) pin approved action SHAs, triggers, the matrix,
  thresholds, hash-locked tools, and timeouts, and forbid `continue-on-error`; they MUST NOT be
  weakened.
- Every CI job MUST finish within 30 minutes and declare `timeout-minutes` of at most 30.
  Release build and signing jobs are not test gates.
- Required gates MUST NOT depend on live third-party network services, exact clock-derived
  values, or wall-clock performance bounds. Soak tests are prohibited; per-test retries are
  permitted and whole-suite reruns are not. A gate MUST fail only for a defect the change
  introduced or can fix.

### IX. Signed, Reproducible, Immutable Releases

- The package and the OCI image share one semantic version. The release tag is `v` plus that
  version, which MUST equal the `pyproject.toml` version, `lets.__version__`, and the
  `CHANGELOG.md` heading.
- A release MUST come only from `.github/workflows/release.yml` on an annotated, verified tag
  that points at current `main` whose `ci` and `security` runs passed. The workflow builds
  twice and compares the results, runs hardened acceptance on the exact candidate, scans and
  attests every architecture, signs the image, and publishes an immutable release with the
  exact asset set. Release notes MUST include a "Compatibility, migration, and rollback"
  section.
- Releases are never built on a workstation, and tags are never moved or reused. The image
  digest is the deployment identity; defects are fixed forward.

### X. Minimal, Locked Supply Chain

- The core runtime dependency MUST remain minimal (currently PyNaCl only); the server, client,
  and development extras hold the rest. A new core runtime dependency MUST be justified
  against the trusted base in its pull request.
- `uv.lock` is used frozen in a repository-local virtual environment; the build backend,
  container base images, and system packages are pinned exactly; CI tools are hash-locked and
  kept out of package metadata. Every other dependency MAY be added when declared in its
  owning manifest.
- Secrets MUST NOT be committed, and the container build context MUST exclude secret-like
  material (`deploy/production/check_build_context.py`).

### XI. Research and Evidence Integrity

- No production, performance, scale, or safety claim may exceed retained evidence. A result is
  admitted only when its exact source version and configuration are identifiable, and
  expected values MUST NOT substitute for measurements.
- Sealed evidence bundles MUST NOT be edited; later corrections go in a separate scope record.
  Evidence campaigns run from a completely clean exact checkout and never overwrite prior
  results. Diagnostics that bypass durability are marked `production_semantics=false`.
- Every citation MUST be verified against its source, and citations to living documents are
  pinned with identifier, status, and retrieval date.
- Manuscripts and anonymized submission builds stay outside the repository; an anonymized
  build MUST be checked for leaked identities.

### XII. Self-Documenting Source

- Every source and test file MUST begin with a header of at most three sentences stating what
  it does and how it connects to other files; Python uses a module docstring.
- No other comments or docstrings are permitted, except a single-line comment where one is
  absolutely necessary to explain a non-obvious *why*. Function and class docstrings,
  narrating comments, commented-out code, TODO/FIXME notes, spec, task, and requirement IDs,
  feature numbers, and change history MUST NOT appear in source. Tool directives are not
  comments and are preserved verbatim.
- Text the runtime reads (CLI help, OpenAPI descriptions, schema descriptions) MUST be an
  explicit value, not a docstring. The HTTP API publishes normative OpenAPI instead of
  interactive `/docs`.
- Files whose exact bytes are pinned by recorded evidence (Principle V) change only together
  with a regeneration of that evidence.
- Documentation claims MUST match the code as merged.
- Files generated and managed by Spec Kit (`.specify/`, `.agents/`, `.claude/`) are upstream
  tooling, exempt from this principle, and change only through Spec Kit.

## Consumers and Compatibility

- AstralDeep consumes LETS as an external, feature-gated component pinned by commit and
  release, together with the API version, OpenAPI digest, receipt wire type, and scope
  profile; the AstralProjection Windows client uses the executor. Consumers adopt changes only
  by moving their pins under their own constitutions, and this repository never edits them.
- Only a signed release tag is a LETS release. A consumer pin of any other commit is a pin to
  unreleased source, and the compatibility surface (Principle III) is guaranteed only at a
  release.

## Development Workflow

- Changes land through pull requests (including Dependabot's) qualified by `ci.yml` and
  `security.yml` unless the owner explicitly authorizes a direct push; a directly pushed
  change runs the same gates on `main`.
- User-visible changes are recorded under `[Unreleased]` in `CHANGELOG.md`.
- Reviewers MUST verify constitution compliance, including the security invariants
  (Principles I and II), contract versioning (Principle III), evidence binding (Principles V
  and XI), and headers and comments (Principle XII).
- Spec, task, and feature IDs belong in pull request descriptions, never in source or tests.

## Governance

- This constitution is the highest-authority engineering policy for LETS and supersedes
  `README.md`, `docs/`, and other guidance where they conflict. It replaces the AstralDeep
  constitution as this repository's governing document; AstralDeep's constitution governs only
  how AstralDeep consumes LETS.
- Amendments land by pull request unless the owner explicitly authorizes a direct push. Each
  amendment is approved by the owner or a lead developer and records its rationale, version
  change, and Sync Impact Report in the pull request or commit message.
- Versioning follows semantic versioning: MAJOR for principle removals or redefinitions,
  MINOR for new principles or materially expanded guidance, and PATCH for clarifications.
- Every pull request and review MUST verify compliance. Violations are resolved before merge,
  and known shortfalls are tracked as follow-up work until closed.
- References to numbered constitution principles in records written before 2026-09-28 refer
  to the AstralDeep constitution v5.0.0.

**Version**: 1.0.0 | **Ratified**: 2026-09-28 | **Last Amended**: 2026-09-28
