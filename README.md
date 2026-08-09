# LETS

LETS—Lineage Escrow Transition Systems—is a real distributed runtime for governing recursively
created agents, replicas, delegates, robots, services, and other autonomous workers.

Stable warden nodes own disjoint shares of a finite, multi-dimensional resource envelope.
Ephemeral subjects receive signed, expiring, capability-attenuated leases; child replicas can
receive only rights removed from a parent. Every protected state transition produces a short-lived,
audience-bound receipt that an independent executor verifies and durably consumes.

LETS is standalone and protocol-neutral. It does not depend on AstralDeep, MCP, A2A, Kubernetes,
or a particular model/runtime. The included adapter contracts make host integration small without
moving host authorization or secrets into LETS.

## What is implemented

- independently persisted warden processes with SQLite WAL and `synchronous=FULL` transactions;
- signed cluster manifests with exact genesis-share conservation and operator trust thresholds;
- immutable, content-addressed policy and state-machine definitions;
- root issuance, child replication, capability attenuation, nested TTLs, lifecycle control, and
  branch revocation;
- atomic, idempotent transition accounting and signed executor receipts;
- protected-executor signature, audience, time, policy, sequence, nonce, and replay verification;
- authenticated peer HTTP messages with Ed25519 signatures and durable nonce replay defense;
- sequenced cross-warden rights transfer with exactly-once target credit, bounded reordering,
  acknowledgement finalization, and signed prefix compaction;
- hash-chained signed audit records, bounded pagination, outbox state, invariants, readiness, and
  operational metrics;
- a typed HTTP client, CLI/bootstrap workflow, three-node Docker topology, and fault/e2e tests;
- a host-neutral replica adapter plus an AstralDeep profile that imports no AstralDeep internals.

The original in-memory research kernel and draft manuscript are retained under `prototype/` and
`paper/original-draft.pdf`; they are not the production runtime.

## Safety model

For each warden projection of an envelope, LETS enforces:

```text
initial local share + cumulative accepted transfers
  = free pool + live lease residuals + consumed rights + cumulative sent transfers
```

The signed cluster manifest additionally enforces:

```text
sum(all initial warden shares) = global initial budget
```

Local transitions require no cross-node round trip. A warden can therefore continue safely during
a peer/control-plane partition, but only within rights already held locally. Rights stranded at an
unreachable node are unavailable; LETS chooses bounded authority over magical availability.

## Dependency isolation

All Python work uses the repository-local `.venv`. Nothing is installed into the system Python:

```powershell
uv sync --all-extras --frozen
uv run pytest
uv run lets --help
```

The package supports Python 3.11–3.14. Containers build their own image-local environment from the
committed `uv.lock`; the host `.venv` is never copied or mounted.

## One-node development start

Initialize a local node:

```powershell
uv run lets --config .lets/a/config.json init `
  --warden-id warden-a `
  --tenant-id example `
  --envelope-id agents `
  --budget 1000000,100000000 `
  --local-share 1000000,100000000
```

The command prints a bootstrap token once and stores only its SHA-256 digest. Start the warden on
loopback:

```powershell
uv run lets --config .lets/a/config.json serve --host 127.0.0.1 --port 8741
```

Inspect it:

```powershell
uv run lets --config .lets/a/config.json info
curl.exe http://127.0.0.1:8741/health/ready
```

Non-loopback serving requires TLS unless the explicit development-only
`--allow-insecure-http` flag is supplied.

## API flow

Register a policy, issue a governed root, spawn a child, and request a receipt with the synchronous
client:

```python
from lets.client import LETSClient
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec

policy = PolicySpec(
    policy_id="agents",
    policy_version="v1",
    dimensions=(
        ResourceDimension("actions", "count"),
        ResourceDimension("tokens", "token"),
    ),
    machine=MachineSpec(
        machine_id="replica",
        initial_state="ready",
        transitions=(
            TransitionSpec(
                name="run",
                source="ready",
                target="ready",
                cost=(1, 100),
                capability="agent.run",
            ),
        ),
    ),
    max_lease_ttl_ns=300_000_000_000,
    receipt_ttl_ns=1_000_000_000,
    max_clock_uncertainty_ns=50_000_000,
    transfer_gap_window=64,
)

with LETSClient("https://warden-a.example", token=bootstrap_token) as lets:
    lets.register_policy(policy.to_dict())
    root = lets.issue_root(
        {
            "request_id": "host-operation-0001",
            "tenant_id": "example",
            "envelope_id": "agents",
            "subject_id": "agent-root",
            "allocation": [1000, 1_000_000],
            "capabilities": ["agent.run"],
            "policy_digest": policy.digest,
            "ttl_ns": 60_000_000_000,
        }
    )
    receipt = lets.authorize(
        root["lease_id"],
        {
            "request_id": "tool-operation-0042",
            "transition": "run",
            "executor_audience": "protected-tool-gateway",
            "nonce": "tool-effect-0042",
            "expected_sequence": 0,
        },
    )
```

Use the host's durable operation ID as `request_id`; reuse it on retry. A reused ID with changed
content is rejected.

## Protected execution

Authorization accounting and the physical effect are separate failure domains. Install
`ReceiptVerifier` at the tool gateway or actuator with a filesystem-backed
`SQLiteReceiptReplayStore`. It verifies the warden signature, tenant/envelope/epoch, policy and
machine digests, audience, freshness, and sequence, then durably claims the receipt.

`verify_and_claim()` provides at-most-once authorization. For exactly-once physical effects, bind
the claim and effect in one domain transaction or make the effect idempotent. LETS does not pretend
a generic receipt can make an arbitrary external side effect exactly once.

## Three-node fault and production profiles

The root Compose topology is a cleartext development fault harness. It runs three independent
warden containers with separate databases, keys, and persistent volumes and exercises real HTTP
peer transfer rather than several logical wardens sharing one process or database.

```powershell
uv run --frozen python deploy/run_acceptance.py
```

The separate [production deployment](deploy/production/README.md) is one warden per Linux failure
domain with TLS and required mTLS, external signer/JWT/provider bindings, independently mounted
state/authority/audit domains, an immutable staged config, container hardening, recovery and release
runbooks, and an opt-in three-node production acceptance gate. See `deploy/`,
`docs/operations.md`, and `docs/release.md` for bootstrap, partition, recovery, backup, and release
procedures. Test harnesses record reproducible evidence under `results/generated/`.

## Host integrations

The portable adapter surface is `lets.integrations.ReplicaAuthorizer`. It deliberately accepts
only lifecycle IDs, rights vectors, capabilities, TTLs, evidence, and policy references—never
credentials, process memory, owner identity, open sockets, or opaque agent state.

The optional `AstralDeepAuthorizer` maps AstralDeep's six declared tool scopes to explicit LETS
capabilities/transitions while preserving AstralDeep's Keycloak/RFC 8693, owner, permission, PHI,
egress, confirmation, and audit gates. Details: `docs/adapters/astraldeep.md`.

Recommended standards composition:

- A2A Agent Cards, OASF, Agent Spec, or ARD for discovery;
- MCP or A2A for invocation and capability negotiation;
- OCI, SLSA/in-toto, SPDX, and CycloneDX for artifact provenance;
- SPIFFE and attestation evidence for workload identity;
- CloudEvents/OpenTelemetry for non-authoritative event export.

Discovery never grants authority. An operation is enabled only after the host's policy gates, the
lease's capability/residual/state, evidence rules, and the executor's receipt policy all agree.

## Repository map

| Path | Purpose |
|---|---|
| `src/lets/` | domain, policy, crypto, durable storage, warden service, API, clients, executor |
| `src/lets/integrations/` | standalone host adapter contracts and AstralDeep profile |
| `protocol/` | cluster-manifest schema and OpenAPI contract |
| `tests/` | unit, property, security, integration, fault, and real-node e2e tests |
| `deploy/` | Docker topology and bootstrap assets |
| `formal/` | bounded model and trace-conformance tooling |
| `benchmarks/` | reproducible workloads and profiling harnesses |
| `docs/` | architecture, threat model, operations, ADRs, and integrations |
| `paper/` | reproducible LaTeX source and rebuilt manuscript |
| `prototype/` | preserved pre-runtime research kernel; not imported by `lets` |

## Verification

```powershell
uv run ruff check src tests
uv run mypy src
uv run pytest
uv run pytest --cov=lets --cov-report=term-missing
```

The committed coverage gate is a measured 74% branch-aware regression floor for the current
runtime; it is not presented as a substitute for the fault, adversarial, and bounded-state checks.

Paper and artifact reproduction commands are documented in `paper/README.md` and the root
`Makefile` after the runtime evidence is regenerated.

## Current boundaries

LETS 1.0 is a production release within the documented v1 threat and lifecycle boundary. It has
not yet received an independent third-party security audit. Its explicit boundaries are:

- one envelope per SQLite database;
- one live warden identity per local-disk database; production monotonic anchors make stale or
  losing clones fail closed, but shared filesystems and multi-writer operation remain unsupported;
- trusted (non-Byzantine) wardens in the base protocol;
- no supported simultaneous use or automatic merge of cloned/restored warden state;
- no live configuration-epoch rollover;
- no arbitrary active-subtree migration; v1 transfers free rights and issues at the target;
- no automatic copying of agent artifacts, workspace state, memory, identities, or secrets;
- no exactly-once external-effect claim without an executor/domain transaction.

Read `docs/threat-model.md` and `docs/operations.md` before deploying. Security reports belong in
GitHub's private vulnerability-reporting channel, as described in `SECURITY.md`.

Licensed under Apache-2.0.
