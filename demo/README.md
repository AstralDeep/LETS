# LETS demo — Warden Register

A working demo application built on [LETS 1.0.10](https://github.com/AstralDeep/LETS/releases/tag/v1.0.10)
(Lineage Escrow Transition Systems), a distributed authorization runtime for populations of
autonomous agents.

LETS is not an agent framework. It is the accounting and authorization layer underneath one.
Its claim is that agents should not hold permissions — they should hold a **finite budget they
can subdivide but never inflate**, and every protected effect should require a signed receipt.

This demo makes that claim checkable. It runs a real warden node, drives a fleet of agents
against it, and puts the runtime's own answers on screen.

## Quickstart

```powershell
.\scripts\bootstrap.ps1   # venv, verified release wheel, `lets init`
.\scripts\run.ps1         # starts the warden + dashboard, opens the browser
```

Then click through the controls, top to bottom. `scripts\reset.ps1` rebuilds the node from
scratch if you want the genesis budget back.

Ctrl+C in the `run.ps1` window stops both processes. If that window is gone — or a warden is
left holding its node lock — `scripts\stop.ps1` stops them by port:

```powershell
.\scripts\stop.ps1          # dev and production
.\scripts\stop.ps1 -Dev     # or just one pair
.\scripts\stop.ps1 -Prod
```

Three pages:

- **`/`** — the live register. A lineage tree, the conservation ledger, and a journal of
  what the warden allowed or refused. Beside the ledger, a running commentary explains what
  the current numbers mean and what to look at next.
- **`/delegation`** — [an animated walkthrough](demo/static/delegation.html) of what
  delegation does to an agent's budget: escrow out of the parent, both refusals, and an
  agent working itself to a halt. Scripted, so it makes the point without needing a warden.
- **`/docs`** — [how LETS works](demo/static/docs.html): the problem it solves, its vocabulary,
  the conservation rule, the four lifecycle seams, and how this demo maps onto them.

## What the demo proves

Four claims, each visible in the interface and each verifiable headlessly:

| # | Claim | Where you see it |
|---|---|---|
| 1 | **A child cannot outspend its parent.** Spawning is an atomic escrow out of the parent's residual. | *Delegate to new agent* moves budget down the tree; *Ask for more than parent holds* is refused with `policy_denied — parent residual does not cover the child allocation`. |
| 2 | **Capability attenuation is one-way.** A child can only ever hold a subset of its parent's capabilities. | *Ask for withheld capability* is refused with `policy_denied — child capability set is not attenuated from its parent`. |
| 3 | **The conservation equation never breaks** — across every operation, allowed or denied. | The Conservation panel, which re-derives the arithmetic client-side rather than trusting the warden's own health flag. |
| 4 | **Work debits the residual, and a drained agent simply stops.** | *Run research* costs `[1, 500]`; *Run until refused* works an agent to exhaustion and ends in `policy_denied — lease residual does not cover transition cost`. |

Run the same checks without a browser:

```powershell
.\.venv\Scripts\python.exe verify_core_four.py
```

It asserts the exact arithmetic — that a parent's residual falls by *precisely* the child's
allocation, that a denial leaves the lease tree byte-identical, that consumed rises by exactly
the transition cost — and exits non-zero if any of it fails.

## Two details worth pointing at

**The ledger checks itself.** `_ledger()` in [demo/fleet.py](demo/fleet.py) recomputes
`free_pool + residuals + consumed + sent = genesis + accepted` componentwise from the
`/v1/invariants` snapshot. The warden also reports a `healthy` boolean, and the demo ignores it.
A status light a system grades itself on proves nothing; the arithmetic printed on screen is
the actual claim.

**A refusal has to cost nothing.** Every denied action records whether the ledger moved, and the
journal says *"ledger unchanged — the refusal moved nothing"*. A permission system that rejected
requests while still leaking budget would be worse than useless, so the demo shows the absence of
an effect, not just the presence of an error message.

The red text in the journal is never written by this demo — `code` and `detail` come straight off
the wire from the warden's RFC 9457 problem documents.

## How it fits together

```
┌─ browser ──────────┐  HTTP   ┌─ demo app ─────────┐ LETSClient ┌─ warden ────────┐
│ dashboard          │ ──────▶ │ FastAPI :8800      │ ─────────▶ │ lets serve :8741│
│ tree · ledger · log│ ◀────── │ holds token + tree │ ◀───────── │ SQLite + Ed25519│
└────────────────────┘ /api/*  └────────────────────┘   bearer   └─────────────────┘
```

The demo app *is* the host application in LETS terms: it owns durable operation IDs, holds the
credential, and calls the runtime at its four lifecycle seams. The browser never sees the token.

| File | Role |
|---|---|
| [demo/policy.py](demo/policy.py) | The immutable, content-addressed policy: two resource dimensions, three transitions |
| [demo/fleet.py](demo/fleet.py) | The host side — lease registry, the seven demo actions, the ledger check |
| [demo/server.py](demo/server.py) | FastAPI: serves both pages and one `/api/*` endpoint per action |
| [demo/identity.py](demo/identity.py) | Mints the production JWTs, one per request |
| [demo/static/index.html](demo/static/index.html) | The register: tree, ledger, commentary, journal |
| [demo/static/delegation.html](demo/static/delegation.html) | The animated delegation walkthrough |
| [demo/static/docs.html](demo/static/docs.html) | The explainer page |
| [demo/static/app.css](demo/static/app.css) | Shared styling for all three pages |
| [prod/params.py](prod/params.py) | One source of truth for every production identity and path |
| [prod/build_manifest.py](prod/build_manifest.py) | Builds and operator-signs the cluster manifest |
| [prod/signer.py](prod/signer.py) | The external signer: stdin bytes in, one signature out |
| [prod/init_node.py](prod/init_node.py) | Provisions state volumes and runs `lets init --production` |
| [verify_core_four.py](verify_core_four.py) | Headless assertions for the four claims, either node |
| [verify_production.py](verify_production.py) | Headless assertions that mTLS, JWT, and the manifest are enforced |

### Leases outlive the process that made them

A lease lives in the warden, not in this app, so an in-memory registry would orphan every
live lease on restart — their budget would stay escrowed with nothing left able to close
them. LETS has no "list my leases" endpoint to recover from that, so the host has to
remember. `Fleet` writes its registry to `.lets-demo-fleet.json` and re-adopts on startup,
keeping only leases the warden still reports as live:

```
[demo] re-adopted 2 live lease(s) from a previous run
```

This is the same obligation a real host has, which is why the demo carries it rather than
papering over it.

### The policy

Two positional dimensions — `actions` and `tokens` — and three transitions. `agent.publish` is
declared by the state machine but deliberately **never granted to the root**. That is what makes
the escalation demo a genuine attenuation failure rather than an "undeclared capability" error;
without a withheld-but-declared capability, claim 2 would be untestable.

Dimension order is load-bearing throughout. Index `i` of the warden's `--budget`, of every lease
`allocation`, and of every transition `cost` all refer to the same resource. LETS treats units as
declarative labels and does no unit math.

## Running it for real

The quickstart above runs the configuration LETS itself calls development-grade. A second
node runs under a genuine `--production` admission, alongside the first — the dev node in
`.lets\a` is untouched and keeps working.

```powershell
.\scripts\bootstrap-prod.ps1   # keys, PKI, signed manifest, `lets init --production`
.\scripts\run-prod.ps1         # warden on https://127.0.0.1:8443, dashboard on :8801
```

|  | dev | production |
|---|---|---|
| transport | `http://127.0.0.1:8741` | `https://127.0.0.1:8443`, **client certificate required** |
| identity | one static bearer token | EdDSA JWTs minted per request, 5-minute lifetime |
| signing | built-in file signer | external subprocess; the warden never holds a private key |
| trust root | CLI arguments | an operator-signed cluster manifest, re-verified every boot |
| launch | `scripts\run.ps1` | `scripts\run-prod.ps1` |

Nothing about the demo's *behaviour* changes, which is the point — the same seven actions
drive the same policy, and `verify_core_four.py` passes against either node:

```powershell
$env:LETS_DEMO_PROFILE='production'
.\.venv-prod\Scripts\python.exe verify_core_four.py
```

### Checking that the hardening is real, not decorative

`verify_production.py` asserts the parts that are easy to claim and easy to fake. It runs in
two phases because `lets serve` locks the node before it validates anything, so run it once
with the warden up and once with it down:

```powershell
.\.venv-prod\Scripts\python.exe verify_production.py
```

With the warden **running** it checks that a trusted client certificate is admitted, that no
certificate and a certificate from an untrusted CA are both refused, that the warden's own
certificate fails under the wrong CA, and that expired, wrong-audience, wrong-issuer,
untrusted-key, and under-scoped JWTs are each rejected while a valid one succeeds. With the
warden **stopped** it checks that `--production` refuses to start without TLS, without
inbound mTLS, with the built-in signer, or with a cleartext opt-in — and that flipping a
single byte in the manifest locks the node until it is restored.

A deliberately untrusted CA and client certificate are generated for exactly this purpose;
without them, "mTLS is configured" and "mTLS is enforced" look identical.

### Three things worth knowing before you run it

**It needs a specific interpreter.** `--production` refuses to run on a SQLite build without
the 2026 WAL-reset fix, which rules out the interpreter the dev demo uses. `bootstrap-prod.ps1`
searches for a conforming one and fails loudly rather than half-provisioning, which is why
production gets its own `.venv-prod`.

**The manifest is signed over a reconstruction, not over the file.** Loading a manifest
canonicalizes endpoints, drops empty descriptions, and recomputes the policy digests, so
signing the bytes you typed produces a signature that verifies against nothing.
`prod/build_manifest.py` always goes build → `unsigned_dict()` → sign → attach, and verifies
its own output before exiting. Edit the manifest by hand and the node stops booting — which
is the feature.

**There is no stored credential.** `lets init --production` prints no bootstrap token; it
reports `bootstrap_identity: external-runtime-provider` instead. The dashboard mints its own
short-lived JWTs from the issuer seed, so there is nothing to leak from a config file.

### Working around a defect in lets-agent 1.0.10

A single-warden manifest cluster cannot start as shipped. `lets init` writes `peer_endpoints`
only when it is non-empty ([cli.py:629]), and a lone warden has no peers — but the serve-time
manifest check reads it with no default and demands a mapping ([cli.py:1275]), so it fails
with *"configured peer endpoints do not exactly match the signed manifest"* against the empty
set it just computed. Every other reader in the runtime already defaults it to `{}`.
`prod/init_node.py` writes the empty object explicitly after init; the field is not one of the
ten diffed against the manifest, and an empty map is falsy, so production peer-TLS admission
is unaffected.

## Notes

- **`lets-agent` is not on PyPI.** `bootstrap.ps1` fetches the wheel from the GitHub release and
  verifies it against `RELEASE_SHA256SUMS` before installing. The distribution is `lets-agent`;
  the import package is `lets`.
- **The bootstrap token is printed once.** `lets init` stores only its SHA-256 digest, so
  `bootstrap.ps1` captures the token into `.lets-demo.json`. That file and `.lets/` (which holds
  the raw Ed25519 signing seed) are gitignored.
- **The quickstart is a development configuration**: loopback HTTP, a static bearer token, and
  the built-in file signer. LETS refuses all three under `--production`. There is now a second
  node that runs under that flag for real — see [Running it for real](#running-it-for-real).
- **Consumed budget does not come back.** Closing a lease returns its *residual* to the free pool,
  but budget spent on authorized work is spent — that is the design. After many runs the genesis
  share thins out; `scripts\reset.ps1` restores it.
- **NTFS required.** `lets init` writes its config atomically via `os.link()`, which needs a local
  NTFS volume.
