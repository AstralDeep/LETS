# LETS Research Artifact

This repository accompanies the extended research draft:

> **LETS: Lineage Escrow Transition Systems for Partition-Safe Autonomous Agent Populations**

LETS is a candidate abstract object and enforcement architecture for constraining the aggregate protected effects of recursively changing autonomous-agent lineages. A bounded set of stable wardens owns distributed escrow state; ephemeral agents receive signed, expiring, capability-attenuated leases and may spawn descendants by partitioning their own residual rights. The reasoner is outside the trusted computing base.

## Status and claim boundary

This is a research package, not a production authorization system. The package deliberately distinguishes:

- **Established mechanisms:** escrow, bounded counters, capabilities, leases, recursive delegation, HSMs, lineage, and lifecycle management.
- **Proposed contribution:** the lineage-oriented transition-escrow abstraction, stable-warden/ephemeral-agent split, operational semantics under partition, online metadata bound after compaction, and bounded offline branch-revocation exposure.
- **Preliminary evidence:** an in-memory Python kernel, eight unit tests, a bounded exhaustive checker, analytical metadata model, and laptop-scale simulations.
- **Unvalidated work:** durable multi-warden networking, crash recovery, executor receipt enforcement, transfer compaction, active-subtree migration, Byzantine wardens, and realistic cyber-physical workloads.

The novelty audit is documented in `research_dossier.md`, `literature_matrix.csv`, and `citation_verification.csv`. It should be rerun before submission because 2026 agent-systems literature is moving rapidly.

## Artifact layout

| Path | Contents |
|---|---|
| `paper.tex`, `references.bib` | Editable arXiv-style manuscript and verified bibliography |
| `paper.pdf` | Compiled 36-page manuscript |
| `research_dossier.md` | Literature review, collision log, candidate ranking, proposal, reviewer-risk analysis |
| `engineering_roadmap.md` | Eight-week implementation plan, MVP, effort estimates, and go/no-go gates |
| `protocol.md`, `openapi.yaml` | Protocol contract and editable API sketch |
| `prototype/lets.py` | Auditable in-memory LETS reference kernel |
| `prototype/test_lets.py` | Eight unit tests |
| `prototype/benchmark.py` | Preliminary simulations and microbenchmark |
| `prototype/analyze_results.py` | Mann–Whitney tests, Cliff's delta, and Holm correction |
| `formal/exhaustive_checker.py` | Executed bounded state-space checker |
| `formal/LineageEscrow.tla`, `formal/MC.cfg` | Finite TLA+ model; included but not claimed as an executed TLC result |
| `figures/` | Diagram/plot source plus PDF and PNG outputs |
| `results/` | Raw CSV/JSON outputs and logs |

## Environment

Reference environment used for final artifact validation:

- Python 3.13
- `cryptography` 46.0.4
- `matplotlib` 3.10.8
- `scipy` 1.17.0
- Graphviz `dot`
- TeX Live with `latexmk` and `bibtex8`

Create an isolated environment and install Python dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Reproduce the executable evidence

Run the unit tests:

```bash
PYTHONPATH=prototype python -m unittest discover -s prototype -p 'test_*.py' -v
```

Run the bounded exhaustive checker:

```bash
python formal/exhaustive_checker.py
```

Regenerate the preliminary datasets, statistics, and plots:

```bash
PYTHONPATH=prototype python prototype/benchmark.py --output-dir results --seeds 30 --operations 20000
python prototype/analyze_results.py
python figures/make_plots.py
```

Regenerate architecture, lifecycle, sequence, and deployment diagrams:

```bash
python figures/make_diagrams.py
```

The diagram script requires Graphviz. The benchmark rewrites the CSV/JSON files in `results/`; microbenchmark throughput will vary by machine. Safety counts and seeded simulation outcomes should remain reproducible under the stated dependency range.

## Build the paper

The `.latexmkrc` file selects `bibtex8`, because a `bibtex` executable was not present in the validation container.

```bash
make paper
```

Equivalent command:

```bash
mkdir -p build
latexmk -r .latexmkrc -pdf -interaction=nonstopmode -halt-on-error -outdir=build paper.tex
cp build/paper.pdf paper.pdf
```

## One-command workflow

```bash
make all
```

This runs the tests, checker, simulations, statistical analysis, figures, diagrams, and paper build. It does not execute TLC/Apalache, a distributed deployment, or a real sensor workload.

## Current preliminary results

The checked artifact reports:

- 8/8 unit tests passing.
- 35,209 unique bounded-model states and 127,480 transitions explored.
- 8,986 duplicate-transfer acceptance self-loops handled idempotently.
- No conservation violation found within the finite checker bounds.
- In the included 30-seed partition simulation, LETS preserves the configured budget and continues local work; the centralized baseline is safe but loses work while disconnected; the deliberately unsafe eventual-accounting baseline exceeds the budget in every run.

These results are feasibility evidence only. The baselines are intentionally diagnostic and do not constitute a publication-grade comparative evaluation.

## Submission-critical next steps

The minimum publishable implementation must add durable transactional wardens, authenticated RPC, replay-safe executor receipts, crash/restart recovery, compact transfer watermarks, partition/fault injection, and one realistic sensor-driven workload. Active-subtree migration should either be implemented with a checked protocol or removed from the main contribution. The go/no-go criterion is whether LETS demonstrates a measurable advantage beyond a conventional bounded counter plus lease layer while retaining a concise, auditable invariant.

# LETS
