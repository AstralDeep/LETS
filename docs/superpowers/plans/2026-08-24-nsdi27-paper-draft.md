# NSDI 2027 Paper Draft Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a complete, evidence-backed named arXiv paper and a separately titled, fully anonymous NSDI 2027 Traditional Research Track paper about warden-mediated conservation of effect authority in recursive autonomous systems.

**Architecture:** One shared LaTeX manuscript consumes variant macros from two thin wrappers, so the technical text and evidence cannot drift. Deterministic evidence extraction, citation audits, vector-figure generation, PDF inspection, and anonymity checks fail closed around the two builds. The named wrapper exposes LETS, AstralDeep, and Samuel E. Armstrong, while the anonymous wrapper substitutes Lattice and Helios everywhere, including PDF metadata.

**Tech Stack:** LaTeX with the official USENIX style, BibTeX, Python 3.11 standard library, deterministic SVG/PDF figure generation, Docker-pinned TeX Live and Poppler, retained LETS JSON evidence, official provider documentation, and primary research papers.

**Spec:** `docs/superpowers/specs/2026-08-24-nsdi27-authoring-draft-design.md`

## Global Constraints

- Samuel E. Armstrong is the only author.
- The named author block is exactly `Samuel E. Armstrong, MS`, `Kentucky Open Science`, and `kyopenscience.com` on separate lines.
- The named title is `Conservation of Agentic Authority: A Warden for Recursive Autonomous Systems` unless evidence gathered during the title audit proves that a more precise, non-colliding title is needed.
- The anonymous title is `Escrowed Effect Rights for Partitioned Autonomous Systems`.
- The anonymous source maps LETS to `Lattice` and AstralDeep to `Helios`.
- No production, performance, scale, or safety claim may exceed retained evidence.
- The owner-reported production deployment is provenance, not experimental evidence.
- The manuscript contains no visible warning, watermark, draft disclaimer, altered metadata, or rhetorical hedge tied to how it was produced.
- The manuscript contains no em dashes or semicolons. Colon use remains sparse and reviewed.
- The NSDI body is at most 12 pages, and the Introduction is at most three pages.
- Figures remain readable at printed column width and in grayscale.
- The ignored `paper/submission/` tree remains local and must not be pushed while double-blind preparation is active.
- No arXiv upload, HotCRP action, artifact submission, or production-server access occurs in this plan.

---

## File Map

- `paper/submission/manuscript.tex`: all shared substantive prose, equations, tables, figure placement, labels, bibliography call, and body-page markers.
- `paper/submission/paper-arxiv.tex`: named title, LETS and AstralDeep macros, Samuel's author block, and named PDF metadata.
- `paper/submission/paper-nsdi27.tex`: anonymous title, Lattice and Helios macros, Traditional Research Track label, anonymous author field, and neutral PDF metadata.
- `paper/submission/main.tex`: compatibility wrapper that inputs `paper-arxiv.tex`.
- `paper/submission/paper-anon.tex`: compatibility wrapper that inputs `paper-nsdi27.tex`.
- `paper/submission/usenix-2020-09.sty`: unmodified official USENIX style retrieved from the official author-resources package.
- `paper/submission/TEMPLATE_PROVENANCE.md`: official template URL, retrieval date, archive digest, style-file digest, and confirmation that the style file is unmodified.
- `paper/submission/evidence.tex`: generated and reviewed LaTeX macros for every number used in the manuscript.
- `paper/submission/claim-evidence-matrix.md`: claim identifier, exact wording boundary, evidence identity, version, allowed inference, and excluded inference.
- `paper/submission/provider-interface-audit.md`: official public-interface comparison for provider and adjacent control-plane systems.
- `paper/submission/citation-audit.md`: citation key, primary or official source URL, verification date, and the manuscript claim the source supports.
- `paper/submission/references.bib`: verified bibliography entries only.
- `paper/submission/figures/generate_figures.py`: deterministic renderer for the three paper figures.
- `paper/submission/figures/evidence_behavior.json`: exact observed counts used by the evidence figure.
- `paper/submission/figures/control-gap.svg` and `.pdf`: authority multiplication compared with one conserved envelope.
- `paper/submission/figures/trusted-effect-path.svg` and `.pdf`: proposal-to-effect path with trust and denial boundaries.
- `paper/submission/figures/evidence-behavior.svg` and `.pdf`: off, shadow, enforce, and typed-denial observations.
- `paper/submission/check_submission.py`: source, evidence, citation, PDF, page-budget, style, and anonymity checks.
- `paper/submission/test_check_submission.py`: standard-library unit tests for every fail-closed checker rule.
- `paper/submission/latexmkrc`: isolated output directories for both variants.
- `paper/submission/Makefile`: reproducible `research-check`, `figures`, `arxiv`, `nsdi`, `check`, `render`, and `clean` targets.
- `paper/submission/verification-report.md`: exact commands, digests, page counts, font results, anonymity results, and visual-inspection record.

### Task 1: Establish the official venue and build baseline

**Files:**
- Create: `paper/submission/usenix-2020-09.sty`
- Create: `paper/submission/TEMPLATE_PROVENANCE.md`
- Create: `paper/submission/Makefile`
- Modify: `paper/submission/latexmkrc`

**Interfaces:**
- Consumes: the NSDI 2027 CFP, USENIX author template page, and the pinned TeX Live and Poppler images already used by this repository.
- Produces: `make arxiv` and `make nsdi`, each writing a PDF and full LaTeX log below `paper/submission/build/<variant>/`.

- [ ] **Step 1: Retrieve the official sources and record immutable provenance**

Open the official NSDI 2027 CFP and USENIX paper-template pages. Download the official LaTeX template archive to a temporary directory, calculate its SHA-256 digest, and copy only the unmodified USENIX style file into `paper/submission/`. Record the URLs, retrieval date `2026-08-24`, archive digest, and style digest in `TEMPLATE_PROVENANCE.md`.

- [ ] **Step 2: Write the two clean-build targets**

Define these exact Make interfaces:

```make
arxiv:
	rm -rf build/arxiv
	mkdir -p build/arxiv
	latexmk -r latexmkrc -outdir=build/arxiv paper-arxiv.tex

nsdi:
	rm -rf build/nsdi
	mkdir -p build/nsdi
	latexmk -r latexmkrc -outdir=build/nsdi paper-nsdi27.tex
```

The Docker wrappers must mount the repository read-only except for `paper/submission/build/`, use the repository's pinned TeX image, and never use host secrets or network access during compilation.

- [ ] **Step 3: Run a minimal style smoke build**

Build a temporary two-paragraph anonymous document with the copied style.

Run: `make nsdi`

Expected: a numbered US-letter, two-column PDF with no missing style, font, citation, or reference error.

- [ ] **Step 4: Check geometry and fonts from the built PDF**

Run the pinned Poppler image against `build/nsdi/paper-nsdi27.pdf` using `pdfinfo` and `pdffonts`.

Expected: `Page size: 612 x 792 pts (letter)`, embedded fonts only, and no Type 3 font.

- [ ] **Step 5: Preserve the baseline locally**

Record the template and container digests in `verification-report.md`. Do not add the ignored submission tree to Git.

### Task 2: Build shared named and anonymous source architecture

**Files:**
- Create: `paper/submission/manuscript.tex`
- Create: `paper/submission/paper-arxiv.tex`
- Create: `paper/submission/paper-nsdi27.tex`
- Modify: `paper/submission/main.tex`
- Modify: `paper/submission/paper-anon.tex`
- Test: `paper/submission/test_check_submission.py`

**Interfaces:**
- Consumes: the official style from Task 1.
- Produces: `\SystemName`, `\HostName`, `\PaperTitle`, `\PaperAuthor`, `\PaperTrack`, and `\PaperAnonymous` wrapper macros consumed by `manuscript.tex`.

- [ ] **Step 1: Write failing wrapper-isolation tests**

Add unit tests that load both wrappers as text and assert all of the following:

```python
self.assertIn(r"\newcommand{\SystemName}{LETS}", named)
self.assertIn(r"\newcommand{\HostName}{AstralDeep}", named)
self.assertIn("Samuel E. Armstrong, MS", named)
self.assertIn(r"\newcommand{\SystemName}{Lattice}", anonymous)
self.assertIn(r"\newcommand{\HostName}{Helios}", anonymous)
self.assertNotIn("Samuel", anonymous)
self.assertNotEqual(extract_title(named), extract_title(anonymous))
```

- [ ] **Step 2: Run the wrapper tests and confirm failure**

Run: `python -m unittest paper/submission/test_check_submission.py -v`

Expected: failures because the wrapper macros and shared manuscript do not exist.

- [ ] **Step 3: Implement the wrapper contract**

Make both wrappers define every macro before `\input{manuscript.tex}`. Keep all author identity in `paper-arxiv.tex`. Put `Traditional Research Track` on the anonymous title page and keep review page numbers enabled. Make `main.tex` contain only `\input{paper-arxiv.tex}` and make `paper-anon.tex` contain only `\input{paper-nsdi27.tex}`.

- [ ] **Step 4: Add the shared manuscript skeleton**

Create the exact top-level order:

```tex
\begin{abstract}
Recursive autonomous subjects can multiply aggregate effect authority unless a trusted runtime conserves that authority across the lineage.
\end{abstract}
\section{Introduction}
\label{IntroStartPage}
The systems problem is to preserve a finite effect envelope while subjects delegate, fail, retry, and cross provider boundaries.
\label{IntroEndPage}
\section{The Missing Control Boundary}
Public agent interfaces expose useful controls, but the audited interfaces do not specify lineage-wide conservation joined to executor-consumed receipts.
\section{System and Threat Model}
Stable wardens own durable rights while ephemeral lineage subjects hold attenuated leases.
\section{Warden Design}
Balanced transitions and durable receipt claims connect conserved authority to protected effects.
\section{Implementation and Host Integration}
The implementation places this boundary inside the host's normal authenticated dispatcher.
\section{Evaluation}
The evaluation separates model exploration, runtime qualification, and the retained host integration study.
\section{Security Boundaries and Limitations}
The guarantee depends on trusted wardens, executors, keys, storage, clocks, and complete effect mediation.
\section{Related Work}
The construction composes escrow accounting with delegated authorization and runtime mediation.
\section{Conclusion}
Stable wardens preserve a finite effect envelope across recursive subjects at the cost of stranded rights during partition.
\label{LastBodyPage}
\bibliographystyle{plainnat}
\bibliography{references}
```

The skeleton uses complete section-purpose sentences so every intermediate PDF builds with substantive text in every section.

- [ ] **Step 5: Run tests and both clean builds**

Run: `python -m unittest paper/submission/test_check_submission.py -v && make arxiv && make nsdi`

Expected: wrapper tests pass and both PDFs compile from the same `manuscript.tex`.

### Task 3: Establish the claim and evidence ledger

**Files:**
- Create: `paper/submission/claim-evidence-matrix.md`
- Modify: `paper/submission/evidence.tex`
- Test: `paper/submission/test_check_submission.py`

**Interfaces:**
- Consumes: `results/astraldeep-case-study/*.json`, retained formal outputs, archived v1.0.10 paper evidence, current v1.0.11 source identity, and exact benchmark or soak outputs that remain locally available.
- Produces: LaTeX evidence macros and claim IDs `C1` through `C6`, with each numeric claim bound to an evidence path, version, and allowed inference.

- [ ] **Step 1: Inventory every retained evidence object**

For each source, record path, SHA-256 digest, runtime version, host topology, trial count, and what it can prove. Treat the 57-scenario aggregate as integration and refusal evidence only. Treat archived formal, transfer, soak, and microbenchmark output as historical unless its exact generating version and configuration are retained.

- [ ] **Step 2: Write failing evidence-consistency tests**

Add tests that compare the JSON totals with exact macro names:

```python
expected = {
    "ScenarioCount": 57,
    "ArtifactCount": 183,
    "MeasurementCount": 151,
    "SampleCount": 163,
    "SingleSampleCount": 147,
}
self.assertEqual(read_evidence_macros(), expected)
self.assertFalse(summary["statistical_limits"]["publication_inference_supported"])
```

Add one fixture test that changes a macro to `58` and proves the checker rejects it.

- [ ] **Step 3: Write the six-row claim matrix**

Use one row per approved claim family. Each row includes claim text, supporting evidence, exact version, confidence, admissible wording, excluded wording, and manuscript section. Explicitly exclude population latency, clinical benefit, multi-host availability, production reliability, and provider intent unless new retained evidence exists.

- [ ] **Step 4: Verify historical results before reuse**

Match the archived bounded exploration, TLA+ exploration, three-warden acceptance, one-hour soak, mutation, and microbenchmark results to retained outputs and exact source commits. Include a result only if both identity and output exist. Otherwise place it in the excluded-evidence portion of the matrix and omit its number from the manuscript.

- [ ] **Step 5: Regenerate and test `evidence.tex`**

Run: `python -m unittest paper/submission/test_check_submission.py -v`

Expected: all macro values equal retained JSON and every manuscript number has one claim-matrix row.

### Task 3A: Regenerate current v1.0.11 evaluation evidence

**Files:**
- Create: `paper/submission/evaluation/v1.0.11/release/`
- Create: `paper/submission/evaluation/v1.0.11/local/`
- Create: `paper/submission/evaluation/summarize_v1_0_11.py`
- Create: `paper/submission/evaluation/v1.0.11/README.md`
- Modify: `paper/submission/claim-evidence-matrix.md`
- Modify: `paper/submission/evidence.tex`
- Test: `paper/submission/test_check_submission.py`

**Interfaces:**
- Consumes: the exact `v1.0.11` tag at `6245189920c686353c4ced7a208d56ec266f745c`, the immutable v1.0.11 GitHub release assets, `ghcr.io/astraldeep/lets@sha256:73f6b442df0a849f1d8cf6e13e29ff8b23bf515aae2d34cfc56bac7ccc60774c`, the current formal and benchmark harnesses, Docker Desktop, and no production credentials.
- Produces: authenticated release evidence, fresh exact-tag local evidence, a machine-readable aggregate, and current-version macros whose scope remains explicit.

- [ ] **Step 1: Authenticate the immutable release evidence**

Download the complete v1.0.11 release asset set. Verify `RELEASE_SHA256SUMS` with Cosign v3.1.3 against the release workflow identity and GitHub Actions issuer, then verify every payload digest. Retain the authenticated production-profile acceptance, one-hour soak, image manifest, image digest, checksum manifest, Sigstore bundle, release metadata, and verification transcript. Reject a partial, extra, unsigned, or mismatched asset set.

- [ ] **Step 2: Create an exact-release execution boundary**

Create a temporary detached worktree at the signed `v1.0.11` tag. Record the tag, commit, tree, source archive digest, tool versions, host facts, and a clean pre-run status. Inventory Docker containers, networks, images, and volumes before mutation. Assert that `astraldeep_pgdata` exists and is never a cleanup target. Do not inspect or copy its credential contents.

- [ ] **Step 3: Rerun code and formal checks**

From the exact-tag worktree run the frozen full test suite. Rerun the bounded model exploration, its duplicate-credit mutation, and TLC with the pinned v1.8.0 JAR. If the host lacks Java, use a digest-pinned Java container through a recorded wrapper rather than changing the host. Retain raw logs and outputs, including the expected nonzero mutation result and its counterexample.

- [ ] **Step 4: Collect repeated current-version microbenchmarks**

Run ten independent benchmark trials with 1,000 measured operations, 100 warmups, and four workers. Also run the existing storage-scaling and invariant-scaling profiles. Preserve every raw JSON/CSV file. Summarize per-trial medians and p95 values with median, interquartile range, minimum, and maximum across trials. Treat the results as descriptive evidence from one physical host, not a population estimate or a cross-system comparison.

- [ ] **Step 5: Rerun both three-warden acceptance profiles**

Run `deploy/run_acceptance.py` from the clean exact-tag source. Then run `deploy/production/run_acceptance.py` against the exact published OCI index digest. Retain both sanitized outputs and logs. Record that Docker Desktop supplies one VM-backed host and does not test independent machines or WAN behavior.

- [ ] **Step 6: Rerun the one-hour exact-image soak**

Run `deploy/production/run_soak.py` for 3,600 seconds with its release-default fault cadence and the exact published image digest. Preserve success or failure evidence exactly. Do not replace a failed local reproduction with the published release result or weaken the harness. The published release soak remains a separate authenticated execution.

- [ ] **Step 7: Normalize, admit, test, and clean**

Generate a deterministic aggregate and SHA-256 manifest across all release and local objects. Add only validated current-v1.0.11 observations to the claim matrix and `evidence.tex`, with separate rows for release-run and local-run topology. Extend the checker so every new macro is source-derived and mapped to one approved claim family. Remove the temporary worktree and all LETS/Astral containers, networks, test volumes, and task-created LETS/Astral images. Verify that no such resources remain and that `astraldeep_pgdata` still exists.

Expected: the paper uses current v1.0.11 numbers, every admitted number resolves to authenticated or locally retained raw evidence, all rerun limitations are explicit, and the Docker cleanup leaves only the protected AstralDeep credential volume among Astral/LETS resources.

### Task 4: Audit provider interfaces and primary related work

**Files:**
- Create: `paper/submission/provider-interface-audit.md`
- Create: `paper/submission/citation-audit.md`
- Modify: `paper/submission/references.bib`

**Interfaces:**
- Consumes: official public documentation for OpenAI, Anthropic, Google, Microsoft, Amazon Web Services, Wardline, Intended, A2A, and MCP, plus original papers for escrow, bounded counters, quantity transfer, quota delegation, capabilities, Macaroons, WAVE, reference monitors, and security automata.
- Produces: verified BibTeX keys and carefully scoped comparison statements for the Introduction, Missing Control Boundary, and Related Work sections.

- [ ] **Step 1: Audit official provider documentation**

For each provider, record the documented control unit, delegation model, enforcement point, accounting object, replay behavior, descendant-lineage behavior, executor-consumed proof, URL, page title, and access date. Use `not documented in the audited public interface` where a property is absent. Do not infer internal implementation or motive.

- [ ] **Step 2: Audit adjacent public control-plane systems**

Read Wardline and Intended from their official project documentation. Record only their documented enforcement and accounting semantics. Place them in the provider table only when the comparison column is supported by direct text or an official protocol example.

- [ ] **Step 3: Validate every academic citation at the primary source**

For each research claim, open the publisher paper page, proceedings page, RFC, or original preprint. Record title, authors, year, venue, DOI or canonical URL, and the precise proposition it supports. Remove any bibliography entry whose identity or relevance cannot be verified.

- [ ] **Step 4: Validate all BibTeX keys and URLs**

Run a standard-library citation scan that extracts `\cite{}` and `\citep{}` keys from `manuscript.tex`, then compares them with `references.bib`.

Expected: no undefined key, no uncited provider-comparison source, no repository self-link in the anonymous build, and no non-primary technical source when a primary one exists.

- [ ] **Step 5: Perform the title collision check**

Search the exact named and anonymous titles. Record the queries and result date in `citation-audit.md`. Retain the designed titles when no exact or confusingly close systems-paper collision exists.

### Task 5: Create the three publication figures

**Files:**
- Create: `paper/submission/figures/generate_figures.py`
- Create: `paper/submission/figures/evidence_behavior.json`
- Create: `paper/submission/figures/control-gap.svg`
- Create: `paper/submission/figures/control-gap.pdf`
- Create: `paper/submission/figures/trusted-effect-path.svg`
- Create: `paper/submission/figures/trusted-effect-path.pdf`
- Create: `paper/submission/figures/evidence-behavior.svg`
- Create: `paper/submission/figures/evidence-behavior.pdf`
- Test: `paper/submission/test_check_submission.py`

**Interfaces:**
- Consumes: approved claim families, wrapper-neutral labels, and exact evidence counts from Tasks 3 and 3A.
- Produces: deterministic vector files with a stable `render_all(output_dir: Path, evidence: dict[str, object]) -> list[Path]` interface.

- [ ] **Step 1: Write failing deterministic-render tests**

Render every figure twice into separate temporary directories and compare SHA-256 digests. Parse the SVGs and assert each has a `viewBox`, descriptive `<title>`, descriptive `<desc>`, and no raster `<image>` node.

- [ ] **Step 2: Draw the control-gap figure**

Use two horizontal panels. The upper panel shows one parent creating three descendants, each crossing a distinct provider boundary with an independent allowance. Label the resulting aggregate `3 x b` without implying provider intent. The lower panel shows the same descendants obtaining attenuated shares from one warden envelope `B`, then presenting receipts to effect executors. The caption states that the figure illustrates the control boundary and is not a measurement.

- [ ] **Step 3: Draw the trusted-effect-path figure**

Show proposal, authenticated host policy, warden debit, signed receipt, executor verification, durable claim, and effect in sequence. Mark model output and external provider transport outside the trusted core. Mark the host policy, warden state, executor keys, and claim store as trusted. Label denial points before debit, before claim, and before effect.

- [ ] **Step 4: Draw the evidence-behavior figure**

Use grouped grayscale bars for LETS calls, receipts issued, receipts claimed, and physical effects in off, shadow, and enforce modes. Add a compact four-row denial panel for `warden_unavailable`, `receipt_replayed`, `budget_exhausted`, and `binding_unavailable`, each observed once in enforce mode. The caption states that these are exact scenario counts, not samples from a performance distribution.

- [ ] **Step 5: Render and inspect at final size**

Run: `python figures/generate_figures.py --evidence figures/evidence_behavior.json --output figures`

Expected: three SVG and three PDF files, identical digests across repeat runs, legible at one-column or two-column placement, and distinguishable after grayscale conversion.

### Task 6: Write the prescreening core

**Files:**
- Modify: `paper/submission/manuscript.tex`
- Modify: `paper/submission/references.bib`

**Interfaces:**
- Consumes: claim matrix, provider audit, citation audit, control-gap figure, and evidence macros.
- Produces: Abstract, Introduction, and Missing Control Boundary sections that remain correct in both named and anonymous variants.

- [ ] **Step 1: Write the complete Abstract**

Use one paragraph of roughly 180 to 220 words. State the recursive authority-multiplication problem, stable warden construction, executor-claimed receipt boundary, exact retained integration evidence, and the main evidence limit. Include no undefined acronym and no claim about production scale.

- [ ] **Step 2: Write the Introduction problem and systems insight**

Start from a concrete recursive agent that delegates across first-party and commercial provider boundaries. Explain why per-agent permissions, rate limits, model guardrails, and central counters do not jointly provide partition-tolerant lineage-wide conservation. Introduce stable escrow wardens and effect receipts as the missing systems boundary.

- [ ] **Step 3: Write the Introduction evidence and contributions**

Report only verified headline evidence. State three compact contributions in prose rather than a long list: the abstraction and invariants, the executor-bound distributed design, and the implementation plus bounded evaluation. State clearly that partitions may strand rights and that the current integration study is not a population performance result.

- [ ] **Step 4: Write the Missing Control Boundary section**

Use the provider audit to compare public interfaces by control object and enforcement point. Say that the audited public interfaces do not document the full composition of transferable lineage-conserved effect rights and executor-consumed receipts. Do not say providers ignored, overlooked, or failed to consider the idea.

- [ ] **Step 5: Run prescreen checks**

Build the anonymous PDF and inspect the abstract plus Introduction as a standalone packet.

Expected: the Introduction ends within three numbered pages, states novelty and evidence without relying on later sections, and contains the control-gap figure at readable size.

### Task 7: Write the system model, design, and implementation

**Files:**
- Modify: `paper/submission/manuscript.tex`
- Modify: `paper/submission/references.bib`

**Interfaces:**
- Consumes: verified formal model, current runtime source, claim matrix, and trusted-effect-path figure.
- Produces: precise definitions and a complete construction whose safety claim is conditional on stated trust and mediation assumptions.

- [ ] **Step 1: Write the System and Threat Model**

Define the bounded stable warden set, churn-heavy lineage subjects, resource vector, capabilities, immutable transition machine, epoch, lease, protected effect, receipt, and executor. State crash, retry, reordering, and partition assumptions. State that wardens are non-Byzantine and that compromised keys, clocks, persistent state, or incomplete effect mediation are outside the guarantee.

- [ ] **Step 2: Write the local and global conservation argument**

Present the local accounting equation and explain every term in plain language. Explain how issue, spawn, transition, close, prepare, accept, and finalize move rights without creating them. Treat prepared but uncredited transfers explicitly in the global equation.

- [ ] **Step 3: Write attenuation, lifecycle, and replay behavior**

Explain child budget and capability attenuation, nested expiry, sequence monotonicity, branch revocation, idempotent operation identities, and the consequence of lost responses. Connect each mechanism to one invariant rather than cataloging fields.

- [ ] **Step 4: Write the receipt-bound effect path**

Use the trusted-path figure to explain debit, signed receipt, executor verification, durable claim, replay rejection, and physical effect. Make clear that neither LLM output nor provider transport is trusted to conserve authority.

- [ ] **Step 5: Write cross-warden transfer and availability behavior**

Explain prepare, accept, finalize, and checkpoint. State that retries and reordering can strand capacity but cannot duplicate accepted rights under the stated assumptions. Add a compact transfer timeline only if the prose plus equation cannot fit the Design budget.

- [ ] **Step 6: Write Implementation and Host Integration**

Describe the implemented Python 3.11 runtime and the normal authenticated AstralDeep or Helios dispatcher. Explain off, shadow, and enforce modes, the existing Keycloak and RFC 8693 policy boundary, and the governed executor. Keep runtime ownership separate from host orchestration and avoid private deployment details.

### Task 8: Write the evaluation and limitations

**Files:**
- Modify: `paper/submission/manuscript.tex`
- Modify: `paper/submission/claim-evidence-matrix.md`
- Modify: `paper/submission/figures/evidence_behavior.json`

**Interfaces:**
- Consumes: only evidence admitted by Tasks 3 and 3A, exact study manifests, and the evidence-behavior figure.
- Produces: reproducible research questions, methods, results, and explicit limits with no invented baseline or uncertainty.

- [ ] **Step 1: Frame four evaluation questions**

Ask whether the implementation preserves the stated invariants under explored interleavings, whether receipt mediation refuses representative unsafe effects, what exact behavior appears across off, shadow, and enforce integration modes, and what overhead or availability evidence the retained measurements can validly support.

- [ ] **Step 2: Write formal and protocol evaluation**

Include bounded exploration and TLA+ results only when exact configs and outputs were admitted to the claim matrix. State state counts, transition counts, depth bounds, and modeled assumptions exactly. Separate model exploration from implementation testing.

- [ ] **Step 3: Write runtime qualification evidence**

Include three-warden acceptance, soak, mutation, and microbenchmark observations only when their version identities are retained. Report trial counts and descriptive statistics exactly. Prefer authenticated or freshly generated v1.0.11 evidence. Do not transfer archived v1.0.10 values to v1.0.11.

- [ ] **Step 4: Write the 57-scenario host study**

Describe nineteen scenarios repeated across off, shadow, and enforce modes. Report `57` scenarios, `183` retained artifacts, `151` measurements, `163` samples, and `147` one-sample measurements. Report the exact mode counts and four typed enforce denials. State that no governed enforce effect occurred without a claimed receipt.

- [ ] **Step 5: Write Security Boundaries and Limitations**

State trusted components, key and storage assumptions, incomplete mediation risk, warden-set stability within an epoch, stranded authority during partition, lack of Byzantine tolerance, single-host integration limits, absence of clinical-outcome evidence, and absence of population performance inference. State the later owner-authorized deployment only as chronology unless a separate retained deployment evidence set is admitted.

- [ ] **Step 6: Build and audit every number**

Run the numeric-claim checker against the rendered text and claim matrix.

Expected: every number resolves to one admitted evidence row, the evaluation figure matches JSON, and no excluded inference appears in prose or captions.

### Task 9: Write Related Work and Conclusion, then tighten the full paper

**Files:**
- Modify: `paper/submission/manuscript.tex`
- Modify: `paper/submission/references.bib`
- Modify: `paper/submission/citation-audit.md`

**Interfaces:**
- Consumes: verified citations and all completed manuscript sections.
- Produces: a complete paper within the section page budgets and with a precise novelty boundary.

- [ ] **Step 1: Write Related Work by technical boundary**

Use compact paragraphs for escrow and bounded counters, delegated authorization and capabilities, runtime enforcement and reference monitors, and current agent control planes. For each family, state what it contributes and the specific composition supplied here. Do not use a long paper-by-paper catalog.

- [ ] **Step 2: Write the Conclusion**

Use one short paragraph. Restate that stable wardens conserve a finite effect-authority envelope across recursive subjects and that executor claims connect accounting to effects. End with the measured integration result and the availability tradeoff, not a broad claim about safe AI.

- [ ] **Step 3: Perform a full style edit**

Remove em dashes, semicolons, inflated transitions, repeated claims, vague pronouns, and dense strings of abstract nouns. Keep paragraphs focused on one claim. Review every colon and retain only those needed in a title, caption, definition, or short lead-in.

- [ ] **Step 4: Fit the page budget without shrinking text**

Build both variants and use label-derived page boundaries. Tighten redundant prose and oversized figure whitespace until the body is at most 12 pages and the Introduction is at most three pages. Do not change the official font size, leading, margins, or column gap.

- [ ] **Step 5: Re-run citation and evidence audits**

Expected: every citation supports the adjacent statement, every cited key exists, all provider statements retain the public-interface qualifier, and all quantitative claims remain admitted.

### Task 10: Implement fail-closed source and PDF verification

**Files:**
- Modify: `paper/submission/check_submission.py`
- Modify: `paper/submission/test_check_submission.py`
- Modify: `paper/submission/Makefile`

**Interfaces:**
- Consumes: both source variants, both PDFs, LaTeX auxiliary files, logs, evidence JSON, audit files, and Poppler output.
- Produces: `check_source(variant: str)`, `check_evidence()`, `check_citations()`, `check_pdf(variant: str, pdf: Path)`, and a zero-exit `main()` only when every gate passes.

- [ ] **Step 1: Write failing source and anonymity tests**

Use temporary copies to prove rejection of each condition: em dash, semicolon, missing track, same title, same system name, real author in anonymous source, LETS or AstralDeep in anonymous rendered text, public digest, repository URL, and identifying PDF author or title metadata.

- [ ] **Step 2: Write failing venue and PDF tests**

Use recorded `pdfinfo`, `pdffonts`, auxiliary, and log fixtures to prove rejection of body page 13, four-page Introduction, non-letter page size, Type 3 fonts, unembedded fonts, missing page numbers, undefined references, undefined citations, and overfull boxes that touch content.

- [ ] **Step 3: Implement source checks**

Scan shared prose for forbidden punctuation. Resolve cited keys against BibTeX. Compare wrapper titles and system names. Require the exact named author block only in the named wrapper. Require the track label only in the NSDI title block.

- [ ] **Step 4: Implement evidence and PDF checks**

Compare LaTeX macros with retained JSON. Parse `LastBodyPage`, `IntroStartPage`, and `IntroEndPage` from auxiliary files. Parse page size, metadata, fonts, and page count from Poppler output. Extract anonymous text and reject real names, affiliations, system names, repository links, and exact public study digests.

- [ ] **Step 5: Run the complete unit suite**

Run: `python -m unittest paper/submission/test_check_submission.py -v`

Expected: every negative fixture fails for its declared reason and both real variants pass source-level checks.

- [ ] **Step 6: Wire the final gate**

Define `make check` to run clean figure generation, both clean LaTeX builds, all unit tests, the real PDF checker, and log scans in that order. Stop on the first failed command and leave the failed build directory for diagnosis.

### Task 11: Render, inspect, and finalize both PDFs

**Files:**
- Create: `paper/submission/verification-report.md`
- Modify: any manuscript, figure, bibliography, or checker file whose defect is found during inspection.

**Interfaces:**
- Consumes: the complete named and anonymous builds.
- Produces: final local PDFs and an evidence-backed verification record.

- [ ] **Step 1: Run the clean end-to-end gate**

Run: `make clean && make check`

Expected: zero exit, no LaTeX correctness warning, body page count at most 12, Introduction page span at most three, and all fonts embedded.

- [ ] **Step 2: Render every PDF page to PNG**

Use the pinned Poppler image at 150 DPI for both variants. Record the command and output digest in `verification-report.md`.

- [ ] **Step 3: Inspect every page visually**

Check column balance, title blocks, track label, page numbers, equations, table width, figure labels, grayscale distinction, citation placement, widows, orphan headings, clipped text, and blank pages. Inspect the anonymous title, body, acknowledgments area, references, and metadata for identity leaks.

- [ ] **Step 4: Correct defects and repeat the full gate**

Make the smallest source or figure change that fixes each observed defect. Repeat `make clean && make check` and page rendering after any change that can alter layout.

- [ ] **Step 5: Record final identities and handoff**

Record SHA-256 digests for source inputs, figures, `paper-arxiv.pdf`, and `paper-nsdi27.pdf`, plus exact page counts and check results. State outside the manuscript that Samuel must materially rewrite and approve every substantive section, caption, table, claim, and reference before submission. Do not upload or push the ignored submission tree.

### Task 12: Record the private project checkpoint

**Files:**
- Modify: `../kos-wiki/wiki/project-lets.md`
- Modify: `../kos-wiki/index.md`
- Modify: `../kos-wiki/log.md`

**Interfaces:**
- Consumes: final local verification report and the two PDF identities.
- Produces: a durable private record of the local branch, manuscript state, exact evidence boundary, and actions that still require Samuel's authorization.

- [ ] **Step 1: Refresh the knowledge-vault repository anchor**

Read the vault instructions, fetch its remote, and verify its working tree before editing curated pages.

- [ ] **Step 2: Update the curated LETS page and index**

Record the local LETS branch, design and plan commits, chosen named and anonymous titles, build identities, evidence limits, and the fact that neither manuscript nor anonymous aliases were pushed.

- [ ] **Step 3: Append the checkpoint log entry**

Add a UTC timestamped entry that records completed checks, remaining human rewrite and approval, and that arXiv and NSDI submissions remain unauthorized external actions.

- [ ] **Step 4: Commit and push the private vault checkpoint**

Run the vault's required validation, commit only curated vault files, and push its main branch when the remote is available. Keep this commit separate from the LETS repository.
