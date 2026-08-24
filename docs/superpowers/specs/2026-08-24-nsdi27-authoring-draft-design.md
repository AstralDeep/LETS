# NSDI 2027 Authoring Draft Design

Date: 2026-08-24

## Purpose

Produce a comprehensive, evidence-backed paper draft that is written and reasoned as a competitive NSDI 2027 Traditional Research Track submission. Samuel E. Armstrong will materially rewrite it in his own words before submission.

The work has two publication variants. The named arXiv version identifies LETS, AstralDeep, and the sole author. The anonymous NSDI version uses a different title and different system names as required by the venue. Both variants derive from one content source so their technical claims cannot drift.

## Non-negotiable constraints

- Samuel E. Armstrong is the only author.
- The named author block is:

  ```text
  Samuel E. Armstrong, MS
  Kentucky Open Science
  kyopenscience.com
  ```

- Samuel must materially rewrite every substantive section before making the NSDI attestation that the paper is primarily human-written. This responsibility stays in the handoff and does not alter the manuscript's language, structure, metadata, argument, or presentation.
- No production, performance, scale, or safety claim may exceed retained evidence.
- The owner-reported production deployment is provenance, not experimental evidence. It may be described only as a later deployment event unless independently retained deployment measurements support more.
- The manuscript keeps Samuel's direct style. It avoids em dashes, semicolons, long lists, inflated transitions, and dense strings of abstract nouns. Colons are permitted only where they improve a title, caption, definition, or short lead-in.
- The NSDI body is at most 12 pages. References and supplementary appendices follow the body.
- The Introduction is at most three pages and is written to stand alone for prescreening.
- Figures are legible at printed column width and remain understandable in grayscale.

## Positioning and titles

The paper is a distributed-systems paper about conserving effect authority across recursively changing autonomous subjects. It is not a general survey of AI safety. Stable wardens, escrowed vector rights, durable transfers, executor receipt claims, failure behavior, and the availability cost of stranded authority form the systems contribution.

The recommended named title is:

> Conservation of Agentic Authority: A Warden for Recursive Autonomous Systems

This is more precise than "Conservation of Agentic Budgets." Authority covers finite quantitative rights, qualitative capabilities, lifecycle state, and execution mediation. The subtitle makes the warden contribution explicit.

The anonymous NSDI title is:

> Escrowed Effect Rights for Partitioned Autonomous Systems

The anonymous source maps LETS to `Lattice` and AstralDeep to `Helios`. The mapping exists only in the local anonymous wrapper. The named variant never uses those aliases.

## Approaches considered

### Recommended: NSDI-first hybrid

Use the current five-page paper as the evidence spine. Recover the stronger system model, cross-warden protocol, formal exploration, implementation detail, and diagrams from the archived long paper. Revalidate every recovered result against its exact version before including it. This route gives the paper enough systems depth without inheriting the archived paper's length or broad operational appendix.

### Alternative: short case study only

Expand only the current five-page AstralDeep integration paper. This is easier to verify, but the current evidence is too narrow for a strong NSDI Traditional Research submission. It also leaves the distributed protocol underexplained.

### Alternative: full historical system paper

Compress the archived long paper into USENIX format and add the AstralDeep study. This preserves more technical detail, but it risks a survey-like paper with too many claims and version identities. It would also make the Introduction less focused for NSDI prescreening.

The implementation uses the NSDI-first hybrid.

## Source architecture

The ignored local submission tree remains private during double-blind preparation. It contains:

- `manuscript.tex` for shared substantive content.
- `paper-arxiv.tex` for the named title, real system names, author block, and named metadata.
- `paper-nsdi27.tex` for the anonymous title, system aliases, Traditional Research Track label, anonymous metadata, and numbered review pages.
- `main.tex` as a compatibility wrapper for the named draft.
- `paper-anon.tex` as a compatibility wrapper for the NSDI draft.
- `claim-evidence-matrix.md` for every consequential claim, its evidence identity, scope, confidence, and exclusion.
- `provider-interface-audit.md` for official documentation from commercial and third-party agent providers.
- `figures/` for deterministic vector figures and their source files.
- `references.bib` for verified primary literature and official provider documentation.
- `check_submission.py` for fail-closed venue, evidence, prose-style, and anonymity checks.

The official USENIX LaTeX style is vendored from the official template page with its source URL and retrieval date recorded. No third-party LaTeX class is introduced.

## Manuscript architecture and page budget

| Section | Target body pages | Purpose |
| --- | ---: | --- |
| Abstract | 0.25 | State the multiplication problem, warden construction, and bounded evidence |
| Introduction | 1.75 | Establish NSDI scope, novelty, headline results, contributions, and one main nonclaim |
| Missing control boundary | 0.9 | Show why provider permissions, rate limits, and model guardrails do not conserve descendant effect authority |
| System and threat model | 1.0 | Define wardens, leases, effects, partitions, trust, and failure assumptions |
| Design | 2.25 | Explain conservation, attenuation, transitions, receipts, transfers, lifecycle, and fail-closed behavior |
| Implementation and host integration | 1.15 | Describe the runtime and the normal AstralDeep dispatcher boundary |
| Evaluation | 3.15 | Present formal exploration, runtime qualification, failure tests, and the 57-scenario integration study |
| Security boundaries and limitations | 0.75 | State trusted components, incomplete mediation risks, and evidence limits |
| Related work | 0.55 | Draw a precise novelty boundary without turning the section into a catalog |
| Conclusion | 0.20 | Restate the systems result and its limits |

The target is 11.95 body pages or fewer. The paper remains complete without appendices.

## Core claims

The draft may support only these claim families:

1. Recursive creation can multiply aggregate effect authority when every descendant receives an independent full allowance.
2. A bounded set of stable wardens can conserve a finite multidimensional authority envelope while ephemeral subjects churn.
3. Executor-claimed receipts can connect an authorized debit to a protected effect without trusting model compliance.
4. Cross-warden transfer preserves conservation under the stated non-Byzantine trust and failure model, while partitions can strand capacity.
5. The AstralDeep integration places the warden boundary in the normal authenticated dispatcher and produces exact fail-closed denials in the retained scenarios.
6. Public commercial-provider interfaces expose useful permissions, approvals, guardrails, quotas, or usage accounting, but the audited interfaces do not document the full combination of lineage-conserved transferable effect rights and executor-consumed receipts.

The sixth claim is an interface audit. It is not a claim about private provider systems or provider intent.

## Evidence policy

The current 57-scenario evidence supports integration, typed refusal, lifecycle, and complete-receipt observations. It does not support population performance, clinical outcome, multi-host availability, or production-scale claims.

Historical formal exploration, three-warden acceptance, soak, mutation, and microbenchmark results may be recovered only when their exact source version, configuration, and retained output are verified. Version-bound results remain labeled as such. No result is silently promoted to the current v1.0.11 runtime.

The paper states the chronology directly. The integration study alone did not authorize rollout. A later owner-authorized deployment occurred. The paper does not infer production reliability or scale from that event.

Missing competitive, independent-host, or repeated performance experiments are described as evaluation gaps. The draft does not invent baselines, uncertainty, or measurements. If new evidence is later collected, it enters through the claim-evidence matrix before entering prose or figures.

## Research and citation design

The literature review uses primary papers for escrow transactions, bounded counters, exactly-once rights transfer, quota delegation, capabilities, Macaroons, WAVE, security automata, reference monitors, and closely related agent-governance systems.

Commercial and third-party agent-provider comparisons use official documentation. The initial audit covers OpenAI, Anthropic, Google, Microsoft, Amazon Web Services, and current agent control-plane projects that make materially adjacent claims. Each row records the documented unit of control, delegation model, enforcement point, accounting object, replay semantics, and whether lineage-wide conserved effect authority is specified.

The prose distinguishes absence from public documentation from absence in private implementation. It avoids motive claims and categorical statements such as "providers are not considering this."

## Figures

The paper uses three primary figures.

1. **The control gap.** A two-panel vector diagram contrasts recursive agents calling first-party and third-party providers with a warden-mediated path. The first panel shows how independent allowances multiply. The second shows one conserved envelope crossing provider boundaries through executor receipts.
2. **The trusted effect path.** A sequence and boundary diagram shows proposal, host policy, warden debit, signed receipt, executor verification, durable claim, and physical effect. Trust boundaries and denial points are explicit.
3. **Evidence and failure behavior.** A grayscale figure combines the retained off, shadow, and enforce counts with exact denial classes. It reports observations only and does not imply a statistical distribution.

A compact transfer timeline may replace prose if the cross-warden protocol cannot be explained within the Design page budget. Every figure has deterministic source, accessible labels, grayscale validation, and a caption that states what the figure does not prove.

## Human rewrite responsibility

The manuscript contains no visible warning, watermark, draft disclaimer, altered metadata, or rhetorical hedge tied to how it was produced. It is written as a complete conference paper whose objective is acceptance.

The authorship boundary exists outside the manuscript. Samuel must materially rewrite and approve every substantive section, caption, table, claim, and reference before submission. Automated checks cannot determine whether text is primarily human-written and must not claim to do so.

## Verification

The workflow must verify:

- Official USENIX geometry, fonts, two-column layout, review page numbers, and Traditional Research Track label.
- No more than 12 body pages and no more than three Introduction pages.
- Different named and anonymous titles and system names.
- Exact named author block only in the arXiv variant.
- No real names, affiliations, acknowledgments, repository links, real system names, public digests, identifying filenames, or identifying PDF metadata in the anonymous variant.
- Every cited key exists and every bibliography URL resolves to a primary or official source where available.
- Every numeric statement matches the claim-evidence matrix and retained evidence.
- No em dashes or semicolons in manuscript prose. Colon use remains sparse and reviewed.
- Every figure is legible at final size and in grayscale.
- All fonts are embedded and the PDF is searchable.
- Both variants build from a clean output directory without warnings that affect correctness.

The checker fails closed. A failed anonymity, evidence, formatting, or build check produces no final PDF.

## Completion boundary

This phase ends with complete named and anonymous paper-draft PDFs, source, figures, citation audit, evidence matrix, and verification results. It does not include arXiv upload, HotCRP registration, NSDI submission, artifact submission, production-server access, or TDSC submission. Those actions require separate explicit authorization and Samuel's completed rewrite and review.
