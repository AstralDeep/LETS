# Research Dossier: Lineage Escrow Transition Systems (LETS)

**Status:** research proposal and extended preprint package; not peer reviewed
**Primary venue fit:** AAMAS 2027, Engineering and Analysis of Multiagent Systems (EMAS)
**Secondary venue path:** USENIX Security / IEEE S&P only after adding a substantially stronger adversarial implementation, formal security model, and distributed evaluation
**Date of novelty audit:** 8 August 2026
**Companion artifacts:** `paper.tex`, `references.bib`, `literature_matrix.csv`, `citation_verification.csv`, `prototype/`, `formal/`, `results/`, and `figures/`

## Executive decision

The selected project is **LETS: Lineage Escrow Transition Systems**, a reasoner-independent computational model and enforcement architecture for autonomous populations that may recursively create descendants and continue operating during network partitions.

The key question is not whether software can replicate. The research question is:

> How can a distributed autonomous population remain locally useful during disconnection while a finite, population-wide envelope on protected effects is preserved across all descendants, and while revocation exposure and online safety metadata remain bounded?

The selected contribution is deliberately narrower than several initially attractive ideas. Existing work already provides agent lifecycles, hierarchical budgets, capability delegation, complete mediation, stateful policy enforcement, numeric escrow, bounded counters, leases, recursive finite-resource delegation, lineage records, and agent runtimes. LETS therefore does **not** claim to invent any of those components. It proposes a new abstract object and systems composition centered on four properties that were not found together in the audited literature:

1. a conserved, multi-dimensional transition envelope spanning a recursively changing agent lineage;
2. partition-safe local spawn and effect authorization without making each ephemeral agent a distributed-counter replica;
3. branch revocation with a quantified bound on disconnected post-revocation effects; and
4. HSM-mediated, reasoner-independent execution in which sensor evidence may enable a transition but cannot create authority.

This is a plausible AAMAS systems paper if the next two months produce a real multi-warden implementation, a physical or emulated sensor workload, competitive baselines, adversarial schedules, and a stronger formal validation. The present package contains a functioning reference kernel, eight unit tests, an exhaustive finite-state checker, a finite TLA+ specification, diagrams, and preliminary simulations. Those results establish feasibility; they are not yet sufficient for a top-tier acceptance.

---

# Part 1 — Literature review and novelty audit

## 1. Review protocol

### 1.1 Scope

The audit covered the following requested areas:

- autonomous agents and LLM-based agents;
- self-replicating and self-modifying software;
- multi-agent systems, agent protocols, and lifecycle management;
- recursive task decomposition and autonomous planning;
- capability-based security, delegation, and revocation;
- finite-state machines, hierarchical state machines, temporal logic, Petri nets, model checking, timed automata, and graph rewriting;
- distributed systems, escrow transactions, quotas, bounded CRDTs, and exactly-once quantity transfer;
- cyber-physical systems, sensor networks, swarm intelligence, and distributed robotics;
- self-healing, autonomic, and self-adaptive systems;
- AI safety architectures, runtime enforcement, and verified systems;
- biological replication and evolutionary computation.

The review included work from or associated with NeurIPS, ICML, ICLR, AAAI, AAMAS, USENIX Security, USENIX NSDI, IEEE S&P, NDSS, ACM, IEEE, Nature Machine Intelligence, Communications of the ACM, and arXiv. The bibliographic artifact contains 84 entries. Each entry is mapped to a research area, its established contribution, its relationship to LETS, the remaining gap, and a novelty-audit verdict in `literature_matrix.csv`.

### 1.2 Inclusion and verification rules

A source was included when it was one of the following:

- a canonical primary source for a required concept;
- a close architectural or formal predecessor;
- a recent agent-governance work that could invalidate the proposed novelty;
- a benchmark or implementation that could support the evaluation; or
- a source needed to delimit a non-claim.

Bibliographic metadata was checked against publisher proceedings, conference pages, DOI records, or arXiv records where available. `citation_verification.csv` records the verification basis. No citation should be treated as evidence for a claim broader than its row in `literature_matrix.csv`.

### 1.3 Novelty-disproof procedure

For each candidate contribution, the audit used an adversarial sequence:

1. state the strongest plausible novelty claim;
2. search for the same nouns and for equivalent mechanisms under older terminology;
3. decompose the claim into primitive mechanisms;
4. identify prior art for each primitive;
5. search for prior compositions of those mechanisms;
6. reject or narrow the candidate when a materially equivalent contribution appears; and
7. retain only the smallest claim that survives.

This procedure rejected three broad candidates before LETS was selected and continued to narrow LETS after selection.

## 2. State of the art by research area

### 2.1 Autonomous agents, planning, and recursive decomposition

Classical agent research defines autonomous agents in terms of situated action, reactivity, proactivity, and social behavior [wooldridge1995agents]. Contract Net established distributed task allocation through manager–contractor relationships [smith1980contractnet]. HTN planning formalized recursive decomposition and its complexity [erol1994htn], while SHOP2 showed a practical ordered HTN planner [nau2003shop2]. More recent LLM-agent methods such as ReAct, Tree of Thoughts, Reflexion, and Toolformer expand the proposal-generation and tool-use layer [yao2023react; yao2023tot; shinn2023reflexion; schick2023toolformer]. AgentBench and AgentDojo provide interactive and adversarial evaluation substrates [liu2024agentbench; debenedetti2024agentdojo].

**Established:** agents can recursively decompose tasks, delegate work, call tools, and adapt their internal reasoning process.

**Weakness relevant to this project:** planning and reasoning methods generally optimize which action to propose. They do not provide a non-bypassable, population-wide conservation law over effects produced by descendants. A planner may model a resource, but a model is not an enforcement boundary.

**Opportunity:** treat any planner, policy, search procedure, or LLM as an untrusted proposal generator and mediate the transition that causes an external effect.

### 2.2 Multi-agent systems, actors, protocols, and lifecycle management

The actor model supplies asynchronous local state, message passing, and dynamic process creation [hewitt1973actors; agha1986actors]. AAMAS work on HAPN uses hierarchical finite-state structures to define agent protocols [yadav2015hapn], and dynamic protocols address changing interaction rules in open agent systems [artikis2009dynamic]. JADE and the FIPA Agent Management Specification supply practical lifecycle and directory-service precedents [bellifemine2001jade; fipa2004management]. Cluster managers such as Borg and Kubernetes demonstrate declarative desired state and large-scale lifecycle orchestration [verma2015borg; burns2016kubernetes].

Recent agent infrastructure materially overlaps broad versions of the proposed project. Agent libOS provides long-running agent processes, identity, lineage, capabilities, checkpoints, and audit [zhang2026agentlibos]. Agent Contracts defines lifecycle states, multi-dimensional contracts, conservation constraints, and recursive budget delegation [ye2026agentcontracts].

**Established:** dynamic creation, parent–child relationships, lifecycle states, contracts, and resource accounting are not new.

**Weakness relevant to this project:** generic actor or lifecycle systems do not make finite rights conserved across a descendant population during network partitions. Agent Contracts is particularly close and invalidates any claim that hierarchical agent budgets or conservation laws are novel by themselves.

**Opportunity:** define the distributed semantics of a lineage-wide object under partition, migration, expiry, reclamation, and revocation rather than propose another agent runtime.

### 2.3 Distributed quotas, escrow, and numeric invariants

The Escrow Transactional Method partitions rights so that local transactions can preserve numeric constraints [oneil1986escrow]. Distributed quota systems have used vouchers, trees, decentralized protocols, and storage-specific designs [walfish2006quota; pollack2007quota; behl2012dqmp; lakew2014treequota]. Bounded counters and related CRDT work preserve numeric invariants without coordination on every operation [balegas2015bounded; almeida2019counters]. Exactly-once quantity transfer and dynamic identity techniques address rights movement and replica churn [shoker2015exactlyonce; enes2017identity].

Agudo, Fernandez-Gago, and Lopez directly address quota-preserving recursive delegation over finite resources [agudo2009quota]. This result invalidates a broad claim that recursive quantitative delegation is new.

**Established:** splitting finite rights, preserving a numeric invariant under concurrency, moving quantities idempotently, and recursively delegating quota are all prior art.

**Weakness relevant to this project:** the audited quota literature is generally organized around stable users, storage namespaces, sites, or replicas. It does not define autonomous descendants as short-lived subjects with HSM transitions, signed subleases, sensor evidence, branch epochs, and a reasoner-independent effect boundary. A naïve mapping in which every descendant is a bounded-counter replica creates identity and metadata growth tied to historical population size.

**Opportunity:** make a small set of stable wardens the escrow replicas while treating dynamic agents as leased subjects, and formally connect the quota object to executable transition semantics.

### 2.4 Capabilities, delegation, revocation, and complete mediation

Capabilities provide unforgeable references and authority [dennis1966capabilities]. Saltzer and Schroeder articulate complete mediation and least privilege [saltzer1975protection]. Macaroons supply attenuated credentials with contextual caveats [birgisson2014macaroons]. WAVE supplies decentralized transitive delegation [andersen2019wave]. OASIS and later work study distributed access control and role activation [hayton1998oasis]. The delegation-and-revocation literature identifies persistent weaknesses in revocation semantics [chuat2020delegation]. Proof-carrying code, security automata, and verified kernels show different ways to reduce trust in untrusted components [necula1997pcc; schneider2000enforceable; murray2013sel4].

Recent agent-specific work further narrows the gap. Faramesh proposes a non-bypassable execution control plane [fatmi2026faramesh]. AgentBound combines delegation, behavioral constitutions, site contracts, and receipts [kaul2026agentbound]. Fixed Ceiling constrains evolving agents under an authority ceiling and attenuating delegation [zhang2026fixedceiling]. Context Lineage Assurance and Agent Identity URI address provenance and identity [malkapuram2025lineage; rodriguez2026agenturi]. Provenact addresses serializable policy state and state/effect enforcement for concurrent agents [peng2026provenact].

**Established:** complete mediation, capability attenuation, transitive delegation, receipts, lineage identity, stateful policy, and fixed ceilings are not novel individually.

**Weakness relevant to this project:** qualitative capability inclusion does not itself conserve a quantitative population envelope. Fixed-ceiling authorization primarily constrains the authorized subject across evolution; LETS asks how a finite ceiling is partitioned across independently executing siblings and descendants during disconnection. Provenact protects stateful policy decisions but is not designed around offline recursive subleasing and bounded lease exposure.

**Opportunity:** combine qualitative attenuation with quantitative conservation and state-machine legality, while making revocation exposure an explicit, measurable systems parameter.

### 2.5 Formal models: state machines, temporal logic, Petri nets, and rewriting

Statecharts and STATEMATE define hierarchical and concurrent state-machine semantics [harel1987statecharts; harel1996statemate]. Petri nets model concurrency, synchronization, and resource flow [murata1989petrinets]. Temporal logic and TLA support safety/liveness specification [pnueli1977temporal; lamport1994tla], while model checking explores finite-state systems [clarke1986modelchecking]. Timed automata support timing constraints [alur1994timed]. Bigraphical reactive systems provide graph-rewriting semantics for changing topology [milner2001bigraphs]. Runtime shields and online verification enforce safe behavior around untrusted controllers [bloem2015shield; pek2020onlineverification].

**Established:** hierarchical transition semantics, formal invariants, temporal properties, topology rewriting, and runtime enforcement are mature fields.

**Weakness relevant to this project:** a state machine constrains order but does not inherently bound the aggregate effects of dynamically created machines. A Petri net can model token conservation, but a model alone does not define identity, cryptographic delegation, partition behavior, or a deployable enforcement protocol.

**Opportunity:** define a small abstract object whose conservation law can be represented in Petri-net or TLA terms, but whose operational interface directly mediates real effects.

### 2.6 Cyber-physical systems, sensors, and swarms

Cyber-physical systems couple computation and physical processes under timing and safety constraints [lee2008cps]. Sensor-network work emphasizes scalable coordination, energy-aware scheduling, and constrained runtimes [estrin1999sensor; akyildiz2002wsn; heinzelman2000leach; hill2000tinyos]. Swarm intelligence and swarm robotics study decentralized collective behavior [reynolds1987flocks; dorigo1996antsystem; kennedy1995pso; brambilla2013swarmrobotics; werfel2014termites].

**Established:** decentralized populations can coordinate from local observations and can adapt topology or role allocation.

**Weakness relevant to this project:** emergent coordination and energy optimization usually optimize behavior rather than impose a cryptographically enforced lineage-wide bound on protected effects. Sensor readings can be stale, forged, or ambiguous; they cannot safely be allowed to create authorization.

**Opportunity:** use sensor evidence only as a guard on a transition whose authority was already allocated. This makes the framework transferable to robots, aviation, healthcare devices, manufacturing, emergency response, vehicles, and infrastructure without making the sensor the root of trust.

### 2.7 Replication, self-modification, and evolutionary systems

Von Neumann and Langton establish formal self-reproduction in automata [vonneumann1966selfreproducing; langton1984selfreproduction]. Cohen analyzes computer viruses [cohen1987viruses]. Eigen models biological self-organization and replication [eigen1971selforganization]. NEAT and Gödel machines address evolutionary structure and self-modification [stanley2002neat; schmidhuber2003godel].

Recent empirical work studies self-replicating or self-evolving AI agents, including Agent Matrix, autonomous hacking and replication, adaptive computer worms, and safety amplification in self-evolving systems [zhang2025agentmatrix; air2026selfreplicate; guan2026adaptiveworms; lin2026selfevolving]. Self-Sovereign Agent analyzes economically persistent autonomy [qu2026selfsovereign].

**Established:** replication, mutation, and self-modification are old computational ideas, and modern agents can instantiate operational versions of them.

**Weakness relevant to this project:** replication research often asks whether replication succeeds or how it propagates. It rarely treats replication as one ordinary transition within a general lifecycle whose descendants share a conserved envelope.

**Opportunity:** remove “self-replication” from the center of the contribution. Spawn is one transition that moves existing rights; it cannot create net authority.

### 2.8 Self-healing, autonomic infrastructure, and AI safety

Self-stabilization, autonomic computing, and architecture-based adaptation address recovery and self-management [dijkstra1974selfstabilizing; kephart2003autonomic; garlan2004rainbow]. AI safety work identifies side effects, reward hacking, unsafe exploration, interruptibility, and evaluation environments [amodei2016concrete; leike2017gridworlds; hadfield2017offswitch]. Multi-Agent Security Tax measures collaboration/security trade-offs [peigne2025securitytax].

**Established:** systems can monitor and repair themselves, and runtime safety usually incurs utility or availability costs.

**Weakness relevant to this project:** self-healing mechanisms can themselves amplify authority if they recreate workers without conserving population rights. Safety controls are often evaluated at the individual-agent or prompt layer.

**Opportunity:** make repair, restart, migration, and replacement consume or transfer the same lineage envelope as ordinary operation, and report the safety–availability frontier rather than hiding it.

## 3. Unresolved questions exposed by the review

1. **Population invariant under dynamic membership.** How should a hard bound be expressed when the set of agents is created recursively and is not known in advance?
2. **Partition availability without identity explosion.** How can descendants operate locally during disconnection without treating each descendant as a permanent CRDT replica?
3. **Revocation semantics for offline descendants.** What can be guaranteed when a branch cannot receive a revocation message?
4. **Authority versus evidence.** How should observations enable actions without allowing compromised sensors to mint rights?
5. **State legality plus quantitative safety.** How can an implementation enforce both transition order and a lineage-wide vector bound?
6. **Reasoner independence.** Can the enforcement model remain valid when the decision component is an LLM, symbolic planner, RL policy, classical search procedure, or robotics controller?
7. **Reclamation under failure.** When and how may residual rights be safely reclaimed after crash, partition, or lost identity?
8. **Compact lineage governance.** Can online safety metadata depend on active leases and stable wardens rather than all historical descendants?
9. **Evaluation methodology.** What workloads expose the difference between centralized safety, unsafe eventual accounting, and partition-safe local escrow?

## 4. Novelty collision log

| Initial claim | Prior art that defeats it | Decision |
|---|---|---|
| A secure agent runtime with identity, lifecycle, lineage, capabilities, and audit | Agent libOS; FIPA/JADE; Borg/Kubernetes | Rejected as non-novel |
| Hierarchical contracts and budgets for recursively spawned agents | Agent Contracts; finite-resource quota delegation | Rejected as non-novel |
| Stateful authorization and reservation for concurrent agents | Provenact; escrow transactions; bounded counters | Rejected as non-novel |
| Capability inheritance and attenuating delegation | Capability systems; Macaroons; WAVE; Fixed Ceiling | Retained only as a required component, not a contribution |
| Recursive quota delegation | Agudo et al.; tree quota systems | Explicitly disclaimed |
| Leased distributed quota | voucher/quota systems and bounded counters | Explicitly disclaimed |
| Lineage tracking | Agent libOS; Context Lineage Assurance; identity schemes | Explicitly disclaimed |
| HSM-constrained agents | statecharts; HAPN; runtime shields | Explicitly disclaimed |
| **Partition-safe conserved transition envelopes over dynamic lineages with stable wardens and bounded branch-revocation exposure** | No essentially equivalent composition found in the audited corpus | Retained as the candidate contribution; still at collision risk |

## 5. State-of-the-art weaknesses and opportunity statement

The literature has strong solutions at different layers:

- planners choose actions;
- state machines constrain order;
- capabilities constrain qualitative authority;
- quota systems constrain quantities;
- runtimes manage lifecycle;
- lineage systems preserve provenance;
- policy engines coordinate stateful authorization;
- leases place time bounds on disconnected authority.

The unresolved systems problem is the **cross-layer invariant**. A dynamically created population needs an execution model in which:

- every protected effect is a legal transition;
- every transition consumes pre-existing quantitative rights;
- every descendant receives rights only by subtracting them from an ancestor or warden pool;
- disconnection does not permit double use;
- revocation cannot be instantaneous during disconnection, but its residual exposure is bounded; and
- online coordination state does not grow with every agent that ever existed.

That is the proposed research gap. It is a synthesis gap, not a primitive-mechanism gap.

---

# Part 2 — Candidate research ideas

## 6. Selection criteria

Candidates were assessed on five dimensions:

- **novelty defensibility (30%)** — whether the claim survives the collision audit;
- **two-month implementability (25%)** — whether a credible artifact and evaluation can be completed;
- **falsifiability (20%)** — whether the contribution has measurable failure conditions and competitive baselines;
- **venue fit (15%)** — especially AAMAS EMAS/RR and, with expansion, security venues; and
- **cross-domain impact (10%)** — transferability beyond an LLM application.

Scores below are planning judgments, not empirical probabilities. “Collision probability” estimates the chance that materially similar work exists but was not found or appears before submission.

## 7. Candidate 1 — Lineage Escrow Transition Systems (LETS)

**Idea.** Define and implement a distributed abstract object that conserves a vector of protected transition rights across recursive agent descendants. Stable wardens hold escrow state; ephemeral agents receive signed, expiring, attenuated leases. HSM guards, capability checks, and evidence predicates are evaluated at a complete-mediation boundary.

**Claimed novelty.** The composition and formal object: dynamic lineage subleasing, partition-safe local effects, compact stable-warden accounting, and bounded offline branch-revocation exposure.

**Publishability.** High for AAMAS EMAS if the distributed implementation and evaluation are completed; medium for USENIX Security/IEEE S&P unless the threat model and adversarial evidence are substantially expanded.

**Implementation complexity.** High but bounded. The reference kernel exists; the missing critical work is transport, persistence, multi-warden migration/rebalancing, failure injection, and realistic workload integration.

**Expected reviewer criticisms.** “This is bounded counters plus leases plus capabilities”; trusted wardens trivialize the problem; revocation is only TTL; HSM integration is superficial; no Byzantine security; synthetic experiments; no evidence that lineage semantics add value over per-site quota.

**Estimated impact.** High if the object is simple, formally specified, and demonstrated across at least two reasoning backends or domains.

**Probability similar work already exists.** **0.55.** Primitive overlap is certain; exact composition collision remains plausible.

**Planning score.** 8.2/10.

## 8. Candidate 2 — Evidence-Carrying Hierarchical Transitions

**Idea.** Require each protected transition in a distributed HSM to carry a compact evidence certificate combining sensor provenance, temporal freshness, machine state, and a proof that safety predicates hold.

**Claimed novelty.** A domain-independent evidence object and compiler for agent transitions, not tied to a particular reasoning model.

**Publishability.** Medium. Stronger for CPS or formal-methods venues if the certificate language and verification algorithm are genuinely new.

**Implementation complexity.** Medium. Build a policy DSL, certificate verifier, sensor adapters, and examples.

**Expected reviewer criticisms.** Proof-carrying code, runtime assurance, shield synthesis, signed telemetry, remote attestation, and temporal access-control systems already cover much of the mechanism. The work risks becoming integration engineering without a new theorem or language result.

**Estimated impact.** Medium-high in safety-critical sensor systems.

**Probability similar work already exists.** **0.75.**

**Planning score.** 6.9/10.

## 9. Candidate 3 — Lineage-Aware Branch Containment and Recovery

**Idea.** Model compromise containment, selective branch revocation, and safe recovery for recursively spawned agents. Derive policies that minimize collateral shutdown while bounding descendant effects.

**Claimed novelty.** Revocation and recovery semantics over dynamic descendant branches rather than fixed services or identities.

**Publishability.** Medium, potentially security-oriented.

**Implementation complexity.** Medium-high. Requires an adversarial agent workload, key/epoch rotation, distributed branch discovery, and attack evaluation.

**Expected reviewer criticisms.** This may reduce to certificate revocation, process-tree killing, taint tracking, or lineage provenance. Without a conserved resource model, the bound on harm may be weak or application-specific.

**Estimated impact.** High if coupled to measurable harm budgets.

**Probability similar work already exists.** **0.75.**

**Planning score.** 6.8/10.

## 10. Candidate 4 — Verified Graph-Rewrite Lifecycle Compiler

**Idea.** Specify autonomous populations as graph-rewrite rules over agent topology and compile them into distributed HSM/actor code with generated safety monitors.

**Claimed novelty.** A verified translation preserving topology and lifecycle invariants while allowing reasoner modules to remain opaque.

**Publishability.** Medium for formal methods or AAMAS RR/EMAS if the semantics-preservation proof is substantial.

**Implementation complexity.** Very high for two months. A credible compiler, semantics, proof, and evaluation are all required.

**Expected reviewer criticisms.** Bigraphs, graph transformation systems, actor languages, statecharts, and protocol compilers already provide nearby machinery. A small prototype could look like a DSL rather than a research contribution.

**Estimated impact.** High long term, but delivery risk is high.

**Probability similar work already exists.** **0.65.**

**Planning score.** 6.5/10.

## 11. Candidate 5 — Autonomous Replication Safety Benchmark

**Idea.** Build a benchmark in which agents can spawn, migrate, acquire resources, and recover under resource, identity, and network constraints. Evaluate lineage-level containment mechanisms rather than merely replication success.

**Claimed novelty.** Benchmark tasks and metrics for population growth, lineage authority, revocation exposure, and safety–availability trade-offs.

**Publishability.** Medium as an artifact or benchmark paper. It is less aligned with the requirement for a systems contribution unless paired with a method.

**Implementation complexity.** Medium. The environment is feasible, but broad adoption and external baselines are difficult within two months.

**Expected reviewer criticisms.** Existing agent benchmarks and self-replication evaluations could be extended instead. Synthetic tasks may not predict real risk. The benchmark may encode the authors’ preferred defense.

**Estimated impact.** Medium-high if released and adopted.

**Probability similar work already exists.** **0.55.**

**Planning score.** 6.7/10.

## 12. Candidate 6 — Topology-Adaptive Sensor/Agent Replication Scheduler

**Idea.** Jointly decide when to instantiate agents, activate sensors, migrate computation, or merge branches under energy, communication, and latency constraints.

**Claimed novelty.** A cross-layer scheduler unifying agent population topology and sensor-network duty cycling.

**Publishability.** Medium for CPS, IoT, or robotics if a new algorithm outperforms strong optimization/RL baselines.

**Implementation complexity.** High. Requires optimization formulation, simulator, multiple baselines, and realistic traces.

**Expected reviewer criticisms.** This can look like another task-allocation, autoscaling, or sensor scheduling problem. Domain independence may make the objective too abstract.

**Estimated impact.** Medium-high in edge systems.

**Probability similar work already exists.** **0.80.**

**Planning score.** 6.2/10.

## 13. Ranking and selection gate

| Rank | Candidate | Planning score | Decision |
|---:|---|---:|---|
| 1 | LETS | 8.2 | **Selected** |
| 2 | Evidence-Carrying Hierarchical Transitions | 6.9 | Retain as a future LETS extension |
| 3 | Lineage-Aware Branch Containment | 6.8 | Incorporate revocation semantics into LETS |
| 4 | Autonomous Replication Safety Benchmark | 6.7 | Use as an evaluation direction, not the main contribution |
| 5 | Verified Graph-Rewrite Lifecycle Compiler | 6.5 | Defer; excessive two-month risk |
| 6 | Topology-Adaptive Sensor/Agent Scheduler | 6.2 | Reject for this cycle |

**Selection rationale.** LETS has the strongest combination of a precise safety claim, implementable distributed object, formal invariants, domain independence, and measurable trade-offs. It also directly benefits from the researcher’s state-machine, agentic-system, and sensor-network background. Its main risk is novelty-by-composition; the paper must make the abstract object, failure model, and distinguishing experiments unusually precise.

The project should be stopped or reframed if a newly discovered paper provides all of the following: recursive descendant subleasing, partition-safe quantitative conservation, stable replica/ephemeral subject separation, branch-scoped bounded offline revocation, and state-machine effect mediation.

---

# Part 3 — Complete research proposal

## 14. Problem statement

Autonomous software increasingly operates as a population rather than as one process. An agent may decompose a task, instantiate workers, migrate execution, recover from failure, or create specialized descendants. These descendants can act through services, sensors, actuators, storage, networks, robots, or other agents. The membership set is dynamic and may change while communication is unavailable.

A centralized authorization service can preserve a global bound but denies work during partition. An eventually consistent counter can preserve availability but over-allocate. Assigning every ephemeral descendant a bounded-counter identity preserves safety in principle but couples coordination metadata to population churn. Qualitative capabilities prevent unauthorized action classes but do not bound aggregate quantity. State machines constrain action order but not lineage-wide consumption.

The problem is to enforce a vector bound on protected effects across all descendants while supporting local operation, recursive delegation, selective revocation, and bounded online metadata.

## 15. Research questions

**RQ1 — Safety.** Can a lineage-wide transition envelope remain conserved under arbitrary interleavings of spawn, execute, close, expiry, reclamation, and idempotent rights transfer?

**RQ2 — Partition availability.** Can agents continue protected work during disconnection whenever their local leases contain sufficient rights, without coordination on each transition?

**RQ3 — Revocation.** Can post-revocation effects from disconnected descendants be bounded by both residual rights and lease duration?

**RQ4 — Scalability.** Can online enforcement metadata depend on stable wardens and active leases rather than the number of historical descendants?

**RQ5 — Generality.** Can the same mediation semantics support an LLM, symbolic planner, RL policy, classical search procedure, or fixed robotics controller without changing the safety proof?

**RQ6 — Utility cost.** What availability, throughput, and coordination costs are introduced by conservation, short leases, signature verification, and HSM mediation?

## 16. Hypotheses

- **H1:** LETS never exceeds the configured global vector budget under the stated trusted-warden and complete-mediation assumptions, even during arbitrary network partitions.
- **H2:** During partitions, LETS completes more safe work than an online centralized coordinator when local rights are available.
- **H3:** LETS prevents the overrun exhibited by an unsafe eventually consistent counter under concurrent disconnected execution.
- **H4:** The optimized online safety metadata is independent of historical descendant count after inactive lease and transfer state is compacted.
- **H5:** Shorter lease duration reduces disconnected post-revocation effects but also reduces disconnected availability.
- **H6:** Qualitative capability attenuation and quantitative rights conservation are complementary: removing either admits a distinct class of unsafe behavior.

## 17. Proposed architecture

### 17.1 Planes

1. **Replaceable agent plane.** A reasoning module proposes actions. It may be an LLM, planner, RL policy, search algorithm, expert system, or controller. It is outside the trusted computing base.
2. **Agent runtime.** Maintains task context and HSM state, gathers evidence, and invokes the mediation API. It is not trusted to authorize its own effects.
3. **Stable warden plane.** A small, configured set of enforcement services stores escrow state, verifies leases, evaluates HSM/capability/evidence guards, commits debits, and emits authorization receipts.
4. **Protected executor plane.** Services or actuators accept effect requests only with a valid, fresh warden receipt. This is the complete-mediation assumption.
5. **Control plane.** Creates root envelopes, distributes policy and machine specifications, rotates keys, observes state, and initiates branch revocation.

### 17.2 Stable wardens versus ephemeral agents

The principal design decision is to separate **replicas** from **subjects**. Wardens are the bounded set of distributed escrow replicas. Agents are dynamic subjects holding leases. An agent can create a child by partitioning its residual vector locally at its current warden. The child is not added to a global rights-transfer matrix. This avoids making population churn equivalent to replica churn.

### 17.3 Lease

A lease contains:

- lease, lineage, parent, subject, and warden identifiers;
- allocation and residual vectors;
- attenuated capability set;
- machine-specification digest and current state;
- ancestor path or compact branch proof;
- branch epoch;
- issuance and expiry times;
- sequence number; and
- a warden signature over immutable authorization fields.

In a production design, mutable residual/state fields remain authoritative in warden storage and are bound to receipts or a hash-chain sequence. A bearer token alone is insufficient because an agent could replay an earlier residual.

### 17.4 Transition mediation

For a proposed transition, the warden:

1. authenticates the subject and retrieves authoritative lease state;
2. checks status, expiry, branch epoch, and signature;
3. resolves the transition from the current HSM state;
4. verifies capability and evidence predicates;
5. checks that the cost vector is componentwise within residual rights;
6. atomically debits the residual, updates HSM state, and appends an audit event; and
7. returns a single-use authorization receipt to the protected executor.

Sensor evidence can change a guard result. It cannot increase the residual vector or capability set.

### 17.5 Spawn

A local spawn is a conservation-preserving split:

- require child allocation ≤ parent residual;
- require child capabilities ⊆ parent capabilities;
- require child expiry ≤ parent expiry;
- subtract the child allocation from the parent residual; and
- create the child with exactly that allocation.

Spawn can be modeled as a protected lifecycle transition and can itself have a nonzero cost.

### 17.6 Revocation and expiry

Branch revocation is represented by a monotonically increasing branch epoch or revocation prefix. Connected wardens reject the branch immediately. Disconnected wardens or agents cannot learn the revocation instantly; therefore leases are finite and descendants cannot outlive ancestors. Residual effects after revocation are bounded by remaining rights and remaining lease time.

### 17.7 Rights transfer and migration

Wardens rebalance free rights using an idempotent quantity-transfer protocol. A prepare operation removes rights from the source free pool and marks them in flight. The target accepts a transfer identifier at most once. Accepted-transfer state is compacted with per-peer sequence watermarks and bounded sparse windows.

The current prototype implements free-pool transfer. Full migration of an active descendant subtree across wardens is proposed but not implemented. A safe implementation must freeze the subtree or use an ownership-epoch handoff so that one warden is authoritative at a time.

## 18. Mathematical model

Let `W` be a finite set of stable wardens and `A(t)` the dynamic set of agents at time `t`. Agents form a rooted lineage forest. Let the system have `m` nonnegative resource dimensions and root budget vector `B ∈ N^m`.

An HSM transition is a tuple:

`τ = (source, target, capability, guard, cost)`

where `cost(τ) ∈ N^m`. Each live lease `ℓ` has residual vector `r_ℓ`, capability set `K_ℓ`, expiry `x_ℓ`, state `s_ℓ`, and parent `p_ℓ`.

For each warden `w`, let `f_w` be its free vector. Let `C` be cumulative consumed rights and `X` the sum of prepared but unaccepted transfer vectors. The central invariant is componentwise:

`B = C + Σ_w f_w + Σ_ℓ r_ℓ + X`.

Revoked or expired-but-not-reclaimed lease residual remains in the lease term until returned. Audit logs are not part of the conserved state.

### 18.1 Safety properties

- **Non-negativity:** all vectors are componentwise nonnegative.
- **Conservation:** the equation above holds after every operation.
- **Capability attenuation:** for every non-root lease, `K_child ⊆ K_parent`.
- **Nested expiry:** for every non-root lease, `x_child ≤ x_parent`.
- **Transition legality:** an effect receipt is issued only for a transition enabled from `s_ℓ` whose guard and capability requirements hold.
- **At-most-once transfer acceptance:** each transfer identifier contributes to a target pool at most once.

### 18.2 Main proof obligations

1. **Conservation theorem.** Prove by induction over issue, spawn, execute, close, reclaim, prepare-transfer, and accept-transfer.
2. **Partition-safety corollary.** Since a partition cannot duplicate locally assigned rights and each local operation preserves conservation, aggregate consumption cannot exceed `B` under arbitrary message delay.
3. **Capability attenuation theorem.** Subset checks on spawn and absence of capability-minting operations make capability authority monotone non-increasing down a lineage.
4. **Metadata theorem.** With `|W|` stable wardens, `L` active/unreclaimed leases, dimension `m`, and bounded per-peer transfer windows, online safety metadata is `O(m|W|^2 + mL + R)`, where `R` is the active revocation-prefix representation; it is independent of historical descendant count after compaction.
5. **Revocation-exposure theorem.** For branch `b`, resource dimension `j`, remaining branch rights `R_bj`, maximum effective consumption rate `ρ_j`, maximum remaining nested lease duration `T_b`, and clock/propagation uncertainty `ε`, post-revocation consumption is bounded by `min(R_bj, ρ_j(T_b + ε))` under complete mediation.
6. **Impossibility proposition.** A disconnected subject cannot simultaneously retain unrestricted availability and receive immediate revocation in an asynchronous system without an online oracle. Finite leases convert the impossibility into a bounded-exposure design choice.

The current exhaustive checker validates a finite scalar kernel, not the complete timed or cryptographic model. The TLA+ file is a formal artifact but has not been reported as TLC-checked in this package.

## 19. Algorithms and protocol concepts

### 19.1 Core operations

- `issue_root(subject, vector, capabilities, machine, ttl)`
- `spawn(parent, subject, vector, capabilities, machine, ttl)`
- `execute(lease, transition, evidence, nonce)`
- `quiesce(lease)` / `resume(lease)`
- `renew(lease, ttl)`
- `close(lease)`
- `reclaim_expired(now)`
- `revoke_branch(branch, epoch)`
- `prepare_transfer(source, target, vector, sequence)`
- `accept_transfer(token)`
- `migrate_subtree(...)` — proposed, not in the current prototype

### 19.2 Receipt concept

An authorization receipt should bind:

- warden and executor identities;
- lease and lineage identifiers;
- machine digest, source state, transition, and target state;
- evidence digest and policy version;
- cost vector and resulting sequence number;
- executor-specific nonce and short expiry; and
- warden signature.

The executor records receipt identifiers or monotonic sequences to prevent replay.

### 19.3 Scheduling

A production scheduler should use a two-level policy:

- **within a warden:** deficit round robin or weighted fair scheduling across lineages, with reservation for safety-critical transitions;
- **between wardens:** periodically rebalance free vectors according to demand forecasts, but preserve a local reserve so partitions do not eliminate availability.

A research ablation should compare equal static partitioning, demand-proportional rebalancing, and centralized allocation.

## 20. Implementation roadmap within the proposal

The minimum viable implementation is:

- persistent wardens with an atomic local store;
- signed root and child leases;
- HSM registry and transition mediation;
- local spawn, execute, close, expiry, and branch revocation;
- idempotent free-rights transfer;
- protected mock executor that rejects unreceipted effects;
- partition/failure injector; and
- invariant checker and metrics exporter.

A realistic stack is Python or Rust for the prototype, SQLite/PostgreSQL or RocksDB for atomic local state, gRPC or HTTP/2 for warden traffic, MQTT for sensor events, Docker Compose or `kind` for deployment, and Prometheus/OpenTelemetry for metrics. The paper must not make performance claims from the present in-memory Python kernel as if it were a production service.

## 21. Experimental plan

### 21.1 Baselines

1. **Online central coordinator:** safe but unavailable under partition.
2. **Consensus-backed coordinator (Raft):** safe within quorum; unavailable to minority partitions.
3. **Naïve eventually consistent counter:** available but unsafe under concurrent disconnected spending.
4. **Replica-per-agent bounded counter:** safe comparator with metadata tied to dynamic identities.
5. **Tree quota / static hierarchical allocation:** safe but less adaptive under churn.
6. **Parent-local contracts without distributed escrow:** recursive budget accounting at one runtime boundary.
7. **LETS ablations:** no leases, no HSM guard, no capability attenuation, no idempotence, all agents as replicas, and no transfer rebalancing.

### 21.2 Workloads

- **Synthetic lineage stressor:** configurable spawn depth, branching factor, churn, action-cost distribution, and partition schedule.
- **Sensor-response workflow:** sensor events trigger observe–validate–act transitions over MQTT. Use recorded or generated telemetry and inject stale/forged evidence.
- **Distributed logistics simulation:** agents allocate vehicles, tasks, fuel/energy, and communication budget under site partitions.
- **Optional physical edge test:** Raspberry Pi or Jetson nodes with sensors and a protected actuator simulator.
- **Reasoner swap:** fixed policy, symbolic planner, and one LLM-backed proposer execute against the same warden API. The safety result should not depend on reasoner quality.

### 21.3 Metrics

- global vector overrun and invariant violations;
- completed safe work and deadline success;
- coordination denials and partition availability;
- spawn/execute/renew/transfer latency and throughput;
- post-revocation actions and consumed vector;
- time to reclaim residual rights;
- online metadata bytes and records;
- transfer and audit traffic;
- fairness across lineages;
- false rejection caused by evidence freshness or lease expiry;
- recovery time after crash and partition healing.

### 21.4 Fault and attack injection

- delayed, duplicated, reordered, and dropped transfer messages;
- warden crash and restart;
- executor replay attempts;
- parent death during child spawn;
- branch revocation during partition;
- clock skew at the assumed bound and beyond it;
- forged or stale sensor evidence;
- deeply nested lineages and hot branches;
- compromised reasoner attempting illegal transitions, capability amplification, token alteration, and overspending.

### 21.5 Statistical analysis

Use at least 30 independent seeds per stochastic condition; report means or medians with 95% bootstrap confidence intervals; use Mann–Whitney U or paired Wilcoxon tests as appropriate; report Cliff’s delta; and apply Holm correction within each hypothesis family. Pre-register the primary outcomes: overrun, completed safe work, post-revocation consumption, p99 transition latency, and online metadata. Separate deterministic safety failures from inferential performance comparisons.

### 21.6 Engineering effort per experiment

| Experiment | Work | Estimated engineering effort | Publishable intermediate result |
|---|---|---:|---|
| Finite-state safety checking | extend current checker; run parameter sweep; add counterexample traces | 2–3 days | Formal artifact / appendix |
| Multi-warden partition benchmark | persistent wardens, fault proxy, three core baselines | 7–10 days | Main systems result |
| Churn and metadata scaling | generator, compaction, replica-per-agent comparator | 3–5 days | Scalability result |
| Revocation frontier | timed leases, skew injection, branch workloads | 3–4 days | Safety–availability curve |
| Sensor workflow | MQTT adapters, evidence provenance, protected executor | 5–7 days | Domain-transfer result |
| Reasoner swap | fixed policy, symbolic planner, optional LLM proposer | 3–5 days | Model-independence result |
| Crash/recovery and transfer idempotence | persistence, replay, duplicate/reorder injection | 4–6 days | Reliability result |
| Artifact hardening | scripts, containers, one-command reproduction | 3–4 days | Reproducibility package |

## 22. Preliminary validation already completed

The current package contains:

- **8/8 unit tests passing** for recursive conservation, capability attenuation, nested expiry, state/evidence guards, branch revocation, expiry reclamation, signature tampering, and idempotent transfer acceptance;
- an exhaustive Python checker that explored **35,209 states** and **127,480 transitions** for a finite scalar model with no conservation violation;
- a preliminary 30-seed simulation in which LETS and a central coordinator had no overrun, whereas the naïve eventual counter overran in all runs;
- a synthetic lease-duration study showing the expected exposure–availability trade-off;
- an analytic metadata-scaling comparison; and
- an in-process microbenchmark of the Python reference path.

These results are **preliminary and structurally favorable to LETS**. The central baseline deliberately loses connectivity, the unsafe baseline deliberately permits overspend, and the reference benchmark is not a networked service. The complete separation observed in some statistical tests should not be presented as strong empirical evidence. The value of the current results is that they catch implementation errors and demonstrate that the experimental harness can express the intended trade-off.

## 23. Risk analysis

### 23.1 Novelty risk

The dominant risk is that reviewers characterize LETS as a straightforward composition of bounded counters, leases, capabilities, and HSMs. Mitigation requires:

- a crisp abstract data type and failure model;
- a theorem or impossibility result that depends on dynamic lineage semantics;
- a baseline in which every agent is a replica, demonstrating why the stable-warden split matters;
- an experiment showing branch-scoped revocation and reclamation under churn; and
- explicit non-claims.

### 23.2 Trusted-computing-base risk

Trusted wardens and executors may seem to move the problem rather than solve it. The paper should quantify the TCB, explain why complete mediation is necessary, and show that reasoners are fully outside it. A later security version can use TEEs, verified kernels, or threshold wardens, but those should not be promised for the two-month paper.

### 23.3 Formal-model risk

A hand proof plus finite checker may be considered insufficient. The minimum mitigation is to run TLC or Apalache on the TLA+ model, add timed properties in UPPAAL or a discrete model, and connect implementation traces to model events.

### 23.4 Evaluation risk

Synthetic workloads can make the result appear tautological. The paper needs at least one realistic sensor/edge workload, one non-LLM reasoner, one adversarial workload, and measured persistence/network costs.

### 23.5 Scope risk

A full active-subtree migration protocol, Byzantine wardens, privacy-preserving lineage, economic incentive design, and real robotics deployment cannot all fit in two months. They are future work. The main paper should prioritize one coherent invariant and its implementation.

---

# Part 4 — Manuscript artifact

The complete editable manuscript is `paper.tex`; the compiled version is `paper.pdf`. It includes:

- title and abstract;
- introduction and claim taxonomy;
- related work and novelty boundary;
- background and problem definition;
- architecture and formal model;
- algorithms and protocol;
- implementation status;
- experimental methodology and preliminary evaluation;
- discussion, limitations, threats to validity, future work, and conclusion;
- proofs, API schema, experiment-effort estimates, reproducibility checklist, and novelty audit in appendices; and
- a verified BibTeX database in `references.bib`.

---

# Part 5 — Engineering roadmap

## 24. Eight-week plan

### Week 1 — Specification lock and novelty freeze

- freeze the abstract object, threat model, and non-claims;
- run one final targeted novelty audit;
- convert the current informal operation table into a state-machine and message specification;
- add trace identifiers and expected invariants to every operation; and
- define primary hypotheses and experimental outcomes.

**Exit criterion:** no unresolved ambiguity about who owns a right during every operation and failure point.

**Intermediate result:** position paper or extended abstract containing the formal problem and collision audit.

### Week 2 — Formalization and property testing

- make the TLA+ specification executable under TLC or use Apalache;
- add nested lease expiry, branch epochs, duplicate/reordered transfer messages, and crash/restart abstraction;
- add property-based tests against the Python/Rust kernel; and
- generate minimized counterexample traces for intentionally broken variants.

**Exit criterion:** all safety invariants are machine-checked for bounded configurations; intentionally faulty variants fail.

**Intermediate result:** formal artifact suitable for a workshop/demo appendix.

### Week 3 — Persistent multi-warden service

- implement durable local transactions;
- implement authenticated warden APIs and signed receipts;
- implement executor replay protection;
- containerize three or more wardens; and
- expose metrics and trace export.

**Exit criterion:** kill/restart and duplicate-message tests preserve conservation.

**Intermediate result:** open-source minimum viable prototype.

### Week 4 — Transfer, revocation, and partition harness

- implement sequence-based idempotent transfer compaction;
- add network partition/reorder/duplication injection;
- add branch epoch propagation, expiry, and reclamation;
- either implement safe active-subtree migration or explicitly remove it from the main claim; and
- implement centralized, consensus-backed, unsafe eventual, and replica-per-agent baselines.

**Exit criterion:** an automated adversarial suite runs all baselines and produces invariant traces.

**Intermediate result:** systems demonstration and first main figure.

### Week 5 — Realistic workloads

- implement the MQTT sensor-response workload;
- add a logistics or emergency-response simulator;
- connect a fixed policy and symbolic planner; and
- optionally connect an LLM proposer without making it central.

**Exit criterion:** the same warden API mediates at least three reasoner types or two domains.

**Intermediate result:** domain-independence evidence.

### Week 6 — Full benchmark and ablation campaign

- run partition, churn, revocation, crash, throughput, and metadata experiments;
- run all ablations;
- gather 30+ seeds where stochastic;
- record hardware/software provenance; and
- freeze raw data and analysis scripts.

**Exit criterion:** every hypothesis has either supporting evidence, a null result, or a documented failure.

**Intermediate result:** complete results section.

### Week 7 — Analysis and manuscript compression

- apply the predeclared statistical analysis;
- inspect failure cases and negative results;
- rewrite the paper around the smallest supported claim;
- prepare the AAMAS-length version while retaining the extended arXiv version; and
- conduct an internal “Reviewer #2” review.

**Exit criterion:** no result is described more strongly than its method permits.

### Week 8 — Reproduction and submission hardening

- test one-command reproduction on a clean machine;
- archive containers, seeds, data, and commit hashes;
- complete the reproducibility checklist;
- verify every citation and figure; and
- prepare rebuttal notes for the top ten objections.

**Exit criterion:** an external colleague can reproduce the primary safety and performance figures.

## 25. Minimum viable prototype

The MVP is reached when:

1. three persistent wardens can partition and recover;
2. a root lease can recursively create descendants locally;
3. a protected executor rejects direct or replayed actions;
4. each authorized transition atomically checks HSM state, capability, evidence, expiry, epoch, and residual vector;
5. free rights move between wardens idempotently;
6. branch revocation and expiry bound disconnected operation;
7. the global invariant is independently checked from exported traces; and
8. the central, naïve eventual, and replica-per-agent baselines run in the same harness.

This MVP is the minimum credible systems contribution. The current in-memory kernel is a precursor, not the MVP.

## 26. Go/no-go gates

- **End of Week 1:** stop if the novelty audit finds an equivalent object and protocol.
- **End of Week 2:** narrow the paper if machine checking reveals an unresolvable ownership ambiguity.
- **End of Week 4:** stop the main-track submission if persistent multi-warden execution is not stable.
- **End of Week 6:** redirect to a workshop/artifact paper if no realistic workload or competitive baseline is complete.
- **End of Week 7:** remove any theorem or feature not matched by implementation or a clearly scoped formal artifact.

## 27. Venue strategy

As of 8 August 2026, AAMAS 2027 lists author registration on 17 September, abstract submission on 1 October, and paper submission on 8 October 2026. The EMAS area explicitly includes runtime infrastructures, lifecycle management, verification, fault tolerance, open-source toolchains, and engineering autonomous systems. This is the most realistic primary venue for the two-month schedule.

The extended arXiv manuscript should remain longer and more explicit than the submission. The AAMAS version should center:

- the LETS abstract object;
- conservation, partition safety, revocation exposure, and metadata results;
- the stable-warden/ephemeral-agent distinction;
- a complete distributed prototype; and
- a focused evaluation.

A security-venue version would require a stronger adversary, protocol security proof, executor replay analysis, compromised-warden story, and a materially larger attack evaluation. An ICML/NeurIPS version would require a learning or optimization contribution beyond the present systems object.

---

# Reviewer #2 stress test

## 28. Likely rejection arguments and required responses

### Objection 1: “This is bounded counters plus leases plus capabilities.”

**Required response:** agree that those primitives are prior art. Demonstrate that the contribution is an abstract object with dynamic lineage operations, nested expiry, branch epochs, transition mediation, and stable-replica metadata. Include a reduction table showing which required property each baseline lacks. Provide a counterexample trace for naïve compositions.

### Objection 2: “A stable warden set removes the hard dynamic-membership problem.”

**Required response:** state that this is the point, not an evasion: agents are subjects, not consensus replicas. Quantify the cost and limitation. Compare against replica-per-agent bounded counters and show metadata/reconfiguration behavior under churn. Do not claim arbitrary decentralized trust.

### Objection 3: “Revocation is just lease expiration.”

**Required response:** do not claim immediate offline revocation. Prove and measure the joint residual/time exposure bound, compare TTL values, and report availability loss. Show branch-scoped epoch propagation when connectivity exists.

### Objection 4: “The HSM is decorative.”

**Required response:** use non-commutative transitions and show attacks that a quantitative counter alone cannot prevent, such as act-before-validate or close-before-settle. Include an ablation without state mediation.

### Objection 5: “The trusted executor can be bypassed.”

**Required response:** make complete mediation an explicit assumption and build an executor that requires receipts. Enumerate bypass channels and keep them outside the claim. A security extension can reduce the TCB with TEEs or verified components.

### Objection 6: “The evaluation is constructed so LETS wins.”

**Required response:** add consensus, bounded-counter, tree-quota, and parent-contract baselines; use shared workloads; report cases where central coordination wins on utilization or latency; and include workload traces not generated from LETS assumptions.

### Objection 7: “There is no AI contribution.”

**Required response:** frame the object as multi-agent systems engineering, not machine learning. Demonstrate multiple autonomous reasoners and recursive delegation. Submit to AAMAS EMAS rather than a learning track.

### Objection 8: “The theorem assumes the implementation is correct.”

**Required response:** connect implementation traces to model operations, use atomic storage transactions, add property-based testing, and machine-check bounded cases. Avoid claiming end-to-end verification.

### Objection 9: “Metadata independence ignores the audit log and transfer history.”

**Required response:** distinguish online safety state from append-only audit storage. Implement transfer watermark compaction and inactive-lease garbage collection. Report both online and total archival storage.

### Objection 10: “The threat model excludes Byzantine wardens.”

**Required response:** state the exclusion prominently. Explain that the paper isolates governance of untrusted agents by trusted enforcement services. Treat threshold/Byzantine wardens as future work, not an implicit guarantee.

## 29. Final novelty statement suitable for the paper

> LETS does not introduce capabilities, leases, recursive delegation, hierarchical state machines, escrow, bounded counters, lineage tracking, or complete mediation. It proposes a lineage-oriented transition-escrow object that composes these mechanisms to preserve a multi-dimensional population invariant for recursively created autonomous agents during network partitions, while separating stable escrow replicas from ephemeral subjects and bounding disconnected branch-revocation exposure. The novelty claim is the formal object, its operational semantics, and its evaluated systems consequences.

That statement is the strongest currently defensible claim. It should be narrowed further if the completed implementation or additional literature does not support it.
