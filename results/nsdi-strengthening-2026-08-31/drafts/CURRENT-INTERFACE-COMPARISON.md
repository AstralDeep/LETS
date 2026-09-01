# Comparison with current agent control interfaces

**Audit date:** 2026-08-31.

This is a documentation audit, not a product impossibility claim. “Not
documented in the audited public interface” means that the capability was not
specified in the official public pages linked below on the audit date; it does
not assert that no private, application-defined, or future mechanism can
provide it.

For this comparison, **finite lineage allocation** means one quantified parent
allocation that descendants attenuate while preserving a single lineage-wide
balance. **Cross-site authority transfer** means moving units of that conserved
allocation between accounting sites; task routing, handoff, A2A messaging, and
credential delegation do not by themselves satisfy that definition. A
**durable executor claim** is an atomic, single-use settlement at the protected
effect boundary before the effect runs.

| Audited interface | Documented control and orchestration | Finite lineage allocation | Recursive subdivision of allocation | Cross-site authority transfer | Durable executor claim |
|---|---|---|---|---|---|
| [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/) | [Handoffs](https://openai.github.io/openai-agents-python/handoffs/) delegate control within one run; [tool guardrails](https://openai.github.io/openai-agents-python/guardrails/) can validate or block custom function tools before and after execution; [usage](https://openai.github.io/openai-agents-python/usage/) aggregates model tokens per run; [tracing](https://openai.github.io/openai-agents-python/tracing/) records agents, tools, handoffs, and guardrails. | Not documented in the audited public interface. | Agent handoff and agent-as-tool composition are documented; recursive subdivision of one conserved finite allocation is not documented in the audited public interface. | Not documented in the audited public interface. | Not documented in the audited public interface. Tool guardrails and session/tracing records are not specified as atomic single-use settlement of effect authority. |
| [Anthropic Claude Platform / Claude Code](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview) | The [tool-use interface](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview) separates client-executed and server-executed tools. Claude Code has ordered [allow, ask, and deny permission rules](https://code.claude.com/docs/en/permissions), including rules for named subagents. [Task budgets](https://platform.claude.com/docs/en/build-with-claude/task-budgets) are advisory across an agentic loop; `max_tokens` is a hard per-request output bound. [Rate and spend limits](https://platform.claude.com/docs/en/api/rate-limits) apply at organization or workspace scope. | Not documented in the audited public interface. Advisory task budgets and API rate/spend limits are different accounting scopes. | Subagent selection is documented; recursive subdivision of one conserved finite allocation is not documented in the audited public interface. | Not documented in the audited public interface. | Not documented in the audited public interface. The client application executes client tools, but the audited interface does not specify an atomic, replay-safe executor claim for inherited effect units. |
| [Google Gemini Enterprise Agent Platform and ADK](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/manage-agent-access) | Agent Platform documents per-agent or service-account identity and IAM permissions through [agent identity](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/agent-identity), plus adjustable project/region [service quotas](https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/agent-quotas). ADK documents [multi-agent and multi-node workflows](https://adk.dev/workflows/) and [function tools](https://adk.dev/tools-custom/function-tools/). | Not documented in the audited public interface. Project quotas govern platform resource use rather than a descendant-conserved effect allocation. | Multi-agent graphs, coordinators, sequences, loops, and parallel workflows are documented; recursive subdivision of one conserved finite allocation is not documented in the audited public interface. | Multi-node workflows and agent communication are documented; transfer of conserved effect-authority units between accounting sites is not documented in the audited public interface. | Not documented in the audited public interface. The audited IAM, workflow, and function-tool pages do not specify atomic single-use settlement of inherited effect units. |
| [Intended](https://www.intended.so/developers/docs/concepts/what-is-intended) | Intended documents an action-bound, short-lived [Authority Token](https://www.intended.so/developers/docs/concepts/decision-token-model), explicitly not an identity credential. The adapter verifies tenant, target, signature, expiry, and decision locally. Intended also states that it is not an agent-workflow orchestrator. | Not documented in the audited public interface. The documented unit is one approved action token, not a parent quantity shared across descendants. | Not documented in the audited public interface. | Local token verification is documented; transfer of a conserved allocation between accounting sites is not documented in the audited public interface. | **Single-use boundary documented; durability incomplete:** the [Connector SDK](https://www.intended.so/developers/docs/developer/connector-sdk) consumes a per-tenant nonce atomically before calling the action, and [token-verification documentation](https://www.intended.so/developers/docs/guides/verify-token) specifies a database uniqueness constraint and replay rejection. The audited pages do not specify the nonce store's crash-recovery or rollback-fencing semantics. |

## Reading the comparison

- OpenAI's per-run token usage, Anthropic's advisory task budget and service
  limits, and Google's project quotas are useful accounting or capacity
  controls. None of the audited pages specifies those values as an escrowed
  resource that a parent transfers to descendants while preserving one
  lineage-wide balance.
- OpenAI handoffs, Anthropic subagents, and Google ADK workflows establish that
  agent composition is supported. They should not be reported as recursive
  finite allocation unless a separate conserved accounting protocol is added.
- Intended is the closest documented executor-boundary mechanism in this set:
  its public interface binds one token to one action and consumes a nonce before
  execution. That supports a narrow single-use authorization claim, not a
  claim of recursive lineage conservation.

## Source and identity notes

Only first-party documentation was used:

- **OpenAI:** [Handoffs](https://openai.github.io/openai-agents-python/handoffs/),
  [Guardrails](https://openai.github.io/openai-agents-python/guardrails/),
  [Usage](https://openai.github.io/openai-agents-python/usage/), and
  [Tracing](https://openai.github.io/openai-agents-python/tracing/).
- **Anthropic:** [Tool use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/overview),
  [Claude Code permissions](https://code.claude.com/docs/en/permissions),
  [Task budgets](https://platform.claude.com/docs/en/build-with-claude/task-budgets),
  and [Rate limits](https://platform.claude.com/docs/en/api/rate-limits).
- **Google:** [Managing access](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/manage-agent-access),
  [Agent identity](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/agent-identity),
  [Agent Platform quotas](https://docs.cloud.google.com/gemini-enterprise-agent-platform/resources/agent-quotas),
  [ADK workflows](https://adk.dev/workflows/), and
  [ADK function tools](https://adk.dev/tools-custom/function-tools/).
- **Intended:** [What Is Intended](https://www.intended.so/developers/docs/concepts/what-is-intended),
  [Authority Token Model](https://www.intended.so/developers/docs/concepts/decision-token-model),
  [Connector SDK](https://www.intended.so/developers/docs/developer/connector-sdk),
  and [Verify a Token](https://www.intended.so/developers/docs/guides/verify-token).

**Identity resolution for “Intended.”** The manuscript bibliography identifies
the entity only through entries authored “Intended” at `www.intended.so`; those
pages identify their publisher as Intended, Inc. This audit therefore uses
Intended, Inc.'s public documentation for that row. The bibliography does not
identify a specific source repository, so the relationship between that vendor
and any similarly named repository or project remains unresolved and no
repository-derived claims are included.
