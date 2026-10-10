# Agentic architecture references and future strategy selection

Research date: 2026-10-04. Documentation only; no external repository installed,
source incorporated, dependency added, agent started or model invoked. Stage
3G-C/3G remain OPEN, execution_ready=false, real_codex_executions=0,
provider_sends=0. No current Router, Brain, protocol or production proof change.
Semantic acceptance, quality benchmark, Delegation Value and savings remain null.

## Sources and review scope

Read-only GitHub source inspection, pinned to:

| Repository | Revision | Classification |
| --- | --- | --- |
| [all-agentic-architectures](https://github.com/FareedKhan-dev/all-agentic-architectures/tree/cf9d620a8cc55d59589399c30f305e6dfaa428ec) | cf9d620a8cc55d59589399c30f305e6dfaa428ec | STRONG REFERENCE; adoption BENCHMARK FIRST |
| [production-grade-agentic-system](https://github.com/FareedKhan-dev/production-grade-agentic-system/tree/20def050e099d12c079f501aa6e85b48fe8783bc) | 20def050e099d12c079f501aa6e85b48fe8783bc | REFERENCE / architecture comparison |
| [kimi-k3-in-c](https://github.com/FareedKhan-dev/kimi-k3-in-c/tree/81bb6c23ccee2154bc35cad922588ab66494a9a9) | 81bb6c23ccee2154bc35cad922588ab66494a9a9 | REFERENCE / OPTIONAL BACKEND for AI Platform; BENCHMARK FIRST |
| [train-llm-from-scratch](https://github.com/FareedKhan-dev/train-llm-from-scratch/tree/bdd480a518094ca834e05ab32131dc126b522d3d) | bdd480a518094ca834e05ab32131dc126b522d3d | REFERENCE / EDUCATIONAL; not a core subsystem |

Inventory comes from the actual [package exports](https://github.com/FareedKhan-dev/all-agentic-architectures/blob/cf9d620a8cc55d59589399c30f305e6dfaa428ec/src/agentic_architectures/architectures/__init__.py)
and the module descriptions in that same directory, not an inferred list.
README advertises 35 architectures and there are 35 numbered notebook topics;
the package exports **36 concrete classes**, excluding Architecture and
ArchitectureResult. BrowserAgent and ComputerUse are separate: the former uses
Playwright; the latter describes a simulated screen. The comparison below covers
all 36. Selected routing, service, security and lifecycle code was read more
deeply; this is not a complete security audit or an independent performance test.

## Pattern mapping

All impacts below are **our prospective engineering assessment**, not measured
results or an assertion of external quality. Token/latency arrows mean additional
work versus one direct answer, not numeric estimates. D describes control flow:
M = model-dependent; H = deterministic gate over model-produced features;
D = deterministic operation over fixed inputs. None implies deterministic model
output. Every candidate must pass the security/budget conditions below.

| Pattern (export) | Existing Dev Hub equivalent / overlap | Missing capability | Security impact to control | Tokens | Latency | D | Benchmark value | Action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Reflection | Output validation only; semantic critique not established | Critique/revise strategy | Critique cannot authorize tools | Up per iteration | Up serially | M | Does revision reduce rework? | BENCHMARK FIRST |
| Reflexion | Brain + future Observer proposals | Reviewed failure lessons | Poisoned lessons / project mixing | Up; recall benefit unknown | Up | M | Transfer across similar tasks | BENCHMARK FIRST |
| ChainOfVerification | Citation validator checks source IDs | Independent factual checks | Verification text is untrusted evidence | Up per claim | Up | M | Unsupported-claim reduction | BENCHMARK FIRST |
| SelfDiscover | task_class + fixed policy | Bounded reasoning-plan selection | Plan cannot expand permissions | Up planning | Up startup | M | Complex-task benefit | REFERENCE / BENCHMARK FIRST |
| ConstitutionalAI | Trusted policy; no model policy judge | Optional content critique | Model verdict cannot replace policy | Up per rule | Up | H | Content defects, not authorization | BENCHMARK FIRST |
| SelfConsistency | Single accepted delegation | Multiple independent samples | Each sample needs accounting | Up with samples | Up or parallel load | H | Accuracy versus sample cost | BENCHMARK FIRST |
| TreeOfThoughts | No tree strategy | Bounded beam search | Branch multiplication | High growth with width/depth | High | M | Hard reasoning only | REFERENCE / BENCHMARK FIRST; costly |
| LATS | No search strategy | Bounded tree/UCB exploration | Node/call limits; no production exploration default | High branching | High | H | Search benefit after simple baseline | REFERENCE / BENCHMARK FIRST; costly |
| MentalLoop | Admission preflight, not imagined outcomes | Candidate outcome simulation | Prediction is not execution proof | Up per candidate | Up | M/H | Planning before expensive actions | REFERENCE / BENCHMARK FIRST |
| Ensemble | One selected provider | Independent outputs/aggregation | No provider shopping; all calls reserved | Up with voters | Parallel resource pressure | M/H | Diversity benefit versus cost | BENCHMARK FIRST |
| AgenticRAG | Brain + Context Builder | Budgeted query/refinement loop | Retrieved instructions untrusted | Variable; extra retrieval calls | Up | M | Recall improvement over FTS5 | BENCHMARK FIRST |
| CorrectiveRAG | Retrieval failure/context_insufficient | Evidence quality triage | Web fallback must not bypass privacy | Up grading/search | Up | H | Recovery from poor retrieval | REFERENCE; REJECT automatic wider export |
| SelfRAG | Context ranking/provenance validation | Optional relevance labels | Labels cannot override source validation | Up grading | Up | H | Precision versus omitted evidence | BENCHMARK FIRST |
| AdaptiveRAG | Explicit task_class/policy | Retrieval-depth selector | Fail closed; trusted eligibility first | Routing overhead; benefit unknown | Variable | H | Avoid unnecessary retrieval | TAKE CONCEPT / BENCHMARK FIRST |
| GraphRAG | Revision-bound FTS5 Brain | Graph/community retrieval | Derived graph provenance and staleness | Ingest + query overhead | Ingest + query cost | M/H | Only if lexical baseline insufficient | REFERENCE / BENCHMARK FIRST |
| EpisodicSemanticAgent | Brain + future observations | Typed event/fact retrieval | No parallel uncontrolled memory | Retrieval-dependent | Retrieval-dependent | M/H | Relevant session recall | REFERENCE; Brain primary |
| GraphMemoryAgent | Brain source records | Relationship traversal | Extracted triples are not source truth | Extraction overhead | Ingest/query cost | M/H | Relationship-heavy retrieval | REFERENCE / BENCHMARK FIRST |
| MemGPT | Context budget + Brain retrieval | Progressive paging | Revalidate recovered evidence | Smaller selection possible; unknown | Extra fetches | M/H | Budgeted context retention | REFERENCE; Brain primary |
| Voyager | Future reviewed skills | Skill proposal/reuse lifecycle | Generated code must not auto-execute | Generation/retrieval overhead | Sandbox/review cost | M | Repeated workflow benefit | TAKE CONCEPT; REJECT auto skill execution |
| AgentWorkflowMemory | Future Session Observer | Reviewed workflow recipes | No silent policy mutation | Mining overhead; reuse unknown | Offline mining | M/H | Recurring-work reduction | TAKE CONCEPT / BENCHMARK FIRST |
| ToolUse | devhub_delegate + exact tool ceiling | Optional additional capabilities | Origin, sandbox, authorization per tool | Depends on calls | Depends on tools | M | Tool utility versus exposure | REFERENCE; no ceiling expansion |
| ReAct | Codex can request delegation | Optional bounded tool loop | Task text cannot grant authority | Up per loop | Up per tool | M | Multi-hop tasks | BENCHMARK FIRST |
| Planning | Task/acceptance DTO | Separate plan/executor strategy | Validate plan and budgets before effects | Planning overhead | Serial dependencies | M | Decomposable tasks | TAKE CONCEPT / BENCHMARK FIRST |
| PEV | Output validation/accounting | Step-level validation | Never force-accept exhausted failure or resend ambiguous dispatch | Up retries | Up retries | M | Step validation benefit | REFERENCE; REJECT force acceptance |
| SWEAgent | Codex coding + future executor | Optional isolated code strategy | Path checks alone are not OS sandbox | Up tool cycles | Tests/execution cost | M | Incremental value beyond Codex | REFERENCE / BENCHMARK FIRST |
| BrowserAgent | Future Playwright tool | Scoped browser capability | Domain/network/action approval + audit | Up page/tool context | Browser/network cost | M/H | UI tasks only | REFERENCE / optional capability |
| ComputerUse | No core desktop tool | Simulated interaction pattern | Simulation proves no real isolation | Up action cycles | Simulation-dependent | M/H | Safe synthetic controls | REFERENCE |
| MultiAgent | Worker concept, not benchmark runtime | Budgeted role orchestration | Per-agent privacy and accounting | Up coordination | Serial/parallel tradeoff | M | Gain must exceed coordination cost | BENCHMARK FIRST; future |
| Blackboard | No shared agent board | Typed scoped contributions | Cross-agent contamination / authority | Up bids/messages | Up rounds | M | Coordination alternatives | REFERENCE / BENCHMARK FIRST |
| Debate | No debate strategy | Independent rounds + comparison | Agreement is not truth | Up agents x rounds | Up rounds | H | Error correction versus convergence | BENCHMARK FIRST |
| STORM | Brain evidence + summarization | Multi-perspective research | Web export/domain scope | High question fan-out | Retrieval + synthesis | M | Long-form research only | REFERENCE / BENCHMARK FIRST |
| MetaController | Registry/Controller/deterministic Router | Optional strategy registry | LLM choice cannot be policy authority | Extra classifier call | Extra routing latency | M in source | Structured-feature routing experiment | REFERENCE; TAKE constrained concept |
| DryRun | Preflight + permits | Optional effect preview | Simulation never substitutes approval | Simulation overhead | Extra gate | M/H | Catch unsafe plans offline | TAKE CONCEPT; REJECT model authorization |
| ReflexiveMetacognitive | Capability/eligibility checks | Untrusted task-feature extraction | Self-confidence cannot grant capability | Extra classification | Extra gate | H | Escalation calibration | TAKE CONCEPT / BENCHMARK FIRST |
| RLHFSelfImprovement | Future Observer proposals | Reviewed example archive | No autonomous prompt/skill rewriting | Critique/archive overhead | Offline + inference | H | Repeated defects | REFERENCE; not training proof |
| CellularAutomata | None | Grid interaction experiment | Unbounded aggregate calls | High cells x steps | High rounds | M | Low current relevance | REFERENCE; no core adoption |

## Deterministic picker: take the separation, not the claims

The [picker tutorial](https://github.com/FareedKhan-dev/all-agentic-architectures/blob/cf9d620a8cc55d59589399c30f305e6dfaa428ec/docs/tutorials/deterministic-picker.md)
uses structured labels/booleans with Python composition. Some examples still use
model-estimated numeric features or weighted formulas. This does not prove
calibration, truth, safety or immunity to prompt injection. A deterministic
formula over unreliable features remains unreliable.

The actual [MetaController](https://github.com/FareedKhan-dev/all-agentic-architectures/blob/cf9d620a8cc55d59589399c30f305e6dfaa428ec/src/agentic_architectures/architectures/meta_controller.py)
constrains a model-selected architecture to roster names, then executes that
choice. This is **not** our desired deterministic eligibility decision.

Future flow: task -> structured task features -> validated schema -> Capability
Registry -> Strategy Registry -> ResourceController -> deterministic policy ->
strategy + provider. task_class is a hint; privacy, quotas, account eligibility,
tool permissions and paid approval are trusted inputs. Model-generated features
may narrow a choice but cannot promote private data to public, invent capacity,
authorize a tool or widen a denied provider set. Unknowns fail closed. Opaque
model-generated numeric provider/agent scores as authority are REJECTED.

## Production system: layers, not a quality endorsement

The [README](https://github.com/FareedKhan-dev/production-grade-agentic-system/blob/20def050e099d12c079f501aa6e85b48fe8783bc/README.md)
presents seven central application layers, then evaluation and stress-testing
sections. The name production-grade is an author label, not our qualification.
Comparison is scoped to inspected source; broader infrastructure does not imply
stronger accounting or security.

| Their layer | Our equivalent | Gap / stronger-weaker by requirement | Candidate idea |
| --- | --- | --- | --- |
| Modular codebase/config/containerization | Typed config, locked dependencies, runtime proof | Their app deployment is broader; our frozen security boundary remains required | REFERENCE modular lifecycle, no services now |
| Persistence | Brain + SQLite ledger/outbox | Postgres users/sessions/threads are broader app storage; not revision/hash-bound Brain evidence | Keep storage responsibilities separate |
| Security/safeguards | Privacy release, strict DTOs, origin/admission work | JWT/IP rate limits and HTML sanitization do not supply our origin/accounting guarantees | Compare threat models, not feature counts |
| AI service/resilience | Registry, deterministic Router, ResourceController, adapters | Retry/circular model fallback conflicts with our post-dispatch rule | REJECT that behavior; circuit state may later be reference |
| Agent workflow/memory | Brain, Context Builder, delegation | LangGraph + mem0/pgvector provide broader conversation workflows; not our Git truth/provenance system | REFERENCE bounded strategies, no parallel memory |
| API gateway | MCP DTO boundary; future AI Platform facades | Their FastAPI/JWT/SSE surface is broader web API scope | OPTIONAL future facade reference, not core replacement |
| Observability/operations | Usage settlement, transactional outbox, redacted evidence | Prometheus/Langfuse/logging are broader dashboards; not durable spend liability | REFERENCE metrics presentation only |
| Evaluation/stress testing (adjacent sections) | Frozen paired harness/oracles | Their judge-based grading is different evidence; not accepted Stage 3G oracle | Hold-out discipline and load tests separately |

### Security comparison against inspected code

Primary files: [workflow](https://github.com/FareedKhan-dev/production-grade-agentic-system/blob/20def050e099d12c079f501aa6e85b48fe8783bc/src/agent/workflow.py),
[LLM service](https://github.com/FareedKhan-dev/production-grade-agentic-system/blob/20def050e099d12c079f501aa6e85b48fe8783bc/src/services/llm_provider.py),
[sanitization](https://github.com/FareedKhan-dev/production-grade-agentic-system/blob/20def050e099d12c079f501aa6e85b48fe8783bc/src/utils/sanitization.py),
[rate limit](https://github.com/FareedKhan-dev/production-grade-agentic-system/blob/20def050e099d12c079f501aa6e85b48fe8783bc/src/system/rate_limit.py),
[logging](https://github.com/FareedKhan-dev/production-grade-agentic-system/blob/20def050e099d12c079f501aa6e85b48fe8783bc/src/system/logs.py).

| Boundary | Observation / evidence limit | Required here |
| --- | --- | --- |
| Prompt injection | Sanitization escapes HTML; that does not distinguish instructions from retrieved evidence | Explicit trust boundaries and provenance; no model authorization |
| Tool authorization/origin | Workflow resolves tools_by_name then invokes arguments; reviewed client-generation admission seal not established there | Exact approved binding through dispatch; our production proof still UNKNOWN |
| Privacy | Workflow sends conversation into memory and tracing callbacks; public/redacted release contract not established in inspected path | Hash-bound release before cloud; private stays local |
| Project isolation | User/session scoping exists; Git project/root/revision binding not established | Cross-project/source validation, separate state |
| Retries/unknown usage | Service retries timeout/API failures and rotates models | No automatic resend/fallback after dispatch; retain unknown_usage |
| Paid fallback/quota | Model registry + IP limiter is not spend reservation or verified remaining provider capacity | Known price, explicit approval, durable budget/quota admission |
| Secret handling | Settings/env boundary exists; workflow error logging can include query text and callbacks need data-retention review | Redaction/secret scans; no sensitive payload logs by default |
| Auditability/replay | Traces/checkpoints are not proof of atomic outbox or request-key replay denial | Durable transitions and replay protection; require explicit evidence |

Absence of a guarantee in inspected paths is not a claim of a confirmed exploit
or a complete repository-wide absence. All-agentic examples also need these same
checks: bounded loops alone do not provide reservations, origin sealing or OS
isolation. In particular inspect PEV failure acceptance, SWE/Voyager subprocess
execution, browser actions, automatic web fallback and memory writes before reuse.

## Future Strategy Registry and bounded experiments

TAKE CONCEPT only: a strategy description may declare id/version, required
capabilities, privacy class, max calls/context/latency, eligible providers,
validation requirements and benchmark status. Keep one small execution core;
direct, retrieve, reflect and planner_executor are optional strategies, not new
accounting systems. No registry implementation in this PR.

Every loop needs max iterations, provider calls, tokens, wall time and cost,
replay protection and an explicit stop condition. Exhaustion is a failure or
insufficient result, never forced acceptance. Free-first does not mean unlimited.
No recursive agents or cross-provider retry after ambiguous dispatch.

After Stage 3G and separate review, freeze an experiment comparing Codex alone,
simple delegation, reflection, retrieval and planner/executor. Freeze prompts,
policies, budgets, oracles and raw metrics before results. Measure quality,
corrections, actual/proxy tokens separately, latency and coordination cost; no
arbitrary aggregate score or primary LLM judge. No such experiment runs now.

Brain remains the shared durable context source through approved retrieval APIs.
FTS5 remains baseline; embeddings/graphs need measured benefit first. Strategies
must not spawn independent ungoverned memories. Session Observer can identify
strategy rework/usefulness and propose changes, never mutate policy autonomously.
Browser capability requires explicit tools, sandbox, network/domain scope, action
approval and audit logs; it is not part of default delegation. Multi-agent gain
must exceed token/latency/coordination cost while preserving privacy/accounting.

## Reuse gates and related research

Before source reuse: verify license/copyright, transitive dependencies, model and
weight licenses, commercial terms, security, maintenance and telemetry/network
behavior. Repository naming/popularity and benchmark claims are not evidence for
our environment. No source snippets were incorporated or external programs run.

Training reference: [held-out evaluation discussion](https://github.com/FareedKhan-dev/train-llm-from-scratch/blob/bdd480a518094ca834e05ab32131dc126b522d3d/docs/08_evaluation.md)
is educational material alongside tokenization, data preparation and training
pipelines; foundation-model training is not a current roadmap priority.

See [context/memory research](CONTEXT_AND_QUALITY.md), [future startup UX](FUTURE_PLATFORM.md)
and the separate AI Platform [local-backend catalog](https://github.com/voronpap/ai-platform/blob/docs/provider-aggregator-research/docs/catalog/LOCAL_INFERENCE_BACKENDS.md).
