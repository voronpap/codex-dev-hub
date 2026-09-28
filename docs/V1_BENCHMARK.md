# Baseline and Delegation Value protocol

Status: Proposed protocol; **no benchmark has been executed**.

## Question and experimental arms

A: Codex completes the task directly with normal allowed tools, no Dev Hub.
B: the same Codex model/settings completes the same task using Dev Hub when
appropriate. Include discovery, context building, failed attempts, review and
integration in B's cost/time. B choosing not to delegate is valid and recorded.
Never count just provider latency or just the compact returned summary.

Freeze fixture commit, task text, acceptance rubric, Codex version/model/settings,
Hub commit/config, provider model IDs/plan and local hardware. Run in fresh isolated
worktrees and independent sessions; randomize A/B order, do not share solutions or
Brain memories across arms. Record warm/cold caches separately. Start with 12 tasks
(two per class below), three paired repeats each: 36 pairs/72 sessions. This is a
pilot, not a statistically definitive model ranking.

## Fixture manifest design

| Class | Two bounded fixtures | Correctness oracle |
|---|---|---|
| Document reduction | 10-page architecture summary; conflicting ADR comparison | Required facts, contradictions and correct source references |
| Structured extraction | API error table; config migration table | Exact schema plus fixture gold values |
| Code review | Parser boundary bug; missing authorization check | Seeded findings and false-positive count, line evidence |
| Test drafting | Date rollover; quota concurrency | Tests catch seeded defects and pass corrected fixtures |
| Research | Official API feature comparison; rate-limit interpretation | Frozen official source snapshots, citation support; live freshness reported separately |
| Do not delegate | Rename a constant; explain adjacent three-line change | Correct change/answer with no needless Hub overhead |

Use synthetic/local fixtures authored in Stage 1; no PLAIK/DealHunter modifications.
Freeze manifest IDs `summary-01/02`, `extract-01/02`, `review-01/02`,
`tests-01/02`, `research-01/02`, `direct-01/02`, input hashes, rubric version and
gold acceptance checks before measurement. Keep holdout variants for later router
tuning. Avoid judging tests solely by test count or generation fluency.

## Measurements and missing data

Collect per task/pair: quality score 0–100 from a blinded rubric, required test
results, completion time, Codex input/output tokens and peak context when exposed,
delegated input/output/reasoning tokens, provider free-unit consumption, paid
cost, retries, human corrections/minutes, Codex redo flag/minutes, and errors.
Retain raw measurement source/provenance with no secrets.

Codex host counters may not be available per task. If unavailable, use a declared
tokenizer estimate of task-visible messages as a **proxy**, not exact total usage
or saved subscription quota. Report proxy results separately; mark true counts
null. Returned Hub context size is not total Codex context. Shared account usage
windows cannot attribute consumption to an individual task reliably.

Human time requires a consistent timer/logging protocol; missing human corrections
remain unknown. Include time spent reviewing successful-looking but wrong output.
Do not use a free model to grade itself. Tests and human rubric are primary;
optional model grading is a separate metric with its own cost.

## Delegation Value

Report a vector first: quality delta, test delta, wall-clock delta, Codex-token
delta, delegated tokens, free units, paid-cost delta, retry delta, human-time delta
and redo rate. Quality/security are gates, not something cheap tokens can buy off.

For comparable pairs define a configurable economic cost:

```text
J = paid_API_USD
  + codex_input_tokens * w_ci + codex_output_tokens * w_co
  + elapsed_minutes * w_wait
  + human_correction_minutes * w_human
  + local_compute_minutes * w_local
  + sum(free_resource_units[k] * w_quota[k])

DelegationValue_USD_equivalent = J(A) - J(B)
DelegationValue_relative = (J(A) - J(B)) / J(A), if J(A) > 0
```

Weights are user valuations, not asserted API prices. Publish a weight manifest
and sensitivity results (zero, base and doubled quota/wait valuations). External
tokens are recorded; paid tokens are already priced in paid_API_USD and free
tokens in their quota units, so do not charge them twice. Retry and Codex redo
tokens/time are already in totals; redo flag remains a diagnostic, not a duplicate
cost term. Hardware sunk cost assumptions must be stated.

When a required J field is missing, economic Delegation Value is `unknown`; do
not fill it with zero. A partial measurement can establish narrower facts such as
less returned context, but cannot prove total savings. Illustrative calculation:
if comparable measured J(A)=1.00 and J(B)=0.70 with quality gates passed, value is
0.30 (30%); this is an example, not an observed result.

## Proposed acceptance thresholds

Before running, freeze thresholds: no critical security/correctness regression;
all required fixture tests pass; mean quality decrease <=2 points and inspect
paired distribution; at least two delegated task classes show positive median
value, >=20% median Codex token reduction when measurable and <=25% p95 elapsed
time increase. Redo rate must not increase by >5 percentage points. Nondelegation
controls should stay on Codex and expose the cost of unnecessary discovery.

Report paired differences, median/p95, sample counts and a paired bootstrap
interval; three repeats per task are not independent tasks. Bootstrap by fixture
cluster and flag the small sample. If the interval crosses zero, label evidence
inconclusive and collect more data before enabling that class by default.
Failures/timeouts stay in the denominator. Publish raw metadata and exclusions.

## Sequence

Stage 1 freezes fixtures and captures A when Codex access permits; no adaptive
router is built first. Stage 3 captures initial B for text delegates. Stage 6
repeats complete A/B under frozen versions, adds the retrieval/sandbox cases and
publishes the matrix. Smart routing requires a separate ADR after positive value.
Real existing-repository pilots follow V1 readiness, with separate authorization.
