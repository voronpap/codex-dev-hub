# Stage 3G-A: offline paired benchmark harness

Stage 3F CLOSED; local unified delegation gate PASSED (PR #21). Stage 3G OPEN.
Stage 3G-A CLOSED; offline harness accepted in PR #22.
This slice is storage, input isolation and integrity infrastructure only.
The next protocol/launcher slice requires review before real execution. No Codex/provider executor, model
pull, network client, generated-test execution, provider comparison or Router
change is included. CI uses synthetic captures, never a real benchmark.

## Reproduce packet preparation

From a clean checkout of the implementation commit, with locked dependencies:

```sh
uv sync --locked
uv run --locked python -m devhub.benchmark prepare --config benchmarks/harness-config.json --run ../stage3g-offline-001 --run-id stage3g-offline-001
uv run --locked python -m devhub.benchmark verify --config benchmarks/harness-config.json --run ../stage3g-offline-001
uv run --locked pytest -q tests/test_benchmark.py tests/test_baseline.py
```

Both commands refuse dirty tracked/staged/untracked source, changed implementation,
changed frozen fixture/oracle/seed-manifest hashes, mismatched configuration or
artifacts. Preparation refuses existing directories and storage inside the source
repository. Use a new run ID and directory for every configuration version; verify
an old run from its recorded implementation commit. The verifier also checks that
the loaded harness code matches that commit. No shell commands from fixtures run.

The existing Stage 1 preparation command now shares the same frozen hash verifier.
The 12 fixture and 12 oracle files and their seed-1 manifest remain byte-identical.
No expansion or replacement of the small summary seed is part of this experiment.
Older proposed protocol items (three repeats, aggregate weighted scores) are not
silently adopted by this slice: the requested initial experiment is 12 pairs and
raw dimensions. A real execution protocol needs its own reviewed frozen config.

## Artifacts and isolation

`manifest.json` records implementation, run/config/seed hashes, all fixture/oracle
hashes and original task classes, policy hashes and model identity/digest fields.
The draft offline config intentionally leaves model identity and runtime policies
null: it is NOT a claim that a real benchmark configuration has been frozen.
Stage 3G-B must bind the accepted local configuration, model manifest, Context Builder
and deterministic routing policy before any real execution.

`executors/<fixture>/<A|B>/` contains only task.txt, input.txt and instructions.txt.
A/B task and input bytes are identical. Acceptance requirements remain those in the
frozen prompt, not reviewer-only answers. Both arms receive the same common
instructions; B additionally describes availability of the accepted local mechanism.
That instruction does not force delegation when the task explicitly forbids it.
No oracle, measurement record, other arm output, prior answer or evaluator metadata
is copied into either packet. Files are independent copies, not links.

`records/<fixture>/<arm>/prepared.json` starts as not_run, with an explicit reason
and null usage, cost, duration, quality and retry measurements. A technical skip can
be appended with mark_not_run and a reason. SyntheticCapture/freeze_synthetic test
append-only output/final records; they cannot claim actual model usage, zero API
cost, quality, savings, or completed real execution. No real-result ingestion is
authorized or implemented in this slice; the reviewed executor slice must extend
that boundary with observable metric provenance.

Artifact creation uses exclusive writes; overwrites/run reuse fail. SHA-256 binds
outputs to final records and packets to the manifest. Verification recomputes the
expected packets from frozen fixtures/config, detecting even a substituted input
whose adjacent hash was recomputed. Missing, extra, symlinked, changed or
cross-fixture artifacts fail closed. A partial write leaves an invalid run; do not
repair/reuse it. Preserve the failed directory and start a new run ID.
These are immutable-by-API, content-verified artifacts, not signed forensic storage
against an administrator rewriting an entire run and all its hashes.

The reviewer-only API refuses to return oracle content before both output artifacts
are frozen and verified. Synthetic results always yield inconclusive. Executors
never invoke this API. This is a packet boundary, not an OS sandbox: the later
launcher MUST expose only one packet to a fresh independent session, never the
whole run/source tree, evaluator files, prior session history or opposite arm.
No live launcher is present, so this PR makes no claim of live-session isolation.

## Measurements and evaluation boundary

The frozen timing definition covers immediately before executor invocation through
final captured output, including startup/context/tools/inference/validation. It
excludes preparation and post-freeze oracle review. Store UTC start/end and monotonic
duration_ns. Synthetic capture times describe only offline stubs; never compare them
to Codex or provider latency. Inference latency is a separate metric.

Raw fields distinguish actual Codex input/output, explicitly named context proxies
and estimator IDs, delegated input/output, API monetary cost, local inference time,
Codex retries, Dev Hub retries, provider sends and fallbacks. Unknown means null,
including unobservable Codex internal retries. Local API cost can be zero only when
an actual local execution establishes it; hardware/electricity costs are not inferred.

Quality dimensions are separate: acceptance/tests/citations, required items hit or
missing, incorrect/unsupported claims and human correction category. They remain
null in unexecuted/synthetic records. Before real evaluation use frozen oracle,
exact/schema checks where applicable and isolated tests for generated test tasks;
no primary LLM judge and no aggregate 60/25/15 score inherited implicitly from the
historical rubric. Required facts cannot generally be graded by literal substring.

Correction definitions are included in each manifest before evaluation:

- none: all required criteria verified; no edits.
- minor: all required criteria verified; presentation edits only.
- major: a required criterion fails; substantive repair.
- unusable: no usable task artifact, or a critical oracle requirement fails.
- insufficient evidence: null, not an assumed correction category.

No A-better/B-better winner rule is approved here. Comparison remains inconclusive
until a reviewed real protocol freezes explicit comparison criteria. Model quality,
Delegation Value and savings are not inferred from a working harness. Analysis by
six existing classes and routing recommendations belong after frozen paired results;
Router changes need a subsequent review.

## Gate and CI

Offline tests cover all 12 pairs, seed tampering, oracle/reviewer ordering, arm
contamination, deterministic packets, output/config/commit binding, dirty tree,
exclusive storage, schema/null handling, synthetic timing and honest skips.
Linux runs the full suite. The Unicode/spaced-path/exclusive-file test joins Windows
smoke because those filesystem/encoding semantics are platform-sensitive; the rest
is not duplicated routinely on Windows. Stage 3G closure will still require full
Windows CI, not a duplicate 12-pair Windows experiment.

STOP after this PR. No real 24-run benchmark, cloud calls, provider shopping,
prompt tuning, adaptive routing or runtime policy changes are authorized here.
