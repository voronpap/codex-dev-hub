# Offline baseline seed fixtures

Twelve frozen seed cases cover six classes, two each. Fixtures are synthetic;
research cards are small attributed paraphrases of official documentation checked
on 2026-09-28. These are smoke-size fixtures, not completed performance results.
Expand the summary seed to the full ten-page workload in a new manifest version
before the representative V1 benchmark. Do not silently change hashed inputs.

```sh
uv run python scripts/prepare_baseline.py --verify
uv run python scripts/prepare_baseline.py --fixture review-01 --arm A --output benchmark-runs/review-01-A-1
```

The script creates input.txt, task.txt and measurement.json in a new directory.
It does not run Codex or any model. Unknown measurements remain null. Freeze the
commit, model/settings, manifest version and task rubric before running arm A.

For an actual A run, open only the prepared packet in a separate session, without
Hub or evaluator files. Save the answer/diff, elapsed time and available usage
evidence; mark estimates as proxy. Repeat B independently after real delegation
exists. Never use the fake adapter as arm B evidence. Randomize order, three paired
repeats per fixture; see [full protocol](../docs/V1_BENCHMARK.md).

`oracles/` is reviewer-only. Each includes expected facts or exact output and
60/25/15 correctness/evidence/scope weights. Deduct for false-positive findings;
missing the seeded authorization bug is a critical failure. Candidate test code
must fail the seeded bug and pass a corrected reference before acceptance; Stage 1
does not execute generated code. A human evaluator scores these criteria blinded
to A/B. This packet preparation is not an automatic grader or economic benchmark.

Verification: three packet tests passed on Windows Python 3.12.10 and WSL Ubuntu
24.04 Python 3.12.3 (22 tests total together with the skeleton). They detect edited
oracles, verify six classes/twelve cases, ensure no gold answers enter packets,
refuse run-directory reuse and preserve null measurements.

Stage 3G-A adds the [offline paired harness](../docs/STAGE3G-A.md). It preserves
these exact seeds and prepares all 12 pairs; real execution requires later review.
