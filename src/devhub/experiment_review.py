"""Pre-result reviewer rules and comparison; no model judge or generated code execution."""

import json
from pathlib import Path
from typing import Literal

from devhub.baseline import verified_cases
from devhub.benchmark import Quality
from devhub.experiment import ExperimentProtocol
from devhub.models import Contract


class ComparisonInput(Contract):
    quality: Quality
    duration_ms: int | None
    technically_valid: bool
    timing_valid: bool
    contamination: bool = False


class PairComparison(Contract):
    result: Literal["A better", "B better", "equivalent", "inconclusive"]
    dimension: Literal["acceptance", "human_correction", "latency", "primary_dimensions", "unknown"]
    reason: str
    delegation_value: None = None


def compare(a: ComparisonInput, b: ComparisonInput, policy: ExperimentProtocol) -> PairComparison:
    def answer(result: str, dimension: str, reason: str) -> PairComparison:
        return PairComparison.model_validate(
            dict(result=result, dimension=dimension, reason=reason)
        )

    if any(not x.technically_valid or not x.timing_valid or x.contamination for x in (a, b)):
        return answer("inconclusive", "unknown", "Technical or isolation boundary compromised")
    if a.quality.acceptance_pass is None or b.quality.acceptance_pass is None:
        return answer("inconclusive", "unknown", "Acceptance not established")
    if a.quality.acceptance_pass != b.quality.acceptance_pass:
        return answer(
            "A better" if a.quality.acceptance_pass else "B better",
            "acceptance",
            "Only one arm passed acceptance",
        )
    if not a.quality.acceptance_pass:
        return answer(
            "inconclusive", "unknown", "Neither arm passed; retain raw failure dimensions"
        )
    corrections = {"none": 0, "minor": 1}
    if any(x.quality.human_correction not in corrections for x in (a, b)):
        return answer(
            "inconclusive", "unknown", "Missing or inconsistent correction classification"
        )
    ac = corrections[str(a.quality.human_correction)]
    bc = corrections[str(b.quality.human_correction)]
    if ac != bc:
        return answer(
            "A better" if ac < bc else "B better",
            "human_correction",
            "Both accepted; one requires less presentation repair",
        )
    if a.duration_ms is None or b.duration_ms is None or min(a.duration_ms, b.duration_ms) < 0:
        return answer("inconclusive", "unknown", "Comparable duration unavailable")
    tolerance = max(
        policy.latency_absolute_ms, policy.latency_relative * min(a.duration_ms, b.duration_ms)
    )
    if abs(a.duration_ms - b.duration_ms) <= tolerance:
        return answer(
            "equivalent", "primary_dimensions", "Acceptance/rework equal; time within tolerance"
        )
    return answer(
        "A better" if a.duration_ms < b.duration_ms else "B better",
        "latency",
        "Acceptance/rework equal; time difference exceeds frozen tolerance, not an aggregate value",
    )


def reviewer_rules(repo: Path) -> list[dict[str, object]]:
    """Evaluator metadata only. Must never be mounted into an executor container."""
    result = []
    for case in verified_cases(repo / "benchmarks"):
        oracle = json.loads((repo / "benchmarks" / case["oracle"]).read_bytes())
        result.append(
            {
                "fixture_id": case["id"],
                "oracle_sha256": case["oracle_sha256"],
                "output": "text_only",
                "needs_files_during_execution": False,
                "exact_check": "json_typed_equality"
                if "expected_json" in oracle
                else "source_text_ignore_terminal_newlines_and_crlf"
                if "expected_source" in oracle
                else None,
                "requires_isolated_test_execution": "execution_gate" in oracle,
                "tests_pass_applicable": "execution_gate" in oracle,
                "citation_pass_applicable": bool(
                    oracle.get("required_citations")
                    or oracle.get("required_urls")
                    or case["id"].startswith("review-")
                ),
                "manual_checks": {
                    k: v for k, v in oracle.items() if k not in {"rubric", "schema_version", "id"}
                },
                "acceptance_rule": "All oracle requirements checked; no incorrect claims; "
                "No unsupported claims. No-delegation fixtures require zero calls; "
                "applicable tests/citations pass. "
                "Unverified required criterion => null, demonstrated failure => false.",
                "human_correction_rule": "Unchanged CORRECTION_RULES; unknown => null.",
                "review_barrier": "Both outputs frozen/verified before blinded oracle review.",
            }
        )
    return result
