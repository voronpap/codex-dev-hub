import pytest
from pydantic import ValidationError

from devhub.delegate import DelegationResult, Selection
from devhub.usage import ApiCost, Baseline, TokenUsage, derive_usage
from devhub.usage_render import render_compact, render_footer, render_verbose


def demo(**updates):
    return DelegationResult(
        **(
            dict(
                status="completed",
                reason="ok",
                provider="ollama",
                model="qwen2.5:14b-instruct",
                execution="completed",
                accounting="settled",
                accounting_reference="demo-reservation",
                actual_input_tokens=647,
                actual_output_tokens=77,
                latency_ms=16264,
                output_validation="passed",
                citations_validation="passed",
            )
            | updates
        )
    )


def usage(**updates):
    return TokenUsage(
        **(
            dict(
                input_tokens=60,
                output_tokens=40,
                evidence_ref="actual:1",
                comparison_key="task/protocol/token-convention",
            )
            | updates
        )
    )


def baseline(**updates):
    return Baseline(
        **(
            dict(
                kind="exact",
                tokens=200,
                source="paired_benchmark",
                evidence_ref="baseline:1",
                comparison_key="task/protocol/token-convention",
            )
            | updates
        )
    )


def test_demo_measured_unknown_and_api_scope():
    summary = derive_usage(demo())
    assert summary.delegated_total == 724
    assert summary.codex_usage is summary.baseline is summary.savings is None
    assert summary.semantic_acceptance is None
    assert summary.model_dump()["savings"] is None
    assert render_footer(summary, "off") == ""
    assert render_compact(summary) == (
        "DF task: Codex unknown | delegated 724 | saving unknown | 16.3s | API $0.00"
    )
    verbose = render_verbose(summary)
    assert "724 measured" in verbose and "Semantic quality: unknown" in verbose
    assert "Output validation: PASS" in verbose and "Citation validation: PASS" in verbose
    assert "hardware/energy unmeasured" in verbose
    assert "ollama/qwen2.5:14b-instruct" in verbose
    assert "full Codex route unknown" in verbose


def test_exact_and_estimated_savings():
    exact = derive_usage(demo(), codex_usage=usage(), baseline=baseline())
    assert exact.savings.percent == 50
    assert "saving 50.0%" in render_compact(exact)
    assert "~" not in render_compact(exact)
    estimate = baseline(
        kind="estimated",
        source="reviewed_estimator",
        estimator_version="estimator-v1",
        source_data_ref="accepted:history",
        limitations="Illustrative test; not project evidence",
    )
    estimated = derive_usage(demo(), codex_usage=usage(), baseline=estimate)
    assert "saving ~50.0%" in render_compact(estimated)
    assert "Estimated premium token saving" in render_verbose(estimated)
    assert estimated.savings.baseline_ref == estimate.evidence_ref


@pytest.mark.parametrize("value", [baseline(tokens=0), baseline(comparison_key="other")])
def test_invalid_comparison_is_unknown(value):
    assert derive_usage(demo(), codex_usage=usage(), baseline=value).savings is None


def test_missing_usage_unknown_cost_no_send_and_negative_savings():
    assert derive_usage(demo(), baseline=baseline()).savings is None
    assert (
        derive_usage(demo(), codex_usage=usage(output_tokens=None), baseline=baseline()).savings
        is None
    )
    unknown = derive_usage(demo(provider="groq", actual_input_tokens=None))
    assert unknown.delegated_total is unknown.provider_api_cost is None
    assert "API unknown" in render_compact(unknown)
    denied = derive_usage(demo(execution="not_sent", accounting="not_reserved"))
    assert denied.route == () and denied.provider_api_cost is None
    negative = derive_usage(demo(), codex_usage=usage(input_tokens=400), baseline=baseline())
    assert negative.savings.percent < 0
    assert "saving -120.0%" in render_compact(negative)


def test_provenance_and_cached_dimensions():
    with pytest.raises(ValidationError):
        baseline(kind="estimated")
    with pytest.raises(ValidationError):
        baseline(source="reviewed_estimator")
    with pytest.raises(ValidationError):
        baseline(evidence_ref="")
    with pytest.raises(ValidationError):
        usage(cached_input_tokens=61)
    assert usage(cached_input_tokens=20).total == 100


def test_selection_is_not_execution_route_and_cost_labels():
    result = demo(selection=(Selection(profile="x", provider="groq", reason="denied"),))
    summary = derive_usage(
        result,
        provider_api_cost=ApiCost(
            kind="estimated", microusd=123000, evidence_ref="pricing:reviewed-v1"
        ),
    )
    assert [s.provider for s in summary.route] == ["ollama"]
    assert "API ~$0.12" in render_compact(summary)
    assert "$0.12 estimated" in render_verbose(summary)


def test_local_charge_is_known_zero_not_billing_measurement():
    summary = derive_usage(demo())
    assert summary.provider_api_cost.kind == "known_zero"
    assert summary.provider_api_cost.microusd == 0
    assert summary.provider_api_cost.evidence_ref == (
        "local-ollama:no-external-api-charge:accounting:demo-reservation"
    )
    line = next(x for x in render_verbose(summary).splitlines() if x.startswith("Provider/API"))
    assert "known-zero local API charge" in line
    assert "hardware/energy unmeasured" in line
    assert "$0.00 measured" not in line
    assert "API $0.00" in render_compact(summary)
    with pytest.raises(ValidationError):
        ApiCost(kind="known_zero", microusd=1, evidence_ref="invalid")


def test_accounting_does_not_establish_cloud_billing():
    summary = derive_usage(demo(provider="groq"))
    assert summary.accounting == "settled" and summary.evidence_refs
    assert summary.provider_api_cost is None
    assert "Provider/API cost: unknown" in render_verbose(summary)


@pytest.mark.parametrize("kind,prefix", [("measured", ""), ("estimated", "~")])
def test_explicit_cost_evidence_is_preserved(kind, prefix):
    cost = ApiCost(kind=kind, microusd=123000, evidence_ref="billing-or-estimator:reviewed")
    summary = derive_usage(demo(), provider_api_cost=cost)
    assert summary.provider_api_cost == cost
    assert f"Provider/API cost: {prefix}$0.12 {kind}" in render_verbose(summary)
    assert f"API {prefix}$0.12" in render_compact(summary)
