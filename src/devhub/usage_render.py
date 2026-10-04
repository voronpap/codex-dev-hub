"""Deterministic presentation; all evidence decisions live in usage derivation."""

from devhub.usage import FooterMode, UsageSummaryV1


def _tokens(value: int | None) -> str:
    if value is None:
        return "unknown"
    return f"{value / 1000:.1f}k" if value >= 1000 else str(value)


def _saving(summary: UsageSummaryV1) -> str:
    if summary.savings is None:
        return "unknown"
    prefix = "~" if summary.savings.kind == "estimated" else ""
    return f"{prefix}{summary.savings.percent:.1f}%"


def render_compact(summary: UsageSummaryV1) -> str:
    codex = summary.codex_usage.total if summary.codex_usage else None
    latency = "unknown" if summary.latency_ms is None else f"{summary.latency_ms / 1000:.1f}s"
    cost = summary.provider_api_cost
    price = (
        "unknown"
        if cost is None
        else (("~" if cost.kind == "estimated" else "") + f"${cost.microusd / 1_000_000:.2f}")
    )
    return (
        f"DF task: Codex {_tokens(codex)} | delegated {_tokens(summary.delegated_total)}"
        f" | saving {_saving(summary)} | {latency} | API {price}"
    )


def render_verbose(summary: UsageSummaryV1) -> str:
    codex = summary.codex_usage.total if summary.codex_usage else None
    route = " → ".join(x.provider + (f"/{x.model}" if x.model else "") for x in summary.route)
    if not route:
        route = "unknown"
    elif not summary.route_complete:
        route += " (observed provider only; full Codex route unknown)"
    baseline = summary.baseline
    baseline_text = (
        "unknown"
        if baseline is None
        else (f"{baseline.tokens:,} ({baseline.kind}; {baseline.evidence_ref})")
    )
    saving_label = (
        "Estimated premium token saving"
        if (summary.savings and summary.savings.kind == "estimated")
        else "Premium token saving"
    )
    cost = summary.provider_api_cost
    cost_text = (
        "unknown"
        if cost is None
        else (
            f"${cost.microusd / 1_000_000:.2f} {cost.kind} (API only; hardware/energy unmeasured)"
        )
    )
    quality = {None: "unknown", True: "PASS", False: "FAIL"}[summary.semantic_acceptance]

    def validation(value: str) -> str:
        return {"passed": "PASS", "failed": "FAIL", "not_checked": "unknown"}[value]

    return "\n".join(
        [
            "DevFabric task usage",
            f"Route: {route}",
            "Codex tokens: " + ("unknown" if codex is None else f"{codex:,} measured"),
            "Delegated tokens: "
            + (
                "unknown"
                if summary.delegated_total is None
                else f"{summary.delegated_total:,} measured"
            ),
            f"Baseline: {baseline_text}",
            f"{saving_label}: {_saving(summary)}",
            "Delegation result latency: "
            + (
                "unknown"
                if summary.latency_ms is None
                else f"{summary.latency_ms / 1000:.1f} s measured"
            ),
            f"Provider/API cost: {cost_text}",
            f"Semantic quality: {quality}",
            f"Output validation: {validation(summary.output_validation)}",
            f"Citation validation: {validation(summary.citations_validation)}",
        ]
    )


def render_footer(summary: UsageSummaryV1, mode: FooterMode) -> str:
    if mode == "off":
        return ""
    return render_compact(summary) if mode == "compact" else render_verbose(summary)
