"""Codex-facing policy orchestration over the accepted local/cloud runtimes."""

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from devhub.cloud import CloudConfig, CloudHandoff, CloudRuntime, GeminiCloudConfig
from devhub.controller import Denied
from devhub.ledger import Ledger
from devhub.local import LocalConfig, LocalHandoff, LocalRuntime, LocalTask, now_ms
from devhub.models import Contract, Identifier
from devhub.output import OutputPolicy

TaskClass = Literal["summarize", "explain", "extract"]
Privacy = Literal["local_only", "project_private", "public", "redacted"]
RuntimeConfig = LocalConfig | CloudConfig | GeminiCloudConfig


class DelegationRequest(LocalTask):
    project: Identifier
    acceptance_criteria: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=8000)], ...],
        Field(min_length=1, max_length=15),
    ]
    task_class: TaskClass = "summarize"
    privacy: Privacy = "local_only"
    allow_cloud: bool = False
    require_citations: bool = True

    def local_task(self) -> LocalTask:
        # These validation/policy inputs must be bound by the package/export hash too.
        rule = (
            f"Delegation v1: task_class={self.task_class}; privacy={self.privacy}; "
            f"allow_cloud={self.allow_cloud}; require_citations={self.require_citations}."
        )
        return LocalTask(
            task_id=self.task_id,
            request_key=self.request_key,
            instructions=self.instructions,
            acceptance_criteria=(*self.acceptance_criteria, rule),
            query=self.query,
        )


class ProviderProfile(Contract):
    id: Identifier
    config: RuntimeConfig
    task_classes: tuple[TaskClass, ...] = ("summarize", "explain", "extract")

    @property
    def provider(self) -> Literal["ollama", "groq", "gemini"]:
        if isinstance(self.config, LocalConfig):
            return "ollama"
        return "groq" if isinstance(self.config, CloudConfig) else "gemini"

    @property
    def model(self) -> str:
        if isinstance(self.config, LocalConfig):
            return self.config.ollama.model
        if isinstance(self.config, CloudConfig):
            return self.config.groq.model
        return self.config.gemini.model


class DelegationConfig(Contract):
    profiles: Annotated[tuple[ProviderProfile, ...], Field(min_length=1, max_length=3)]
    # Tuple order is trusted policy, never a claim of comparative provider quality.
    cloud_enabled: bool = False

    @model_validator(mode="after")
    def shared_scope(self) -> "DelegationConfig":
        first = self.profiles[0].config
        scope = (first.project, Path(first.root).resolve(), Path(first.state_root).resolve())
        if scope[2] == scope[1] or scope[2].is_relative_to(scope[1]):
            raise ValueError("state must be outside project")
        if len({p.id for p in self.profiles}) != len(self.profiles):
            raise ValueError("duplicate profile")
        for profile in self.profiles:
            cfg = profile.config
            if (cfg.project, Path(cfg.root).resolve(), Path(cfg.state_root).resolve()) != scope:
                raise ValueError("profiles must share project, worktree and accounting ledger")
        return self


class Selection(Contract):
    profile: str
    provider: str
    reason: str


class DelegationResult(Contract):
    status: Literal["completed", "failed", "context_insufficient", "unknown_usage", "denied"]
    reason: str
    provider: str | None = None
    model: str | None = None
    summary: str | None = None
    citations: tuple[str, ...] = ()
    package_hash: str | None = None
    export_hash: str | None = None
    context_estimate: int | None = None
    input_preflight: int | None = None
    actual_input_tokens: int | None = None
    actual_output_tokens: int | None = None
    latency_ms: int | None = None
    accounting_reference: str | None = None
    execution: Literal["not_sent", "completed", "failed", "unknown"] = "not_sent"
    accounting: Literal[
        "not_reserved", "reserved", "released", "dispatched", "settled", "unknown_usage"
    ] = "not_reserved"
    output_validation: Literal["not_checked", "passed", "failed"] = "not_checked"
    citations_validation: Literal["not_checked", "passed", "failed"] = "not_checked"
    selection: tuple[Selection, ...] = ()
    retries: Literal[0] = 0
    fallback: Literal[False] = False
    semantic_acceptance: None = None
    quality_benchmark: None = None
    delegation_value: None = None
    savings: None = None


class DelegationRuntime:
    def __init__(self, config: DelegationConfig) -> None:
        self.config = config
        self.project = config.profiles[0].config.project
        state = Path(config.profiles[0].config.state_root)
        state.mkdir(parents=True, exist_ok=True)
        self.ledger = Ledger(state / "ledger.db")

    def reservation(self, key: str) -> tuple[str, str, str] | None:
        with self.ledger.transaction() as connection:
            row = connection.execute(
                "SELECT id,state,resource FROM reservations WHERE project=? AND request_key=?",
                (self.project, key),
            ).fetchone()
            return (row[0], row[1], row[2]) if row else None

    def run(self, request: DelegationRequest) -> DelegationResult:
        if request.project != self.project:
            return DelegationResult(status="denied", reason="project_denied")
        if self.reservation(request.request_key) is not None:
            return DelegationResult(status="denied", reason="request_already_attempted")
        selections = []
        last_handoff: LocalHandoff | None = None
        task = request.local_task()
        # The internal task has one additional policy-binding criterion.
        output_policy = OutputPolicy(require_citations=request.require_citations)
        for profile in self.config.profiles:
            if request.task_class not in profile.task_classes:
                reason = "task_class_denied"
            elif profile.provider != "ollama" and (
                request.privacy not in {"public", "redacted"}
                or not request.allow_cloud
                or not self.config.cloud_enabled
            ):
                reason = "cloud_privacy_or_policy_denied"
            else:
                reason = "candidate"
            selections.append(
                Selection(profile=profile.id, provider=profile.provider, reason=reason)
            )
            if reason != "candidate":
                continue
            # Selection precedes runtime metadata, counting, Router and reservation.
            started = now_ms()
            candidate_resource: str | None = None
            try:
                runtime: LocalRuntime | CloudRuntime = (
                    LocalRuntime(profile.config, output_policy=output_policy)
                    if isinstance(profile.config, LocalConfig)
                    else CloudRuntime(profile.config, output_policy=output_policy)
                )
                candidate_resource = runtime.resource
                handoff = runtime.run(task)
            except Denied:
                handoff = LocalHandoff(status="denied", reason="provider_ineligible")
            last_handoff = handoff
            reservation = self.reservation(request.request_key)
            if (reservation is not None and reservation[2] != candidate_resource) or (
                handoff.reason == "request_already_attempted"
            ):
                return DelegationResult(status="denied", reason="request_already_attempted")
            if reservation is None and handoff.status in {"denied", "context_insufficient"}:
                selections[-1] = Selection(
                    profile=profile.id, provider=profile.provider, reason=handoff.reason
                )
                continue
            # Any reservation is a terminal boundary for this delegation, even released.
            # No second backend after dispatch, unknown usage, invalid output or restart.
            state = reservation[1] if reservation else "not_reserved"
            execution = "not_sent"
            if state in {"dispatched", "unknown_usage"}:
                execution = "unknown"
            elif state == "settled":
                execution = (
                    "failed"
                    if isinstance(handoff, CloudHandoff) and handoff.http_status != 200
                    else "completed"
                )
            return DelegationResult.model_validate(
                {
                    "status": handoff.status,
                    "reason": handoff.reason,
                    "provider": profile.provider,
                    "model": profile.model,
                    "summary": handoff.summary,
                    "citations": handoff.citations,
                    "package_hash": handoff.package_hash,
                    "export_hash": handoff.export_hash
                    if isinstance(handoff, CloudHandoff)
                    else None,
                    "context_estimate": handoff.offline_context_proxy,
                    "input_preflight": handoff.model_input_tokens_preflight,
                    "actual_input_tokens": handoff.actual_model_input_tokens,
                    "actual_output_tokens": handoff.actual_model_output_tokens,
                    "latency_ms": handoff.latency_ms
                    if handoff.latency_ms is not None
                    else now_ms() - started,
                    "accounting_reference": reservation[0] if reservation else None,
                    "execution": execution,
                    "accounting": state,
                    "output_validation": handoff.output_validation,
                    "citations_validation": handoff.citations_validation,
                    "selection": tuple(selections),
                }
            )
        insufficient = last_handoff is not None and last_handoff.status == "context_insufficient"
        return DelegationResult(
            status="context_insufficient" if insufficient else "denied",
            reason="context_insufficient" if insufficient else "no_eligible_provider",
            selection=tuple(selections),
        )
