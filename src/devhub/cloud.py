"""Opt-in, one-shot free cloud proof through the shared execution contracts."""

import json
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, ValidationError

from devhub import gemini
from devhub.brain import ProjectBrain
from devhub.brain_models import RelativePath, SearchQuery, sha256
from devhub.brain_store import BrainError
from devhub.cloud_export import ExportPolicy, export_context
from devhub.context import ContextBuilder, canonical
from devhub.context_models import ContextLimits, ContextPolicy, ContextTask
from devhub.controller import Denied, ResourceController
from devhub.execution import dispatch_execution, reserve_execution, settle_execution
from devhub.gemini import GeminiAdapter, GeminiConfig, GeminiError
from devhub.gemini_gate import claim_count, finish_count
from devhub.gemini_permit import claim_permit, finish_permit
from devhub.groq import GroqAdapter, GroqConfig, GroqError, complete_usage, error_category
from devhub.ledger import Ledger
from devhub.local import LocalHandoff, LocalTask, Summary, now_ms
from devhub.models import Contract, Identifier
from devhub.quota import QuotaObservation, observe, save_observation
from devhub.registry import CapabilityRecord
from devhub.resources import Bucket, ResourcePolicy
from devhub.router import RouteRequest


class CloudConfig(Contract):
    project: Identifier
    root: str
    state_root: str
    approved_paths: Annotated[tuple[RelativePath, ...], Field(min_length=1, max_length=128)]
    groq: GroqConfig
    export: ExportPolicy


class GeminiCloudConfig(Contract):
    project: Identifier
    root: str
    state_root: str
    approved_paths: Annotated[tuple[RelativePath, ...], Field(min_length=1, max_length=128)]
    gemini: GeminiConfig
    export: ExportPolicy


class CloudHandoff(LocalHandoff):
    model: str | None = None
    provider_input_estimate: int | None = None
    input_estimator: str | None = None
    export_hash: str | None = None
    latency_ms: int | None = None
    http_status: int | None = None
    quota: QuotaObservation | None = None
    discovery_quota: QuotaObservation | None = None
    observed_rate_headers: dict[str, str] = Field(default_factory=dict)
    discovery_rate_headers: dict[str, str] = Field(default_factory=dict)
    semantic_acceptance: None = None
    provider_usage: dict[str, int | None] | None = None
    provider_error: dict[str, Any] | None = None
    count_response_hash: str | None = None
    preflight_http_status: int | None = None
    preflight_latency_ms: int | None = None


class CloudRuntime:
    def __init__(self, config: CloudConfig | GeminiCloudConfig) -> None:
        self.config = config
        root, state = Path(config.root).resolve(strict=True), Path(config.state_root).resolve()
        if state == root or state.is_relative_to(root):
            raise ValueError("state must be outside project")
        state.mkdir(parents=True, exist_ok=True)
        self.state = state
        self.brain = ProjectBrain(state / "brain", {config.project: root})
        self.scope = self.brain.scope(config.project)
        self.builder = ContextBuilder(self.brain)
        self.core = ResourceController(Ledger(state / "ledger.db"), allow_free_probe=True)
        self.provider = "groq" if isinstance(config, CloudConfig) else "gemini"
        self.provider_config = config.groq if isinstance(config, CloudConfig) else config.gemini
        self.adapter = (
            GroqAdapter(config.groq)
            if isinstance(config, CloudConfig)
            else GeminiAdapter(config.gemini)
        )
        self.resource = (
            self.provider + "-" + sha256(canonical(self.provider_config.model_dump()).encode())[:32]
        )
        self.buckets = {}
        for unit in ("requests", "input_tokens", "output_tokens", "total_tokens"):
            name = self.resource + "-" + unit
            self.buckets[unit] = name
            self.core.register_bucket(
                Bucket(
                    id=name,
                    pool="probe-" + sha256(self.provider_config.account.encode())[:24] + "-" + unit,
                    unit=unit,
                    starts_ms=config.gemini.qualification.observed_ms
                    if isinstance(config, GeminiCloudConfig) and config.gemini.followup_permit_id
                    else 0,
                    ends_ms=self.provider_config.probe_expires_ms,
                    capacity=1 if unit == "requests" else self.provider_config.probe_token_cap,
                )
            )
        self.core.register_policy(
            ResourcePolicy(
                id=self.resource,
                kind="free",
                synthetic=False,
                live_account=self.provider_config.account,
                quota_scope=self.provider_config.quota_scope,
                quota_provider="gemini" if self.provider == "gemini" else "groq",
                single_probe=True,
                buckets=tuple(self.buckets.values()),
            )
        )
        self.core.recover(now_ms=now_ms())

    def run(self, request: LocalTask) -> CloudHandoff:
        with self.core.ledger.transaction() as connection:
            old = connection.execute(
                "SELECT id FROM reservations WHERE project=? AND request_key=?",
                (self.config.project, request.request_key),
            ).fetchone()
        if old is not None:
            return CloudHandoff(
                status="denied", reason="request_already_attempted", reservation=old[0]
            )
        try:
            return self._run(request)
        except (GroqError, GeminiError, BrainError, Denied) as error:
            reason = str(error)
            return CloudHandoff(
                status="context_insufficient" if reason == "context_insufficient" else "denied",
                reason=reason,
            )

    def _run(self, request: LocalTask) -> CloudHandoff:
        if now_ms() >= self.provider_config.probe_expires_ms:
            raise Denied("probe_authorization_expired")
        old = self.brain.current_snapshot(self.scope)
        snapshot = self.brain.index(
            self.scope,
            approved_paths=self.config.approved_paths,
            expected_snapshot=old.snapshot_id if old else None,
        )
        batch = self.brain.search(
            self.scope, snapshot_id=snapshot.snapshot_id, query=SearchQuery(text=request.query)
        )
        task = ContextTask(
            task_id=request.task_id,
            instructions=request.instructions,
            acceptance_criteria=request.acceptance_criteria,
        )
        policy = ContextPolicy()
        limits = ContextLimits(
            model_identity=self.resource,
            context_window_tokens=self.provider_config.context_tokens,
            max_output_tokens=self.provider_config.max_output_tokens,
        )
        result = self.builder.build(
            self.scope,
            task=task,
            snapshot_id=snapshot.snapshot_id,
            batches=(batch,),
            policy=policy,
            limits=limits,
            now_ms=now_ms(),
        )
        if result.package is None:
            return CloudHandoff(status="context_insufficient", reason=result.missing_context[0])
        package = result.package
        # No adapter receives a ContextPackage or original SourceBinding, ever.
        released, receipt = export_context(package, self.config.export)
        evidence, probe = self.adapter.inspect()
        discovery_quota = None
        if isinstance(self.adapter, GeminiAdapter):
            if not self.builder.validate_package(
                self.scope, package, task=task, policy=policy, limits=limits, now_ms=now_ms()
            ):
                raise Denied("context_insufficient")
            body_hash = sha256(self.adapter.request_body(released))
            permit_id = self.adapter.config.followup_permit_id
            if permit_id is None:
                claim_count(
                    self.core.ledger, self.adapter.config.qualification, body_hash, now_ms()
                )
            else:
                claim_permit(
                    self.core.ledger,
                    permit_id,
                    self.adapter.config.qualification,
                    body_hash,
                    self.config.project,
                    request.task_id,
                    request.request_key,
                    now_ms(),
                )
            try:
                prepared = self.adapter.prepare(released)
            except (GeminiError, Denied) as error:
                count_response = self.adapter.count_response
                return CloudHandoff(
                    status="context_insufficient"
                    if str(error) == "context_insufficient"
                    else "denied",
                    reason=str(error),
                    model=evidence.model,
                    package_hash=package.package_hash,
                    offline_context_proxy=package.input_estimate,
                    export_hash=released.digest,
                    preflight_http_status=count_response.status if count_response else None,
                    preflight_latency_ms=count_response.latency_ms if count_response else None,
                    count_response_hash=sha256(canonical(count_response.body).encode())
                    if count_response
                    else None,
                    provider_error=gemini.error_evidence(count_response)
                    if count_response and count_response.status != 200
                    else None,
                )
            finish = finish_count if permit_id is None else finish_permit
            finish(
                self.core.ledger,
                self.adapter.config.quota_scope,
                prepared.request_hash,
                prepared.input_estimate,
            )
        else:
            discovery_quota = observe(
                probe.headers,
                scope=self.provider_config.quota_scope,
                now_ms=now_ms(),
                source="models_response",
            )
            save_observation(self.core.ledger, discovery_quota)
            prepared = self.adapter.prepare(released)
        started = now_ms()
        expiry = started + self.provider_config.timeout_seconds * 1000 + 15000
        capability = CapabilityRecord(
            resource=self.resource,
            provider=self.provider,
            model=evidence.model,
            endpoint="api-groq-com"
            if self.provider == "groq"
            else "generativelanguage-googleapis-com",
            plan="Free-operator-declared" if self.provider == "groq" else "Free-reviewed-ai-studio",
            kind="free",
            locality="cloud",
            synthetic=False,
            supports_text=True,
            supports_json=self.provider_config.supports_json,
            context_tokens=min(self.provider_config.context_tokens, evidence.context_tokens),
            max_output_tokens=self.provider_config.max_output_tokens,
            healthy=True,
            task_classes=(self.resource,),
            observed_ms=started,
            valid_until_ms=expiry,
            evidence=evidence.metadata_hash,
        )
        ticket, admission = reserve_execution(
            self.core,
            capability,
            RouteRequest(
                project=self.config.project,
                task=request.task_id,
                key=request.request_key,
                payload_sha256=sha256(
                    canonical(
                        {
                            "request": prepared.request_hash,
                            "package": package.package_hash,
                            "export": receipt.model_dump(),
                            "model": evidence.model_dump(),
                            "config": self.provider_config.model_dump(),
                        }
                    ).encode()
                ),
                input_tokens=prepared.input_estimate,
                max_output_tokens=self.provider_config.max_output_tokens,
                expires_ms=expiry,
                task_class=self.resource,
                requires_json=True,
                privacy="cloud_allowed",
            ),
            now_ms=started,
        )

        def revalidate() -> None:
            if not self.builder.validate_package(
                self.scope, package, task=task, policy=policy, limits=limits, now_ms=now_ms()
            ):
                raise Denied("context_insufficient")
            current, current_receipt = export_context(package, self.config.export)
            if current != released or current_receipt != receipt:
                raise Denied("cloud_export_changed")
            # The receipt remains LOCAL and binds original hashes/lines to released text.
            receipts = self.state / "exports"
            receipts.mkdir(exist_ok=True)
            (receipts / f"{ticket.id}.json").write_text(receipt.model_dump_json(), encoding="utf-8")

        dispatch_execution(self.core, ticket, admission, revalidate, now_ms)
        base: dict[str, Any] = dict(
            reservation=ticket.id,
            package_hash=package.package_hash,
            offline_context_proxy=package.input_estimate,
            provider_input_estimate=prepared.input_estimate,
            input_estimator=self.provider_config.input_estimator,
            model=evidence.model,
            export_hash=released.digest,
            discovery_quota=discovery_quota,
            discovery_rate_headers=probe.headers,
            model_input_tokens_preflight=prepared.model_input_tokens_preflight,
        )
        if isinstance(self.adapter, GeminiAdapter) and self.adapter.count_response is not None:
            base["count_response_hash"] = sha256(
                canonical(self.adapter.count_response.body).encode()
            )
        try:
            response = self.adapter.send(prepared)
        except (GroqError, GeminiError, Denied):
            self.core.unknown(ticket.id, project=self.config.project)
            return CloudHandoff(status="unknown_usage", reason="send_outcome_unknown", **base)
        category = gemini.error_category if self.provider == "gemini" else error_category
        base.update(
            latency_ms=response.latency_ms,
            http_status=response.status,
            observed_rate_headers=response.headers,
        )
        if self.provider == "gemini":
            usage = gemini.complete_usage(response, evidence.model)
            base["provider_usage"] = gemini.usage_dimensions(response)
            if response.status != 200:
                base["provider_error"] = gemini.error_evidence(response)
        else:
            observation = observe(
                response.headers,
                scope=self.provider_config.quota_scope,
                now_ms=now_ms(),
                source="inference_response",
            )
            save_observation(self.core.ledger, observation)
            base["quota"] = observation
            usage = complete_usage(response, evidence.model)
        if usage is None:
            self.core.unknown(ticket.id, project=self.config.project)
            return CloudHandoff(
                status="unknown_usage",
                reason=category(response.status) if response.status != 200 else "usage_incomplete",
                **base,
            )
        inputs, outputs = usage
        settle_execution(self.core, ticket, admission, self.buckets, inputs, outputs)
        base.update(actual_model_input_tokens=inputs, actual_model_output_tokens=outputs)
        if inputs > prepared.input_estimate or outputs > self.provider_config.max_output_tokens:
            return CloudHandoff(
                status="failed", reason="provider_estimate_or_output_exceeded", **base
            )
        if response.status != 200:
            return CloudHandoff(status="failed", reason=category(response.status), **base)
        try:
            if self.provider == "gemini":
                summary = Summary.model_validate(json.loads(gemini.summary_text(response)))
            else:
                body = response.body or {}
                choices = body["choices"]
                if (
                    not isinstance(choices, list)
                    or len(choices) != 1
                    or choices[0]["finish_reason"] != "stop"
                ):
                    raise ValueError
                message = choices[0]["message"]
                if not isinstance(message, dict):
                    raise ValueError
                if message.get("role") != "assistant" or message.get("tool_calls"):
                    raise ValueError
                summary = Summary.model_validate(json.loads(message["content"]))
        except (KeyError, TypeError, ValueError, ValidationError):
            return CloudHandoff(status="failed", reason="invalid_output", **base)
        return CloudHandoff(status="completed", reason="settled", summary=summary.summary, **base)
