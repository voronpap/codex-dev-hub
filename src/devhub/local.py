"""Opt-in local delegation composition; no fallback, retries or model pulls."""

import json
import time
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, ValidationError

from devhub.brain import ProjectBrain
from devhub.brain_models import RelativePath, SearchQuery, sha256
from devhub.brain_store import BrainError
from devhub.context import ContextBuilder, canonical
from devhub.context_models import ContextLimits, ContextPolicy, ContextTask
from devhub.controller import Denied, ResourceController
from devhub.ledger import Ledger
from devhub.models import Contract, Identifier
from devhub.ollama import OllamaAdapter, OllamaConfig, OllamaError
from devhub.registry import CapabilityRecord, CapabilityRegistry
from devhub.resources import Bucket, ResourcePolicy
from devhub.router import Router, RouteRequest, RoutingPolicy


def now_ms() -> int:
    return time.time_ns() // 1_000_000


class LocalConfig(Contract):
    project: Identifier
    root: str
    state_root: str
    approved_paths: Annotated[tuple[RelativePath, ...], Field(min_length=1, max_length=128)]
    authoritative_paths: tuple[RelativePath, ...] = ()
    ollama: OllamaConfig


class LocalTask(Contract):
    task_id: Identifier
    request_key: Identifier
    instructions: Annotated[str, Field(min_length=1, max_length=64000)]
    acceptance_criteria: Annotated[tuple[str, ...], Field(min_length=1, max_length=16)]
    query: Annotated[str, Field(min_length=1, max_length=2000)]


class Summary(Contract):
    summary: Annotated[str, Field(min_length=1, max_length=800)]


class LocalHandoff(Contract):
    status: Literal["completed", "failed", "context_insufficient", "unknown_usage", "denied"]
    reason: str
    summary: str | None = None
    reservation: str | None = None
    package_hash: str | None = None
    offline_context_proxy: int | None = None
    model_input_tokens_preflight: int | None = None
    actual_model_input_tokens: int | None = None
    actual_model_output_tokens: int | None = None


class LocalRuntime:
    def __init__(self, config: LocalConfig) -> None:
        self.config = config
        root = Path(config.root).resolve(strict=True)
        state = Path(config.state_root).resolve()
        if state == root or state.is_relative_to(root):
            raise ValueError("state must be outside project")
        state.mkdir(parents=True, exist_ok=True)
        self.state = state
        self.brain = ProjectBrain(state / "brain", {config.project: root})
        self.scope = self.brain.scope(config.project)
        self.builder = ContextBuilder(self.brain)
        self.core = ResourceController(Ledger(state / "ledger.db"), allow_local_execution=True)
        self.adapter = OllamaAdapter(config.ollama)
        self.resource = "ollama-" + sha256(canonical(config.ollama.model_dump()).encode())[:32]
        self.buckets = {}
        for unit in ("requests", "input_tokens", "output_tokens", "total_tokens"):
            name = self.resource + "-" + unit
            self.buckets[unit] = name
            self.core.register_bucket(
                Bucket(
                    id=name,
                    pool=name,
                    unit=unit,
                    starts_ms=0,
                    ends_ms=9_000_000_000_000_000,
                    capacity=1_000_000_000_000,
                )
            )
        self.core.register_policy(
            ResourcePolicy(
                id=self.resource,
                kind="local",
                synthetic=False,
                buckets=tuple(self.buckets.values()),
            )
        )
        self.core.recover(now_ms=now_ms())

    def run(self, request: LocalTask) -> LocalHandoff:
        # A repeated key must never cause another HTTP inference, even after restart.
        with self.core.ledger.transaction() as connection:
            old = connection.execute(
                "SELECT id FROM reservations WHERE project=? AND request_key=?",
                (self.config.project, request.request_key),
            ).fetchone()
        if old is not None:
            return LocalHandoff(
                status="denied", reason="request_already_attempted", reservation=old[0]
            )
        if (self.state / "tokenizer-mismatch.block").exists():
            return LocalHandoff(status="denied", reason="tokenizer_verification_required")
        try:
            return self._run(request)
        except (OllamaError, BrainError, Denied) as error:
            reason = str(error)
            return LocalHandoff(
                status="context_insufficient" if reason == "context_insufficient" else "denied",
                reason=reason,
            )

    def _run(self, request: LocalTask) -> LocalHandoff:
        evidence, tokenizer = self.adapter.inspect()
        old = self.brain.current_snapshot(self.scope)
        snapshot = self.brain.index(
            self.scope,
            approved_paths=self.config.approved_paths,
            expected_snapshot=old.snapshot_id if old else None,
        )
        batch = self.brain.search(
            self.scope,
            snapshot_id=snapshot.snapshot_id,
            query=SearchQuery(text=request.query),
        )
        task = ContextTask(
            task_id=request.task_id,
            instructions=request.instructions,
            acceptance_criteria=request.acceptance_criteria,
        )
        policy = ContextPolicy(authoritative_paths=self.config.authoritative_paths)
        # Preserve the independent offline proxy budget; actual model admission is below.
        limits = ContextLimits(
            model_identity=self.resource,
            context_window_tokens=self.config.ollama.context_tokens,
            max_output_tokens=self.config.ollama.max_output_tokens,
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
            return LocalHandoff(status="context_insufficient", reason=result.missing_context[0])
        package = result.package
        artifacts = self.state / "packages"
        artifacts.mkdir(exist_ok=True)
        (artifacts / (package.package_hash + ".json")).write_text(
            package.model_dump_json(), encoding="utf-8"
        )
        prepared = self.adapter.prepare(package, evidence, tokenizer)
        started = now_ms()
        expiry = started + self.config.ollama.timeout_seconds * 1000 + 15000
        CapabilityRegistry(self.core.ledger).put(
            CapabilityRecord(
                resource=self.resource,
                provider="ollama",
                model=evidence.digest[:32],
                endpoint=sha256(self.config.ollama.endpoint.encode())[:32],
                plan="installed-local",
                kind="local",
                locality="local",
                synthetic=False,
                supports_text=True,
                supports_json=True,
                context_tokens=self.config.ollama.context_tokens,
                max_output_tokens=self.config.ollama.max_output_tokens,
                healthy=True,
                task_classes=(self.resource,),
                observed_ms=started,
                valid_until_ms=expiry,
                evidence=evidence.metadata_hash,
            )
        )
        route = Router(self.core).route(
            RouteRequest(
                project=self.config.project,
                task=request.task_id,
                key=request.request_key,
                payload_sha256=sha256(
                    canonical(
                        {
                            "package": package.package_hash,
                            "prompt": prepared.prompt_hash,
                            "model": evidence.model_dump(),
                            "config": self.config.ollama.model_dump(),
                        }
                    ).encode()
                ),
                input_tokens=prepared.model_input_tokens,
                max_output_tokens=self.config.ollama.max_output_tokens,
                expires_ms=expiry,
                task_class=self.resource,
                requires_json=True,
            ),
            now_ms=started,
            policy=RoutingPolicy(preferred_resources=(self.resource,), max_attempts=1),
        )
        if route.ticket is None or route.admission is None:
            raise Denied(";".join(decision.reason for decision in route.decisions))
        ticket, admission = route.ticket, route.admission
        if admission.resource != self.resource or ticket.state != "reserved":
            raise Denied("unexpected_route_or_attempt")
        try:
            self.adapter.check_digest()
            if not self.builder.validate_package(
                self.scope,
                package,
                task=task,
                policy=policy,
                limits=limits,
                now_ms=now_ms(),
            ):
                raise OllamaError("context_insufficient")
            self.core.dispatch(ticket.id, admission, now_ms=now_ms())
        except (OllamaError, BrainError, Denied):
            self.core.release(ticket.id, project=self.config.project)
            raise
        base: dict[str, Any] = dict(
            reservation=ticket.id,
            package_hash=package.package_hash,
            offline_context_proxy=prepared.offline_context_proxy,
            model_input_tokens_preflight=prepared.model_input_tokens,
        )
        try:
            response = self.adapter.send(prepared)
        except OllamaError:
            self.core.unknown(ticket.id, project=self.config.project)
            return LocalHandoff(status="unknown_usage", reason="send_outcome_unknown", **base)
        inputs, outputs = response.get("prompt_eval_count"), response.get("eval_count")
        if (
            response.get("done") is not True
            or response.get("model") != self.config.ollama.model
            or type(inputs) is not int
            or type(outputs) is not int
            or not 0 < inputs <= 1_000_000_000
            or not 0 <= outputs <= 1_000_000_000
        ):
            self.core.unknown(ticket.id, project=self.config.project)
            return LocalHandoff(status="unknown_usage", reason="usage_incomplete", **base)
        self.core.settle(
            ticket.id,
            project=self.config.project,
            actual={
                self.buckets["requests"]: 1,
                self.buckets["input_tokens"]: inputs,
                self.buckets["output_tokens"]: outputs,
                self.buckets["total_tokens"]: inputs + outputs,
            },
        )
        base.update(actual_model_input_tokens=inputs, actual_model_output_tokens=outputs)
        if inputs != prepared.model_input_tokens:
            (self.state / "tokenizer-mismatch.block").write_text(
                "Operator verification required.\n"
            )
            return LocalHandoff(status="failed", reason="tokenizer_count_mismatch", **base)
        try:
            if response.get("done_reason") != "stop":
                raise ValueError("incomplete output")
            output = json.loads(response.get("response", ""))
            summary = Summary.model_validate(output)
        except (TypeError, ValueError, ValidationError):
            return LocalHandoff(status="failed", reason="invalid_output", **base)
        return LocalHandoff(status="completed", reason="settled", summary=summary.summary, **base)
