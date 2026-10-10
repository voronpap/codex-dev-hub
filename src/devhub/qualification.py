"""Strict Stage 3G qualification identities and immutable manifest verification.

This module is metadata-only. It never starts Codex, a provider, or a benchmark task.
Paths locate evidence; canonical hashes and typed identities establish authority.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, cast

from pydantic import BaseModel, Field, JsonValue, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.ledger import LedgerIdentityCoreV1, ledger_identity_sha256
from devhub.models import Contract, ContractV2
from devhub.ollama_transport import OllamaBridgeAuthorityV1

GitCommit = Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
EnvironmentInstanceId = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
ImageId = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]

STAGE3G_OLLAMA_VERSION = "0.34.2"
STAGE3G_OLLAMA_MODEL = "qwen2.5:14b-instruct"
STAGE3G_OLLAMA_DIGEST = "7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6"
STAGE3G_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"
STAGE3G_OLLAMA_RELEASE_ASSET = "ollama-linux-amd64.tar.zst"
STAGE3G_OLLAMA_RELEASE_SHA256 = "e155b83589986d2c581fdbf1381ea3ebdb16549883679cd5a0627f7cdc05b12b"
STAGE3G_DELEGATE_TOOL = "mcp__devhub_delegate.devhub_delegate"
DELEGATE_SCHEMA_SHA256 = "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
DELEGATE_ENTRYPOINT = "devhub.delegate_server"
ISOLATED_DELEGATE_ARGS = ("-I", "-m", DELEGATE_ENTRYPOINT)

ReceiptKind = Literal[
    "isolation",
    "effects_boundary",
    "auth_egress",
    "ollama_metadata",
    "ledger_identity",
    "codex_executable",
    "host_process_visibility",
    "evaluator",
    "python_runtime",
    "runtime_config_probe",
]

RECEIPT_KINDS: tuple[ReceiptKind, ...] = (
    "isolation",
    "effects_boundary",
    "auth_egress",
    "ollama_metadata",
    "ledger_identity",
    "codex_executable",
    "host_process_visibility",
    "evaluator",
    "python_runtime",
    "runtime_config_probe",
)


def generate_environment_instance_id() -> str:
    """Generate an opaque 128-bit correlation authority without host-derived data."""

    return secrets.token_hex(16)


def _model_hash(value: BaseModel) -> str:
    return digest(canonical(cast(JsonValue, value.model_dump(mode="json"))))


class PythonRuntimeExpectedV1(Contract):
    source_commit: GitCommit
    wheel_sha256: Digest
    dependency_lock_sha256: Digest
    python_implementation: Literal["CPython"] = "CPython"
    python_version: Annotated[str, Field(pattern=r"^3\.12(?:\.[0-9]+)?$")]
    python_executable_sha256: Digest
    runtime_environment_id: Digest
    distribution_name: Literal["codex-dev-hub"] = "codex-dev-hub"
    distribution_version: str = Field(min_length=1, max_length=64)
    entrypoint: Literal["devhub.delegate_server"] = "devhub.delegate_server"
    isolated_argv: tuple[Literal["-I"], Literal["-m"], Literal["devhub.delegate_server"]] = (
        "-I",
        "-m",
        "devhub.delegate_server",
    )


class ImplementationExpectedV1(Contract):
    devhub_commit: GitCommit
    python_runtime: PythonRuntimeExpectedV1

    @model_validator(mode="after")
    def same_source_commit(self) -> ImplementationExpectedV1:
        if self.devhub_commit != self.python_runtime.source_commit:
            raise ValueError("Runtime artifact source commit differs from DevFabric commit")
        return self


class CodexExpectedV1(Contract):
    source_commit: GitCommit
    source_archive_sha256: Digest
    executable_version: str = Field(min_length=1, max_length=128)
    executable_sha256: Digest
    candidate_b_base_patch_sha256: Digest
    host_integration_patch_sha256: Digest
    combined_patchset_sha256: Digest


class BenchmarkExpectedV1(Contract):
    protocol_sha256: Digest
    config_sha256: Digest
    plan_sha256: Digest
    session_bindings_sha256: Digest
    fixture_oracle_manifest_sha256: Digest


class RuntimeExpectedV1(Contract):
    image_id: ImageId
    image_metadata_sha256: Digest
    bootstrap_sha256: Digest
    approved_host_manifest_sha256: Digest


class LedgerExpectedV1(Contract):
    identity: LedgerIdentityCoreV1
    identity_sha256: Digest
    domain_schema_version: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def exact_identity_hash(self) -> LedgerExpectedV1:
        if ledger_identity_sha256(self.identity) != self.identity_sha256:
            raise ValueError("Ledger identity hash mismatch")
        return self


class EvaluatorExpectedV1(Contract):
    image_id: ImageId
    artifact_sha256: Digest
    runner_sha256: Digest


class OllamaExpectedV1(Contract):
    version: Literal["0.34.2"] = "0.34.2"
    model: Literal["qwen2.5:14b-instruct"] = "qwen2.5:14b-instruct"
    digest: Literal["7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6"] = (
        "7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6"
    )


class ArmExpectedV1(Contract):
    arm: Literal["A", "B"]
    tool_ceiling: tuple[str, ...]
    approved_delegate_policy_sha256: Digest | None

    @model_validator(mode="after")
    def exact_stage3g_surface(self) -> ArmExpectedV1:
        if self.arm == "A":
            if self.tool_ceiling or self.approved_delegate_policy_sha256 is not None:
                raise ValueError("Arm A must have an empty ceiling and no delegate policy")
        elif self.tool_ceiling != (STAGE3G_DELEGATE_TOOL,) or (
            self.approved_delegate_policy_sha256 is None
        ):
            raise ValueError("Arm B must bind exactly the reviewed delegate surface")
        return self


class ArmsExpectedV1(Contract):
    arm_a: ArmExpectedV1
    arm_b: ArmExpectedV1

    @model_validator(mode="after")
    def correctly_labeled(self) -> ArmsExpectedV1:
        if self.arm_a.arm != "A" or self.arm_b.arm != "B":
            raise ValueError("Arm expectations are mislabeled")
        return self


class QualificationContextPayloadV1(Contract):
    environment_instance_id: EnvironmentInstanceId
    implementation: ImplementationExpectedV1
    codex: CodexExpectedV1
    benchmark: BenchmarkExpectedV1
    runtime_expected: RuntimeExpectedV1
    ledger_expected: LedgerExpectedV1
    evaluator_expected: EvaluatorExpectedV1
    ollama_expected: OllamaExpectedV1
    arms_expected: ArmsExpectedV1


class QualificationContextV1(Contract):
    qualification_context_id: Digest
    payload: QualificationContextPayloadV1

    @classmethod
    def create(cls, payload: QualificationContextPayloadV1) -> QualificationContextV1:
        return cls(qualification_context_id=_model_hash(payload), payload=payload)

    @model_validator(mode="after")
    def canonical_id(self) -> QualificationContextV1:
        if self.qualification_context_id != _model_hash(self.payload):
            raise ValueError("Qualification context ID mismatch")
        return self


class QualificationReceiptHeaderV1(Contract):
    receipt_kind: ReceiptKind
    qualification_context_id: Digest
    environment_instance_id: EnvironmentInstanceId


class QualificationReceiptHeaderV2(ContractV2):
    """Header version used only by receipts with a reviewed V2 authority contract."""

    receipt_kind: ReceiptKind
    qualification_context_id: Digest
    environment_instance_id: EnvironmentInstanceId


class AuthEgressReceiptV1(QualificationReceiptHeaderV1):
    """Real-auth presence and the frozen scoped-egress policy, without secret material."""

    receipt_kind: Literal["auth_egress"] = "auth_egress"
    kind: Literal["intended_host_auth_egress"] = "intended_host_auth_egress"
    auth_source: Literal["existing_operator_codex_auth"]
    auth_regular_file: Literal[True]
    auth_json_object: Literal[True]
    auth_material_nonempty: Literal[True]
    auth_material_published: Literal[False]
    staged_copy_mode: Literal["0600"]
    staged_copy_matches_source: Literal[True]
    proxy_environment_inherited: Literal[False]
    allowed_connect_targets: tuple[str, ...]
    denied_connect_targets: tuple[str, ...]
    policy_checks_passed: Literal[True]
    model_requests: Literal[0]
    provider_sends: Literal[0]
    qualification_passed: Literal[True]

    @model_validator(mode="after")
    def exact_policy(self) -> AuthEgressReceiptV1:
        expected_allowed = ("api.openai.com:443", "chatgpt.com:443")
        expected_denied = (
            "10.0.0.1:443",
            "127.0.0.1:443",
            "169.254.169.254:443",
            "api.groq.com:443",
            "example.com:443",
            "generativelanguage.googleapis.com:443",
        )
        if self.allowed_connect_targets != expected_allowed:
            raise ValueError("Auth/egress receipt does not bind the exact Codex allowlist")
        if self.denied_connect_targets != expected_denied:
            raise ValueError("Auth/egress receipt does not bind the exact denied targets")
        return self


class LedgerIdentityReceiptV1(QualificationReceiptHeaderV1):
    """Read-only observation of the exact qualification-bound accounting authority."""

    receipt_kind: Literal["ledger_identity"] = "ledger_identity"
    kind: Literal["intended_host_ledger_identity"] = "intended_host_ledger_identity"
    ledger_identity_sha256: Digest
    domain_schema_version: Annotated[int, Field(ge=1)]
    sqlite_application_id: Literal[1145459276]
    identity_record_count: Literal[1]
    integrity_check: Literal["ok"]
    path_is_locator_only: Literal[True]
    reserved_count: Literal[0]
    dispatched_count: Literal[0]
    unknown_usage_count: Literal[0]
    qualification_passed: Literal[True]


class OllamaNetworkIsolationObservationV1(Contract):
    """Process-scoped Linux network namespace proof used by Ollama qualification."""

    kind: Literal["ollama_process_network_isolation"] = "ollama_process_network_isolation"
    executable_sha256: Digest
    network_namespace_id: Annotated[str, Field(pattern=r"^net:\[[0-9]+\]$")]
    separate_network_namespace: Literal[True]
    loopback_bind_available: Literal[True]
    non_loopback_route_count: Literal[0]
    outbound_probe_denied: Literal[True]
    proxy_environment_inherited: Literal[False]


class OllamaMetadataReceiptV1(QualificationReceiptHeaderV1):
    """Historical metadata-only receipt without a reachable transport binding."""

    receipt_kind: Literal["ollama_metadata"] = "ollama_metadata"
    kind: Literal["intended_host_ollama_metadata"] = "intended_host_ollama_metadata"
    version: Literal["0.34.2"]
    model: Literal["qwen2.5:14b-instruct"]
    digest: Literal["7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6"]
    endpoint: Literal["http://127.0.0.1:11434"]
    release_asset: Literal["ollama-linux-amd64.tar.zst"]
    release_artifact_sha256: Literal[
        "e155b83589986d2c581fdbf1381ea3ebdb16549883679cd5a0627f7cdc05b12b"
    ]
    executable_sha256: Digest
    server_executable_matches: Literal[True]
    network_isolation: OllamaNetworkIsolationObservationV1
    network_isolation_sha256: Digest
    model_metadata_sha256: Digest
    context_tokens: Annotated[int, Field(ge=8192)]
    completion_capability: Literal[True]
    remote_model: Literal[False]
    remote_host: Literal[False]
    metadata_endpoints: tuple[str, ...]
    generate_requests: Literal[0]
    proxy_environment_inherited: Literal[False]
    outbound_network_denied: Literal[True]
    model_requests: Literal[0]
    provider_sends: Literal[0]
    qualification_passed: Literal[True]

    @model_validator(mode="after")
    def metadata_only(self) -> OllamaMetadataReceiptV1:
        if self.metadata_endpoints != ("/api/show", "/api/tags", "/api/version"):
            raise ValueError("Ollama qualification must use the exact metadata-only endpoints")
        if self.network_isolation.executable_sha256 != self.executable_sha256:
            raise ValueError("Ollama network isolation belongs to another executable")
        expected_hash = digest(canonical(self.network_isolation.model_dump(mode="json")))
        if self.network_isolation_sha256 != expected_hash:
            raise ValueError("Ollama network isolation hash mismatch")
        return self


class OllamaMetadataReceiptV2(QualificationReceiptHeaderV2):
    """Current metadata proof bound to the exact reachable fixed bridge."""

    receipt_kind: Literal["ollama_metadata"] = "ollama_metadata"
    kind: Literal["intended_host_ollama_metadata_v2"] = "intended_host_ollama_metadata_v2"
    version: Literal["0.34.2"]
    model: Literal["qwen2.5:14b-instruct"]
    digest: Literal["7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6"]
    endpoint: Literal["http://127.0.0.1:11434"]
    release_asset: Literal["ollama-linux-amd64.tar.zst"]
    release_artifact_sha256: Literal[
        "e155b83589986d2c581fdbf1381ea3ebdb16549883679cd5a0627f7cdc05b12b"
    ]
    executable_sha256: Digest
    server_executable_matches: Literal[True]
    network_isolation: OllamaNetworkIsolationObservationV1
    network_isolation_sha256: Digest
    bridge: OllamaBridgeAuthorityV1
    model_metadata_sha256: Digest
    context_tokens: Annotated[int, Field(ge=8192)]
    completion_capability: Literal[True]
    remote_model: Literal[False]
    remote_host: Literal[False]
    metadata_endpoints: tuple[str, ...]
    generate_requests: Literal[0]
    proxy_environment_inherited: Literal[False]
    outbound_network_denied: Literal[True]
    model_requests: Literal[0]
    provider_sends: Literal[0]
    qualification_passed: Literal[True]

    @model_validator(mode="after")
    def metadata_and_bridge_match(self) -> OllamaMetadataReceiptV2:
        if self.metadata_endpoints != ("/api/show", "/api/tags", "/api/version"):
            raise ValueError("Ollama qualification must use the exact metadata-only endpoints")
        if self.network_isolation.executable_sha256 != self.executable_sha256:
            raise ValueError("Ollama network isolation belongs to another executable")
        expected_hash = digest(canonical(self.network_isolation.model_dump(mode="json")))
        if self.network_isolation_sha256 != expected_hash:
            raise ValueError("Ollama network isolation hash mismatch")
        if (
            self.bridge.server_executable_sha256 != self.executable_sha256
            or self.bridge.server_network_namespace_id
            != self.network_isolation.network_namespace_id
        ):
            raise ValueError("Ollama bridge belongs to another qualified server")
        return self


class ApprovedDelegateIdentityObservationV1(Contract):
    server_key: Literal["devhub_delegate"]
    raw_tool: Literal["devhub_delegate"]
    canonical_namespace: Literal["mcp__devhub_delegate"]
    canonical_function: Literal["devhub_delegate"]
    schema_sha256: Literal["0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"]
    generation_identity: Annotated[str, Field(pattern=r"^generation-[a-f0-9]{16}$")]


class RouterObservationV1(Contract):
    observer: Literal["read_only_pre_sampling_router_v1"]
    effective_tool_mode: Literal["CodeModeOnly"]
    allowed_tools_ceiling_present: bool
    allowed_tools: tuple[str, ...]
    approved_delegate_policy_present: bool
    approved_identity: ApprovedDelegateIdentityObservationV1 | None
    expected_schema_sha256: Digest | None
    host_manifest_sha256: Digest | None
    visible_model_tools: tuple[str, ...]
    nested_code_mode_map: tuple[str, ...]
    hosted_tools: tuple[str, ...]
    dynamic_tool_count: Annotated[int, Field(ge=0)]
    model_requests: Literal[0]
    provider_sends: Literal[0]
    real_codex_task_executions: Literal[0]


class CatalogObservationV1(Contract):
    event: Literal["tools_list"]
    schema_sha256: Literal["0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"]
    provider_send: Literal[False]


class CodexBuildArtifactObservationV1(Contract):
    workflow_run_id: Literal[38024891950]
    artifact_id: Literal[11659714382]
    artifact_name: Literal["stage3g-build020-production-host-proof"]
    artifact_zip_sha256: Literal["c03fbe7596a95c2b667348db879c205c83d5cd74b3f9e1d2b4d2d5ab79546979"]
    build_evidence_sha256: Digest


class CodexExecutableReceiptV1(QualificationReceiptHeaderV1):
    receipt_kind: Literal["codex_executable"] = "codex_executable"
    kind: Literal["retained_build020_executable"] = "retained_build020_executable"
    image_id: ImageId
    source_commit: GitCommit
    source_archive_sha256: Digest
    executable_sha256: Digest
    executable_version: str = Field(min_length=1, max_length=128)
    candidate_b_base_patch_sha256: Digest
    host_integration_patch_sha256: Digest
    combined_patchset_sha256: Digest
    source_artifact: CodexBuildArtifactObservationV1
    real_codex_task_executions: Literal[0]
    model_requests: Literal[0]
    provider_sends: Literal[0]
    qualification_passed: Literal[True]


class HostProcessVisibilityReceiptV1(QualificationReceiptHeaderV1):
    receipt_kind: Literal["host_process_visibility"] = "host_process_visibility"
    kind: Literal["actual_codex_exec_pre_sampling_router_visibility"]
    image_id: ImageId
    executable_sha256: Digest
    executable_version: str = Field(min_length=1, max_length=128)
    approved_host_manifest_sha256: Digest
    default_observation: RouterObservationV1
    arm_a_observation: RouterObservationV1
    arm_b_observation: RouterObservationV1
    b_minus_a: tuple[Literal["mcp__devhub_delegate.devhub_delegate"], ...]
    a_minus_b: tuple[()]
    catalog_records: tuple[CatalogObservationV1, ...]
    catalog_tools_list_count: Literal[1]
    mcp_tool_call_count: Literal[0]
    stopped_before_sampling: Literal[True]
    model_requests: Literal[0]
    provider_sends: Literal[0]
    real_codex_task_executions: Literal[0]
    qualification_passed: Literal[True]

    @model_validator(mode="after")
    def exact_surfaces(self) -> HostProcessVisibilityReceiptV1:
        default = self.default_observation
        default_surface_values = (
            *default.allowed_tools,
            *default.visible_model_tools,
            *default.nested_code_mode_map,
            *default.hosted_tools,
        )
        if (
            default.allowed_tools_ceiling_present
            or default.approved_delegate_policy_present
            or default.approved_identity is not None
            or default.expected_schema_sha256 is not None
            or default.host_manifest_sha256 is not None
            or any(
                STAGE3G_DELEGATE_TOOL in value or "mcp__devhub_delegate" in value
                for value in default_surface_values
            )
            or default.dynamic_tool_count
        ):
            raise ValueError("Default Codex observation contains Stage 3G delegate leakage")
        arm_a = self.arm_a_observation
        if (
            not arm_a.allowed_tools_ceiling_present
            or arm_a.allowed_tools
            or arm_a.approved_delegate_policy_present
            or arm_a.approved_identity is not None
            or arm_a.expected_schema_sha256 is not None
            or arm_a.host_manifest_sha256 != self.approved_host_manifest_sha256
            or arm_a.visible_model_tools
            or arm_a.nested_code_mode_map
            or arm_a.hosted_tools
            or arm_a.dynamic_tool_count
        ):
            raise ValueError("Arm A finalized router surface is not empty")
        arm_b = self.arm_b_observation
        if (
            not arm_b.allowed_tools_ceiling_present
            or arm_b.allowed_tools != (STAGE3G_DELEGATE_TOOL,)
            or not arm_b.approved_delegate_policy_present
            or arm_b.approved_identity is None
            or arm_b.expected_schema_sha256 != DELEGATE_SCHEMA_SHA256
            or arm_b.host_manifest_sha256 != self.approved_host_manifest_sha256
            or arm_b.visible_model_tools != (STAGE3G_DELEGATE_TOOL,)
            or arm_b.nested_code_mode_map
            or arm_b.hosted_tools
            or arm_b.dynamic_tool_count
        ):
            raise ValueError("Arm B finalized router surface is not the exact delegate")
        if self.b_minus_a != (STAGE3G_DELEGATE_TOOL,) or self.a_minus_b:
            raise ValueError("Stage 3G A/B surface difference is not exact")
        if len(self.catalog_records) != 1:
            raise ValueError("Arm B must observe exactly one catalog listing")
        return self


class RequiredFeatureStatesV1(Contract):
    shell_tool: Literal["true", "false"] | None
    apps: Literal["true", "false"] | None
    multi_agent: Literal["true", "false"] | None
    goals: Literal["true", "false"] | None
    hooks: Literal["true", "false"] | None
    memories: Literal["true", "false"] | None
    remote_plugin: Literal["true", "false"] | None
    shell_snapshot: Literal["true", "false"] | None


class RuntimeArmConfigObservationV1(Contract):
    arm: Literal["A", "B"]
    features_exit_code: int
    mcp_list_exit_code: int
    mcp_scope_matches: bool
    required_feature_states: RequiredFeatureStatesV1
    config_error: str | None = Field(default=None, max_length=256)


class RuntimeConfigChecksV1(Contract):
    auth_tmpfs: bool
    cli_config: bool
    egress_runtime: bool


class RuntimeConfigProbeReceiptV1(QualificationReceiptHeaderV1):
    receipt_kind: Literal["runtime_config_probe"] = "runtime_config_probe"
    kind: Literal["runtime_config_probe"] = "runtime_config_probe"
    image_id: ImageId
    protocol_sha256: Digest
    host_process_visibility_sha256: Digest
    checks: RuntimeConfigChecksV1
    arms: tuple[RuntimeArmConfigObservationV1, RuntimeArmConfigObservationV1]
    auth_material: Literal["synthetic only; real auth presence is a separate preflight gate"]
    real_codex_executions: Literal[0]
    model_requests: Literal[0]
    provider_sends: Literal[0]
    qualification_passed: bool

    @model_validator(mode="after")
    def exact_arms(self) -> RuntimeConfigProbeReceiptV1:
        if tuple(arm.arm for arm in self.arms) != ("A", "B"):
            raise ValueError("Runtime config receipt must contain exact A/B observations")
        passed = all((self.checks.auth_tmpfs, self.checks.cli_config, self.checks.egress_runtime))
        if self.qualification_passed is not passed:
            raise ValueError("Runtime config qualification result differs from checks")
        if passed:
            for arm in self.arms:
                if (
                    arm.features_exit_code != 0
                    or arm.mcp_list_exit_code != 0
                    or not arm.mcp_scope_matches
                    or arm.config_error is not None
                    or any(
                        value != "false"
                        for name, value in arm.required_feature_states.model_dump().items()
                        if name != "schema_version"
                    )
                ):
                    raise ValueError("Passing runtime config receipt contains failed diagnostics")
        return self


class ArtifactReferenceV1(Contract):
    relative_path: str = Field(min_length=1, max_length=512)
    sha256: Digest

    @field_validator("relative_path")
    @classmethod
    def safe_relative_locator(cls, value: str) -> str:
        if "\\" in value:
            raise ValueError("Artifact locator must use canonical POSIX separators")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("Artifact locator must remain beneath the manifest root")
        return value


class ReceiptReferenceV1(ArtifactReferenceV1):
    receipt_kind: ReceiptKind


class QualificationReceiptSetV2(Contract):
    isolation: ReceiptReferenceV1 | None = None
    effects_boundary: ReceiptReferenceV1 | None = None
    auth_egress: ReceiptReferenceV1 | None = None
    ollama_metadata: ReceiptReferenceV1 | None = None
    ledger_identity: ReceiptReferenceV1 | None = None
    codex_executable: ReceiptReferenceV1 | None = None
    host_process_visibility: ReceiptReferenceV1 | None = None
    evaluator: ReceiptReferenceV1 | None = None
    python_runtime: ReceiptReferenceV1 | None = None
    runtime_config_probe: ReceiptReferenceV1 | None = None

    @model_validator(mode="after")
    def kinds_match_fields(self) -> QualificationReceiptSetV2:
        seen_paths: set[str] = set()
        for kind in RECEIPT_KINDS:
            item = getattr(self, kind)
            if item is None:
                continue
            if item.receipt_kind != kind:
                raise ValueError(f"Receipt kind mismatch for {kind}")
            if item.relative_path in seen_paths:
                raise ValueError("Duplicate receipt locator")
            seen_paths.add(item.relative_path)
        return self

    def complete(self) -> bool:
        return all(getattr(self, kind) is not None for kind in RECEIPT_KINDS)


class ObservedArtifactHashesV2(Contract):
    qualification_context_sha256: Digest
    devhub_wheel_sha256: Digest
    dependency_lock_sha256: Digest
    python_executable_sha256: Digest
    python_runtime_environment_id: Digest
    codex_executable_sha256: Digest
    runtime_image_metadata_sha256: Digest
    evaluator_artifact_sha256: Digest
    ledger_identity_sha256: Digest
    ollama_model_digest: Digest


class QualificationGatesV2(Contract):
    context_integrity: bool = False
    artifact_integrity: bool = False
    same_environment: bool = False
    isolation: bool = False
    effects_boundary: bool = False
    auth_egress: bool = False
    ollama_metadata: bool = False
    ledger_identity: bool = False
    codex_executable: bool = False
    host_process_visibility: bool = False
    evaluator: bool = False
    python_runtime: bool = False
    runtime_config_probe: bool = False

    def all_passed(self) -> bool:
        return all(value for name, value in self.model_dump().items() if name != "schema_version")


class QualificationManifestPayloadV2(ContractV2):
    qualification_context_id: Digest
    environment_instance_id: EnvironmentInstanceId
    context: ArtifactReferenceV1
    receipts: QualificationReceiptSetV2
    observed_artifacts: ObservedArtifactHashesV2
    gates: QualificationGatesV2
    execution_ready: bool

    @classmethod
    def create(
        cls,
        *,
        qualification_context_id: str,
        environment_instance_id: str,
        context: ArtifactReferenceV1,
        receipts: QualificationReceiptSetV2,
        observed_artifacts: ObservedArtifactHashesV2,
        gates: QualificationGatesV2,
    ) -> QualificationManifestPayloadV2:
        return cls(
            qualification_context_id=qualification_context_id,
            environment_instance_id=environment_instance_id,
            context=context,
            receipts=receipts,
            observed_artifacts=observed_artifacts,
            gates=gates,
            execution_ready=receipts.complete() and gates.all_passed(),
        )

    @model_validator(mode="after")
    def readiness_is_derived(self) -> QualificationManifestPayloadV2:
        derived = self.receipts.complete() and self.gates.all_passed()
        if self.execution_ready is not derived:
            raise ValueError("execution_ready differs from required receipts/gates")
        return self


class QualificationManifestV2(ContractV2):
    qualification_manifest_id: Digest
    payload: QualificationManifestPayloadV2

    @classmethod
    def create(cls, payload: QualificationManifestPayloadV2) -> QualificationManifestV2:
        return cls(qualification_manifest_id=_model_hash(payload), payload=payload)

    @model_validator(mode="after")
    def canonical_id(self) -> QualificationManifestV2:
        if self.qualification_manifest_id != _model_hash(self.payload):
            raise ValueError("Qualification manifest ID mismatch")
        return self


class RuntimeBindings(Contract):
    """New execution binding: one final manifest identity, no component authorities."""

    qualification_manifest_id: Digest


class HistoricalRuntimeBindingsV1(Contract):
    """Read-only parser for historical evidence; never accepted by the new execution gate."""

    image_id: ImageId
    bootstrap_sha256: Digest
    environment: dict[str, JsonValue]
    isolation_probe_sha256: Digest
    protocol_sha256: Digest
    reviewed_plan_sha256: Digest
    boundary_reviewed: Literal[True]
    qualification_sha256: Digest | None = None


class VerifiedQualificationV2:
    """In-memory result returned only after the entire manifest chain is re-read."""

    def __init__(
        self,
        manifest: QualificationManifestV2,
        context: QualificationContextV1,
        receipts: dict[ReceiptKind, dict[str, JsonValue]],
    ) -> None:
        self.manifest = manifest
        self.context = context
        self.receipts = receipts

    @property
    def image_id(self) -> str:
        return self.context.payload.runtime_expected.image_id

    @property
    def bootstrap_sha256(self) -> str:
        return self.context.payload.runtime_expected.bootstrap_sha256

    @property
    def protocol_sha256(self) -> str:
        return self.context.payload.benchmark.protocol_sha256

    @property
    def reviewed_plan_sha256(self) -> str:
        return self.context.payload.benchmark.plan_sha256

    @property
    def codex_cli_version(self) -> str:
        return self.context.payload.codex.executable_version


def _safe_read(root: Path, reference: ArtifactReferenceV1) -> bytes:
    root = root.resolve(strict=True)
    path = root.joinpath(*PurePosixPath(reference.relative_path).parts)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Referenced qualification artifact is not a regular file")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("Referenced qualification artifact escapes manifest root")
    raw = resolved.read_bytes()
    if digest(raw) != reference.sha256:
        raise ValueError("Referenced qualification artifact hash mismatch")
    return raw


def _receipt_header(
    data: dict[str, JsonValue],
) -> QualificationReceiptHeaderV1 | QualificationReceiptHeaderV2:
    keys = (
        "schema_version",
        "receipt_kind",
        "qualification_context_id",
        "environment_instance_id",
    )
    try:
        selected = {key: data[key] for key in keys}
    except KeyError as error:
        raise ValueError("Qualification receipt header is incomplete") from error
    if selected["schema_version"] == 2:
        return QualificationReceiptHeaderV2.model_validate(selected)
    return QualificationReceiptHeaderV1.model_validate(selected)


def _expected_artifacts(context: QualificationContextV1) -> dict[str, str]:
    payload = context.payload
    runtime = payload.implementation.python_runtime
    return {
        "devhub_wheel_sha256": runtime.wheel_sha256,
        "dependency_lock_sha256": runtime.dependency_lock_sha256,
        "python_executable_sha256": runtime.python_executable_sha256,
        "python_runtime_environment_id": runtime.runtime_environment_id,
        "codex_executable_sha256": payload.codex.executable_sha256,
        "runtime_image_metadata_sha256": payload.runtime_expected.image_metadata_sha256,
        "evaluator_artifact_sha256": payload.evaluator_expected.artifact_sha256,
        "ledger_identity_sha256": payload.ledger_expected.identity_sha256,
        "ollama_model_digest": payload.ollama_expected.digest,
    }


def _validate_receipt_observation(
    kind: ReceiptKind, data: dict[str, JsonValue], context: QualificationContextV1
) -> None:
    """Bind receipt claims to context authority before any execution can be exposed."""

    expected = context.payload
    common: dict[ReceiptKind, dict[str, JsonValue]] = {
        "isolation": {
            "image_id": expected.runtime_expected.image_id,
            "bootstrap_sha256": expected.runtime_expected.bootstrap_sha256,
        },
        "effects_boundary": {
            "image_id": expected.runtime_expected.image_id,
            "bootstrap_sha256": expected.runtime_expected.bootstrap_sha256,
        },
        "auth_egress": {},
        "ollama_metadata": {
            "version": expected.ollama_expected.version,
            "model": expected.ollama_expected.model,
            "digest": expected.ollama_expected.digest,
        },
        "ledger_identity": {
            "ledger_identity_sha256": expected.ledger_expected.identity_sha256,
            "domain_schema_version": expected.ledger_expected.domain_schema_version,
        },
        "codex_executable": {
            "source_commit": expected.codex.source_commit,
            "source_archive_sha256": expected.codex.source_archive_sha256,
            "executable_sha256": expected.codex.executable_sha256,
            "executable_version": expected.codex.executable_version,
            "candidate_b_base_patch_sha256": expected.codex.candidate_b_base_patch_sha256,
            "host_integration_patch_sha256": expected.codex.host_integration_patch_sha256,
            "combined_patchset_sha256": expected.codex.combined_patchset_sha256,
            "image_id": expected.runtime_expected.image_id,
        },
        "host_process_visibility": {
            "approved_host_manifest_sha256": (
                expected.runtime_expected.approved_host_manifest_sha256
            ),
            "image_id": expected.runtime_expected.image_id,
            "executable_sha256": expected.codex.executable_sha256,
            "executable_version": expected.codex.executable_version,
        },
        "evaluator": {
            "artifact_sha256": expected.evaluator_expected.artifact_sha256,
            "runner_sha256": expected.evaluator_expected.runner_sha256,
        },
        "python_runtime": {
            "interpreter_sha256": (expected.implementation.python_runtime.python_executable_sha256),
            "wheel_sha256": expected.implementation.python_runtime.wheel_sha256,
            "dependency_lock_sha256": (
                expected.implementation.python_runtime.dependency_lock_sha256
            ),
            "runtime_environment_id": (
                expected.implementation.python_runtime.runtime_environment_id
            ),
        },
        "runtime_config_probe": {
            "image_id": expected.runtime_expected.image_id,
            "protocol_sha256": expected.benchmark.protocol_sha256,
        },
    }
    if any(data.get(key) != value for key, value in common[kind].items()):
        raise ValueError(f"{kind} receipt artifact identity differs from context")
    if kind == "auth_egress":
        AuthEgressReceiptV1.model_validate_json(canonical(data))
    elif kind == "ollama_metadata":
        if data.get("schema_version") != 2:
            # Historical V1 remains strictly parseable for audit, but it lacks a
            # qualified transport and cannot authorize current execution.
            OllamaMetadataReceiptV1.model_validate_json(canonical(data))
            raise ValueError("Historical Ollama metadata V1 is non-authorizing")
        observation = OllamaMetadataReceiptV2.model_validate_json(canonical(data))
        runtime = expected.implementation.python_runtime
        if (
            observation.bridge.bridge_python_executable_sha256 != runtime.python_executable_sha256
            or observation.bridge.bridge_runtime_environment_id != runtime.runtime_environment_id
        ):
            raise ValueError("Ollama bridge differs from the immutable Python runtime")
    elif kind == "ledger_identity":
        LedgerIdentityReceiptV1.model_validate_json(canonical(data))
    elif kind == "codex_executable":
        CodexExecutableReceiptV1.model_validate_json(canonical(data))
    elif kind == "host_process_visibility":
        HostProcessVisibilityReceiptV1.model_validate_json(canonical(data))
    elif kind == "runtime_config_probe":
        RuntimeConfigProbeReceiptV1.model_validate_json(canonical(data))


def verify_manifest_tree(
    manifest_path: Path, expected_manifest_id: str, *, require_execution_ready: bool = True
) -> VerifiedQualificationV2:
    """Re-read and verify a final manifest, context, and fixed receipt set.

    The caller supplies only the expected final ID and a locator. Component paths and
    hashes cannot independently authorize execution.
    """

    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("Qualification manifest must be a regular file")
    manifest = QualificationManifestV2.model_validate_json(manifest_path.read_bytes())
    if manifest.qualification_manifest_id != expected_manifest_id:
        raise ValueError("Runtime binding does not match qualification manifest")
    root = manifest_path.parent
    context_raw = _safe_read(root, manifest.payload.context)
    context = QualificationContextV1.model_validate_json(context_raw)
    if context.qualification_context_id != manifest.payload.qualification_context_id:
        raise ValueError("Qualification manifest references a different context")
    if context.payload.environment_instance_id != manifest.payload.environment_instance_id:
        raise ValueError("Qualification manifest mixes environment instances")
    if digest(context_raw) != manifest.payload.observed_artifacts.qualification_context_sha256:
        raise ValueError("Qualification context artifact binding mismatch")
    expected = _expected_artifacts(context)
    observed = manifest.payload.observed_artifacts.model_dump(mode="json")
    if any(observed[name] != value for name, value in expected.items()):
        raise ValueError("Qualification observed artifact differs from context")

    receipts: dict[ReceiptKind, dict[str, JsonValue]] = {}
    for kind in RECEIPT_KINDS:
        reference = getattr(manifest.payload.receipts, kind)
        if reference is None:
            continue
        raw = _safe_read(root, reference)
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            raise ValueError("Qualification receipt must be an object")
        data = cast(dict[str, JsonValue], loaded)
        header = _receipt_header(data)
        if (
            header.receipt_kind != kind
            or header.qualification_context_id != context.qualification_context_id
            or header.environment_instance_id != context.payload.environment_instance_id
        ):
            raise ValueError("Qualification receipt belongs to another context/environment")
        gate = getattr(manifest.payload.gates, kind)
        if gate and data.get("qualification_passed") is not True:
            raise ValueError("Qualification gate is true without a passing receipt")
        _validate_receipt_observation(kind, data, context)
        if kind == "runtime_config_probe":
            host_reference = manifest.payload.receipts.host_process_visibility
            if (
                host_reference is None
                or data.get("host_process_visibility_sha256") != host_reference.sha256
            ):
                raise ValueError("Runtime config receipt is not bound to host visibility")
        receipts[kind] = data

    if "ollama_metadata" in receipts and "python_runtime" in receipts:
        # Import locally to keep the runtime artifact module's dependency on the
        # qualification contracts acyclic.
        from devhub.runtime_artifact import PythonRuntimeReceiptV1

        ollama = OllamaMetadataReceiptV2.model_validate_json(canonical(receipts["ollama_metadata"]))
        python = PythonRuntimeReceiptV1.model_validate_json(canonical(receipts["python_runtime"]))
        if (
            ollama.bridge.bridge_python_path != python.interpreter_path
            or ollama.bridge.bridge_python_executable_sha256 != python.interpreter_sha256
            or ollama.bridge.bridge_process_executable_sha256 != python.interpreter_sha256
            or ollama.bridge.bridge_runtime_environment_id != python.runtime_environment_id
        ):
            raise ValueError("Ollama bridge is not the exact qualified Python runtime")

    if require_execution_ready and not manifest.payload.execution_ready:
        raise ValueError("Stage 3G-C execution_ready is false")
    if require_execution_ready and len(receipts) != len(RECEIPT_KINDS):
        raise ValueError("Qualification receipt set is incomplete")
    return VerifiedQualificationV2(manifest, context, receipts)


def receipt_header(context: QualificationContextV1, kind: ReceiptKind) -> dict[str, JsonValue]:
    """Return the shared flattened header for a context-bound receipt."""

    return cast(
        dict[str, JsonValue],
        QualificationReceiptHeaderV1(
            receipt_kind=kind,
            qualification_context_id=context.qualification_context_id,
            environment_instance_id=context.payload.environment_instance_id,
        ).model_dump(mode="json"),
    )


def receipt_header_v2(context: QualificationContextV1, kind: ReceiptKind) -> dict[str, JsonValue]:
    """Return a V2 flattened header for a receipt with a V2 authority contract."""

    return cast(
        dict[str, JsonValue],
        QualificationReceiptHeaderV2(
            receipt_kind=kind,
            qualification_context_id=context.qualification_context_id,
            environment_instance_id=context.payload.environment_instance_id,
        ).model_dump(mode="json"),
    )


def load_context(path: Path) -> QualificationContextV1:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Qualification context must be a regular file")
    return QualificationContextV1.model_validate_json(path.read_bytes())


def canonical_context(context: QualificationContextV1) -> bytes:
    return canonical(cast(JsonValue, context.model_dump(mode="json")))


def canonical_manifest(manifest: QualificationManifestV2) -> bytes:
    return canonical(cast(JsonValue, manifest.model_dump(mode="json")))
