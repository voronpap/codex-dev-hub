"""Strict authority contracts for the native Linux Codex build pair.

This module records build and pre-sampling evidence only.  It does not qualify
the future Linux runtime bundle, native executor isolation, or execution
readiness.
"""

from __future__ import annotations

from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.models import Contract
from devhub.qualification import GitCommit

LinuxBinaryRole = Literal["codex", "codex-code-mode-host"]


class LinuxElfIdentityV1(Contract):
    elf_class: Literal["ELF64"] = "ELF64"
    endianness: Literal["little"] = "little"
    machine: Literal["x86_64"] = "x86_64"
    interpreter: str = Field(min_length=1, max_length=256, pattern=r"^/[^\x00\r\n]+$")
    needed: tuple[str, ...] = Field(min_length=1, max_length=64)
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    required_symbol_versions: tuple[str, ...] = Field(max_length=256)

    @model_validator(mode="after")
    def canonical_dynamic_identity(self) -> LinuxElfIdentityV1:
        for label, values in (
            ("needed", self.needed),
            ("rpath", self.rpath),
            ("runpath", self.runpath),
            ("required_symbol_versions", self.required_symbol_versions),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"ELF {label} identity must be sorted and unique")
        if self.rpath or self.runpath:
            raise ValueError("Native Linux executables must not embed RPATH or RUNPATH")
        return self


class LinuxNativeBinaryV1(Contract):
    role: LinuxBinaryRole
    relative_path: Literal["binary/codex", "binary/codex-code-mode-host"]
    sha256: Digest
    size: Annotated[int, Field(ge=1)]
    elf: LinuxElfIdentityV1
    identity_output_sha256: Digest

    @model_validator(mode="after")
    def matching_role_path(self) -> LinuxNativeBinaryV1:
        if self.relative_path != f"binary/{self.role}":
            raise ValueError("Linux binary role and path differ")
        return self


class LinuxBuildProvenanceV1(Contract):
    repository: Literal["voronpap/codex-dev-hub"] = "voronpap/codex-dev-hub"
    build_id: Literal["linux-build-001"] = "linux-build-001"
    implementation_commit: GitCommit
    codex_source_commit: GitCommit
    source_archive_sha256: Digest
    candidate_b_base_patch_sha256: Digest
    host_integration_patch_sha256: Digest
    combined_patchset_sha256: Digest
    canonical_schema_sha256: Digest
    raw_schema_file_sha256: Digest
    host_manifest_sha256: Digest
    resolved_mcp_config_sha256: Digest
    original_cargo_lock_sha256: Digest
    derived_cargo_lock_sha256: Digest
    target: Literal["x86_64-unknown-linux-gnu"] = "x86_64-unknown-linux-gnu"
    rustc_version: str = Field(min_length=1, max_length=4096)
    cargo_version: str = Field(min_length=1, max_length=4096)
    rustc_sha256: Digest
    cargo_sha256: Digest
    build_script_sha256: Digest
    shared_proof_script_sha256: Digest
    workflow_sha256: Digest


class LinuxHostProofSummaryV1(Contract):
    process_proof_sha256: Digest
    code_mode_host_sha256: Digest
    code_mode_host_relative_path: Literal["binary/codex-code-mode-host"] = (
        "binary/codex-code-mode-host"
    )
    code_mode_host_eof_receipt_sha256: Digest
    code_mode_host_eof_exit_code: Literal[0] = 0
    code_mode_host_eof_timed_out: Literal[False] = False
    default_visible_tools: tuple[()] = ()
    arm_a_visible_tools: tuple[()] = ()
    arm_b_visible_tools: tuple[Literal["mcp__devhub_delegate.devhub_delegate"]] = (
        "mcp__devhub_delegate.devhub_delegate",
    )
    b_minus_a: tuple[Literal["mcp__devhub_delegate.devhub_delegate"]] = (
        "mcp__devhub_delegate.devhub_delegate",
    )
    a_minus_b: tuple[()] = ()
    default_allowed_tools_ceiling_present: Literal[False] = False
    arm_a_allowed_tools_ceiling_present: Literal[True] = True
    arm_b_allowed_tools_ceiling_present: Literal[True] = True
    approved_delegate_policy_arm_a: Literal[False] = False
    approved_delegate_policy_arm_b: Literal[True] = True
    code_mode_host_missing_error_observed: Literal[False] = False
    code_mode_host_stdio_eof_passed: Literal[True] = True
    mcp_child_cleanup_passed: Literal[True] = True
    security_negatives_passed: Literal[True] = True
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0


class LinuxNativeCodexBuildPayloadV1(Contract):
    provenance: LinuxBuildProvenanceV1
    binaries: tuple[LinuxNativeBinaryV1, LinuxNativeBinaryV1]
    process_proof: LinuxHostProofSummaryV1
    compilation: Literal["PASS"] = "PASS"
    qualification: Literal["LINUX_NATIVE_CODEX_AUTHORITY_PRE_SAMPLING"] = (
        "LINUX_NATIVE_CODEX_AUTHORITY_PRE_SAMPLING"
    )
    native_bundle_qualified: Literal[False] = False
    native_executor_isolation_qualified: Literal[False] = False
    execution_ready: Literal[False] = False

    @field_validator("binaries")
    @classmethod
    def exact_binary_pair(
        cls, value: tuple[LinuxNativeBinaryV1, LinuxNativeBinaryV1]
    ) -> tuple[LinuxNativeBinaryV1, LinuxNativeBinaryV1]:
        if tuple(item.role for item in value) != ("codex", "codex-code-mode-host"):
            raise ValueError("Linux build must bind the ordered Codex/code-mode-host pair")
        if value[0].sha256 == value[1].sha256:
            raise ValueError("Linux build binaries must have distinct identities")
        return value

    @model_validator(mode="after")
    def proof_uses_exact_sibling_host(self) -> LinuxNativeCodexBuildPayloadV1:
        host = self.binaries[1]
        if (
            self.process_proof.code_mode_host_sha256 != host.sha256
            or self.process_proof.code_mode_host_relative_path != host.relative_path
        ):
            raise ValueError("Linux process proof does not bind the exact sibling code-mode host")
        return self


class LinuxNativeCodexBuildV1(Contract):
    linux_native_codex_build_id: Digest
    payload: LinuxNativeCodexBuildPayloadV1

    @classmethod
    def create(cls, payload: LinuxNativeCodexBuildPayloadV1) -> LinuxNativeCodexBuildV1:
        return cls(
            linux_native_codex_build_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeCodexBuildV1:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_codex_build_id != expected:
            raise ValueError("Linux native Codex build ID mismatch")
        return self
