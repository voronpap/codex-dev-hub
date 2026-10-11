"""Strict authority contracts for the native Windows Codex executable pair.

The contracts qualify immutable build and pre-sampling host evidence only. They
do not qualify the Windows native bundle, executor isolation, or execution
readiness.
"""

from __future__ import annotations

from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.models import Contract
from devhub.native_proof import ORDINARY_DEFAULT_VISIBLE_TOOLS_V1, OrdinaryDefaultVisibleToolsV1
from devhub.qualification import GitCommit

WindowsBinaryRole = Literal["codex", "codex-code-mode-host"]
WindowsBuildId = Literal[
    "windows-build-002",
    "windows-build-003",
    "windows-build-004",
    "windows-build-005",
    "windows-build-006",
    "windows-build-007",
    "windows-build-008",
]


class WindowsPeIdentityV1(Contract):
    image_format: Literal["PE32+"] = "PE32+"
    machine: Literal["x86_64"] = "x86_64"
    machine_code: Literal[34404] = 34404  # IMAGE_FILE_MACHINE_AMD64 / 0x8664
    subsystem: Literal["console"] = "console"
    subsystem_code: Literal[3] = 3  # IMAGE_SUBSYSTEM_WINDOWS_CUI
    dll_characteristics: Annotated[int, Field(ge=0, le=65535)]


class WindowsNativeBinaryV2(Contract):
    role: WindowsBinaryRole
    relative_path: Literal["binary/codex.exe", "binary/codex-code-mode-host.exe"]
    sha256: Digest
    size: Annotated[int, Field(ge=1)]
    pe: WindowsPeIdentityV1

    @model_validator(mode="after")
    def matching_role_path(self) -> WindowsNativeBinaryV2:
        if self.relative_path != f"binary/{self.role}.exe":
            raise ValueError("Windows binary role and path differ")
        return self


class WindowsBuildProvenanceV2(Contract):
    repository: Literal["voronpap/codex-dev-hub"] = "voronpap/codex-dev-hub"
    build_id: Literal["windows-build-002", "windows-build-003"] = "windows-build-002"
    workflow_run_id: Annotated[int, Field(ge=1)]
    workflow_run_attempt: Annotated[int, Field(ge=1)]
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
    target: Literal["x86_64-pc-windows-msvc"] = "x86_64-pc-windows-msvc"
    rustc_version: str = Field(min_length=1, max_length=4096)
    cargo_version: str = Field(min_length=1, max_length=4096)
    rustc_sha256: Digest
    cargo_sha256: Digest
    build_script_sha256: Digest
    shared_proof_script_sha256: Digest
    workflow_sha256: Digest


class WindowsBuildProvenanceV3(Contract):
    repository: Literal["voronpap/codex-dev-hub"] = "voronpap/codex-dev-hub"
    build_id: Literal["windows-build-004"] = "windows-build-004"
    workflow_run_id: Annotated[int, Field(ge=1)]
    workflow_run_attempt: Annotated[int, Field(ge=1)]
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
    target: Literal["x86_64-pc-windows-msvc"] = "x86_64-pc-windows-msvc"
    rustc_version: str = Field(min_length=1, max_length=4096)
    cargo_version: str = Field(min_length=1, max_length=4096)
    rustc_sha256: Digest
    cargo_sha256: Digest
    build_script_sha256: Digest
    shared_proof_script_sha256: Digest
    workflow_sha256: Digest
    v8_crate_version: Literal["150.4.0"] = "150.4.0"
    v8_build_mode: Literal["official_openai_sandbox_release"] = "official_openai_sandbox_release"
    v8_release_tag: Literal["rusty-v8-v150.4.0"] = "rusty-v8-v150.4.0"
    codex_module_bazel_sha256: Literal[
        "1a6c8685d241a5390ff94432581e842c2950cbe5262b47b27d8db467cebec4c2"
    ]
    v8_sandbox_feature_enabled: Literal[True] = True
    v8_archive_url: Literal[
        "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"
        "rusty_v8_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.lib.gz"
    ]
    v8_archive_sha256: Literal["732ec5da4243aa166799780c8519a5eea6f32f6e47657a323342794dc3c239d6"]
    v8_binding_url: Literal[
        "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"
        "src_binding_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.rs"
    ]
    v8_binding_sha256: Literal["dabf78ba1faac127660db9862b1d0354175c71b8db2d4fcb5bacbd9c93576b16"]
    v8_checksum_url: Literal[
        "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"
        "rusty_v8_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.sha256"
    ]
    v8_checksum_sha256: Literal["a4d6221dddb4b5724b23411eaac47caf6095489fbf9d126f65b33cef96a0a8ef"]
    v8_archive_post_build_sha256: Literal[
        "732ec5da4243aa166799780c8519a5eea6f32f6e47657a323342794dc3c239d6"
    ]
    v8_binding_post_build_sha256: Literal[
        "dabf78ba1faac127660db9862b1d0354175c71b8db2d4fcb5bacbd9c93576b16"
    ]
    v8_checksum_post_build_sha256: Literal[
        "a4d6221dddb4b5724b23411eaac47caf6095489fbf9d126f65b33cef96a0a8ef"
    ]


class WindowsBuildProvenanceV4(WindowsBuildProvenanceV3):
    """Forward build identity for the corrected ordinary Default observation."""

    build_id: Literal["windows-build-005"] = "windows-build-005"  # type: ignore[assignment]


class WindowsBuildProvenanceV5(WindowsBuildProvenanceV3):
    """Forward build identity for complete inventory-bound artifact retention."""

    build_id: Literal["windows-build-006"] = "windows-build-006"  # type: ignore[assignment]


class WindowsBuildProvenanceV6(WindowsBuildProvenanceV3):
    """Forward build identity for the current merged bundle implementation."""

    build_id: Literal["windows-build-007"] = "windows-build-007"  # type: ignore[assignment]


class WindowsBuildProvenanceV7(WindowsBuildProvenanceV3):
    """Forward build identity for the current merged native implementation."""

    build_id: Literal["windows-build-008"] = "windows-build-008"  # type: ignore[assignment]


class WindowsHostProofSummaryV2(Contract):
    process_proof_sha256: Digest
    code_mode_host_sha256: Digest
    code_mode_host_relative_path: Literal["binary/codex-code-mode-host.exe"] = (
        "binary/codex-code-mode-host.exe"
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


class WindowsHostProofSummaryV3(WindowsHostProofSummaryV2):
    """Forward proof binds the observed ordinary Default catalog exactly."""

    default_visible_tools: OrdinaryDefaultVisibleToolsV1 = ORDINARY_DEFAULT_VISIBLE_TOOLS_V1  # type: ignore[assignment]


class WindowsNativeCodexBuildPayloadV2(Contract):
    provenance: WindowsBuildProvenanceV2
    binaries: tuple[WindowsNativeBinaryV2, WindowsNativeBinaryV2]
    process_proof: WindowsHostProofSummaryV2
    compilation: Literal["PASS"] = "PASS"
    qualification: Literal["WINDOWS_NATIVE_CODEX_PAIR_AUTHORITY_PRE_SAMPLING"] = (
        "WINDOWS_NATIVE_CODEX_PAIR_AUTHORITY_PRE_SAMPLING"
    )
    native_bundle_qualified: Literal[False] = False
    native_executor_isolation_qualified: Literal[False] = False
    execution_ready: Literal[False] = False

    @field_validator("binaries")
    @classmethod
    def exact_binary_pair(
        cls, value: tuple[WindowsNativeBinaryV2, WindowsNativeBinaryV2]
    ) -> tuple[WindowsNativeBinaryV2, WindowsNativeBinaryV2]:
        if tuple(item.role for item in value) != ("codex", "codex-code-mode-host"):
            raise ValueError("Windows build must bind the ordered Codex/code-mode-host pair")
        if value[0].sha256 == value[1].sha256:
            raise ValueError("Windows build binaries must have distinct identities")
        return value

    @model_validator(mode="after")
    def proof_uses_exact_sibling_host(self) -> WindowsNativeCodexBuildPayloadV2:
        host = self.binaries[1]
        if (
            self.process_proof.code_mode_host_sha256 != host.sha256
            or self.process_proof.code_mode_host_relative_path != host.relative_path
        ):
            raise ValueError("Windows process proof does not bind the exact sibling code-mode host")
        return self


class WindowsNativeCodexBuildV2(Contract):
    windows_native_codex_build_id: Digest
    payload: WindowsNativeCodexBuildPayloadV2

    @classmethod
    def create(cls, payload: WindowsNativeCodexBuildPayloadV2) -> WindowsNativeCodexBuildV2:
        return cls(
            windows_native_codex_build_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> WindowsNativeCodexBuildV2:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.windows_native_codex_build_id != expected:
            raise ValueError("Windows native Codex build ID mismatch")
        return self


class WindowsNativeCodexBuildPayloadV3(Contract):
    provenance: WindowsBuildProvenanceV3
    binaries: tuple[WindowsNativeBinaryV2, WindowsNativeBinaryV2]
    process_proof: WindowsHostProofSummaryV2
    compilation: Literal["PASS"] = "PASS"
    qualification: Literal["WINDOWS_NATIVE_CODEX_PAIR_AUTHORITY_PRE_SAMPLING"] = (
        "WINDOWS_NATIVE_CODEX_PAIR_AUTHORITY_PRE_SAMPLING"
    )
    native_bundle_qualified: Literal[False] = False
    native_executor_isolation_qualified: Literal[False] = False
    execution_ready: Literal[False] = False

    @field_validator("binaries")
    @classmethod
    def exact_binary_pair(
        cls, value: tuple[WindowsNativeBinaryV2, WindowsNativeBinaryV2]
    ) -> tuple[WindowsNativeBinaryV2, WindowsNativeBinaryV2]:
        if tuple(item.role for item in value) != ("codex", "codex-code-mode-host"):
            raise ValueError("Windows build must bind the ordered Codex/code-mode-host pair")
        if value[0].sha256 == value[1].sha256:
            raise ValueError("Windows build binaries must have distinct identities")
        return value

    @model_validator(mode="after")
    def proof_uses_exact_sibling_host(self) -> WindowsNativeCodexBuildPayloadV3:
        host = self.binaries[1]
        if (
            self.process_proof.code_mode_host_sha256 != host.sha256
            or self.process_proof.code_mode_host_relative_path != host.relative_path
        ):
            raise ValueError("Windows process proof does not bind the exact sibling code-mode host")
        return self


class WindowsNativeCodexBuildV3(Contract):
    windows_native_codex_build_id: Digest
    payload: WindowsNativeCodexBuildPayloadV3

    @classmethod
    def create(cls, payload: WindowsNativeCodexBuildPayloadV3) -> WindowsNativeCodexBuildV3:
        return cls(
            windows_native_codex_build_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> WindowsNativeCodexBuildV3:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.windows_native_codex_build_id != expected:
            raise ValueError("Windows native Codex build ID mismatch")
        return self


class WindowsNativeCodexBuildPayloadV4(WindowsNativeCodexBuildPayloadV3):
    """Forward payload for windows-build-005 without altering pair/security semantics."""

    provenance: WindowsBuildProvenanceV4
    process_proof: WindowsHostProofSummaryV3


class WindowsNativeCodexBuildV4(Contract):
    windows_native_codex_build_id: Digest
    payload: WindowsNativeCodexBuildPayloadV4

    @classmethod
    def create(cls, payload: WindowsNativeCodexBuildPayloadV4) -> WindowsNativeCodexBuildV4:
        return cls(
            windows_native_codex_build_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> WindowsNativeCodexBuildV4:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.windows_native_codex_build_id != expected:
            raise ValueError("Windows native Codex build ID mismatch")
        return self


class WindowsNativeCodexBuildPayloadV5(WindowsNativeCodexBuildPayloadV3):
    """Forward payload for windows-build-006 with unchanged proof semantics."""

    provenance: WindowsBuildProvenanceV5
    process_proof: WindowsHostProofSummaryV3


class WindowsNativeCodexBuildV5(Contract):
    windows_native_codex_build_id: Digest
    payload: WindowsNativeCodexBuildPayloadV5

    @classmethod
    def create(cls, payload: WindowsNativeCodexBuildPayloadV5) -> WindowsNativeCodexBuildV5:
        return cls(
            windows_native_codex_build_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> WindowsNativeCodexBuildV5:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.windows_native_codex_build_id != expected:
            raise ValueError("Windows native Codex build ID mismatch")
        return self


class WindowsNativeCodexBuildPayloadV6(WindowsNativeCodexBuildPayloadV3):
    """Forward payload for windows-build-007 with unchanged proof semantics."""

    provenance: WindowsBuildProvenanceV6
    process_proof: WindowsHostProofSummaryV3


class WindowsNativeCodexBuildV6(Contract):
    windows_native_codex_build_id: Digest
    payload: WindowsNativeCodexBuildPayloadV6

    @classmethod
    def create(cls, payload: WindowsNativeCodexBuildPayloadV6) -> WindowsNativeCodexBuildV6:
        return cls(
            windows_native_codex_build_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> WindowsNativeCodexBuildV6:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.windows_native_codex_build_id != expected:
            raise ValueError("Windows native Codex build ID mismatch")
        return self


class WindowsNativeCodexBuildPayloadV7(WindowsNativeCodexBuildPayloadV3):
    """Forward payload for windows-build-008 with unchanged proof semantics."""

    provenance: WindowsBuildProvenanceV7
    process_proof: WindowsHostProofSummaryV3


class WindowsNativeCodexBuildV7(Contract):
    windows_native_codex_build_id: Digest
    payload: WindowsNativeCodexBuildPayloadV7

    @classmethod
    def create(cls, payload: WindowsNativeCodexBuildPayloadV7) -> WindowsNativeCodexBuildV7:
        return cls(
            windows_native_codex_build_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> WindowsNativeCodexBuildV7:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.windows_native_codex_build_id != expected:
            raise ValueError("Windows native Codex build ID mismatch")
        return self
