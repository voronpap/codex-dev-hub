"""Shared immutable observations for native Codex host proofs."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.models import Contract

OrdinaryDefaultVisibleToolsV1 = tuple[
    Literal["clock.sleep"],
    Literal["collaboration.followup_task"],
    Literal["collaboration.interrupt_agent"],
    Literal["collaboration.list_agents"],
    Literal["collaboration.send_message"],
    Literal["collaboration.spawn_agent"],
    Literal["collaboration.wait_agent"],
    Literal["functions.exec"],
    Literal["functions.request_user_input"],
    Literal["functions.request_user_input_async"],
    Literal["functions.wait"],
]

ORDINARY_DEFAULT_VISIBLE_TOOLS_V1: OrdinaryDefaultVisibleToolsV1 = (
    "clock.sleep",
    "collaboration.followup_task",
    "collaboration.interrupt_agent",
    "collaboration.list_agents",
    "collaboration.send_message",
    "collaboration.spawn_agent",
    "collaboration.wait_agent",
    "functions.exec",
    "functions.request_user_input",
    "functions.request_user_input_async",
    "functions.wait",
)


class NativeBuildArtifactEntryV1(Contract):
    """One immutable file retained from a native build output directory."""

    relative_path: str = Field(min_length=1, max_length=1024)
    kind: Literal["evidence", "binary"]
    size: Annotated[int, Field(ge=0)]
    sha256: Digest

    @field_validator("relative_path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value or value != path.as_posix():
            raise ValueError("Native build artifact path is not canonical and relative")
        return value

    @model_validator(mode="after")
    def matching_kind(self) -> NativeBuildArtifactEntryV1:
        expected = "binary" if self.relative_path.startswith("binary/") else "evidence"
        if self.kind != expected:
            raise ValueError("Native build artifact kind differs from its path")
        return self


class WindowsNativeBuildArtifactJoinV1(Contract):
    """Exact join from a successful inventory to the Windows pair authority."""

    build_receipt_sha256: Digest
    windows_native_codex_build_id: Digest
    codex_sha256: Digest
    code_mode_host_sha256: Digest
    process_proof_sha256: Digest
    code_mode_host_eof_receipt_sha256: Digest


class NativeBuildArtifactInventoryPayloadV1(Contract):
    """Closed, sorted inventory; the inventory file itself is excluded to avoid a hash cycle."""

    platform: Literal["windows", "linux"]
    build_id: str = Field(pattern=r"^(windows|linux)-build-[0-9]{3}$")
    status: Literal["PASS", "FAIL"]
    build_result_sha256: Digest
    windows_pair: WindowsNativeBuildArtifactJoinV1 | None = None
    files: tuple[NativeBuildArtifactEntryV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def sorted_unique_files(self) -> NativeBuildArtifactInventoryPayloadV1:
        paths = tuple(item.relative_path for item in self.files)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("Native build artifact inventory must be unique and sorted")
        expected_prefix = f"{self.platform}-build-"
        if not self.build_id.startswith(expected_prefix):
            raise ValueError("Native build artifact ID differs from its platform")
        if self.platform == "windows" and (self.status == "PASS") != (
            self.windows_pair is not None
        ):
            raise ValueError("Successful Windows inventory requires its exact pair authority")
        if self.platform != "windows" and self.windows_pair is not None:
            raise ValueError("Windows pair authority cannot be used by another platform")
        return self


class NativeBuildArtifactInventoryV1(Contract):
    native_build_artifact_inventory_id: Digest
    payload: NativeBuildArtifactInventoryPayloadV1

    @classmethod
    def create(
        cls, payload: NativeBuildArtifactInventoryPayloadV1
    ) -> NativeBuildArtifactInventoryV1:
        return cls(
            native_build_artifact_inventory_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> NativeBuildArtifactInventoryV1:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.native_build_artifact_inventory_id != expected:
            raise ValueError("Native build artifact inventory ID mismatch")
        return self
