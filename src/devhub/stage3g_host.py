"""Strict Stage 3G host-owned Arm A/B tool-ceiling contract."""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, JsonValue, model_validator

from devhub.benchmark import Digest, digest

DELEGATE_TOOL = "mcp__devhub_delegate.devhub_delegate"
DELEGATE_SCHEMA_SHA256 = "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
PRODUCTION_DELEGATE_MCP_CONFIG = {
    "args": ["/bootstrap.py", "mcp"],
    "command": "python3",
    "enabled": True,
    "enabled_tools": ["devhub_delegate"],
    "environment_id": "local",
    "required": True,
    "tool_timeout_sec": None,
    "tools": {"devhub_delegate": {"approval_mode": "approve"}},
}
PRODUCTION_DELEGATE_MCP_CONFIG_SHA256 = digest(
    json.dumps(
        PRODUCTION_DELEGATE_MCP_CONFIG,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
)


class HostContractV2(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, validate_default=True)


class ApprovedDelegateHostV1(HostContractV2):
    server_key: Literal["devhub_delegate"]
    raw_tool: Literal["devhub_delegate"]
    canonical_namespace: Literal["mcp__devhub_delegate"]
    canonical_function: Literal["devhub_delegate"]
    expected_mcp_server_config_sha256: Digest
    expected_input_schema: dict[str, JsonValue]
    expected_input_schema_sha256: Literal[
        "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
    ]
    direct_only_tool_namespaces: tuple[Literal["mcp__devhub_delegate"], ...]

    @model_validator(mode="after")
    def exact_schema_and_namespace(self) -> "ApprovedDelegateHostV1":
        schema = json.dumps(
            self.expected_input_schema,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if digest(schema) != self.expected_input_schema_sha256:
            raise ValueError("Approved delegate input schema hash mismatch")
        if self.direct_only_tool_namespaces != ("mcp__devhub_delegate",):
            raise ValueError("Approved delegate requires one direct-only namespace")
        return self


class Stage3gArmHostV2(HostContractV2):
    tool_ceiling: tuple[str, ...]
    approved_delegate: ApprovedDelegateHostV1 | None


class Stage3gHostArmsV2(HostContractV2):
    arm_a: Stage3gArmHostV2
    arm_b: Stage3gArmHostV2

    @model_validator(mode="after")
    def exact_surfaces(self) -> "Stage3gHostArmsV2":
        if self.arm_a.tool_ceiling or self.arm_a.approved_delegate is not None:
            raise ValueError("Arm A must have an empty ceiling and no delegate policy")
        if self.arm_b.tool_ceiling != (DELEGATE_TOOL,) or self.arm_b.approved_delegate is None:
            raise ValueError("Arm B must have exactly the reviewed delegate policy")
        return self


class Stage3gHostManifestV2(HostContractV2):
    schema_version: Literal[2]
    expected_global_tool_mode: Literal["CodeModeOnly"]
    error_on_tool_collisions: Literal[True]
    arms: Stage3gHostArmsV2


def read_stage3g_host_manifest(path: Path) -> tuple[Stage3gHostManifestV2, bytes]:
    """Re-read and strictly validate the locator; bytes remain the hash authority."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("Stage 3G host manifest must be a regular non-symlink file")
    raw = path.read_bytes()
    manifest = Stage3gHostManifestV2.model_validate_json(raw)
    return manifest, raw
