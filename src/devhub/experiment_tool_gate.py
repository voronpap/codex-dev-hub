"""Versioned, fail-closed tool qualification for the exact pinned CLI.

Also mounted standalone into the metadata-only guest; standard library only.
"""

import hashlib
from pathlib import Path
from typing import Any

POLICY_VERSION = "stage3g-tool-capabilities-v1"
CLI_VERSION = "codex-cli 0.155.0-alpha.9.2"
SOURCE_COMMIT = "4607249e430dac1c961df4dc615beae88e33cec8"

SOURCE_FILE_SHA256 = {
    "managed_features.rs": "94cd6d897ecf7c33ad9cb1f401425f5437671f278e7b8cc74331f389e0afef22",
    "spec_plan.rs": "40f98e42507bf2b0e4251a6cdb9d96bda68c863db2953eb2bc09d99a9bfe1d8d",
    "spec_plan_tests.rs": "b856b5343784b4db9acbb44416fb24ee3eb9703cd0064c6df2af2a768eb700e3",
}


def policy_hash() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def tool_surface(features: dict[str, str], cli_version: str) -> dict[str, Any]:
    exact = cli_version == CLI_VERSION
    shell_absent = exact and features.get("shell_tool") == "false"
    # spec_plan.rs:1031-1069 guards both handlers with ShellTool.
    # spec_plan.rs:1213-1216 registers ApplyPatch independently, conditional on
    # model metadata. Service-default model is intentionally unknown here.
    absent: dict[str, bool | None] = {
        "exec_command": True if shell_absent else None,
        "write_stdin": True if shell_absent else None,
        "apply_patch": None,
    }
    return {
        "qualification_policy_version": POLICY_VERSION,
        "qualification_policy_sha256": policy_hash(),
        "source_commit": SOURCE_COMMIT,
        "tool_surface_observation": "source_derived",
        "exact_cli_matches": exact,
        "effective_shell_tool_disabled": shell_absent,
        "forbidden_tools_absent": absent,
        "forbidden_execution_tools_absent": all(v is True for v in absent.values()),
        "unresolved_surfaces": [
            "apply_patch registration depends on unknown service-default model metadata",
            "write_file: canonical mapping/extension surface not established",
        ],
        "feature_diagnostics": {
            "requested_unified_exec": False,
            "observed_unified_exec": features.get("unified_exec"),
            "expected_behavior_for_exact_cli": "forced_true_without_managed_requirements",
        },
    }
